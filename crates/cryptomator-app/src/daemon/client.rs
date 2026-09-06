//! The synchronous client for the [daemon protocol](super): one connection, one vault.
//!
//! Every CLI command that talks to an unlocked vault goes through here. The client is
//! deliberately blocking and single-threaded -- a command sends one request and waits for its
//! answer -- and it owns the connection, so dropping it closes the socket.
use crate::daemon::protocol::{
    read_line, write_line, EventRecord, EventsResult, Hello, Request, Response, StatsResult,
    StatusResult, StreamItem, PROTOCOL_VERSION,
};
use crate::error::{AppError, Result};
use serde::de::DeserializeOwned;
use std::io::{self, BufReader};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

/// How long to wait for the daemon's greeting before giving up on the connection.
const HELLO_TIMEOUT: Duration = Duration::from_secs(30);

/// How long [`DaemonClient::connect_with_retry`] waits between attempts.
const RETRY_INTERVAL: Duration = Duration::from_millis(100);

/// A connection to one vault's daemon.
#[derive(Debug)]
pub struct DaemonClient {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
    next_id: u64,
    /// The greeting the daemon sent; it names the vault and the daemon's pid.
    pub hello: Hello,
}

/// A failed [`DaemonClient::connect`], split by whether waiting could still help.
///
/// A missing or not-yet-listening socket is transient -- a daemon that is still starting up looks
/// exactly like that. A daemon that greets us with the wrong magic or the wrong protocol version
/// will never start being compatible, so retrying it only delays the error.
enum ConnectFailure {
    Transient(AppError),
    Fatal(AppError),
}

impl ConnectFailure {
    fn into_error(self) -> AppError {
        match self {
            ConnectFailure::Transient(err) | ConnectFailure::Fatal(err) => err,
        }
    }
}

/// One line from the daemon.
#[derive(Debug)]
enum Message {
    Response(Response),
    StreamItem(StreamItem),
}

impl DaemonClient {
    /// Connects to `socket` and reads the daemon's [`Hello`]. One attempt.
    ///
    /// Everything that can go wrong here -- no socket, nobody listening, a stranger on the other
    /// end, a protocol version this build does not speak -- is an
    /// [`AppError::DaemonUnreachable`], which the CLI reports as exit code 10.
    pub fn connect(socket: &Path) -> Result<Self> {
        Self::try_connect(socket).map_err(ConnectFailure::into_error)
    }

    /// Connects to `socket`, retrying every 100 ms until `deadline` has passed.
    ///
    /// This is what runs right after a daemon was spawned: the socket appears only once the
    /// daemon is ready to serve. An incompatible daemon fails immediately -- waiting cannot fix
    /// a version mismatch -- and the last transient error is what surfaces when the deadline hits.
    pub fn connect_with_retry(socket: &Path, deadline: Duration) -> Result<Self> {
        let started = Instant::now();
        let mut last_transient: Option<AppError> = None;
        loop {
            let remaining = deadline.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                // No time left even for the read timeout of one more attempt. Stop here instead
                // of calling `try_connect_within` with a zero `hello_timeout`, which would need
                // `set_read_timeout(Some(Duration::ZERO))` -- that call is `EINVAL`.
                return Err(last_transient.unwrap_or_else(|| {
                    AppError::DaemonUnreachable(format!(
                        "{}: timed out waiting for the daemon",
                        socket.display()
                    ))
                }));
            }
            match Self::try_connect_within(socket, remaining.min(HELLO_TIMEOUT)) {
                Ok(client) => return Ok(client),
                Err(ConnectFailure::Fatal(err)) => return Err(err),
                Err(ConnectFailure::Transient(err)) => {
                    let remaining = deadline.saturating_sub(started.elapsed());
                    if remaining.is_zero() {
                        return Err(err);
                    }
                    last_transient = Some(err);
                    thread::sleep(RETRY_INTERVAL.min(remaining));
                }
            }
        }
    }

    fn try_connect(socket: &Path) -> std::result::Result<Self, ConnectFailure> {
        Self::try_connect_within(socket, HELLO_TIMEOUT)
    }

    /// Connects to `socket` once, bounding the wait for the [`Hello`] by `hello_timeout` (which
    /// callers keep at or below [`HELLO_TIMEOUT`]).
    fn try_connect_within(
        socket: &Path,
        hello_timeout: Duration,
    ) -> std::result::Result<Self, ConnectFailure> {
        let stream = UnixStream::connect(socket).map_err(|err| {
            let message = format!("{}: {err}", socket.display());
            match err.kind() {
                // A socket cannot become shorter or change its permissions by waiting: these
                // never resolve themselves, so retrying only delays the error.
                io::ErrorKind::InvalidInput | io::ErrorKind::PermissionDenied => {
                    ConnectFailure::Fatal(AppError::DaemonUnreachable(message))
                }
                _ => ConnectFailure::Transient(AppError::DaemonUnreachable(message)),
            }
        })?;
        // Only the greeting is on a clock. Afterwards the client blocks for as long as the user
        // wants -- `events --follow` sits on the socket until it is interrupted.
        stream
            .set_read_timeout(Some(hello_timeout))
            .map_err(|err| ConnectFailure::Transient(transport(&err)))?;
        let writer = stream
            .try_clone()
            .map_err(|err| ConnectFailure::Transient(transport(&err)))?;
        let mut reader = BufReader::new(stream);

        let line = match read_line(&mut reader) {
            Ok(Some(line)) => line,
            Ok(None) => {
                return Err(ConnectFailure::Transient(AppError::DaemonUnreachable(
                    "the daemon closed the connection before greeting".to_owned(),
                )))
            }
            Err(err) => return Err(ConnectFailure::Transient(transport(&err))),
        };
        let hello: Hello = serde_json::from_str(&line).map_err(|_| not_a_daemon())?;
        if hello.hello != Hello::MAGIC {
            return Err(not_a_daemon());
        }
        if hello.protocol != PROTOCOL_VERSION {
            return Err(ConnectFailure::Fatal(AppError::DaemonUnreachable(format!(
                "protocol mismatch: the daemon speaks version {}, this build speaks {PROTOCOL_VERSION}",
                hello.protocol
            ))));
        }
        reader
            .get_ref()
            .set_read_timeout(None)
            .map_err(|err| ConnectFailure::Transient(transport(&err)))?;

        Ok(Self {
            reader,
            writer,
            next_id: 1,
            hello,
        })
    }

    /// Sends `request` and returns the `result` of its [`Response`].
    ///
    /// The `id` of `request` is overwritten with this connection's next one. A daemon error
    /// becomes [`AppError::DaemonError`], which carries the code the CLI maps to an exit code.
    /// Stream items for this request are skipped, so a `call` on a following request would hang
    /// until the stream ends -- use [`stream`](Self::stream) for those.
    pub fn call(&mut self, mut request: Request) -> Result<serde_json::Value> {
        let id = self.send(&mut request)?;
        drop(request); // wipes the key of an `unlock` before the answer is awaited
        loop {
            match self.read_message()? {
                Message::Response(response) if response.id == id => {
                    return unwrap_response(response)
                }
                Message::StreamItem(item) if item.id == id => continue,
                _ => return Err(unexpected()),
            }
        }
    }

    /// Sends `request` and hands every [`StreamItem`] of the resulting stream to `on_item`.
    ///
    /// Returns when the daemon closes the stream with a [`Response`], or as soon as `on_item`
    /// returns `false`. In the latter case the socket is shut down in both directions: the daemon
    /// takes the closed connection as the end of the stream. The client is spent afterwards, so
    /// drop it.
    pub fn stream(
        &mut self,
        mut request: Request,
        mut on_item: impl FnMut(EventRecord) -> bool,
    ) -> Result<()> {
        let id = self.send(&mut request)?;
        drop(request);
        loop {
            match self.read_message()? {
                Message::StreamItem(item) if item.id == id => {
                    if !on_item(item.event) {
                        // Errors are irrelevant here: we are done with the socket either way.
                        let _ = self.writer.shutdown(Shutdown::Both);
                        return Ok(());
                    }
                }
                Message::Response(response) if response.id == id => {
                    unwrap_response(response)?;
                    return Ok(());
                }
                _ => return Err(unexpected()),
            }
        }
    }

    /// What the daemon has mounted, and since when.
    pub fn status(&mut self) -> Result<StatusResult> {
        let result = self.call(Request::Status { id: 0 })?;
        typed(result)
    }

    /// The daemon's throughput and cache counters.
    pub fn stats(&mut self) -> Result<StatsResult> {
        let result = self.call(Request::Stats { id: 0 })?;
        typed(result)
    }

    /// Unmounts and stops the daemon. `force` takes the volume down even while it is in use.
    pub fn lock(&mut self, force: bool) -> Result<()> {
        self.call(Request::Lock { id: 0, force })?;
        Ok(())
    }

    /// The event log from `since` on, in one batch.
    pub fn events(&mut self, since: u64) -> Result<EventsResult> {
        let result = self.call(Request::Events {
            id: 0,
            follow: false,
            since,
        })?;
        typed(result)
    }

    /// Checks that the daemon answers.
    pub fn ping(&mut self) -> Result<()> {
        self.call(Request::Ping { id: 0 })?;
        Ok(())
    }

    /// Stamps the next id on `request` and writes it. The request is dropped -- and an
    /// [`Request::Unlock`] therefore wiped -- before the answer is awaited.
    fn send(&mut self, request: &mut Request) -> Result<u64> {
        let id = self.next_id;
        self.next_id += 1;
        request.set_id(id);
        // The payload never reaches the error: an `unlock` carries the vault key.
        write_line(&mut self.writer, &*request).map_err(|err| transport(&err))?;
        Ok(id)
    }

    fn read_message(&mut self) -> Result<Message> {
        let Some(line) = read_line(&mut self.reader).map_err(|err| transport(&err))? else {
            return Err(AppError::DaemonUnreachable(
                "the daemon closed the connection".to_owned(),
            ));
        };
        let value: serde_json::Value = serde_json::from_str(&line).map_err(|_| malformed())?;
        if value.get("event").is_some() {
            serde_json::from_value(value)
                .map(Message::StreamItem)
                .map_err(|_| malformed())
        } else {
            serde_json::from_value(value)
                .map(Message::Response)
                .map_err(|_| malformed())
        }
    }
}

/// The `result` of a successful response, or the daemon's error.
fn unwrap_response(response: Response) -> Result<serde_json::Value> {
    if response.ok {
        return Ok(response.result.unwrap_or(serde_json::Value::Null));
    }
    let (code, message) = match response.error {
        Some(body) => (body.code, body.message),
        None => (
            crate::daemon::protocol::ErrorBody::INTERNAL.to_owned(),
            "the daemon reported a failure without a reason".to_owned(),
        ),
    };
    Err(AppError::DaemonError { code, message })
}

/// Decodes a `result` into the struct the command expects.
fn typed<T: DeserializeOwned>(value: serde_json::Value) -> Result<T> {
    serde_json::from_value(value)
        .map_err(|_| AppError::DaemonUnreachable("malformed result from the daemon".to_owned()))
}

/// A read or write on the socket failed. The daemon is gone or the connection broke, which is the
/// same thing from a command's point of view.
fn transport(err: &io::Error) -> AppError {
    AppError::DaemonUnreachable(format!("connection to the daemon failed: {err}"))
}

fn malformed() -> AppError {
    AppError::DaemonUnreachable("malformed message from the daemon".to_owned())
}

/// The greeting failed to parse, or its `hello` field is not [`Hello::MAGIC`].
fn not_a_daemon() -> ConnectFailure {
    ConnectFailure::Fatal(AppError::DaemonUnreachable(
        "the process on the socket is not a crypto daemon".to_owned(),
    ))
}

fn unexpected() -> AppError {
    AppError::DaemonUnreachable("unexpected message from the daemon".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::protocol::{read_request, ErrorBody};
    use std::io::Write;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn greeting(protocol: u32) -> Hello {
        Hello {
            hello: Hello::MAGIC.to_owned(),
            protocol,
            vault_id: "vault-1".to_owned(),
            pid: 4242,
        }
    }

    fn event(seq: u64) -> EventRecord {
        EventRecord {
            seq,
            timestamp: 1_757_000_000 + seq,
            kind: "DECRYPTION_FAILED".to_owned(),
            message: format!("event {seq}"),
            cleartext_path: None,
            ciphertext_path: None,
        }
    }

    fn status() -> StatusResult {
        StatusResult {
            vault_id: "vault-1".to_owned(),
            state: "UNLOCKED".to_owned(),
            mountpoint: Some("/mnt/v".to_owned()),
            mounter: "org.cryptomator.cli.FuseMountProvider".to_owned(),
            read_only: false,
            started_at: 1_757_000_000,
            uptime_secs: 12,
            last_activity: 1_757_000_010,
            in_use: true,
        }
    }

    /// A daemon stand-in: greets, answers `ping`/`status`/`lock`, and serves `events --follow`
    /// with two items followed by the closing response.
    fn handle(conn: UnixStream, protocol: u32) {
        let Ok(mut writer) = conn.try_clone() else {
            return;
        };
        let mut reader = BufReader::new(conn);
        if write_line(&mut writer, &greeting(protocol)).is_err() {
            return;
        }
        while let Ok(Some(request)) = read_request(&mut reader) {
            let id = request.id();
            let written = match &request {
                Request::Ping { .. } => {
                    write_line(&mut writer, &Response::ok(id, serde_json::Value::Null))
                }
                Request::Status { .. } => {
                    let result = serde_json::to_value(status()).expect("a status serialises");
                    write_line(&mut writer, &Response::ok(id, result))
                }
                Request::Lock { force: true, .. } => {
                    write_line(&mut writer, &Response::ok(id, serde_json::Value::Null))
                }
                Request::Lock { force: false, .. } => write_line(
                    &mut writer,
                    &Response::err(id, ErrorBody::UNMOUNT_FAILED, "volume is in use"),
                ),
                Request::Events { follow: true, .. } => {
                    let mut result = Ok(());
                    for seq in 1..=2 {
                        result = write_line(
                            &mut writer,
                            &StreamItem {
                                id,
                                event: event(seq),
                            },
                        );
                        if result.is_err() {
                            break;
                        }
                    }
                    result.and_then(|()| {
                        write_line(&mut writer, &Response::ok(id, serde_json::Value::Null))
                    })
                }
                _ => write_line(
                    &mut writer,
                    &Response::err(id, ErrorBody::BAD_REQUEST, "unsupported in the fake"),
                ),
            };
            if written.is_err() {
                return;
            }
        }
    }

    /// The socket of a fake daemon; dropping it removes the directory. The serving thread is
    /// left blocked in `accept` -- it dies with the test process.
    struct Fake {
        _dir: TempDir,
        socket: PathBuf,
    }

    fn spawn_fake(protocol: u32) -> Fake {
        // `env::temp_dir()` keeps the path short: `sun_path` is 104 bytes on macOS.
        let dir = tempfile::tempdir().expect("a temp dir");
        let socket = dir.path().join("d.sock");
        let listener = UnixListener::bind(&socket).expect("binding the fake daemon socket");
        thread::spawn(move || serve(listener, protocol));
        Fake { _dir: dir, socket }
    }

    fn serve(listener: UnixListener, protocol: u32) {
        for conn in listener.incoming() {
            let Ok(conn) = conn else { return };
            handle(conn, protocol);
        }
    }

    /// A daemon stand-in that greets, reads exactly one request, and answers with whatever
    /// `reply` (given the request's `id`) returns, written to the socket verbatim -- unlike
    /// [`handle`], which always encodes a well-formed [`Response`]. Used to feed the client lines
    /// it must reject: garbage JSON, or a `Response` with the wrong `id`.
    fn spawn_fake_with_reply(
        protocol: u32,
        reply: impl FnOnce(u64) -> String + Send + 'static,
    ) -> Fake {
        let dir = tempfile::tempdir().expect("a temp dir");
        let socket = dir.path().join("d.sock");
        let listener = UnixListener::bind(&socket).expect("binding the fake daemon socket");
        thread::spawn(move || {
            let Ok((conn, _)) = listener.accept() else {
                return;
            };
            let Ok(mut writer) = conn.try_clone() else {
                return;
            };
            let mut reader = BufReader::new(conn);
            if write_line(&mut writer, &greeting(protocol)).is_err() {
                return;
            }
            let Ok(Some(request)) = read_request(&mut reader) else {
                return;
            };
            let line = reply(request.id());
            let _ = writer.write_all(line.as_bytes());
            let _ = writer.flush();
        });
        Fake { _dir: dir, socket }
    }

    #[test]
    fn connect_reads_the_greeting() {
        let fake = spawn_fake(PROTOCOL_VERSION);
        let client = DaemonClient::connect(&fake.socket).expect("the fake daemon greets");
        assert_eq!(client.hello.vault_id, "vault-1");
        assert_eq!(client.hello.pid, 4242);
        assert_eq!(client.hello.protocol, PROTOCOL_VERSION);
    }

    #[test]
    fn a_ping_succeeds_and_a_refused_lock_becomes_a_daemon_error() {
        let fake = spawn_fake(PROTOCOL_VERSION);
        let mut client = DaemonClient::connect(&fake.socket).expect("connects");
        client.ping().expect("the fake answers a ping");
        match client.lock(false) {
            Err(AppError::DaemonError { code, message }) => {
                assert_eq!(code, ErrorBody::UNMOUNT_FAILED);
                assert_eq!(message, "volume is in use");
            }
            other => panic!("expected a daemon error, got {other:?}"),
        }
        // The connection survives an error response, and ids keep advancing.
        client.lock(true).expect("a forced lock succeeds");
    }

    #[test]
    fn status_is_decoded_into_the_typed_result() {
        let fake = spawn_fake(PROTOCOL_VERSION);
        let mut client = DaemonClient::connect(&fake.socket).expect("connects");
        assert_eq!(client.status().expect("a status"), status());
    }

    #[test]
    fn a_follow_stream_delivers_every_item_until_the_closing_response() {
        let fake = spawn_fake(PROTOCOL_VERSION);
        let mut client = DaemonClient::connect(&fake.socket).expect("connects");
        let mut seen = Vec::new();
        client
            .stream(
                Request::Events {
                    id: 0,
                    follow: true,
                    since: 0,
                },
                |item| {
                    seen.push(item.seq);
                    true
                },
            )
            .expect("the stream ends with an ok response");
        assert_eq!(seen, vec![1, 2]);
    }

    #[test]
    fn a_follow_stream_stops_when_the_callback_says_so() {
        let fake = spawn_fake(PROTOCOL_VERSION);
        let mut client = DaemonClient::connect(&fake.socket).expect("connects");
        let mut seen = Vec::new();
        client
            .stream(
                Request::Events {
                    id: 0,
                    follow: true,
                    since: 0,
                },
                |item| {
                    seen.push(item.seq);
                    false
                },
            )
            .expect("stopping early is not an error");
        assert_eq!(seen, vec![1]);
    }

    #[test]
    fn connect_on_a_missing_socket_reports_the_daemon_unreachable() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let missing = dir.path().join("absent.sock");
        match DaemonClient::connect(&missing) {
            Err(AppError::DaemonUnreachable(message)) => {
                assert!(message.contains("absent.sock"), "{message}");
            }
            other => panic!("expected the daemon to be unreachable, got {other:?}"),
        }
    }

    #[test]
    fn a_protocol_mismatch_is_reported_instead_of_retried() {
        let fake = spawn_fake(PROTOCOL_VERSION + 1);
        let started = Instant::now();
        match DaemonClient::connect_with_retry(&fake.socket, Duration::from_secs(30)) {
            Err(AppError::DaemonUnreachable(message)) => {
                assert!(message.contains("protocol mismatch"), "{message}");
            }
            other => panic!("expected a protocol mismatch, got {other:?}"),
        }
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "a version mismatch must not be retried"
        );
    }

    #[test]
    fn connect_with_retry_waits_for_a_socket_that_appears_late() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let socket = dir.path().join("late.sock");
        let bind_at = socket.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(300));
            let listener = UnixListener::bind(&bind_at).expect("binding late");
            serve(listener, PROTOCOL_VERSION);
        });

        let started = Instant::now();
        let mut client = DaemonClient::connect_with_retry(&socket, Duration::from_secs(30))
            .expect("the socket shows up within the deadline");
        assert!(started.elapsed() >= Duration::from_millis(300));
        client.ping().expect("the late daemon answers");
    }

    #[test]
    fn connect_with_retry_gives_up_at_the_deadline() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let never = dir.path().join("never.sock");
        let started = Instant::now();
        match DaemonClient::connect_with_retry(&never, Duration::from_millis(250)) {
            Err(AppError::DaemonUnreachable(message)) => {
                assert!(message.contains("never.sock"), "{message}");
            }
            other => panic!("expected the daemon to be unreachable, got {other:?}"),
        }
        assert!(started.elapsed() >= Duration::from_millis(250));
    }

    /// A listener that accepts every connection and then never writes anything -- a daemon that
    /// is wedged, or stopped, between `accept` and sending its `Hello`.
    fn spawn_silent_listener() -> Fake {
        let dir = tempfile::tempdir().expect("a temp dir");
        let socket = dir.path().join("silent.sock");
        let listener = UnixListener::bind(&socket).expect("binding the silent socket");
        thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(conn) = conn else { return };
                // Hold the connection open without ever writing the greeting.
                thread::sleep(Duration::from_secs(60));
                drop(conn);
            }
        });
        Fake { _dir: dir, socket }
    }

    #[test]
    fn connect_with_retry_does_not_overrun_the_deadline_waiting_for_a_stuck_hello() {
        let fake = spawn_silent_listener();
        let started = Instant::now();
        match DaemonClient::connect_with_retry(&fake.socket, Duration::from_millis(300)) {
            Err(AppError::DaemonUnreachable(_)) => {}
            other => panic!("expected the daemon to be unreachable, got {other:?}"),
        }
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "connect_with_retry must not wait out a full HELLO_TIMEOUT past its deadline: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn connect_with_retry_fails_fast_on_an_overlong_socket_path() {
        // `sun_path` is 104 bytes on macOS (108 on Linux): this path can never be connectable, no
        // matter how long we wait.
        let overlong = PathBuf::from(format!("/{}/x.sock", "a".repeat(200)));
        let started = Instant::now();
        match DaemonClient::connect_with_retry(&overlong, Duration::from_secs(2)) {
            Err(AppError::DaemonUnreachable(_)) => {}
            other => panic!("expected the daemon to be unreachable, got {other:?}"),
        }
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "an unconnectable path must not be retried: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn read_message_rejects_malformed_json() {
        let fake = spawn_fake_with_reply(PROTOCOL_VERSION, |_id| "not json\n".to_owned());
        let mut client = DaemonClient::connect(&fake.socket).expect("connects");
        match client.ping() {
            Err(AppError::DaemonUnreachable(message)) => {
                assert!(message.contains("malformed"), "{message}");
            }
            other => panic!("expected a malformed-message error, got {other:?}"),
        }
    }

    #[test]
    fn call_rejects_a_response_with_a_mismatched_id() {
        let fake = spawn_fake_with_reply(PROTOCOL_VERSION, |id| {
            let response = Response::ok(id + 1, serde_json::Value::Null);
            format!(
                "{}\n",
                serde_json::to_string(&response).expect("a response serialises")
            )
        });
        let mut client = DaemonClient::connect(&fake.socket).expect("connects");
        match client.ping() {
            Err(AppError::DaemonUnreachable(message)) => {
                assert!(message.contains("unexpected"), "{message}");
            }
            other => panic!("expected an unexpected-message error, got {other:?}"),
        }
    }
}
