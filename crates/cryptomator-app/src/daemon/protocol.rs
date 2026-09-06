//! The message types of the [daemon protocol](super) and the two line primitives around them.
//!
//! Every struct here is plain data with `camelCase` field names; nothing in this module talks to
//! a socket, so both the daemon and the client build on it.
//!
//! The one value that needs care is the vault key: [`Request::Unlock`] carries it as base64 of
//! the 64 raw key bytes. `serde` cannot deserialise into a `Zeroizing<String>`, so the field is a
//! plain `String` and [`Request`] wipes it in [`Drop`] instead; [`read_request`] additionally
//! wipes the raw line it decoded from. Because of that `Drop` impl a `Request` cannot be
//! destructured by move -- match on a reference, or `std::mem::take` the fields you need.
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::{self, BufRead, Read, Write};
use zeroize::{Zeroize, Zeroizing};

/// The protocol version the daemon announces in its [`Hello`] and the client insists on.
pub const PROTOCOL_VERSION: u32 = 1;

/// The longest line either side accepts, excluding the terminating newline.
///
/// A well-formed request stays far below this -- the largest one, [`Request::Unlock`], is a
/// base64 key plus a few paths. The limit is what keeps a peer that never sends a newline from
/// growing the read buffer without bound.
pub const MAX_LINE_LEN: usize = 1024 * 1024;

/// Capacity [`read_line`] reserves up front.
///
/// Growing the buffer would leave copies of the old contents in freed memory, which matters for
/// the one line that carries the vault key. Every realistic request fits in this.
const LINE_BUFFER: usize = 4096;

/// The daemon's greeting: the first line on every accepted connection.
///
/// It identifies the process before the client sends anything, so a socket left behind by some
/// other program is rejected instead of being fed a vault key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Hello {
    /// Always `"crypto-daemon"`.
    pub hello: String,
    /// [`PROTOCOL_VERSION`] of the daemon.
    pub protocol: u32,
    /// The vault this daemon serves.
    pub vault_id: String,
    /// The daemon's process id, for `crypto status` and for signalling.
    pub pid: u32,
}

impl Hello {
    /// The value of the [`hello`](Hello::hello) field of a genuine daemon.
    pub const MAGIC: &'static str = "crypto-daemon";
}

/// A command from the client, tagged by `"op"` and carrying the `id` its [`Response`] echoes.
///
/// Ids are per connection and assigned by the client; [`DaemonClient`](super::DaemonClient) does
/// that in [`call`](super::DaemonClient::call), so callers may leave `id` at `0`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "camelCase")]
pub enum Request {
    /// Hand the vault key to a daemon that has not mounted yet. Sent once, by the process that
    /// spawned the daemon.
    #[serde(rename_all = "camelCase")]
    Unlock {
        id: u64,
        /// Base64 of the 64 raw key bytes. Wiped when the request is dropped.
        key: String,
        /// Mount service id, or `None` for "pick the best available one".
        mounter: Option<String>,
        /// Where to mount, or `None` for the configured default.
        mount_point: Option<String>,
        /// Extra options handed to the mount service verbatim.
        mount_options: Vec<String>,
        /// `None` means "whatever the vault's settings say".
        read_only: Option<bool>,
        /// The volume name to show in the file manager.
        volume_name: Option<String>,
        /// The longest cleartext file name the vault's shortening scheme allows.
        max_cleartext_name_length: usize,
    },
    /// What is mounted where, and since when. Answered with a [`StatusResult`].
    Status { id: u64 },
    /// Throughput and cache counters. Answered with a [`StatsResult`].
    Stats { id: u64 },
    /// Unmount and exit. `force` takes the volume down even while it is in use.
    Lock { id: u64, force: bool },
    /// The event log from `since` on. With `follow` the daemon keeps sending [`StreamItem`]s
    /// until the client stops reading; otherwise it answers with an [`EventsResult`] at once.
    Events { id: u64, follow: bool, since: u64 },
    /// Liveness check; the result is `null`.
    Ping { id: u64 },
    /// Exit without unmounting. Used when the mount is already gone.
    Shutdown { id: u64 },
}

impl Request {
    /// The `id` this request carries.
    pub fn id(&self) -> u64 {
        match self {
            Request::Unlock { id, .. }
            | Request::Status { id }
            | Request::Stats { id }
            | Request::Lock { id, .. }
            | Request::Events { id, .. }
            | Request::Ping { id }
            | Request::Shutdown { id } => *id,
        }
    }

    /// Stamps `id` on this request, whatever the caller passed in.
    pub fn set_id(&mut self, new_id: u64) {
        match self {
            Request::Unlock { id, .. }
            | Request::Status { id }
            | Request::Stats { id }
            | Request::Lock { id, .. }
            | Request::Events { id, .. }
            | Request::Ping { id }
            | Request::Shutdown { id } => *id = new_id,
        }
    }

    /// The `"op"` tag, for logging a request without any of its payload.
    pub fn op(&self) -> &'static str {
        match self {
            Request::Unlock { .. } => "unlock",
            Request::Status { .. } => "status",
            Request::Stats { .. } => "stats",
            Request::Lock { .. } => "lock",
            Request::Events { .. } => "events",
            Request::Ping { .. } => "ping",
            Request::Shutdown { .. } => "shutdown",
        }
    }
}

impl Drop for Request {
    fn drop(&mut self) {
        if let Request::Unlock { key, .. } = self {
            key.zeroize();
        }
    }
}

// Hand-written so that the key cannot reach a log line through `{:?}`.
impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Request::Unlock {
                id,
                key: _,
                mounter,
                mount_point,
                mount_options,
                read_only,
                volume_name,
                max_cleartext_name_length,
            } => f
                .debug_struct("Unlock")
                .field("id", id)
                .field("key", &"<redacted>")
                .field("mounter", mounter)
                .field("mount_point", mount_point)
                .field("mount_options", mount_options)
                .field("read_only", read_only)
                .field("volume_name", volume_name)
                .field("max_cleartext_name_length", max_cleartext_name_length)
                .finish(),
            Request::Status { id } => f.debug_struct("Status").field("id", id).finish(),
            Request::Stats { id } => f.debug_struct("Stats").field("id", id).finish(),
            Request::Lock { id, force } => f
                .debug_struct("Lock")
                .field("id", id)
                .field("force", force)
                .finish(),
            Request::Events { id, follow, since } => f
                .debug_struct("Events")
                .field("id", id)
                .field("follow", follow)
                .field("since", since)
                .finish(),
            Request::Ping { id } => f.debug_struct("Ping").field("id", id).finish(),
            Request::Shutdown { id } => f.debug_struct("Shutdown").field("id", id).finish(),
        }
    }
}

/// The one answer to a [`Request`], echoing its `id`.
///
/// Exactly one of `result` and `error` is set, and the unset one is left off the wire.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Response {
    pub id: u64,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorBody>,
}

impl Response {
    /// A successful answer to `id`.
    pub fn ok(id: u64, result: serde_json::Value) -> Self {
        Self {
            id,
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    /// A failed answer to `id`; `code` is one of the constants on [`ErrorBody`].
    pub fn err(id: u64, code: &str, message: impl Into<String>) -> Self {
        Self {
            id,
            ok: false,
            result: None,
            error: Some(ErrorBody {
                code: code.to_owned(),
                message: message.into(),
            }),
        }
    }
}

/// Why a request failed. `code` is stable and drives the CLI's exit code; `message` is for humans.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
}

impl ErrorBody {
    /// The mount service refused to mount.
    pub const MOUNT_FAILED: &'static str = "MOUNT_FAILED";
    /// The volume could not be taken down, e.g. because it is still in use.
    pub const UNMOUNT_FAILED: &'static str = "UNMOUNT_FAILED";
    /// An `unlock` arrived at a daemon that is already serving a mount.
    pub const ALREADY_UNLOCKED: &'static str = "ALREADY_UNLOCKED";
    /// A request arrived before the vault was unlocked.
    pub const NOT_UNLOCKED: &'static str = "NOT_UNLOCKED";
    /// The line did not decode, or its fields make no sense.
    pub const BAD_REQUEST: &'static str = "BAD_REQUEST";
    /// Anything the daemon did not expect.
    pub const INTERNAL: &'static str = "INTERNAL";
}

/// The result of [`Request::Status`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusResult {
    pub vault_id: String,
    /// `"STARTING"`, `"UNLOCKED"` or `"LOCKING"`.
    pub state: String,
    /// `None` while the mount is still coming up.
    pub mountpoint: Option<String>,
    /// Id of the mount service in use.
    pub mounter: String,
    pub read_only: bool,
    /// Unix time the daemon started.
    pub started_at: u64,
    pub uptime_secs: u64,
    /// Unix time of the last file system operation.
    pub last_activity: u64,
    /// Whether a process currently has files open on the volume.
    pub in_use: bool,
}

/// The result of [`Request::Stats`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatsResult {
    pub bytes_per_second_read: u64,
    pub bytes_per_second_written: u64,
    pub bytes_per_second_encrypted: u64,
    pub bytes_per_second_decrypted: u64,
    pub cache_hit_rate: f64,
    pub total_bytes_read: u64,
    pub total_bytes_written: u64,
    pub total_bytes_encrypted: u64,
    pub total_bytes_decrypted: u64,
    pub files_read: u64,
    pub files_written: u64,
    pub total_files_accessed: u64,
    pub last_activity: u64,
}

/// One entry of the daemon's event log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventRecord {
    /// Monotonically increasing within one daemon; `since` of the next [`Request::Events`].
    pub seq: u64,
    /// Unix time in seconds.
    pub timestamp: u64,
    /// The event type, e.g. `"DECRYPTION_FAILED"`.
    pub kind: String,
    pub message: String,
    pub cleartext_path: Option<String>,
    pub ciphertext_path: Option<String>,
}

/// The result of a non-following [`Request::Events`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventsResult {
    pub events: Vec<EventRecord>,
    /// The `since` to pass next time to pick up where this batch ended.
    pub next_seq: u64,
}

/// One line of a follow stream: a single event, tagged with the `id` of the request that opened
/// the stream. The stream ends with a [`Response`] carrying the same `id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamItem {
    pub id: u64,
    pub event: EventRecord,
}

/// Serialises `value` as one JSON line and flushes it.
///
/// The buffer is wiped afterwards: for [`Request::Unlock`] it holds the base64 key.
pub fn write_line<W: Write>(w: &mut W, value: &impl Serialize) -> io::Result<()> {
    let mut line = Zeroizing::new(serde_json::to_vec(value).map_err(io::Error::other)?);
    line.push(b'\n');
    w.write_all(&line)?;
    w.flush()
}

/// What [`read_line_into`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineStatus {
    /// The buffer holds one complete line, terminator already stripped.
    Complete,
    /// End of input, and the buffer is empty.
    Eof,
    /// The read timed out before the line was complete. Whatever arrived is in the buffer and
    /// the next call continues where this one stopped.
    Incomplete,
}

/// Reads one line into `buf`, without its terminator, and says whether it is complete.
///
/// Unlike [`read_line`] this survives a read timeout: a socket with
/// [`set_read_timeout`](std::os::unix::net::UnixStream::set_read_timeout) reports
/// [`LineStatus::Incomplete`] with the bytes that did arrive left in `buf`, so a caller polling
/// for a signal in between cannot lose half a message. `buf` is only ever appended to; the caller
/// clears it once it has taken the line.
///
/// A line longer than [`MAX_LINE_LEN`] (the terminator does not count towards the limit, so
/// `\r\n` gets its own byte of headroom) is an [`io::ErrorKind::InvalidData`] error rather than an
/// unbounded allocation, and the reader is left just past the limit -- the connection is not
/// usable afterwards.
pub fn read_line_into<R: BufRead>(r: &mut R, buf: &mut String) -> io::Result<LineStatus> {
    // Two bytes of headroom past MAX_LINE_LEN: one for `\n`, one more so a `\r\n` terminator on a
    // line at exactly the limit still fits before the length check below rejects it.
    let limit = (MAX_LINE_LEN + 2).saturating_sub(buf.len()) as u64;
    let read = match r.take(limit).read_line(buf) {
        Ok(read) => read,
        // The bytes read before the timeout stay in `buf` (`read_line` appends as it goes), so
        // this is a resumption point, not a loss.
        Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
            return Ok(LineStatus::Incomplete)
        }
        Err(e) => return Err(e),
    };
    if read == 0 && buf.is_empty() {
        return Ok(LineStatus::Eof);
    }
    // A last line without a terminator is accepted: peers that close right after writing are
    // common enough, and the JSON either parses or it does not. `read_line` only returns without
    // a `\n` at end of input or at the limit, so there is nothing more to wait for either way.
    while buf.ends_with('\n') || buf.ends_with('\r') {
        buf.pop();
    }
    if buf.len() > MAX_LINE_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("protocol line exceeds {MAX_LINE_LEN} bytes"),
        ));
    }
    Ok(LineStatus::Complete)
}

/// Reads one line, without its terminator, from a blocking reader.
///
/// Returns `Ok(None)` at end of input. See [`read_line_into`] for the length limit; a reader with
/// a read timeout should use that function instead, because a timeout here is an error that
/// throws the partial line away.
pub fn read_line<R: BufRead>(r: &mut R) -> io::Result<Option<String>> {
    let mut line = String::with_capacity(LINE_BUFFER);
    match read_line_into(r, &mut line)? {
        LineStatus::Complete => Ok(Some(line)),
        LineStatus::Eof => Ok(None),
        LineStatus::Incomplete => Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "the read timed out before the line was complete",
        )),
    }
}

/// Reads and decodes one [`Request`], wiping the raw line afterwards.
///
/// This is the entry point the daemon uses: it keeps the base64 key of an [`Request::Unlock`]
/// out of any buffer that outlives the call. Returns `Ok(None)` at end of input; a line that
/// does not decode is an [`io::ErrorKind::InvalidData`] error whose message names the position
/// only -- never the payload.
pub fn read_request<R: BufRead>(r: &mut R) -> io::Result<Option<Request>> {
    let Some(line) = read_line(r)? else {
        return Ok(None);
    };
    let line = Zeroizing::new(line);
    let request = serde_json::from_str(&line).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "malformed request (line {}, column {})",
                err.line(),
                err.column()
            ),
        )
    })?;
    Ok(Some(request))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn json(value: &impl Serialize) -> String {
        let mut buf = Vec::new();
        write_line(&mut buf, value).expect("writing to a Vec cannot fail");
        String::from_utf8(buf).expect("serde_json emits UTF-8")
    }

    #[test]
    fn a_request_is_tagged_by_op_and_written_as_one_line() {
        assert_eq!(
            json(&Request::Lock { id: 3, force: true }),
            "{\"op\":\"lock\",\"id\":3,\"force\":true}\n"
        );
        assert_eq!(
            json(&Request::Events {
                id: 7,
                follow: true,
                since: 42
            }),
            "{\"op\":\"events\",\"id\":7,\"follow\":true,\"since\":42}\n"
        );
        assert_eq!(
            json(&Request::Ping { id: 1 }),
            "{\"op\":\"ping\",\"id\":1}\n"
        );
    }

    #[test]
    fn unlock_fields_are_camel_case() {
        let request = Request::Unlock {
            id: 1,
            key: "a2V5".to_owned(),
            mounter: None,
            mount_point: Some("/mnt/v".to_owned()),
            mount_options: vec!["ro".to_owned()],
            read_only: Some(true),
            volume_name: None,
            max_cleartext_name_length: 220,
        };
        assert_eq!(
            json(&request),
            concat!(
                "{\"op\":\"unlock\",\"id\":1,\"key\":\"a2V5\",\"mounter\":null,",
                "\"mountPoint\":\"/mnt/v\",\"mountOptions\":[\"ro\"],\"readOnly\":true,",
                "\"volumeName\":null,\"maxCleartextNameLength\":220}\n"
            )
        );
    }

    #[test]
    fn debug_of_an_unlock_hides_the_key() {
        let request = Request::Unlock {
            id: 1,
            key: "s3cr3t".to_owned(),
            mounter: None,
            mount_point: None,
            mount_options: Vec::new(),
            read_only: None,
            volume_name: None,
            max_cleartext_name_length: 220,
        };
        let rendered = format!("{request:?}");
        assert!(!rendered.contains("s3cr3t"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }

    #[test]
    fn the_id_can_be_read_and_stamped_on_every_variant() {
        let mut requests = [
            Request::Status { id: 0 },
            Request::Stats { id: 0 },
            Request::Lock {
                id: 0,
                force: false,
            },
            Request::Events {
                id: 0,
                follow: false,
                since: 0,
            },
            Request::Ping { id: 0 },
            Request::Shutdown { id: 0 },
        ];
        for (n, request) in requests.iter_mut().enumerate() {
            request.set_id(n as u64 + 1);
            assert_eq!(request.id(), n as u64 + 1, "{}", request.op());
        }
    }

    #[test]
    fn an_error_response_carries_no_result_field() {
        let response = Response::err(4, ErrorBody::UNMOUNT_FAILED, "volume is in use");
        assert_eq!(
            json(&response),
            concat!(
                "{\"id\":4,\"ok\":false,",
                "\"error\":{\"code\":\"UNMOUNT_FAILED\",\"message\":\"volume is in use\"}}\n"
            )
        );
        assert_eq!(
            json(&Response::ok(4, serde_json::Value::Null)),
            "{\"id\":4,\"ok\":true,\"result\":null}\n"
        );
    }

    #[test]
    fn a_stream_item_round_trips() {
        let item = StreamItem {
            id: 9,
            event: EventRecord {
                seq: 2,
                timestamp: 1_757_000_000,
                kind: "DECRYPTION_FAILED".to_owned(),
                message: "cannot decrypt".to_owned(),
                cleartext_path: Some("/a/b".to_owned()),
                ciphertext_path: None,
            },
        };
        let line = json(&item);
        assert_eq!(
            line,
            concat!(
                "{\"id\":9,\"event\":{\"seq\":2,\"timestamp\":1757000000,",
                "\"kind\":\"DECRYPTION_FAILED\",\"message\":\"cannot decrypt\",",
                "\"cleartextPath\":\"/a/b\",\"ciphertextPath\":null}}\n"
            )
        );
        let back: StreamItem = serde_json::from_str(line.trim_end()).expect("round trip");
        assert_eq!(back, item);
    }

    #[test]
    fn read_line_strips_the_terminator_and_reports_eof() {
        let mut input = Cursor::new(b"{\"a\":1}\n{\"b\":2}\r\ntail".to_vec());
        assert_eq!(
            read_line(&mut input).expect("first"),
            Some("{\"a\":1}".into())
        );
        assert_eq!(
            read_line(&mut input).expect("second"),
            Some("{\"b\":2}".into())
        );
        // A last line without a terminator is still a line.
        assert_eq!(read_line(&mut input).expect("third"), Some("tail".into()));
        assert_eq!(read_line(&mut input).expect("eof"), None);
        assert_eq!(read_line(&mut input).expect("eof again"), None);
    }

    #[test]
    fn read_line_accepts_a_line_at_the_limit_and_rejects_one_beyond_it() {
        let mut at_limit = Vec::with_capacity(MAX_LINE_LEN + 1);
        at_limit.resize(MAX_LINE_LEN, b'a');
        at_limit.push(b'\n');
        let mut input = Cursor::new(at_limit);
        let line = read_line(&mut input)
            .expect("at the limit")
            .expect("a line");
        assert_eq!(line.len(), MAX_LINE_LEN);

        let mut too_long = vec![b'a'; MAX_LINE_LEN + 1];
        too_long.push(b'\n');
        let err = read_line(&mut Cursor::new(too_long)).expect_err("beyond the limit");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("exceeds"), "{err}");
    }

    #[test]
    fn read_line_accepts_a_crlf_line_at_the_limit_and_rejects_one_beyond_it() {
        let mut at_limit = vec![b'a'; MAX_LINE_LEN];
        at_limit.extend_from_slice(b"\r\n");
        let mut input = Cursor::new(at_limit);
        let line = read_line(&mut input)
            .expect("at the limit")
            .expect("a line");
        assert_eq!(line.len(), MAX_LINE_LEN);

        let mut too_long = vec![b'a'; MAX_LINE_LEN + 1];
        too_long.extend_from_slice(b"\r\n");
        let err = read_line(&mut Cursor::new(too_long)).expect_err("beyond the limit");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("exceeds"), "{err}");
    }

    #[test]
    fn read_request_decodes_an_unlock() {
        let line = concat!(
            "{\"op\":\"unlock\",\"id\":5,\"key\":\"a2V5\",\"mounter\":\"fuse\",",
            "\"mountPoint\":\"/mnt/v\",\"mountOptions\":[],\"readOnly\":false,",
            "\"volumeName\":\"V\",\"maxCleartextNameLength\":220}\n"
        );
        let mut input = Cursor::new(line.as_bytes().to_vec());
        let request = read_request(&mut input)
            .expect("decodes")
            .expect("one request");
        match &request {
            Request::Unlock {
                id,
                key,
                mounter,
                max_cleartext_name_length,
                ..
            } => {
                assert_eq!(*id, 5);
                assert_eq!(key, "a2V5");
                assert_eq!(mounter.as_deref(), Some("fuse"));
                assert_eq!(*max_cleartext_name_length, 220);
            }
            other => panic!("expected an unlock, got {other:?}"),
        }
        assert_eq!(read_request(&mut input).expect("eof").map(|r| r.op()), None);
    }

    /// A reader that hands its input out in pieces with a timeout in between -- what a socket
    /// with a read timeout looks like when a message arrives split in two.
    struct Stuttering {
        chunks: std::collections::VecDeque<&'static [u8]>,
        timeout_next: bool,
    }

    impl Read for Stuttering {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.timeout_next {
                self.timeout_next = false;
                return Err(io::Error::new(io::ErrorKind::WouldBlock, "timed out"));
            }
            match self.chunks.pop_front() {
                Some(chunk) => {
                    let n = chunk.len().min(buf.len());
                    buf[..n].copy_from_slice(&chunk[..n]);
                    self.timeout_next = true;
                    Ok(n)
                }
                None => Ok(0),
            }
        }
    }

    #[test]
    fn read_line_into_resumes_where_a_timeout_stopped_it() {
        let mut input = io::BufReader::new(Stuttering {
            chunks: [b"{\"a\":".as_slice(), b"1}\n{\"b\":2}\n".as_slice()].into(),
            timeout_next: false,
        });
        let mut buf = String::new();
        // The first half arrives, then the read times out -- and the half is still there.
        assert_eq!(
            read_line_into(&mut input, &mut buf).expect("first half"),
            LineStatus::Incomplete
        );
        assert_eq!(buf, "{\"a\":");
        assert_eq!(
            read_line_into(&mut input, &mut buf).expect("second half"),
            LineStatus::Complete
        );
        assert_eq!(buf, "{\"a\":1}", "nothing was lost across the timeout");

        buf.clear();
        assert_eq!(
            read_line_into(&mut input, &mut buf).expect("the buffered second line"),
            LineStatus::Complete
        );
        assert_eq!(buf, "{\"b\":2}");
        buf.clear();
        assert_eq!(
            read_line_into(&mut input, &mut buf).expect("a timeout with nothing pending"),
            LineStatus::Incomplete
        );
        assert_eq!(
            read_line_into(&mut input, &mut buf).expect("end of input"),
            LineStatus::Eof
        );
    }

    #[test]
    fn read_line_reports_a_timeout_as_an_error() {
        let mut input = io::BufReader::new(Stuttering {
            chunks: [b"{}\n".as_slice()].into(),
            timeout_next: true,
        });
        let err = read_line(&mut input).expect_err("a timeout on a blocking reader is an error");
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(read_line(&mut input).expect("the line"), Some("{}".into()));
    }

    #[test]
    fn a_malformed_request_never_quotes_the_payload() {
        let mut input = Cursor::new(b"{\"op\":\"unlock\",\"id\":1,\"key\":\"s3cr3t\"}\n".to_vec());
        let err = read_request(&mut input).expect_err("missing fields");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let rendered = err.to_string();
        assert!(!rendered.contains("s3cr3t"), "{rendered}");
        assert!(rendered.contains("malformed request"), "{rendered}");
    }
}
