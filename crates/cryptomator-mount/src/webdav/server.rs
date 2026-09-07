//! The loopback HTTP server that carries a [`CryptoDavFs`] -- Cryptomator's `WebDavServer` plus
//! `WebDavServletController`, with `hyper` where Java has Jetty.
//!
//! Java keeps a reference-counted map of running servers (`WebDavServerManager`) because one
//! desktop app serves many vaults through one port. A `crypto` daemon serves exactly one vault,
//! so there is one server per process and [`WebDavServerHandle`] owns it outright: the handle
//! holds the shutdown channel and the serving thread (which in turn owns the tokio runtime), and
//! dropping it takes the server down. That is what keeps a panicking test -- or a failed mount --
//! from leaving a listener behind.
use crate::api::MountError;
use crate::webdav::fs::CryptoDavFs;
use dav_server::memls::MemLs;
use dav_server::DavHandler;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use hyper_util::server::graceful::GracefulShutdown;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

/// How long [`WebDavServerHandle::start`] waits for the server to answer its first request.
pub const HEALTH_TIMEOUT: Duration = Duration::from_secs(10);
/// How often the health probe tries while it waits.
const HEALTH_POLL: Duration = Duration::from_millis(25);
/// How long one health probe waits for the connect and for the status line.
const HEALTH_CONNECT_TIMEOUT: Duration = Duration::from_millis(500);
/// How long a graceful shutdown lets open connections drain before they are cut.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
/// How long the runtime then waits for the blocking pool to run dry.
///
/// This is deliberately generous and deliberately *not* `shutdown_background`:
/// [`crate::webdav::CryptoDavFile`]'s `Drop` hands the release flush -- the last chance a body
/// written without an explicit `flush` has to reach the vault -- to `spawn_blocking`. Abandoning
/// the blocking pool at shutdown would throw those writes away.
const RUNTIME_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(60);
/// How long the accept loop pauses after an `accept` error, so a persistent one (`EMFILE`) does
/// not turn into a busy loop.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);
/// Worker threads of the server runtime. Two is enough: every byte of work happens on the
/// blocking pool, the workers only shuffle futures.
const WORKER_THREADS: usize = 2;
/// The blocking pool every `CryptoFs` call runs on.
const MAX_BLOCKING_THREADS: usize = 64;
/// How many bytes of a status line the health probe is willing to read before it gives up.
const MAX_STATUS_LINE: u64 = 4096;

/// What a server needs to know before it starts.
#[derive(Debug)]
pub struct WebDavServerConfig {
    /// The vault, as `dav-server` sees it.
    pub fs: CryptoDavFs,
    /// The address to bind, from [`crate::webdav::bind_address`]. Anything but a loopback address
    /// is refused unless [`crate::webdav::ALLOW_NONLOOPBACK_ENV`] says otherwise.
    pub bind: IpAddr,
    /// The TCP port, `0` for "any free one".
    pub port: u16,
    /// The context path from [`crate::webdav::normalize_context_path`], always starting with `/`.
    pub context_path: String,
}

/// Everything that can go wrong around the server itself.
#[derive(Debug, thiserror::Error)]
pub enum WebDavServerError {
    /// The configured address is taken -- by another `crypto` daemon, by the desktop app or by an
    /// unrelated program. The message carries the two ways out, because this is the one failure a
    /// user hits routinely; the variant is matchable so the CLI can phrase its own hint.
    #[error(
        "address {addr} is already in use; mount on a free port with `--port 0` or store one \
         with `crypto vault set <VAULT> --port <N>`"
    )]
    AddressInUse {
        /// The address that could not be bound; `addr.port()` is the port the user asked for.
        addr: SocketAddr,
    },
    /// The listener came up but nothing answered on the context path.
    #[error("the WebDAV server did not answer on {0} within {1} s")]
    NotHealthy(String, u64),
    /// The runtime or the serving thread could not be created, or the bind address is refused.
    #[error("{0}")]
    Failed(String),
    /// An I/O error surfaced unchanged.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl From<WebDavServerError> for MountError {
    /// Every server failure is a failed mount (exit code 6); the wording is the error's own, so
    /// the `--port 0` hint survives all the way to the terminal.
    fn from(err: WebDavServerError) -> Self {
        MountError::Failed(err.to_string())
    }
}

/// The prefix `dav-server` strips off a request path.
///
/// A context path of `/` (an empty volume id) becomes the *empty* prefix, which is what a root
/// servlet context is in Java too. `dav-server` 0.11.0's `DavPath::set_prefix` happens to
/// normalise `"/"` to the same zero-length prefix (`davpath.rs:180-197`), so the two are
/// equivalent today; this keeps them equivalent by construction rather than by that coincidence.
pub fn strip_prefix_for(context_path: &str) -> &str {
    if context_path == "/" {
        ""
    } else {
        context_path
    }
}

/// A running server. Dropping it stops the server.
#[derive(Debug)]
pub struct WebDavServerHandle {
    local_addr: SocketAddr,
    context_path: String,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl WebDavServerHandle {
    /// Binds, starts serving and returns once the server answers on its context path.
    ///
    /// **Blocking.** It polls the health probe on the calling thread for up to [`HEALTH_TIMEOUT`],
    /// and on the (rare) thread-spawn failure it drops the freshly built `Runtime` there too --
    /// which panics inside a runtime. Call it from a plain thread, never from an async context;
    /// wrap it in `spawn_blocking` if the caller has a runtime.
    ///
    /// The listener is bound on *this* thread with `std::net::TcpListener`, before the runtime is
    /// built: that way `EADDRINUSE` is a synchronous [`WebDavServerError::AddressInUse`] instead
    /// of something that happens later on a thread nobody is watching, and the ephemeral port that
    /// `port: 0` produces is known ([`local_addr`](Self::local_addr)) by the time this returns.
    ///
    /// # Errors
    /// [`WebDavServerError::AddressInUse`] for a taken address, [`WebDavServerError::Io`] for any
    /// other bind failure, [`WebDavServerError::Failed`] for a refused bind address or if the
    /// runtime or the thread cannot be created, and [`WebDavServerError::NotHealthy`] if nothing
    /// answers within [`HEALTH_TIMEOUT`].
    pub fn start(config: WebDavServerConfig) -> Result<Self, WebDavServerError> {
        crate::webdav::check_bind_address(config.bind)
            .map_err(|err| WebDavServerError::Failed(err.to_string()))?;
        let requested = SocketAddr::new(config.bind, config.port);
        let listener = std::net::TcpListener::bind(requested).map_err(|err| match err.kind() {
            std::io::ErrorKind::AddrInUse => WebDavServerError::AddressInUse { addr: requested },
            _ => WebDavServerError::Io(err),
        })?;
        listener.set_nonblocking(true)?;
        let local_addr = listener.local_addr()?;
        let handler = DavHandler::builder()
            .filesystem(Box::new(config.fs))
            // Class 2 locking: macOS's WebDAVFS refuses to mount a share without it, and Java
            // answers `DAV: 1, 2` through its `ExclusiveSharedLockManager`. `dav-server` answers
            // `DAV: 1,2,3,sabredav-partialupdate` -- a superset, which clients read the same way.
            .locksystem(MemLs::new())
            .strip_prefix(strip_prefix_for(&config.context_path).to_owned())
            // Java's servlet has no directory browsing; a GET on a collection is 405.
            .autoindex(false)
            .hide_symlinks(true)
            .build_handler();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(WORKER_THREADS)
            .max_blocking_threads(MAX_BLOCKING_THREADS)
            .thread_name("crypto-webdav")
            .enable_all()
            .build()
            .map_err(|e| {
                WebDavServerError::Failed(format!("cannot start the WebDAV runtime: {e}"))
            })?;
        let (shutdown, stopped) = tokio::sync::oneshot::channel();
        let worker = std::thread::Builder::new()
            .name("crypto-webdav".to_owned())
            .spawn(move || {
                runtime.block_on(serve(listener, handler, stopped));
                // Not `shutdown_background`: `CryptoDavFile`'s `Drop` defers the release flush to
                // `spawn_blocking`, and those tasks must finish before the runtime goes away.
                runtime.shutdown_timeout(RUNTIME_SHUTDOWN_TIMEOUT);
            })
            .map_err(|e| {
                WebDavServerError::Failed(format!("cannot start the WebDAV thread: {e}"))
            })?;
        let handle = Self {
            local_addr,
            context_path: config.context_path,
            shutdown: Some(shutdown),
            worker: Some(worker),
        };
        if !probe_context_root(handle.local_addr, &handle.context_path, HEALTH_TIMEOUT) {
            // `handle` goes out of scope here and its `Drop` stops what did come up.
            return Err(WebDavServerError::NotHealthy(
                handle.root_uri(),
                HEALTH_TIMEOUT.as_secs(),
            ));
        }
        log::info!("WebDAV server listening on {}", handle.root_uri());
        Ok(handle)
    }

    /// The address the server is actually bound to; the port is never `0` here.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The port the server is actually bound to.
    pub fn port(&self) -> u16 {
        self.local_addr.port()
    }

    /// The context path this server serves under.
    pub fn context_path(&self) -> &str {
        &self.context_path
    }

    /// The URL a client mounts, exactly like `WebDavServletController.getServletRootUri`:
    /// `new URI("http", null, host, port, contextPath, null, null)`. An IPv6 host is bracketed,
    /// which is what `URI` does too.
    pub fn root_uri(&self) -> String {
        let host = match self.local_addr.ip() {
            IpAddr::V4(ip) => ip.to_string(),
            IpAddr::V6(ip) => format!("[{ip}]"),
        };
        format!(
            "http://{host}:{}{}",
            self.local_addr.port(),
            self.context_path
        )
    }

    /// Whether the serving thread is still there *and* still running.
    ///
    /// A thread that ended on its own -- `serve` bails out when tokio refuses the listener --
    /// leaves the handle behind, so the mere presence of the join handle would keep answering
    /// `true` for a server that is long gone.
    pub fn is_running(&self) -> bool {
        self.worker
            .as_ref()
            .is_some_and(|worker| !worker.is_finished())
    }

    /// Stops the server and returns once it is gone.
    ///
    /// **Blocking**, for up to 65 s in the worst case (5 s drain + 60 s blocking pool), and
    /// [`Drop`](Self::drop) runs it too. Call it from a plain thread, never from an async context:
    /// it joins the serving thread, and a daemon that stops a mount from inside its own runtime
    /// would block a worker for the whole drain.
    ///
    /// Three steps, in this order: the accept loop is signalled so no new connection is taken; the
    /// open ones get 5 s to finish their request; then the runtime is torn down with 60 s for the
    /// blocking pool, which is where the deferred flushes of [`crate::webdav::CryptoDavFile`]
    /// live. Only then does the serving thread end, and only then does this return -- so the port
    /// is free and every write is on disk by the time the caller sees `Ok(())`. Calling it again
    /// does nothing.
    ///
    /// # Errors
    /// [`WebDavServerError::Failed`] if the serving thread panicked.
    pub fn stop(&mut self) -> Result<(), WebDavServerError> {
        // A dropped sender is a closed channel, which the accept loop reads the same way as a
        // sent value -- so a receiver that is already gone is not an error.
        drop(self.shutdown.take());
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        worker
            .join()
            .map_err(|_| WebDavServerError::Failed("the WebDAV server thread panicked".to_owned()))
    }
}

impl Drop for WebDavServerHandle {
    /// No test, no failed mount and no panicking daemon may leave a listener behind.
    fn drop(&mut self) {
        if let Err(err) = self.stop() {
            log::warn!("stopping the WebDAV server: {err}");
        }
    }
}

/// The accept loop: one hyper HTTP/1 connection per socket, all of them watched by one
/// [`GracefulShutdown`] so `stop()` drains instead of cutting.
async fn serve(
    listener: std::net::TcpListener,
    handler: DavHandler,
    stopped: tokio::sync::oneshot::Receiver<()>,
) {
    let listener = match tokio::net::TcpListener::from_std(listener) {
        Ok(listener) => listener,
        Err(err) => {
            log::error!("cannot hand the WebDAV listener to tokio: {err}");
            return;
        }
    };
    let graceful = GracefulShutdown::new();
    let mut stopped = std::pin::pin!(stopped);
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let stream = match accepted {
                    Ok((stream, _peer)) => stream,
                    Err(err) => {
                        // Out of descriptors, mostly. Pausing keeps this from spinning.
                        log::warn!("WebDAV accept failed: {err}");
                        tokio::time::sleep(ACCEPT_BACKOFF).await;
                        continue;
                    }
                };
                let handler = handler.clone();
                // Deliberately unbounded: no connection cap, no idle-read timeout, one task per
                // socket. The listener is loopback-only (`check_bind_address`) and unauthenticated
                // by design, so the only process that can pile sockets up here already runs as the
                // user whose vault this is. Back-pressure comes from `MAX_BLOCKING_THREADS`.
                let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                    let handler = handler.clone();
                    async move {
                        // Request paths are cleartext vault paths, so this never rises above
                        // debug.
                        log::debug!("WebDAV {} {}", request.method(), request.uri().path());
                        Ok::<_, std::convert::Infallible>(handler.handle(request).await)
                    }
                });
                let connection = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service);
                let watched = graceful.watch(connection);
                tokio::spawn(async move {
                    if let Err(err) = watched.await {
                        // A client that hangs up mid-request is routine, not a server error.
                        log::debug!("WebDAV connection ended: {err}");
                    }
                });
            }
            // Both a sent value and a dropped sender end the loop.
            _ = stopped.as_mut() => break,
        }
    }
    // Before the drain, not after it: while the listener lives, the kernel keeps completing
    // handshakes from its backlog and those clients would get a reset instead of a plain
    // `ECONNREFUSED`.
    drop(listener);
    if tokio::time::timeout(DRAIN_TIMEOUT, graceful.shutdown())
        .await
        .is_err()
    {
        log::warn!(
            "a WebDAV connection did not finish within {} s; closing anyway",
            DRAIN_TIMEOUT.as_secs()
        );
    }
}

/// Whether the server answers a `GET` on its context path within `timeout`.
///
/// A raw `TcpStream` rather than a hyper client: this runs on the *caller's* thread, which has no
/// runtime, and one status line is all that has to be read. `2xx`, `3xx` (the redirect to the
/// trailing slash) and `405` (no directory browsing) all prove that the servlet is mounted and
/// that [`crate::webdav::CryptoDavFs`]'s `metadata` answered for the root; `404` and `5xx` do
/// not, and neither does a refused connection.
pub fn probe_context_root(addr: SocketAddr, context_path: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if probe_once(addr, context_path) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(HEALTH_POLL);
    }
}

/// One `GET`; `true` if the status line says the server is up.
fn probe_once(addr: SocketAddr, context_path: &str) -> bool {
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, HEALTH_CONNECT_TIMEOUT) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(HEALTH_CONNECT_TIMEOUT));
    let _ = stream.set_write_timeout(Some(HEALTH_CONNECT_TIMEOUT));
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        if context_path.is_empty() {
            "/"
        } else {
            context_path
        },
        addr
    );
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }
    let mut status = String::new();
    // Bounded: on the way down the port may already belong to somebody else, and whoever answers
    // is not obliged to ever send a newline.
    if BufReader::new(stream.take(MAX_STATUS_LINE))
        .read_line(&mut status)
        .is_err()
    {
        return false;
    }
    healthy_status(&status)
}

/// `true` for a status line that proves the servlet is mounted.
fn healthy_status(status_line: &str) -> bool {
    let Some(code) = status_line.split_whitespace().nth(1) else {
        return false;
    };
    matches!(code.parse::<u16>(), Ok(200..=399 | 405))
}

#[cfg(all(test, feature = "webdav"))]
mod tests {
    use super::*;
    use crate::testing::{env_lock, test_fs};
    use crate::webdav::ALLOW_NONLOOPBACK_ENV;
    use std::net::Ipv4Addr;

    #[test]
    fn the_health_probe_accepts_a_redirect_and_a_405_but_not_a_404() {
        assert!(healthy_status("HTTP/1.1 200 OK"));
        assert!(healthy_status("HTTP/1.1 302 Found"));
        assert!(healthy_status("HTTP/1.1 405 Method Not Allowed"));
        assert!(!healthy_status("HTTP/1.1 404 Not Found"));
        assert!(!healthy_status("HTTP/1.1 500 Internal Server Error"));
        assert!(!healthy_status(""));
        assert!(!healthy_status("garbage"));
    }

    #[test]
    fn a_root_context_path_strips_nothing() {
        assert_eq!(strip_prefix_for("/"), "");
        assert_eq!(strip_prefix_for("/vault"), "/vault");
        assert_eq!(strip_prefix_for("/a/b"), "/a/b");
    }

    #[test]
    fn a_taken_address_names_both_ways_out() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 42427);
        let err = MountError::from(WebDavServerError::AddressInUse { addr });
        let message = err.to_string();
        assert!(message.contains("42427"), "{message}");
        assert!(message.contains("--port 0"), "{message}");
        assert!(message.contains("crypto vault set"), "{message}");
    }

    /// The server refuses a reachable address *before* it opens a socket, so this test never
    /// binds anything -- which is also why it is safe to run in the normal test job.
    #[test]
    fn a_reachable_bind_address_is_refused_before_the_socket_is_opened() {
        let _guard = env_lock();
        std::env::remove_var(ALLOW_NONLOOPBACK_ENV);
        let (_dir, fs) = test_fs();
        // TEST-NET-3, so a mistake here cannot bind anything real either.
        let err = WebDavServerHandle::start(WebDavServerConfig {
            fs: CryptoDavFs::new(fs),
            bind: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            port: 0,
            context_path: "/v".to_owned(),
        })
        .expect_err("a non-loopback address is refused");
        assert!(
            matches!(&err, WebDavServerError::Failed(message) if message.contains("loopback")),
            "{err:?}"
        );
        // The default is loopback; nothing above changed it, but say so for the next test.
        assert_eq!(
            crate::webdav::bind_address(),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
    }

    /// A serving thread that ended on its own -- `serve()` bails out when tokio refuses the
    /// listener -- leaves its join handle behind; the handle must not keep claiming to be up.
    #[test]
    fn a_serving_thread_that_ended_on_its_own_is_not_running() {
        let worker = std::thread::spawn(|| {});
        while !worker.is_finished() {
            std::thread::sleep(Duration::from_millis(1));
        }
        let handle = WebDavServerHandle {
            local_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4711),
            context_path: "/v".to_owned(),
            shutdown: None,
            worker: Some(worker),
        };
        assert!(
            !handle.is_running(),
            "the thread is gone, whatever the join handle says"
        );
    }

    /// An IPv6 loopback host has to be bracketed or the URL is unparseable.
    #[test]
    fn the_root_uri_brackets_an_ipv6_host() {
        let handle = WebDavServerHandle {
            local_addr: SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 4711),
            context_path: "/v".to_owned(),
            shutdown: None,
            worker: None,
        };
        assert_eq!(handle.root_uri(), "http://[::1]:4711/v");
        assert!(!handle.is_running());
    }
}
