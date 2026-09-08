//! The WebDAV server over HTTP: one in-process server against a temporary vault, driven with a
//! hyper client. These run in the normal test job -- they need no FUSE, no privileges and no
//! network beyond loopback.
#![cfg(feature = "webdav")]

use cryptomator_core::constants::DEFAULT_KEY_ID;
use cryptomator_core::fs::{CleartextPath, CryptoFs, CryptoFsOptions};
use cryptomator_core::{initialize, open_vault_with_key, CipherCombo, DetRng, Masterkey};
use cryptomator_mount::webdav::fs::CryptoDavFs;
use cryptomator_mount::webdav::{
    host_header_allowed, probe_context_root, strip_prefix_for, WebDavServerConfig,
    WebDavServerError, WebDavServerHandle, HEALTH_TIMEOUT,
};
use hyper::{HeaderMap, StatusCode};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;

const CTX: &str = "/dix6BcCSNSl5";

/// An empty vault in a temporary directory, opened. The directory must outlive the file system.
///
/// A copy of `cryptomator_mount::testing::test_fs`, which is `#[cfg(test)]` and therefore invisible
/// to an integration test: those link against the *library*, not against its unit-test build.
fn test_fs() -> (TempDir, Arc<CryptoFs>) {
    let dir = tempfile::tempdir().expect("temp dir");
    let key = Masterkey::from_raw([0x42; 64]);
    initialize(
        dir.path(),
        &key,
        CipherCombo::SivGcm,
        220,
        DEFAULT_KEY_ID,
        &mut DetRng::default(),
    )
    .expect("initialize vault");
    let opened = open_vault_with_key(dir.path(), key).expect("open vault");
    (
        dir,
        Arc::new(CryptoFs::open(opened, CryptoFsOptions::default())),
    )
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("client runtime")
}

/// A server on an ephemeral port serving `fs` under [`CTX`].
///
/// Port 0 throughout: a fixed port would collide with whatever else this machine is running, and
/// with the other tests in this file, which cargo runs in parallel threads of one process.
fn server(fs: Arc<CryptoFs>) -> WebDavServerHandle {
    server_at(fs, CTX)
}

/// The same, under `context_path`.
fn server_at(fs: Arc<CryptoFs>, context_path: &str) -> WebDavServerHandle {
    WebDavServerHandle::start(WebDavServerConfig {
        fs: CryptoDavFs::new(fs),
        bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port: 0,
        context_path: context_path.to_owned(),
    })
    .expect("the server starts on an ephemeral port")
}

/// One request over a fresh connection; returns status, headers and the body as a string.
///
/// The `Host` is the address that was dialled, which is what every real client sends and what
/// [`host_header_allowed`] therefore has to accept; [`send_with_host`] overrides it.
async fn send(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &'static [u8],
) -> (StatusCode, HeaderMap, String) {
    send_with_host(addr, &addr.to_string(), method, path, headers, body).await
}

/// The same, with a `Host` header of our choosing.
async fn send_with_host(
    addr: SocketAddr,
    host: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &'static [u8],
) -> (StatusCode, HeaderMap, String) {
    let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .expect("handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let mut builder = hyper::Request::builder()
        .method(method)
        .uri(path)
        .header("host", host);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder
        .body(http_body_util::Full::new(bytes::Bytes::from_static(body)))
        .expect("request");
    let response = sender.send_request(request).await.expect("response");
    let (parts, body) = response.into_parts();
    let collected = http_body_util::BodyExt::collect(body)
        .await
        .expect("body")
        .to_bytes();
    (
        parts.status,
        parts.headers,
        String::from_utf8_lossy(&collected).into_owned(),
    )
}

#[test]
fn a_context_path_of_slash_becomes_an_empty_strip_prefix() {
    // `strip_prefix("/")` would eat the leading slash of every request path.
    assert_eq!(strip_prefix_for("/"), "");
    assert_eq!(strip_prefix_for(CTX), CTX);
}

#[test]
fn the_server_reports_the_port_it_actually_bound_and_the_root_uri() {
    let (_dir, fs) = test_fs();
    let handle = server(fs);
    assert_ne!(handle.port(), 0, "port 0 means: tell me which one you got");
    assert_eq!(handle.local_addr().ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(handle.context_path(), CTX);
    assert_eq!(
        handle.root_uri(),
        format!("http://127.0.0.1:{}{CTX}", handle.port())
    );
    assert!(handle.is_running());
}

/// A volume id of `""` normalises to `/`, which is a reachable configuration -- and the one that
/// `strip_prefix` must be *empty* for, or `DavPath` mis-parses every request path.
#[test]
fn a_root_context_path_serves_the_vault_at_the_server_root() {
    let (_dir, fs) = test_fs();
    let handle = server_at(Arc::clone(&fs), "/");
    let addr = handle.local_addr();
    assert_eq!(
        handle.root_uri(),
        format!("http://127.0.0.1:{}/", handle.port())
    );
    runtime().block_on(async move {
        let (status, _, body) = send(addr, "PROPFIND", "/", &[("depth", "0")], b"").await;
        assert_eq!(status, StatusCode::MULTI_STATUS);
        assert!(
            body.contains("<D:href>/</D:href>"),
            "the root's own href is a bare slash: {body}"
        );

        let (status, _, _) = send(addr, "PUT", "/x.txt", &[], b"at the root").await;
        assert_eq!(status, StatusCode::CREATED);
        let (status, _, body) = send(addr, "GET", "/x.txt", &[], b"").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "at the root");
    });
    assert_eq!(
        fs.read_file(&CleartextPath::parse("/x.txt"))
            .expect("read back"),
        b"at the root"
    );
}

#[test]
fn propfind_lists_the_vault_at_depth_zero_and_one() {
    let (_dir, fs) = test_fs();
    fs.create_dir(&CleartextPath::parse("/sub")).expect("mkdir");
    fs.write_file(&CleartextPath::parse("/hello.txt"), b"hello dav", false)
        .expect("write");
    let handle = server(Arc::clone(&fs));
    let addr = handle.local_addr();
    runtime().block_on(async move {
        let (status, _, body) = send(addr, "PROPFIND", CTX, &[("depth", "0")], b"").await;
        assert_eq!(status, StatusCode::MULTI_STATUS);
        assert!(body.contains("<D:collection"), "{body}");
        assert!(
            !body.contains("hello.txt"),
            "depth 0 is the root alone: {body}"
        );

        let (status, _, body) = send(addr, "PROPFIND", CTX, &[("depth", "1")], b"").await;
        assert_eq!(status, StatusCode::MULTI_STATUS);
        assert!(body.contains("hello.txt"), "{body}");
        assert!(body.contains("sub"), "{body}");
        assert!(
            body.contains(&format!("{CTX}/hello.txt")),
            "hrefs carry the context path: {body}"
        );
        assert!(body.contains("<D:getcontentlength>9<"), "{body}");
    });
}

#[test]
fn put_get_and_a_ranged_get_move_bytes_through_the_vault() {
    let (_dir, fs) = test_fs();
    let handle = server(Arc::clone(&fs));
    let addr = handle.local_addr();
    runtime().block_on(async move {
        let (status, _, _) = send(addr, "PUT", &format!("{CTX}/put.bin"), &[], b"0123456789").await;
        assert!(status.is_success(), "{status}");

        let (status, headers, body) = send(addr, "GET", &format!("{CTX}/put.bin"), &[], b"").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "0123456789");
        assert_eq!(
            headers.get("accept-ranges").and_then(|v| v.to_str().ok()),
            Some("bytes"),
            "every GET advertises byte ranges, like Java's AcceptRangeFilter"
        );

        let (status, headers, body) = send(
            addr,
            "GET",
            &format!("{CTX}/put.bin"),
            &[("range", "bytes=3-6")],
            b"",
        )
        .await;
        assert_eq!(status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(body, "3456");
        assert_eq!(
            headers.get("content-range").and_then(|v| v.to_str().ok()),
            Some("bytes 3-6/10")
        );

        // A client asks HEAD before it downloads; it must get the size and no body.
        let (status, headers, body) = send(addr, "HEAD", &format!("{CTX}/put.bin"), &[], b"").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers.get("content-length").and_then(|v| v.to_str().ok()),
            Some("10")
        );
        assert!(body.is_empty(), "a HEAD has no body: {body:?}");
    });
    assert_eq!(
        fs.read_file(&CleartextPath::parse("/put.bin"))
            .expect("read back"),
        b"0123456789"
    );
}

#[test]
fn mkcol_move_copy_and_delete_reach_the_vault() {
    let (_dir, fs) = test_fs();
    let handle = server(Arc::clone(&fs));
    let addr = handle.local_addr();
    let root = handle.root_uri();
    runtime().block_on(async move {
        let (status, _, _) = send(addr, "MKCOL", &format!("{CTX}/coll"), &[], b"").await;
        assert_eq!(status, StatusCode::CREATED);
        // RFC 4918 9.3.1: the collection is already there, and its parent is not.
        let (status, _, _) = send(addr, "MKCOL", &format!("{CTX}/coll"), &[], b"").await;
        assert_eq!(
            status,
            StatusCode::METHOD_NOT_ALLOWED,
            "MKCOL on an existing collection"
        );
        let (status, _, _) = send(addr, "MKCOL", &format!("{CTX}/nope/deep"), &[], b"").await;
        assert_eq!(status, StatusCode::CONFLICT, "MKCOL without a parent");

        let (status, _, _) = send(addr, "PUT", &format!("{CTX}/coll/a.txt"), &[], b"body").await;
        assert!(status.is_success(), "{status}");

        let destination = format!("{root}/coll/b.txt");
        let (status, _, _) = send(
            addr,
            "COPY",
            &format!("{CTX}/coll/a.txt"),
            &[("destination", &destination), ("overwrite", "T")],
            b"",
        )
        .await;
        assert!(status.is_success(), "{status}");

        // `Overwrite: F` onto a target that exists is a precondition failure, not a clobber.
        let destination = format!("{root}/coll/a.txt");
        let (status, _, _) = send(
            addr,
            "MOVE",
            &format!("{CTX}/coll/b.txt"),
            &[("destination", &destination), ("overwrite", "F")],
            b"",
        )
        .await;
        assert_eq!(
            status,
            StatusCode::PRECONDITION_FAILED,
            "Overwrite: F protects the target"
        );

        let destination = format!("{root}/moved.txt");
        let (status, _, _) = send(
            addr,
            "MOVE",
            &format!("{CTX}/coll/b.txt"),
            &[("destination", &destination), ("overwrite", "T")],
            b"",
        )
        .await;
        assert!(status.is_success(), "{status}");

        let (status, _, _) = send(addr, "DELETE", &format!("{CTX}/coll"), &[], b"").await;
        assert!(status.is_success(), "{status}");
        let (status, _, _) = send(addr, "GET", &format!("{CTX}/coll/a.txt"), &[], b"").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    });
    assert_eq!(
        fs.read_file(&CleartextPath::parse("/moved.txt"))
            .expect("the MOVE landed"),
        b"body"
    );
    assert!(
        fs.symlink_metadata(&CleartextPath::parse("/coll")).is_err(),
        "the DELETE took the whole collection"
    );
}

/// macOS and Windows clients refuse to mount a share without class 2 locking; Java answers
/// `DAV: 1, 2` and installs an `ExclusiveSharedLockManager`.
#[test]
fn options_advertises_class_two_and_lock_unlock_round_trips() {
    let (_dir, fs) = test_fs();
    let handle = server(Arc::clone(&fs));
    let addr = handle.local_addr();
    runtime().block_on(async move {
        let (status, headers, _) = send(addr, "OPTIONS", CTX, &[], b"").await;
        assert!(status.is_success(), "{status}");
        let dav = headers
            .get("dav")
            .expect("a DAV header")
            .to_str()
            .expect("ascii");
        assert!(dav.starts_with("1,2"), "class 2 is required: {dav}");
        assert!(
            headers
                .get("allow")
                .expect("an Allow header")
                .to_str()
                .expect("ascii")
                .contains("LOCK"),
            "LOCK is offered"
        );

        let (status, _, _) = send(addr, "PUT", &format!("{CTX}/locked.txt"), &[], b"x").await;
        assert!(status.is_success(), "{status}");
        let (status, headers, body) = send(
            addr,
            "LOCK",
            &format!("{CTX}/locked.txt"),
            &[("timeout", "Second-30")],
            br#"<?xml version="1.0" encoding="utf-8" ?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype><D:owner>crypto</D:owner></D:lockinfo>"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let token = headers
            .get("lock-token")
            .expect("a Lock-Token header")
            .to_str()
            .expect("ascii")
            .to_owned();
        let (status, _, _) = send(
            addr,
            "UNLOCK",
            &format!("{CTX}/locked.txt"),
            &[("lock-token", &token)],
            b"",
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    });
}

/// The health probe's contract: a GET on the context root is 302 (redirect to the trailing slash)
/// or 405 (no directory browsing) -- both mean "the server is up", 404 and 5xx do not.
#[test]
fn a_get_on_the_context_root_is_not_a_directory_listing() {
    let (_dir, fs) = test_fs();
    let handle = server(fs);
    let addr = handle.local_addr();
    runtime().block_on(async move {
        let (status, _, _) = send(addr, "GET", &format!("{CTX}/"), &[], b"").await;
        assert_eq!(
            status,
            StatusCode::METHOD_NOT_ALLOWED,
            "autoindex is off, like Java's servlet"
        );
    });
    assert!(probe_context_root(addr, CTX, HEALTH_TIMEOUT));
}

#[test]
fn a_second_server_on_the_same_port_reports_the_port_as_taken() {
    let (_dir, fs) = test_fs();
    let first = server(Arc::clone(&fs));
    let port = first.port();
    let err = WebDavServerHandle::start(WebDavServerConfig {
        fs: CryptoDavFs::new(Arc::clone(&fs)),
        bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port,
        context_path: CTX.to_owned(),
    })
    .expect_err("the port is taken");
    assert!(
        matches!(err, WebDavServerError::AddressInUse { addr } if addr.port() == port),
        "{err:?}"
    );
    let message = err.to_string();
    assert!(message.contains("--port 0"), "{message}");
    assert!(message.contains("vault set"), "{message}");
}

#[test]
fn stopping_the_server_frees_the_port_and_is_idempotent() {
    let (_dir, fs) = test_fs();
    let mut handle = server(fs);
    let addr = handle.local_addr();
    handle.stop().expect("stop");
    assert!(!handle.is_running());
    handle.stop().expect("stopping twice is a no-op");
    assert!(
        !probe_context_root(addr, CTX, Duration::from_millis(300)),
        "nothing answers on the port any more"
    );
    std::net::TcpListener::bind(addr).expect("the port is free again");
}

#[test]
fn dropping_the_handle_stops_the_server() {
    let (_dir, fs) = test_fs();
    let addr = {
        let handle = server(fs);
        handle.local_addr()
    };
    // `Drop` is the only thing that can have stopped it, and a test that panics half way through
    // relies on exactly this.
    std::net::TcpListener::bind(addr).expect("the port is free again");
}

/// How much of the announced body the two half-sent PUTs below start with.
const PARTIAL_BODY: usize = 256 * 1024;

/// Waits until the accept loop is provably closed: a *brand new* connection no longer gets a
/// status line, because `stop()` dropped the listener before it started draining. That is the
/// signal the drain test needs -- and it is an assertion in itself, where a fixed sleep was not.
fn wait_until_not_accepting(addr: SocketAddr) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while probe_context_root(addr, CTX, Duration::ZERO) {
        assert!(
            std::time::Instant::now() < deadline,
            "the accept loop never closed"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Waits until the server has opened `path`, i.e. until the PUT really is in flight.
fn wait_until_open(fs: &CryptoFs, path: &CleartextPath) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while fs.symlink_metadata(path).is_err() {
        assert!(
            std::time::Instant::now() < deadline,
            "the PUT never started"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// `stop()` drains rather than cuts: a request that is half-way through its body when the stop is
/// signalled still gets to finish, and its answer still reaches the client.
#[test]
fn stopping_drains_a_request_that_is_still_in_flight() {
    use std::io::{BufRead, BufReader, Write};

    let (_dir, fs) = test_fs();
    let handle = server(Arc::clone(&fs));
    let addr = handle.local_addr();
    let path = CleartextPath::parse("/slow.bin");

    let mut stream = std::net::TcpStream::connect(addr).expect("connect");
    let head = format!(
        "PUT {CTX}/slow.bin HTTP/1.1\r\nHost: {addr}\r\nContent-Length: {}\r\n\r\n",
        PARTIAL_BODY * 2
    );
    stream.write_all(head.as_bytes()).expect("headers");
    stream
        .write_all(&vec![b'a'; PARTIAL_BODY])
        .expect("first half");
    stream.flush().expect("flush");
    wait_until_open(&fs, &path);

    // Stop while the body is still arriving. The accept loop ends at once; this connection does
    // not, and `stop()` blocks in the drain until it is done.
    let stopper = std::thread::spawn(move || {
        let mut handle = handle;
        handle.stop().expect("stop");
    });
    wait_until_not_accepting(addr);

    stream
        .write_all(&vec![b'b'; PARTIAL_BODY])
        .expect("the drained connection still takes the second half");
    stream.flush().expect("flush");
    let mut status = String::new();
    BufReader::new(&stream)
        .read_line(&mut status)
        .expect("a status line");
    assert!(status.starts_with("HTTP/1.1 201"), "{status:?}");
    drop(stream);
    stopper.join().expect("the stopping thread");

    let body = fs.read_file(&path).expect("the whole body landed");
    assert_eq!(body.len(), PARTIAL_BODY * 2);
    assert_eq!(body[PARTIAL_BODY], b'b');
}

/// A body a client never gets to flush still has to reach the vault.
///
/// `dav-server`'s `handle_put` flushes on the happy path, so only an *aborted* PUT exercises the
/// deferred release: the body errors out, `CryptoDavFile` is dropped unflushed and its `Drop`
/// hands the flush to `spawn_blocking`. Tearing the runtime down without waiting for that pool
/// (`shutdown_background`) throws those bytes away, which is why `stop()` does not.
#[test]
fn an_aborted_put_is_still_on_disk_once_the_server_has_stopped() {
    use std::io::Write;

    let (_dir, fs) = test_fs();
    let mut handle = server(Arc::clone(&fs));
    let addr = handle.local_addr();
    let path = CleartextPath::parse("/aborted.bin");

    let mut stream = std::net::TcpStream::connect(addr).expect("connect");
    // Announce four times what we are going to send, then hang up: `handle_put` writes everything
    // that did arrive and then fails on the premature end of the body.
    let head = format!(
        "PUT {CTX}/aborted.bin HTTP/1.1\r\nHost: {addr}\r\nContent-Length: {}\r\n\r\n",
        PARTIAL_BODY * 4
    );
    stream.write_all(head.as_bytes()).expect("headers");
    stream.write_all(&vec![b'z'; PARTIAL_BODY]).expect("body");
    stream.flush().expect("flush");

    // Wait until the server has opened the file, so that `stop()` cannot outrun the accept loop.
    wait_until_open(&fs, &path);
    drop(stream);

    handle.stop().expect("stop");
    assert_eq!(
        fs.read_file(&path)
            .expect("the partial body survived")
            .len(),
        PARTIAL_BODY,
        "every byte that reached the server before the abort is in the vault"
    );
}

/// The `Host` rule, at the level the server applies it: a literal address (with or without a
/// port, brackets and all) or the name `localhost` -- and nothing else, because a name that is
/// not `localhost` can only have got here through DNS, which is what a rebinding attack uses.
#[test]
fn only_a_literal_address_or_localhost_is_an_acceptable_host() {
    for allowed in [
        "127.0.0.1",
        "127.0.0.1:42427",
        "localhost",
        "LocalHost:42427",
        "[::1]",
        "[::1]:42427",
        "::1",
        "0:0:0:0:0:0:0:1",
    ] {
        assert!(
            host_header_allowed(allowed),
            "{allowed} is a client of ours"
        );
    }
    for refused in [
        "evil.example",
        "evil.example:42427",
        "localhost.evil.example",
        "vault.localhost",
        "[::1",
        "[::1]x",
        "[::1]:notaport",
        "127.0.0.1:notaport",
        "localhost:",
        "127.0.0.1:",
        "[::1]:",
        "",
    ] {
        assert!(!host_header_allowed(refused), "{refused} is not");
    }
}

/// DNS rebinding, end to end: a page served from a name the attacker controls sends that name as
/// its `Host`, and the server answers `400` with nothing in the body. The addresses a real client
/// sends -- the dialled `127.0.0.1:<port>`, the `localhost` that `cli_daemon.rs` uses, and the
/// bracketed IPv6 form -- all still reach the vault.
#[test]
fn a_foreign_host_header_is_refused_and_the_real_ones_are_not() {
    let (_dir, fs) = test_fs();
    let handle = server(fs);
    let addr = handle.local_addr();
    let port = handle.port();
    runtime().block_on(async move {
        let (status, _, body) = send_with_host(
            addr,
            "evil.example",
            "PROPFIND",
            CTX,
            &[("depth", "0")],
            b"",
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.is_empty(), "nothing leaks in the body: {body:?}");

        for host in [
            format!("127.0.0.1:{port}"),
            "localhost".to_owned(),
            format!("[::1]:{port}"),
        ] {
            let (status, _, _) =
                send_with_host(addr, &host, "PROPFIND", CTX, &[("depth", "0")], b"").await;
            assert_eq!(status, StatusCode::MULTI_STATUS, "Host: {host}");
        }
    });
}

/// An HTTP/1.0 request carries no `Host` at all, and RFC 7230 lets it: an absent header is served,
/// because a browser's rebinding machinery cannot produce one.
#[test]
fn a_request_without_a_host_header_is_served() {
    use std::io::{BufRead, BufReader, Write};

    let (_dir, fs) = test_fs();
    let handle = server(fs);
    let addr = handle.local_addr();
    let mut stream = std::net::TcpStream::connect(addr).expect("connect");
    stream
        .write_all(
            format!("PROPFIND {CTX} HTTP/1.0\r\nDepth: 0\r\nContent-Length: 0\r\n\r\n").as_bytes(),
        )
        .expect("request");
    stream.flush().expect("flush");
    let mut status = String::new();
    BufReader::new(&stream)
        .read_line(&mut status)
        .expect("a status line");
    // hyper answers an HTTP/1.0 request in kind, hence the version is not pinned here.
    assert!(status.starts_with("HTTP/1.0 207"), "{status:?}");
}

/// The `Content-Range` PUT, through `handle_put`'s own header parsing rather than a hand-made
/// `seek`: it must patch the named bytes and leave everything around them -- and the file's
/// length -- alone. `truncate = options.truncate` in `CryptoDavFs::open` is what makes that work;
/// the defect it replaced wiped the file.
#[test]
fn a_content_range_put_patches_bytes_in_place() {
    let (_dir, fs) = test_fs();
    let handle = server(Arc::clone(&fs));
    let addr = handle.local_addr();
    runtime().block_on(async move {
        let (status, _, _) =
            send(addr, "PUT", &format!("{CTX}/patch.bin"), &[], b"0123456789").await;
        assert!(status.is_success(), "{status}");

        let (status, _, _) = send(
            addr,
            "PUT",
            &format!("{CTX}/patch.bin"),
            &[("content-range", "bytes 2-4/*")],
            b"XYZ",
        )
        .await;
        assert!(status.is_success(), "{status}");

        let (status, _, body) = send(addr, "GET", &format!("{CTX}/patch.bin"), &[], b"").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "01XYZ56789", "only bytes 2..=4 changed");
    });
    assert_eq!(
        fs.read_file(&CleartextPath::parse("/patch.bin"))
            .expect("read back"),
        b"01XYZ56789",
        "and the file is no longer or shorter than it was"
    );
}

/// The conditional PUTs, whose status depends on this adapter's `FsError` mapping rather than on
/// `dav-server`: `If-None-Match: *` sets `create_new`, so an existing file has to come back as
/// `412` and not as the `409` a plain `Exists` would give; `If-Match: *` clears `create`, so a
/// missing file is `412` too.
#[test]
fn conditional_puts_answer_412_rather_than_409() {
    let (_dir, fs) = test_fs();
    let handle = server(Arc::clone(&fs));
    let addr = handle.local_addr();
    runtime().block_on(async move {
        let (status, _, _) = send(addr, "PUT", &format!("{CTX}/cond.bin"), &[], b"first").await;
        assert_eq!(status, StatusCode::CREATED);

        let (status, _, _) = send(
            addr,
            "PUT",
            &format!("{CTX}/cond.bin"),
            &[("if-none-match", "*")],
            b"second",
        )
        .await;
        assert_eq!(
            status,
            StatusCode::PRECONDITION_FAILED,
            "`If-None-Match: *` on a file that exists"
        );

        let (status, _, _) = send(
            addr,
            "PUT",
            &format!("{CTX}/missing.bin"),
            &[("if-match", "*")],
            b"nope",
        )
        .await;
        assert_eq!(
            status,
            StatusCode::PRECONDITION_FAILED,
            "`If-Match: *` on a file that does not exist"
        );
    });
    assert_eq!(
        fs.read_file(&CleartextPath::parse("/cond.bin"))
            .expect("read back"),
        b"first",
        "the refused PUT wrote nothing"
    );
    assert!(
        fs.symlink_metadata(&CleartextPath::parse("/missing.bin"))
            .is_err(),
        "and neither did the other one"
    );
}
