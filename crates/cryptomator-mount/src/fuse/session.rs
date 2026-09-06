//! The handle on a running FUSE session.
//!
//! [`fuser::Session`] owns the event loop; this wraps it in the shape the mount services need: a
//! background thread that serves requests, a caller-supplied way of taking the mount down (the
//! unmount command differs per back end -- FUSE-T mounts NFS, libfuse3 uses `fusermount3`), and a
//! bounded wait for the session thread to notice.
//!
//! The wait matters because a FUSE session does not end when `umount` returns; it ends when the
//! kernel (or FUSE-T's NFS server) closes the channel, which it does only once the last request is
//! answered. Spike C found that FUSE-T signals this with EOF rather than with a `DESTROY` message,
//! so `Ok(())` out of the event loop is the one signal that the mount is really gone.
use super::adapter::CryptoFuse;
use super::ops::VaultOps;
use crate::api::UnmountError;
use fuser::{BackgroundSession, Config, KernelAbi, MountOption, Session, SessionACL};
use std::fmt;
use std::io;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// How long [`FuseSessionHandle::unmount`] waits for the session thread to end before it reports
/// the mount as busy.
const UNMOUNT_TIMEOUT: Duration = Duration::from_secs(10);

/// Takes the mount down. The `bool` is `forced`: a forced unmount may drop buffered writes, which
/// is why it is a separate request rather than an automatic retry.
///
/// The back end supplies this because there is no portable way to unmount: FUSE-T's mount is an
/// NFS mount (`umount`), libfuse3's needs `fusermount3 -u`, and macFUSE has `umount` again.
pub type Unmounter = Box<dyn Fn(bool) -> Result<(), UnmountError> + Send>;

/// The session thread, in whichever stage of ending it is.
#[derive(Debug)]
enum SessionState {
    /// Serving requests.
    Running(BackgroundSession),
    /// Ending: a helper thread is blocked in `join` and will deliver the result here. The wait is
    /// off the caller's thread so [`FuseSessionHandle::unmount`] can time out, and it is resumable
    /// so a forced unmount after a timed-out graceful one keeps waiting for the same session.
    Ending(Receiver<io::Result<()>>),
    /// Ended; this is the event loop's verdict.
    Ended(io::Result<()>),
}

/// A mounted vault's live FUSE session.
///
/// Dropping the handle drops the [`BackgroundSession`], which unmounts and joins -- but without a
/// timeout and without the back end's own unmount command. Prefer [`FuseSessionHandle::unmount`].
pub struct FuseSessionHandle {
    session: SessionState,
    ops: Arc<VaultOps>,
    mountpoint: PathBuf,
    unmounter: Unmounter,
}

impl fmt::Debug for FuseSessionHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FuseSessionHandle")
            .field("session", &self.session)
            .field("mountpoint", &self.mountpoint)
            .finish_non_exhaustive() // the unmounter is a closure
    }
}

impl FuseSessionHandle {
    /// Serves `ops` on an already mounted `/dev/fuse`-style descriptor.
    ///
    /// This is the FUSE-T and macFUSE path: the back end mounted the volume itself (through
    /// `fuse_mount_compat25` in the library it loaded) and hands over the fd it got, together with
    /// the `mountpoint` it used. `abi` says which struct layouts the peer expects --
    /// [`KernelAbi::Linux`] for FUSE-T even on macOS, see
    /// `docs/superpowers/spikes/2026-09-06-spike-c-fuse-t-linux-abi.md`.
    ///
    /// # Errors
    /// Returns the error of the FUSE handshake on `fd`, or of spawning the session thread.
    pub fn spawn_from_fd(
        ops: Arc<VaultOps>,
        mountpoint: PathBuf,
        fd: OwnedFd,
        abi: KernelAbi,
        unmounter: Unmounter,
    ) -> io::Result<Self> {
        // `Config` is `#[non_exhaustive]`, so it can only be built by assignment. `n_threads`
        // stays at the default of one: the event loop is the only thing serialising the vault.
        // `config.acl` is not set: `from_fd` takes the ACL as its own argument and ignores the
        // one in the config (which only `Session::new`, the mounting constructor, reads).
        let mut config = Config::default();
        config.abi = abi;
        let fs = CryptoFuse::new(Arc::clone(&ops));
        let session = Session::from_fd(fs, fd, SessionACL::Owner, config)?;
        Ok(Self::new(session.spawn()?, ops, mountpoint, unmounter))
    }

    /// Mounts `ops` at `mountpoint` through fuser itself and serves it.
    ///
    /// This is the libfuse3 path on Linux. On macOS the vendored fuser is built with
    /// `macos-no-mount`, where this always fails: there the back ends mount themselves and use
    /// [`spawn_from_fd`](Self::spawn_from_fd).
    ///
    /// # Errors
    /// Returns the error of the mount, of the FUSE handshake, or of spawning the session thread.
    pub fn spawn_mounted(
        ops: Arc<VaultOps>,
        mountpoint: PathBuf,
        options: Vec<MountOption>,
        acl: SessionACL,
        unmounter: Unmounter,
    ) -> io::Result<Self> {
        // See `spawn_from_fd` on why `Config` is built field by field. `abi` stays
        // `KernelAbi::Native`: this path talks to a real kernel driver.
        let mut config = Config::default();
        config.mount_options = options;
        config.acl = acl;
        let fs = CryptoFuse::new(Arc::clone(&ops));
        let session = Session::new(fs, &mountpoint, &config)?;
        Ok(Self::new(session.spawn()?, ops, mountpoint, unmounter))
    }

    fn new(
        bg: BackgroundSession,
        ops: Arc<VaultOps>,
        mountpoint: PathBuf,
        unmounter: Unmounter,
    ) -> Self {
        Self {
            session: SessionState::Running(bg),
            ops,
            mountpoint,
            unmounter,
        }
    }

    /// Where the volume is mounted.
    pub fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }

    /// Whether any file is still open. An unmount would lose their buffered writes, so the mount
    /// service asks before it offers a graceful unmount.
    pub fn is_in_use(&self) -> bool {
        self.ops.is_in_use()
    }

    /// Takes the mount down and waits up to ten seconds for the session thread to end.
    ///
    /// # Errors
    /// The unmounter's own error, or [`UnmountError::Busy`] if the session was still serving
    /// requests when the wait ran out. A graceful unmount that reports `Busy` can be repeated with
    /// `forced == true`; that runs the back end's forced unmount and keeps waiting for the same
    /// session rather than starting over.
    pub fn unmount(&mut self, forced: bool) -> Result<(), UnmountError> {
        self.unmount_within(forced, UNMOUNT_TIMEOUT)
    }

    /// [`unmount`](Self::unmount) with the wait spelled out, so the tests need not take ten
    /// seconds to observe a timeout.
    fn unmount_within(&mut self, forced: bool, timeout: Duration) -> Result<(), UnmountError> {
        if !matches!(self.session, SessionState::Ended(_)) {
            (self.unmounter)(forced)?;
        }
        self.wait_for_end(timeout);
        match self.session {
            SessionState::Ended(_) => Ok(()),
            // Still serving. A forced unmount has already done everything it can -- the volume is
            // gone from the namespace even if the thread has not noticed yet -- so it does not
            // report a failure the caller could not act on anyway.
            _ if forced => Ok(()),
            _ => Err(UnmountError::Busy),
        }
    }

    /// Waits for the session thread, giving up after `timeout`. The handle ends up in
    /// [`SessionState::Ended`] if the thread ended and stays in [`SessionState::Ending`] if not.
    fn wait_for_end(&mut self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        self.start_joining();
        let SessionState::Ending(rx) = &self.session else {
            return; // already ended
        };
        match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(result) => self.session = SessionState::Ended(result),
            Err(RecvTimeoutError::Timeout) => {} // stays `Ending`, so a retry keeps waiting
            Err(RecvTimeoutError::Disconnected) => {
                self.session = SessionState::Ended(Err(thread_lost()));
            }
        }
    }

    /// Moves a running session onto a helper thread that blocks in `join`.
    ///
    /// That thread outlives the handle if the session never ends -- a mount the kernel refuses to
    /// let go of. It holds nothing but the session it is waiting for, and the alternative is
    /// blocking the caller forever.
    fn start_joining(&mut self) {
        // The placeholder is only observed if the state was `Running`, in which case every arm
        // below overwrites it.
        match std::mem::replace(&mut self.session, SessionState::Ended(Ok(()))) {
            SessionState::Running(bg) => {
                let (tx, rx) = mpsc::channel();
                let joining = thread::Builder::new()
                    .name("crypto-fuse-join".to_owned())
                    .spawn(move || {
                        let _ = tx.send(bg.join());
                    });
                self.session = match joining {
                    Ok(_) => SessionState::Ending(rx),
                    // No thread to wait on it; reporting the session as ended beats hanging.
                    Err(e) => SessionState::Ended(Err(e)),
                };
            }
            other => self.session = other,
        }
    }

    /// Waits for the session to end, however long it takes, and reports what the event loop
    /// returned. A clean unmount is `Ok(())` -- including the EOF FUSE-T ends with.
    ///
    /// # Errors
    /// The event loop's error, if it ended with one.
    pub fn join(self) -> io::Result<()> {
        match self.session {
            SessionState::Running(bg) => bg.join(),
            SessionState::Ending(rx) => rx.recv().map_err(|_| thread_lost())?,
            SessionState::Ended(result) => result,
        }
    }
}

fn thread_lost() -> io::Error {
    io::Error::other("the FUSE session thread ended without a result")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flags::AdapterOptions;
    use crate::fuse::ops::VaultOpsConfig;
    use crate::transcoder::{FuseNormalization, NameTranscoder};
    use cryptomator_core::constants::DEFAULT_KEY_ID;
    use cryptomator_core::fs::{CryptoFs, CryptoFsOptions};
    use cryptomator_core::{initialize, open_vault_with_key, CipherCombo, DetRng, Masterkey};
    use fuser::OpenFlags;
    use std::ffi::OsStr;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::TempDir;

    /// The mount services hand the handle around as a `Box<dyn Mount>`, which is `Send`.
    ///
    /// It is deliberately not `Sync`: [`Unmounter`] is a `Send`-only boxed closure, because the
    /// back ends build it from whatever their dynamically loaded library gives them. Nothing
    /// shares a `&FuseSessionHandle` between threads -- the session thread lives inside it.
    fn assert_send<T: Send>() {}

    #[test]
    fn the_handle_can_be_moved_between_threads() {
        assert_send::<FuseSessionHandle>();
        assert_send::<Unmounter>();
    }

    // --- a real session over a socket pair -------------------------------------------------
    //
    // A socket is also what FUSE-T gives us instead of `/dev/fuse` (spike C), so this exercises
    // the transport the macOS back end will use, down to the EOF that ends the session.

    /// How long a test waits for one reply from the session thread. Generous enough for a loaded
    /// CI machine, short enough that a regression reports a failure instead of hanging the suite.
    const PEER_READ_TIMEOUT: Duration = Duration::from_secs(5);

    /// `fuse_in_header`: len, opcode, unique, nodeid, uid, gid, pid, padding.
    const IN_HEADER: usize = 40;
    /// `fuse_out_header`: len, error, unique.
    const OUT_HEADER: usize = 16;
    /// `fuse_attr_out` = `attr_valid`(8) + `attr_valid_nsec`(4) + dummy(4), then `fuse_attr`.
    const ATTR_OUT_PREFIX: usize = 16;
    /// `fuse_entry_out` = nodeid(8) + generation(8) + two TTLs (16) + two nsec (8), then
    /// `fuse_attr`.
    const ENTRY_OUT_PREFIX: usize = 40;
    /// Offsets inside the 88-byte Linux `fuse_attr`.
    const ATTR_SIZE: usize = 8;
    const ATTR_MODE: usize = 60;
    const ATTR_NLINK: usize = 64;
    const ATTR_UID: usize = 68;
    const S_IFMT: u32 = 0o170000;

    const FUSE_LOOKUP: u32 = 1;
    const FUSE_GETATTR: u32 = 3;
    const FUSE_INIT: u32 = 26;
    const FUSE_OPENDIR: u32 = 27;
    const FUSE_READDIR: u32 = 28;
    const FUSE_RELEASEDIR: u32 = 29;
    const FUSE_READDIRPLUS: u32 = 44;
    /// `fuse_dirent` = ino(8) + off(8) + namelen(4) + typ(4), then the name, padded to 8 bytes.
    const DIRENT_HEADER: usize = 24;

    const CONTENT: &[u8] = b"hello world";

    fn masterkey() -> Masterkey {
        Masterkey::from_raw([0x42; 64])
    }

    /// A vault holding one file, `hello.txt`, with [`CONTENT`] in it.
    fn test_vault() -> (TempDir, Arc<VaultOps>) {
        let dir = tempfile::tempdir().expect("temp dir");
        initialize(
            dir.path(),
            &masterkey(),
            CipherCombo::SivGcm,
            220,
            DEFAULT_KEY_ID,
            &mut DetRng::default(),
        )
        .expect("initialize vault");
        let opened = open_vault_with_key(dir.path(), masterkey()).expect("open vault");
        let fs = CryptoFs::open(opened, CryptoFsOptions::default());
        let cfg = VaultOpsConfig {
            transcoder: NameTranscoder::new(FuseNormalization::Nfc),
            options: AdapterOptions::for_user(501, 20),
            read_only: false,
            delete_apple_double: false,
            max_name_length: 255,
        };
        let ops = Arc::new(VaultOps::new(Arc::new(fs), cfg));
        let created = ops
            .create(
                1,
                OsStr::new("hello.txt"),
                OpenFlags(libc::O_RDWR | libc::O_CREAT | libc::O_EXCL),
            )
            .expect("create hello.txt");
        ops.write(created.fh, 0, CONTENT).expect("write");
        ops.release(created.fh).expect("release");
        (dir, ops)
    }

    /// A `fuse_in_header` for `opcode` on `nodeid`, followed by `arg`. The `uid` has to be our
    /// own: the session runs with `SessionACL::Owner` and answers anybody else with `EACCES`.
    fn request(opcode: u32, unique: u64, nodeid: u64, arg: &[u8]) -> Vec<u8> {
        let len = IN_HEADER + arg.len();
        let mut buf = vec![0u8; len];
        buf[0..4].copy_from_slice(&(len as u32).to_ne_bytes());
        buf[4..8].copy_from_slice(&opcode.to_ne_bytes());
        buf[8..16].copy_from_slice(&unique.to_ne_bytes());
        buf[16..24].copy_from_slice(&nodeid.to_ne_bytes());
        buf[24..28].copy_from_slice(&nix::unistd::geteuid().as_raw().to_ne_bytes());
        buf[28..32].copy_from_slice(&nix::unistd::getegid().as_raw().to_ne_bytes());
        buf[IN_HEADER..].copy_from_slice(arg);
        buf
    }

    /// The truncated `fuse_init_in` (major, minor, `max_readahead`, flags) a 7.19-era peer sends;
    /// FUSE-T is one of them.
    fn init_request() -> Vec<u8> {
        let mut arg = Vec::with_capacity(16);
        for value in [7u32, 19, 0, 0] {
            arg.extend_from_slice(&value.to_ne_bytes());
        }
        request(FUSE_INIT, 1, 1, &arg)
    }

    /// Reads one reply; the 16-byte `fuse_out_header` says how long the message is and carries
    /// the negated errno.
    fn read_raw(peer: &mut UnixStream, what: &str) -> (i32, Vec<u8>) {
        let mut header = [0u8; OUT_HEADER];
        peer.read_exact(&mut header)
            .unwrap_or_else(|e| panic!("no {what} reply: {e}"));
        let len = u32::from_ne_bytes([header[0], header[1], header[2], header[3]]) as usize;
        let error = i32::from_ne_bytes([header[4], header[5], header[6], header[7]]);
        let mut body = vec![0u8; len.saturating_sub(OUT_HEADER)];
        peer.read_exact(&mut body)
            .unwrap_or_else(|e| panic!("truncated {what} reply: {e}"));
        (error, body)
    }

    /// The body of a reply that has to have succeeded.
    fn read_reply(peer: &mut UnixStream, what: &str) -> Vec<u8> {
        let (error, body) = read_raw(peer, what);
        assert_eq!(error, 0, "{what} failed with errno {}", -error);
        body
    }

    /// The `fuse_dirent`s of a `READDIR` reply, as (ino, next offset, type, name).
    fn dirents(buf: &[u8]) -> Vec<(u64, u64, u32, String)> {
        let mut out = Vec::new();
        let mut at = 0;
        while at + DIRENT_HEADER <= buf.len() {
            let namelen = u32_at(buf, at + 16) as usize;
            let name = &buf[at + DIRENT_HEADER..at + DIRENT_HEADER + namelen];
            out.push((
                u64_at(buf, at),
                u64_at(buf, at + 8),
                u32_at(buf, at + 20),
                String::from_utf8_lossy(name).into_owned(),
            ));
            at += (DIRENT_HEADER + namelen).next_multiple_of(8);
        }
        out
    }

    fn u32_at(buf: &[u8], off: usize) -> u32 {
        u32::from_ne_bytes(buf[off..off + 4].try_into().expect("4 bytes"))
    }

    fn u64_at(buf: &[u8], off: usize) -> u64 {
        u64::from_ne_bytes(buf[off..off + 8].try_into().expect("8 bytes"))
    }

    /// Spawns a session on one end of a socket pair, with the INIT request already queued on the
    /// other end (the handshake happens inside `spawn_from_fd` and would deadlock otherwise).
    fn spawn_over_socket(
        ops: Arc<VaultOps>,
        name: &str,
        unmounter: Unmounter,
    ) -> (UnixStream, FuseSessionHandle) {
        let (ours, theirs) = UnixStream::pair().expect("socketpair");
        let mut peer = theirs;
        // A reply that never comes must fail the test rather than hang it forever: every read
        // below goes through `read_exact` on this socket.
        peer.set_read_timeout(Some(PEER_READ_TIMEOUT))
            .expect("set read timeout");
        peer.write_all(&init_request()).expect("write init");
        let handle = FuseSessionHandle::spawn_from_fd(
            ops,
            PathBuf::from(name),
            OwnedFd::from(ours),
            KernelAbi::Linux,
            unmounter,
        )
        .expect("spawn session");
        let init = read_reply(&mut peer, "init");
        assert_eq!(u32_at(&init, 0), 7, "init major");
        (peer, handle)
    }

    /// GETATTR on the root and LOOKUP of a file that is really in the vault, answered by
    /// `CryptoFuse` over `VaultOps`. Closing the peer is what an unmount does to a FUSE-T session.
    #[test]
    fn a_session_answers_getattr_and_lookup_from_the_vault() {
        let (_dir, ops) = test_vault();
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        // The "unmount" of a socket-backed session is the peer hanging up, which the test does
        // itself; this only records that the handle asked for it.
        let unmounter: Unmounter = Box::new(move |_forced| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        let (mut peer, mut handle) = spawn_over_socket(ops, "/nonexistent/session", unmounter);
        assert_eq!(handle.mountpoint(), Path::new("/nonexistent/session"));
        assert!(!handle.is_in_use());

        peer.write_all(&request(FUSE_GETATTR, 2, 1, &[0u8; 16]))
            .expect("write getattr");
        let reply = read_reply(&mut peer, "getattr");
        assert_eq!(
            reply.len(),
            ATTR_OUT_PREFIX + 88,
            "the reply must use the 88-byte Linux fuse_attr"
        );
        let attr = &reply[ATTR_OUT_PREFIX..];
        assert_eq!(u32_at(attr, ATTR_MODE) & S_IFMT, 0o040000, "root is a dir");
        assert_eq!(u32_at(attr, ATTR_NLINK), 2, "root nlink");
        assert_eq!(u32_at(attr, ATTR_UID), 501, "the mount's uid");

        let mut name = b"hello.txt".to_vec();
        name.push(0);
        peer.write_all(&request(FUSE_LOOKUP, 3, 1, &name))
            .expect("write lookup");
        let reply = read_reply(&mut peer, "lookup");
        assert_ne!(u64_at(&reply, 0), 0, "the entry got an inode");
        let attr = &reply[ENTRY_OUT_PREFIX..];
        assert_eq!(
            u64_at(attr, ATTR_SIZE),
            CONTENT.len() as u64,
            "the cleartext size of hello.txt"
        );
        assert_eq!(u32_at(attr, ATTR_MODE) & S_IFMT, 0o100000, "a regular file");

        // OPENDIR / READDIR / RELEASEDIR of the root. `readdirplus` must decline, so that peers
        // fall back to the plain `readdir` the snapshot can actually answer.
        peer.write_all(&request(FUSE_OPENDIR, 4, 1, &[0u8; 8]))
            .expect("write opendir");
        let opened = read_reply(&mut peer, "opendir");
        let dh = u64_at(&opened, 0);
        assert_ne!(dh, 0, "a directory handle");

        let mut read_in = Vec::with_capacity(40);
        read_in.extend_from_slice(&dh.to_ne_bytes());
        read_in.extend_from_slice(&0u64.to_ne_bytes()); // offset
        read_in.extend_from_slice(&4096u32.to_ne_bytes()); // size
        read_in.resize(40, 0);
        peer.write_all(&request(FUSE_READDIRPLUS, 5, 1, &read_in))
            .expect("write readdirplus");
        let (error, _) = read_raw(&mut peer, "readdirplus");
        assert_eq!(-error, libc::ENOSYS, "readdirplus declines");

        peer.write_all(&request(FUSE_READDIR, 6, 1, &read_in))
            .expect("write readdir");
        let entries = dirents(&read_reply(&mut peer, "readdir"));
        let names: Vec<&str> = entries.iter().map(|(_, _, _, n)| n.as_str()).collect();
        assert_eq!(names, vec![".", "..", "hello.txt"]);
        let offsets: Vec<u64> = entries.iter().map(|&(_, off, _, _)| off).collect();
        assert_eq!(offsets, vec![1, 2, 3], "each entry resumes after itself");
        assert_eq!(entries[2].2, 0o100000 >> 12, "hello.txt is a regular file");

        peer.write_all(&request(FUSE_RELEASEDIR, 7, 1, &{
            let mut arg = vec![0u8; 24];
            arg[0..8].copy_from_slice(&dh.to_ne_bytes());
            arg
        }))
        .expect("write releasedir");
        read_reply(&mut peer, "releasedir");

        drop(peer);
        handle.unmount(false).expect("unmount");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        handle.join().expect("the session ended cleanly");
    }

    /// A session whose peer never hangs up cannot end: the graceful unmount has to report `Busy`
    /// instead of blocking, and a forced one has to give up instead of failing. Both must still
    /// reach the back end's unmount command.
    #[test]
    fn an_unresponsive_session_is_busy_and_then_forced_down() {
        let (_dir, ops) = test_vault();
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);
        let unmounter: Unmounter = Box::new(move |forced| {
            recorder.lock().expect("not poisoned").push(forced);
            Ok(())
        });
        let (peer, mut handle) = spawn_over_socket(ops, "/nonexistent/busy", unmounter);

        let short = Duration::from_millis(100);
        assert!(matches!(
            handle.unmount_within(false, short),
            Err(UnmountError::Busy)
        ));
        handle
            .unmount_within(true, short)
            .expect("a forced unmount does not fail on a busy session");
        assert_eq!(*seen.lock().expect("not poisoned"), vec![false, true]);

        drop(peer);
        handle.join().expect("the session ended cleanly");
    }
}
