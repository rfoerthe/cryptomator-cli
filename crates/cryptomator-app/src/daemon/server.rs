//! The per-vault daemon: one process, one vault, one control socket.
//!
//! `crypto unlock` spawns this server, hands it the vault key over the socket exactly once and
//! then goes away. From that point on the daemon owns the [`CryptoFs`] and the mount, and every
//! later command ([`crate::daemon::DaemonClient`]) is a round trip over the socket.
//!
//! # Life cycle
//!
//! | phase      | reported as  | accepted requests                                |
//! |------------|--------------|--------------------------------------------------|
//! | starting   | `STARTING`   | `ping`, `status`, `shutdown`, one `unlock`       |
//! | unlocked   | `UNLOCKED`   | all of the above plus `stats`, `events`, `lock`  |
//! | locking    | `LOCKING`    | `ping`, `status`, `shutdown` (the rest is gone)  |
//!
//! Without an `unlock` within [`DaemonConfig::unlock_timeout`] the daemon removes its state files
//! and exits with an error -- an orphaned daemon holding a socket nobody unlocks is worse than a
//! failed unlock.
//!
//! # Write order of the state files
//!
//! `<id>.pid` first, then the socket, then `<id>.json` once the mount is up. See [`RunInfo`]: the
//! registry recognises a starting daemon by its live pid, and the run info has to name the real
//! mount point (which only exists after the mount) for stale-mount detection to work.
//!
//! # Threads
//!
//! The daemon runs on plain `std` threads -- no async runtime:
//!
//! * the main thread binds the socket and runs the accept loop, then tears everything down;
//! * one thread per accepted connection, serving requests until the peer hangs up;
//! * one sampler thread taking a [`StatsSnapshot`] every [`DaemonConfig::stats_interval`];
//! * one auto-lock thread waking every [`DaemonConfig::autolock_tick`].
//!
//! All of them share one [`Shared`], and all of them stop on the same signal: the external
//! `shutdown` flag (set by the signal handler) or an internal stop request (`lock`, `shutdown`,
//! auto-lock). Waiting is always `Condvar::wait_timeout` with a 100 ms cap -- the condvar makes an
//! internal stop immediate, the cap bounds how long the flag a signal handler can only *set* stays
//! unnoticed. There is no busy loop anywhere.
use crate::cli_config::CliConfig;
use crate::daemon::logging;
use crate::daemon::protocol::{
    self, ErrorBody, EventRecord, EventsResult, Hello, Request, Response, StatsResult,
    StatusResult, StreamItem, PROTOCOL_VERSION,
};
use crate::error::{AppError, Result};
use crate::mounting::{
    self, MountHandle, MountOverrides, MountRequest, FORCED_UNMOUNT_UNSUPPORTED,
};
use crate::settings::SettingsStore;
use crate::state_dir::{process_alive, RunInfo, StateDir, VaultStateFiles};
use cryptomator_core::fs::{
    CryptoFs, CryptoFsOptions, FilesystemEvent, StatsSnapshot, DEFAULT_MAX_CLEARTEXT_NAME_LENGTH,
};
use cryptomator_core::{open_vault_with_key, CoreError, Masterkey};
use cryptomator_mount::api::{MountCapability, MountService, Mountpoint};
use data_encoding::BASE64;
use std::collections::{HashMap, VecDeque};
use std::fs::Permissions;
use std::io::{self, BufReader};
use std::net::Shutdown;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

/// The longest any thread sleeps without looking at the external shutdown flag.
///
/// A signal handler may only *set* an `AtomicBool`, so nothing can wake a waiting thread on a
/// signal; this is the resulting reaction time, and the cap on every wait in this module.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// How long an `unlock` waits for the mounted volume to appear in the system mount table.
///
/// FUSE-T mounts asynchronously: its helper drives the `mount -t nfs` only *after* the mount call
/// has returned, so for a moment the mount point is still the bare directory underneath. Answering
/// the `unlock` in that window loses data -- everything a script writes there lands beside the
/// vault, with no error. Linux's `fusermount3` mounts before the call returns, so there the wait
/// is over on the first look.
const MOUNT_VISIBLE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long [`MOUNT_VISIBLE_POLL_FAST`] is used before backing off to [`MOUNT_VISIBLE_POLL_SLOW`].
const MOUNT_VISIBLE_POLL_FAST_FOR: Duration = Duration::from_secs(1);

/// The poll interval for the first [`MOUNT_VISIBLE_POLL_FAST_FOR`] of the wait. Shorter than
/// [`POLL_INTERVAL`] because this is latency a user waits through on every unlock, and the happy
/// path is 1-5 looks.
const MOUNT_VISIBLE_POLL_FAST: Duration = Duration::from_millis(50);

/// The poll interval after [`MOUNT_VISIBLE_POLL_FAST_FOR`] has passed. Each look forks
/// `/sbin/mount` on macOS, so a volume that never appears backs off instead of costing ~200
/// processes over the full [`MOUNT_VISIBLE_TIMEOUT`].
const MOUNT_VISIBLE_POLL_SLOW: Duration = Duration::from_millis(250);

/// How long the wait must have run before it fires `--foreground`'s `notice` callback once, so a
/// user watching the terminal is not left staring at silence.
const MOUNT_VISIBLE_NOTICE_AFTER: Duration = Duration::from_secs(1);

/// How many events the daemon keeps for `crypto events`.
const EVENT_BUFFER_CAPACITY: usize = 1000;

/// The mode of the control socket: only its owner may talk to the daemon.
const SOCKET_MODE: u32 = 0o600;

/// A callback told about a notice-worthy event as one line of text; see [`DaemonConfig::notice`].
pub type NoticeFn = Box<dyn Fn(&str) + Send + Sync>;

/// Everything one daemon needs to know before it starts.
pub struct DaemonConfig {
    /// The vault's id in `settings.json`; it names the state files and the socket.
    pub vault_id: String,
    /// Where the state files live.
    pub state_dir: StateDir,
    /// The settings the vault is configured in. Re-read on every auto-lock tick, so a change to
    /// `autoLockWhenIdle` takes effect without a re-unlock.
    pub store: SettingsStore,
    /// The CLI's own settings (`cli.json`).
    pub cli: CliConfig,
    /// The user's home directory, for the default mount-point base.
    pub home: PathBuf,
    /// The mount services to pick from, usually [`cryptomator_mount::registry::all_services`].
    pub services: Vec<Box<dyn MountService>>,
    /// How long the daemon waits for its one `unlock` request before giving up.
    pub unlock_timeout: Duration,
    /// How often the stats sampler takes a snapshot; the `stats` rates are the deltas of one such
    /// interval, so this is 1 s in production.
    pub stats_interval: Duration,
    /// How often the auto-lock thread compares the idle time against the vault's settings.
    pub autolock_tick: Duration,
    /// How long a shutdown waits after a failed graceful unmount before forcing it
    /// (`cli.forceUnmountOnSignalAfterSecs`).
    pub force_unmount_after: Duration,
    /// Where to write the daemon's log, or `None` to leave the process's logger alone (tests, and
    /// anything embedding the daemon).
    pub log_file: Option<PathBuf>,
    /// Told about it once a graceful unmount fails and the daemon is about to wait out
    /// [`DaemonConfig::force_unmount_after`] before forcing it.
    ///
    /// The daemon itself has no terminal -- a detached daemon's stderr goes nowhere anybody is
    /// watching, so this stays `None` for one. `crypto unlock --foreground` is the one caller with
    /// a terminal in front of it, and passes a closure that writes to its stderr, so the person who
    /// just sent the first signal learns there is a wait ahead and a second signal skips it.
    pub notice: Option<NoticeFn>,
}

impl std::fmt::Debug for DaemonConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let services: Vec<&str> = self
            .services
            .iter()
            .map(|service| service.java_class_name())
            .collect();
        f.debug_struct("DaemonConfig")
            .field("vault_id", &self.vault_id)
            .field("state_dir", &self.state_dir)
            .field("home", &self.home)
            .field("services", &services)
            .field("unlock_timeout", &self.unlock_timeout)
            .field("stats_interval", &self.stats_interval)
            .field("autolock_tick", &self.autolock_tick)
            .field("force_unmount_after", &self.force_unmount_after)
            .field("log_file", &self.log_file)
            .field("notice", &self.notice.is_some())
            .finish_non_exhaustive()
    }
}

/// Serves one vault until it is locked, shut down, auto-locked or signalled.
///
/// Returns `Ok(())` once the mount is down -- gracefully or, after
/// [`DaemonConfig::force_unmount_after`], forcefully -- the file system is closed and the state
/// files are gone. `shutdown` is the flag a signal handler sets; the daemon notices it within
/// [`POLL_INTERVAL`] and then runs exactly the teardown a `lock` request runs.
///
/// `shutdown` is re-armed to `false` the moment its first `true` has taken effect -- once the
/// accept loop has stopped accepting new connections because of it. From then on the flag turning
/// `true` again can only be a *second* signal, and the forced-unmount wait a busy volume runs
/// (inside [`shutdown_sequence`]) treats exactly that as "force it now": it polls the flag every
/// [`POLL_INTERVAL`] instead of sleeping through the whole [`DaemonConfig::force_unmount_after`],
/// so a second Ctrl-C (or `kill`, or `SIGHUP`) does not sit out a wait that can run for as long as
/// `cli.forceUnmountOnSignalAfterSecs` says.
///
/// This function never calls `std::process::exit` -- the CLI (`crypto unlock --foreground`, the
/// detached daemon's `main`) turns the returned error into an exit code.
///
/// # Errors
/// [`AppError::MountFailed`] when the `unlock` failed (a wrong key included, message
/// `vault key does not match`), [`AppError::Io`] with [`io::ErrorKind::TimedOut`] when no
/// `unlock` arrived in time, [`AppError::DaemonError`] with [`ErrorBody::ALREADY_UNLOCKED`] when
/// another daemon already serves this vault, [`AppError::UnmountFailed`] when the volume survived
/// both the graceful and the forced unmount (the run info then stays behind on purpose, see
/// [`shutdown_sequence`]), and anything [`StateDir::ensure`] or writing the pid file reports.
pub fn run_daemon(config: DaemonConfig, shutdown: Arc<AtomicBool>) -> Result<()> {
    run_daemon_with_hook(config, shutdown, |_| {})
}

/// [`run_daemon`], with a hook that sees the [`Shared`] state once the daemon is listening. The
/// tests use it to inject file system events; production goes through [`run_daemon`].
fn run_daemon_with_hook(
    config: DaemonConfig,
    shutdown: Arc<AtomicBool>,
    on_ready: impl FnOnce(&Arc<Shared>),
) -> Result<()> {
    config.state_dir.ensure()?;
    if let Some(path) = config.log_file.clone() {
        logging::init_file_logger(&path, logging::level_filter(&config.cli.log_level))?;
    }
    let files = config.state_dir.files(&config.vault_id);
    let pid = std::process::id();

    // Before the first byte is written: a daemon that answers on this socket owns these state
    // files, and overwriting its pid file would leave it unreachable but mounted.
    refuse_if_serving(&files.socket)?;

    // Order (see the module docs): pid, then socket, then -- after the mount -- the run info.
    if let Err(err) = files.write_pid(pid) {
        let _ = files.remove_all();
        return Err(err);
    }
    let listener = match bind_socket(&files.socket) {
        Ok(listener) => listener,
        // A daemon that won the race in the meantime owns the files now; removing them would be
        // exactly the damage `refuse_if_serving` prevents -- except for the pid file, which
        // `write_pid` above has already overwritten with ours. Anything else is ours to clean up.
        Err(err) if is_already_serving(&err) => {
            drop_pid_file_if_ours(&files, pid);
            return Err(err);
        }
        Err(err) => {
            let _ = files.remove_all();
            return Err(err);
        }
    };

    let shared = Arc::new(Shared::new(config, files, shutdown, pid));
    on_ready(&shared);
    log::info!(
        "daemon for vault {} listening on {}",
        shared.config.vault_id,
        shared.files.socket.display()
    );
    let workers = vec![
        spawn_worker("crypto-stats", Arc::clone(&shared), stats_loop),
        spawn_worker("crypto-autolock", Arc::clone(&shared), autolock_loop),
    ];

    let outcome = accept_loop(&shared, &listener);
    shared.request_stop();
    // Re-arms the external flag now that its first `true` has done its job (the accept loop has
    // already stopped because of it, or because of an internal stop that leaves this a no-op): a
    // signal that fires from here on sets it fresh, and `shutdown_sequence`'s forced-unmount wait
    // reads that as a second signal asking to escalate right now. See `run_daemon`'s docs.
    shared.external_shutdown.store(false, Ordering::Relaxed);
    drop(listener);
    // The workers first: the auto-lock thread may be in the middle of an unmount, and the
    // teardown must see the state it leaves behind, not the state halfway through it.
    for worker in workers.into_iter().flatten() {
        let _ = worker.join();
    }
    let stuck = shutdown_sequence(&shared);
    // A connection thread may still be blocked reading; closing its socket ends it.
    shared.close_connections();

    match (outcome, shared.take_fatal(), stuck) {
        // A failed unlock answers the client first and only then stops the daemon, so the accept
        // loop ends without an error of its own; the failure is in `fatal`.
        (_, Some(fatal), _) => Err(fatal),
        // Nothing else went wrong, but a volume is still mounted: that is what the caller has to
        // hear about (exit code 7), and the run info the teardown kept is what points at it.
        (_, None, Some(stuck)) => Err(stuck),
        (outcome, None, None) => outcome,
    }
}

/// Refuses to start when a daemon is already listening on `path`.
///
/// The socket *file* says nothing -- a crashed daemon leaves one behind -- so the question is
/// whether somebody accepts on it. The registry asks it too before it spawns a daemon, but that
/// check is a TOCTOU: two `crypto unlock`s for the same vault would otherwise both get here, and
/// the second would take the socket away from the first while its volume stays mounted.
///
/// The probe is a connect and an immediate hangup, which is what `crypto status` does anyway.
///
/// # Errors
/// [`AppError::DaemonError`] with [`ErrorBody::ALREADY_UNLOCKED`] when somebody answered.
fn refuse_if_serving(path: &Path) -> Result<()> {
    if UnixStream::connect(path).is_ok() {
        return Err(AppError::DaemonError {
            code: ErrorBody::ALREADY_UNLOCKED.to_owned(),
            message: "another daemon is already serving this vault".to_owned(),
        });
    }
    Ok(())
}

/// Takes back the pid file this daemon wrote, after losing the start-up race.
///
/// [`refuse_if_serving`] runs before anything is written, but it is a TOCTOU: another daemon can
/// bind the socket between that probe and [`bind_socket`]'s. By then `<id>.pid` names *this*
/// process, which is about to die -- and a pid file naming a dead process is how a crashed daemon
/// looks to [`VaultRegistry::runtime_state`](crate::registry::VaultRegistry::runtime_state), so
/// the winner would carry a wrong one for its whole life.
///
/// The file is removed **only while it still names us**: if the winner's own `write_pid` landed
/// after ours, that pid is the one that belongs there and must survive. Everything else the winner
/// owns (the socket, the run info) is left alone, which is the Task-11 pid → socket → info order
/// seen from the losing side.
fn drop_pid_file_if_ours(files: &VaultStateFiles, pid: u32) {
    if files.read_pid() != Some(pid) {
        return;
    }
    match std::fs::remove_file(&files.pid) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => log::warn!(
            "cannot take back the pid file at {}: {err}",
            files.pid.display()
        ),
    }
}

/// Whether `err` is what [`refuse_if_serving`] reports.
fn is_already_serving(err: &AppError) -> bool {
    matches!(err, AppError::DaemonError { code, .. } if code == ErrorBody::ALREADY_UNLOCKED)
}

/// Binds the control socket and narrows it to 0600.
///
/// A socket file left behind by a crashed daemon is removed first -- `bind` would fail with
/// `EADDRINUSE` on it. Removing one somebody is listening on would unhook a running daemon, so
/// [`refuse_if_serving`] guards the removal; `run_daemon` has asked the same question before it
/// wrote anything, and this closes the window between the two.
///
/// The listener is non-blocking: [`accept_loop`] polls it so that a shutdown request is noticed
/// within [`POLL_INTERVAL`] instead of only when the next client connects.
fn bind_socket(path: &Path) -> Result<UnixListener> {
    refuse_if_serving(path)?;
    match std::fs::remove_file(path) {
        Ok(()) => log::debug!("removed a leftover socket at {}", path.display()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(AppError::Io(err)),
    }
    let listener = UnixListener::bind(path)?;
    // The state directory is 0700 already; this narrows the socket itself, for the case where the
    // user pointed `--state-dir` at something wider.
    std::fs::set_permissions(path, Permissions::from_mode(SOCKET_MODE))?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// Accepts connections until the daemon is asked to stop, or until the unlock deadline passes.
///
/// # Errors
/// [`AppError::Io`] with [`io::ErrorKind::TimedOut`] when no `unlock` arrived within
/// [`DaemonConfig::unlock_timeout`].
fn accept_loop(shared: &Arc<Shared>, listener: &UnixListener) -> Result<()> {
    let started = Instant::now();
    loop {
        if shared.stop_requested() {
            return Ok(());
        }
        if shared.unlock_deadline_passed(started) {
            let secs = shared.config.unlock_timeout.as_secs_f32();
            log::error!("no unlock request within {secs:.1}s; giving up");
            return Err(AppError::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("no unlock request within {secs:.1} seconds"),
            )));
        }
        match listener.accept() {
            Ok((stream, _)) => serve_connection(shared, stream),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                shared.wait_for_stop(POLL_INTERVAL);
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => {
                log::warn!("cannot accept a connection: {err}");
                shared.wait_for_stop(POLL_INTERVAL);
            }
        }
    }
}

/// Greets the peer and serves its requests on a thread of its own.
fn serve_connection(shared: &Arc<Shared>, stream: UnixStream) {
    // The listener is non-blocking and macOS hands that flag to the accepted socket; the
    // connection threads block on purpose.
    if let Err(err) = stream.set_nonblocking(false) {
        log::warn!("cannot configure an accepted connection: {err}");
        return;
    }
    let shared = Arc::clone(shared);
    let spawned = std::thread::Builder::new()
        .name("crypto-conn".to_owned())
        .spawn(move || connection(&shared, stream));
    if let Err(err) = spawned {
        log::warn!("cannot serve a connection: {err}");
    }
}

/// One connection: the greeting, then one request at a time until the peer hangs up.
fn connection(shared: &Arc<Shared>, stream: UnixStream) {
    let Ok(mut writer) = stream.try_clone() else {
        return;
    };
    let Some(registration) = shared.register(&stream) else {
        return;
    };
    let hello = Hello {
        hello: Hello::MAGIC.to_owned(),
        protocol: PROTOCOL_VERSION,
        vault_id: shared.config.vault_id.clone(),
        pid: shared.pid,
    };
    // `crypto status` probes the daemon by connecting and dropping the connection at once, so a
    // greeting that cannot be written is the normal case, not an error.
    if protocol::write_line(&mut writer, &hello).is_ok() {
        let mut reader = BufReader::new(stream);
        serve_requests(shared, &mut reader, &mut writer);
    }
    shared.unregister(registration);
}

/// Reads and answers requests until the peer hangs up or a handler closes the connection.
fn serve_requests(
    shared: &Arc<Shared>,
    reader: &mut BufReader<UnixStream>,
    writer: &mut UnixStream,
) {
    loop {
        match protocol::read_request(reader) {
            Ok(None) => return,
            Ok(Some(mut request)) => {
                log::debug!("request {}", request.op());
                if !handle_request(shared, &mut request, writer) {
                    return;
                }
            }
            Err(err) if err.kind() == io::ErrorKind::InvalidData => {
                // The id is unknown -- the line did not parse -- so the answer carries id 0 and
                // the connection ends: the peer and this daemon no longer agree on the format.
                let response = Response::err(0, ErrorBody::BAD_REQUEST, err.to_string());
                respond(writer, &response);
                return;
            }
            Err(_) => return,
        }
    }
}

/// Answers one request. Returns whether the connection stays open.
fn handle_request(shared: &Arc<Shared>, request: &mut Request, writer: &mut UnixStream) -> bool {
    let id = request.id();
    match request {
        Request::Ping { .. } => respond(writer, &Response::ok(id, serde_json::Value::Null)),
        Request::Status { .. } => {
            let status = shared.lock_state().status(shared);
            respond(writer, &ok_json(id, &status))
        }
        Request::Shutdown { .. } => {
            log::info!("shutdown requested");
            respond(writer, &Response::ok(id, serde_json::Value::Null));
            shared.request_stop();
            false
        }
        Request::Unlock {
            key,
            mounter,
            mount_point,
            mount_options,
            port,
            read_only,
            volume_name,
            max_cleartext_name_length,
            ..
        } => {
            let args = UnlockArgs {
                // The key is moved out of the request and wiped here instead; `Request`'s own
                // `Drop` then finds an empty string.
                key: Zeroizing::new(std::mem::take(key)),
                overrides: MountOverrides {
                    mounter: mounter.clone(),
                    mount_point: mount_point.as_deref().map(PathBuf::from),
                    mount_options: mount_options.clone(),
                    read_only: *read_only,
                    port: *port,
                    volume_name: volume_name.clone(),
                },
                max_cleartext_name_length: *max_cleartext_name_length,
            };
            handle_unlock(shared, id, args, writer)
        }
        Request::Stats { .. } => {
            let state = shared.lock_state();
            if state.phase != Phase::Unlocked {
                drop(state);
                return respond(writer, &not_unlocked(id));
            }
            let stats = state.stats();
            drop(state);
            respond(writer, &ok_json(id, &stats))
        }
        Request::Lock { force, .. } => handle_lock(shared, id, *force, writer),
        Request::Events { follow, since, .. } => handle_events(shared, id, *since, *follow, writer),
    }
}

/// What an `unlock` request says, with the key already moved out of it.
struct UnlockArgs {
    key: Zeroizing<String>,
    overrides: MountOverrides,
    max_cleartext_name_length: usize,
}

/// The one `unlock` a daemon accepts: decode the key, open the vault, mount it, publish the run
/// info.
///
/// A failed unlock is fatal -- the daemon answers, records the error for [`run_daemon`]'s return
/// value and stops. A malformed key is the exception: it never reached the vault, so the caller
/// may try again until the unlock deadline passes.
fn handle_unlock(shared: &Arc<Shared>, id: u64, args: UnlockArgs, writer: &mut UnixStream) -> bool {
    {
        let mut state = shared.lock_state();
        if state.phase != Phase::Starting || state.unlock_started {
            return respond(
                writer,
                &Response::err(
                    id,
                    ErrorBody::ALREADY_UNLOCKED,
                    "this daemon has already unlocked its vault",
                ),
            );
        }
        state.unlock_started = true;
    }
    let key = match decode_key(&args.key) {
        Ok(key) => key,
        Err(message) => {
            shared.lock_state().unlock_started = false;
            return respond(writer, &Response::err(id, ErrorBody::BAD_REQUEST, message));
        }
    };
    match unlock(shared, key, args.overrides, args.max_cleartext_name_length) {
        Ok(mountpoint) => {
            log::info!("vault {} mounted at {mountpoint}", shared.config.vault_id);
            respond(
                writer,
                &Response::ok(id, serde_json::json!({ "mountpoint": mountpoint })),
            )
        }
        Err(err) => {
            log::error!("unlock failed: {err}");
            let message = match &err {
                AppError::MountFailed(message) => message.clone(),
                other => other.to_string(),
            };
            respond(writer, &Response::err(id, ErrorBody::MOUNT_FAILED, message));
            shared.set_fatal(err);
            shared.request_stop();
            false
        }
    }
}

/// The 64 raw key bytes of a base64 `key` field.
///
/// # Errors
/// A message naming what is wrong -- never the value itself.
fn decode_key(encoded: &str) -> std::result::Result<Zeroizing<[u8; 64]>, &'static str> {
    let raw = Zeroizing::new(
        BASE64
            .decode(encoded.as_bytes())
            .map_err(|_| "the key is not valid base64")?,
    );
    if raw.len() != 64 {
        return Err("the key must decode to 64 bytes");
    }
    // Built *inside* the `Zeroizing` and filled by reference: `[u8; 64]` is `Copy`, so decoding
    // into a plain array and wrapping it afterwards would leave the key bytes in a stack slot
    // nobody wipes.
    let mut key = Zeroizing::new([0u8; 64]);
    key.copy_from_slice(&raw);
    Ok(key)
}

/// Opens the vault with `key`, mounts it and publishes the [`RunInfo`].
///
/// # Errors
/// [`AppError::MountFailed`] for a key that does not match the vault (message
/// `vault key does not match`), for a vault that is not in `settings.json`, for a `webdavBind`
/// that a loopback-port service cannot use (and only for such a service) and for anything the
/// mounter refuses, plus whatever [`SettingsStore::load`] and writing the run info report.
fn unlock(
    shared: &Arc<Shared>,
    key: Zeroizing<[u8; 64]>,
    overrides: MountOverrides,
    max_cleartext_name_length: usize,
) -> Result<String> {
    let _operation = shared.lock_operation();
    // With the operation lock held, a teardown that is already running has finished; mounting now
    // would leave a volume behind that nobody takes down again.
    if shared.stop_requested() {
        return Err(AppError::MountFailed(
            "the daemon is shutting down".to_owned(),
        ));
    }
    let vault_id = &shared.config.vault_id;
    let settings = shared.config.store.load()?;
    let vault = settings
        .directories
        .iter()
        .find(|vault| &vault.id == vault_id)
        .ok_or_else(|| {
            AppError::MountFailed(format!("vault {vault_id} is not in settings.json"))
        })?;
    let path = vault
        .path_buf()
        .ok_or_else(|| AppError::MountFailed(format!("vault {vault_id} has no path")))?;

    // `from_zeroizing`, not `from_raw(*key)`: dereferencing the `Zeroizing` would copy the 64
    // bytes onto the stack as a plain argument that nothing wipes afterwards.
    let opened =
        open_vault_with_key(&path, Masterkey::from_zeroizing(key)).map_err(|err| match err {
            // The one error a user is likely to cause, and the one the CLI has a hint for.
            CoreError::VaultKeyInvalid => {
                AppError::MountFailed("vault key does not match".to_owned())
            }
            other => AppError::MountFailed(other.to_string()),
        })?;

    let request = MountRequest {
        vault,
        settings: &settings,
        cli: &shared.config.cli,
        home: &shared.config.home,
        overrides,
        running_services: running_services(&shared.config.state_dir, vault_id),
    };
    // Only a service that binds a loopback socket reads `cli.json`'s `webdavBind`, so only for
    // one does the value have to be usable: `choose_service` first, then the address -- a typo'd
    // `webdavBind` must not fail a FUSE unlock that never looks at it. Still before anything is
    // mounted and inside the unlock, so the refusal travels back as `MOUNT_FAILED` (exit code 6)
    // rather than as a daemon that never comes up. `set_bind_address` applies the loopback rule
    // itself (`CRYPTO_WEBDAV_ALLOW_NONLOOPBACK=1` overrides it) and refuses before it writes.
    //
    // What it writes is process-global (`cryptomator_mount::webdav::BIND_ADDRESS`), which is fine
    // in production -- one daemon process serves one vault. The tests of this crate, however,
    // share one process: no two of them may vary `webdav_bind` concurrently, because nothing
    // would serialize them (the mount crate's `ENV_LOCK` is crate-private). Every app test
    // therefore leaves `CliConfig::webdav_bind` unset; the `cli.json` value is exercised from
    // `crates/crypto/tests/cli_daemon.rs`, where each daemon is its own process.
    if mounting::choose_service(&request, &shared.config.services)?
        .has_capability(MountCapability::LoopbackPort)
    {
        cryptomator_mount::webdav::set_bind_address(shared.config.cli.webdav_bind_addr()?)
            .map_err(|e| AppError::MountFailed(e.to_string()))?;
    }
    // The mounter's own rule, not a second copy of it: for a service whose read-only mode follows
    // the file system (the WebDAV back ends) this `CryptoFs` is the only thing that makes the
    // volume read-only, so the two must never disagree (`mounting::read_only`).
    let read_only = mounting::read_only(&request);
    let fs = Arc::new(CryptoFs::open(
        opened,
        CryptoFsOptions {
            read_only,
            max_cleartext_name_length: if max_cleartext_name_length == 0 {
                DEFAULT_MAX_CLEARTEXT_NAME_LENGTH
            } else {
                max_cleartext_name_length
            },
            events: shared.events.sink(),
        },
    ));
    let handle = match mounting::mount(&request, &shared.config.services, Arc::clone(&fs)) {
        Ok(handle) => handle,
        Err(err) => {
            close_fs(fs);
            return Err(err);
        }
    };
    let mountpoint = match handle.mountpoint() {
        Mountpoint::Path(path) => path.display().to_string(),
        Mountpoint::Uri(uri) => uri,
    };

    // Nobody may be told the vault is unlocked while the mount point is still the bare directory
    // underneath the volume; a write in that window would silently miss the vault. Only a local
    // path can be looked up in the mount table, and only a service whose volumes appear there at
    // all is worth waiting for (the null mounter's never do).
    if let (true, Mountpoint::Path(path)) = (handle.appears_in_mount_table, handle.mountpoint()) {
        let notice = shared.config.notice.as_deref();
        let visible = wait_until_visible(
            || cryptomator_mount::mounttab::lookup(&path),
            || shared.stop_requested(),
            MOUNT_VISIBLE_TIMEOUT,
            || {
                if let Some(notice) = notice {
                    notice(&format!(
                        "waiting for the volume to appear at {mountpoint} …"
                    ));
                }
            },
        );
        if !visible {
            let message = format!(
                "the volume did not become visible at {mountpoint} within {} s",
                MOUNT_VISIBLE_TIMEOUT.as_secs()
            );
            log::error!("{message}");
            return Err(abort_mount(
                shared,
                handle,
                fs,
                "an invisible volume",
                AppError::MountFailed(message),
            ));
        }
    }

    // The run info is what `crypto status` reads and what stale-mount detection needs the real
    // mount point for, so it is written here -- after the mount, before the answer.
    let info = RunInfo {
        vault_id: vault_id.clone(),
        path: path.display().to_string(),
        mounter: handle.service_class.clone(),
        mountpoint: Some(mountpoint.clone()),
        pid: shared.pid,
        started_at: now_secs(),
        read_only,
    };
    if let Err(err) = shared.files.write_info(&info) {
        return Err(abort_mount(shared, handle, fs, "a failed run info", err));
    }

    let mut state = shared.lock_state();
    state.phase = Phase::Unlocked;
    state.last_snapshot = Some(fs.stats().snapshot());
    state.mounter = handle.service_class.clone();
    state.mount = Some(handle);
    state.fs = Some(fs);
    state.mountpoint = Some(mountpoint.clone());
    state.read_only = read_only;
    state.last_activity = now_secs();
    Ok(mountpoint)
}

/// Polls `check` until it says the volume is visible, `stop` says the daemon should give up
/// waiting, or `timeout` passes -- whichever comes first. `false` in the latter two cases.
///
/// A pure helper so the wait itself is testable without a mount table: the daemon passes
/// [`cryptomator_mount::mounttab::lookup`]. `check` is called once before the first sleep, so a
/// volume that is already up costs no delay at all.
///
/// `check`'s `Err` ends the wait as a **success** (logged once as a warning): an unreadable mount
/// table (a `/sbin/mount` that will not run, a missing `/proc/self/mountinfo`) makes "not yet
/// visible" and "will never say yes" indistinguishable, and failing a mount that is probably fine
/// is worse than answering the unlock without having confirmed it.
///
/// `stop` is checked once per look, right after `check` -- so a shutdown request during the wait
/// (`unlock` holds the operation lock the whole time, which `shutdown_sequence` needs) ends it
/// within one poll instead of after the full [`MOUNT_VISIBLE_TIMEOUT`].
///
/// The first [`MOUNT_VISIBLE_POLL_FAST_FOR`] is polled every [`MOUNT_VISIBLE_POLL_FAST`], since
/// the happy path is 1-5 looks; after that every [`MOUNT_VISIBLE_POLL_SLOW`], since each look
/// forks a process on macOS. `on_slow` is called at most once, the first time the wait has run
/// longer than [`MOUNT_VISIBLE_NOTICE_AFTER`] -- the daemon uses it to fire `--foreground`'s
/// `notice` callback.
fn wait_until_visible(
    mut check: impl FnMut() -> io::Result<bool>,
    stop: impl Fn() -> bool,
    timeout: Duration,
    mut on_slow: impl FnMut(),
) -> bool {
    let start = Instant::now();
    let deadline = start + timeout;
    let mut notified = false;
    loop {
        match check() {
            Ok(true) => return true,
            Ok(false) => {}
            Err(error) => {
                log::warn!("cannot read the mount table; assuming the volume is visible: {error}");
                return true;
            }
        }
        if stop() {
            return false;
        }
        let elapsed = start.elapsed();
        if !notified && elapsed > MOUNT_VISIBLE_NOTICE_AFTER {
            notified = true;
            on_slow();
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        let poll = if elapsed < MOUNT_VISIBLE_POLL_FAST_FOR {
            MOUNT_VISIBLE_POLL_FAST
        } else {
            MOUNT_VISIBLE_POLL_SLOW
        };
        std::thread::sleep(remaining.min(poll));
    }
}

/// Takes a mount back down that must not stay up, and hands `err` back for the caller to fail
/// with. `what` names the reason, for the log line of an unmount that fails on top of it.
///
/// Nothing may stay mounted that the CLI cannot find again, so this is the full escalation the
/// teardown does -- graceful, then forced. A volume that survives both goes back into the state --
/// together with the file system it serves -- so `shutdown_sequence` tries again instead of
/// walking away from a mounted volume with no daemon and no run info behind it.
fn abort_mount(
    shared: &Arc<Shared>,
    handle: MountHandle,
    fs: Arc<CryptoFs>,
    what: &str,
    err: AppError,
) -> AppError {
    if let Some(failure) = release_mount(handle, true, shared) {
        log::error!("cannot unmount after {what}: {}", failure.error);
        if let Some(handle) = failure.handle {
            let mut state = shared.lock_state();
            state.mounter = handle.service_class.clone();
            state.mount = Some(handle);
            state.fs = Some(fs);
            return err;
        }
    }
    close_fs(fs);
    err
}

/// The mount services the *other* running daemons use, for the mounter's conflict check.
///
/// [`crate::registry::VaultRegistry::running_mounters`] answers the same question but drops the
/// vault ids on the way, and this daemon must not count itself; the run info of this vault is not
/// written yet, but a leftover of an earlier run of it may still be lying around.
fn running_services(state_dir: &StateDir, vault_id: &str) -> Vec<String> {
    state_dir
        .list_run_infos()
        .unwrap_or_else(|err| {
            log::warn!("cannot read the state directory: {err}");
            Vec::new()
        })
        .into_iter()
        .filter(|info| info.vault_id != vault_id && process_alive(info.pid))
        .map(|info| info.mounter)
        .collect()
}

/// `lock`: unmount, release everything and stop the daemon.
///
/// A failed unmount is answered with `UNMOUNT_FAILED` and the daemon keeps serving -- the volume
/// is still there, and the user may retry with `--force`.
fn handle_lock(shared: &Arc<Shared>, id: u64, force: bool, writer: &mut UnixStream) -> bool {
    match lock_now(shared, force) {
        Ok(()) => {
            log::info!("vault {} locked", shared.config.vault_id);
            respond(writer, &Response::ok(id, serde_json::Value::Null));
            shared.request_stop();
            false
        }
        Err(LockFailure::NotUnlocked) => respond(writer, &not_unlocked(id)),
        Err(LockFailure::Unmount(message)) => {
            log::warn!("lock failed: {message}");
            respond(
                writer,
                &Response::err(id, ErrorBody::UNMOUNT_FAILED, message),
            )
        }
    }
}

/// Why a lock did not happen.
enum LockFailure {
    /// There is nothing mounted (yet, or any more).
    NotUnlocked,
    /// The volume could not be taken down; the daemon stays up.
    Unmount(String),
}

/// Unmounts and releases the mount and the file system, leaving the daemon in [`Phase::Locking`].
///
/// Shared by the `lock` request and the auto-lock thread. The mount is taken out of the state
/// before the unmount runs, so a `umount` that retries a busy volume for seconds blocks neither a
/// concurrent `status` nor anything else; a second `lock` finds no mount and is answered with
/// `NOT_UNLOCKED`. On failure the mount goes back and the phase returns to [`Phase::Unlocked`]:
/// the volume is still there and must still be lockable.
fn lock_now(shared: &Arc<Shared>, force: bool) -> std::result::Result<(), LockFailure> {
    let _operation = shared.lock_operation();
    let mut handle = {
        let mut state = shared.lock_state();
        if state.phase != Phase::Unlocked {
            return Err(LockFailure::NotUnlocked);
        }
        let Some(handle) = state.mount.take() else {
            return Err(LockFailure::NotUnlocked);
        };
        if force && !handle.supports_forced {
            // The same refusal `MountHandle::unmount(true)` would give, one step earlier: this way
            // the mount never leaves the state and the phase never becomes `Locking`.
            let message = format!("{}: {FORCED_UNMOUNT_UNSUPPORTED}", handle.service_class);
            state.mount = Some(handle);
            return Err(LockFailure::Unmount(message));
        }
        state.phase = Phase::Locking;
        handle
    };
    match handle.unmount(force) {
        Ok(()) => {
            // `close` joins the session and removes the mount directory the mounter created.
            if let Err(err) = handle.close() {
                log::warn!("releasing the mount failed: {err}");
            }
            let fs = {
                let mut state = shared.lock_state();
                state.mountpoint = None;
                state.fs.take()
            };
            if let Some(fs) = fs {
                close_fs(fs);
            }
            Ok(())
        }
        Err(err) => {
            let mut state = shared.lock_state();
            state.phase = Phase::Unlocked;
            state.mount = Some(handle);
            Err(LockFailure::Unmount(err.to_string()))
        }
    }
}

/// Takes the volume down and releases everything the daemon holds, then removes the state files.
///
/// This is the end of every daemon: the accept loop has stopped, either because it was asked to
/// or because the unlock deadline passed. A graceful unmount comes first; only if that fails does
/// the daemon wait [`DaemonConfig::force_unmount_after`] and force it, and only if the service can
/// (`umount -f` exists, `fusermount3 -u` does not).
///
/// Returns [`None`] once nothing is mounted any more -- the state files are gone then and the
/// daemon ends successfully. A volume that survived even the forced unmount (or a service that
/// has no forced unmount at all) comes back as [`AppError::UnmountFailed`], and the run info
/// **stays**: it is the only record of the volume nobody unmounted, and it is what makes
/// `crypto status` report `STALE_MOUNT` instead of a vault that looks locked while it is not.
fn shutdown_sequence(shared: &Arc<Shared>) -> Option<AppError> {
    // Waits out an `unlock` that is still mounting or a `lock` that is still unmounting: both run
    // without the state lock (they may take seconds), and tearing down around them would leave a
    // mounted volume with no daemon behind it.
    let _operation = shared.lock_operation();
    let handle = {
        let mut state = shared.lock_state();
        if state.mount.is_some() {
            state.phase = Phase::Locking;
        }
        state.mount.take()
    };
    let mut stuck = None;
    if let Some(handle) = handle {
        // The mount is out of the shared state, so the wait for a forced unmount blocks nothing
        // but this teardown.
        if let Some(failure) = release_mount(handle, true, shared) {
            // The daemon is on its way out; there is nobody left to hand the handle back to.
            log::error!(
                "cannot unmount {}: {}",
                shared.config.vault_id,
                failure.error
            );
            // With the handle: the volume is still mounted and outlives this process. Without it
            // the volume is down and only releasing it failed -- nothing is left behind, so that
            // stays a warning in the log.
            if failure.handle.is_some() {
                stuck = Some(failure.error);
            }
            // Explicit, not incidental: a real FUSE `MountHandle` unmounts its `BackgroundSession`
            // on drop, and this process is on its way out either way, so dropping it here -- right
            // before `close_fs` below closes the file system it served -- is deliberate rather than
            // something that happens to fall out of scope.
            drop(failure.handle);
        }
    }
    let fs = shared.lock_state().fs.take();
    if let Some(fs) = fs {
        close_fs(fs);
    }
    let removed = match &stuck {
        Some(_) => shared.files.remove_for_stale(),
        None => shared.files.remove_all(),
    };
    if let Err(err) = removed {
        log::warn!("cannot remove the state files: {err}");
    }
    match stuck {
        Some(error) => {
            log::error!(
                "daemon for vault {} stopped with its volume still mounted; \
                 `crypto lock --force` is the way out",
                shared.config.vault_id
            );
            Some(error)
        }
        None => {
            log::info!("daemon for vault {} stopped", shared.config.vault_id);
            None
        }
    }
}

/// A volume that would not go down, and what to do with it.
struct ReleaseFailure {
    /// The handle of a volume that is still mounted, so the caller can put it back and retry it
    /// later. `None` once the volume is gone and only the release itself failed -- there is
    /// nothing left to retry then.
    handle: Option<MountHandle>,
    error: AppError,
}

/// Unmounts `handle` and releases it. With `retry_forced` a failed graceful unmount is retried
/// forcefully after [`DaemonConfig::force_unmount_after`], if the service has a forced unmount at
/// all.
///
/// Returns [`None`] when the volume is down and released, and a [`ReleaseFailure`] carrying
/// [`AppError::UnmountFailed`] otherwise -- with the handle while the volume is still mounted,
/// without it once only the release itself failed. (A [`Result`] of the two would be the more
/// obvious shape, but an error variant this large is one clippy refuses.)
fn release_mount(
    mut handle: MountHandle,
    retry_forced: bool,
    shared: &Arc<Shared>,
) -> Option<ReleaseFailure> {
    if let Err(error) = handle.unmount(false) {
        if !retry_forced || !handle.supports_forced {
            return Some(ReleaseFailure {
                handle: Some(handle),
                error,
            });
        }
        let force_after = shared.config.force_unmount_after;
        log::warn!("graceful unmount failed ({error}); forcing it in {force_after:?}");
        if let Some(notice) = &shared.config.notice {
            notice(&format!(
                "unmount busy; forcing in {}s (press Ctrl-C again to force now)",
                force_after.as_secs()
            ));
        }
        wait_or_escalate(shared, force_after);
        if let Err(error) = handle.unmount(true) {
            return Some(ReleaseFailure {
                handle: Some(handle),
                error,
            });
        }
    }
    handle.close().err().map(|error| ReleaseFailure {
        handle: None,
        error,
    })
}

/// Waits out `force_after` before a forced unmount, in [`POLL_INTERVAL`] slices so a second
/// shutdown signal ends the wait early instead of being sat out.
///
/// `run_daemon` re-arms `Shared::external_shutdown` to `false` the moment the first signal that
/// got the daemon this far has taken effect (see its docs), so the flag reading `true` here can
/// only be a fresh signal -- there is no internal-stop case to confuse it with, since an internal
/// stop (`lock`, auto-lock) never sets this flag at all.
fn wait_or_escalate(shared: &Arc<Shared>, force_after: Duration) {
    let deadline = Instant::now() + force_after;
    loop {
        if shared.external_shutdown.load(Ordering::Relaxed) {
            return;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return;
        }
        std::thread::sleep(remaining.min(POLL_INTERVAL));
    }
}

/// Flushes and closes the file system.
///
/// [`CryptoFs::close`] consumes the file system, so only its last owner can call it. Every caller
/// here *is* that owner: the mount is released first, and nothing else keeps an `Arc<CryptoFs>`
/// outside [`DaemonState::fs`] (the sampler reads it under the state lock for exactly that
/// reason). A clone that is still alive is therefore a bug -- and one that must not cost the user
/// their buffered writes, so the flush ([`CryptoFs::flush_all`], what `close` does) runs anyway.
fn close_fs(fs: Arc<CryptoFs>) {
    // `try_unwrap` rather than `into_inner`: it hands the `Arc` back, and only with it in hand can
    // the fallback flush run. It may also fail while another thread is dropping the last other
    // clone, which is the same "somebody else still holds it" this reports.
    match Arc::try_unwrap(fs) {
        Ok(fs) => {
            #[cfg(test)]
            OWNED_CLOSES.fetch_add(1, Ordering::Relaxed);
            if let Err(err) = fs.close() {
                log::warn!("closing the file system failed: {err}");
            }
        }
        Err(fs) => {
            #[cfg(test)]
            SHARED_CLOSES.fetch_add(1, Ordering::Relaxed);
            log::error!("the file system is still in use; flushing it without releasing it");
            if let Err(err) = fs.flush_all() {
                log::warn!("flushing the file system failed: {err}");
            }
        }
    }
}

/// How often [`close_fs`] owned the file system it closed.
#[cfg(test)]
static OWNED_CLOSES: AtomicU64 = AtomicU64::new(0);

/// How often [`close_fs`] found a clone of the file system still alive -- the bug it reports. The
/// tests assert this stays 0.
#[cfg(test)]
static SHARED_CLOSES: AtomicU64 = AtomicU64::new(0);

/// `events`: the buffered records, and with `follow` everything that arrives afterwards.
///
/// A follow stream is `StreamItem`s on the connection that asked for it, terminated by exactly one
/// [`Response`] carrying `nextSeq` -- that final response is what tells the client the stream
/// ended in an orderly way. It ends when the daemon stops or when writing to the client fails
/// (the client shuts its side down when the user interrupts `crypto events --follow`).
fn handle_events(
    shared: &Arc<Shared>,
    id: u64,
    since: u64,
    follow: bool,
    writer: &mut UnixStream,
) -> bool {
    // Only a mounted vault has events to report: before the mount there are none, and once the
    // daemon is locking, the file system that produces them is on its way out (see the phase table
    // in the module docs).
    if shared.lock_state().phase != Phase::Unlocked {
        return respond(writer, &not_unlocked(id));
    }
    if !follow {
        let (events, next_seq) = shared.events.since(since);
        return respond(writer, &ok_json(id, &EventsResult { events, next_seq }));
    }
    let mut cursor = since;
    let mut alive = true;
    while alive {
        let (batch, next_seq) = shared.events.since(cursor);
        cursor = next_seq;
        for event in batch {
            if protocol::write_line(writer, &StreamItem { id, event }).is_err() {
                alive = false;
                break;
            }
        }
        if !alive || shared.stop_requested() {
            break;
        }
        shared.events.wait_for_more(cursor, POLL_INTERVAL);
    }
    if alive {
        respond(
            writer,
            &Response::ok(id, serde_json::json!({ "nextSeq": cursor })),
        );
    }
    // The stream owned the connection; whether it ended in a response or in a broken pipe, there
    // is nothing more to serve on it.
    false
}

/// Samples the file system counters once per [`DaemonConfig::stats_interval`].
///
/// Sample and fold happen in one critical section, and the `Arc<CryptoFs>` never leaves the state:
/// a clone held across the sample would be the one that makes [`close_fs`] in a concurrent `lock`
/// miss its flush. Taking a snapshot is a handful of atomic loads, no I/O, so holding the state
/// lock for it costs a `status` nothing.
fn stats_loop(shared: &Arc<Shared>) {
    while !shared.wait_for_stop(shared.config.stats_interval) {
        let mut state = shared.lock_state();
        let Some(snapshot) = state.fs.as_ref().map(|fs| fs.stats().snapshot()) else {
            continue;
        };
        state.apply_sample(snapshot, now_secs());
    }
}

/// Locks the vault once it has been idle for as long as its settings allow.
///
/// The settings are re-read on every tick, so changing `autoLockWhenIdle` or
/// `autoLockIdleSeconds` takes effect without unlocking the vault again. A failed unmount (the
/// volume is busy) is logged and retried on the next tick -- auto-lock never forces anything.
fn autolock_loop(shared: &Arc<Shared>) {
    while !shared.wait_for_stop(shared.config.autolock_tick) {
        let (phase, last_activity) = {
            let state = shared.lock_state();
            (state.phase, state.last_activity)
        };
        if phase != Phase::Unlocked {
            continue;
        }
        let settings = match shared.config.store.load() {
            Ok(settings) => settings,
            Err(err) => {
                log::warn!("cannot read the settings for auto-lock: {err}");
                continue;
            }
        };
        let Some(vault) = settings
            .directories
            .iter()
            .find(|vault| vault.id == shared.config.vault_id)
        else {
            continue;
        };
        if !vault.auto_lock_when_idle {
            continue;
        }
        let idle = now_secs().saturating_sub(last_activity);
        if idle < u64::from(vault.auto_lock_idle_seconds) {
            continue;
        }
        match lock_now(shared, false) {
            Ok(()) => {
                log::info!("auto-locking vault {} after {idle}s idle", vault.id);
                shared.request_stop();
                return;
            }
            Err(LockFailure::NotUnlocked) => return,
            Err(LockFailure::Unmount(message)) => {
                log::info!("auto-lock deferred: {message}");
            }
        }
    }
}

/// Spawns one of the daemon's worker threads. A thread that cannot be spawned is logged and left
/// out: a daemon without a stats sampler still serves its mount.
fn spawn_worker(name: &str, shared: Arc<Shared>, body: fn(&Arc<Shared>)) -> Option<JoinHandle<()>> {
    match std::thread::Builder::new()
        .name(name.to_owned())
        .spawn(move || body(&shared))
    {
        Ok(handle) => Some(handle),
        Err(err) => {
            log::error!("cannot start the {name} thread: {err}");
            None
        }
    }
}

/// Writes `response`; returns whether the connection is still usable.
fn respond(writer: &mut UnixStream, response: &Response) -> bool {
    match protocol::write_line(writer, response) {
        Ok(()) => true,
        Err(err) => {
            log::debug!("cannot answer request {}: {err}", response.id);
            false
        }
    }
}

/// A successful response carrying `value` as its result. A value that cannot be serialised (which
/// none of the result types can be) becomes `null` rather than a panic.
fn ok_json(id: u64, value: &impl serde::Serialize) -> Response {
    let result = serde_json::to_value(value).unwrap_or(serde_json::Value::Null);
    Response::ok(id, result)
}

/// The answer to a request that needs a mounted vault.
fn not_unlocked(id: u64) -> Response {
    Response::err(
        id,
        ErrorBody::NOT_UNLOCKED,
        "the vault is not unlocked (yet)",
    )
}

/// Now, in seconds since the epoch. A clock before 1970 reads as 0.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// What the daemon is doing, as `status.state` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Listening, waiting for the one `unlock`.
    Starting,
    /// Serving a mounted vault.
    Unlocked,
    /// Taking the mount down; nothing is served any more.
    Locking,
}

impl Phase {
    fn as_str(self) -> &'static str {
        match self {
            Phase::Starting => "STARTING",
            Phase::Unlocked => "UNLOCKED",
            Phase::Locking => "LOCKING",
        }
    }
}

/// Everything the threads mutate, behind one mutex.
///
/// One mutex rather than several: the phase, the mount, the file system and the counters are read
/// together by `status` and `stats` and changed together by `unlock` and `lock`, and a daemon has
/// no contention worth splitting them for.
///
/// It is held for short, I/O-free stretches only. Mounting and unmounting run under
/// [`Shared::operation`] instead and take this lock just to publish their result, so a `status`
/// that arrives while the vault is being mounted is answered right away -- with `STARTING`, until
/// the mount is up. The one thing that must happen under this lock is reading
/// [`DaemonState::fs`]: an `Arc<CryptoFs>` cloned out of here and kept alive would stop
/// [`close_fs`] from closing the file system.
struct DaemonState {
    phase: Phase,
    /// Set as soon as an `unlock` starts, so the unlock deadline does not fire in the middle of a
    /// slow mount and a second `unlock` is refused while the first is still running.
    unlock_started: bool,
    mount: Option<MountHandle>,
    fs: Option<Arc<CryptoFs>>,
    mountpoint: Option<String>,
    /// The Java class name of the mount service in use; empty while the daemon is starting.
    mounter: String,
    read_only: bool,
    last_activity: u64,
    in_use: bool,
    /// The previous sample, to derive the per-interval deltas from.
    last_snapshot: Option<StatsSnapshot>,
    rates: Rates,
}

/// The deltas of the most recent sampling interval.
#[derive(Debug, Default, Clone, Copy)]
struct Rates {
    bytes_read: u64,
    bytes_written: u64,
    bytes_encrypted: u64,
    bytes_decrypted: u64,
    cache_hit_rate: f64,
}

impl DaemonState {
    fn new() -> Self {
        Self {
            phase: Phase::Starting,
            unlock_started: false,
            mount: None,
            fs: None,
            mountpoint: None,
            mounter: String::new(),
            read_only: false,
            last_activity: now_secs(),
            in_use: false,
            last_snapshot: None,
            rates: Rates::default(),
        }
    }

    fn status(&self, shared: &Shared) -> StatusResult {
        StatusResult {
            vault_id: shared.config.vault_id.clone(),
            state: self.phase.as_str().to_owned(),
            mountpoint: self.mountpoint.clone(),
            mounter: self.mounter.clone(),
            read_only: self.read_only,
            started_at: shared.started_at,
            uptime_secs: now_secs().saturating_sub(shared.started_at),
            last_activity: self.last_activity,
            in_use: self.in_use,
        }
    }

    /// The totals straight from the file system, the rates from the last sampling interval.
    fn stats(&self) -> StatsResult {
        let totals = self
            .fs
            .as_ref()
            .map(|fs| fs.stats().snapshot())
            .or(self.last_snapshot)
            .unwrap_or(EMPTY_SNAPSHOT);
        StatsResult {
            bytes_per_second_read: self.rates.bytes_read,
            bytes_per_second_written: self.rates.bytes_written,
            bytes_per_second_encrypted: self.rates.bytes_encrypted,
            bytes_per_second_decrypted: self.rates.bytes_decrypted,
            cache_hit_rate: self.rates.cache_hit_rate,
            total_bytes_read: totals.bytes_read,
            total_bytes_written: totals.bytes_written,
            total_bytes_encrypted: totals.bytes_encrypted,
            total_bytes_decrypted: totals.bytes_decrypted,
            files_read: totals.accesses_read,
            files_written: totals.accesses_written,
            total_files_accessed: totals.accesses,
            last_activity: self.last_activity,
        }
    }

    /// Folds one sample into the rates.
    ///
    /// The `bytesPerSecond*` fields are the deltas of one sampling interval, which is 1 s in
    /// production ([`DaemonConfig::stats_interval`]); `cacheHitRate` is the hit ratio of that same
    /// interval, 0 when nothing was read. The first sample only establishes the baseline.
    ///
    /// `inUse` is derived here as well: [`CryptoFs`] does not publish how many file handles are
    /// open, so "in use" means "the access counter grew during the last interval". A volume that
    /// somebody keeps a file open on without touching it therefore reads as idle.
    fn apply_sample(&mut self, snapshot: StatsSnapshot, now: u64) {
        let Some(previous) = self.last_snapshot.replace(snapshot) else {
            return;
        };
        let delta = |current: u64, before: u64| current.saturating_sub(before);
        self.rates = Rates {
            bytes_read: delta(snapshot.bytes_read, previous.bytes_read),
            bytes_written: delta(snapshot.bytes_written, previous.bytes_written),
            bytes_encrypted: delta(snapshot.bytes_encrypted, previous.bytes_encrypted),
            bytes_decrypted: delta(snapshot.bytes_decrypted, previous.bytes_decrypted),
            cache_hit_rate: hit_rate(
                delta(snapshot.chunk_cache_hits, previous.chunk_cache_hits),
                delta(snapshot.chunk_cache_accesses, previous.chunk_cache_accesses),
            ),
        };
        let operations = delta(snapshot.accesses_read, previous.accesses_read)
            + delta(snapshot.accesses_written, previous.accesses_written);
        if operations > 0 {
            self.last_activity = now;
        }
        self.in_use = delta(snapshot.accesses, previous.accesses) > 0;
    }
}

/// `hits / accesses`, and 0 when nothing was accessed.
fn hit_rate(hits: u64, accesses: u64) -> f64 {
    if accesses == 0 {
        0.0
    } else {
        hits as f64 / accesses as f64
    }
}

/// An all-zero snapshot, for a `stats` request that arrives before the first sample.
const EMPTY_SNAPSHOT: StatsSnapshot = StatsSnapshot {
    bytes_read: 0,
    bytes_written: 0,
    bytes_decrypted: 0,
    bytes_encrypted: 0,
    chunk_cache_accesses: 0,
    chunk_cache_hits: 0,
    chunk_cache_misses: 0,
    accesses_read: 0,
    accesses_written: 0,
    accesses: 0,
};

/// The daemon's shared state: the configuration, the mutable state and the two ways to wait.
struct Shared {
    config: DaemonConfig,
    files: VaultStateFiles,
    pid: u32,
    /// When the daemon started, in seconds since the epoch; `status.uptimeSecs` counts from here.
    started_at: u64,
    state: Mutex<DaemonState>,
    /// Held for the duration of a mount or an unmount. Those run *without* [`Shared::state`] held
    /// -- they can take seconds and must not block `status` -- so this is what serialises them
    /// against each other and against the teardown.
    operation: Mutex<()>,
    events: Arc<Events>,
    /// The internal stop request (`lock`, `shutdown`, auto-lock), paired with [`Shared::stop_cv`].
    stop: Mutex<bool>,
    stop_cv: Condvar,
    /// The flag the signal handler sets; it can only be polled.
    external_shutdown: Arc<AtomicBool>,
    /// The error [`run_daemon`] returns, set by whoever ends the daemon abnormally.
    fatal: Mutex<Option<AppError>>,
    /// The open connections, so a shutdown can unblock the threads reading them.
    connections: Mutex<Option<HashMap<u64, UnixStream>>>,
    next_connection: AtomicU64,
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared")
            .field("vault_id", &self.config.vault_id)
            .field("pid", &self.pid)
            .field("started_at", &self.started_at)
            .finish_non_exhaustive()
    }
}

impl Shared {
    fn new(
        config: DaemonConfig,
        files: VaultStateFiles,
        external_shutdown: Arc<AtomicBool>,
        pid: u32,
    ) -> Self {
        Self {
            config,
            files,
            pid,
            started_at: now_secs(),
            state: Mutex::new(DaemonState::new()),
            operation: Mutex::new(()),
            events: Arc::new(Events::new()),
            stop: Mutex::new(false),
            stop_cv: Condvar::new(),
            external_shutdown,
            fatal: Mutex::new(None),
            connections: Mutex::new(Some(HashMap::new())),
            next_connection: AtomicU64::new(1),
        }
    }

    /// The mutable state. Poisoning is ignored: a panicking handler leaves the phase and the
    /// counters as they were, and a daemon that refuses to answer is worse than one that answers
    /// from slightly stale state.
    fn lock_state(&self) -> MutexGuard<'_, DaemonState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The mount/unmount lock, see [`Shared::operation`].
    fn lock_operation(&self) -> MutexGuard<'_, ()> {
        self.operation
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether the daemon has been asked to stop, from outside or from within.
    fn stop_requested(&self) -> bool {
        self.external_shutdown.load(Ordering::Relaxed)
            || *self.stop.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Asks every thread to stop and wakes the ones that are waiting.
    fn request_stop(&self) {
        *self.stop.lock().unwrap_or_else(PoisonError::into_inner) = true;
        self.stop_cv.notify_all();
        self.events.cv.notify_all();
    }

    /// Waits up to `timeout` for a stop request; returns whether one arrived.
    ///
    /// The wait is chopped into [`POLL_INTERVAL`] slices so the external flag -- which nothing can
    /// notify on -- is noticed promptly. An internal stop wakes the condvar at once.
    fn wait_for_stop(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if self.stop_requested() {
                return true;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            let guard = self.stop.lock().unwrap_or_else(PoisonError::into_inner);
            let (guard, _) = self
                .stop_cv
                .wait_timeout(guard, remaining.min(POLL_INTERVAL))
                .unwrap_or_else(PoisonError::into_inner);
            drop(guard);
        }
    }

    /// Whether the daemon has been waiting for its `unlock` for too long.
    fn unlock_deadline_passed(&self, started: Instant) -> bool {
        if started.elapsed() < self.config.unlock_timeout {
            return false;
        }
        let state = self.lock_state();
        state.phase == Phase::Starting && !state.unlock_started
    }

    fn set_fatal(&self, err: AppError) {
        let mut fatal = self.fatal.lock().unwrap_or_else(PoisonError::into_inner);
        if fatal.is_none() {
            *fatal = Some(err);
        }
    }

    fn take_fatal(&self) -> Option<AppError> {
        self.fatal
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }

    /// Remembers a connection so [`Shared::close_connections`] can unblock it. `None` once the
    /// daemon has stopped accepting -- the caller then drops the connection.
    fn register(&self, stream: &UnixStream) -> Option<u64> {
        let Ok(stream) = stream.try_clone() else {
            return None;
        };
        let id = self.next_connection.fetch_add(1, Ordering::Relaxed);
        let mut connections = self
            .connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        connections.as_mut()?.insert(id, stream);
        Some(id)
    }

    fn unregister(&self, id: u64) {
        if let Some(connections) = self
            .connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_mut()
        {
            connections.remove(&id);
        }
    }

    /// Shuts every open connection down, so the threads blocked on `read` return instead of
    /// keeping a client alive after the daemon is gone. The connection threads are detached: they
    /// end on their own once their socket is closed.
    fn close_connections(&self) {
        let connections = self
            .connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        for (_, stream) in connections.into_iter().flatten() {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }

    /// Pushes a file system event into the buffer as if the file system had reported it.
    #[cfg(test)]
    fn inject_event(&self, event: &FilesystemEvent) {
        self.events.push(event);
    }

    /// Forces the phase, so a test can look at a daemon in [`Phase::Locking`] without racing the
    /// unmount that would otherwise be the only way there.
    #[cfg(test)]
    fn force_phase(&self, phase: Phase) {
        self.lock_state().phase = phase;
    }
}

/// The daemon's event log: a bounded ring of the most recent [`EVENT_BUFFER_CAPACITY`] events,
/// plus the condvar that a follow stream waits on.
///
/// This lives in an `Arc` of its own rather than inside [`Shared`], because the [`CryptoFs`] event
/// sink holds a reference to it and [`Shared`] holds the file system -- routing the sink through
/// [`Shared`] would be a reference cycle that never frees either.
struct Events {
    queue: Mutex<EventQueue>,
    cv: Condvar,
}

/// The buffered records and the sequence number of the most recent one.
struct EventQueue {
    records: VecDeque<EventRecord>,
    /// The highest sequence number handed out so far; 0 before the first event.
    last_seq: u64,
}

impl Events {
    fn new() -> Self {
        Self {
            queue: Mutex::new(EventQueue {
                records: VecDeque::new(),
                // Sequence numbers start at 1, so `since: 0` means "everything".
                last_seq: 0,
            }),
            cv: Condvar::new(),
        }
    }

    /// The [`cryptomator_core::fs::EventSink`] the file system reports through.
    ///
    /// The sink is called with file system locks held, so it must not call back into the file
    /// system -- pushing onto this queue does not.
    fn sink(self: &Arc<Self>) -> cryptomator_core::fs::EventSink {
        let events = Arc::clone(self);
        Arc::new(move |event: FilesystemEvent| events.push(&event))
    }

    fn push(&self, event: &FilesystemEvent) {
        let record = {
            let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
            queue.last_seq += 1;
            let seq = queue.last_seq;
            let (cleartext_path, ciphertext_path) = event_paths(event);
            let record = EventRecord {
                seq,
                timestamp: now_secs(),
                kind: event.kind().to_owned(),
                message: event.to_string(),
                cleartext_path,
                ciphertext_path,
            };
            queue.records.push_back(record.clone());
            while queue.records.len() > EVENT_BUFFER_CAPACITY {
                queue.records.pop_front();
            }
            record
        };
        // Outside the lock: a follow stream wakes up and takes the same lock immediately.
        self.cv.notify_all();
        log::debug!("event {} {}", record.seq, record.kind);
    }

    /// Every buffered event after `since`, and the `since` to pass next time.
    ///
    /// `nextSeq` on the wire is that resume token -- the sequence number of the newest event the
    /// daemon has produced, 0 when it has produced none. It is *not* the number the next event
    /// will get: `since` is exclusive (`seq > since`), so handing back `last + 1` would skip
    /// exactly the event that number belongs to.
    fn since(&self, since: u64) -> (Vec<EventRecord>, u64) {
        let queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        let events: Vec<EventRecord> = queue
            .records
            .iter()
            .filter(|record| record.seq > since)
            .cloned()
            .collect();
        (events, queue.last_seq)
    }

    /// Waits up to `timeout` for an event newer than `cursor`.
    fn wait_for_more(&self, cursor: u64, timeout: Duration) {
        let queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        if queue.last_seq > cursor {
            return;
        }
        let (guard, _) = self
            .cv
            .wait_timeout(queue, timeout)
            .unwrap_or_else(PoisonError::into_inner);
        drop(guard);
    }
}

/// The cleartext and ciphertext paths an event names, if it names them.
fn event_paths(event: &FilesystemEvent) -> (Option<String>, Option<String>) {
    let path = |p: &Path| Some(p.display().to_string());
    match event {
        FilesystemEvent::DecryptionFailed {
            ciphertext_path, ..
        } => (None, path(ciphertext_path)),
        FilesystemEvent::ConflictResolved {
            canonical_cleartext_path,
            resolved_ciphertext_path,
            ..
        } => (
            Some(canonical_cleartext_path.clone()),
            path(resolved_ciphertext_path),
        ),
        FilesystemEvent::ConflictResolutionFailed {
            canonical_cleartext_path,
            conflicting_ciphertext_path,
            ..
        } => (
            Some(canonical_cleartext_path.clone()),
            path(conflicting_ciphertext_path),
        ),
        FilesystemEvent::BrokenDirFile { ciphertext_path } => (None, path(ciphertext_path)),
        FilesystemEvent::BrokenFileNode {
            cleartext_path,
            ciphertext_path,
        } => (Some(cleartext_path.clone()), path(ciphertext_path)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::DaemonClient;
    use crate::settings::{SettingsJson, VaultSettingsJson};
    use cryptomator_core::constants::DEFAULT_KEY_ID;
    use cryptomator_core::{initialize, CipherCombo, OsRng};
    use cryptomator_mount::api::{Mount, MountBuilder, MountCapability, MountError, UnmountError};
    use cryptomator_mount::registry::{
        NullMountProvider, FALLBACK_WEBDAV_CLASS, NULL_MOUNTER_CLASS, NULL_MOUNT_MARKER,
    };
    use cryptomator_mount::FallbackMounter;
    use std::sync::mpsc::{self, Receiver, RecvTimeoutError, TryRecvError};
    use tempfile::TempDir;

    /// The vault id every test uses. Short on purpose: it becomes the socket's file name, and
    /// macOS caps a socket path at 104 bytes.
    const VAULT_ID: &str = "V1";
    /// The vault's display name, and therefore the name of its mount directory.
    const MOUNT_NAME: &str = "Vault";
    /// The key the test vault is initialised with.
    const KEY: [u8; 64] = [7u8; 64];
    /// How long a test waits for something the daemon does in another thread.
    const DEADLINE: Duration = Duration::from_secs(10);

    /// A daemon running in a thread of this process, with everything it works on in a temporary
    /// directory.
    struct Daemon {
        dir: TempDir,
        shared: Arc<Shared>,
        shutdown: Arc<AtomicBool>,
        outcome: Receiver<Result<()>>,
        files: VaultStateFiles,
        mount_dir: PathBuf,
    }

    impl Daemon {
        /// [`Daemon::start_sampling`] with a sampling interval no test has to think about.
        fn start(
            busy: bool,
            timeouts: (Duration, Duration),
            settings: impl FnOnce(&mut VaultSettingsJson),
        ) -> Self {
            Self::start_sampling(busy, timeouts, Duration::from_millis(20), settings)
        }

        /// [`Daemon::start_with`] on the null mounter; `busy` makes its graceful unmount refuse.
        fn start_sampling(
            busy: bool,
            timeouts: (Duration, Duration),
            stats_interval: Duration,
            settings: impl FnOnce(&mut VaultSettingsJson),
        ) -> Self {
            Self::start_with(
                vec![Box::new(NullMountProvider::enabled(true, busy))],
                timeouts,
                stats_interval,
                settings,
            )
        }

        /// [`Daemon::start_full`] with the 10 ms `force_unmount_after` every other test needs and
        /// no notice callback.
        fn start_with(
            services: Vec<Box<dyn MountService>>,
            timeouts: (Duration, Duration),
            stats_interval: Duration,
            settings: impl FnOnce(&mut VaultSettingsJson),
        ) -> Self {
            Self::start_full(
                services,
                timeouts,
                stats_interval,
                Duration::from_millis(10),
                None,
                settings,
            )
        }

        /// Starts a daemon over a freshly initialised vault, picking from `services`;
        /// `settings` gets to change the vault's entry before it is saved.
        #[allow(clippy::too_many_arguments)]
        fn start_full(
            services: Vec<Box<dyn MountService>>,
            timeouts: (Duration, Duration),
            stats_interval: Duration,
            force_unmount_after: Duration,
            notice: Option<NoticeFn>,
            settings: impl FnOnce(&mut VaultSettingsJson),
        ) -> Self {
            // `tempfile` builds below `std::env::temp_dir()`, which keeps the socket path inside
            // the 104 bytes macOS allows for one.
            let dir = tempfile::tempdir().expect("temp dir");
            let vault_path = dir.path().join("v");
            std::fs::create_dir_all(&vault_path).expect("vault dir");
            initialize(
                &vault_path,
                &Masterkey::from_raw(KEY),
                CipherCombo::SivGcm,
                220,
                DEFAULT_KEY_ID,
                &mut OsRng,
            )
            .expect("initialize");

            let mut json = SettingsJson::default();
            let mut vault = VaultSettingsJson::new(VAULT_ID.to_owned(), &vault_path);
            vault.display_name = Some(MOUNT_NAME.to_owned());
            settings(&mut vault);
            json.directories.push(vault);
            let store = SettingsStore::at(dir.path().join("settings.json"));
            store.save(&mut json).expect("save settings");

            let mount_points_dir = dir.path().join("m");
            let cli = CliConfig {
                mount_points_dir: Some(mount_points_dir.to_string_lossy().into_owned()),
                ..CliConfig::default()
            };

            let state_dir = StateDir::at(dir.path().join("s"));
            let files = state_dir.files(VAULT_ID);
            let (unlock_timeout, autolock_tick) = timeouts;
            let config = DaemonConfig {
                vault_id: VAULT_ID.to_owned(),
                state_dir,
                store,
                cli,
                home: dir.path().to_path_buf(),
                services,
                unlock_timeout,
                stats_interval,
                autolock_tick,
                force_unmount_after,
                // The `log` crate allows one logger per process and the test binary shares one,
                // so the daemons under test write no log file.
                log_file: None,
                notice,
            };

            let shutdown = Arc::new(AtomicBool::new(false));
            let (ready_tx, ready_rx) = mpsc::channel();
            let (outcome_tx, outcome) = mpsc::channel();
            let flag = Arc::clone(&shutdown);
            std::thread::spawn(move || {
                let result = run_daemon_with_hook(config, flag, |shared| {
                    let _ = ready_tx.send(Arc::clone(shared));
                });
                let _ = outcome_tx.send(result);
            });
            let shared = ready_rx.recv_timeout(DEADLINE).expect("the daemon starts");
            Daemon {
                dir,
                shared,
                shutdown,
                outcome,
                files,
                mount_dir: mount_points_dir.join(MOUNT_NAME),
            }
        }

        /// A connected client. The socket appears a moment after the daemon thread starts.
        fn client(&self) -> DaemonClient {
            DaemonClient::connect_with_retry(&self.files.socket, DEADLINE).expect("connect")
        }

        /// What `run_daemon` returned, waiting up to `DEADLINE` for it.
        fn wait(&self) -> Result<()> {
            match self.outcome.recv_timeout(DEADLINE) {
                Ok(result) => result,
                Err(RecvTimeoutError::Timeout) => {
                    panic!("the daemon did not stop within {DEADLINE:?}")
                }
                Err(RecvTimeoutError::Disconnected) => panic!("the daemon thread died"),
            }
        }

        /// Whether the daemon is still running.
        fn running(&self) -> bool {
            matches!(self.outcome.try_recv(), Err(TryRecvError::Empty))
        }
    }

    /// [`unlock_request_for`] on the null mounter.
    fn unlock_request(key: &str) -> Request {
        unlock_request_for(NULL_MOUNTER_CLASS, key)
    }

    /// An `unlock` request for `mounter`, carrying `key` -- base64 of the 64 raw bytes, as the
    /// wire format has it. `Request` has a `Drop` impl and therefore no functional-update syntax,
    /// so the whole variant is written out here and the encoded key passed in.
    fn unlock_request_for(mounter: &str, key: &str) -> Request {
        unlock_request_full(mounter, key, None, None)
    }

    /// [`unlock_request_for`] with the two fields the WebDAV tests need: a loopback `port` and
    /// `read_only`.
    fn unlock_request_full(
        mounter: &str,
        key: &str,
        port: Option<u16>,
        read_only: Option<bool>,
    ) -> Request {
        Request::Unlock {
            id: 0,
            key: key.to_owned(),
            mounter: Some(mounter.to_owned()),
            mount_point: None,
            mount_options: Vec::new(),
            port,
            read_only,
            volume_name: None,
            max_cleartext_name_length: 220,
        }
    }

    /// The test vault's key, base64 encoded as the wire format wants it.
    fn encoded(key: [u8; 64]) -> String {
        BASE64.encode(&key)
    }

    /// The daemon error code of a failed call.
    fn error_code(err: &AppError) -> &str {
        match err {
            AppError::DaemonError { code, .. } => code,
            other => panic!("expected a daemon error, got {other:?}"),
        }
    }

    /// A configuration for a daemon that never gets as far as its vault: the tests using it make
    /// publishing the state files fail. Only what a test puts below `dir` exists.
    fn state_file_config(dir: &Path) -> DaemonConfig {
        DaemonConfig {
            vault_id: VAULT_ID.to_owned(),
            state_dir: StateDir::at(dir.join("s")),
            store: SettingsStore::at(dir.join("settings.json")),
            cli: CliConfig::default(),
            home: dir.to_path_buf(),
            services: vec![Box::new(NullMountProvider::enabled(true, false))],
            unlock_timeout: Duration::from_millis(200),
            stats_interval: Duration::from_millis(20),
            autolock_tick: Duration::from_secs(3600),
            force_unmount_after: Duration::from_millis(10),
            log_file: None,
            notice: None,
        }
    }

    /// One HTTP request on a loopback address, written and read by hand: the app crate has no HTTP
    /// client, and a `TcpStream` is all a status line needs. `Connection: close` makes the server
    /// end the response, so reading to the end terminates.
    ///
    /// Byte-identical to `http` in `crates/crypto/tests/cli_daemon.rs`, and deliberately so: the
    /// two live in different crates, and a `#[cfg(test)]` helper cannot be shared across a crate
    /// boundary without turning it into a published API. Change one, change the other.
    fn http(addr: &str, request: &str) -> String {
        use std::io::{Read, Write};
        let mut stream = std::net::TcpStream::connect(addr).expect("connect to the WebDAV server");
        stream.set_read_timeout(Some(DEADLINE)).expect("timeout");
        stream
            .write_all(request.as_bytes())
            .expect("write the request");
        let mut response = Vec::new();
        // A timeout is not a failure of the test's own I/O: whatever arrived is what is asserted
        // on, and an empty answer fails the assertion with the status line it did not get.
        let _ = stream.read_to_end(&mut response);
        String::from_utf8_lossy(&response).into_owned()
    }

    /// `host:port` of a `http://host:port/path` URL. The twin of `authority` in
    /// `crates/crypto/tests/cli_daemon.rs` -- see the note on [`http`].
    fn authority(url: &str) -> String {
        url.trim_start_matches("http://")
            .split('/')
            .next()
            .expect("an authority")
            .to_owned()
    }

    /// A read-only unlock over the WebDAV fallback: nothing in the mount chain enforces it (the
    /// service has neither `READ_ONLY` nor `MOUNT_FLAGS`), so the `CryptoFs` the daemon opens is
    /// the only thing that does -- which is why `unlock` and `apply_capabilities` share
    /// [`mounting::read_only`]. A `PUT` proves it end to end.
    ///
    /// The very same `PUT` against a writable unlock is the control: without it a server that
    /// stopped implementing `PUT` at all would still read as "read-only works".
    #[test]
    fn a_read_only_webdav_unlock_answers_a_put_with_403_while_a_writable_one_stores_it() {
        let daemon = Daemon::start_with(
            vec![Box::new(FallbackMounter)],
            (DEADLINE, Duration::from_secs(3600)),
            Duration::from_millis(20),
            |_| {},
        );
        let mut client = daemon.client();
        // Port 0: any free one. The vault's own `usesReadOnlyMode` is false, so `--read-only` is
        // the only thing that can make this read-only.
        let result = client
            .call(unlock_request_full(
                FALLBACK_WEBDAV_CLASS,
                &encoded(KEY),
                Some(0),
                Some(true),
            ))
            .expect("unlock");
        let url = result
            .get("mountpoint")
            .and_then(serde_json::Value::as_str)
            .expect("the answer names the URL")
            .to_owned();
        assert!(url.starts_with("http://127.0.0.1:"), "{url}");
        assert!(
            daemon.files.read_info().expect("run info").read_only,
            "the run info records the read-only mount"
        );

        let addr = authority(&url);
        let path = format!("/{VAULT_ID}");
        let response = http(
            &addr,
            &format!(
                "PROPFIND {path} HTTP/1.1\r\nHost: {addr}\r\nDepth: 0\r\n\
                 Content-Length: 0\r\nConnection: close\r\n\r\n"
            ),
        );
        assert!(
            response.starts_with("HTTP/1.1 207"),
            "the vault is served: {response}"
        );
        let response = http(
            &addr,
            &format!(
                "PUT {path}/new.txt HTTP/1.1\r\nHost: {addr}\r\nContent-Length: 2\r\n\
                 Connection: close\r\n\r\nhi"
            ),
        );
        assert!(
            response.starts_with("HTTP/1.1 403"),
            "a read-only vault forbids every write: {response}"
        );

        client.lock(false).expect("lock");
        daemon.wait().expect("a clean stop");

        // The control: the same request, the same mounter, `read_only` false -- the write goes
        // through, so the 403 above is the read-only rule and not a missing `PUT`.
        let writable = Daemon::start_with(
            vec![Box::new(FallbackMounter)],
            (DEADLINE, Duration::from_secs(3600)),
            Duration::from_millis(20),
            |_| {},
        );
        let mut client = writable.client();
        let result = client
            .call(unlock_request_full(
                FALLBACK_WEBDAV_CLASS,
                &encoded(KEY),
                Some(0),
                Some(false),
            ))
            .expect("unlock");
        let url = result
            .get("mountpoint")
            .and_then(serde_json::Value::as_str)
            .expect("the answer names the URL")
            .to_owned();
        assert!(
            !writable.files.read_info().expect("run info").read_only,
            "the run info records the writable mount"
        );
        let addr = authority(&url);
        let response = http(
            &addr,
            &format!(
                "PUT /{VAULT_ID}/new.txt HTTP/1.1\r\nHost: {addr}\r\nContent-Length: 2\r\n\
                 Connection: close\r\n\r\nhi"
            ),
        );
        assert!(
            response.starts_with("HTTP/1.1 201") || response.starts_with("HTTP/1.1 204"),
            "a writable vault stores the file: {response}"
        );

        client.lock(false).expect("lock");
        writable.wait().expect("a clean stop");
    }

    #[test]
    fn a_daemon_unlocks_serves_and_locks_one_vault() {
        // Busy, so that the graceful `lock` fails and only `lock --force` gets through.
        let daemon = Daemon::start(true, (DEADLINE, Duration::from_secs(3600)), |_| {});
        let mut client = daemon.client();

        let status = client.status().expect("status");
        assert_eq!(status.state, "STARTING", "nothing is mounted yet");
        assert_eq!(status.vault_id, VAULT_ID);
        assert_eq!(status.mountpoint, None);

        let result = client.call(unlock_request(&encoded(KEY))).expect("unlock");
        let mountpoint = result
            .get("mountpoint")
            .and_then(serde_json::Value::as_str)
            .expect("the answer names the mount point");
        assert_eq!(
            Path::new(mountpoint),
            daemon.mount_dir,
            "the vault mounts at <mountPointsDir>/<mountName>"
        );
        assert!(
            daemon.mount_dir.join(NULL_MOUNT_MARKER).is_file(),
            "the null mounter left its marker"
        );

        let info = daemon.files.read_info().expect("the run info is published");
        assert_eq!(info.vault_id, VAULT_ID);
        assert_eq!(info.mounter, NULL_MOUNTER_CLASS);
        assert_eq!(info.mountpoint.as_deref(), Some(mountpoint));
        assert_eq!(info.pid, std::process::id());
        assert!(!info.read_only);

        let status = client.status().expect("status");
        assert_eq!(status.state, "UNLOCKED");
        assert_eq!(status.mounter, NULL_MOUNTER_CLASS);
        assert_eq!(status.mountpoint.as_deref(), Some(mountpoint));

        let second = client
            .call(unlock_request(&encoded(KEY)))
            .expect_err("second unlock");
        assert_eq!(error_code(&second), ErrorBody::ALREADY_UNLOCKED);

        let stats = client.stats().expect("stats");
        assert_eq!(stats.total_bytes_read, 0, "nothing has been read yet");
        assert_eq!(stats.cache_hit_rate, 0.0);
        assert!(stats.last_activity >= info.started_at.saturating_sub(1));

        daemon.shared.inject_event(&FilesystemEvent::BrokenDirFile {
            ciphertext_path: PathBuf::from("/v/d/AB/CD/dir.c9r"),
        });
        let events = client.events(0).expect("events");
        assert_eq!(
            events.next_seq, 1,
            "`nextSeq` is the newest event's own number: `since` is exclusive"
        );
        assert_eq!(events.events.len(), 1);
        let event = &events.events[0];
        assert_eq!(event.seq, 1);
        assert_eq!(event.kind, "BROKEN_DIR_FILE");
        assert_eq!(event.ciphertext_path.as_deref(), Some("/v/d/AB/CD/dir.c9r"));
        assert!(event.message.contains("broken directory file"));
        assert!(
            client.events(1).expect("events since 1").events.is_empty(),
            "`since` skips what the caller has already seen"
        );

        // A follow stream replays the buffer and then keeps delivering. The second event is
        // injected while the stream is already open, so the condvar path is exercised too.
        let mut follower = daemon.client();
        let injecting = Arc::clone(&daemon.shared);
        let injector = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            injecting.inject_event(&FilesystemEvent::BrokenDirFile {
                ciphertext_path: PathBuf::from("/v/d/AB/EF/dir.c9r"),
            });
        });
        let mut streamed = Vec::new();
        follower
            .stream(
                Request::Events {
                    id: 0,
                    follow: true,
                    since: 0,
                },
                |event| {
                    streamed.push(event.seq);
                    // Stop after the second one; the client then shuts the connection down and
                    // the daemon's stream ends with it.
                    streamed.len() < 2
                },
            )
            .expect("follow stream");
        injector.join().expect("the injector thread");
        assert_eq!(streamed, vec![1, 2], "buffered first, then live");
        drop(follower);

        let busy = client.lock(false).expect_err("the volume is busy");
        assert_eq!(error_code(&busy), ErrorBody::UNMOUNT_FAILED);
        client.ping().expect("a failed lock leaves the daemon up");
        assert_eq!(
            client.status().expect("status").state,
            "UNLOCKED",
            "a failed lock returns to UNLOCKED"
        );

        client.lock(true).expect("forced lock");
        assert!(daemon.wait().is_ok(), "a locked daemon exits cleanly");
        assert!(!daemon.files.socket.exists(), "the socket is gone");
        assert!(!daemon.files.pid.exists(), "the pid file is gone");
        assert!(!daemon.files.info.exists(), "the run info is gone");
        assert!(
            !daemon.mount_dir.exists(),
            "the mount directory the daemon created is gone"
        );
        drop(daemon.dir);
    }

    #[test]
    fn an_idle_vault_locks_itself() {
        let daemon = Daemon::start(false, (DEADLINE, Duration::from_millis(50)), |vault| {
            vault.auto_lock_when_idle = true;
            vault.auto_lock_idle_seconds = 1;
        });
        let mut client = daemon.client();
        client.call(unlock_request(&encoded(KEY))).expect("unlock");

        assert!(daemon.wait().is_ok(), "the daemon auto-locks and exits");
        assert!(!daemon.files.socket.exists(), "the state files are gone");
        assert!(
            !daemon.mount_dir.join(NULL_MOUNT_MARKER).exists(),
            "the volume is unmounted"
        );
        assert!(
            !daemon.shutdown.load(Ordering::Relaxed),
            "no signal was involved"
        );
        drop(daemon.dir);
    }

    #[test]
    fn a_daemon_nobody_unlocks_gives_up() {
        let daemon = Daemon::start(
            false,
            (Duration::from_millis(200), Duration::from_secs(3600)),
            |_| {},
        );
        // The daemon serves requests while it waits, and a `status` must not keep it alive.
        let mut client = daemon.client();
        assert_eq!(client.status().expect("status").state, "STARTING");

        let err = daemon.wait().expect_err("the unlock deadline passes");
        match &err {
            AppError::Io(io) => assert_eq!(io.kind(), io::ErrorKind::TimedOut, "{io}"),
            other => panic!("expected a timeout, got {other:?}"),
        }
        assert!(!daemon.files.socket.exists(), "the socket is gone");
        assert!(!daemon.files.pid.exists(), "the pid file is gone");
        assert!(!daemon.files.info.exists(), "no run info was ever written");
        drop(daemon.dir);
    }

    #[test]
    fn a_key_that_does_not_match_fails_the_unlock_and_stops_the_daemon() {
        let daemon = Daemon::start(false, (DEADLINE, Duration::from_secs(3600)), |_| {});
        let mut client = daemon.client();

        let short = client
            .call(unlock_request("AAAA"))
            .expect_err("a key of the wrong length");
        assert_eq!(error_code(&short), ErrorBody::BAD_REQUEST);
        assert!(daemon.running(), "a malformed key may be retried");

        let err = client
            .call(unlock_request(&encoded([9u8; 64])))
            .expect_err("the wrong key");
        match &err {
            AppError::DaemonError { code, message } => {
                assert_eq!(code, ErrorBody::MOUNT_FAILED);
                assert_eq!(message, "vault key does not match");
            }
            other => panic!("expected a daemon error, got {other:?}"),
        }

        match daemon.wait().expect_err("the daemon gives up") {
            AppError::MountFailed(message) => {
                assert_eq!(message, "vault key does not match");
            }
            other => panic!("expected a mount failure, got {other:?}"),
        }
        assert!(!daemon.files.socket.exists(), "the state files are gone");
        assert!(!daemon.files.pid.exists());
        assert!(
            !daemon.mount_dir.exists(),
            "nothing was mounted, so no mount directory was left behind"
        );
        drop(daemon.dir);
    }

    #[test]
    fn a_lock_closes_the_file_system_the_sampler_is_reading() {
        let owned_before = OWNED_CLOSES.load(Ordering::Relaxed);
        // 1 ms between samples: the stats thread is inside the state almost continuously, which is
        // where a clone of the `Arc<CryptoFs>` would escape from.
        for _ in 0..3 {
            let daemon = Daemon::start_sampling(
                false,
                (DEADLINE, Duration::from_secs(3600)),
                Duration::from_millis(1),
                |_| {},
            );
            let mut client = daemon.client();
            client.call(unlock_request(&encoded(KEY))).expect("unlock");
            client.lock(false).expect("lock");
            assert!(daemon.wait().is_ok(), "a locked daemon exits cleanly");
            drop(daemon.dir);
        }
        assert_eq!(
            SHARED_CLOSES.load(Ordering::Relaxed),
            0,
            "the file system was owned every time it was closed, so every `close` flushed"
        );
        assert!(
            OWNED_CLOSES.load(Ordering::Relaxed) > owned_before,
            "and it really was closed"
        );
    }

    #[test]
    fn a_run_info_that_cannot_be_written_takes_the_volume_down_again() {
        // Busy, so the graceful unmount fails: only the forced retry gets this volume down.
        let daemon = Daemon::start(true, (DEADLINE, Duration::from_secs(3600)), |_| {});
        let mut client = daemon.client();
        // A directory where the run info goes; the rename that publishes it cannot succeed.
        std::fs::create_dir(&daemon.files.info).expect("the blocked run info path");

        let err = client
            .call(unlock_request(&encoded(KEY)))
            .expect_err("the run info cannot be published");
        assert_eq!(error_code(&err), ErrorBody::MOUNT_FAILED);

        let outcome = daemon.wait().expect_err("a failed unlock stops the daemon");
        assert!(matches!(outcome, AppError::Io(_)), "{outcome:?}");
        assert!(
            !daemon.mount_dir.join(NULL_MOUNT_MARKER).exists(),
            "a volume the CLI could not find again must not stay mounted"
        );
        assert!(
            !daemon.mount_dir.exists(),
            "and the mount directory goes with it"
        );
        drop(daemon.dir);
    }

    #[test]
    fn the_visibility_wait_polls_until_the_volume_is_there() {
        let mut looks = 0;
        let visible = wait_until_visible(
            || {
                looks += 1;
                Ok(looks == 3)
            },
            || false,
            Duration::from_secs(30),
            || {},
        );
        assert!(visible, "the third look finds the volume");
        assert_eq!(looks, 3, "and nothing is checked after that");
    }

    #[test]
    fn the_visibility_wait_gives_up_after_its_timeout() {
        let timeout = Duration::from_millis(120);
        let mut looks = 0;
        let started = Instant::now();
        let visible = wait_until_visible(
            || {
                looks += 1;
                Ok(false)
            },
            || false,
            timeout,
            || {},
        );
        let elapsed = started.elapsed();
        assert!(!visible, "a volume that never appears is a failure");
        assert!(
            elapsed >= timeout,
            "the full timeout is waited out: {elapsed:?}"
        );
        assert!(
            looks > 1,
            "and it is polled, not slept through: {looks} looks"
        );
    }

    #[test]
    fn the_visibility_wait_stops_early_when_asked_to() {
        // `unlock` holds the operation lock for the whole wait, which `shutdown_sequence` needs
        // to take a volume down on SIGINT/SIGTERM -- so a stop request must end the wait right
        // away instead of after the full `MOUNT_VISIBLE_TIMEOUT`.
        let mut looks = 0;
        let visible = wait_until_visible(
            || {
                looks += 1;
                Ok(false)
            },
            || true,
            Duration::from_secs(30),
            || {},
        );
        assert!(
            !visible,
            "a stop request is treated as failure, like a timeout"
        );
        assert_eq!(
            looks, 1,
            "it gives up after the very first look, within one poll"
        );
    }

    #[test]
    fn the_visibility_wait_notices_once_past_one_second() {
        let notices = std::cell::RefCell::new(0);
        let visible = wait_until_visible(
            || Ok(false),
            || false,
            Duration::from_millis(1200),
            || *notices.borrow_mut() += 1,
        );
        assert!(!visible, "the volume never appears, so this times out");
        assert_eq!(
            *notices.borrow(),
            1,
            "the notice fires exactly once, once the wait has lasted past the first second"
        );
    }

    #[test]
    fn the_visibility_wait_backs_off_after_the_first_second() {
        let mut looks = 0;
        let visible = wait_until_visible(
            || {
                looks += 1;
                Ok(false)
            },
            || false,
            Duration::from_secs(2),
            || {},
        );
        assert!(!visible, "the volume never appears");
        // ~1s of 50ms looks (20) plus ~1s of 250ms looks (4), plus the very first look before any
        // sleep -- a range wide enough for scheduling jitter without pinning an exact count.
        assert!(
            (18..=30).contains(&looks),
            "expected roughly 20 fast + 4 slow polls, got {looks}"
        );
    }

    #[test]
    fn the_visibility_wait_treats_an_unreadable_mount_table_as_visible() {
        // An unreadable mount table (`/sbin/mount` refusing to run, a missing
        // `/proc/self/mountinfo`) cannot tell "not yet visible" from "never will be", so this must
        // not fail a mount that is probably fine.
        let mut looks = 0;
        let visible = wait_until_visible(
            || {
                looks += 1;
                Err(io::Error::other("mount table unreadable"))
            },
            || false,
            Duration::from_secs(30),
            || {},
        );
        assert!(
            visible,
            "an unreadable mount table is treated as the volume being visible"
        );
        assert_eq!(
            looks, 1,
            "it gives up on the very first look, not the full timeout"
        );
    }

    #[test]
    fn a_null_mount_is_not_waited_for_in_the_mount_table() {
        // A null mount never enters the mount table, so `MountHandle::appears_in_mount_table` is
        // false for it and the unlock must not wait at all -- waiting would cost
        // `MOUNT_VISIBLE_TIMEOUT` and then fail the unlock.
        let daemon = Daemon::start(false, (DEADLINE, Duration::from_secs(3600)), |_| {});
        let mut client = daemon.client();
        let started = Instant::now();
        client.call(unlock_request(&encoded(KEY))).expect("unlock");
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(1),
            "the unlock answered after {elapsed:?}, so it waited for the mount table"
        );
        assert!(
            daemon.mount_dir.join(NULL_MOUNT_MARKER).is_file(),
            "and it really mounted"
        );
        client.lock(false).expect("lock");
        assert!(daemon.wait().is_ok(), "a locked daemon exits cleanly");
        drop(daemon.dir);
    }

    #[test]
    fn a_locking_daemon_refuses_events_and_stats() {
        let daemon = Daemon::start(false, (DEADLINE, Duration::from_secs(3600)), |_| {});
        let mut client = daemon.client();
        client.call(unlock_request(&encoded(KEY))).expect("unlock");
        // The real `Locking` window is an unmount long; this is the same state, held still.
        daemon.shared.force_phase(Phase::Locking);

        let events = client.events(0).expect_err("events while locking");
        assert_eq!(error_code(&events), ErrorBody::NOT_UNLOCKED);
        let stats = client.stats().expect_err("stats while locking");
        assert_eq!(error_code(&stats), ErrorBody::NOT_UNLOCKED);
        assert_eq!(
            client.status().expect("status").state,
            "LOCKING",
            "ping, status and shutdown are what a locking daemon still answers"
        );
        client.ping().expect("ping");

        daemon.shutdown.store(true, Ordering::Relaxed);
        assert!(daemon.wait().is_ok(), "the shutdown takes the volume down");
        assert!(!daemon.mount_dir.join(NULL_MOUNT_MARKER).exists());
        drop(daemon.dir);
    }

    #[test]
    fn a_daemon_leaves_the_socket_another_one_answers_on_alone() {
        let dir = tempfile::tempdir().expect("temp dir");
        let config = state_file_config(dir.path());
        config.state_dir.ensure().expect("state dir");
        let files = config.state_dir.files(VAULT_ID);
        // Stand-in for the daemon that is already serving this vault.
        let listener = UnixListener::bind(&files.socket).expect("the first daemon's socket");
        files.write_pid(4242).expect("its pid file");

        let err = run_daemon(config, Arc::new(AtomicBool::new(false)))
            .expect_err("the vault is already served");
        assert_eq!(error_code(&err), ErrorBody::ALREADY_UNLOCKED);
        assert!(
            files.socket.exists(),
            "the running daemon keeps its socket -- it is still listening on it"
        );
        listener.set_nonblocking(true).expect("nonblocking");
        assert!(
            listener.accept().is_ok(),
            "the probe connected -- that is how the second daemon noticed the first"
        );
        assert!(
            matches!(listener.accept(), Err(err) if err.kind() == io::ErrorKind::WouldBlock),
            "and it was the only connection"
        );
        assert_eq!(files.read_pid(), Some(4242), "its pid file is untouched");
        drop(listener);
        drop(dir);
    }

    /// The lost start-up race: `refuse_if_serving` passes, `write_pid` overwrites `<id>.pid` with
    /// this daemon's pid, and only `bind_socket`'s own probe then finds the winner. The loser has
    /// to take its pid back -- but only its own: if the winner's `write_pid` landed after ours,
    /// removing the file would leave the winner without one for its whole life.
    #[test]
    fn the_loser_of_the_start_up_race_takes_back_only_its_own_pid_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let state_dir = StateDir::at(dir.path().join("s"));
        state_dir.ensure().expect("state dir");
        let files = state_dir.files(VAULT_ID);
        let ours = std::process::id();

        // Our own pid, written a moment before the race was lost: it names a process that is
        // about to die, and a pid file naming a dead process is what a crashed daemon looks like.
        files.write_pid(ours).expect("write pid");
        drop_pid_file_if_ours(&files, ours);
        assert_eq!(files.read_pid(), None, "we take our own pid back");

        // The winner wrote its pid after ours: that one belongs there and has to survive.
        files.write_pid(4242).expect("the winner's pid");
        drop_pid_file_if_ours(&files, ours);
        assert_eq!(
            files.read_pid(),
            Some(4242),
            "the winner's pid file is left alone"
        );

        // No pid file at all (or an unreadable one) is not an error either.
        std::fs::remove_file(&files.pid).expect("remove");
        drop_pid_file_if_ours(&files, ours);
        std::fs::write(&files.pid, b"not a pid").expect("garbage");
        drop_pid_file_if_ours(&files, ours);
        assert!(files.pid.exists(), "a pid file we cannot read is not ours");
        drop(dir);
    }

    /// Two `run_daemon`s on the same state directory: exactly one serves the vault, the other
    /// fails fast with `ALREADY_UNLOCKED`, and the pid file that survives names the winner.
    #[test]
    fn two_daemons_on_one_state_dir_leave_exactly_one_serving() {
        let dir = tempfile::tempdir().expect("temp dir");
        let first = state_file_config(dir.path());
        let files = first.state_dir.files(VAULT_ID);
        let second = state_file_config(dir.path());

        let shutdown = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&shutdown);
        let (ready_tx, ready_rx) = mpsc::channel();
        let (winner_tx, winner) = mpsc::channel();
        std::thread::spawn(move || {
            let result = run_daemon_with_hook(first, flag, |shared| {
                let _ = ready_tx.send(Arc::clone(shared));
            });
            let _ = winner_tx.send(result);
        });
        // Only start the second one once the first is listening, so "already serving" is a fact
        // and not a race the test has to win.
        let shared = ready_rx
            .recv_timeout(DEADLINE)
            .expect("the first daemon starts");
        assert_eq!(files.read_pid(), Some(shared.pid), "the winner's pid file");

        let err = run_daemon(second, Arc::new(AtomicBool::new(false)))
            .expect_err("the vault is already served");
        assert_eq!(error_code(&err), ErrorBody::ALREADY_UNLOCKED);
        assert_eq!(
            files.read_pid(),
            Some(shared.pid),
            "the loser did not take the winner's pid file with it"
        );
        assert!(
            files.socket.exists(),
            "nor its socket -- the winner is still listening on it"
        );

        shutdown.store(true, Ordering::Relaxed);
        winner
            .recv_timeout(DEADLINE)
            .expect("the first daemon stops")
            .expect("cleanly");
        drop(dir);
    }

    #[test]
    fn a_daemon_that_cannot_write_its_pid_file_leaves_nothing_behind() {
        let dir = tempfile::tempdir().expect("temp dir");
        let config = state_file_config(dir.path());
        config.state_dir.ensure().expect("state dir");
        let files = config.state_dir.files(VAULT_ID);
        // A directory where the pid file goes; the rename that publishes it cannot succeed.
        std::fs::create_dir(&files.pid).expect("the blocked pid path");
        // What an earlier, crashed run of this vault left behind.
        std::fs::write(&files.info, "{}").expect("a stale run info");

        let err = run_daemon(config, Arc::new(AtomicBool::new(false)))
            .expect_err("the pid file cannot be written");
        assert!(matches!(err, AppError::Io(_)), "{err:?}");
        assert!(
            !files.info.exists(),
            "a daemon that gives up while publishing its state files removes them"
        );
        assert!(!files.socket.exists(), "and never bound a socket");
        drop(dir);
    }

    /// The class name of [`StuckMountProvider`]; no Java counterpart, like the null mounter's.
    const STUCK_MOUNTER_CLASS: &str = "org.cryptomator.cli.StuckMountProvider";

    /// It advertises `UNMOUNT_FORCED`, so the teardown really runs the whole escalation instead
    /// of skipping the forced attempt.
    const STUCK_CAPABILITIES: &[MountCapability] = &[
        MountCapability::MountToExistingDir,
        MountCapability::UnmountForced,
    ];

    /// A mount service whose volume never goes down -- what a wedged FUSE mount looks like from
    /// here: the graceful unmount says the volume is busy, the forced one fails too, and so does
    /// the release.
    #[derive(Debug, Clone, Copy)]
    struct StuckMountProvider;

    impl MountService for StuckMountProvider {
        fn java_class_name(&self) -> &'static str {
            STUCK_MOUNTER_CLASS
        }
        fn display_name(&self) -> &'static str {
            "Stuck mounter (testing)"
        }
        fn priority(&self) -> u32 {
            0
        }
        fn is_supported(&self) -> bool {
            true
        }
        fn capabilities(&self) -> &'static [MountCapability] {
            STUCK_CAPABILITIES
        }
        /// A test double like the null mounter: nothing it does reaches the kernel, so its mount
        /// point never turns up in the mount table and the unlock must not wait for it.
        fn appears_in_mount_table(&self) -> bool {
            false
        }
        fn default_mount_flags(&self) -> String {
            String::new()
        }
        fn for_file_system(&self, fs: Arc<CryptoFs>) -> Box<dyn MountBuilder> {
            Box::new(StuckMountBuilder {
                _fs: fs,
                mountpoint: None,
            })
        }
    }

    struct StuckMountBuilder {
        /// Held like a real mount holds it, so the file system is only released with the mount.
        _fs: Arc<CryptoFs>,
        mountpoint: Option<PathBuf>,
    }

    impl MountBuilder for StuckMountBuilder {
        fn set_mountpoint(&mut self, path: &Path) -> std::result::Result<(), MountError> {
            self.mountpoint = Some(path.to_path_buf());
            Ok(())
        }
        fn mount(self: Box<Self>) -> std::result::Result<Box<dyn Mount>, MountError> {
            let mountpoint = self
                .mountpoint
                .clone()
                .ok_or_else(|| MountError::Failed("no mount point".to_owned()))?;
            Ok(Box::new(StuckMount {
                _fs: self._fs,
                mountpoint,
            }))
        }
    }

    struct StuckMount {
        _fs: Arc<CryptoFs>,
        mountpoint: PathBuf,
    }

    impl Mount for StuckMount {
        fn mountpoint(&self) -> Mountpoint {
            Mountpoint::Path(self.mountpoint.clone())
        }
        fn unmount(&mut self) -> std::result::Result<(), UnmountError> {
            Err(UnmountError::Busy)
        }
        fn unmount_forced(&mut self) -> std::result::Result<(), UnmountError> {
            Err(UnmountError::Failed("the volume is wedged".to_owned()))
        }
        fn close(self: Box<Self>) -> std::result::Result<(), UnmountError> {
            Err(UnmountError::Failed("the volume is wedged".to_owned()))
        }
    }

    #[test]
    fn a_volume_that_survives_the_forced_unmount_keeps_its_run_info() {
        let daemon = Daemon::start_with(
            vec![Box::new(StuckMountProvider)],
            (DEADLINE, Duration::from_secs(3600)),
            Duration::from_millis(20),
            |_| {},
        );
        let mut client = daemon.client();
        client
            .call(unlock_request_for(STUCK_MOUNTER_CLASS, &encoded(KEY)))
            .expect("unlock");
        assert!(daemon.files.info.is_file(), "the run info is published");

        // Exactly what a signal does: set the flag, and nothing else.
        daemon.shutdown.store(true, Ordering::SeqCst);
        let outcome = daemon.wait();
        assert!(
            matches!(outcome, Err(AppError::UnmountFailed(_))),
            "a volume that would not go down is an error, not a clean stop: {outcome:?}"
        );
        // Nobody answers on the socket and no pid is alive any more, but the run info stays: it
        // is what makes `crypto status` say STALE_MOUNT instead of LOCKED, and what
        // `crypto lock --force` addresses the leftover volume by.
        assert!(!daemon.files.socket.exists(), "the socket is removed");
        assert!(!daemon.files.pid.exists(), "the pid file is removed");
        let info = daemon.files.read_info().expect("the run info survives");
        assert_eq!(
            info.mountpoint.map(PathBuf::from),
            Some(daemon.mount_dir.clone())
        );
        assert!(
            daemon.mount_dir.is_dir(),
            "the mount directory of a volume that is still mounted stays too"
        );
    }

    #[test]
    fn a_second_signal_escalates_a_stuck_unmount_immediately() {
        let notices: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&notices);
        // A generous 5s `force_unmount_after`: if the second signal below did not shorten the
        // wait, this test would still be sitting it out well past the 2s deadline it asserts.
        let daemon = Daemon::start_full(
            vec![Box::new(NullMountProvider::enabled(true, true))],
            (DEADLINE, Duration::from_secs(3600)),
            Duration::from_millis(20),
            Duration::from_secs(5),
            Some(Box::new(move |message: &str| {
                recorder
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(message.to_owned());
            })),
            |_| {},
        );
        let mut client = daemon.client();
        client.call(unlock_request(&encoded(KEY))).expect("unlock");

        let started = Instant::now();
        // Exactly what the first signal does: set the flag, nothing else.
        daemon.shutdown.store(true, Ordering::SeqCst);
        // Gives the accept loop time to notice the first signal and re-arm the flag (see
        // `run_daemon`'s docs) before the second one below, so that one lands as a fresh `true`
        // instead of being folded into the first.
        std::thread::sleep(Duration::from_millis(200));
        daemon.shutdown.store(true, Ordering::SeqCst);

        assert!(
            daemon.wait().is_ok(),
            "the forced unmount gets the volume down"
        );
        let took = started.elapsed();
        assert!(
            took < Duration::from_secs(2),
            "a second signal should skip the 5s wait instead of sitting it out, took {took:?}"
        );
        assert_eq!(
            *notices.lock().unwrap_or_else(PoisonError::into_inner),
            vec!["unmount busy; forcing in 5s (press Ctrl-C again to force now)".to_owned()],
            "the notice fires exactly once, when the graceful unmount first fails"
        );
    }
}
