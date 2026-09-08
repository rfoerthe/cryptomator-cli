//! `crypto unlock`: derive the vault key here, mount the vault in a daemon over there.
//!
//! The password never leaves this process and the key never touches `argv`, the environment or a
//! file: the parent derives it with scrypt, spawns the daemon detached and sends the key as the
//! first request over the daemon's 0600 control socket.
use crate::cli::UnlockArgs;
use crate::commands::{daemon, keychain_source, locked_vault, store_passphrase_or_warn, Ctx};
use crate::exit;
use anyhow::{anyhow, Context, Result};
use cryptomator_app::settings::{VaultSettingsJson, WhenUnlocked};
use cryptomator_app::{
    read_passphrase_with_keychain, resolve_mounter, AppError, DaemonClient, Request, SystemIo,
    VaultStateFiles,
};
use cryptomator_core::fs::{
    determine_supported_cleartext_file_name_length, DEFAULT_MAX_CLEARTEXT_NAME_LENGTH,
};
use cryptomator_core::{open_vault, read_vault_config, MasterkeyFileAccess};
use cryptomator_mount::registry::NULL_MOUNTER_CLASS;
use data_encoding::BASE64;
use serde_json::json;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// How long the parent waits for the daemon's socket to appear.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// How long the parent waits for the answer to its `unlock` request, i.e. for the mount itself.
///
/// The daemon gives up on an `unlock` that never arrives after 60 seconds
/// (`commands::daemon::UNLOCK_TIMEOUT`); this is that plus a margin, so a daemon that is merely
/// slow always gets to answer -- with its own error, which says more than a timeout here can.
const UNLOCK_CALL_TIMEOUT: Duration = Duration::from_secs(70);
/// How long the parent waits for a daemon that failed its unlock to exit before killing it.
const CHILD_EXIT_TIMEOUT: Duration = Duration::from_secs(10);
/// How often the parent looks whether that daemon is gone.
const CHILD_POLL: Duration = Duration::from_millis(20);
/// How much of the daemon's log a failed unlock shows.
const LOG_TAIL_LINES: usize = 20;
/// The mode of the log file; it names the vault path and the mount point.
const LOG_MODE: u32 = 0o600;
/// Replaces the file manager `--reveal` opens, for a desktop whose opener is neither of the two
/// below -- and for the tests, which point it at a script instead of a file manager.
const REVEAL_CMD_ENV: &str = "CRYPTO_REVEAL_CMD";
/// The platform's "open this in the file manager" command.
const DEFAULT_OPENER: &str = if cfg!(target_os = "macos") {
    "open"
} else {
    "xdg-open"
};

pub fn unlock(ctx: &Ctx, args: UnlockArgs) -> Result<u8> {
    // Before the password: an unusable mounter name is a usage error, not a failed unlock.
    let mounter = args.mounter.as_deref().map(resolve_mounter).transpose()?;
    let (vault, path) = locked_vault(ctx, &args.vault)?;
    // Reject Hub and unsupported key ids before asking for any passphrase.
    read_vault_config(&path)?
        .key_id()?
        .require_masterkey_file()?;

    // `--store-password` with nowhere to store is exit 8 *here*, before the vault is opened: the
    // alternative is an unlocked vault plus an error, which is the worst of both answers. Only
    // the *absence* of a provider is caught this way; one that is there and refuses is not known
    // until it is asked, which happens after the mount (see `store_after_report`).
    if args.store_password {
        ctx.keychain_required()?;
    }

    let read_only = args.read_only || vault.uses_read_only_mode;
    // The keychain is the parent process's business only: the daemon gets the derived key and
    // never talks to a keyring (see `docs/daemon-protocol.md`). Lazy: the provider is only probed
    // when the password source order actually reaches the keychain steps, so
    // `crypto unlock --password-stdin` never pays for it.
    let passphrase = read_passphrase_with_keychain(
        &args.password,
        "Password: ",
        || Ok(keychain_source(ctx.keychain()?.as_ref(), &vault)),
        &mut SystemIo,
    )?;
    let opened = open_vault(&path, &MasterkeyFileAccess::new(Vec::new()), &passphrase)?;
    // Not dropped yet when `--store-password` was given: the passphrase is written *after* the
    // daemon reported ready, so a mount that fails never leaves a password behind.
    let to_store = args.store_password.then(|| passphrase.clone());
    drop(passphrase);
    let max_cleartext_name_length = name_length(ctx, &vault, &path, read_only)?;
    // The wire format is base64; this buffer is wiped when it goes out of scope and `Request`'s
    // own `Drop` wipes the copy inside the request.
    let key = Zeroizing::new(BASE64.encode(opened.masterkey.raw()));
    drop(opened);

    // `--mount-point` is sent to the daemon over the socket, not as an argument, but the same
    // problem applies: a relative path is meaningless once it reaches a process (or a mount
    // service call inside this one) that does not share the shell's cwd.
    let mount_point = absolute_mount_point(args.mount_point.as_deref())?;
    let request = Request::Unlock {
        id: 0,
        key: key.as_str().to_owned(),
        mounter,
        mount_point,
        mount_options: args.mount_option.clone(),
        port: args.port,
        // `None`, not `Some(false)`: without the flag the vault's own `usesReadOnlyMode` decides.
        read_only: args.read_only.then_some(true),
        volume_name: args.volume_name.clone(),
        max_cleartext_name_length,
    };
    drop(key);

    ctx.state_dir.ensure()?;
    let files = ctx.state_dir.files(&vault.id);
    if args.foreground {
        serve_in_foreground(ctx, &vault, &files, request, &args, to_store)
    } else {
        spawn_daemon(ctx, &vault, &files, request, &args, to_store)
    }
}

/// Saves the passphrase of a vault that is now mounted, if `--store-password` asked for it.
///
/// Called only after [`report`] returned: at that point the daemon has answered `ready` and the
/// mount point is known, so a keychain entry can no longer outlive a failed unlock. Nothing here
/// is an exit code -- the vault *is* mounted, and telling a script otherwise would be a lie -- so
/// both "there was no keychain after all" and "the provider refused" are warnings on stderr
/// ([`store_passphrase_or_warn`], shared with `vault create --store-password`).
fn store_after_report(ctx: &Ctx, vault: &VaultSettingsJson, to_store: Option<Zeroizing<String>>) {
    let Some(passphrase) = to_store else {
        return;
    };
    store_passphrase_or_warn(ctx, vault, &passphrase);
}

/// Absolutizes `--mount-point`: `None` stays `None`, a relative path is resolved against this
/// process's cwd before it leaves for the daemon.
fn absolute_mount_point(mount_point: Option<&Path>) -> Result<Option<String>> {
    mount_point
        .map(|p| {
            std::path::absolute(p)
                .with_context(|| format!("cannot resolve mount point {}", p.display()))
                .map(|abs| abs.to_string_lossy().into_owned())
        })
        .transpose()
}

/// The longest cleartext file name the mounted vault accepts.
///
/// `maxCleartextFilenameLength` is `-1` ("probe on unlock") until the first unlock: the probe
/// creates and removes directories inside the vault, so a read-only unlock cannot run it and
/// takes the cryptofs default instead -- exactly what `crypto fs` does. A probed value is written
/// back to `settings.json`, so later unlocks skip the probe.
fn name_length(
    ctx: &Ctx,
    vault: &VaultSettingsJson,
    path: &Path,
    read_only: bool,
) -> Result<usize> {
    if let Ok(configured) = usize::try_from(vault.max_cleartext_filename_length) {
        if configured > 0 {
            return Ok(configured);
        }
    }
    if read_only {
        return Ok(DEFAULT_MAX_CLEARTEXT_NAME_LENGTH);
    }
    let probed = determine_supported_cleartext_file_name_length(path)
        .with_context(|| format!("cannot probe the file name length of {}", path.display()))?;
    let id = vault.id.clone();
    ctx.store.update(|settings| {
        if let Some(entry) = settings.directories.iter_mut().find(|v| v.id == id) {
            entry.max_cleartext_filename_length = i32::try_from(probed).unwrap_or(-1);
        }
        Ok(())
    })?;
    Ok(probed as usize)
}

/// Spawns the detached daemon, hands it the key and reports where the vault landed.
fn spawn_daemon(
    ctx: &Ctx,
    vault: &VaultSettingsJson,
    files: &VaultStateFiles,
    request: Request,
    args: &UnlockArgs,
    to_store: Option<Zeroizing<String>>,
) -> Result<u8> {
    let log = open_log(&files.log)?;
    let exe = std::env::current_exe().context("cannot locate the crypto binary")?;
    let mut command = Command::new(exe);
    command
        .arg("__daemon")
        .arg("--vault-id")
        .arg(&vault.id)
        .arg("--socket")
        .arg(&files.socket)
        .arg("--state-dir")
        .arg(ctx.state_dir.root());
    if let Some(settings) = ctx.settings_arg.as_deref() {
        command.arg("--settings").arg(settings);
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log))
        // The daemon outlives this shell; a working directory inside the vault or on a removable
        // volume would pin it.
        .current_dir("/")
        // The daemon has no use for the password and must not carry it in its environment.
        .env_remove("CRYPTO_PASSWORD");
    // SAFETY: `pre_exec` runs in the child between `fork` and `exec`, where only async-signal-safe
    // calls are allowed. `setsid(2)` is one of them; the closure allocates nothing, takes no lock
    // and calls nothing else. Its failure (we are already a session leader) needs no handling --
    // the daemon is detached from the terminal either way.
    unsafe {
        command.pre_exec(|| {
            let _ = libc::setsid();
            Ok(())
        });
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("cannot start the vault daemon for {}", vault.id))?;
    match handshake(&files.socket, request, &files.log) {
        Ok(mountpoint) => {
            // The result is bound first: `--store-password` writes only once the mount point has
            // been reported, and not at all if reporting it failed.
            let reported = report(ctx, vault, files, &mountpoint, args);
            if reported.is_ok() {
                store_after_report(ctx, vault, to_store);
            }
            reported
        }
        Err(err) => {
            // The timeout above lands here too: the daemon gets a SIGTERM and with it its own
            // graceful unmount, so a mount that came up late is still taken down again.
            reap(&mut child);
            Err(with_log_tail(&files.log, err))
        }
    }
}

/// Serves the vault in this process (`--foreground`): the daemon runs on a thread, the main
/// thread does the same handshake a detached unlock does and then waits for the daemon to end.
/// SIGINT, SIGTERM and SIGHUP set the same flag `crypto lock` triggers over the socket.
fn serve_in_foreground(
    ctx: &Ctx,
    vault: &VaultSettingsJson,
    files: &VaultStateFiles,
    request: Request,
    args: &UnlockArgs,
    to_store: Option<Zeroizing<String>>,
) -> Result<u8> {
    let mut config = daemon::config(ctx, &vault.id, Some(files.log.clone()))?;
    // Unlike the detached daemon, this process has the terminal the signal came from -- so a
    // stuck unmount's wait gets a line on its stderr instead of only the log file nobody is
    // watching while it happens.
    config.notice = Some(Box::new(|message: &str| eprintln!("{message}")));
    let shutdown = daemon::install_signal_flag()?;
    let flag = Arc::clone(&shutdown);
    let served = std::thread::Builder::new()
        .name("crypto-daemon".to_owned())
        .spawn(move || cryptomator_app::run_daemon(config, flag))
        .context("cannot start the vault daemon thread")?;
    let handshake = match handshake(&files.socket, request, &files.log) {
        Ok(mountpoint) => {
            // Before the wait for the shutdown signal below, and only after `report` succeeded --
            // the same order the detached path uses.
            let reported = report(ctx, vault, files, &mountpoint, args);
            if reported.is_ok() {
                store_after_report(ctx, vault, to_store);
            }
            reported
        }
        Err(err) => {
            // Nobody else is going to lock this daemon: it either never came up or refused the
            // unlock, and it would otherwise sit out its whole unlock deadline.
            shutdown.store(true, Ordering::SeqCst);
            Err(with_log_tail(&files.log, err))
        }
    };
    let served = served
        .join()
        .map_err(|_| anyhow!("the vault daemon thread panicked"))?;
    match (handshake, served) {
        (Err(err), _) => Err(err),
        (Ok(_), Err(err)) => Err(with_log_tail(&files.log, err.into())),
        (Ok(code), Ok(())) => Ok(code),
    }
}

/// Connects to the daemon and sends the one `unlock` request it accepts; returns the mount point.
///
/// The connect deadline only covers the socket showing up; mounting happens afterwards and used
/// to have no deadline at all, so a mount service that hung left `crypto unlock` waiting forever.
/// [`UNLOCK_CALL_TIMEOUT`] bounds that wait -- generously, since a slow FUSE mount is not a
/// failed one.
///
/// # Errors
/// [`AppError::DaemonUnreachable`] when no daemon answers within [`CONNECT_TIMEOUT`] or when the
/// connection breaks, [`AppError::MountFailed`] when the daemon stops answering while mounting,
/// and the daemon's own [`AppError::DaemonError`] when the unlock failed.
fn handshake(socket: &Path, request: Request, log: &Path) -> Result<String> {
    let mut client = DaemonClient::connect_with_retry(socket, CONNECT_TIMEOUT)?;
    client.set_read_timeout(Some(UNLOCK_CALL_TIMEOUT))?;
    let started = Instant::now();
    let result = client
        .call(request)
        .map_err(|err| unlock_failure(err, started.elapsed(), log))?;
    Ok(result
        .get("mountpoint")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_owned())
}

/// What a failed `unlock` call means to the user.
///
/// A daemon that says nothing for [`UNLOCK_CALL_TIMEOUT`] is one whose mount is stuck: the client
/// reports the silence as a transport failure ([`AppError::DaemonUnreachable`], exit code 10),
/// which is the wrong story -- the daemon is there, its mount is not. Only a silence that lasted
/// the whole timeout is turned into [`AppError::MountFailed`] (exit code 6) and pointed at the
/// log; a connection that broke early stays what it is.
fn unlock_failure(err: AppError, waited: Duration, log: &Path) -> anyhow::Error {
    if waited >= UNLOCK_CALL_TIMEOUT && matches!(err, AppError::DaemonUnreachable(_)) {
        return AppError::MountFailed(format!(
            "the daemon did not finish mounting within {}s; see {}",
            UNLOCK_CALL_TIMEOUT.as_secs(),
            log.display()
        ))
        .into();
    }
    err.into()
}

/// Prints where the vault was mounted and opens the mount point if asked to.
fn report(
    ctx: &Ctx,
    vault: &VaultSettingsJson,
    files: &VaultStateFiles,
    mountpoint: &str,
    args: &UnlockArgs,
) -> Result<u8> {
    // The daemon publishes the run info before it answers, so this is the mounter and pid of the
    // process that actually holds the mount.
    let info = files.read_info();
    let name = vault.mount_name();
    ctx.out.emit(
        json!({
            "id": vault.id,
            "mountpoint": mountpoint,
            "mounter": info.as_ref().map(|i| i.mounter.clone()),
            "pid": info.as_ref().map(|i| i.pid),
        }),
        || format!("Unlocked {name} at {mountpoint}"),
    )?;
    // A URL is not something the shell can `cd` into: the one line that says what to do with it
    // goes to stderr, so `--json`'s document on stdout keeps its shape.
    if is_url(mountpoint) {
        eprintln!("{}", url_hint(mountpoint));
    }
    if args.reveal || vault.action_after_unlock == WhenUnlocked::Reveal {
        reveal(mountpoint, info.as_ref().map(|i| i.mounter.as_str()));
    }
    Ok(exit::OK)
}

/// Whether the daemon answered with a URL instead of a path -- what the WebDAV back ends serve.
///
/// A mount point is always absolute (`absolute_mount_point`, and the daemon's own default), so the
/// two cannot be confused.
fn is_url(mountpoint: &str) -> bool {
    !mountpoint.starts_with('/') && mountpoint.contains("://")
}

/// The one line telling the user how to mount a WebDAV URL by hand. The vault is served the moment
/// `unlock` returns; mounting it in the file manager is a separate, optional step.
fn url_hint(url: &str) -> String {
    if cfg!(target_os = "macos") {
        format!("Mount it in Finder: Go -> Connect to Server, then enter {url}")
    } else {
        // `gio` wants the WebDAV scheme, not the HTTP one: `gio mount http://…` is a download,
        // `gio mount dav://…` is the volume. The file manager's dialog takes either.
        format!(
            "Mount it with `gio mount {}`, or in the file manager: Other Locations -> Connect to Server",
            url.replacen("http://", "dav://", 1)
        )
    }
}

/// Opens the mount point in the desktop's file manager, best effort: a missing `open`/`xdg-open`
/// or a headless session is not a failed unlock, so nothing here is reported and nothing is
/// waited for -- the opener outlives this process.
fn reveal(mountpoint: &str, mounter: Option<&str>) {
    let overridden = std::env::var(REVEAL_CMD_ENV).ok();
    let Some(argv) = reveal_command(mountpoint, mounter, overridden.as_deref()) else {
        return;
    };
    let Some((program, args)) = argv.split_first() else {
        return;
    };
    let child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    if let Ok(child) = child {
        // Detached this process exits right away and nothing collects the opener; under
        // `--foreground` this process keeps running and, without a `wait`, so would the opener as
        // a zombie. A detached thread that only waits on it is enough either way -- the exit
        // status is not interesting, since a failed opener was already ignored above.
        std::thread::spawn(move || {
            let mut child = child;
            let _ = child.wait();
        });
    }
}

/// What [`reveal`] runs, mount point last, or [`None`] when there is nothing to open.
///
/// `$CRYPTO_REVEAL_CMD` replaces the platform's opener; it is split on whitespace, so a program
/// with arguments (`"xdg-open -w"`) works and a path containing spaces does not -- the same trade
/// every `$EDITOR`-style variable makes.
///
/// Without the override a null mount is skipped: it mounts nothing, and popping up a file manager
/// on its marker directory in the middle of a test run helps nobody. That is exactly why the
/// override exists -- it is how the reveal hook itself is tested.
fn reveal_command(
    mountpoint: &str,
    mounter: Option<&str>,
    overridden: Option<&str>,
) -> Option<Vec<String>> {
    if mountpoint.is_empty() {
        return None;
    }
    // A WebDAV URL is skipped even with the override: the opener would hand it to a browser, and a
    // browser is not the vault. The hint printed above is what the user needs instead.
    if is_url(mountpoint) {
        return None;
    }
    let mut argv: Vec<String> = match overridden.map(str::trim).filter(|cmd| !cmd.is_empty()) {
        Some(cmd) => cmd.split_whitespace().map(str::to_owned).collect(),
        None if mounter == Some(NULL_MOUNTER_CLASS) => return None,
        None => vec![DEFAULT_OPENER.to_owned()],
    };
    argv.push(mountpoint.to_owned());
    Some(argv)
}

/// Waits for a daemon that failed its unlock (it stops itself) and kills one that does not go.
/// Without this the parent would leave a zombie behind on every failed unlock.
///
/// Most callers reach this with a daemon that never got past its own unlock handshake, but a
/// transport error can strand this here after the daemon has already mounted the volume -- so a
/// plain `SIGKILL` is not good enough: it skips the daemon's own signal handler and the graceful
/// unmount it runs (see `commands::daemon::install_signal_flag`), leaving the volume mounted with
/// nothing left to lock it. `SIGTERM` first gives that handler a chance; only a daemon that still
/// has not exited by [`CHILD_EXIT_TIMEOUT`] gets `SIGKILL`.
fn reap(child: &mut Child) {
    terminate(child);
    let deadline = Instant::now() + CHILD_EXIT_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) if Instant::now() >= deadline => break,
            Ok(None) => std::thread::sleep(CHILD_POLL),
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// Sends `SIGTERM` to `child`, best effort: a send that fails (the process already exited) needs
/// no handling since `reap`'s poll notices the exit either way.
fn terminate(child: &Child) {
    // SAFETY: `kill(2)` has no preconditions beyond a valid signal number, which `SIGTERM` is; the
    // pid is the one `Child` itself reports for a process this same code just spawned and still
    // owns, so this cannot signal an unrelated process even if the child has already exited (the
    // pid is not reused while the parent holds it unreaped).
    unsafe {
        let _ = libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
    }
}

/// Prints the tail of the daemon's log to stderr and hands `err` back unchanged: the daemon's
/// own stderr goes into that file, and it is the only place the reason for a failed mount is
/// written down.
fn with_log_tail(log: &Path, err: anyhow::Error) -> anyhow::Error {
    let tail = log_tail(log);
    if !tail.is_empty() {
        eprintln!("--- last {} lines of {} ---", tail.len(), log.display());
        for line in tail {
            eprintln!("{line}");
        }
    }
    err
}

/// The last [`LOG_TAIL_LINES`] lines of the daemon's log, or nothing if it cannot be read.
fn log_tail(path: &Path) -> Vec<String> {
    let Ok(file) = File::open(path) else {
        return Vec::new();
    };
    let mut tail: std::collections::VecDeque<String> = std::collections::VecDeque::new();
    for line in BufReader::new(file)
        .lines()
        .map_while(std::result::Result::ok)
    {
        if tail.len() == LOG_TAIL_LINES {
            tail.pop_front();
        }
        tail.push_back(line);
    }
    tail.into()
}

fn open_log(path: &Path) -> Result<File> {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(LOG_MODE)
        .open(path)
        .with_context(|| format!("cannot open the daemon log {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reveal_command_ends_with_the_mount_point() {
        assert_eq!(
            reveal_command("/mnt/v", Some("org.example.Fuse"), None),
            Some(vec![DEFAULT_OPENER.to_owned(), "/mnt/v".to_owned()])
        );
        // The override wins over the platform's opener and may carry arguments.
        assert_eq!(
            reveal_command("/mnt/v", Some("org.example.Fuse"), Some(" /bin/echo -n ")),
            Some(vec![
                "/bin/echo".to_owned(),
                "-n".to_owned(),
                "/mnt/v".to_owned()
            ])
        );
    }

    #[test]
    fn nothing_is_opened_without_a_mount_point_or_for_a_null_mount() {
        assert_eq!(reveal_command("", Some("org.example.Fuse"), None), None);
        assert_eq!(reveal_command("", None, Some("/bin/echo")), None);
        // A null mount has nothing to show -- unless a test asked for a specific command.
        assert_eq!(
            reveal_command("/mnt/v", Some(NULL_MOUNTER_CLASS), None),
            None
        );
        // An empty or blank override is "not set", not "run nothing".
        assert_eq!(
            reveal_command("/mnt/v", Some(NULL_MOUNTER_CLASS), Some("  ")),
            None
        );
        assert_eq!(
            reveal_command("/mnt/v", Some(NULL_MOUNTER_CLASS), Some("/bin/echo")),
            Some(vec!["/bin/echo".to_owned(), "/mnt/v".to_owned()])
        );
    }

    #[test]
    fn a_webdav_url_is_recognised_and_never_opened() {
        assert!(is_url("http://127.0.0.1:42427/AAAAAAAAAAAA"));
        assert!(is_url("dav://127.0.0.1:42427/AAAAAAAAAAAA"));
        assert!(!is_url("/mnt/v"), "a mount point is always absolute");
        assert!(!is_url("/mnt/http://weird"), "still a path");
        assert!(!is_url(""), "no mount point at all is no URL either");
        // Not even the test override opens a URL: a browser is not the vault.
        assert_eq!(
            reveal_command(
                "http://127.0.0.1:42427/AAAAAAAAAAAA",
                Some("org.cryptomator.frontend.webdav.mount.FallbackMounter"),
                Some("/bin/echo")
            ),
            None
        );
        let hint = url_hint("http://127.0.0.1:42427/AAAAAAAAAAAA");
        assert!(
            hint.contains("http://127.0.0.1:42427/AAAAAAAAAAAA"),
            "{hint}"
        );
        assert!(hint.contains("Connect to Server"), "{hint}");
        if !cfg!(target_os = "macos") {
            // `gio` takes the WebDAV scheme, not the HTTP one.
            assert!(
                hint.contains("dav://127.0.0.1:42427/AAAAAAAAAAAA"),
                "{hint}"
            );
        }
    }

    #[test]
    fn a_daemon_that_stops_answering_while_mounting_is_a_failed_mount() {
        let log = Path::new("/tmp/x.log");
        let silent = unlock_failure(
            AppError::DaemonUnreachable("the daemon did not answer in time".to_owned()),
            UNLOCK_CALL_TIMEOUT,
            log,
        );
        assert_eq!(crate::exit::code_for(&silent), crate::exit::MOUNT_FAILED);
        let message = format!("{silent:#}");
        assert!(
            message.contains("did not finish mounting within 70s"),
            "{message}"
        );
        assert!(message.contains("/tmp/x.log"), "{message}");

        // A connection that broke early is a transport failure, not a stuck mount.
        let broke = unlock_failure(
            AppError::DaemonUnreachable("the daemon closed the connection".to_owned()),
            Duration::from_secs(1),
            log,
        );
        assert_eq!(
            crate::exit::code_for(&broke),
            crate::exit::DAEMON_UNREACHABLE
        );
        // And a refusal the daemon actually sent keeps its own code.
        let refused = unlock_failure(
            AppError::DaemonError {
                code: "ALREADY_UNLOCKED".to_owned(),
                message: "another daemon is already serving this vault".to_owned(),
            },
            UNLOCK_CALL_TIMEOUT,
            log,
        );
        assert_eq!(crate::exit::code_for(&refused), crate::exit::WRONG_STATE);
    }
}
