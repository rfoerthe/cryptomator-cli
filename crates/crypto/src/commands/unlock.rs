//! `crypto unlock`: derive the vault key here, mount the vault in a daemon over there.
//!
//! The password never leaves this process and the key never touches `argv`, the environment or a
//! file: the parent derives it with scrypt, spawns the daemon detached and sends the key as the
//! first request over the daemon's 0600 control socket.
use crate::cli::UnlockArgs;
use crate::commands::{daemon, locked_vault, Ctx};
use crate::exit;
use anyhow::{anyhow, Context, Result};
use cryptomator_app::settings::{VaultSettingsJson, WhenUnlocked};
use cryptomator_app::{
    read_passphrase, resolve_mounter, AppError, DaemonClient, Request, RunInfo, RuntimeState,
    SystemIo, VaultStateFiles,
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
/// How long the parent waits for a daemon that failed its unlock to exit before killing it.
const CHILD_EXIT_TIMEOUT: Duration = Duration::from_secs(10);
/// How often the parent looks whether that daemon is gone.
const CHILD_POLL: Duration = Duration::from_millis(20);
/// How much of the daemon's log a failed unlock shows.
const LOG_TAIL_LINES: usize = 20;
/// The mode of the log file; it names the vault path and the mount point.
const LOG_MODE: u32 = 0o600;

pub fn unlock(ctx: &Ctx, args: UnlockArgs) -> Result<u8> {
    // Before the password: an unusable mounter name is a usage error, not a failed unlock.
    let mounter = args.mounter.as_deref().map(resolve_mounter).transpose()?;
    let (vault, path) = locked_vault(ctx, &args.vault)?;
    require_not_running(ctx, &vault)?;
    // Reject Hub and unsupported key ids before asking for any passphrase.
    read_vault_config(&path)?
        .key_id()?
        .require_masterkey_file()?;

    let read_only = args.read_only || vault.uses_read_only_mode;
    let passphrase = read_passphrase(&args.password, "Password: ", &mut SystemIo)?;
    let opened = open_vault(&path, &MasterkeyFileAccess::new(Vec::new()), &passphrase)?;
    drop(passphrase);
    let max_cleartext_name_length = name_length(ctx, &vault, &path, read_only)?;
    // The wire format is base64; this buffer is wiped when it goes out of scope and `Request`'s
    // own `Drop` wipes the copy inside the request.
    let key = Zeroizing::new(BASE64.encode(opened.masterkey.raw()));
    drop(opened);

    let request = Request::Unlock {
        id: 0,
        key: key.as_str().to_owned(),
        mounter,
        mount_point: args
            .mount_point
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned()),
        mount_options: args.mount_option.clone(),
        // `None`, not `Some(false)`: without the flag the vault's own `usesReadOnlyMode` decides.
        read_only: args.read_only.then_some(true),
        volume_name: args.volume_name.clone(),
        max_cleartext_name_length,
    };
    drop(key);

    ctx.state_dir.ensure()?;
    let files = ctx.state_dir.files(&vault.id);
    if args.foreground {
        serve_in_foreground(ctx, &vault, &files, request, &args)
    } else {
        spawn_daemon(ctx, &vault, &files, request, &args)
    }
}

/// Refuses a vault a daemon is already serving, or whose volume a crashed daemon left behind.
///
/// # Errors
/// [`AppError::WrongState`] (exit code 5) in both cases, plus anything `settings.json` reports.
fn require_not_running(ctx: &Ctx, vault: &VaultSettingsJson) -> Result<()> {
    let (state, info) = ctx.registry().runtime_state(&vault.id)?;
    let at = |info: Option<RunInfo>| match info.and_then(|i| i.mountpoint) {
        Some(mountpoint) => format!(" at {mountpoint}"),
        None => String::new(),
    };
    let actual = match state {
        RuntimeState::Unlocked => format!("already unlocked{}", at(info)),
        RuntimeState::StaleMount => format!(
            "STALE_MOUNT{} -- a previous daemon left the volume behind; take it down with `crypto lock {} --force`",
            at(info),
            vault.id
        ),
        _ => return Ok(()),
    };
    Err(AppError::WrongState {
        expected: "LOCKED".to_owned(),
        actual,
    }
    .into())
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
    match handshake(&files.socket, request) {
        Ok(mountpoint) => report(ctx, vault, files, &mountpoint, args),
        Err(err) => {
            reap(&mut child);
            Err(with_log_tail(&files.log, err))
        }
    }
}

/// Serves the vault in this process (`--foreground`): the daemon runs on a thread, the main
/// thread does the same handshake a detached unlock does and then waits for the daemon to end.
/// SIGINT and SIGTERM set the same flag `crypto lock` triggers over the socket.
fn serve_in_foreground(
    ctx: &Ctx,
    vault: &VaultSettingsJson,
    files: &VaultStateFiles,
    request: Request,
    args: &UnlockArgs,
) -> Result<u8> {
    let config = daemon::config(ctx, &vault.id, Some(files.log.clone()))?;
    let shutdown = daemon::install_signal_flag()?;
    let flag = Arc::clone(&shutdown);
    let served = std::thread::Builder::new()
        .name("crypto-daemon".to_owned())
        .spawn(move || cryptomator_app::run_daemon(config, flag))
        .context("cannot start the vault daemon thread")?;
    let handshake = match handshake(&files.socket, request) {
        Ok(mountpoint) => report(ctx, vault, files, &mountpoint, args),
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
/// # Errors
/// [`AppError::DaemonUnreachable`] when no daemon answers within [`CONNECT_TIMEOUT`], and the
/// daemon's own [`AppError::DaemonError`] when the unlock failed.
fn handshake(socket: &Path, request: Request) -> Result<String> {
    let mut client = DaemonClient::connect_with_retry(socket, CONNECT_TIMEOUT)?;
    let result = client.call(request)?;
    Ok(result
        .get("mountpoint")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_owned())
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
    if args.reveal || vault.action_after_unlock == WhenUnlocked::Reveal {
        reveal(mountpoint, info.as_ref().map(|i| i.mounter.as_str()));
    }
    Ok(exit::OK)
}

/// Opens the mount point in the desktop's file manager, best effort: a missing `open`/`xdg-open`
/// or a headless session is not a failed unlock.
///
/// The null mounter mounts nothing, so revealing its directory would pop up a file manager in the
/// middle of a test run for no reason.
fn reveal(mountpoint: &str, mounter: Option<&str>) {
    if mountpoint.is_empty() || mounter == Some(NULL_MOUNTER_CLASS) {
        return;
    }
    let program = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    let _ = Command::new(program)
        .arg(mountpoint)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
}

/// Waits for a daemon that failed its unlock (it stops itself) and kills one that does not go.
/// Without this the parent would leave a zombie behind on every failed unlock.
fn reap(child: &mut Child) {
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
