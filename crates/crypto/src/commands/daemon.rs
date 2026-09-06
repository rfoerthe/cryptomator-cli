//! `crypto __daemon`: the hidden subcommand `crypto unlock` spawns.
//!
//! The daemon is never started by hand. `crypto unlock` reads the password, derives the vault key
//! and spawns this command detached; the key is then handed over the control socket as the first
//! request, so it never appears in `argv`, in the environment or in the log.
use crate::cli::DaemonArgs;
use crate::commands::Ctx;
use crate::exit;
use anyhow::Result;
use cryptomator_app::{AppError, CliConfig, DaemonConfig};
use cryptomator_mount::registry;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

/// How long a daemon waits for the `unlock` request of the `crypto unlock` that spawned it.
const UNLOCK_TIMEOUT: Duration = Duration::from_secs(60);
/// The sampling interval the `stats` rates are the deltas of.
const STATS_INTERVAL: Duration = Duration::from_secs(1);
/// How often the daemon compares the idle time against `autoLockIdleSeconds`.
const DEFAULT_AUTOLOCK_TICK_SECS: u64 = 60;
/// Shortens the auto-lock tick; the auto-lock tests would otherwise run for a minute.
const AUTOLOCK_TICK_ENV: &str = "CRYPTO_AUTOLOCK_TICK_SECS";

/// Everything a daemon needs, built the same way for the detached child and for
/// `crypto unlock --foreground`.
///
/// # Errors
/// [`AppError::NoHomeDirectory`] without `$HOME` (the default mount-point base needs it), plus
/// anything reading `cli.json` reports.
pub fn config(ctx: &Ctx, vault_id: &str, log_file: Option<PathBuf>) -> Result<DaemonConfig> {
    let cli = CliConfig::load(&CliConfig::path_next_to(ctx.store.preferred_path()))?;
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or(AppError::NoHomeDirectory)?;
    Ok(DaemonConfig {
        vault_id: vault_id.to_owned(),
        state_dir: ctx.state_dir.clone(),
        store: ctx.store.clone(),
        force_unmount_after: Duration::from_secs(u64::from(cli.force_unmount_on_signal_after_secs)),
        cli,
        home,
        services: registry::all_services(),
        unlock_timeout: UNLOCK_TIMEOUT,
        stats_interval: STATS_INTERVAL,
        autolock_tick: Duration::from_secs(autolock_tick_secs()),
        log_file,
    })
}

/// The auto-lock tick in seconds; `$CRYPTO_AUTOLOCK_TICK_SECS` overrides the default. An
/// unparsable or zero value falls back to the default rather than spinning.
fn autolock_tick_secs() -> u64 {
    std::env::var(AUTOLOCK_TICK_ENV)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .unwrap_or(DEFAULT_AUTOLOCK_TICK_SECS)
}

/// Installs the flag both signals set. The daemon notices it within its poll interval and takes
/// the volume down gracefully.
///
/// # Errors
/// Whatever `signal_hook` reports while installing the handlers.
pub fn install_signal_flag() -> std::io::Result<Arc<AtomicBool>> {
    let shutdown = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&shutdown))?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&shutdown))?;
    Ok(shutdown)
}

/// Serves one vault until it is locked, shut down, auto-locked or signalled.
///
/// # Errors
/// Anything [`cryptomator_app::run_daemon`] reports; the exit code follows [`exit::code_for`], so
/// a failed mount ends up as [`exit::MOUNT_FAILED`].
pub fn run(ctx: &Ctx, args: DaemonArgs) -> Result<u8> {
    let files = ctx.state_dir.files(&args.vault_id);
    if let Some(socket) = args.socket.as_deref() {
        if socket != files.socket {
            // Not fatal: the state directory decides. Saying so beats a daemon that silently
            // listens somewhere else than the caller waits.
            eprintln!(
                "warning: --socket {} ignored; this daemon listens on {}",
                socket.display(),
                files.socket.display()
            );
        }
    }
    let config = config(ctx, &args.vault_id, Some(files.log.clone()))?;
    let shutdown = install_signal_flag()?;
    cryptomator_app::run_daemon(config, shutdown)?;
    Ok(exit::OK)
}
