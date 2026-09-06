//! Command implementations; each returns the process exit code.
pub mod config;
pub mod daemon;
pub mod events;
pub mod fs;
pub mod lock;
pub mod mounters;
pub mod name;
pub mod password;
pub mod recovery;
pub mod stats;
pub mod status;
pub mod unlock;
pub mod vault;

use crate::output::Output;
use anyhow::Result;
use cryptomator_app::settings::{resolve_vault_index, SettingsStore, VaultSettingsJson};
use cryptomator_app::{AppError, ErrorBody, RuntimeState, StateDir, VaultInfo, VaultRegistry};
use cryptomator_core::{determine_vault_state, VaultState};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

#[derive(Debug)]
pub struct Ctx {
    pub store: SettingsStore,
    pub out: Output,
    /// Where the daemons publish their socket, pid and run info.
    pub state_dir: StateDir,
    /// The `--settings` path exactly as it was given, so a spawned daemon can be handed the same
    /// one. `None` means "resolve it from the environment", which the child does the same way.
    pub settings_arg: Option<PathBuf>,
}

impl Ctx {
    /// The vaults of `settings.json` together with what the state directory says about them.
    pub fn registry(&self) -> VaultRegistry {
        VaultRegistry::new(self.store.clone(), self.state_dir.clone())
    }
}

/// Resolves a vault reference and requires a daemon to be serving it, returning the vault and the
/// socket to talk to that daemon on.
///
/// `crypto stats` and `crypto events` both need one: their answers exist only inside the running
/// daemon. A vault in any other state -- locked, or left behind by a crashed daemon -- is an
/// [`AppError::WrongState`] (exit code 5), not an empty result.
///
/// # Errors
/// [`AppError::VaultNotFound`] / [`AppError::AmbiguousVault`] (exit code 3) for a reference that
/// names no vault, [`AppError::WrongState`] (5) for one that is not unlocked.
pub fn unlocked_vault(ctx: &Ctx, reference: &str) -> Result<(VaultInfo, PathBuf)> {
    let info = ctx.registry().info(reference)?;
    if info.state != RuntimeState::Unlocked {
        return Err(AppError::WrongState {
            expected: RuntimeState::Unlocked.as_str().to_string(),
            actual: info.state.as_str().to_string(),
        }
        .into());
    }
    let socket = ctx.state_dir.files(&info.id).socket;
    Ok((info, socket))
}

/// Whether `err` means the daemon is not there any more.
///
/// For a `--follow` stream that is the end of the story rather than a failure: the vault was
/// locked (or auto-locked, or signalled) while it was being watched, and the watcher saw
/// everything there was to see. It stays an error for a command that never got an answer at all.
pub fn daemon_gone(err: &AppError) -> bool {
    matches!(err, AppError::DaemonUnreachable(_))
}

/// Whether `err` is the honest end of a `--follow` stream rather than a failure of it.
///
/// [`daemon_gone`] covers the socket disappearing entirely, but `crypto stats --follow` can also
/// land its next poll while the daemon is still there and mid-teardown (`Phase::Locking`): it
/// answers `NOT_UNLOCKED` right up until the socket itself goes away. Both are the same event --
/// the vault was locked, auto-locked or signalled while the stream was watching it -- just caught
/// at different points of the daemon's shutdown, so both end the stream the same way (after at
/// least one sample was ever delivered; see the call sites).
pub fn stream_ended(err: &AppError) -> bool {
    daemon_gone(err)
        || matches!(err, AppError::DaemonError { code, .. } if code == ErrorBody::NOT_UNLOCKED)
}

/// How a vault is named in a message to the user: its display name, or its id when it has none.
pub fn vault_label(info: &VaultInfo) -> &str {
    info.display_name.as_deref().unwrap_or(&info.id)
}

/// Sets a flag on Ctrl-C instead of ending the process, so a `--follow` loop can stop between
/// messages and exit 0 like any other successful command.
///
/// Shared by `crypto stats --follow` and `crypto events --follow`.
///
/// # Errors
/// Whatever `signal_hook` reports while installing the handler.
pub fn install_interrupt() -> Result<Arc<AtomicBool>> {
    let flag = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&flag))?;
    Ok(flag)
}

/// Resolves a vault reference to its settings entry and path, requiring the vault to be in state
/// LOCKED (config + masterkey present).
pub fn locked_vault(ctx: &Ctx, reference: &str) -> Result<(VaultSettingsJson, PathBuf)> {
    let settings = ctx.store.load()?;
    let index = resolve_vault_index(&settings, reference)?;
    let vault = settings.directories[index].clone();
    let path = vault.path_buf().ok_or_else(|| AppError::InvalidValue {
        key: "path".to_string(),
        message: format!("vault {} has no path", vault.id),
    })?;
    let state = determine_vault_state(&path)?;
    if state != VaultState::Locked {
        return Err(AppError::WrongState {
            expected: VaultState::Locked.as_str().to_string(),
            actual: state.as_str().to_string(),
        }
        .into());
    }
    Ok((vault, path))
}

pub fn locked_vault_path(ctx: &Ctx, reference: &str) -> Result<PathBuf> {
    locked_vault(ctx, reference).map(|(_, path)| path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_ended_matches_a_gone_daemon() {
        assert!(stream_ended(&AppError::DaemonUnreachable(
            "connection refused".to_string()
        )));
    }

    #[test]
    fn stream_ended_matches_not_unlocked() {
        assert!(stream_ended(&AppError::DaemonError {
            code: ErrorBody::NOT_UNLOCKED.to_string(),
            message: "vault is locking".to_string(),
        }));
    }

    #[test]
    fn stream_ended_does_not_match_other_daemon_errors() {
        assert!(!stream_ended(&AppError::DaemonError {
            code: ErrorBody::MOUNT_FAILED.to_string(),
            message: "mount failed".to_string(),
        }));
    }
}
