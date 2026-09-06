//! Command implementations; each returns the process exit code.
pub mod config;
pub mod daemon;
pub mod fs;
pub mod lock;
pub mod name;
pub mod password;
pub mod recovery;
pub mod unlock;
pub mod vault;

use crate::output::Output;
use anyhow::Result;
use cryptomator_app::settings::{resolve_vault_index, SettingsStore, VaultSettingsJson};
use cryptomator_app::{AppError, StateDir, VaultRegistry};
use cryptomator_core::{determine_vault_state, VaultState};
use std::path::PathBuf;

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
