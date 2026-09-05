//! Command implementations; each returns the process exit code.
pub mod config;
pub mod password;
pub mod recovery;
pub mod vault;

use crate::output::Output;
use anyhow::Result;
use cryptomator_app::settings::{resolve_vault_index, SettingsStore};
use cryptomator_app::AppError;
use cryptomator_core::{determine_vault_state, VaultState};
use std::path::PathBuf;

#[derive(Debug)]
pub struct Ctx {
    pub store: SettingsStore,
    pub out: Output,
}

/// Resolves a vault reference and requires the vault to be in state LOCKED (config + masterkey present).
pub fn locked_vault_path(ctx: &Ctx, reference: &str) -> Result<PathBuf> {
    let settings = ctx.store.load()?;
    let index = resolve_vault_index(&settings, reference)?;
    let vault = &settings.directories[index];
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
    Ok(path)
}
