//! Exit codes from the design spec and the mapping from error types.
use cryptomator_app::AppError;
use cryptomator_core::CoreError;

pub const OK: u8 = 0;
pub const GENERAL: u8 = 1;
pub const USAGE: u8 = 2;
pub const VAULT_NOT_FOUND: u8 = 3;
pub const INVALID_PASSPHRASE: u8 = 4;
pub const WRONG_STATE: u8 = 5;
pub const HUB_VAULT: u8 = 9;
pub const NOT_A_VAULT: u8 = 12;

fn core_code(err: &CoreError) -> u8 {
    match err {
        CoreError::InvalidPassphrase
        | CoreError::InvalidRecoveryKey(_)
        | CoreError::VaultKeyInvalid
        | CoreError::AuthenticationFailed(_) => INVALID_PASSPHRASE,
        CoreError::HubVaultUnsupported(_) => HUB_VAULT,
        CoreError::NotAVaultDirectory { .. } => NOT_A_VAULT,
        CoreError::NeedsMigration(_)
        | CoreError::ContentRootMissing(_)
        | CoreError::VaultVersionMismatch { .. } => WRONG_STATE,
        CoreError::InvalidArgument(_) => USAGE,
        _ => GENERAL,
    }
}

pub fn code_for(err: &anyhow::Error) -> u8 {
    if let Some(app) = err.downcast_ref::<AppError>() {
        return match app {
            AppError::Core(core) => core_code(core),
            AppError::VaultNotFound(_) | AppError::AmbiguousVault(..) => VAULT_NOT_FOUND,
            AppError::PasswordTooShort(_) | AppError::PasswordMismatch => INVALID_PASSPHRASE,
            AppError::WrongState { .. } | AppError::VaultAlreadyAdded(_) => WRONG_STATE,
            AppError::NoPasswordSource | AppError::InvalidValue { .. } => USAGE,
            AppError::Io(_)
            | AppError::SettingsCorrupt { .. }
            | AppError::SettingsUnreadable { .. }
            | AppError::NoHomeDirectory => GENERAL,
        };
    }
    if let Some(core) = err.downcast_ref::<CoreError>() {
        return core_code(core);
    }
    GENERAL
}
