//! Exit codes from the design spec and the mapping from error types.
use cryptomator_app::AppError;
use cryptomator_core::CoreError;

pub const OK: u8 = 0;
pub const GENERAL: u8 = 1;
pub const USAGE: u8 = 2;
pub const VAULT_NOT_FOUND: u8 = 3;
pub const INVALID_PASSPHRASE: u8 = 4;
pub const WRONG_STATE: u8 = 5;
pub const MOUNT_FAILED: u8 = 6;
pub const UNMOUNT_FAILED: u8 = 7;
pub const HUB_VAULT: u8 = 9;
pub const DAEMON_UNREACHABLE: u8 = 10;
pub const NOT_A_VAULT: u8 = 12;

// Exhaustive on purpose (no `_` arm): a new `CoreError` variant must be given an exit code here
// instead of silently becoming a generic failure.
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
        CoreError::InvalidMasterkeyFile(_)
        | CoreError::VaultConfigLoad(_)
        | CoreError::UnsupportedKeyId(_)
        | CoreError::Io(_) => GENERAL,
    }
}

fn app_code(err: &AppError) -> u8 {
    match err {
        AppError::Core(core) => core_code(core),
        AppError::VaultNotFound(_) | AppError::AmbiguousVault(..) => VAULT_NOT_FOUND,
        AppError::PasswordTooShort(_) | AppError::PasswordMismatch => INVALID_PASSPHRASE,
        AppError::WrongState { .. } | AppError::VaultAlreadyAdded(_) => WRONG_STATE,
        AppError::NoPasswordSource { .. } | AppError::InvalidValue { .. } => USAGE,
        AppError::MountFailed(_) | AppError::MountPointInvalid(..) => MOUNT_FAILED,
        AppError::UnmountFailed(_) => UNMOUNT_FAILED,
        AppError::DaemonUnreachable(_) => DAEMON_UNREACHABLE,
        // The daemon reports what went wrong on its side; its code decides ours.
        AppError::DaemonError { code, .. } => match code.as_str() {
            "MOUNT_FAILED" => MOUNT_FAILED,
            "UNMOUNT_FAILED" => UNMOUNT_FAILED,
            "ALREADY_UNLOCKED" | "NOT_UNLOCKED" => WRONG_STATE,
            _ => GENERAL,
        },
        AppError::Io(_)
        | AppError::SettingsCorrupt { .. }
        | AppError::SettingsUnreadable { .. }
        | AppError::NoHomeDirectory => GENERAL,
    }
}

/// The whole chain is searched, so an error that was given an `anyhow` context (`with_context`)
/// keeps the exit code of the typed error underneath it.
pub fn code_for(err: &anyhow::Error) -> u8 {
    for cause in err.chain() {
        if let Some(app) = cause.downcast_ref::<AppError>() {
            return app_code(app);
        }
        if let Some(core) = cause.downcast_ref::<CoreError>() {
            return core_code(core);
        }
    }
    GENERAL
}
