//! Exit codes from the design spec and the mapping from error types.
use cryptomator_app::AppError;
use cryptomator_core::CoreError;
use std::io::ErrorKind;

pub const OK: u8 = 0;
pub const GENERAL: u8 = 1;
pub const USAGE: u8 = 2;
pub const VAULT_NOT_FOUND: u8 = 3;
pub const INVALID_PASSPHRASE: u8 = 4;
pub const WRONG_STATE: u8 = 5;
pub const MOUNT_FAILED: u8 = 6;
pub const UNMOUNT_FAILED: u8 = 7;
pub const KEYCHAIN_UNAVAILABLE: u8 = 8;
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
        AppError::Keychain(_) | AppError::KeychainNoEntry { .. } => KEYCHAIN_UNAVAILABLE,
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
        | AppError::SettingsLocked(_)
        | AppError::NoHomeDirectory => GENERAL,
    }
}

/// How a failed command ends: its exit code, or [`None`] when it did not really fail.
///
/// The one case of the latter is a closed pipe. `crypto vault list | head -3` closes its reader
/// as soon as it has what it wants, and the write that discovers this is an
/// [`ErrorKind::BrokenPipe`] -- not a failure of the command, and not something to print an error
/// about (stderr is usually still open, so the message would be the only thing the user sees).
/// Every command goes through here, so this holds for the ones that print through
/// [`crate::output`] as well as for `--follow` streams, which additionally end their loop on it.
pub fn failure_report(err: &anyhow::Error) -> Option<u8> {
    if is_broken_pipe(err) {
        return None;
    }
    Some(code_for(err))
}

/// Whether `err` is a reader that closed the pipe, wherever in the `anyhow` chain it sits --
/// as a bare [`std::io::Error`] (what [`crate::output::write_line`] reports) or wrapped in
/// [`AppError::Io`] (what everything going through `cryptomator_app` reports).
fn is_broken_pipe(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            return io.kind() == ErrorKind::BrokenPipe;
        }
        matches!(cause.downcast_ref::<AppError>(), Some(AppError::Io(io)) if io.kind() == ErrorKind::BrokenPipe)
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;

    fn broken_pipe() -> std::io::Error {
        std::io::Error::new(ErrorKind::BrokenPipe, "Broken pipe (os error 32)")
    }

    #[test]
    fn a_closed_pipe_is_a_successful_end_without_a_message() {
        // What `crypto vault list | head -0` produces, in the two shapes it can have.
        assert_eq!(failure_report(&anyhow::Error::from(broken_pipe())), None);
        assert_eq!(
            failure_report(&anyhow::Error::from(AppError::Io(broken_pipe()))),
            None
        );
        // Still recognised under an `anyhow` context, which is how commands annotate their I/O.
        let contextual = anyhow::Result::<()>::Err(broken_pipe().into())
            .context("cannot write the vault list")
            .unwrap_err();
        assert_eq!(failure_report(&contextual), None);
    }

    #[test]
    fn every_keychain_failure_is_exit_code_eight() {
        use cryptomator_app::KeychainError;
        let timed_out = AppError::Keychain(KeychainError::TimedOut {
            provider: "macOS Keychain".to_string(),
        });
        assert_eq!(
            failure_report(&anyhow::Error::from(timed_out)),
            Some(KEYCHAIN_UNAVAILABLE)
        );
        let missing = AppError::KeychainNoEntry {
            vault: "Secret".to_string(),
            provider: "macOS Keychain".to_string(),
        };
        assert_eq!(
            failure_report(&anyhow::Error::from(missing)),
            Some(KEYCHAIN_UNAVAILABLE)
        );
    }

    #[test]
    fn every_other_failure_keeps_its_exit_code() {
        let denied = AppError::Io(std::io::Error::new(
            ErrorKind::PermissionDenied,
            "permission denied",
        ));
        assert_eq!(failure_report(&anyhow::Error::from(denied)), Some(GENERAL));
        assert_eq!(
            failure_report(&anyhow::Error::from(AppError::VaultNotFound(
                "v".to_owned()
            ))),
            Some(VAULT_NOT_FOUND)
        );
        assert_eq!(
            failure_report(&anyhow::Error::from(AppError::UnmountFailed(
                "busy".to_owned()
            ))),
            Some(UNMOUNT_FAILED)
        );
    }
}
