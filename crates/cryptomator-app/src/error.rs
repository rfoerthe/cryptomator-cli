//! Errors of the application layer.
use crate::password::PASSWORD_ENV;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error(transparent)]
    Core(#[from] cryptomator_core::CoreError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    // No `{source}`: the field is a `#[source]`, and the CLI renders the whole chain with `{err:#}`.
    #[error("settings file {path} is not valid JSON")]
    SettingsCorrupt {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("cannot read settings file {path}")]
    SettingsUnreadable {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// Another process holds the `flock` on `settings.json.lock`; the CLI reports exit code 1.
    #[error("{0} is locked by another process; it did not let go in time")]
    SettingsLocked(PathBuf),
    #[error("no vault matches {0:?} (by id, display name or path)")]
    VaultNotFound(String),
    #[error("{:?} matches several vaults: {}", _0, _1.join(", "))]
    AmbiguousVault(String, Vec<String>),
    #[error("vault at {0} is already registered")]
    VaultAlreadyAdded(PathBuf),
    #[error("no password source: {}", no_password_hint(.label, .env_fallback))]
    NoPasswordSource {
        /// Flag prefix of the passphrase that is missing (`--password` or `--new-password`).
        label: &'static str,
        /// Whether `$CRYPTO_PASSWORD` is an accepted source in this position. `password change`
        /// reads the *current* password from it, so it never supplies the new one.
        env_fallback: bool,
    },
    #[error("password must be at least {0} characters long")]
    PasswordTooShort(usize),
    #[error("passwords do not match")]
    PasswordMismatch,
    #[error("vault is {actual}, expected {expected}")]
    WrongState { expected: String, actual: String },
    #[error("invalid value for {key}: {message}")]
    InvalidValue { key: String, message: String },
    /// Mounting the vault failed; the CLI reports exit code 6.
    #[error("mount failed: {0}")]
    MountFailed(String),
    /// The mount point the user chose cannot be used; exit code 6 as well.
    #[error("mount point {0}: {1}")]
    MountPointInvalid(PathBuf, String),
    /// Taking a mount down failed, e.g. because the volume is still in use; exit code 7.
    #[error("unmount failed: {0}")]
    UnmountFailed(String),
    /// The vault daemon could not be reached; exit code 10.
    #[error("cannot reach the vault daemon: {0}")]
    DaemonUnreachable(String),
    /// The daemon answered with an error; the CLI maps `code` to an exit code.
    #[error("{message}")]
    DaemonError { code: String, message: String },
    /// The keychain could not serve the request; the CLI reports exit code 8.
    #[error(transparent)]
    Keychain(#[from] crate::keychain::KeychainError),
    /// `--password-keychain` was given but nothing is stored for this vault; exit code 8 as well,
    /// because the source the user insisted on is not available.
    #[error("no passphrase is stored for {vault} in {provider}")]
    KeychainNoEntry { vault: String, provider: String },
    #[error("no home directory (set HOME or CRYPTO_SETTINGS_PATH)")]
    NoHomeDirectory,
}

/// Message branch of [`AppError::NoPasswordSource`]: which flags apply and whether
/// `$CRYPTO_PASSWORD` is one of the sources.
fn no_password_hint(label: &str, env_fallback: &bool) -> String {
    // `--password-keychain` only exists at the current-password position (`label == "--password"`):
    // a *new* password is never read from the keychain, so there is no `--new-password-keychain`
    // to name here (see `password::read_new`'s own rejection of the flag).
    let flags = if label == "--password" {
        format!("use {label}-stdin, {label}-file, {label}-env or {label}-keychain")
    } else {
        format!("use {label}-stdin, {label}-file or {label}-env")
    };
    if *env_fallback {
        format!("{flags}, set {PASSWORD_ENV}, or run interactively")
    } else {
        format!("{flags}, or run interactively; {PASSWORD_ENV} supplies only the current password")
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
