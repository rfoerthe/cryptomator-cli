//! Errors of the application layer.
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error(transparent)]
    Core(#[from] cryptomator_core::CoreError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("settings file {path} is not valid JSON: {source}")]
    SettingsCorrupt {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("cannot read settings file {path}: {source}")]
    SettingsUnreadable {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("no vault matches {0:?} (by id, display name or path)")]
    VaultNotFound(String),
    #[error("{:?} matches several vaults: {}", _0, _1.join(", "))]
    AmbiguousVault(String, Vec<String>),
    #[error("vault at {0} is already registered")]
    VaultAlreadyAdded(PathBuf),
    #[error("no password source: use --password-stdin, --password-file, --password-env or CRYPTO_PASSWORD, or run interactively")]
    NoPasswordSource,
    #[error("password must be at least {0} characters long")]
    PasswordTooShort(usize),
    #[error("passwords do not match")]
    PasswordMismatch,
    #[error("vault is {actual}, expected {expected}")]
    WrongState { expected: String, actual: String },
    #[error("invalid value for {key}: {message}")]
    InvalidValue { key: String, message: String },
    #[error("no home directory (set HOME or CRYPTO_SETTINGS_PATH)")]
    NoHomeDirectory,
}

pub type Result<T> = std::result::Result<T, AppError>;
