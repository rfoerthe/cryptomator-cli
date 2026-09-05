//! Error type of the core crate. Variants mirror the cryptolib/cryptofs exceptions.
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("invalid passphrase")]
    InvalidPassphrase,
    #[error("authentication failed: {0}")]
    AuthenticationFailed(String),
    #[error("invalid masterkey file: {0}")]
    InvalidMasterkeyFile(String),
    #[error("failed to load vault config: {0}")]
    VaultConfigLoad(String),
    #[error("vault key does not match the vault config signature")]
    VaultKeyInvalid,
    #[error("vault config is for format {actual}, expected {expected}")]
    VaultVersionMismatch { expected: u32, actual: u32 },
    #[error("Cryptomator Hub vaults are not supported (key id: {0})")]
    HubVaultUnsupported(String),
    #[error("unsupported key id: {0}")]
    UnsupportedKeyId(String),
    #[error("invalid recovery key: {0}")]
    InvalidRecoveryKey(String),
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, CoreError>;
