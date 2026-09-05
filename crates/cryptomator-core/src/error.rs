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
    #[error("not a vault directory: {path} ({reason})")]
    NotAVaultDirectory {
        path: std::path::PathBuf,
        reason: NotAVaultReason,
    },
    #[error("vault content root is missing: {0}")]
    ContentRootMissing(std::path::PathBuf),
    #[error("vault needs migration to format 8: {0}")]
    NeedsMigration(std::path::PathBuf),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Why a directory is not usable as a vault (`common/vaults/NotAVaultDirectoryException.Reason`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotAVaultReason {
    MissingDataDir,
    DataNotADirectory,
    MissingVaultConfig,
    VaultConfigAccessDenied,
    UnsupportedStructure,
}

impl NotAVaultReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            NotAVaultReason::MissingDataDir => "MISSING_DATA_DIR",
            NotAVaultReason::DataNotADirectory => "DATA_NOT_A_DIRECTORY",
            NotAVaultReason::MissingVaultConfig => "MISSING_VAULT_CONFIG",
            NotAVaultReason::VaultConfigAccessDenied => "VAULT_CONFIG_ACCESS_DENIED",
            NotAVaultReason::UnsupportedStructure => "UNSUPPORTED_STRUCTURE",
        }
    }
}

impl std::fmt::Display for NotAVaultReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

pub type Result<T> = std::result::Result<T, CoreError>;
