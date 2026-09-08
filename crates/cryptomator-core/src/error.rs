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
    /// `FileSystemCapabilityChecker.MissingCapabilityException`. `capability` is `"read access"`
    /// or `"write access"`.
    #[error("the storage does not support {capability}: {path}")]
    MissingCapability {
        path: std::path::PathBuf,
        capability: &'static str,
    },
    /// The vault is, as it is, not migratable — e.g. a `vault.cryptomator` already sits next to a
    /// format 7 masterkey file, or a step of the chain is not implemented yet.
    #[error("migration cannot continue: {0}")]
    MigrationBlocked(String),
    /// `cryptofs/FileNameTooLongException`: the 6 → 7 migration would produce a name or a path
    /// that the storage cannot hold. `allowed` is what the capability probe found — the name limit
    /// for a name, that limit plus 48 for a path — and the vault is left unchanged.
    #[error("{path} needs {needed} characters, but the storage supports only {allowed}")]
    FileNameTooLong {
        path: std::path::PathBuf,
        needed: usize,
        allowed: usize,
    },
    /// `MasterkeyService.detect` found nothing to read the cipher combo from: the vault holds no
    /// encrypted file whose header decrypts with either scheme (or no candidate file at all).
    /// The caller has to be told which combo to use instead of guessing one.
    #[error("cannot detect the cipher combo of {0}: no encrypted file it could be read from")]
    CipherComboUndetectable(std::path::PathBuf),
    /// A vault format outside 5..=8: either older than any migrator this tool has
    /// (`NoApplicableMigratorException`) or newer than it knows.
    #[error("vault format {version} cannot be migrated by this version of the tool")]
    UnsupportedVaultVersion { version: u32 },
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Why a directory is not usable as a vault (`common/vaults/NotAVaultDirectoryException.Reason`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotAVaultReason {
    /// The path does not exist at all.
    PathNotFound,
    /// The path exists but is not a directory (e.g. a regular file).
    NotADirectory,
    MissingDataDir,
    DataNotADirectory,
    MissingVaultConfig,
    VaultConfigAccessDenied,
    UnsupportedStructure,
}

impl NotAVaultReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            NotAVaultReason::PathNotFound => "PATH_NOT_FOUND",
            NotAVaultReason::NotADirectory => "NOT_A_DIRECTORY",
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
