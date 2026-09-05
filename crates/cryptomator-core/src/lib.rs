//! Cryptomator vault format 8, ported from cryptolib 2.2.2 and cryptofs 2.10.0.
#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod backup;
pub mod constants;
pub mod crypto;
pub mod error;
pub mod masterkey_file;
pub mod recovery;
pub mod vault;
pub mod vault_config;

pub use backup::{
    attempt_backup, backup_file_name, generate_file_id_suffix, BackupOutcome, BackupStatus,
};
pub use crypto::cryptor::{CipherCombo, ContentCryptor, Cryptor, HeaderCryptor};
pub use crypto::header::FileHeader;
pub use crypto::masterkey::Masterkey;
/// Deterministic, insecure RNG for known-answer tests only; requires the `det-rng` feature.
#[cfg(any(test, feature = "det-rng"))]
pub use crypto::rng::DetRng;
pub use crypto::rng::{OsRng, Rng};
pub use crypto::siv::FileNameCryptor;
pub use crypto::stream::{decrypt_all, encrypt_all, DecryptingReader, EncryptingWriter};
pub use error::{CoreError, NotAVaultReason, Result};
pub use masterkey_file::{MasterkeyFile, MasterkeyFileAccess};
pub use vault::init::{
    create_vault, initialize, write_root_file, CreateVaultOptions, DEFAULT_SHORTENING_THRESHOLD,
    MAX_SHORTENING_THRESHOLD, MIN_SHORTENING_THRESHOLD,
};
pub use vault::open::{
    open_vault, open_vault_with_key, read_vault_config, root_content_dir, OpenedVault,
};
pub use vault::password::change_password;
pub use vault::readme::{
    access_location_readme_rtf, storage_location_readme_rtf, ACCESS_LOCATION_README_FILE_NAME,
    STORAGE_LOCATION_README_FILE_NAME,
};
pub use vault::state::{
    assert_is_vault_directory, check_dir_structure, determine_vault_state, determine_vault_version,
    needs_migration, restore_if_backup_present, DirStructure, VaultState,
};
pub use vault_config::{JwtAlgorithm, KeyId, UnverifiedVaultConfig, VaultConfig};
