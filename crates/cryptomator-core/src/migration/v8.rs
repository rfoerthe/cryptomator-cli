//! 7 → 8, a port of `migration/v8/Version8Migrator.java`.
//!
//! The masterkey file is split in two: `vault.cryptomator` takes the vault format and the
//! vault-specific metadata, `masterkey.cryptomator` keeps only the KDF parameters and from now on
//! carries the placeholder version 999. The ciphertext below `d/` is untouched — format 7 and 8
//! store names and contents identically.
use crate::constants::{DEFAULT_KEY_ID, MASTERKEY_FILENAME, VAULTCONFIG_FILENAME};
use crate::crypto::cryptor::CipherCombo;
use crate::crypto::rng::Rng;
use crate::error::{CoreError, Result};
use crate::masterkey_file::{MasterkeyFileAccess, DEFAULT_MASTERKEY_FILE_VERSION};
use crate::migration::back_up;
use crate::vault_config::VaultConfig;
use std::io::Write;
use std::path::Path;

/// Format 7 knew no cipher combo other than SIV+CTR/MAC and no configurable name length, so
/// Java hard-codes both claims (`Version8Migrator.migrate`).
const FORMAT_7_CIPHER_COMBO: CipherCombo = CipherCombo::SivCtrMac;
const FORMAT_7_SHORTENING_THRESHOLD: u32 = 220;

pub fn migrate(vault_path: &Path, passphrase: &str, rng: &mut dyn Rng) -> Result<()> {
    let masterkey_file = vault_path.join(MASTERKEY_FILENAME);
    let config_file = vault_path.join(VAULTCONFIG_FILENAME);
    let access = MasterkeyFileAccess::new(Vec::new());
    // Load first: the backup is only written once the passphrase is known to be correct.
    let masterkey = access.load(&masterkey_file, passphrase)?;
    back_up(&masterkey_file)?;

    let config = VaultConfig::create_new(FORMAT_7_CIPHER_COMBO, FORMAT_7_SHORTENING_THRESHOLD);
    let token = config.to_token(DEFAULT_KEY_ID, masterkey.raw());
    // Java writes with CREATE_NEW: an existing vault.cryptomator is an error, never an overwrite.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&config_file)
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::AlreadyExists => CoreError::MigrationBlocked(format!(
                "{} already exists; the vault may already be migrated",
                config_file.display()
            )),
            _ => CoreError::Io(e),
        })?;
    file.write_all(token.as_bytes())?;
    file.sync_all()?;

    access.persist(
        &masterkey,
        &masterkey_file,
        passphrase,
        DEFAULT_MASTERKEY_FILE_VERSION,
        rng,
    )
}
