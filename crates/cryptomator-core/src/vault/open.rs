//! Opening a vault: read + verify `vault.cryptomator`, load the masterkey, write the best-effort
//! backups Java writes on every unlock, and check the content root (`CryptoFileSystems.create`,
//! `MasterkeyFileLoadingStrategy.loadKey`).
use crate::backup::attempt_backup;
use crate::constants::{DATA_DIR_NAME, ROOT_DIR_ID, VAULTCONFIG_FILENAME, VAULT_VERSION};
use crate::crypto::cryptor::Cryptor;
use crate::crypto::masterkey::Masterkey;
use crate::error::{CoreError, Result};
use crate::masterkey_file::MasterkeyFileAccess;
use crate::vault_config::{UnverifiedVaultConfig, VaultConfig};
use std::path::{Path, PathBuf};

pub struct OpenedVault {
    pub path: PathBuf,
    pub config: VaultConfig,
    pub masterkey: Masterkey,
    pub cryptor: Cryptor,
}

impl std::fmt::Debug for OpenedVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenedVault")
            .field("path", &self.path)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

pub fn read_vault_config(vault_path: &Path) -> Result<UnverifiedVaultConfig> {
    let token = std::fs::read_to_string(vault_path.join(VAULTCONFIG_FILENAME))?;
    UnverifiedVaultConfig::decode(token.trim())
}

/// `<vault>/d/<hash[..2]>/<hash[2..]>` for the root directory id `""`.
pub fn root_content_dir(vault_path: &Path, cryptor: &Cryptor) -> PathBuf {
    let hash = cryptor.file_name_cryptor().hash_directory_id(ROOT_DIR_ID);
    vault_path
        .join(DATA_DIR_NAME)
        .join(&hash[..2])
        .join(&hash[2..])
}

/// Password-based unlock. Rejects Hub vaults before touching any key material.
pub fn open_vault(
    vault_path: &Path,
    access: &MasterkeyFileAccess,
    passphrase: &str,
) -> Result<OpenedVault> {
    let unverified = read_vault_config(vault_path)?;
    let masterkey_file_name = unverified.key_id()?.require_masterkey_file()?.to_string();
    let masterkey_path = vault_path.join(&masterkey_file_name);
    let masterkey = access.load(&masterkey_path, passphrase)?;
    // Java backs the masterkey file up after every successful load (best effort, read-only vaults tolerated).
    let _ = attempt_backup(&masterkey_path);
    open_with_key(vault_path, unverified, masterkey)
}

/// Unlock with an already known masterkey (recovery key flows, tests).
pub fn open_vault_with_key(vault_path: &Path, masterkey: Masterkey) -> Result<OpenedVault> {
    let unverified = read_vault_config(vault_path)?;
    open_with_key(vault_path, unverified, masterkey)
}

fn open_with_key(
    vault_path: &Path,
    unverified: UnverifiedVaultConfig,
    masterkey: Masterkey,
) -> Result<OpenedVault> {
    let config = unverified.verify(masterkey.raw(), VAULT_VERSION)?;
    let _ = attempt_backup(&vault_path.join(VAULTCONFIG_FILENAME));
    let cryptor = Cryptor::new(config.cipher_combo, &masterkey);
    let root = root_content_dir(vault_path, &cryptor);
    if !root.exists() {
        return Err(CoreError::ContentRootMissing(root));
    }
    Ok(OpenedVault {
        path: vault_path.to_path_buf(),
        config,
        masterkey,
        cryptor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::MASTERKEY_FILENAME;
    use std::fs;
    use std::path::PathBuf;

    const PASSPHRASE: &str = "test-password-123";

    /// Copies a committed fixture into a temp dir (opening writes .bkup files; fixtures must stay pristine).
    fn copy_fixture(name: &str) -> tempfile::TempDir {
        let src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name);
        let dir = tempfile::tempdir().unwrap();
        copy_recursively(&src, dir.path());
        dir
    }

    fn copy_recursively(src: &Path, dst: &Path) {
        for entry in fs::read_dir(src).unwrap() {
            let entry = entry.unwrap();
            let target = dst.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                fs::create_dir(&target).unwrap();
                copy_recursively(&entry.path(), &target);
            } else {
                fs::copy(entry.path(), &target).unwrap();
            }
        }
    }

    fn backups(dir: &Path, prefix: &str) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(prefix) && n.ends_with(".bkup"))
            .collect();
        names.sort();
        names
    }

    #[test]
    fn opens_fixture_and_writes_both_backups() {
        for name in ["siv_gcm_basic", "siv_ctrmac_basic"] {
            let dir = copy_fixture(name);
            let access = MasterkeyFileAccess::new(Vec::new());
            let opened = open_vault(dir.path(), &access, PASSPHRASE).unwrap();
            assert_eq!(opened.path, dir.path());
            assert_eq!(opened.config.vault_version, 8);
            assert_eq!(opened.cryptor.cipher_combo(), opened.config.cipher_combo);
            assert!(root_content_dir(dir.path(), &opened.cryptor).is_dir());
            assert_eq!(
                backups(dir.path(), "vault.cryptomator").len(),
                1,
                "{name}: config backup"
            );
            assert_eq!(
                backups(dir.path(), MASTERKEY_FILENAME).len(),
                1,
                "{name}: masterkey backup"
            );
            // opening again does not create a second backup of unchanged files
            open_vault(dir.path(), &access, PASSPHRASE).unwrap();
            assert_eq!(backups(dir.path(), "vault.cryptomator").len(), 1);
        }
    }

    #[test]
    fn wrong_passphrase_is_invalid_passphrase_and_writes_no_backup() {
        let dir = copy_fixture("siv_gcm_basic");
        let access = MasterkeyFileAccess::new(Vec::new());
        // The fixture ships a committed config backup, so compare against the pre-unlock state.
        let before = backups(dir.path(), "vault.cryptomator");
        assert!(matches!(
            open_vault(dir.path(), &access, "nope"),
            Err(CoreError::InvalidPassphrase)
        ));
        assert_eq!(backups(dir.path(), "vault.cryptomator"), before);
        assert!(backups(dir.path(), MASTERKEY_FILENAME).is_empty());
    }

    #[test]
    fn hub_vault_is_rejected_before_asking_for_a_key() {
        let dir = copy_fixture("siv_gcm_basic");
        let token = crate::VaultConfig {
            id: "x".into(),
            vault_version: 8,
            cipher_combo: crate::CipherCombo::SivGcm,
            shortening_threshold: 220,
        }
        .to_token("hub+https://hub.example.com/api/vaults/1", &[0u8; 64]);
        fs::write(dir.path().join(VAULTCONFIG_FILENAME), token).unwrap();
        let access = MasterkeyFileAccess::new(Vec::new());
        assert!(matches!(
            open_vault(dir.path(), &access, PASSPHRASE),
            Err(CoreError::HubVaultUnsupported(_))
        ));
    }

    #[test]
    fn open_vault_rejects_traversal_in_key_id() {
        let dir = copy_fixture("siv_gcm_basic");
        // `kid` is read before the config signature is verified, so a hostile config must not be
        // able to steer the masterkey load (and its backup) outside the vault directory.
        let token = crate::VaultConfig {
            id: "x".into(),
            vault_version: 8,
            cipher_combo: crate::CipherCombo::SivGcm,
            shortening_threshold: 220,
        }
        .to_token("masterkeyfile:../outside", &[0u8; 64]);
        fs::write(dir.path().join(VAULTCONFIG_FILENAME), token).unwrap();
        let access = MasterkeyFileAccess::new(Vec::new());
        assert!(matches!(
            open_vault(dir.path(), &access, PASSPHRASE),
            Err(CoreError::UnsupportedKeyId(_))
        ));
        assert!(backups(dir.path(), "outside").is_empty());
    }

    #[test]
    fn missing_content_root_is_reported() {
        let dir = copy_fixture("siv_gcm_basic");
        fs::remove_dir_all(dir.path().join("d")).unwrap();
        let access = MasterkeyFileAccess::new(Vec::new());
        assert!(matches!(
            open_vault(dir.path(), &access, PASSPHRASE),
            Err(CoreError::ContentRootMissing(_))
        ));
    }

    #[test]
    fn open_with_key_verifies_signature() {
        let dir = copy_fixture("siv_gcm_basic");
        let access = MasterkeyFileAccess::new(Vec::new());
        let key = access
            .load(&dir.path().join(MASTERKEY_FILENAME), PASSPHRASE)
            .unwrap();
        assert!(open_vault_with_key(dir.path(), key).is_ok());
        assert!(matches!(
            open_vault_with_key(dir.path(), Masterkey::from_raw([1u8; 64])),
            Err(CoreError::VaultKeyInvalid)
        ));
    }

    #[test]
    fn read_vault_config_reports_missing_file_as_io() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            read_vault_config(dir.path()),
            Err(CoreError::Io(_))
        ));
    }
}
