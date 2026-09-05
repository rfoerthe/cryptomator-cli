//! Vault directory structure and state detection, ported from cryptofs `DirStructure.java`,
//! the desktop app's `VaultListManager.java` (`determineVaultState`, `assertIsVaultDirectory`)
//! and `BackupRestorer.java`.
use crate::constants::{
    BACKUP_SUFFIX, DATA_DIR_NAME, MASTERKEY_FILENAME, VAULTCONFIG_FILENAME, VAULT_VERSION,
};
use crate::error::{CoreError, NotAVaultReason, Result};
use crate::masterkey_file::MasterkeyFileAccess;
use crate::vault_config::UnverifiedVaultConfig;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirStructure {
    /// `d/` exists and `vault.cryptomator` is readable.
    Vault,
    /// `d/` exists, no readable `vault.cryptomator`, but a readable `masterkey.cryptomator` (format ≤ 7 or config lost).
    MaybeLegacy,
    Unrelated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultState {
    Missing,
    VaultConfigMissing,
    AllMissing,
    NeedsMigration,
    Locked,
}

impl VaultState {
    pub fn as_str(&self) -> &'static str {
        match self {
            VaultState::Missing => "MISSING",
            VaultState::VaultConfigMissing => "VAULT_CONFIG_MISSING",
            VaultState::AllMissing => "ALL_MISSING",
            VaultState::NeedsMigration => "NEEDS_MIGRATION",
            VaultState::Locked => "LOCKED",
        }
    }
}

impl std::fmt::Display for VaultState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

fn is_readable(path: &Path) -> bool {
    std::fs::File::open(path).is_ok()
}

/// `DirStructure.checkDirStructure`: the path must be a directory (else `NotADirectory` I/O error).
pub fn check_dir_structure(path_to_vault: &Path) -> Result<DirStructure> {
    let metadata = std::fs::metadata(path_to_vault)?;
    if !metadata.is_dir() {
        return Err(CoreError::Io(std::io::Error::new(
            std::io::ErrorKind::NotADirectory,
            format!("{} is not a directory", path_to_vault.display()),
        )));
    }
    if path_to_vault.join(DATA_DIR_NAME).is_dir() {
        if is_readable(&path_to_vault.join(VAULTCONFIG_FILENAME)) {
            return Ok(DirStructure::Vault);
        }
        if is_readable(&path_to_vault.join(MASTERKEY_FILENAME)) {
            return Ok(DirStructure::MaybeLegacy);
        }
    }
    Ok(DirStructure::Unrelated)
}

/// `VaultListManager.assertIsVaultDirectory`: Ok for `Vault` and `MaybeLegacy`, otherwise the most specific reason.
/// A missing path and a path that is not a directory are reported as `NotAVaultDirectory` too, so
/// every "this is not a vault" outcome maps to the same exit code instead of a bare I/O error.
pub fn assert_is_vault_directory(path_to_vault: &Path) -> Result<()> {
    let fail = |reason| {
        Err(CoreError::NotAVaultDirectory {
            path: path_to_vault.to_path_buf(),
            reason,
        })
    };
    match check_dir_structure(path_to_vault) {
        Ok(DirStructure::Unrelated) => {}
        Ok(_) => return Ok(()),
        Err(CoreError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            return fail(NotAVaultReason::PathNotFound)
        }
        Err(CoreError::Io(e)) if e.kind() == std::io::ErrorKind::NotADirectory => {
            return fail(NotAVaultReason::NotADirectory)
        }
        Err(e) => return Err(e),
    }
    let data_dir = path_to_vault.join(DATA_DIR_NAME);
    if !data_dir.exists() {
        return fail(NotAVaultReason::MissingDataDir);
    }
    if !data_dir.is_dir() {
        return fail(NotAVaultReason::DataNotADirectory);
    }
    match std::fs::File::open(path_to_vault.join(VAULTCONFIG_FILENAME)) {
        Ok(_) => fail(NotAVaultReason::UnsupportedStructure),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fail(NotAVaultReason::MissingVaultConfig)
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            fail(NotAVaultReason::VaultConfigAccessDenied)
        }
        Err(_) => fail(NotAVaultReason::UnsupportedStructure),
    }
}

/// `BackupRestorer.restoreIfBackupPresent`: copies the newest `<prefix>*.bkup` over `<vault>/<prefix>`.
/// Best effort like Java: any I/O problem yields `None`.
pub fn restore_if_backup_present(vault_path: &Path, file_prefix: &str) -> Option<PathBuf> {
    let entries = std::fs::read_dir(vault_path).ok()?;
    let newest = entries
        .flatten()
        .filter(|e| {
            let name = e.file_name();
            let name = name.to_string_lossy();
            name.starts_with(file_prefix) && name.ends_with(BACKUP_SUFFIX)
        })
        .filter_map(|e| {
            e.metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .map(|t| (t, e.path()))
        })
        .max_by_key(|(time, _)| *time)
        .map(|(_, path)| path)?;
    std::fs::copy(&newest, vault_path.join(file_prefix)).ok()?;
    Some(newest)
}

/// `Migrators.determineVaultVersion`: the `format` claim if a config exists, else the masterkey file's `version`.
pub fn determine_vault_version(path_to_vault: &Path) -> Result<u32> {
    let config_path = path_to_vault.join(VAULTCONFIG_FILENAME);
    if config_path.exists() {
        let token = std::fs::read_to_string(&config_path)?;
        UnverifiedVaultConfig::decode(token.trim())?
            .alleged_vault_version()
            .ok_or_else(|| CoreError::VaultConfigLoad("vault config has no format claim".into()))
    } else {
        let bytes = std::fs::read(path_to_vault.join(MASTERKEY_FILENAME))?;
        MasterkeyFileAccess::read_alleged_vault_version(&bytes)
    }
}

pub fn needs_migration(path_to_vault: &Path) -> Result<bool> {
    Ok(determine_vault_version(path_to_vault)? < VAULT_VERSION)
}

fn check_structure(path_to_vault: &Path) -> Result<VaultState> {
    Ok(match check_dir_structure(path_to_vault)? {
        DirStructure::Vault => VaultState::Locked,
        DirStructure::Unrelated => VaultState::Missing,
        DirStructure::MaybeLegacy => {
            if needs_migration(path_to_vault)? {
                VaultState::NeedsMigration
            } else {
                VaultState::Missing
            }
        }
    })
}

/// `VaultListManager.determineVaultState`, including the `.bkup` auto-restore of missing key files.
pub fn determine_vault_state(path_to_vault: &Path) -> Result<VaultState> {
    if !path_to_vault.exists() {
        return Ok(VaultState::Missing);
    }
    let structure = check_structure(path_to_vault)?;
    if matches!(structure, VaultState::Locked | VaultState::NeedsMigration) {
        return Ok(structure);
    }
    let config_path = path_to_vault.join(VAULTCONFIG_FILENAME);
    let masterkey_path = path_to_vault.join(MASTERKEY_FILENAME);
    if !config_path.exists() {
        restore_if_backup_present(path_to_vault, VAULTCONFIG_FILENAME);
    }
    if !masterkey_path.exists() {
        restore_if_backup_present(path_to_vault, MASTERKEY_FILENAME);
    }
    let has_config = config_path.exists();
    if !has_config && !masterkey_path.exists() {
        return Ok(VaultState::AllMissing);
    }
    if !has_config {
        return Ok(VaultState::VaultConfigMissing);
    }
    check_structure(path_to_vault)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::NotAVaultReason;
    use std::fs;

    const MASTERKEY_V7: &str = r#"{"version":7,"scryptSalt":"AAAAAAAAAAA=","scryptCostParam":2,"scryptBlockSize":1,"primaryMasterKey":"AA==","hmacMasterKey":"AA==","versionMac":"AA=="}"#;
    const MASTERKEY_V999: &str = r#"{"version":999,"scryptSalt":"AAAAAAAAAAA=","scryptCostParam":2,"scryptBlockSize":1,"primaryMasterKey":"AA==","hmacMasterKey":"AA==","versionMac":"AA=="}"#;
    const CONFIG_TOKEN: &str = "eyJraWQiOiJtYXN0ZXJrZXlmaWxlOm1hc3RlcmtleS5jcnlwdG9tYXRvciIsImFsZyI6IkhTMjU2IiwidHlwIjoiSldUIn0.eyJqdGkiOiI1YmMwMzg0Yi0xNGFjLTRmZGMtYWVkMC02MmU3YmMwOGZkNWEiLCJmb3JtYXQiOjgsImNpcGhlckNvbWJvIjoiU0lWX0dDTSIsInNob3J0ZW5pbmdUaHJlc2hvbGQiOjIyMH0.0DdfRRefLZici0eI0jDe6lS4sU7H8ZGp9eTqESy29Cg";

    fn fixture(name: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name)
    }

    #[test]
    fn fixture_vault_is_locked() {
        assert_eq!(
            check_dir_structure(&fixture("siv_gcm_basic")).unwrap(),
            DirStructure::Vault
        );
        assert_eq!(
            determine_vault_state(&fixture("siv_gcm_basic")).unwrap(),
            VaultState::Locked
        );
        assert!(assert_is_vault_directory(&fixture("siv_gcm_basic")).is_ok());
    }

    #[test]
    fn nonexistent_path_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            determine_vault_state(&dir.path().join("nope")).unwrap(),
            VaultState::Missing
        );
    }

    #[test]
    fn empty_directory_is_unrelated_and_all_missing() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            check_dir_structure(dir.path()).unwrap(),
            DirStructure::Unrelated
        );
        assert_eq!(
            determine_vault_state(dir.path()).unwrap(),
            VaultState::AllMissing
        );
        let err = assert_is_vault_directory(dir.path()).unwrap_err();
        assert!(matches!(
            err,
            CoreError::NotAVaultDirectory {
                reason: NotAVaultReason::MissingDataDir,
                ..
            }
        ));
    }

    #[test]
    fn file_instead_of_directory_is_not_a_directory_error() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file");
        fs::write(&file, b"x").unwrap();
        let err = check_dir_structure(&file).unwrap_err();
        assert!(
            matches!(err, CoreError::Io(ref e) if e.kind() == std::io::ErrorKind::NotADirectory)
        );
    }

    #[test]
    fn data_dir_but_no_config_reports_reason() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("d")).unwrap();
        let err = assert_is_vault_directory(dir.path()).unwrap_err();
        assert!(matches!(
            err,
            CoreError::NotAVaultDirectory {
                reason: NotAVaultReason::MissingVaultConfig,
                ..
            }
        ));
        fs::remove_dir(dir.path().join("d")).unwrap();
        fs::write(dir.path().join("d"), b"not a dir").unwrap();
        let err = assert_is_vault_directory(dir.path()).unwrap_err();
        assert!(matches!(
            err,
            CoreError::NotAVaultDirectory {
                reason: NotAVaultReason::DataNotADirectory,
                ..
            }
        ));
    }

    #[test]
    fn legacy_masterkey_without_config_needs_migration() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("d")).unwrap();
        fs::write(dir.path().join("masterkey.cryptomator"), MASTERKEY_V7).unwrap();
        assert_eq!(
            check_dir_structure(dir.path()).unwrap(),
            DirStructure::MaybeLegacy
        );
        assert_eq!(determine_vault_version(dir.path()).unwrap(), 7);
        assert!(needs_migration(dir.path()).unwrap());
        assert_eq!(
            determine_vault_state(dir.path()).unwrap(),
            VaultState::NeedsMigration
        );
    }

    #[test]
    fn format8_masterkey_without_config_is_vault_config_missing() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("d")).unwrap();
        fs::write(dir.path().join("masterkey.cryptomator"), MASTERKEY_V999).unwrap();
        assert_eq!(
            determine_vault_state(dir.path()).unwrap(),
            VaultState::VaultConfigMissing
        );
    }

    #[test]
    fn data_dir_without_any_key_file_is_all_missing() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("d")).unwrap();
        assert_eq!(
            determine_vault_state(dir.path()).unwrap(),
            VaultState::AllMissing
        );
    }

    #[test]
    fn newest_backup_is_restored_and_vault_becomes_locked() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("d")).unwrap();
        fs::write(dir.path().join("masterkey.cryptomator"), MASTERKEY_V999).unwrap();
        fs::write(dir.path().join("vault.cryptomator.OLDOLD01.bkup"), "old").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        fs::write(
            dir.path().join("vault.cryptomator.NEWNEW02.bkup"),
            CONFIG_TOKEN,
        )
        .unwrap();
        let restored = restore_if_backup_present(dir.path(), "vault.cryptomator").unwrap();
        assert!(restored.ends_with("vault.cryptomator.NEWNEW02.bkup"));
        assert_eq!(
            fs::read_to_string(dir.path().join("vault.cryptomator")).unwrap(),
            CONFIG_TOKEN
        );
        fs::remove_file(dir.path().join("vault.cryptomator")).unwrap();
        assert_eq!(
            determine_vault_state(dir.path()).unwrap(),
            VaultState::Locked
        );
        assert!(
            dir.path().join("vault.cryptomator").exists(),
            "determine_vault_state restores the config backup"
        );
    }

    #[test]
    fn restore_without_backups_is_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(restore_if_backup_present(dir.path(), "vault.cryptomator").is_none());
        assert!(
            restore_if_backup_present(&dir.path().join("missing"), "vault.cryptomator").is_none()
        );
    }

    #[test]
    fn state_names_match_java() {
        assert_eq!(VaultState::Locked.as_str(), "LOCKED");
        assert_eq!(
            VaultState::VaultConfigMissing.as_str(),
            "VAULT_CONFIG_MISSING"
        );
        assert_eq!(
            NotAVaultReason::UnsupportedStructure.as_str(),
            "UNSUPPORTED_STRUCTURE"
        );
    }
}
