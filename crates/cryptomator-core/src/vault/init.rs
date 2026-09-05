//! Vault creation: `CryptoFileSystemProvider.initialize` + the desktop app's
//! `CreateNewVaultPasswordController.createVault` (masterkey file, config, root dir, readme files).
use crate::constants::{
    CRYPTOMATOR_FILE_SUFFIX, DEFAULT_KEY_ID, DIR_ID_BACKUP_FILE_NAME, MASTERKEY_FILENAME,
    ROOT_DIR_ID, VAULTCONFIG_FILENAME,
};
use crate::crypto::cryptor::{CipherCombo, Cryptor};
use crate::crypto::masterkey::Masterkey;
use crate::crypto::rng::Rng;
use crate::crypto::stream::encrypt_all;
use crate::error::{CoreError, Result};
use crate::masterkey_file::{MasterkeyFileAccess, DEFAULT_MASTERKEY_FILE_VERSION};
use crate::vault::open::root_content_dir;
use crate::vault::readme::{
    access_location_readme_rtf, storage_location_readme_rtf, ACCESS_LOCATION_README_FILE_NAME,
    STORAGE_LOCATION_README_FILE_NAME,
};
use crate::vault_config::VaultConfig;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const MIN_SHORTENING_THRESHOLD: u32 = 36;
pub const MAX_SHORTENING_THRESHOLD: u32 = 220;
pub const DEFAULT_SHORTENING_THRESHOLD: u32 = 220;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateVaultOptions {
    pub cipher_combo: CipherCombo,
    pub shortening_threshold: u32,
    pub write_readme_files: bool,
}

impl Default for CreateVaultOptions {
    fn default() -> Self {
        Self {
            cipher_combo: CipherCombo::SivGcm,
            shortening_threshold: DEFAULT_SHORTENING_THRESHOLD,
            write_readme_files: true,
        }
    }
}

fn validate_threshold(shortening_threshold: u32) -> Result<()> {
    if !(MIN_SHORTENING_THRESHOLD..=MAX_SHORTENING_THRESHOLD).contains(&shortening_threshold) {
        return Err(CoreError::InvalidArgument(format!(
            "shortening threshold must be between {MIN_SHORTENING_THRESHOLD} and {MAX_SHORTENING_THRESHOLD}, got {shortening_threshold}"
        )));
    }
    Ok(())
}

/// The readme is written into the root directory as a regular (unshortened) file, so its
/// ciphertext name must fit the vault's shortening threshold. Checked before anything is created.
fn readme_name_fits(cryptor: &Cryptor, threshold: u32) -> Result<()> {
    let name = ACCESS_LOCATION_README_FILE_NAME;
    let len = cryptor
        .file_name_cryptor()
        .encrypt_filename(name, &[ROOT_DIR_ID.as_bytes()])
        .len()
        + CRYPTOMATOR_FILE_SUFFIX.len();
    if len > threshold as usize {
        return Err(CoreError::InvalidArgument(format!(
            "shortening threshold {threshold} is too small for the readme file {name:?} ({len} characters); use at least {len} or disable readme files"
        )));
    }
    Ok(())
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// `CryptoFileSystemProvider.initialize`: writes `vault.cryptomator`, creates the root content dir and its `dirid.c9r`.
pub fn initialize(
    vault_path: &Path,
    masterkey: &Masterkey,
    cipher_combo: CipherCombo,
    shortening_threshold: u32,
    key_id: &str,
    rng: &mut dyn Rng,
) -> Result<VaultConfig> {
    if !vault_path.is_dir() {
        return Err(CoreError::Io(std::io::Error::new(
            std::io::ErrorKind::NotADirectory,
            format!("{} is not a directory", vault_path.display()),
        )));
    }
    validate_threshold(shortening_threshold)?;
    let config = VaultConfig::create_new(cipher_combo, shortening_threshold);
    let token = config.to_token(key_id, masterkey.raw());
    write_new_file(&vault_path.join(VAULTCONFIG_FILENAME), token.as_bytes())?;
    let cryptor = Cryptor::new(cipher_combo, masterkey);
    let root = root_content_dir(vault_path, &cryptor);
    std::fs::create_dir_all(&root)?;
    let dir_id_backup = encrypt_all(&cryptor, rng, ROOT_DIR_ID.as_bytes())?;
    write_new_file(&root.join(DIR_ID_BACKUP_FILE_NAME), &dir_id_backup)?;
    Ok(config)
}

/// Writes one regular file into the vault's root directory (no `.c9s` shortening support; M3 adds the full fs layer).
pub fn write_root_file(
    vault_path: &Path,
    cryptor: &Cryptor,
    cleartext_name: &str,
    content: &[u8],
    shortening_threshold: u32,
    rng: &mut dyn Rng,
) -> Result<PathBuf> {
    let ciphertext_name = format!(
        "{}{CRYPTOMATOR_FILE_SUFFIX}",
        cryptor
            .file_name_cryptor()
            .encrypt_filename(cleartext_name, &[ROOT_DIR_ID.as_bytes()])
    );
    if ciphertext_name.len() > shortening_threshold as usize {
        return Err(CoreError::InvalidArgument(format!("ciphertext name of {cleartext_name:?} exceeds the shortening threshold {shortening_threshold}")));
    }
    let path = root_content_dir(vault_path, cryptor).join(ciphertext_name);
    let ciphertext = encrypt_all(cryptor, rng, content)?;
    write_new_file(&path, &ciphertext)?;
    Ok(path)
}

/// `CreateNewVaultPasswordController.createVault`: directory (must not exist) → masterkey file → config + root → readmes.
pub fn create_vault(
    vault_path: &Path,
    passphrase: &str,
    options: &CreateVaultOptions,
    access: &MasterkeyFileAccess,
    rng: &mut dyn Rng,
) -> Result<Masterkey> {
    validate_threshold(options.shortening_threshold)?;
    let masterkey = Masterkey::generate(rng);
    let readme_cryptor = if options.write_readme_files {
        let cryptor = Cryptor::new(options.cipher_combo, &masterkey);
        readme_name_fits(&cryptor, options.shortening_threshold)?;
        Some(cryptor)
    } else {
        None
    };
    std::fs::create_dir(vault_path)?;
    access.persist(
        &masterkey,
        &vault_path.join(MASTERKEY_FILENAME),
        passphrase,
        DEFAULT_MASTERKEY_FILE_VERSION,
        rng,
    )?;
    let config = initialize(
        vault_path,
        &masterkey,
        options.cipher_combo,
        options.shortening_threshold,
        DEFAULT_KEY_ID,
        rng,
    )?;
    if let Some(cryptor) = &readme_cryptor {
        write_root_file(
            vault_path,
            cryptor,
            ACCESS_LOCATION_README_FILE_NAME,
            access_location_readme_rtf().as_bytes(),
            config.shortening_threshold,
            rng,
        )?;
        write_new_file(
            &vault_path.join(STORAGE_LOCATION_README_FILE_NAME),
            storage_location_readme_rtf().as_bytes(),
        )?;
    }
    Ok(masterkey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rng::OsRng;
    use crate::crypto::stream::decrypt_all;
    use crate::vault::open::open_vault;
    use crate::vault::readme::{
        access_location_readme_rtf, storage_location_readme_rtf, ACCESS_LOCATION_README_FILE_NAME,
        STORAGE_LOCATION_README_FILE_NAME,
    };
    use std::fs;

    const PASSPHRASE: &str = "correct horse battery";

    #[test]
    fn creates_a_vault_that_opens_and_contains_the_readme() {
        for combo in [CipherCombo::SivGcm, CipherCombo::SivCtrMac] {
            let dir = tempfile::tempdir().unwrap();
            let vault = dir.path().join("vault");
            let access = MasterkeyFileAccess::new(Vec::new());
            let options = CreateVaultOptions {
                cipher_combo: combo,
                shortening_threshold: 100,
                write_readme_files: true,
            };
            let masterkey =
                create_vault(&vault, PASSPHRASE, &options, &access, &mut OsRng).unwrap();

            let opened = open_vault(&vault, &access, PASSPHRASE).unwrap();
            assert_eq!(opened.masterkey.raw(), masterkey.raw());
            assert_eq!(opened.config.cipher_combo, combo);
            assert_eq!(opened.config.shortening_threshold, 100);

            let root = root_content_dir(&vault, &opened.cryptor);
            let dirid = decrypt_all(
                &opened.cryptor,
                &fs::read(root.join(DIR_ID_BACKUP_FILE_NAME)).unwrap(),
            )
            .unwrap();
            assert_eq!(dirid, b"");

            let mut entries: Vec<String> = fs::read_dir(&root)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            entries.sort();
            assert_eq!(
                entries.len(),
                2,
                "{combo}: dirid.c9r + WELCOME.rtf, got {entries:?}"
            );
            let readme_entry = entries
                .iter()
                .find(|n| *n != DIR_ID_BACKUP_FILE_NAME)
                .unwrap();
            let base64 = readme_entry.strip_suffix(CRYPTOMATOR_FILE_SUFFIX).unwrap();
            assert_eq!(
                opened
                    .cryptor
                    .file_name_cryptor()
                    .decrypt_filename(base64, &[ROOT_DIR_ID.as_bytes()])
                    .unwrap(),
                ACCESS_LOCATION_README_FILE_NAME
            );
            let content =
                decrypt_all(&opened.cryptor, &fs::read(root.join(readme_entry)).unwrap()).unwrap();
            assert_eq!(
                String::from_utf8(content.to_vec()).unwrap(),
                access_location_readme_rtf()
            );

            assert_eq!(
                fs::read_to_string(vault.join(STORAGE_LOCATION_README_FILE_NAME)).unwrap(),
                storage_location_readme_rtf()
            );
            assert!(vault.join(MASTERKEY_FILENAME).is_file());
            assert!(vault.join(VAULTCONFIG_FILENAME).is_file());
        }
    }

    #[test]
    fn without_readmes_the_root_only_holds_the_dirid_backup() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault");
        let options = CreateVaultOptions {
            write_readme_files: false,
            ..CreateVaultOptions::default()
        };
        create_vault(
            &vault,
            PASSPHRASE,
            &options,
            &MasterkeyFileAccess::new(Vec::new()),
            &mut OsRng,
        )
        .unwrap();
        let opened = open_vault(&vault, &MasterkeyFileAccess::new(Vec::new()), PASSPHRASE).unwrap();
        let root = root_content_dir(&vault, &opened.cryptor);
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        assert!(!vault.join(STORAGE_LOCATION_README_FILE_NAME).exists());
    }

    #[test]
    fn existing_directory_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let err = create_vault(
            dir.path(),
            PASSPHRASE,
            &CreateVaultOptions::default(),
            &MasterkeyFileAccess::new(Vec::new()),
            &mut OsRng,
        )
        .unwrap_err();
        assert!(
            matches!(err, CoreError::Io(ref e) if e.kind() == std::io::ErrorKind::AlreadyExists)
        );
    }

    #[test]
    fn threshold_out_of_range_is_rejected_before_writing() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault");
        for threshold in [35, 221] {
            let options = CreateVaultOptions {
                shortening_threshold: threshold,
                ..CreateVaultOptions::default()
            };
            let err = create_vault(
                &vault,
                PASSPHRASE,
                &options,
                &MasterkeyFileAccess::new(Vec::new()),
                &mut OsRng,
            )
            .unwrap_err();
            assert!(matches!(err, CoreError::InvalidArgument(_)), "{threshold}");
            assert!(!vault.exists(), "{threshold}: nothing may be created");
        }
    }

    #[test]
    fn threshold_too_small_for_readme_leaves_nothing_behind() {
        let dir = tempfile::tempdir().unwrap();
        for threshold in [36, 39] {
            let vault = dir.path().join(format!("vault-{threshold}"));
            let options = CreateVaultOptions {
                shortening_threshold: threshold,
                ..CreateVaultOptions::default()
            };
            let err = create_vault(
                &vault,
                PASSPHRASE,
                &options,
                &MasterkeyFileAccess::new(Vec::new()),
                &mut OsRng,
            )
            .unwrap_err();
            assert!(matches!(err, CoreError::InvalidArgument(_)), "{threshold}");
            assert!(!vault.exists(), "{threshold}: nothing may be created");
        }

        let vault = dir.path().join("vault-40");
        let options = CreateVaultOptions {
            shortening_threshold: 40,
            ..CreateVaultOptions::default()
        };
        create_vault(
            &vault,
            PASSPHRASE,
            &options,
            &MasterkeyFileAccess::new(Vec::new()),
            &mut OsRng,
        )
        .unwrap();
        open_vault(&vault, &MasterkeyFileAccess::new(Vec::new()), PASSPHRASE).unwrap();
    }

    #[test]
    fn write_root_file_rejects_names_longer_than_the_threshold() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault");
        let options = CreateVaultOptions {
            shortening_threshold: 36,
            write_readme_files: false,
            ..CreateVaultOptions::default()
        };
        let masterkey = create_vault(
            &vault,
            PASSPHRASE,
            &options,
            &MasterkeyFileAccess::new(Vec::new()),
            &mut OsRng,
        )
        .unwrap();
        let cryptor = Cryptor::new(CipherCombo::SivGcm, &masterkey);
        let err = write_root_file(
            &vault,
            &cryptor,
            "a-name-that-is-long-enough.txt",
            b"x",
            36,
            &mut OsRng,
        )
        .unwrap_err();
        assert!(matches!(err, CoreError::InvalidArgument(_)));
    }
}
