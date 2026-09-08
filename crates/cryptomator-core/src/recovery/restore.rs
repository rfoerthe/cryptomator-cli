//! Rebuilding the two key files of a vault: `masterkey.cryptomator` from a recovery key,
//! `vault.cryptomator` from the masterkey, or both.
//!
//! Ported from the desktop app's `common/recovery/{RecoveryDirectory, MasterkeyService,
//! CryptoFsInitializer}.java` together with the three controllers that drive them:
//! `RecoveryKeyResetPasswordController.restorePassword` (RESTORE_ALL),
//! `RecoveryKeyResetPasswordController.ResetPasswordTask` (RESTORE_MASTERKEY) and
//! `RecoveryKeyCreationController.restoreWithPassword` (RESTORE_VAULT_CONFIG).
//!
//! Every restore writes into a [`RecoveryDirectory`] first and moves the finished files into the
//! vault only after they have been read back and validated, so a restore that fails half way --
//! a wrong recovery key, a full disk, an undetectable cipher combo -- never leaves the vault in a
//! worse state than it was in.
use crate::backup::attempt_backup;
use crate::constants::{
    CRYPTOMATOR_FILE_SUFFIX, DATA_DIR_NAME, DEFAULT_KEY_ID, DEFLATED_FILE_SUFFIX, DIR_FILE_NAME,
    DIR_ID_BACKUP_FILE_NAME, MASTERKEY_FILENAME, SYMLINK_FILE_NAME, VAULTCONFIG_FILENAME,
    VAULT_VERSION,
};
use crate::crypto::cryptor::{CipherCombo, Cryptor};
use crate::crypto::masterkey::Masterkey;
use crate::crypto::rng::{OsRng, Rng};
use crate::error::{CoreError, Result};
use crate::masterkey_file::{MasterkeyFileAccess, DEFAULT_MASTERKEY_FILE_VERSION};
use crate::recovery::key::decode_recovery_key;
use crate::recovery::words::WordEncoder;
use crate::vault::open::{open_vault, read_vault_config};
use crate::vault_config::VaultConfig;
use data_encoding::HEXLOWER;
use std::io::Read;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

/// How many names [`RecoveryDirectory::create`] tries before giving up on the random suffix.
const TEMP_DIR_ATTEMPTS: usize = 8;

/// What a restored `vault.cryptomator` says beyond the key that signs it.
///
/// One struct rather than two loose parameters, because both restores that write a config need
/// exactly this pair and `restore_all` would otherwise be eight arguments wide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigOptions {
    /// The vault's cipher combo, or `None` to read it from the vault's own files with
    /// [`detect_cipher_combo`] -- which is what Java's `restoreWithPassword` does.
    pub cipher_combo: Option<CipherCombo>,
    /// The `shorteningThreshold` claim of the new config. Nothing in the vault records the old
    /// one, so a restore cannot recover it: the caller either knows it or takes the default.
    pub shortening_threshold: u32,
}

impl Default for ConfigOptions {
    fn default() -> Self {
        Self {
            cipher_combo: None,
            shortening_threshold: crate::vault::init::DEFAULT_SHORTENING_THRESHOLD,
        }
    }
}

impl ConfigOptions {
    /// The combo to write: the given one, or the one detected from the vault.
    fn combo(&self, vault_path: &Path, masterkey: &Masterkey) -> Result<CipherCombo> {
        match self.cipher_combo {
            Some(combo) => Ok(combo),
            None => detect_cipher_combo(vault_path, masterkey),
        }
    }
}

/// A temporary directory the restored files are assembled in, deleted when it goes out of scope
/// (`common/recovery/RecoveryDirectory.java`; its `close()` is this type's [`Drop`]).
///
/// Java uses `Files.createTempDirectory("cryptomator")`. This one is hand-rolled on `std` plus the
/// OS random source rather than pulling a temp-directory crate into the core's runtime
/// dependencies: `$TMPDIR/crypto-restore-<pid>-<16 hex chars>`, created with `create` (so an
/// existing name is an error, never a hijack) and mode `0700`.
#[derive(Debug)]
pub struct RecoveryDirectory {
    vault_path: PathBuf,
    path: PathBuf,
}

impl RecoveryDirectory {
    /// Creates the directory. `vault_path` is remembered as the target of
    /// [`RecoveryDirectory::move_recovered_file`] and is not touched here.
    ///
    /// # Errors
    /// Whatever creating the directory reports, or an [`std::io::ErrorKind::AlreadyExists`] error
    /// after [`TEMP_DIR_ATTEMPTS`] names in a row were taken (which needs an adversary, not luck:
    /// the suffix is 64 bits from the OS random source).
    pub fn create(vault_path: &Path) -> Result<Self> {
        let base = std::env::temp_dir();
        let pid = std::process::id();
        let mut last = None;
        for _ in 0..TEMP_DIR_ATTEMPTS {
            let mut suffix = [0u8; 8];
            OsRng.fill(&mut suffix);
            let path = base.join(format!("crypto-restore-{pid}-{}", HEXLOWER.encode(&suffix)));
            match std::fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => {
                    return Ok(Self {
                        vault_path: vault_path.to_path_buf(),
                        path,
                    })
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => last = Some(e),
                Err(e) => return Err(e.into()),
            }
        }
        Err(CoreError::Io(last.unwrap_or_else(|| {
            std::io::Error::other("no recovery directory could be created")
        })))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Java's `moveRecoveredFile`: `Files.move(..., REPLACE_EXISTING)`.
    ///
    /// The temp directory usually lives on another file system than the vault, where `rename`
    /// fails with `EXDEV`; the fallback copies and then removes the source, which is the same
    /// thing `Files.move` does internally.
    ///
    /// # Errors
    /// Whatever the rename, the copy or the removal of the staged file reports.
    pub fn move_recovered_file(&self, file_name: &str) -> Result<()> {
        let from = self.path.join(file_name);
        let to = self.vault_path.join(file_name);
        if std::fs::rename(&from, &to).is_ok() {
            return Ok(());
        }
        std::fs::copy(&from, &to)?;
        std::fs::remove_file(&from)?;
        Ok(())
    }
}

impl Drop for RecoveryDirectory {
    fn drop(&mut self) {
        // Java logs and asks the user to remove it by hand; a failure here must not mask the
        // result of the restore itself.
        if let Err(e) = std::fs::remove_dir_all(&self.path) {
            log::info!(
                "unable to delete the recovery directory {}: {e}; please delete it manually",
                self.path.display()
            );
        }
    }
}

/// The first encrypted file below `d/` that a file header can be read from, or `None`.
///
/// Deterministic: every directory is read in sorted order, so the same vault always yields the
/// same candidate. `dir.c9r` holds a plain directory id and has no header at all; `symlink.c9r`
/// and `dirid.c9r` do have one, and Java's filter (`MasterkeyService.detect`) accepts them, but
/// this port skips them together with the `.c9s` subtrees so that detection only ever succeeds on
/// a file the *user* put into the vault. The cost is that a vault holding nothing but directories
/// and symlinks reports [`CoreError::CipherComboUndetectable`] where Java would still answer;
/// `--cipher-combo` is then the way out.
///
/// Symlinks are not followed (`DirEntry::file_type` does not traverse them), so a vault whose
/// ciphertext contains a link cannot send the walk into a loop or outside the vault.
fn first_encrypted_file(dir: &Path) -> Option<PathBuf> {
    let mut entries: Vec<_> = std::fs::read_dir(dir).ok()?.flatten().collect();
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if file_type.is_dir() {
            if name.ends_with(DEFLATED_FILE_SUFFIX) {
                continue;
            }
            if let Some(found) = first_encrypted_file(&entry.path()) {
                return Some(found);
            }
        } else if file_type.is_file()
            && name.ends_with(CRYPTOMATOR_FILE_SUFFIX)
            && name != DIR_FILE_NAME
            && name != SYMLINK_FILE_NAME
            && name != DIR_ID_BACKUP_FILE_NAME
        {
            return Some(entry.path());
        }
    }
    None
}

/// Which cipher combo the vault's files were written with (`MasterkeyService.detect` plus
/// `determineScheme`).
///
/// The first candidate file below `d/` (see [`first_encrypted_file`]) is opened once per scheme
/// and its file header decrypted; the first scheme that succeeds wins. The order is the one of
/// Java's `CryptorProvider.Scheme.values()`, i.e. [`CipherCombo::ALL`]: `SIV_CTRMAC` before
/// `SIV_GCM`. Like Java, only the *first* candidate is tried -- a vault whose first file is
/// damaged is undetectable rather than searched through.
///
/// # Errors
/// [`CoreError::CipherComboUndetectable`] when there is no candidate file or neither scheme
/// decrypts its header -- which is also what a masterkey belonging to a different vault looks
/// like.
pub fn detect_cipher_combo(vault_path: &Path, masterkey: &Masterkey) -> Result<CipherCombo> {
    let undetectable = || CoreError::CipherComboUndetectable(vault_path.to_path_buf());
    let candidate =
        first_encrypted_file(&vault_path.join(DATA_DIR_NAME)).ok_or_else(undetectable)?;
    for combo in CipherCombo::ALL {
        let cryptor = Cryptor::new(combo, masterkey);
        let header_cryptor = cryptor.file_header_cryptor();
        let mut buf = vec![0u8; header_cryptor.header_size()];
        let Ok(mut file) = std::fs::File::open(&candidate) else {
            break;
        };
        // A file shorter than the header of this scheme cannot have been written by it.
        if file.read_exact(&mut buf).is_err() {
            continue;
        }
        if header_cryptor.decrypt_header(&buf).is_ok() {
            log::debug!("detected cipher combo {combo} from {}", candidate.display());
            return Ok(combo);
        }
    }
    Err(undetectable())
}

/// Reads the staged masterkey file back and checks that it really holds `expected`.
fn assert_staged_masterkey(
    access: &MasterkeyFileAccess,
    staged: &Path,
    passphrase: &str,
    expected: &Masterkey,
) -> Result<()> {
    let reloaded = access.load(staged, passphrase)?;
    if reloaded.raw() != expected.raw() {
        return Err(CoreError::InvalidMasterkeyFile(
            "the restored masterkey file does not hold the recovered key".to_string(),
        ));
    }
    Ok(())
}

/// RESTORE_MASTERKEY (`ResetPasswordTask.call` →
/// `RecoveryKeyFactory.newMasterkeyFileWithPassphrase`): a recovery key and a **new** password
/// become a fresh `masterkey.cryptomator`.
///
/// The file name is hard-wired, exactly as it is in Java. Unlike
/// [`crate::recovery::key::reset_password`] this must **not** read `vault.cryptomator` to learn
/// the name from the `kid` claim: the config is one of the files a restore may be here to
/// rebuild, so it need not exist. Do not merge the two functions for that reason.
///
/// An existing masterkey file is copied to a `.bkup` first ([`attempt_backup`]) and is only
/// replaced once the staged file has been read back with the new password.
///
/// # Errors
/// [`CoreError::InvalidRecoveryKey`] for a key that does not decode -- reported before anything at
/// all is written -- and whatever wrapping, reading back or moving the file reports.
pub fn restore_masterkey(
    encoder: &WordEncoder,
    access: &MasterkeyFileAccess,
    vault_path: &Path,
    recovery_key: &str,
    new_passphrase: &str,
    rng: &mut dyn Rng,
) -> Result<()> {
    let raw = decode_recovery_key(encoder, recovery_key)?;
    let masterkey = Masterkey::from_raw(*raw);
    let dir = RecoveryDirectory::create(vault_path)?;
    let staged = dir.path().join(MASTERKEY_FILENAME);
    access.persist(
        &masterkey,
        &staged,
        new_passphrase,
        DEFAULT_MASTERKEY_FILE_VERSION,
        rng,
    )?;
    assert_staged_masterkey(access, &staged, new_passphrase, &masterkey)?;
    let target = vault_path.join(MASTERKEY_FILENAME);
    if target.exists() {
        attempt_backup(&target)?;
    }
    dir.move_recovered_file(MASTERKEY_FILENAME)?;
    Ok(())
}

/// RESTORE_VAULT_CONFIG (`RecoveryKeyCreationController.restoreWithPassword`): the vault's own
/// masterkey file and the **vault password** become a fresh `vault.cryptomator`.
///
/// No recovery key is involved -- the key that signs the new config is the one already in
/// `masterkey.cryptomator`. [`ConfigOptions::cipher_combo`] overrides [`detect_cipher_combo`];
/// `None` means "read it from the vault", which is what Java does here.
///
/// # Errors
/// [`CoreError::InvalidPassphrase`] for a wrong password, [`CoreError::CipherComboUndetectable`]
/// when the combo can neither be given nor detected, and whatever writing the config reports.
pub fn restore_config(
    access: &MasterkeyFileAccess,
    vault_path: &Path,
    passphrase: &str,
    options: ConfigOptions,
    rng: &mut dyn Rng,
) -> Result<VaultConfig> {
    let masterkey = access.load(&vault_path.join(MASTERKEY_FILENAME), passphrase)?;
    let combo = options.combo(vault_path, &masterkey)?;
    write_config_via_recovery_dir(
        vault_path,
        &masterkey,
        combo,
        options.shortening_threshold,
        rng,
    )
}

/// `CryptoFsInitializer.init` into a [`RecoveryDirectory`], then the move.
///
/// [`crate::vault::init::initialize`] writes the config *and* creates the root content directory
/// with its `dirid.c9r`, exactly as `CryptoFileSystemProvider.initialize` does. Only the config is
/// taken over; the root directory in the temp dir is throw-away, the vault's real one is already
/// where it belongs.
fn write_config_via_recovery_dir(
    vault_path: &Path,
    masterkey: &Masterkey,
    combo: CipherCombo,
    shortening_threshold: u32,
    rng: &mut dyn Rng,
) -> Result<VaultConfig> {
    let dir = RecoveryDirectory::create(vault_path)?;
    let config = crate::vault::init::initialize(
        dir.path(),
        masterkey,
        combo,
        shortening_threshold,
        DEFAULT_KEY_ID,
        rng,
    )?;
    // The staged token must verify against the key that signed it before the vault's own config
    // is replaced by it.
    read_vault_config(dir.path())?.verify(masterkey.raw(), VAULT_VERSION)?;
    let target = vault_path.join(VAULTCONFIG_FILENAME);
    if target.exists() {
        attempt_backup(&target)?;
    }
    dir.move_recovered_file(VAULTCONFIG_FILENAME)?;
    Ok(config)
}

/// RESTORE_ALL (`RecoveryKeyResetPasswordController.restorePassword`): a recovery key and a
/// **new** password become both `masterkey.cryptomator` and `vault.cryptomator`.
///
/// The cipher combo is detected from the vault's own files before anything is written (Java takes
/// it from an expert-settings dialog instead); [`ConfigOptions::cipher_combo`] overrides that.
///
/// Both files are assembled in a [`RecoveryDirectory`] and the whole thing is opened from there
/// with the new password -- config signature, masterkey and root content directory -- before
/// either of them is moved into the vault.
///
/// # Errors
/// [`CoreError::InvalidRecoveryKey`], [`CoreError::CipherComboUndetectable`] (both before a single
/// byte is written) and whatever writing, opening or moving the two files reports.
pub fn restore_all(
    encoder: &WordEncoder,
    access: &MasterkeyFileAccess,
    vault_path: &Path,
    recovery_key: &str,
    new_passphrase: &str,
    options: ConfigOptions,
    rng: &mut dyn Rng,
) -> Result<VaultConfig> {
    let raw = decode_recovery_key(encoder, recovery_key)?;
    let masterkey = Masterkey::from_raw(*raw);
    // The detection needs the key but no written file, so it happens here -- before anything
    // touches the vault.
    let combo = options.combo(vault_path, &masterkey)?;
    let dir = RecoveryDirectory::create(vault_path)?;
    let staged_masterkey = dir.path().join(MASTERKEY_FILENAME);
    access.persist(
        &masterkey,
        &staged_masterkey,
        new_passphrase,
        DEFAULT_MASTERKEY_FILE_VERSION,
        rng,
    )?;
    let config = crate::vault::init::initialize(
        dir.path(),
        &masterkey,
        combo,
        options.shortening_threshold,
        DEFAULT_KEY_ID,
        rng,
    )?;
    // The staged pair has to be a vault that opens: `open_vault` verifies the config signature
    // against the key it just unwrapped from the staged masterkey file and finds the root content
    // directory `initialize` created next to them. (It also writes .bkup copies of both, which
    // stay in the temp directory and are deleted with it.)
    let opened = open_vault(dir.path(), access, new_passphrase)?;
    if opened.masterkey.raw() != masterkey.raw() {
        return Err(CoreError::InvalidMasterkeyFile(
            "the restored masterkey file does not hold the recovered key".to_string(),
        ));
    }
    drop(opened);
    for name in [MASTERKEY_FILENAME, VAULTCONFIG_FILENAME] {
        let target = vault_path.join(name);
        if target.exists() {
            attempt_backup(&target)?;
        }
        dir.move_recovered_file(name)?;
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rng::DetRng;
    use crate::vault::init::create_vault;
    use crate::vault::init::CreateVaultOptions;

    fn vault_with(combo: CipherCombo) -> (tempfile::TempDir, PathBuf, Masterkey) {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("v");
        let options = CreateVaultOptions {
            cipher_combo: combo,
            ..CreateVaultOptions::default()
        };
        let masterkey = create_vault(
            &vault,
            "vault-passphrase",
            &options,
            &MasterkeyFileAccess::new(Vec::new()),
            &mut DetRng::default(),
        )
        .unwrap();
        (dir, vault, masterkey)
    }

    #[test]
    fn a_recovery_directory_is_private_and_gone_after_its_scope() {
        let vault = tempfile::tempdir().unwrap();
        let path = {
            let dir = RecoveryDirectory::create(vault.path()).unwrap();
            let path = dir.path().to_path_buf();
            assert!(path.is_dir());
            assert!(path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("crypto-restore-"));
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                    0o700
                );
            }
            // A non-empty directory must go too: `remove_dir` alone would leave it behind.
            std::fs::write(path.join("masterkey.cryptomator"), b"staged").unwrap();
            std::fs::create_dir(path.join("d")).unwrap();
            path
        };
        assert!(!path.exists(), "the recovery directory survived its scope");
    }

    #[test]
    fn two_recovery_directories_do_not_collide() {
        let vault = tempfile::tempdir().unwrap();
        let first = RecoveryDirectory::create(vault.path()).unwrap();
        let second = RecoveryDirectory::create(vault.path()).unwrap();
        assert_ne!(first.path(), second.path());
    }

    #[test]
    fn moving_a_recovered_file_replaces_the_one_in_the_vault() {
        let tmp = tempfile::tempdir().unwrap();
        let vault = tmp.path().join("v");
        std::fs::create_dir(&vault).unwrap();
        std::fs::write(vault.join(MASTERKEY_FILENAME), b"old").unwrap();
        let dir = RecoveryDirectory::create(&vault).unwrap();
        std::fs::write(dir.path().join(MASTERKEY_FILENAME), b"new").unwrap();
        dir.move_recovered_file(MASTERKEY_FILENAME).unwrap();
        assert_eq!(
            std::fs::read(vault.join(MASTERKEY_FILENAME)).unwrap(),
            b"new"
        );
        assert!(!dir.path().join(MASTERKEY_FILENAME).exists());
    }

    #[test]
    fn both_schemes_are_detected_from_a_vault_written_with_them() {
        for combo in CipherCombo::ALL {
            let (_tmp, vault, masterkey) = vault_with(combo);
            assert_eq!(
                detect_cipher_combo(&vault, &masterkey).unwrap(),
                combo,
                "{combo}"
            );
        }
    }

    #[test]
    fn a_vault_without_regular_files_has_no_detectable_combo() {
        let (_tmp, vault, masterkey) = vault_with(CipherCombo::SivGcm);
        // Leave the root directory and its `dirid.c9r` in place and remove only the WELCOME.rtf:
        // the detection deliberately does not read the backup file.
        let root = crate::vault::open::root_content_dir(
            &vault,
            &Cryptor::new(CipherCombo::SivGcm, &masterkey),
        );
        for entry in std::fs::read_dir(&root).unwrap().flatten() {
            if entry.file_name() != DIR_ID_BACKUP_FILE_NAME {
                std::fs::remove_file(entry.path()).unwrap();
            }
        }
        assert!(matches!(
            detect_cipher_combo(&vault, &masterkey),
            Err(CoreError::CipherComboUndetectable(path)) if path == vault
        ));
    }

    #[test]
    fn a_foreign_masterkey_detects_nothing() {
        let (_tmp, vault, _masterkey) = vault_with(CipherCombo::SivGcm);
        let foreign = Masterkey::from_raw([7u8; 64]);
        assert!(matches!(
            detect_cipher_combo(&vault, &foreign),
            Err(CoreError::CipherComboUndetectable(_))
        ));
    }
}
