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
use crate::migration::v7::OLD_METADATA_DIR_NAME;
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
    /// The combo to write: the given one -- checked against the vault -- or the one detected from
    /// it.
    ///
    /// A given combo is *not* taken on trust: a typo would write a config the vault cannot be
    /// opened with, and nothing afterwards would say so (the old config is backed up, but the
    /// vault is broken until somebody finds that out). So the vault is asked as well whenever it
    /// can answer, and a disagreement is [`CoreError::CipherComboMismatch`]. The flag stays
    /// authoritative exactly where it is the only source: a vault
    /// [`detect_cipher_combo`] finds nothing to read the combo from -- which is what the flag
    /// exists for.
    ///
    /// # Errors
    /// [`CoreError::CipherComboMismatch`] for a given combo the vault contradicts,
    /// [`CoreError::CipherComboUndetectable`] when none was given and none can be read, and
    /// whatever reading the candidate file reports.
    fn combo(&self, vault_path: &Path, masterkey: &Masterkey) -> Result<CipherCombo> {
        let Some(given) = self.cipher_combo else {
            return detect_cipher_combo(vault_path, masterkey);
        };
        match detect_cipher_combo(vault_path, masterkey) {
            Ok(detected) if detected != given => {
                Err(CoreError::CipherComboMismatch { given, detected })
            }
            Ok(_) => Ok(given),
            // Nothing in the vault to check against -- or a masterkey that does not belong to it,
            // which looks the same from here and is caught by the callers that can tell.
            Err(CoreError::CipherComboUndetectable(_)) => Ok(given),
            Err(other) => Err(other),
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
    /// The temp directory often lives on another file system than the vault (`$TMPDIR` is tmpfs on
    /// most Linux systems), where `rename` fails with `EXDEV`; [`copy_then_rename`] then does the
    /// same thing `Files.move` does internally -- but through a temporary file *inside the vault*,
    /// so the file the vault already has is replaced by one `rename`, never truncated and rewritten
    /// in place. Every other `rename` failure is returned as it came: only `EXDEV` says "try the
    /// other way round", and a permission or read-only error must not be retried as a copy.
    ///
    /// # Errors
    /// Whatever the rename, the copy or the removal of the staged file reports.
    pub fn move_recovered_file(&self, file_name: &str) -> Result<()> {
        let from = self.path.join(file_name);
        let to = self.vault_path.join(file_name);
        match std::fs::rename(&from, &to) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::CrossesDevices => {
                copy_then_rename(&from, &to)
            }
            Err(e) => Err(e.into()),
        }
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

/// The suffix of the in-vault staging file [`copy_then_rename`] writes.
const RESTORE_TMP_SUFFIX: &str = ".restore-tmp";

/// The cross-device half of [`RecoveryDirectory::move_recovered_file`]: copy `from` to
/// `<to>.restore-tmp` -- which is next to `to` and therefore on `to`'s own file system -- and
/// `rename` that over `to`.
///
/// A plain `fs::copy` onto `to` truncates the vault's live key file and fills it again: a crash or
/// a full disk half way through leaves a truncated file, and `restore_if_backup_present` does not
/// rescue that (it only replaces files that are *missing*). Through the staging file the vault
/// either still has its old file or has the whole new one.
///
/// The staging file is removed again when the copy or the rename fails, so a failed restore leaves
/// nothing behind; that removal is best effort, because the error worth reporting is the first one.
///
/// # Errors
/// Whatever the copy, the rename or the removal of the source reports.
fn copy_then_rename(from: &Path, to: &Path) -> Result<()> {
    let mut staged = to.as_os_str().to_os_string();
    staged.push(RESTORE_TMP_SUFFIX);
    let staged = PathBuf::from(staged);
    if let Err(e) = std::fs::copy(from, &staged) {
        let _ = std::fs::remove_file(&staged);
        return Err(e.into());
    }
    if let Err(e) = std::fs::rename(&staged, to) {
        let _ = std::fs::remove_file(&staged);
        return Err(e.into());
    }
    std::fs::remove_file(from)?;
    Ok(())
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
/// The first candidate file below `d/` (see [`first_encrypted_file`]) is opened **once**, the
/// longest header any scheme could have is read from it, and every scheme is tried on those bytes;
/// the first that decrypts wins. The order is the one of Java's `CryptorProvider.Scheme.values()`,
/// i.e. [`CipherCombo::ALL`]: `SIV_CTRMAC` before `SIV_GCM`. Like Java, only the *first* candidate
/// is tried -- a vault whose first file is damaged is undetectable rather than searched through.
///
/// A candidate that cannot be opened or read is an I/O error, not "undetectable": the difference
/// between "this vault says nothing about its combo" (which `--cipher-combo` answers) and "this
/// vault could not be read" (which it does not) is one the caller has to see.
///
/// # Errors
/// [`CoreError::CipherComboUndetectable`] when there is no candidate file or neither scheme
/// decrypts its header -- which is also what a masterkey belonging to a different vault looks
/// like -- and [`CoreError::Io`] when the candidate cannot be read.
pub fn detect_cipher_combo(vault_path: &Path, masterkey: &Masterkey) -> Result<CipherCombo> {
    let undetectable = || CoreError::CipherComboUndetectable(vault_path.to_path_buf());
    let candidate =
        first_encrypted_file(&vault_path.join(DATA_DIR_NAME)).ok_or_else(undetectable)?;
    let cryptors: Vec<_> = CipherCombo::ALL
        .into_iter()
        .map(|combo| (combo, Cryptor::new(combo, masterkey)))
        .collect();
    let longest = cryptors
        .iter()
        .map(|(_, cryptor)| cryptor.file_header_cryptor().header_size())
        .fold(0usize, usize::max);
    // Only the header is read, never the file: a candidate may be gigabytes long.
    let mut head = Vec::with_capacity(longest);
    std::fs::File::open(&candidate)?
        .take(longest as u64)
        .read_to_end(&mut head)?;
    for (combo, cryptor) in &cryptors {
        let header_cryptor = cryptor.file_header_cryptor();
        // A file shorter than the header of this scheme cannot have been written by it.
        let Some(header) = head.get(..header_cryptor.header_size()) else {
            continue;
        };
        if header_cryptor.decrypt_header(header).is_ok() {
            log::debug!("detected cipher combo {combo} from {}", candidate.display());
            return Ok(*combo);
        }
    }
    Err(undetectable())
}

/// Refuses a restore into a vault that still has the format 5/6 layout, before anything is
/// written.
///
/// The tell is `<vault>/m`, the metadata directory of the long names, which only formats 5 and 6
/// have (7 and 8 keep the inflated name inside the node, so stamping a format 8 config onto a
/// format 7 vault is right and is left alone here).
///
/// Without this check a legacy vault that lost **both** key files -- state `ALL_MISSING`, which
/// `crypto recovery-key restore` accepts -- would be given a `format: 8` config and a masterkey
/// file claiming version 999. `determine_vault_version` would then answer 8, `crypto migrate`
/// would refuse it as "already migrated", and nothing would ever rename the BASE32 names below
/// `d/` again: the vault would be unopenable by any Cryptomator. Migrating first and restoring
/// afterwards is the only order that works, and the migration needs the passphrase, not the
/// recovery key.
fn assert_not_legacy_layout(vault_path: &Path) -> Result<()> {
    if vault_path.join(OLD_METADATA_DIR_NAME).is_dir() {
        return Err(CoreError::MigrationBlocked(format!(
            "{} still has the format 5/6 layout (its `{OLD_METADATA_DIR_NAME}` directory is \
             there); restoring would stamp a format {VAULT_VERSION} config onto it and no \
             Cryptomator would open it again -- migrate it first",
            vault_path.display()
        )));
    }
    Ok(())
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
    // Not only `restore_all`/`restore_config`: the file this writes carries version 999, which is
    // what `determine_vault_version` reads when there is no config -- so stamping it onto a format
    // 5/6 vault mislabels that vault as format 8 just as thoroughly. See
    // [`assert_not_legacy_layout`].
    assert_not_legacy_layout(vault_path)?;
    let raw = decode_recovery_key(encoder, recovery_key)?;
    let masterkey = Masterkey::from_zeroizing(raw);
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
    assert_not_legacy_layout(vault_path)?;
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
    assert_not_legacy_layout(vault_path)?;
    let raw = decode_recovery_key(encoder, recovery_key)?;
    let masterkey = Masterkey::from_zeroizing(raw);
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
    // The config **first**, the masterkey second. The two moves are not one transaction, and the
    // order decides what a failure between them leaves behind:
    //
    // * config, then masterkey (this order): a new config next to the *old* masterkey file. The
    //   config is signed with the recovered key, which is the key the new masterkey file would
    //   have held, so `restore --masterkey` with the same recovery key finishes the job -- and
    //   until then nothing was lost, because the old masterkey file is still there and still
    //   backed up as `masterkey.cryptomator.<checksum>.bkup`.
    // * masterkey, then config (the other order): a new masterkey file, wrapping the recovered
    //   key under the *new* password, next to a config signed by the *old* key. Neither password
    //   opens that vault, and repairing it needs `restore --config`, i.e. the new password plus
    //   the knowledge that this is what happened.
    for name in [VAULTCONFIG_FILENAME, MASTERKEY_FILENAME] {
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

    /// `tests/fixtures/<name>` copied into a fresh temp directory, which the caller keeps alive.
    fn fixture_copy(name: &str) -> (tempfile::TempDir, PathBuf) {
        fn copy(src: &Path, dst: &Path) {
            std::fs::create_dir_all(dst).unwrap();
            for entry in std::fs::read_dir(src).unwrap().flatten() {
                let target = dst.join(entry.file_name());
                if entry.file_type().unwrap().is_dir() {
                    copy(&entry.path(), &target);
                } else {
                    std::fs::copy(entry.path(), &target).unwrap();
                }
            }
        }
        let tmp = tempfile::tempdir().unwrap();
        let vault = tmp.path().join(name);
        copy(
            &Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures")
                .join(name),
            &vault,
        );
        (tmp, vault)
    }

    /// A vault that still has the format 5/6 layout must not be given format 8 key files: the
    /// names below `d/` are BASE32 and only `crypto migrate` can rewrite them.
    #[test]
    fn a_vault_with_a_metadata_directory_is_refused_before_anything_is_written() {
        let (_tmp, vault) = fixture_copy("legacy_v6");
        assert!(vault.join("m").is_dir(), "the tell of formats 5 and 6");
        let access = MasterkeyFileAccess::new(Vec::new());
        let encoder = WordEncoder::new();
        // A well-formed key for a vault of our own: the refusal comes before it is looked at.
        let (_other_tmp, _other, masterkey) = vault_with(CipherCombo::SivGcm);
        let key = crate::recovery::key::create_recovery_key(&encoder, masterkey.raw());

        for outcome in [
            restore_all(
                &encoder,
                &access,
                &vault,
                key.as_str(),
                "new-passphrase",
                ConfigOptions::default(),
                &mut DetRng::default(),
            )
            .map(|_| ()),
            restore_masterkey(
                &encoder,
                &access,
                &vault,
                key.as_str(),
                "new-passphrase",
                &mut DetRng::default(),
            ),
            restore_config(
                &access,
                &vault,
                "test-password-123",
                ConfigOptions::default(),
                &mut DetRng::default(),
            )
            .map(|_| ()),
        ] {
            let err = outcome.expect_err("a legacy layout is refused");
            assert!(
                matches!(&err, CoreError::MigrationBlocked(m) if m.contains("format 5/6 layout")),
                "{err}"
            );
        }
        // And nothing moved: the fixture's own masterkey file is untouched and no config appeared.
        assert!(!vault.join(VAULTCONFIG_FILENAME).exists());
        assert!(!vault.join("masterkey.cryptomator.bkup").exists());
    }

    /// Formats 7 and 8 share the on-disk layout, so a format 7 vault has no `m/` and stamping a
    /// format 8 config onto it is exactly right -- the restore is the 7 → 8 step with new key
    /// files. The vault opens afterwards.
    #[test]
    fn a_format_seven_vault_is_restored_because_it_shares_the_layout() {
        let (_tmp, vault) = fixture_copy("legacy_v7");
        assert!(!vault.join("m").exists(), "format 7 has no metadata dir");
        let access = MasterkeyFileAccess::new(Vec::new());
        let encoder = WordEncoder::new();
        let masterkey = access
            .load(&vault.join(MASTERKEY_FILENAME), "test-password-123")
            .expect("the fixture's passphrase");
        let key = crate::recovery::key::create_recovery_key(&encoder, masterkey.raw());

        let config = restore_all(
            &encoder,
            &access,
            &vault,
            key.as_str(),
            "new-passphrase",
            ConfigOptions::default(),
            &mut DetRng::default(),
        )
        .expect("a format 7 vault can be restored");
        assert_eq!(config.cipher_combo, CipherCombo::SivCtrMac);
        let opened = open_vault(&vault, &access, "new-passphrase").expect("the vault opens");
        assert_eq!(opened.masterkey.raw(), masterkey.raw());
    }

    /// `restore_all` moves the config first, so the one repairable half-state is the one a
    /// failure between the two moves leaves behind.
    ///
    /// The masterkey move is made to fail by turning the vault's own masterkey file into a
    /// directory: `attempt_backup` reads it and reports `EISDIR`. The config is by then already
    /// in place -- which is exactly the state `restore --masterkey` finishes off.
    #[test]
    fn the_config_is_moved_before_the_masterkey_so_a_half_state_is_repairable() {
        let (_tmp, vault, _masterkey) = vault_with(CipherCombo::SivGcm);
        let access = MasterkeyFileAccess::new(Vec::new());
        let encoder = WordEncoder::new();
        let (_other, _other_vault, other_key) = vault_with(CipherCombo::SivGcm);
        let key = crate::recovery::key::create_recovery_key(&encoder, other_key.raw());
        std::fs::remove_file(vault.join(MASTERKEY_FILENAME)).unwrap();
        std::fs::create_dir(vault.join(MASTERKEY_FILENAME)).unwrap();
        let config_before = std::fs::read(vault.join(VAULTCONFIG_FILENAME)).unwrap();

        let err = restore_all(
            &encoder,
            &access,
            &vault,
            key.as_str(),
            "new-passphrase",
            ConfigOptions {
                // The vault holds no encrypted file, and the key is a foreign one anyway.
                cipher_combo: Some(CipherCombo::SivGcm),
                ..ConfigOptions::default()
            },
            &mut DetRng::default(),
        )
        .expect_err("the masterkey cannot be backed up over a directory");
        assert!(matches!(err, CoreError::Io(_)), "{err}");

        assert_ne!(
            std::fs::read(vault.join(VAULTCONFIG_FILENAME)).unwrap(),
            config_before,
            "the config was moved before the masterkey"
        );
        assert!(
            vault.join(MASTERKEY_FILENAME).is_dir(),
            "the masterkey move never happened"
        );
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

    /// A directory on a file system other than the one `path` sits on, or `None`.
    ///
    /// Linux has `/dev/shm` (tmpfs) next to a disk-backed repository; on macOS `$TMPDIR` and the
    /// working copy share one APFS volume, so there is nothing to return and the cross-device half
    /// of the test below is skipped. [`copy_then_rename`] is still exercised there -- it is called
    /// directly, not reached through an `EXDEV` that never happens.
    fn dir_on_another_filesystem(path: &Path) -> Option<PathBuf> {
        use std::os::unix::fs::MetadataExt;
        let here = std::fs::metadata(path).ok()?.dev();
        ["/dev/shm", "/run/shm"]
            .into_iter()
            .map(Path::new)
            .find(|candidate| {
                std::fs::metadata(candidate).is_ok_and(|m| m.is_dir() && m.dev() != here)
            })
            .map(Path::to_path_buf)
    }

    #[test]
    fn the_cross_device_fallback_replaces_the_target_and_leaves_no_staging_file() {
        let tmp = tempfile::tempdir().unwrap();
        let vault = tmp.path().join("v");
        std::fs::create_dir(&vault).unwrap();
        let target = vault.join(MASTERKEY_FILENAME);

        let mut sources = vec![tmp.path().join("same-fs")];
        // The branch this helper exists for: a staged file that `rename` cannot move.
        if let Some(other) = dir_on_another_filesystem(&vault) {
            sources.push(other.join(format!("crypto-restore-test-{}", std::process::id())));
        }
        for source_dir in &sources {
            std::fs::create_dir(source_dir).unwrap();
            let from = source_dir.join(MASTERKEY_FILENAME);
            std::fs::write(&from, b"new").unwrap();
            std::fs::write(&target, b"old").unwrap();

            copy_then_rename(&from, &target).unwrap();

            assert_eq!(std::fs::read(&target).unwrap(), b"new");
            assert!(!from.exists(), "the staged file was not removed");
            assert!(
                !vault
                    .join(format!("{MASTERKEY_FILENAME}{RESTORE_TMP_SUFFIX}"))
                    .exists(),
                "the in-vault staging file was left behind"
            );
            std::fs::remove_dir_all(source_dir).unwrap();
        }
    }

    #[test]
    fn a_rename_failure_that_is_not_cross_device_is_reported_rather_than_copied_around() {
        // The vault directory does not exist, so the rename fails with `NotFound` -- which must
        // reach the caller instead of being retried as a copy into the same missing directory.
        let tmp = tempfile::tempdir().unwrap();
        let dir = RecoveryDirectory::create(&tmp.path().join("gone")).unwrap();
        std::fs::write(dir.path().join(MASTERKEY_FILENAME), b"new").unwrap();
        match dir.move_recovered_file(MASTERKEY_FILENAME) {
            Err(CoreError::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound),
            other => panic!("expected a NotFound I/O error, got {other:?}"),
        }
        assert!(
            dir.path().join(MASTERKEY_FILENAME).is_file(),
            "a failed move must leave the staged file where it was"
        );
    }

    #[test]
    fn an_explicit_cipher_combo_is_checked_against_the_vault() {
        let (_tmp, vault, masterkey) = vault_with(CipherCombo::SivGcm);
        let options = |combo| ConfigOptions {
            cipher_combo: Some(combo),
            ..ConfigOptions::default()
        };
        // The one the vault agrees with passes through …
        assert_eq!(
            options(CipherCombo::SivGcm)
                .combo(&vault, &masterkey)
                .unwrap(),
            CipherCombo::SivGcm
        );
        // … and the other one is refused, naming what the vault actually holds.
        match options(CipherCombo::SivCtrMac).combo(&vault, &masterkey) {
            Err(CoreError::CipherComboMismatch { given, detected }) => {
                assert_eq!(given, CipherCombo::SivCtrMac);
                assert_eq!(detected, CipherCombo::SivGcm);
            }
            other => panic!("expected a mismatch, got {other:?}"),
        }
    }

    #[test]
    fn a_given_cipher_combo_stands_when_the_vault_says_nothing() {
        let (_tmp, vault, masterkey) = vault_with(CipherCombo::SivGcm);
        remove_regular_files(&vault, &masterkey, CipherCombo::SivGcm);
        // Nothing to check against, so the flag is the only source -- and is taken, even for the
        // combo the (now unreadable) vault was written with the other way round.
        for combo in CipherCombo::ALL {
            assert_eq!(
                ConfigOptions {
                    cipher_combo: Some(combo),
                    ..ConfigOptions::default()
                }
                .combo(&vault, &masterkey)
                .unwrap(),
                combo
            );
        }
    }

    #[test]
    fn a_candidate_that_cannot_be_read_is_an_io_error_not_an_undetectable_combo() {
        use std::os::unix::fs::PermissionsExt;
        let (_tmp, vault, masterkey) = vault_with(CipherCombo::SivGcm);
        let candidate = first_encrypted_file(&vault.join(DATA_DIR_NAME)).expect("a candidate file");
        std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::File::open(&candidate).is_ok() {
            return; // running as root: the mode says nothing there.
        }
        assert!(matches!(
            detect_cipher_combo(&vault, &masterkey),
            Err(CoreError::Io(_))
        ));
        std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o600)).unwrap();
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

    /// Leaves the root directory and its `dirid.c9r` in place and removes every file the user put
    /// into the vault -- the WELCOME.rtf, here -- so the detection has nothing to read: it
    /// deliberately does not look at the backup file.
    fn remove_regular_files(vault: &Path, masterkey: &Masterkey, combo: CipherCombo) {
        let root = crate::vault::open::root_content_dir(vault, &Cryptor::new(combo, masterkey));
        for entry in std::fs::read_dir(&root).unwrap().flatten() {
            if entry.file_name() != DIR_ID_BACKUP_FILE_NAME {
                std::fs::remove_file(entry.path()).unwrap();
            }
        }
    }

    #[test]
    fn a_vault_without_regular_files_has_no_detectable_combo() {
        let (_tmp, vault, masterkey) = vault_with(CipherCombo::SivGcm);
        remove_regular_files(&vault, &masterkey, CipherCombo::SivGcm);
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
