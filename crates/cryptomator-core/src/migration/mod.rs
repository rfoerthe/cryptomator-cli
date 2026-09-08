//! Vault format migration, ported from `cryptofs/migration/Migrators.java`, `Migration.java` and
//! `common/FileSystemCapabilityChecker.java`.
//!
//! A vault is migrated **in place**, one format at a time, along the chain 5 → 6 → 7 → 8. Every
//! step re-reads the vault's own version first, so an interrupted run simply continues where it
//! stopped, and every step that rewrites `masterkey.cryptomator` backs the old file up first.
//!
//! The passphrase handed to [`migrate`] is what the user typed. Format 6 is precisely the format
//! that encodes the passphrase in Unicode NFC, so the 5 → 6 step normalises it (Java parity:
//! `Version6Migrator` persists with `Normalizer.normalize(passphrase, NFC)`) and the chain then
//! carries the **normalised** form forward. That hand-over at [`migrate`]'s `current = …nfc()` is
//! load-bearing, not a convenience: nothing after format 5 normalises anything — neither our
//! `crypto::kdf` nor cryptolib's `Scrypt.scrypt(CharSequence, …)` does more than UTF-8-encode what
//! it is given — so a chain that kept the user's original NFD input would fail the 6 → 7 step with
//! [`CoreError::InvalidPassphrase`](crate::error::CoreError::InvalidPassphrase) *after* the 5 → 6
//! step had already been committed.
pub mod v6;
pub mod v7;
pub mod v8;

use crate::backup::{attempt_backup, BackupStatus};
use crate::constants::MASTERKEY_FILENAME;
use crate::crypto::rng::{OsRng, Rng};
use crate::error::{CoreError, Result};
use crate::masterkey_file::{MasterkeyFileAccess, DEFAULT_MASTERKEY_FILE_VERSION};
use crate::vault::state::determine_vault_version;
use std::path::{Path, PathBuf};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

/// A vault format this tool can read or migrate.
///
/// Formats below 5 have no migrator (Java: `NoApplicableMigratorException`) and formats above 8 do
/// not exist yet; [`detect_version`] reports both as
/// [`CoreError::UnsupportedVaultVersion`](crate::error::CoreError::UnsupportedVaultVersion).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VaultVersion {
    V5,
    V6,
    V7,
    V8,
}

impl VaultVersion {
    /// The format every migration ends at.
    pub const LATEST: VaultVersion = VaultVersion::V8;

    /// The format number as it appears in `vault.cryptomator`'s `format` claim.
    ///
    /// Note that this is *not* what a format 8 masterkey file carries: since format 8 the vault
    /// version moved into the signed config and `masterkey.cryptomator` stores the placeholder
    /// [`DEFAULT_MASTERKEY_FILE_VERSION`] (999) instead.
    pub fn number(self) -> u32 {
        match self {
            VaultVersion::V5 => 5,
            VaultVersion::V6 => 6,
            VaultVersion::V7 => 7,
            VaultVersion::V8 => 8,
        }
    }

    /// Inverse of [`number`](Self::number). 999 — the version a format 8 masterkey file claims —
    /// maps to [`VaultVersion::V8`] as well, so a format 8 vault whose `vault.cryptomator` is
    /// missing is still recognised as format 8 rather than as something to migrate.
    pub fn from_number(version: u32) -> Option<Self> {
        match version {
            5 => Some(VaultVersion::V5),
            6 => Some(VaultVersion::V6),
            7 => Some(VaultVersion::V7),
            8 | DEFAULT_MASTERKEY_FILE_VERSION => Some(VaultVersion::V8),
            _ => None,
        }
    }
}

impl std::fmt::Display for VaultVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.number())
    }
}

/// One link of the migration chain (`migration/Migration.java`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MigrationStep {
    FiveToSix,
    SixToSeven,
    SevenToEight,
}

impl MigrationStep {
    /// The step applicable to `version`, or `None` when there is nothing left to do
    /// (`Migration.isApplicable`).
    pub fn from_version(version: VaultVersion) -> Option<Self> {
        match version {
            VaultVersion::V5 => Some(MigrationStep::FiveToSix),
            VaultVersion::V6 => Some(MigrationStep::SixToSeven),
            VaultVersion::V7 => Some(MigrationStep::SevenToEight),
            VaultVersion::V8 => None,
        }
    }

    pub fn from(self) -> VaultVersion {
        match self {
            MigrationStep::FiveToSix => VaultVersion::V5,
            MigrationStep::SixToSeven => VaultVersion::V6,
            MigrationStep::SevenToEight => VaultVersion::V7,
        }
    }

    pub fn to(self) -> VaultVersion {
        match self {
            MigrationStep::FiveToSix => VaultVersion::V6,
            MigrationStep::SixToSeven => VaultVersion::V7,
            MigrationStep::SevenToEight => VaultVersion::V8,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            MigrationStep::FiveToSix => "5->6",
            MigrationStep::SixToSeven => "6->7",
            MigrationStep::SevenToEight => "7->8",
        }
    }
}

impl std::fmt::Display for MigrationStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A rename the 6 → 7 step would perform, both paths relative to the vault directory.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PlannedRename {
    pub from: PathBuf,
    pub to: PathBuf,
}

/// What [`migrate`] would do, without doing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationPlan {
    pub from: VaultVersion,
    /// Always [`VaultVersion::LATEST`]; a plan never stops halfway.
    pub to: VaultVersion,
    pub steps: Vec<MigrationStep>,
    /// The renames of the 6 → 7 step's dry run, empty for every plan that does not contain that
    /// step. Collisions are not resolved here: two sources landing on the same target are both
    /// listed with it, and the migration gives the second one a `_1` suffix when it gets there.
    pub renames: Vec<PlannedRename>,
}

/// How [`migrate`] should behave. [`Default`] is "change the vault, and refuse a migration that
/// would need a full scan first".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MigrationOptions {
    /// Permission to walk the whole vault when the storage cannot hold 220-character names.
    ///
    /// Java asks the user through `MigrationContinuationListener.continueMigrationOnEvent(
    /// REQUIRES_FULL_VAULT_DIR_SCAN)`; a CLI cannot ask in the middle of a run, so the answer is
    /// given up front (`--yes`). Without it such a vault is reported as
    /// [`CoreError::MigrationBlocked`](crate::error::CoreError::MigrationBlocked) and left alone.
    /// It has no effect on storage that supports the full name length — the common case, where no
    /// scan is needed at all.
    pub full_scan_allowed: bool,
    /// Report what would happen and change nothing. [`migrate`] then returns the format the vault
    /// is at, having written nothing and reported no [`MigrationEvent`]; the renames it would make
    /// are what [`plan`] lists.
    ///
    /// "Written nothing" is meant literally: the dry run short-circuits ahead of
    /// [`assert_all_capabilities`], whose write probe would otherwise be the one thing it does
    /// touch, so previewing a read-only copy of a vault works.
    pub dry_run: bool,
}

/// What [`migrate`] reports while it works (`migration/api/MigrationProgressListener.java`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationEvent {
    /// A step is about to run (Java's `INITIALIZING`).
    StepStarted { step: MigrationStep },
    /// Progress inside a long-running step (Java's `MIGRATING`); `done` of `total` entries.
    /// Only the 6 → 7 step is long-running enough to report this.
    StepProgress {
        step: MigrationStep,
        done: u64,
        total: u64,
    },
    /// A step finished and the vault is now at `version` (Java's `FINALIZING`).
    StepFinished {
        step: MigrationStep,
        version: VaultVersion,
    },
}

/// `FileSystemCapabilityChecker.assertAllCapabilities`: first read, then write.
///
/// Java probes with `Files.createTempDirectory(checkDir, "write-access")`; a fixed name does the
/// same job and keeps the test deterministic, because the directory disappears immediately.
pub fn assert_all_capabilities(vault_path: &Path) -> Result<()> {
    std::fs::read_dir(vault_path).map_err(|_| CoreError::MissingCapability {
        path: vault_path.to_path_buf(),
        capability: "read access",
    })?;
    let check_dir = vault_path.join("c");
    let result = (|| -> std::io::Result<()> {
        std::fs::create_dir_all(&check_dir)?;
        let probe = check_dir.join("write-access-probe");
        std::fs::create_dir(&probe)?;
        std::fs::remove_dir(&probe)
    })();
    // Java: `deleteRecursivelySilently(checkDir)` in the `finally` block.
    let _ = std::fs::remove_dir_all(&check_dir);
    result.map_err(|_| CoreError::MissingCapability {
        path: check_dir,
        capability: "write access",
    })
}

/// The vault's format, from `vault.cryptomator`'s `format` claim if there is one and from the
/// masterkey file's `version` otherwise (`Migrators.determineVaultVersion`).
pub fn detect_version(vault_path: &Path) -> Result<VaultVersion> {
    let version = determine_vault_version(vault_path)?;
    VaultVersion::from_number(version).ok_or(CoreError::UnsupportedVaultVersion { version })
}

/// Whether the vault is of an older format than this tool writes (`Migrators.needsMigration`).
///
/// Unlike [`crate::needs_migration`], which only compares numbers, this fails on a format outside
/// 5..=8 — the caller asking "should I migrate?" wants to hear that the vault *cannot* be
/// migrated rather than that it should be.
pub fn needs_migration(vault_path: &Path) -> Result<bool> {
    Ok(detect_version(vault_path)? != VaultVersion::LATEST)
}

/// The steps [`migrate`] would run, in order, and the renames the 6 → 7 step among them would
/// perform — the `--dry-run` at core level. Nothing is written.
///
/// The passphrase is verified against the masterkey file whenever there is anything to do, so a
/// wrong passphrase is reported before the first byte is written.
pub fn plan(vault_path: &Path, passphrase: &str) -> Result<MigrationPlan> {
    let mut plan = plan_steps(vault_path, passphrase)?;
    if plan.steps.contains(&MigrationStep::SixToSeven) {
        // Formats 5 and 6 share the on-disk layout, so the renames can be listed for a format 5
        // vault too, long before its own step has run.
        plan.renames = v7::plan_renames(vault_path)?;
    }
    Ok(plan)
}

/// [`plan`] without the rename pass, which [`migrate`] does not need and which costs a full walk
/// of `d/`.
fn plan_steps(vault_path: &Path, passphrase: &str) -> Result<MigrationPlan> {
    let from = detect_version(vault_path)?;
    let mut steps = Vec::new();
    let mut version = from;
    while let Some(step) = MigrationStep::from_version(version) {
        steps.push(step);
        version = step.to();
    }
    if !steps.is_empty() {
        drop(
            MasterkeyFileAccess::new(Vec::new())
                .load(&vault_path.join(MASTERKEY_FILENAME), passphrase)?,
        );
    }
    Ok(MigrationPlan {
        from,
        to: version,
        steps,
        renames: Vec::new(),
    })
}

/// Migrates the vault in place up to format 8 and returns the format it ends at.
///
/// `passphrase` is the passphrase the user typed; see the module documentation for how the 5 → 6
/// step normalises it. A vault that is already at format 8 is left alone and reported as
/// [`VaultVersion::V8`], and so is every vault when
/// [`MigrationOptions::dry_run`] is set.
pub fn migrate(
    vault_path: &Path,
    passphrase: &str,
    options: MigrationOptions,
    progress: &mut dyn FnMut(MigrationEvent),
) -> Result<VaultVersion> {
    migrate_with_rng(vault_path, passphrase, options, progress, &mut OsRng)
}

fn migrate_with_rng(
    vault_path: &Path,
    passphrase: &str,
    options: MigrationOptions,
    progress: &mut dyn FnMut(MigrationEvent),
    rng: &mut dyn Rng,
) -> Result<VaultVersion> {
    // Before `assert_all_capabilities`, which probes for write access by creating and removing
    // `<vault>/c/write-access-probe`: a dry run must be readable-only, so that a preview of a
    // read-only copy or a snapshot prints the plan instead of failing with
    // [`CoreError::MissingCapability`].
    if options.dry_run {
        // Verifies the passphrase, and nothing else: `plan_steps` only reads.
        return Ok(plan_steps(vault_path, passphrase)?.from);
    }
    assert_all_capabilities(vault_path)?;
    // Also verifies the passphrase, so a wrong one leaves the vault untouched.
    let planned = plan_steps(vault_path, passphrase)?;
    if planned.steps.is_empty() {
        return Ok(planned.from);
    }
    // The passphrase changes in 5 → 6 (NFC); the following steps need the new form.
    let mut current: Zeroizing<String> = Zeroizing::new(passphrase.to_string());
    loop {
        // Re-read rather than trust the plan: a step that half-finished on an earlier run is
        // picked up where the vault actually stands.
        let version = detect_version(vault_path)?;
        let Some(step) = MigrationStep::from_version(version) else {
            return Ok(version);
        };
        match step {
            MigrationStep::FiveToSix => {
                progress(MigrationEvent::StepStarted { step });
                v6::migrate(vault_path, &current, rng)?;
                current = Zeroizing::new(current.nfc().collect::<String>());
            }
            MigrationStep::SixToSeven => {
                progress(MigrationEvent::StepStarted { step });
                v7::migrate_reporting(
                    vault_path,
                    &current,
                    options.full_scan_allowed,
                    progress,
                    rng,
                )?;
            }
            MigrationStep::SevenToEight => {
                progress(MigrationEvent::StepStarted { step });
                v8::migrate(vault_path, &current, rng)?;
            }
        }
        progress(MigrationEvent::StepFinished {
            step,
            version: detect_version(vault_path)?,
        });
    }
}

/// `BackupHelper.attemptBackup`, with one **deliberate deviation**: a backup that cannot be
/// written is fatal here, while Java catches the `IOException`, logs `"Failed to backup {}."` and
/// returns the backup path regardless. The original is about to be overwritten, so a migration
/// that could not secure it should not proceed.
///
/// An existing backup is never overwritten — [`attempt_backup`] creates the file with `CREATE_NEW`
/// and otherwise only compares. A backup whose content differs from the current file is a
/// mismatched name collision; Java logs it and carries on, and so do we. The `.bkup` files the
/// cryptofs 1.x releases left in the legacy vaults cannot collide at all: they are named
/// `masterkey.cryptomator.bkup` (1.3.x) or carry a CRC32 suffix (1.6.x and later), while our names
/// carry the first four bytes of the SHA-256 digest.
pub(crate) fn back_up(path: &Path) -> Result<PathBuf> {
    let outcome = attempt_backup(path)?;
    if let BackupStatus::Failed(reason) = &outcome.status {
        return Err(CoreError::Io(std::io::Error::other(format!(
            "cannot back up {} to {}: {reason}",
            path.display(),
            outcome.path.display()
        ))));
    }
    Ok(outcome.path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_chain_covers_every_format_up_to_eight() {
        let mut version = VaultVersion::V5;
        let mut steps = Vec::new();
        while let Some(step) = MigrationStep::from_version(version) {
            assert_eq!(step.from(), version);
            steps.push(step);
            version = step.to();
        }
        assert_eq!(version, VaultVersion::LATEST);
        assert_eq!(
            steps,
            [
                MigrationStep::FiveToSix,
                MigrationStep::SixToSeven,
                MigrationStep::SevenToEight
            ]
        );
        assert_eq!(steps[0].to_string(), "5->6");
    }

    #[test]
    fn a_format_eight_masterkey_file_claims_999() {
        assert_eq!(
            VaultVersion::from_number(DEFAULT_MASTERKEY_FILE_VERSION),
            Some(VaultVersion::V8)
        );
        assert_eq!(VaultVersion::from_number(8), Some(VaultVersion::V8));
        assert_eq!(VaultVersion::V8.number(), 8);
        for unsupported in [0, 4, 9, 998, 1000] {
            assert_eq!(VaultVersion::from_number(unsupported), None);
        }
    }

    #[test]
    fn the_capability_check_passes_on_a_normal_directory_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        assert_all_capabilities(dir.path()).unwrap();
        assert!(
            !dir.path().join("c").exists(),
            "the probe directory is gone"
        );
    }

    #[test]
    fn a_missing_directory_has_no_read_access() {
        let dir = tempfile::tempdir().unwrap();
        let err = assert_all_capabilities(&dir.path().join("nope")).unwrap_err();
        assert!(
            matches!(
                err,
                CoreError::MissingCapability {
                    capability: "read access",
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn an_unsupported_format_is_named_in_the_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("masterkey.cryptomator"),
            r#"{"version":4,"scryptSalt":"AAAAAAAAAAA=","scryptCostParam":2,"scryptBlockSize":1,"primaryMasterKey":"AA==","hmacMasterKey":"AA==","versionMac":"AA=="}"#,
        )
        .unwrap();
        let err = detect_version(dir.path()).unwrap_err();
        assert!(
            matches!(err, CoreError::UnsupportedVaultVersion { version: 4 }),
            "{err}"
        );
        assert!(needs_migration(dir.path()).is_err());
    }

    #[test]
    fn a_file_that_cannot_be_read_cannot_be_backed_up() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            back_up(&dir.path().join("nope")),
            Err(CoreError::Io(_))
        ));
    }

    /// The [`BackupStatus::Failed`] arm proper: the file is there, but its backup path is occupied
    /// by a directory, so opening it fails with something other than `AlreadyExists`.
    #[test]
    fn a_backup_that_cannot_be_written_is_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("masterkey.cryptomator");
        let content = b"hello\n";
        std::fs::write(&file, content).unwrap();
        let blocked = file.with_file_name(crate::backup::backup_file_name(
            "masterkey.cryptomator",
            content,
        ));
        std::fs::create_dir(&blocked).unwrap();
        assert_eq!(
            attempt_backup(&file).unwrap().status,
            BackupStatus::Failed(
                std::fs::read(&blocked)
                    .expect_err("a directory is not readable as a file")
                    .to_string()
            ),
            "the precondition of this test"
        );
        let err = back_up(&file).unwrap_err();
        assert!(
            matches!(&err, CoreError::Io(e) if e.to_string().contains("cannot back up")),
            "{err}"
        );
    }

    /// `assertWriteAccess`: a directory that can be listed but not written to.
    #[test]
    fn a_read_only_directory_has_no_write_access() {
        if is_root() {
            return; // root ignores the permission bits, so there is nothing to observe
        }
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("read-only");
        std::fs::create_dir(&vault).unwrap();
        std::fs::set_permissions(&vault, std::fs::Permissions::from_mode(0o500)).unwrap();
        let err = assert_all_capabilities(&vault).unwrap_err();
        // Restore before the assertion, so a failure still leaves a removable temp dir behind.
        std::fs::set_permissions(&vault, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            matches!(
                err,
                CoreError::MissingCapability {
                    capability: "write access",
                    ..
                }
            ),
            "{err}"
        );
    }

    /// Tests that turn permission bits into an expectation are meaningless as root.
    pub(crate) fn is_root() -> bool {
        std::process::Command::new("id")
            .arg("-u")
            .output()
            .map(|out| String::from_utf8_lossy(&out.stdout).trim() == "0")
            .unwrap_or(false)
    }
}
