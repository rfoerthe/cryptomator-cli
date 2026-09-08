//! Backup copies of `vault.cryptomator` / `masterkey.cryptomator` (`cryptofs/common/BackupHelper.java`).
use crate::constants::BACKUP_SUFFIX;
use crate::error::{CoreError, Result};
use data_encoding::HEXUPPER;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};

pub fn generate_file_id_suffix(file_bytes: &[u8]) -> String {
    let digest = Sha256::digest(file_bytes);
    format!(".{}", HEXUPPER.encode(&digest[..4]))
}

pub fn backup_file_name(original_file_name: &str, file_bytes: &[u8]) -> String {
    format!(
        "{original_file_name}{}{BACKUP_SUFFIX}",
        generate_file_id_suffix(file_bytes)
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackupStatus {
    Created,
    VerifiedExisting,
    MismatchExisting,
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupOutcome {
    pub path: PathBuf,
    pub status: BackupStatus,
}

/// Best-effort backup like Java: `CREATE_NEW`; if the backup exists (or is not writable) compare contents;
/// other I/O failures while writing are reported as `Failed` rather than propagated.
///
/// The original file is copied, never moved or removed.
///
/// The name of the backup encodes the digest of the *intended* content, but the file is created before it
/// is written: a crash or a short write in between leaves a `.bkup` whose content does not hash to the
/// suffix in its own name (reported here as [`BackupStatus::Failed`], but a later run only sees the file).
/// Restore code must therefore re-hash the backup's bytes and must not trust the name as an integrity check.
pub fn attempt_backup(path: &Path) -> Result<BackupOutcome> {
    let file_bytes = std::fs::read(path)?;
    let file_name = path.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
        CoreError::InvalidArgument(format!("not a file path: {}", path.display()))
    })?;
    let backup_path = path.with_file_name(backup_file_name(file_name, &file_bytes));
    let status = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&backup_path)
    {
        // A backup is the copy that has to be there when the original is gone, so it is only
        // called `Created` once its bytes *and* the directory entry naming them are on the
        // platter. Without the two syncs a crash right after a passphrase change could take the
        // backup and the file it was made from at once.
        Ok(mut file) => match file
            .write_all(&file_bytes)
            .and_then(|()| file.sync_all())
            .and_then(|()| crate::durability::sync_parent_dir(&backup_path))
        {
            Ok(()) => BackupStatus::Created,
            Err(e) => BackupStatus::Failed(e.to_string()),
        },
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::PermissionDenied
            ) =>
        {
            match std::fs::read(&backup_path) {
                Ok(existing) if existing == file_bytes => BackupStatus::VerifiedExisting,
                Ok(_) => BackupStatus::MismatchExisting,
                Err(e) => BackupStatus::Failed(e.to_string()),
            }
        }
        Err(e) => BackupStatus::Failed(e.to_string()),
    };
    Ok(BackupOutcome {
        path: backup_path,
        status,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffix_is_upper_hex_of_first_four_sha256_bytes() {
        // sha256("hello\n") = 5891b5b5…; cryptofs BackupHelper.generateFileIdSuffix → ".5891B5B5"
        assert_eq!(generate_file_id_suffix(b"hello\n"), ".5891B5B5");
        assert_eq!(
            backup_file_name("masterkey.cryptomator", b"hello\n"),
            "masterkey.cryptomator.5891B5B5.bkup"
        );
    }

    #[test]
    fn creates_backup_next_to_original() {
        let dir = tempfile::tempdir().unwrap();
        let original = dir.path().join("vault.cryptomator");
        std::fs::write(&original, b"hello\n").unwrap();
        let outcome = attempt_backup(&original).unwrap();
        assert_eq!(
            outcome.path,
            dir.path().join("vault.cryptomator.5891B5B5.bkup")
        );
        assert_eq!(outcome.status, BackupStatus::Created);
        assert_eq!(std::fs::read(&outcome.path).unwrap(), b"hello\n");
    }

    #[test]
    fn existing_identical_backup_is_verified() {
        let dir = tempfile::tempdir().unwrap();
        let original = dir.path().join("vault.cryptomator");
        std::fs::write(&original, b"hello\n").unwrap();
        attempt_backup(&original).unwrap();
        assert_eq!(
            attempt_backup(&original).unwrap().status,
            BackupStatus::VerifiedExisting
        );
    }

    #[test]
    fn existing_different_backup_is_reported_as_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let original = dir.path().join("vault.cryptomator");
        std::fs::write(&original, b"hello\n").unwrap();
        std::fs::write(
            dir.path().join("vault.cryptomator.5891B5B5.bkup"),
            b"corrupt",
        )
        .unwrap();
        assert_eq!(
            attempt_backup(&original).unwrap().status,
            BackupStatus::MismatchExisting
        );
    }

    #[test]
    fn missing_original_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            attempt_backup(&dir.path().join("nope")),
            Err(CoreError::Io(_))
        ));
    }
}
