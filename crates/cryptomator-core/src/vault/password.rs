//! Password change (`ui/changepassword/ChangePasswordController.finish`). Unlike Java, which moves the
//! old file away before writing the new one, this keeps the original until the replacement is renamed
//! into place: backup copy → new file as `.tmp` → atomic rename.
use crate::backup::{attempt_backup, BackupOutcome};
use crate::crypto::rng::Rng;
use crate::error::{CoreError, Result};
use crate::masterkey_file::MasterkeyFileAccess;
use crate::vault::open::read_vault_config;
use std::io::Write;
use std::path::Path;

/// Returns the outcome of the backup attempt: callers must check its
/// [`crate::backup::BackupStatus`] before telling the user that the old masterkey file was kept.
pub fn change_password(
    vault_path: &Path,
    access: &MasterkeyFileAccess,
    old_passphrase: &str,
    new_passphrase: &str,
    rng: &mut dyn Rng,
) -> Result<BackupOutcome> {
    let file_name = read_vault_config(vault_path)?
        .key_id()?
        .require_masterkey_file()?
        .to_string();
    let masterkey_path = vault_path.join(&file_name);
    let old_bytes = std::fs::read(&masterkey_path)?;
    let new_bytes = access.change_passphrase(&old_bytes, old_passphrase, new_passphrase, rng)?;
    let backup = attempt_backup(&masterkey_path)?;
    let tmp_path = vault_path.join(format!("{file_name}.tmp"));
    {
        // A leftover `.tmp` from an interrupted run would otherwise surface as a bare
        // `AlreadyExists` I/O error that names no file at all.
        let mut tmp = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .map_err(|e| {
                CoreError::Io(std::io::Error::new(
                    e.kind(),
                    format!(
                        "cannot create temporary masterkey file {}: {e}",
                        tmp_path.display()
                    ),
                ))
            })?;
        tmp.write_all(&new_bytes)?;
        tmp.sync_all()?;
    }
    // The same durability argument as in `MasterkeyFileAccess::persist`: the new key file's
    // contents are synced above, and the directory entry that names them is synced here. A vault
    // whose passphrase was just changed is the last place to lose a masterkey file to a power cut.
    crate::durability::rename_durably(&tmp_path, &masterkey_path)?
        .warn_unconfirmed(masterkey_path.display());
    Ok(backup)
}
