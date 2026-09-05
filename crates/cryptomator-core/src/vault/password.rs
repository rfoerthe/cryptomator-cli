//! Password change (`ui/changepassword/ChangePasswordController.finish`). Unlike Java, which moves the
//! old file away before writing the new one, this keeps the original until the replacement is renamed
//! into place: backup copy → new file as `.tmp` → atomic rename.
use crate::backup::attempt_backup;
use crate::crypto::rng::Rng;
use crate::error::Result;
use crate::masterkey_file::MasterkeyFileAccess;
use crate::vault::open::read_vault_config;
use std::io::Write;
use std::path::{Path, PathBuf};

pub fn change_password(
    vault_path: &Path,
    access: &MasterkeyFileAccess,
    old_passphrase: &str,
    new_passphrase: &str,
    rng: &mut dyn Rng,
) -> Result<PathBuf> {
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
        let mut tmp = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)?;
        tmp.write_all(&new_bytes)?;
        tmp.sync_all()?;
    }
    std::fs::rename(&tmp_path, &masterkey_path)?;
    Ok(backup.path)
}
