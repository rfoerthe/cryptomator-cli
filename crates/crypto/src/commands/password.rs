//! `crypto password change`
use crate::cli::ChangePasswordArgs;
use crate::commands::{keychain_source, locked_vault, Ctx};
use crate::exit;
use anyhow::Result;
use cryptomator_app::{
    min_password_length, read_new_passphrase_no_env_fallback, read_passphrase_with_keychain,
    PasswordArgs, SystemIo,
};
use cryptomator_core::{
    change_password, read_vault_config, BackupStatus, MasterkeyFileAccess, OsRng,
};
use serde_json::json;

pub fn change(ctx: &Ctx, args: ChangePasswordArgs) -> Result<u8> {
    let (vault, path) = locked_vault(ctx, &args.vault)?;
    // Reject Hub and unsupported key ids before asking for any passphrase.
    read_vault_config(&path)?
        .key_id()?
        .require_masterkey_file()?;
    let mut io = SystemIo;
    // Only the *current* password may come from the keychain; the new one is being invented, and
    // the stored entry is not updated here (`password store` is how it is rewritten).
    let keychain = ctx.keychain()?;
    let old = read_passphrase_with_keychain(
        &args.password,
        "Current password: ",
        keychain_source(keychain.as_ref(), &vault),
        &mut io,
    )?;
    // Not `read_new_passphrase`: $CRYPTO_PASSWORD is where the *current* password just came from,
    // so without an explicit --new-password-* flag we prompt (and fail without a terminal).
    let new = read_new_passphrase_no_env_fallback(
        &PasswordArgs::from(&args.new_password),
        "New password: ",
        min_password_length(),
        &mut io,
    )?;
    let backup = change_password(
        &path,
        &MasterkeyFileAccess::new(Vec::new()),
        &old,
        &new,
        &mut OsRng,
    )?;
    // Only these two statuses mean a file with the *old* masterkey is on disk: `Created` was
    // written completely, `VerifiedExisting` was compared byte for byte.
    let kept = matches!(
        backup.status,
        BackupStatus::Created | BackupStatus::VerifiedExisting
    );
    if !kept {
        eprintln!(
            "warning: no backup of the previous masterkey file could be verified at {}",
            backup.path.display()
        );
    }
    let backup_path = kept.then_some(&backup.path);
    ctx.out.emit(
        json!({ "path": path, "backup": backup_path }),
        || match backup_path {
            Some(path) => format!(
                "Password changed. Previous masterkey file kept as {}",
                path.display()
            ),
            None => "Password changed.".to_string(),
        },
    )?;
    Ok(exit::OK)
}
