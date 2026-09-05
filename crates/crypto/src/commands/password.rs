//! `crypto password change`
use crate::cli::ChangePasswordArgs;
use crate::commands::{locked_vault_path, Ctx};
use crate::exit;
use anyhow::Result;
use cryptomator_app::{
    min_password_length, read_new_passphrase_no_env_fallback, read_passphrase, PasswordArgs,
    SystemIo,
};
use cryptomator_core::{change_password, read_vault_config, MasterkeyFileAccess, OsRng};
use serde_json::json;

pub fn change(ctx: &Ctx, args: ChangePasswordArgs) -> Result<u8> {
    let path = locked_vault_path(ctx, &args.vault)?;
    // Reject Hub and unsupported key ids before asking for any passphrase.
    read_vault_config(&path)?
        .key_id()?
        .require_masterkey_file()?;
    let mut io = SystemIo;
    let old = read_passphrase(&args.password, "Current password: ", &mut io)?;
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
    ctx.out
        .emit(json!({ "path": path, "backup": backup }), || {
            format!(
                "Password changed. Previous masterkey file kept as {}",
                backup.display()
            )
        })?;
    Ok(exit::OK)
}
