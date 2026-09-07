//! `crypto recovery-key show|reset-password`
use crate::cli::{ResetPasswordArgs, ShowArgs};
use crate::commands::{keychain_source, locked_vault, locked_vault_path, Ctx};
use crate::exit;
use anyhow::Result;
use cryptomator_app::{
    min_password_length, read_new_passphrase, read_passphrase_with_keychain, read_secret_file,
    AppError, PasswordArgs, PasswordIo, SystemIo,
};
use cryptomator_core::recovery::{
    create_recovery_key, decode_recovery_key, reset_password, WordEncoder,
};
use cryptomator_core::{open_vault, read_vault_config, MasterkeyFileAccess, OsRng, VAULT_VERSION};
use serde_json::json;
use zeroize::Zeroizing;

pub fn show(ctx: &Ctx, args: ShowArgs) -> Result<u8> {
    let (vault, path) = locked_vault(ctx, &args.vault)?;
    // Reject Hub and unsupported key ids before asking for any passphrase.
    read_vault_config(&path)?
        .key_id()?
        .require_masterkey_file()?;
    let keychain = ctx.keychain()?;
    let passphrase = read_passphrase_with_keychain(
        &args.password,
        "Password: ",
        keychain_source(keychain.as_ref(), &vault),
        &mut SystemIo,
    )?;
    let opened = open_vault(&path, &MasterkeyFileAccess::new(Vec::new()), &passphrase)?;
    let key = create_recovery_key(&WordEncoder::new(), opened.masterkey.raw());
    if ctx.out.json {
        // `emit_secret` wipes the rendered JSON; the payload is built only on this branch so the
        // human path never makes an unwiped `serde_json::Value` copy of the key.
        ctx.out
            .emit_secret(json!({ "recoveryKey": key.as_str() }), String::new)?;
    } else {
        // Printed straight from the wiped buffer.
        println!("{}", key.as_str());
    }
    Ok(exit::OK)
}

fn read_recovery_key(
    args: &ResetPasswordArgs,
    io: &mut dyn PasswordIo,
) -> Result<Zeroizing<String>> {
    let raw = if let Some(file) = &args.recovery_key_file {
        read_secret_file(file, "--recovery-key-file")?
    } else {
        io.read_stdin_line()?
            .map(Zeroizing::new)
            // Not a password source: name the flag that was given but delivered nothing.
            .ok_or_else(|| AppError::InvalidValue {
                key: "--recovery-key-stdin".to_string(),
                message: "no recovery key on standard input".to_string(),
            })?
    };
    Ok(Zeroizing::new(
        raw.split_whitespace().collect::<Vec<_>>().join(" "),
    ))
}

pub fn reset_password_cmd(ctx: &Ctx, args: ResetPasswordArgs) -> Result<u8> {
    let path = locked_vault_path(ctx, &args.vault)?;
    let unverified = read_vault_config(&path)?;
    unverified.key_id()?.require_masterkey_file()?;
    let mut io = SystemIo;
    let recovery_key = read_recovery_key(&args, &mut io)?;
    let encoder = WordEncoder::new();
    // Prove the key belongs to this vault before touching the masterkey file.
    let raw = decode_recovery_key(&encoder, &recovery_key)?;
    unverified.verify(&raw, VAULT_VERSION)?;
    let new = read_new_passphrase(
        &PasswordArgs::from(&args.new_password),
        "New password: ",
        min_password_length(),
        &mut io,
    )?;
    reset_password(
        &encoder,
        &MasterkeyFileAccess::new(Vec::new()),
        &path,
        &recovery_key,
        &new,
        &mut OsRng,
    )?;
    ctx.out.emit(json!({ "path": path }), || {
        "Password reset. A backup of the previous masterkey file was kept next to it.".to_string()
    })?;
    Ok(exit::OK)
}
