//! `crypto password change|store|forget`
use crate::cli::{ChangePasswordArgs, StorePasswordArgs};
use crate::commands::{keychain_call, keychain_source, locked_vault, vault_key_and_name, Ctx};
use crate::exit;
use anyhow::Result;
use cryptomator_app::settings::{resolve_vault_index, VaultSettingsJson};
use cryptomator_app::{
    min_password_length, read_new_passphrase_no_env_fallback, read_passphrase,
    read_passphrase_with_keychain, AppError, KeychainError, PasswordArgs, SystemIo,
};
use cryptomator_core::{
    change_password, open_vault, read_vault_config, BackupStatus, MasterkeyFileAccess, OsRng,
};
use serde_json::json;
use std::path::PathBuf;
use zeroize::Zeroizing;

pub fn change(ctx: &Ctx, args: ChangePasswordArgs) -> Result<u8> {
    let (vault, path) = locked_vault(ctx, &args.vault)?;
    // Reject Hub and unsupported key ids before asking for any passphrase.
    read_vault_config(&path)?
        .key_id()?
        .require_masterkey_file()?;
    let mut io = SystemIo;
    // Only the *current* password may come from the keychain; the new one is being invented. A
    // stored entry is rewritten after the change (see `update_keychain_entry` below), never read
    // for the new password. Lazy: the provider is only probed once the source order actually
    // reaches the keychain steps.
    let old = read_passphrase_with_keychain(
        &args.password,
        "Current password: ",
        || Ok(keychain_source(ctx.keychain()?.as_ref(), &vault)),
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
    // A stored passphrase follows the change, like the desktop app's
    // `KeychainManager.changePassphrase`. The masterkey file is already rewritten at this point,
    // so a keychain that refuses is a warning -- exiting non-zero here would tell a script the
    // password change failed, which it did not.
    let keychain_updated = update_keychain_entry_or_warn(ctx, &vault, &new, &args.vault, "changed");
    ctx.out.emit(
        json!({ "path": path, "backup": backup_path, "keychainUpdated": keychain_updated }),
        || {
            let changed = match backup_path {
                Some(path) => format!(
                    "Password changed. Previous masterkey file kept as {}",
                    path.display()
                ),
                None => "Password changed.".to_string(),
            };
            if keychain_updated {
                format!("{changed}\nThe stored password in the keychain was updated.")
            } else {
                changed
            }
        },
    )?;
    Ok(exit::OK)
}

/// Resolves a vault reference for the keychain commands.
///
/// Unlike [`crate::commands::locked_vault`] this does **not** require the vault to be locked: a
/// keychain entry lives outside the vault directory, so storing or forgetting a passphrase is
/// safe while a daemon is serving it. What it does need is a path, because `password store`
/// verifies the passphrase against `masterkey.cryptomator` before saving it.
fn vault_for_keychain(ctx: &Ctx, reference: &str) -> Result<(VaultSettingsJson, PathBuf)> {
    let settings = ctx.store.load()?;
    let index = resolve_vault_index(&settings, reference)?;
    let vault = settings.directories[index].clone();
    let path = vault.path_buf().ok_or_else(|| AppError::InvalidValue {
        key: "path".to_string(),
        message: format!("vault {} has no path", vault.id),
    })?;
    Ok((vault, path))
}

/// `crypto password store <VAULT>`: read a passphrase, **verify it**, then save it.
///
/// The verification is the point. A wrong passphrase in the keychain is worse than no passphrase
/// at all: every later `crypto unlock` would take it, fail, and never ask the user -- so
/// `open_vault` has to accept it first. The passphrase itself is read *without* the keychain
/// steps ([`read_passphrase`], not `read_passphrase_with_keychain`): storing what is already
/// stored is not a thing. `--password-keychain` therefore ends in
/// [`AppError::Keychain`] (exit code **8**, not 2): the flag is grammatically fine -- it comes
/// with the flattened [`PasswordArgs`] -- but the keychain is where this command *writes*, never
/// where it reads, and the message says exactly that instead of `read_passphrase`'s "no keychain
/// is in use here", which would be untrue one line after a provider was found.
///
/// # Errors
/// [`AppError::VaultNotFound`] (3), [`cryptomator_core::CoreError::InvalidPassphrase`] (4),
/// [`AppError::Keychain`] (8) when there is no keychain or it refuses.
pub fn store(ctx: &Ctx, args: StorePasswordArgs) -> Result<u8> {
    // The vault first, so a name nobody knows is exit 3 here as it is everywhere else -- a machine
    // without a keychain must not answer `crypto password store does-not-exist` with "no
    // keychain", which sends the user after the wrong problem.
    let (vault, path) = vault_for_keychain(ctx, &args.vault)?;
    // Then the keychain: a run without one must not ask for a passphrase it could never store.
    let keychain = ctx.keychain_required()?;
    if args.password.password_keychain {
        // Refused here, by name, rather than further down in `read_passphrase`: there *is* a
        // keychain in this run (the line above found one), it is simply not a source for the one
        // command whose job is to fill it.
        return Err(AppError::Keychain(KeychainError::Unsupported {
            provider: keychain.display_name().to_string(),
            hint: "--password-keychain is not a source for `password store`; give the password \
                   another way"
                .to_string(),
        })
        .into());
    }
    // Reject Hub and unsupported key ids before asking for any passphrase.
    read_vault_config(&path)?
        .key_id()?
        .require_masterkey_file()?;
    let passphrase = read_passphrase(&args.password, "Password: ", &mut SystemIo)?;
    // Exit 4 comes from here, before anything is written to the keychain.
    drop(open_vault(
        &path,
        &MasterkeyFileAccess::new(Vec::new()),
        &passphrase,
    )?);

    let (key, display_name) = vault_key_and_name(&vault);
    let (key, display_name) = (key.to_string(), display_name.map(str::to_string));
    // The clone the worker thread gets is wiped when that thread drops it, however late it runs.
    let secret: Zeroizing<String> = passphrase.clone();
    keychain_call(&keychain, move |keychain| {
        keychain.store(&key, display_name.as_deref(), &secret)
    })?;
    drop(passphrase);

    let provider = keychain.display_name();
    let label = vault_label(&vault);
    ctx.out
        .emit(json!({ "id": vault.id, "stored": true }), || {
            format!("Password stored for {label} in {provider}.")
        })?;
    Ok(exit::OK)
}

/// `crypto password forget <VAULT>`: remove the entry. Removing one that is not there is a
/// success, not an error -- the end state is what the user asked for, and the `forgotten` field
/// says which of the two happened.
///
/// # Errors
/// [`AppError::VaultNotFound`] (3), [`AppError::Keychain`] (8).
pub fn forget(ctx: &Ctx, reference: &str) -> Result<u8> {
    // The vault first, so an unknown one is exit 3 rather than exit 8 (see `store`).
    let (vault, _path) = vault_for_keychain(ctx, reference)?;
    let keychain = ctx.keychain_required()?;
    let key = vault.id.clone();
    let forgotten = keychain_call(&keychain, move |keychain| keychain.delete(&key))?;
    let label = vault_label(&vault);
    ctx.out
        .emit(json!({ "id": vault.id, "forgotten": forgotten }), || {
            if forgotten {
                format!("Forgot the stored password for {label}.")
            } else {
                format!("No stored password for {label}.")
            }
        })?;
    Ok(exit::OK)
}

/// How a vault is named in these messages: its display name, or its id when it has none.
fn vault_label(vault: &VaultSettingsJson) -> &str {
    vault.display_name.as_deref().unwrap_or(&vault.id)
}

/// Updates a stored passphrase after a successful `password change` / `recovery-key
/// reset-password`, **if** one is stored. Returns whether an entry was updated.
///
/// Javas `KeychainManager.changePassphrase` only calls the backend when
/// `isPassphraseStored(key)`, and [`cryptomator_app::Keychain::change`] says the same thing with
/// its `bool`: `Ok(false)` means there was nothing to update. A run without a keychain at all is
/// the same `Ok(false)`: the change itself succeeded, and there is no entry that could go stale.
///
/// # Errors
/// [`AppError::Keychain`] for whatever the provider reported, including a timeout. Callers of a
/// *successful* password change turn that into a warning, never an exit code.
pub fn update_keychain_entry(
    ctx: &Ctx,
    vault: &VaultSettingsJson,
    passphrase: &str,
) -> Result<bool> {
    let Some(keychain) = ctx.keychain()? else {
        log::debug!(
            "no keychain in this run; nothing to update for {}",
            vault.id
        );
        return Ok(false);
    };
    let (key, display_name) = vault_key_and_name(vault);
    let (key, display_name) = (key.to_string(), display_name.map(str::to_string));
    let secret = Zeroizing::new(passphrase.to_string());
    keychain_call(&keychain, move |keychain| {
        keychain.change(&key, display_name.as_deref(), &secret)
    })
}

/// [`update_keychain_entry`] for the two commands that have already rewritten the masterkey file:
/// a keychain that refuses is reported on stderr and the command still succeeds, because the
/// password really did change and an exit code saying otherwise would be a lie.
///
/// `verb` is what happened to the password ("changed" / "reset"), `reference` the vault as the
/// user named it, so the hint can be copy-pasted.
pub fn update_keychain_entry_or_warn(
    ctx: &Ctx,
    vault: &VaultSettingsJson,
    passphrase: &str,
    reference: &str,
    verb: &str,
) -> bool {
    match update_keychain_entry(ctx, vault, passphrase) {
        Ok(updated) => updated,
        Err(err) => {
            eprintln!(
                "warning: the password was {verb}, but the keychain entry could not be updated: {err:#}"
            );
            eprintln!("hint: run `crypto password store {reference}` to fix it");
            false
        }
    }
}
