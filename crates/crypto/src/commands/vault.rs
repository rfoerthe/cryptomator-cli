//! `crypto vault create|add|remove|list|info|set`
use crate::cli::{AddArgs, CreateArgs, SetArgs};
use crate::commands::{keychain_call, store_passphrase_or_warn, Ctx};
use crate::exit;
use anyhow::{Context, Result};
use cryptomator_app::settings::{
    generate_id, normalize_vault_path, resolve_vault_index, VaultSettingsJson, WhenUnlocked,
};
use cryptomator_app::{
    min_password_length, read_new_passphrase, resolve_mounter, AppError, SystemIo,
};
use cryptomator_core::recovery::{create_recovery_key, WordEncoder};
use cryptomator_core::{
    assert_is_vault_directory, create_vault, determine_vault_state, read_vault_config, CipherCombo,
    CreateVaultOptions, KeyId, MasterkeyFileAccess, OsRng,
};
use serde_json::{json, Value};
use std::path::Path;

/// `VaultListManager.initializeLastKnownKeyLoaderIfPossible`: the scheme of the config's key id.
pub fn key_loader_scheme(vault_path: &Path) -> Option<String> {
    let key_id = read_vault_config(vault_path).ok()?.key_id().ok()?;
    Some(match key_id {
        KeyId::MasterkeyFile { .. } => "masterkeyfile".to_string(),
        KeyId::Hub { uri } | KeyId::Other(uri) => {
            uri.split(':').next().unwrap_or_default().to_string()
        }
    })
}

fn state_of(vault: &VaultSettingsJson) -> String {
    match vault.path_buf().map(|p| determine_vault_state(&p)) {
        Some(Ok(state)) => state.as_str().to_string(),
        _ => "ERROR".to_string(),
    }
}

pub fn vault_json(vault: &VaultSettingsJson) -> Value {
    let mut value = json!({
        "id": vault.id,
        "displayName": vault.display_name,
        "path": vault.path,
        "state": state_of(vault),
        "mountPoint": vault.mount_point,
        "usesReadOnlyMode": vault.uses_read_only_mode,
        "mountFlags": vault.mount_flags,
        "mountService": vault.mount_service,
        "port": vault.port,
        "autoLockWhenIdle": vault.auto_lock_when_idle,
        "autoLockIdleSeconds": vault.auto_lock_idle_seconds,
        "maxCleartextFilenameLength": vault.max_cleartext_filename_length,
        "actionAfterUnlock": vault.action_after_unlock.as_str(),
        "lastKnownKeyLoader": vault.last_known_key_loader,
    });
    if let Some(config) = vault.path_buf().and_then(|p| read_vault_config(&p).ok()) {
        let key_type = match config.key_id() {
            Ok(KeyId::MasterkeyFile { .. }) => "masterkeyfile",
            Ok(KeyId::Hub { .. }) => "hub",
            _ => "other",
        };
        value["format"] = json!(config.alleged_vault_version());
        value["shorteningThreshold"] = json!(config.alleged_shortening_threshold());
        value["cipherCombo"] = json!(config.alleged_cipher_combo());
        value["keyId"] = json!(config.key_id().map(|k| k.to_string()).ok());
        value["keyType"] = json!(key_type);
    }
    value
}

fn human_info(value: &Value) -> String {
    let order = [
        "id",
        "displayName",
        "path",
        "state",
        "keyType",
        "keyId",
        "format",
        "cipherCombo",
        "shorteningThreshold",
        "mountPoint",
        "mountService",
        "mountFlags",
        "usesReadOnlyMode",
        "port",
        "autoLockWhenIdle",
        "autoLockIdleSeconds",
        "maxCleartextFilenameLength",
        "actionAfterUnlock",
        "lastKnownKeyLoader",
    ];
    order
        .iter()
        .filter_map(|key| value.get(*key).map(|v| (key, v)))
        .map(|(key, v)| match v {
            Value::String(s) => format!("{key}: {s}"),
            Value::Null => format!("{key}: -"),
            other => format!("{key}: {other}"),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn register(ctx: &Ctx, path: &Path, name: Option<String>) -> Result<VaultSettingsJson> {
    let path = normalize_vault_path(path);
    let scheme = key_loader_scheme(&path);
    let registered = ctx.store.update(|settings| {
        if settings.directories.iter().any(|v| {
            v.path_buf()
                .is_some_and(|p| normalize_vault_path(&p) == path)
        }) {
            return Err(AppError::VaultAlreadyAdded(path.clone()));
        }
        let mut vault = VaultSettingsJson::new(generate_id(&mut OsRng), &path);
        if let Some(name) = name {
            vault.display_name = Some(name);
        }
        vault.last_known_key_loader = scheme.clone();
        settings.directories.push(vault.clone());
        Ok(vault)
    })?;
    Ok(registered)
}

pub fn create(ctx: &Ctx, args: CreateArgs) -> Result<u8> {
    let cipher_combo: CipherCombo = args.cipher_combo.parse()?;
    let path = normalize_vault_path(&args.path);
    let passphrase = read_new_passphrase(
        &args.password,
        "Password for the new vault: ",
        min_password_length(),
        &mut SystemIo,
    )?;
    let options = CreateVaultOptions {
        cipher_combo,
        shortening_threshold: args.shortening_threshold,
        write_readme_files: true,
    };
    let masterkey = create_vault(
        &path,
        &passphrase,
        &options,
        &MasterkeyFileAccess::new(Vec::new()),
        &mut OsRng,
    )
    .with_context(|| format!("cannot create vault at {}", path.display()))?;
    // The directory exists now, so this resolves symlinks like every registered path does.
    let path = normalize_vault_path(&path);
    let recovery_key = args
        .show_recovery_key
        .then(|| create_recovery_key(&WordEncoder::new(), masterkey.raw()));
    let registered = if args.no_register {
        None
    } else {
        Some(register(ctx, &path, args.name.clone())?)
    };
    let display_name = registered
        .as_ref()
        .and_then(|v| v.display_name.clone())
        .or(args.name.clone());
    // The vault exists on disk and, unless `--no-register` said otherwise, in `settings.json`.
    // Nothing below may undo that, so every way the keychain can disappoint is a warning here and
    // the exit code stays 0 -- `stored` says what really happened.
    let stored = store_new_password(ctx, &args, registered.as_ref(), &passphrase);
    drop(passphrase);
    let value = json!({
        "id": registered.as_ref().map(|v| v.id.clone()),
        "path": path,
        "displayName": display_name,
        "cipherCombo": cipher_combo.as_str(),
        "shorteningThreshold": args.shortening_threshold,
        "stored": stored,
        // A `serde_json::Value` cannot be wiped, so this copy of the recovery key outlives the
        // `Zeroizing` buffer; `emit_secret` drops it as soon as the output is rendered.
        "recoveryKey": recovery_key.as_deref(),
    });
    let human = || {
        let mut lines = vec![format!("Created vault at {}", path.display())];
        if let Some(v) = &registered {
            lines.push(format!(
                "Registered as {} ({})",
                v.id,
                v.display_name.clone().unwrap_or_default()
            ));
        }
        if stored {
            lines.push("The password was stored in the keychain.".to_string());
        }
        lines.join("\n")
    };
    if recovery_key.is_some() {
        ctx.out.emit_secret(value, human)?;
    } else {
        ctx.out.emit(value, human)?;
    }
    if !ctx.out.json {
        if let Some(key) = &recovery_key {
            // `as_str()` borrows out of the `Zeroizing` buffer: the key is never copied into an
            // owned `String` on the human path.
            println!("Recovery key: {}", key.as_str());
        }
    }
    Ok(exit::OK)
}

/// `vault create --store-password`: save the password of the vault that was just created.
///
/// Returns whether an entry was written. Every failure is a warning rather than an exit code: the
/// vault is already on disk and in `settings.json`, and a command that ends non-zero would tell a
/// script the creation failed.
fn store_new_password(
    ctx: &Ctx,
    args: &CreateArgs,
    registered: Option<&VaultSettingsJson>,
    passphrase: &str,
) -> bool {
    // `--store-password` only means something for a vault that is in `settings.json`: the keychain
    // is keyed by the vault id, and `--no-register` never assigns one.
    match (args.store_password, registered) {
        (false, _) => false,
        (true, None) => {
            eprintln!(
                "warning: --store-password needs a registered vault; --no-register was given"
            );
            false
        }
        // Every way the keychain can disappoint is one warning on stderr, shared with
        // `unlock --store-password` so the two cannot drift apart.
        (true, Some(vault)) => store_passphrase_or_warn(ctx, vault, passphrase),
    }
}

pub fn add(ctx: &Ctx, args: AddArgs) -> Result<u8> {
    let path = normalize_vault_path(&args.path);
    assert_is_vault_directory(&path)
        .with_context(|| format!("cannot register vault at {}", path.display()))?;
    let vault = register(ctx, &path, args.name)?;
    ctx.out.emit(vault_json(&vault), || {
        format!(
            "Registered {} as {} ({})",
            path.display(),
            vault.id,
            vault.display_name.clone().unwrap_or_default()
        )
    })?;
    Ok(exit::OK)
}

/// `crypto vault remove <VAULT> [--forget-password]`.
///
/// The keychain entry goes first: once `settings.json` no longer lists the vault there is no id
/// left to look it up by. A keychain that refuses therefore stops the removal -- the user can
/// still run `crypto vault remove` without the flag, which never touches the keychain and always
/// works.
///
/// # Errors
/// [`AppError::VaultNotFound`] (exit code 3), [`AppError::Keychain`] (8) when `--forget-password`
/// was given and there is no keychain or it refuses.
pub fn remove(ctx: &Ctx, reference: &str, forget_password: bool) -> Result<u8> {
    // `--forget-password` has to resolve the vault to know which keychain key to delete. What is
    // removed from `settings.json` below is then addressed by that vault's *id*, not by resolving
    // the user's reference a second time: a display name or a path is not unique the way an id is,
    // so two resolutions could name two vaults -- one whose password was forgotten and one that
    // was unregistered. Without the flag nothing has been resolved yet and the reference itself is
    // what the closure looks up, under the settings lock.
    let mut resolved_id = None;
    let forgotten = if forget_password {
        let settings = ctx.store.load()?;
        let index = resolve_vault_index(&settings, reference)?;
        let key = settings.directories[index].id.clone();
        resolved_id = Some(key.clone());
        let keychain = ctx.keychain_required()?;
        // Only if present: `delete` reports `false` for a vault that never had a stored password,
        // which is the end state the user asked for either way.
        keychain_call(&keychain, move |keychain| keychain.delete(&key))?
    } else {
        false
    };
    let target = resolved_id.as_deref().unwrap_or(reference);
    let removed = ctx.store.update(|settings| {
        let index = resolve_vault_index(settings, target)?;
        Ok(settings.directories.remove(index))
    })?;
    ctx.out.emit(
        json!({ "id": removed.id, "path": removed.path, "forgotten": forgotten }),
        || {
            let line = format!("Removed {} from the vault list (files kept)", removed.id);
            if forgotten {
                format!("{line} and forgot the stored password")
            } else {
                line
            }
        },
    )?;
    Ok(exit::OK)
}

pub fn list(ctx: &Ctx) -> Result<u8> {
    let settings = ctx.store.load()?;
    let rows: Vec<Value> = settings.directories.iter().map(vault_json).collect();
    ctx.out.emit(Value::Array(rows.clone()), || {
        if rows.is_empty() {
            return "No vaults registered. Use `crypto vault create` or `crypto vault add`."
                .to_string();
        }
        let mut lines = vec![format!(
            "{:<12}  {:<20}  {:<20}  PATH",
            "ID", "STATE", "NAME"
        )];
        for row in &rows {
            let s = |key: &str| row[key].as_str().unwrap_or("-").to_string();
            lines.push(format!(
                "{:<12}  {:<20}  {:<20}  {}",
                s("id"),
                s("state"),
                s("displayName"),
                s("path")
            ));
        }
        lines.join("\n")
    })?;
    Ok(exit::OK)
}

pub fn info(ctx: &Ctx, reference: &str) -> Result<u8> {
    let settings = ctx.store.load()?;
    let index = resolve_vault_index(&settings, reference)?;
    let value = vault_json(&settings.directories[index]);
    ctx.out.emit(value.clone(), || human_info(&value))?;
    Ok(exit::OK)
}

fn invalid(key: &str, message: impl Into<String>) -> AppError {
    AppError::InvalidValue {
        key: key.to_string(),
        message: message.into(),
    }
}

pub fn set(ctx: &Ctx, args: SetArgs) -> Result<u8> {
    // `Option<Option<_>>`: outer = flag given, inner = the new value (`None` clears the setting).
    let mounter = match args.mounter.as_deref() {
        None => None,
        Some("default") | Some("") => Some(None),
        Some(other) => Some(Some(resolve_mounter(other)?)),
    };
    // Accepted case-insensitively like `--mounter`; settings.json always gets the canonical
    // upper-case spelling, because the desktop app's Jackson mapping is case-sensitive.
    let action =
        match args.action_after_unlock.as_deref() {
            None => None,
            Some(value) => Some(WhenUnlocked::parse(&value.to_uppercase()).ok_or_else(|| {
                invalid("--action-after-unlock", "expected IGNORE, REVEAL or ASK")
            })?),
        };
    let max_name_length = match args.max_filename_length.as_deref() {
        None => None,
        Some("auto") => Some(-1),
        Some(value) => Some(
            value
                .parse::<i32>()
                .ok()
                .filter(|n| *n > 0)
                .ok_or_else(|| {
                    invalid(
                        "--max-filename-length",
                        "expected a positive number or \"auto\"",
                    )
                })?,
        ),
    };
    let updated = ctx.store.update(|settings| {
        let index = resolve_vault_index(settings, &args.vault)?;
        let vault = &mut settings.directories[index];
        if let Some(name) = &args.name {
            vault.display_name = Some(name.clone());
        }
        if let Some(mount_point) = &args.mount_point {
            vault.mount_point = Some(mount_point.to_string_lossy().into_owned());
        }
        if args.no_mount_point {
            vault.mount_point = None;
        }
        if let Some(read_only) = args.read_only {
            vault.uses_read_only_mode = read_only;
        }
        if let Some(flags) = &args.mount_flags {
            vault.mount_flags = flags.clone();
        }
        if args.default_mount_flags {
            vault.mount_flags = String::new();
        }
        if let Some(mounter) = &mounter {
            vault.mount_service = mounter.clone();
        }
        if let Some(port) = args.port {
            vault.port = port;
        }
        if let Some(seconds) = args.auto_lock_idle {
            vault.auto_lock_when_idle = true;
            vault.auto_lock_idle_seconds = seconds;
        }
        if args.no_auto_lock {
            vault.auto_lock_when_idle = false;
        }
        if let Some(n) = max_name_length {
            vault.max_cleartext_filename_length = n;
        }
        if let Some(action) = action {
            vault.action_after_unlock = action;
        }
        Ok(vault.clone())
    })?;
    let value = vault_json(&updated);
    ctx.out.emit(value.clone(), || human_info(&value))?;
    Ok(exit::OK)
}
