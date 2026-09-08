//! `crypto recovery-key show|reset-password|restore`
use crate::cli::{ResetPasswordArgs, RestoreArgs, ShowArgs};
use crate::commands::password::update_keychain_entry_or_warn;
use crate::commands::{backup_files, keychain_source, locked_vault, restorable_vault, Ctx};
use crate::exit;
use anyhow::Result;
use cryptomator_app::{
    min_password_length, read_new_passphrase, read_passphrase_with_keychain, read_secret_file,
    AppError, PasswordArgs, PasswordIo, SystemIo,
};
use cryptomator_core::constants::{MASTERKEY_FILENAME, VAULTCONFIG_FILENAME};
use cryptomator_core::recovery::{
    create_recovery_key, decode_recovery_key, reset_password, restore, WordEncoder,
};
use cryptomator_core::{
    open_vault, read_vault_config, CipherCombo, CoreError, MasterkeyFileAccess, OsRng, VaultConfig,
    VAULT_VERSION,
};
use serde_json::json;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub fn show(ctx: &Ctx, args: ShowArgs) -> Result<u8> {
    let (vault, path) = locked_vault(ctx, &args.vault)?;
    // Reject Hub and unsupported key ids before asking for any passphrase.
    read_vault_config(&path)?
        .key_id()?
        .require_masterkey_file()?;
    // Lazy: the provider is only probed once the source order actually reaches the keychain
    // steps, so a scripted `--password-stdin` run never pays for it.
    let passphrase = read_passphrase_with_keychain(
        &args.password,
        "Password: ",
        || Ok(keychain_source(ctx.keychain()?.as_ref(), &vault)),
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

/// The recovery key from a file or from the next line of stdin, with its whitespace normalised to
/// single blanks (the user may have wrapped the 44 words over several lines).
///
/// Takes the two sources rather than a `ResetPasswordArgs`, so `recovery-key restore` -- whose
/// argument type is a different one and whose `--config` mode has no recovery key at all -- shares
/// the body instead of copying it. The caller decides what "neither was given" means.
fn read_recovery_key(
    recovery_key_file: Option<&Path>,
    recovery_key_stdin: bool,
    io: &mut dyn PasswordIo,
) -> Result<Zeroizing<String>> {
    let raw = if let Some(file) = recovery_key_file {
        read_secret_file(file, "--recovery-key-file")?
    } else {
        debug_assert!(
            recovery_key_stdin,
            "callers check that one of the two sources was given"
        );
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
    let (vault, path) = locked_vault(ctx, &args.vault)?;
    let unverified = read_vault_config(&path)?;
    unverified.key_id()?.require_masterkey_file()?;
    let mut io = SystemIo;
    let recovery_key = read_recovery_key(
        args.recovery_key_file.as_deref(),
        args.recovery_key_stdin,
        &mut io,
    )?;
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
    // Same reasoning as `password change`: a stored passphrase follows the reset, because a stale
    // entry would make every later unlock fail silently. The masterkey file is already rewritten,
    // so a keychain that refuses is a warning, not an exit code.
    let keychain_updated = update_keychain_entry_or_warn(ctx, &vault, &new, &args.vault, "reset");
    ctx.out.emit(
        json!({ "path": path, "keychainUpdated": keychain_updated }),
        || {
            let base =
                "Password reset. A backup of the previous masterkey file was kept next to it.";
            if keychain_updated {
                format!("{base}\nThe stored password in the keychain was updated.")
            } else {
                base.to_string()
            }
        },
    )?;
    Ok(exit::OK)
}

/// `crypto recovery-key restore <VAULT> (--masterkey|--config|--all)`: rebuild the key files a
/// vault lost.
///
/// The three modes are the desktop app's `RecoveryActionType.RESTORE_MASTERKEY`,
/// `RESTORE_VAULT_CONFIG` and `RESTORE_ALL`, and they differ in what they need:
///
/// * `--masterkey` / `--all`: the **recovery key** plus a **new** password. The recovery key *is*
///   the masterkey, so a new masterkey file can be wrapped around it; the old password is gone
///   with the old file.
/// * `--config`: the **vault password**. The masterkey file is still there and unlocks the key
///   that has to sign the new `vault.cryptomator`; no recovery key is involved.
///
/// Everything is validated before the vault is touched (see
/// [`cryptomator_core::recovery::restore`]), and a file that is replaced is copied to a `.bkup`
/// first.
///
/// The vault reference may name a directory that is not in `settings.json` (see
/// [`restorable_vault`]) -- a vault that lost both key files cannot be registered, so requiring an
/// entry would shut this command out of the case it exists for. Nothing is registered here; the
/// hint after a successful restore says how.
///
/// # Errors
/// Exit code 2 for a mode/flag combination that cannot work, for a cipher combo that can neither
/// be given nor detected and for one the vault contradicts, 3 for an unknown vault, 4 for a wrong
/// recovery key or password, 5 for a vault that is not in a restorable state (or that a daemon is
/// serving), 1 for I/O.
pub fn restore(ctx: &Ctx, args: RestoreArgs) -> Result<u8> {
    // Not `locked_vault`: a vault that lost its config is VAULT_CONFIG_MISSING or ALL_MISSING --
    // exactly the states this command exists to end.
    let (vault, path) = restorable_vault(ctx, &args.vault)?;
    // An unregistered vault has no id and no keychain entry; the hint at the end says how to give
    // it one.
    let registered = vault.is_some();
    // `--masterkey` writes no config, so the two settings that only describe one would be quietly
    // ignored. Saying so beats letting somebody believe they changed the vault's cipher combo.
    if args.masterkey {
        for (flag, given) in [
            ("--cipher-combo", args.cipher_combo.is_some()),
            (
                "--shortening-threshold",
                args.shortening_threshold.is_some(),
            ),
        ] {
            if given {
                return Err(AppError::InvalidValue {
                    key: flag.to_string(),
                    message: "--masterkey rebuilds only masterkey.cryptomator, which holds \
                              neither; use --all or --config to write a vault config"
                        .to_string(),
                }
                .into());
            }
        }
    }
    // The same rule for the *old* password: only `--config` reads it (it signs the new config with
    // the key already in the masterkey file). `--masterkey` and `--all` take the recovery key and a
    // **new** password instead, so a `--password-*` flag there is not merely ignored -- with
    // `--password-stdin` next to `--recovery-key-stdin` two readers would race for the same
    // stdin. Refusing beats reading the recovery key out of the password's line.
    if args.masterkey || args.all {
        for (flag, given) in [
            ("--password-stdin", args.password.password_stdin),
            ("--password-file", args.password.password_file.is_some()),
            ("--password-env", args.password.password_env.is_some()),
            ("--password-keychain", args.password.password_keychain),
        ] {
            if given {
                return Err(AppError::InvalidValue {
                    key: flag.to_string(),
                    message: format!(
                        "{} takes the recovery key and a new password, not the vault's old one; \
                         use --new-password-* (and --recovery-key-stdin/--recovery-key-file)",
                        if args.masterkey {
                            "--masterkey"
                        } else {
                            "--all"
                        }
                    ),
                }
                .into());
            }
        }
    }
    let config_options = restore::ConfigOptions {
        cipher_combo: match args.cipher_combo.as_deref() {
            None | Some("auto") => None,
            // clap's value_parser already limits this to the two names.
            Some(other) => Some(other.parse::<CipherCombo>()?),
        },
        shortening_threshold: args
            .shortening_threshold
            .unwrap_or(cryptomator_core::DEFAULT_SHORTENING_THRESHOLD),
    };
    let mut io = SystemIo;
    let access = MasterkeyFileAccess::new(Vec::new());
    let backups_before = backup_files(&path);

    let outcome = if args.config {
        // `restorable_vault` admits ALL_MISSING, where there is no masterkey file to unwrap the
        // key from -- and `restore_config` would then fail with a bare "No such file or
        // directory". Naming the file and the mode that *can* rebuild it is the whole answer.
        if !path.join(MASTERKEY_FILENAME).exists() {
            return Err(AppError::InvalidValue {
                key: "--config".to_string(),
                message: format!(
                    "{MASTERKEY_FILENAME} is gone too, so there is no key to sign a new \
                     config with; use --all with the recovery key"
                ),
            }
            .into());
        }
        if args.recovery_key_stdin || args.recovery_key_file.is_some() {
            return Err(AppError::InvalidValue {
                key: "--config".to_string(),
                message: "restoring only the vault config uses the vault password, not the \
                          recovery key; drop --recovery-key-* or use --all"
                    .to_string(),
            }
            .into());
        }
        // Lazy keychain, like every other passphrase read in this crate: a scripted
        // `--password-stdin` run never pays for the provider probe.
        let passphrase = read_passphrase_with_keychain(
            &args.password,
            "Password: ",
            || match &vault {
                Some(vault) => Ok(keychain_source(ctx.keychain()?.as_ref(), vault)),
                // Keychain entries are keyed by the vault id, which an unregistered vault has not
                // got: there is nothing to look up and nothing to store.
                None => Ok(None),
            },
            &mut io,
        )?;
        let config =
            restore::restore_config(&access, &path, &passphrase, config_options, &mut OsRng)
                .map_err(|err| name_the_combo(err, false))
                .map_err(|err| name_the_migration(err, &args.vault))?;
        Restored {
            files: vec![VAULTCONFIG_FILENAME],
            config: Some(config),
            keychain_updated: false,
        }
    } else {
        if !args.recovery_key_stdin && args.recovery_key_file.is_none() {
            return Err(AppError::InvalidValue {
                key: "--recovery-key-stdin".to_string(),
                message: format!(
                    "restoring the {} needs the recovery key; pass --recovery-key-stdin or \
                     --recovery-key-file",
                    if args.masterkey {
                        "masterkey file"
                    } else {
                        "key files"
                    }
                ),
            }
            .into());
        }
        let recovery_key = read_recovery_key(
            args.recovery_key_file.as_deref(),
            args.recovery_key_stdin,
            &mut io,
        )?;
        let encoder = WordEncoder::new();
        // Prove the key is well-formed -- and, when the vault config survived, that it belongs to
        // *this* vault -- before a new password is even asked for.
        let raw = decode_recovery_key(&encoder, &recovery_key)?;
        if let Ok(unverified) = read_vault_config(&path) {
            unverified.verify(&raw, VAULT_VERSION)?;
        }
        drop(raw);
        let new = read_new_passphrase(
            &PasswordArgs::from(&args.new_password),
            "New password: ",
            min_password_length(),
            &mut io,
        )?;
        let (files, config) = if args.masterkey {
            restore::restore_masterkey(&encoder, &access, &path, &recovery_key, &new, &mut OsRng)
                .map_err(|err| name_the_migration(err.into(), &args.vault))?;
            (vec![MASTERKEY_FILENAME], None)
        } else {
            let config = restore::restore_all(
                &encoder,
                &access,
                &path,
                &recovery_key,
                &new,
                config_options,
                &mut OsRng,
            )
            .map_err(|err| name_the_combo(err, true))
            .map_err(|err| name_the_migration(err, &args.vault))?;
            (vec![MASTERKEY_FILENAME, VAULTCONFIG_FILENAME], Some(config))
        };
        // Same reasoning as `password change` and `reset-password`: a stored passphrase follows the
        // new one, because a stale entry would make every later unlock fail. The masterkey file is
        // already written, so a keychain that refuses is a warning, not an exit code.
        let keychain_updated = match &vault {
            Some(vault) => update_keychain_entry_or_warn(ctx, vault, &new, &args.vault, "restored"),
            None => false,
        };
        Restored {
            files,
            config,
            keychain_updated,
        }
    };

    // The core writes the `.bkup` copies without reporting where they went, so the ones this run
    // created are the difference between the two listings -- a vault that already carried a
    // matching backup gets none, because `attempt_backup` never overwrites.
    let backups: Vec<PathBuf> = backup_files(&path)
        .difference(&backups_before)
        .cloned()
        .collect();
    ctx.out.emit(
        json!({
            "vault": vault.as_ref().map(|v| v.id.clone()),
            "path": path,
            "registered": registered,
            "restored": outcome.restored_names(),
            "cipherCombo": outcome.config.as_ref().map(|c| c.cipher_combo.as_str()),
            "shorteningThreshold": outcome.config.as_ref().map(|c| c.shortening_threshold),
            "backups": backups,
            "keychainUpdated": outcome.keychain_updated,
        }),
        || outcome.human(&path, &backups),
    )?;
    // On stderr, so `--json` keeps a parseable stdout, and after the result, so it reads as the
    // next step it is: the vault is whole again but still unknown to `crypto vault list`, to the
    // keychain and to `crypto unlock`.
    if !registered {
        eprintln!(
            "hint: register it with `crypto vault add {}`",
            path.display()
        );
    }
    Ok(exit::OK)
}

/// What a restore did, for the two renderings below.
struct Restored {
    /// The file names that were written. This is the order they are *named* in, which for `--all`
    /// is not the order they are moved in -- `restore_all` moves the config first, so that a
    /// failure between the two moves can be repaired with `restore --masterkey`.
    files: Vec<&'static str>,
    /// The config that was written, if one was.
    config: Option<VaultConfig>,
    keychain_updated: bool,
}

impl Restored {
    /// The short names of the JSON `restored` array: `masterkey`, `config`.
    fn restored_names(&self) -> Vec<&'static str> {
        self.files
            .iter()
            .map(|file| {
                if *file == MASTERKEY_FILENAME {
                    "masterkey"
                } else {
                    "config"
                }
            })
            .collect()
    }

    fn human(&self, path: &Path, backups: &[PathBuf]) -> String {
        let files = match self.files.as_slice() {
            [one] => (*one).to_string(),
            other => other.join(" and "),
        };
        let mut lines = vec![match &self.config {
            Some(config) => format!(
                "Restored {files} in {} ({}, shortening threshold {})",
                path.display(),
                config.cipher_combo,
                config.shortening_threshold
            ),
            None => format!("Restored {files} in {}", path.display()),
        }];
        if !backups.is_empty() {
            lines.push("The previous files were kept as:".to_string());
            lines.extend(backups.iter().map(|b| format!("  {}", b.display())));
        }
        if self.keychain_updated {
            lines.push("The stored password in the keychain was updated.".to_string());
        }
        lines.join("\n")
    }
}

/// Turns [`CoreError::CipherComboUndetectable`] into a usage error naming `--cipher-combo`.
///
/// The vault is not broken and the command is not wrong: there is simply nothing in it the combo
/// could be read from, and only the user knows which one the vault was created with. `from_key`
/// says whether the masterkey came from a recovery key, in which case a key belonging to a
/// *different* vault looks exactly the same from here and is worth naming.
fn name_the_combo(err: CoreError, from_key: bool) -> anyhow::Error {
    let CoreError::CipherComboUndetectable(_) = &err else {
        return err.into();
    };
    let mut message =
        "the vault holds no encrypted file the cipher combo could be read from; pass \
         --cipher-combo SIV_GCM or --cipher-combo SIV_CTRMAC (vaults created since 2021 use \
         SIV_GCM)"
            .to_string();
    if from_key {
        message.push_str(" -- or the recovery key does not belong to this vault");
    }
    AppError::InvalidValue {
        key: "--cipher-combo".to_string(),
        message,
    }
    .into()
}

/// Adds the way out to the refusal `restore.rs` raises for a vault that still has the format 5/6
/// layout: `crypto migrate` first, then restore.
///
/// Only the message is added -- the typed [`CoreError::MigrationBlocked`] stays in the chain, so
/// the exit code remains `5` (wrong state), which is what every other "this vault has to be
/// migrated first" refusal in the CLI reports.
fn name_the_migration(err: anyhow::Error, reference: &str) -> anyhow::Error {
    let legacy = err.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<CoreError>(),
            Some(CoreError::MigrationBlocked(_))
        )
    });
    if !legacy {
        return err;
    }
    err.context(format!(
        "run `crypto migrate {reference}` first and restore the key files afterwards"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(combo: CipherCombo) -> VaultConfig {
        VaultConfig::create_new(combo, 220)
    }

    #[test]
    fn the_human_line_names_the_files_the_combo_and_the_backups() {
        let restored = Restored {
            files: vec![MASTERKEY_FILENAME, VAULTCONFIG_FILENAME],
            config: Some(config(CipherCombo::SivGcm)),
            keychain_updated: true,
        };
        let text = restored.human(
            Path::new("/vaults/v"),
            &[PathBuf::from("/vaults/v/vault.cryptomator.ABCD1234.bkup")],
        );
        assert_eq!(
            text,
            "Restored masterkey.cryptomator and vault.cryptomator in /vaults/v (SIV_GCM, \
             shortening threshold 220)\nThe previous files were kept as:\n  \
             /vaults/v/vault.cryptomator.ABCD1234.bkup\nThe stored password in the keychain was \
             updated."
        );
        assert_eq!(restored.restored_names(), ["masterkey", "config"]);
    }

    #[test]
    fn a_masterkey_only_restore_names_no_combo() {
        let restored = Restored {
            files: vec![MASTERKEY_FILENAME],
            config: None,
            keychain_updated: false,
        };
        assert_eq!(
            restored.human(Path::new("/vaults/v"), &[]),
            "Restored masterkey.cryptomator in /vaults/v"
        );
        assert_eq!(restored.restored_names(), ["masterkey"]);
    }

    #[test]
    fn an_undetectable_combo_becomes_a_usage_error_naming_the_flag() {
        let err = name_the_combo(
            CoreError::CipherComboUndetectable(PathBuf::from("/vaults/v")),
            true,
        );
        let app = err.downcast_ref::<AppError>().expect("an AppError");
        assert!(matches!(app, AppError::InvalidValue { key, .. } if key == "--cipher-combo"));
        assert_eq!(crate::exit::code_for(&err), crate::exit::USAGE);
        assert!(err.to_string().contains("does not belong to this vault"));
        // Without a recovery key that half of the message is left out …
        let err = name_the_combo(
            CoreError::CipherComboUndetectable(PathBuf::from("/vaults/v")),
            false,
        );
        assert!(!err.to_string().contains("does not belong"));
        // … and every other error passes through untouched, keeping its own exit code.
        let err = name_the_combo(CoreError::InvalidPassphrase, true);
        assert_eq!(crate::exit::code_for(&err), crate::exit::INVALID_PASSPHRASE);
    }
}
