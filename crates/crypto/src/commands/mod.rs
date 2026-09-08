//! Command implementations; each returns the process exit code.
pub mod config;
pub mod daemon;
pub mod events;
pub mod fs;
pub mod health;
pub mod keychain;
pub mod lock;
pub mod migrate;
pub mod mounters;
pub mod name;
pub mod password;
pub mod recovery;
pub mod stats;
pub mod status;
pub mod unlock;
pub mod vault;

use crate::output::Output;
use anyhow::Result;
use cryptomator_app::settings::{resolve_vault_index, SettingsStore, VaultSettingsJson};
use cryptomator_app::{
    AppError, ErrorBody, Keychain, KeychainError, KeychainSource, RuntimeState, StateDir,
    VaultInfo, VaultRegistry,
};
use cryptomator_core::{determine_vault_state, VaultState};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

#[derive(Debug)]
pub struct Ctx {
    pub store: SettingsStore,
    pub out: Output,
    /// Where the daemons publish their socket, pid and run info.
    pub state_dir: StateDir,
    /// The `--settings` path exactly as it was given, so a spawned daemon can be handed the same
    /// one. `None` means "resolve it from the environment", which the child does the same way.
    pub settings_arg: Option<PathBuf>,
    /// `--no-keychain`: the keychain is off for this run, whatever `useKeychain` says.
    pub no_keychain: bool,
    /// Memoised [`Ctx::keychain`]. Choosing a provider probes every candidate
    /// (`KEYCHAIN_PROBE_TIMEOUT` each), so a command that asks twice must not pay twice.
    ///
    /// A `Mutex<Option<…>>` rather than a `OnceLock`: the cell must stay empty when
    /// `settings.json` fails to load, so the next call gets to report that error again instead
    /// of a cached `None` silently standing in for "no keychain" -- `OnceLock::get_or_init`'s
    /// closure cannot fail, so it cannot express that. The lock also makes the whole
    /// probe-then-cache sequence atomic, so two concurrent callers (still theoretical: one `Ctx`,
    /// one thread today) cannot both pay the probe and have one result thrown away.
    keychain: Mutex<Option<Option<Arc<dyn Keychain>>>>,
}

impl Ctx {
    pub fn new(
        store: SettingsStore,
        out: Output,
        state_dir: StateDir,
        settings_arg: Option<PathBuf>,
        no_keychain: bool,
    ) -> Self {
        Self {
            store,
            out,
            state_dir,
            settings_arg,
            no_keychain,
            keychain: Mutex::new(None),
        }
    }

    /// The vaults of `settings.json` together with what the state directory says about them.
    pub fn registry(&self) -> VaultRegistry {
        VaultRegistry::new(self.store.clone(), self.state_dir.clone())
    }

    /// The keychain provider for this run, or `None` when there is none to use: `--no-keychain`,
    /// `useKeychain = false`, or no supported provider on this machine.
    ///
    /// This is `KeychainModule.provideKeychainAccessProvider` plus the CLI's own switch. The
    /// answer is computed once and kept: the probe behind it costs a timeout budget per candidate.
    ///
    /// `Arc`, not `Box`: [`keychain_call`] moves a clone of the provider onto a worker thread it
    /// may stop waiting for, so the provider has to outlive the call that gave up on it.
    ///
    /// This re-reads `settings.json` on the first call even when [`locked_vault`] already loaded
    /// it for the same command: threading the loaded [`cryptomator_app::settings::SettingsJson`]
    /// through here would mean every caller between `locked_vault` and this method carries it
    /// along for that one read. The [`Mutex`] above already removes the read that would actually
    /// repeat -- a second `Ctx::keychain()` call in the same process -- so paying for one more
    /// read of a small local file is not worth that plumbing.
    ///
    /// # Errors
    /// Whatever reading `settings.json` reports. Not cached: a failed read leaves the cell empty,
    /// so the next call gets to report the same error again rather than a wrongly memoised
    /// "no keychain".
    pub fn keychain(&self) -> cryptomator_app::Result<Option<Arc<dyn Keychain>>> {
        let mut cached = self.keychain.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(resolved) = cached.as_ref() {
            return Ok(resolved.clone());
        }
        let resolved = if self.no_keychain {
            None
        } else {
            cryptomator_app::keychain::for_settings(&self.store.load()?).map(Arc::from)
        };
        *cached = Some(resolved.clone());
        Ok(resolved)
    }

    /// Like [`Ctx::keychain`], but "there is none" is a failure (exit code 8). For the commands
    /// whose whole purpose is the keychain: `password store`, `password forget`, `keychain test`.
    ///
    /// # Errors
    /// [`AppError::Keychain`] with [`KeychainError::Unsupported`] when no provider is in use.
    pub fn keychain_required(&self) -> Result<Arc<dyn Keychain>> {
        match self.keychain()? {
            Some(keychain) => Ok(keychain),
            None => Err(AppError::Keychain(KeychainError::Unsupported {
                provider: "keychain".to_string(),
                hint: if self.no_keychain {
                    "--no-keychain is in effect".to_string()
                } else {
                    "no supported provider; check `crypto config get keychainProvider` and \
                     `crypto keychain test`, or set useKeychain to true"
                        .to_string()
                },
            })
            .into()),
        }
    }
}

/// The key and display name a vault's keychain entry is written under: the id (what the desktop
/// app uses) and the display name (which Java passes as `displayName` and which only the Secret
/// Service backend stores).
pub fn vault_key_and_name(vault: &VaultSettingsJson) -> (&str, Option<&str>) {
    (&vault.id, vault.display_name.as_deref())
}

/// The keychain step of the passphrase resolution for `vault`, or `None` when there is no keychain
/// to consult -- which is what makes `--password-keychain` an error and the implicit step a no-op.
pub fn keychain_source<'a>(
    keychain: Option<&Arc<dyn Keychain>>,
    vault: &'a VaultSettingsJson,
) -> Option<KeychainSource<'a>> {
    let (key, display_name) = vault_key_and_name(vault);
    keychain.map(|keychain| KeychainSource {
        keychain: Arc::clone(keychain),
        key,
        vault_label: display_name.unwrap_or(key),
    })
}

/// Saves `passphrase` for `vault`, replacing whatever was stored there before.
///
/// Unlike [`crate::commands::password::update_keychain_entry`] this writes even when nothing was
/// stored yet -- it backs `--store-password`, where the user asked for exactly that. Returns
/// `false` when there is no keychain in this run (`--no-keychain`, `useKeychain = false`, no
/// supported provider), which is not a failure by itself: the caller decides whether that
/// deserves a warning or an exit code.
///
/// The passphrase is not verified here. Both callers hold one that has just opened the vault --
/// `unlock` derived a key from it, `vault create` chose it -- so re-deriving would only cost a
/// second scrypt round. `crypto password store`, whose passphrase comes from the user, does
/// verify.
///
/// # Errors
/// [`AppError::Keychain`] (exit code 8) when a keychain is there but refuses.
pub fn store_passphrase_now(
    ctx: &Ctx,
    vault: &VaultSettingsJson,
    passphrase: &str,
) -> Result<bool> {
    let Some(keychain) = ctx.keychain()? else {
        return Ok(false);
    };
    let (key, display_name) = vault_key_and_name(vault);
    let (key, display_name) = (key.to_string(), display_name.map(str::to_string));
    // The clone the worker thread gets is wiped when that thread drops it, however late it runs.
    let secret = zeroize::Zeroizing::new(passphrase.to_string());
    keychain_call(&keychain, move |keychain| {
        keychain.store(&key, display_name.as_deref(), &secret)
    })?;
    Ok(true)
}

/// [`store_passphrase_now`] for the two commands that must not fail because of the keychain:
/// `crypto unlock --store-password` and `crypto vault create --store-password`. Returns whether an
/// entry was written.
///
/// Both call this only after the thing they are actually for has succeeded -- the vault is mounted,
/// or created and registered -- so neither "there was no keychain after all" nor "the provider
/// refused" may become an exit code: a non-zero exit would tell a script the unlock or the creation
/// failed, which it did not. Both are one warning on stderr, in one place, so the two commands
/// cannot drift apart in what they say.
///
/// The `Ok(false)` branch is close to unreachable for `unlock` (it checks
/// [`Ctx::keychain_required`] before it opens the vault) and the ordinary answer for
/// `vault create`, which never refuses to create a vault over a missing keychain.
pub fn store_passphrase_or_warn(ctx: &Ctx, vault: &VaultSettingsJson, passphrase: &str) -> bool {
    match store_passphrase_now(ctx, vault, passphrase) {
        Ok(stored) => {
            if !stored {
                eprintln!(
                    "warning: --store-password had no effect: no keychain is in use \
                     (--no-keychain, useKeychain=false, or no supported provider)"
                );
            }
            stored
        }
        Err(err) => {
            eprintln!("warning: the password was not stored: {err:#}");
            false
        }
    }
}

/// Runs one keychain call under [`cryptomator_app::KEYCHAIN_TIMEOUT`].
///
/// The provider is owned (`Arc<dyn Keychain>`), so it can be moved to the worker thread that the
/// timeout wrapper gives up on. Every keychain access from a command goes through here -- that is
/// what keeps a stuck macOS ACL dialog from freezing the CLI.
///
/// # Errors
/// [`AppError::Keychain`] (exit code 8) for whatever the provider reported, including a timeout.
// The passphrase source reaches the same wrapper through `cryptomator_app::keychain::call`; the
// `store`/`delete`/`change` callers are the `crypto password store|forget|change` commands.
pub fn keychain_call<T, F>(keychain: &Arc<dyn Keychain>, op: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(&dyn Keychain) -> cryptomator_app::KeychainResult<T> + Send + 'static,
{
    Ok(cryptomator_app::keychain::call(keychain, op).map_err(AppError::Keychain)?)
}

/// Resolves a vault reference and requires a daemon to be serving it, returning the vault and the
/// socket to talk to that daemon on.
///
/// `crypto stats` and `crypto events` both need one: their answers exist only inside the running
/// daemon. A vault in any other state -- locked, or left behind by a crashed daemon -- is an
/// [`AppError::WrongState`] (exit code 5), not an empty result.
///
/// # Errors
/// [`AppError::VaultNotFound`] / [`AppError::AmbiguousVault`] (exit code 3) for a reference that
/// names no vault, [`AppError::WrongState`] (5) for one that is not unlocked.
pub fn unlocked_vault(ctx: &Ctx, reference: &str) -> Result<(VaultInfo, PathBuf)> {
    let info = ctx.registry().info(reference)?;
    if info.state != RuntimeState::Unlocked {
        return Err(AppError::WrongState {
            expected: RuntimeState::Unlocked.as_str().to_string(),
            actual: info.state.as_str().to_string(),
        }
        .into());
    }
    let socket = ctx.state_dir.files(&info.id).socket;
    Ok((info, socket))
}

/// Whether `err` means the daemon is not there any more.
///
/// For a `--follow` stream that is the end of the story rather than a failure: the vault was
/// locked (or auto-locked, or signalled) while it was being watched, and the watcher saw
/// everything there was to see. It stays an error for a command that never got an answer at all.
pub fn daemon_gone(err: &AppError) -> bool {
    matches!(err, AppError::DaemonUnreachable(_))
}

/// Whether `err` is the honest end of a `--follow` stream rather than a failure of it.
///
/// [`daemon_gone`] covers the socket disappearing entirely, but `crypto stats --follow` can also
/// land its next poll while the daemon is still there and mid-teardown (`Phase::Locking`): it
/// answers `NOT_UNLOCKED` right up until the socket itself goes away. Both are the same event --
/// the vault was locked, auto-locked or signalled while the stream was watching it -- just caught
/// at different points of the daemon's shutdown, so both end the stream the same way (after at
/// least one sample was ever delivered; see the call sites).
pub fn stream_ended(err: &AppError) -> bool {
    daemon_gone(err)
        || matches!(err, AppError::DaemonError { code, .. } if code == ErrorBody::NOT_UNLOCKED)
}

/// How a vault is named in a message to the user: its display name, or its id when it has none.
pub fn vault_label(info: &VaultInfo) -> &str {
    info.display_name.as_deref().unwrap_or(&info.id)
}

/// Sets a flag on Ctrl-C instead of ending the process, so a `--follow` loop can stop between
/// messages and exit 0 like any other successful command.
///
/// Shared by `crypto stats --follow` and `crypto events --follow`.
///
/// # Errors
/// Whatever `signal_hook` reports while installing the handler.
pub fn install_interrupt() -> Result<Arc<AtomicBool>> {
    let flag = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&flag))?;
    Ok(flag)
}

/// Resolves a vault reference to its settings entry and path and requires the vault to be in one
/// of `allowed` on disk **and** locked at runtime.
///
/// The runtime half is the same for every caller and is the reason none of them is simply a state
/// check: a vault a daemon is serving looks LOCKED on disk (its key files are untouched), but its
/// key is live in another process and its files are open. Rewriting the masterkey underneath that
/// daemon -- which is what `password change`, `recovery-key reset-password` and
/// `recovery-key restore` do -- or renaming every file below it, as `migrate` does, would leave
/// the running mount serving a vault that no longer opens. `crypto lock --force` is the way out of
/// a stale mount.
///
/// The three public wrappers below differ only in `allowed`; keep them as the documented entry
/// points, because which states a command accepts is part of what that command *is*.
///
/// # Errors
/// [`AppError::VaultNotFound`] / [`AppError::AmbiguousVault`] (exit code 3) for a reference that
/// names no vault, [`AppError::WrongState`] (5) for a state outside `allowed` and for a vault a
/// daemon is serving.
fn vault_in_state(
    ctx: &Ctx,
    reference: &str,
    allowed: &[VaultState],
) -> Result<(VaultSettingsJson, PathBuf)> {
    let settings = ctx.store.load()?;
    let index = resolve_vault_index(&settings, reference)?;
    let vault = settings.directories[index].clone();
    let path = vault.path_buf().ok_or_else(|| AppError::InvalidValue {
        key: "path".to_string(),
        message: format!("vault {} has no path", vault.id),
    })?;
    let state = determine_vault_state(&path)?;
    if !allowed.contains(&state) {
        return Err(AppError::WrongState {
            expected: allowed
                .iter()
                .map(|state| state.as_str())
                .collect::<Vec<_>>()
                .join(" or "),
            // A vault of format 5, 6 or 7 is not broken, it is old: every command that resolves it
            // this way works once it has been migrated, so the state names the way out. The
            // reference is the one the user typed, so the hint can be pasted back into the shell.
            actual: if state == VaultState::NeedsMigration {
                format!("{state} (run `crypto migrate {reference}` first)")
            } else {
                state.as_str().to_string()
            },
        }
        .into());
    }
    ctx.registry().require_locked(&vault)?;
    Ok((vault, path))
}

/// The vault must be LOCKED -- both on disk (config + masterkey present, no partial state) and at
/// runtime. For every command that rewrites a key file of an otherwise intact vault.
pub fn locked_vault(ctx: &Ctx, reference: &str) -> Result<(VaultSettingsJson, PathBuf)> {
    vault_in_state(ctx, reference, &[VaultState::Locked])
}

/// [`locked_vault`] for `crypto migrate`: `NEEDS_MIGRATION` is allowed as well, because it is the
/// very state the command exists to end.
///
/// A daemon cannot be serving a *legacy* vault -- it could not open it -- but it can be serving a
/// format 8 one, and that is exactly the vault this command must refuse before it reports "already
/// at format 8"; [`vault_in_state`]'s runtime check does that.
pub fn migratable_vault(ctx: &Ctx, reference: &str) -> Result<(VaultSettingsJson, PathBuf)> {
    vault_in_state(
        ctx,
        reference,
        &[VaultState::Locked, VaultState::NeedsMigration],
    )
}

/// [`locked_vault`] for `crypto recovery-key restore`: a vault whose `vault.cryptomator` or whose
/// key files are gone is `VAULT_CONFIG_MISSING` or `ALL_MISSING`, and those are the states this
/// command exists to end. (A vault that has only lost its *masterkey* file still reports LOCKED:
/// `determine_vault_state` stops at the readable config.)
///
/// `MISSING` -- the directory is not there, or holds no `d/` at all -- and `NEEDS_MIGRATION` stay
/// refused: neither has key files this command could rebuild.
pub fn restorable_vault(ctx: &Ctx, reference: &str) -> Result<(VaultSettingsJson, PathBuf)> {
    vault_in_state(
        ctx,
        reference,
        &[
            VaultState::Locked,
            VaultState::VaultConfigMissing,
            VaultState::AllMissing,
        ],
    )
}

/// The `*.bkup` files sitting directly in `vault_path`, as a set that can be diffed around an
/// operation to report the backups *this run* created. Shared by `crypto migrate` and
/// `crypto recovery-key restore`, both of which let the core write backups without being told
/// where they went.
pub fn backup_files(vault_path: &Path) -> std::collections::BTreeSet<PathBuf> {
    let Ok(entries) = std::fs::read_dir(vault_path) else {
        return std::collections::BTreeSet::new();
    };
    entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "bkup"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_keychain_key_is_the_id_and_the_label_falls_back_to_it() {
        let keychain: Arc<dyn Keychain> = Arc::new(
            cryptomator_app::keychain::fake::FakeKeychain::at(std::path::Path::new("/dev/null")),
        );
        let mut vault = VaultSettingsJson::new(
            "vault-id".to_string(),
            std::path::Path::new("/vaults/My Vault"),
        );
        assert_eq!(vault_key_and_name(&vault), ("vault-id", Some("My Vault")));
        let source = keychain_source(Some(&keychain), &vault).expect("a source");
        assert_eq!(source.key, "vault-id");
        assert_eq!(source.vault_label, "My Vault");

        // A vault without a display name is named by its id in the "nothing stored" message.
        vault.display_name = None;
        let source = keychain_source(Some(&keychain), &vault).expect("a source");
        assert_eq!(source.vault_label, "vault-id");

        // No keychain, no source -- which is what turns `--password-keychain` into an error.
        assert!(keychain_source(None, &vault).is_none());
    }

    #[test]
    fn stream_ended_matches_a_gone_daemon() {
        assert!(stream_ended(&AppError::DaemonUnreachable(
            "connection refused".to_string()
        )));
    }

    #[test]
    fn stream_ended_matches_not_unlocked() {
        assert!(stream_ended(&AppError::DaemonError {
            code: ErrorBody::NOT_UNLOCKED.to_string(),
            message: "vault is locking".to_string(),
        }));
    }

    #[test]
    fn stream_ended_does_not_match_other_daemon_errors() {
        assert!(!stream_ended(&AppError::DaemonError {
            code: ErrorBody::MOUNT_FAILED.to_string(),
            message: "mount failed".to_string(),
        }));
    }
}
