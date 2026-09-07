//! Vault passphrases in the operating system's keychain, compatible with the desktop app's
//! entries.
//!
//! The trait is `org.cryptomator.integrations.keychain.KeychainAccessProvider` (integrations-api
//! 1.9.0) with two Rust-shaped differences: `load` answers `Ok(None)` where Java answers `null`,
//! and `delete`/`change` answer "was there an entry?" as a `bool` -- which is what
//! `MacKeychain.deletePassword` already does and what `KeychainManager.changePassphrase` needs.
//!
//! **Every** call from the CLI goes through [`with_timeout`]. Spike B
//! (`docs/superpowers/spikes/2026-09-04-spike-b-keychain.md`) showed macOS blocking indefinitely
//! in an ACL dialog that a non-interactive session cannot answer; `SecItemCopyMatching` has no
//! timeout of its own, so the only way out is a worker thread the caller stops waiting for.
use crate::error::AppError;
use std::fmt;
use std::sync::mpsc;
use std::time::Duration;
use zeroize::Zeroizing;

pub mod fake;
#[cfg(target_os = "linux")]
pub mod kde;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;

/// How long the CLI waits for one keychain call. Long enough for a human to answer a dialog,
/// short enough that a headless run fails instead of hanging forever.
pub const KEYCHAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Overrides the macOS/Secret-Service service name, like the desktop app's system property
/// `cryptomator.integrationsMac.keychainServiceName`.
pub const SERVICE_ENV: &str = "CRYPTO_KEYCHAIN_SERVICE";
/// `MacSystemKeychainAccess.SERVICE_NAME` and the Secret Service item label.
pub const DEFAULT_SERVICE: &str = "Cryptomator";

pub const MAC_SYSTEM_CLASS: &str = "org.cryptomator.macos.keychain.MacSystemKeychainAccess";
pub const MAC_TOUCH_ID_CLASS: &str = "org.cryptomator.macos.keychain.TouchIdKeychainAccess";
pub const SECRET_SERVICE_CLASS: &str = "org.cryptomator.linux.keychain.SecretServiceKeychainAccess";
pub const GNOME_KEYRING_CLASS: &str = "org.cryptomator.linux.keychain.GnomeKeyringKeychainAccess";
pub const KDE_WALLET_CLASS: &str = "org.cryptomator.linux.keychain.KDEWalletKeychainAccess";

/// Short names for `crypto config set keychainProvider`, in the order the error message lists
/// them. The stored value is always the Java class name, so the desktop app keeps reading its
/// own setting.
pub const KEYCHAIN_ALIASES: &[(&str, &str)] = &[
    ("macos", MAC_SYSTEM_CLASS),
    ("touchid", MAC_TOUCH_ID_CLASS),
    ("secret-service", SECRET_SERVICE_CLASS),
    ("gnome-keyring", GNOME_KEYRING_CLASS),
    ("kde", KDE_WALLET_CLASS),
    ("kwallet", KDE_WALLET_CLASS),
];

/// Alias (case-insensitive) or a fully qualified Java class name (must contain a dot).
///
/// # Errors
/// [`AppError::InvalidValue`] (exit code 2) for anything else.
pub fn resolve_keychain_provider(input: &str) -> Result<String, AppError> {
    let lowered = input.to_lowercase();
    if let Some((_, class)) = KEYCHAIN_ALIASES.iter().find(|(alias, _)| *alias == lowered) {
        return Ok((*class).to_string());
    }
    if input.contains('.') {
        return Ok(input.to_string());
    }
    Err(AppError::InvalidValue {
        key: "keychainProvider".to_string(),
        message: format!(
            "unknown keychain provider {input:?}; use one of {} or a Java class name",
            KEYCHAIN_ALIASES
                .iter()
                .map(|(alias, _)| *alias)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    })
}

/// The first alias of `class_name`, for human-readable output. `kwallet` never wins over `kde`
/// because it comes later in [`KEYCHAIN_ALIASES`].
pub fn alias_for_keychain(class_name: &str) -> Option<&'static str> {
    KEYCHAIN_ALIASES
        .iter()
        .find(|(_, class)| *class == class_name)
        .map(|(alias, _)| *alias)
}

/// The service name (macOS) / item label (Secret Service). An empty override counts as unset:
/// an empty service matches no item, so it could only ever hide entries.
pub fn service_name() -> String {
    match std::env::var(SERVICE_ENV) {
        Ok(value) if !value.is_empty() => value,
        _ => DEFAULT_SERVICE.to_string(),
    }
}

/// What a keychain backend can fail with. Never carries a passphrase: the fields are the
/// provider's name and whatever the backend itself said went wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeychainError {
    /// The backend cannot work on this machine (no Secret Service, KWallet, wrong OS).
    Unsupported { provider: String, hint: String },
    /// The keyring exists but is locked and nobody unlocked it.
    Locked { provider: String },
    /// The backend refused the call: the user cancelled the prompt, authentication failed, or the
    /// session may not show a prompt at all. Distinct from [`Self::Backend`] because it is the one
    /// failure the user can do something about without filing a bug.
    AccessDenied { provider: String, message: String },
    /// The call did not answer within `after` -- on macOS almost always an ACL dialog nobody is
    /// looking at. `after` is the budget the call actually had, which is [`KEYCHAIN_TIMEOUT`] for
    /// a real call and [`KEYCHAIN_PROBE_TIMEOUT`] for a support probe.
    TimedOut { provider: String, after: Duration },
    /// Anything the backend itself reported.
    Backend { provider: String, message: String },
}

impl fmt::Display for KeychainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported { provider, hint } => {
                write!(f, "{provider} cannot be used here: {hint}")
            }
            Self::Locked { provider } => {
                write!(f, "{provider} is locked; unlock the keyring and try again")
            }
            Self::AccessDenied { provider, message } => write!(
                f,
                "{provider} denied access: {message}; approve the keychain prompt (\"Always Allow\") and try again"
            ),
            // The wording the README documents. It deliberately does not name the provider: what
            // the user has to act on is the dialog, and callers that want the provider in their
            // message have [`KeychainError::provider`]. The number is the budget this very call
            // had, not the default -- a 5 s probe must not claim it waited 30 s.
            Self::TimedOut { after, .. } => write!(
                f,
                "the keychain did not answer within {} s; a system dialog may be waiting for you",
                after.as_secs()
            ),
            Self::Backend { provider, message } => write!(f, "{provider}: {message}"),
        }
    }
}

impl std::error::Error for KeychainError {}

impl KeychainError {
    /// The provider that failed, for the message the CLI prints.
    pub fn provider(&self) -> &str {
        match self {
            Self::Unsupported { provider, .. }
            | Self::Locked { provider }
            | Self::AccessDenied { provider, .. }
            | Self::TimedOut { provider, .. }
            | Self::Backend { provider, .. } => provider,
        }
    }
}

pub type KeychainResult<T> = std::result::Result<T, KeychainError>;

/// One vault passphrase store. `Sync` because [`with_timeout`] hands the call to another thread.
pub trait Keychain: Send + Sync + fmt::Debug {
    /// The name in `settings.json`'s `keychainProvider`.
    fn java_class_name(&self) -> &'static str;
    /// Javas `NamedServiceProvider.getName()`; a short, human-readable name.
    fn display_name(&self) -> &'static str;
    /// Javas `@Priority`; higher wins when `keychainProvider` names nothing usable.
    fn priority(&self) -> u32;
    /// Javas `isSupported()`: must not throw and must fail fast.
    fn is_supported(&self) -> bool;
    /// Javas `isLocked()`.
    fn is_locked(&self) -> bool;
    /// Javas `storePassphrase(key, displayName, passphrase)`; replaces an existing entry.
    fn store(&self, key: &str, display_name: Option<&str>, passphrase: &str) -> KeychainResult<()>;
    /// Javas `loadPassphrase(key)`; `Ok(None)` is Javas `null` -- nothing stored, not an error.
    fn load(&self, key: &str) -> KeychainResult<Option<Zeroizing<String>>>;
    /// Javas `deletePassphrase(key)`; `Ok(false)` when there was nothing to delete.
    fn delete(&self, key: &str) -> KeychainResult<bool>;
    /// Javas `changePassphrase(key, displayName, passphrase)`: "Noop, if there is no item for the
    /// given key". `Ok(false)` says it was that noop.
    fn change(
        &self,
        key: &str,
        display_name: Option<&str>,
        passphrase: &str,
    ) -> KeychainResult<bool>;
}

/// Runs `op` on a worker thread and gives up after [`KEYCHAIN_TIMEOUT`].
///
/// The worker is **not** cancelled on timeout -- a thread blocked in `securityd` or in a D-Bus
/// prompt cannot be. It is detached: it keeps its own end of a one-shot channel, so a late answer
/// goes nowhere and can never be handed to a later call, and the thread dies with the process.
/// That is why [`Keychain`] implementations are stateless and `Sync`: a leaked worker must not be
/// able to observe or corrupt anything the caller goes on to do.
pub fn with_timeout<T, F>(provider: &str, op: F) -> KeychainResult<T>
where
    T: Send + 'static,
    F: FnOnce() -> KeychainResult<T> + Send + 'static,
{
    with_timeout_for(provider, KEYCHAIN_TIMEOUT, op)
}

/// [`with_timeout`] with an explicit budget, so the tests do not have to wait 30 seconds.
pub fn with_timeout_for<T, F>(provider: &str, budget: Duration, op: F) -> KeychainResult<T>
where
    T: Send + 'static,
    F: FnOnce() -> KeychainResult<T> + Send + 'static,
{
    // A fresh channel per call, dropped with the call: a worker that answers after the timeout
    // sends into a receiver nobody holds any more, so its result cannot leak into a later call.
    let (tx, rx) = mpsc::sync_channel::<KeychainResult<T>>(1);
    // `sync_channel(1)`: the worker never blocks on the send, so a late answer does not keep the
    // thread alive any longer than the call it was making.
    let spawned = std::thread::Builder::new()
        .name("keychain".to_string())
        .spawn(move || {
            let _ = tx.send(op());
        });
    if let Err(err) = spawned {
        return Err(KeychainError::Backend {
            provider: provider.to_string(),
            message: format!("cannot start the keychain worker: {err}"),
        });
    }
    match rx.recv_timeout(budget) {
        Ok(result) => result,
        // The budget goes into the error so the message states what this call actually waited --
        // `supported_or_skipped` passes `KEYCHAIN_PROBE_TIMEOUT`, not `KEYCHAIN_TIMEOUT`.
        Err(mpsc::RecvTimeoutError::Timeout) => Err(KeychainError::TimedOut {
            provider: provider.to_string(),
            after: budget,
        }),
        // The worker panicked and dropped its sender.
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(KeychainError::Backend {
            provider: provider.to_string(),
            message: "the keychain worker stopped unexpectedly".to_string(),
        }),
    }
}

/// How long a support probe may take before the provider counts as unusable.
///
/// `is_supported()` is documented as "must not throw and must fail fast", but on Linux it is a
/// D-Bus round trip and on macOS it can wake `securityd`, so it is not actually guaranteed to
/// answer. The registry therefore probes through [`with_timeout_for`] with a much shorter budget
/// than a real call gets: choosing a provider must not cost the user 30 seconds per candidate.
pub const KEYCHAIN_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// The provider class a settings value is served from.
///
/// Ruling 6: `TouchIdKeychainAccess` and `MacSystemKeychainAccess` address the *same* generic
/// password items (same service, same account); only `requireOsAuthentication` differs, and the
/// CLI cannot set that. So a `settings.json` that names the Touch-ID provider is served from the
/// macOS backend -- reading and deleting work, and newly written items simply have no Touch-ID
/// access control.
pub fn canonical_provider_class(class_name: &str) -> &str {
    if class_name == MAC_TOUCH_ID_CLASS {
        MAC_SYSTEM_CLASS
    } else {
        class_name
    }
}

/// The Java class name `settings.keychainProvider` asks for, after alias resolution
/// ([`resolve_keychain_provider`]) and [`canonical_provider_class`].
///
/// An unusable value is *not* an error here: `KeychainModule.provideKeychainAccessProvider` falls
/// back to the highest-priority supported provider for anything it does not recognise, and so do
/// we. `crypto config set keychainProvider` is the place that rejects nonsense.
fn wanted_provider_class(settings: &crate::settings::SettingsJson) -> String {
    let resolved = resolve_keychain_provider(&settings.keychain_provider)
        .unwrap_or_else(|_| settings.keychain_provider.clone());
    canonical_provider_class(&resolved).to_string()
}

/// `provider` if it says it is supported within [`KEYCHAIN_PROBE_TIMEOUT`], otherwise `None`.
///
/// The provider is moved into the worker and handed back with the answer, because the worker
/// outlives a timed-out call: a probe that hangs takes its provider with it rather than leaving
/// the caller with a borrow into a thread nobody can stop.
fn supported_or_skipped(provider: Box<dyn Keychain>) -> Option<Box<dyn Keychain>> {
    let name = provider.display_name();
    match with_timeout_for(name, KEYCHAIN_PROBE_TIMEOUT, move || {
        let supported = provider.is_supported();
        Ok((provider, supported))
    }) {
        Ok((provider, true)) => Some(provider),
        Ok((_, false)) => None,
        // A probe that times out counts as unsupported: the alternative is hanging the CLI on a
        // backend that cannot even answer whether it exists.
        Err(err) => {
            log::warn!("skipping keychain provider {name}: {err}");
            None
        }
    }
}

/// Every provider this build knows, highest [`Keychain::priority`] first.
///
/// While `$CRYPTO_KEYCHAIN_FAKE` is set this is exactly one entry -- the fake -- so no test can
/// reach the user's real keychain (ruling 8). The fake also carries the highest priority, so it
/// would win any selection even if a future caller mixed it with the real ones.
///
/// The list is *not* filtered by [`Keychain::is_supported`]: that probe belongs to the choice
/// ([`for_settings`], which makes it through [`KEYCHAIN_PROBE_TIMEOUT`]), while `crypto keychain
/// test` wants to report on the unsupported ones too.
pub fn all_providers() -> Vec<Box<dyn Keychain>> {
    if let Some(fake) = fake::FakeKeychain::from_env() {
        return vec![Box::new(fake)];
    }
    let mut providers: Vec<Box<dyn Keychain>> = Vec::new();
    #[cfg(target_os = "macos")]
    providers.push(Box::new(macos::MacKeychain::new()));
    // The Linux and KDE back ends arrive in task 4.
    providers.extend(std::iter::empty());
    providers.sort_by_key(|provider| std::cmp::Reverse(provider.priority()));
    providers
}

/// `KeychainModule.provideKeychainAccessProvider`: nothing when `useKeychain` is off, otherwise
/// the supported provider whose Java class name matches, otherwise the highest-priority supported
/// one.
///
/// Every `is_supported()` call here goes through [`KEYCHAIN_PROBE_TIMEOUT`]; a provider that does
/// not answer is skipped with a warning.
pub fn for_settings(settings: &crate::settings::SettingsJson) -> Option<Box<dyn Keychain>> {
    if !settings.use_keychain {
        return None;
    }
    let wanted = wanted_provider_class(settings);
    let mut fallback: Option<Box<dyn Keychain>> = None;
    for provider in all_providers() {
        let Some(provider) = supported_or_skipped(provider) else {
            continue;
        };
        if provider.java_class_name() == wanted {
            return Some(provider);
        }
        // `all_providers` is sorted, so the first survivor is the highest-priority one.
        if fallback.is_none() {
            fallback = Some(provider);
        }
    }
    fallback
}

#[cfg(test)]
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// A provider that answers instantly, so the trait itself can be exercised without a keychain.
    #[derive(Debug, Default)]
    struct Dummy {
        calls: Arc<AtomicUsize>,
    }

    impl Keychain for Dummy {
        fn java_class_name(&self) -> &'static str {
            "org.example.Dummy"
        }
        fn display_name(&self) -> &'static str {
            "Dummy"
        }
        fn priority(&self) -> u32 {
            1
        }
        fn is_supported(&self) -> bool {
            true
        }
        fn is_locked(&self) -> bool {
            false
        }
        fn store(&self, _key: &str, _name: Option<&str>, _pw: &str) -> KeychainResult<()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn load(&self, key: &str) -> KeychainResult<Option<Zeroizing<String>>> {
            Ok((key == "known").then(|| Zeroizing::new("secret".to_string())))
        }
        fn delete(&self, key: &str) -> KeychainResult<bool> {
            Ok(key == "known")
        }
        fn change(&self, key: &str, _name: Option<&str>, _pw: &str) -> KeychainResult<bool> {
            Ok(key == "known")
        }
    }

    #[test]
    fn aliases_map_to_java_class_names_and_back() {
        assert_eq!(
            resolve_keychain_provider("macos").unwrap(),
            MAC_SYSTEM_CLASS
        );
        assert_eq!(
            resolve_keychain_provider("MacOS").unwrap(),
            MAC_SYSTEM_CLASS
        );
        assert_eq!(
            resolve_keychain_provider("touchid").unwrap(),
            MAC_TOUCH_ID_CLASS
        );
        assert_eq!(
            resolve_keychain_provider("secret-service").unwrap(),
            SECRET_SERVICE_CLASS
        );
        assert_eq!(
            resolve_keychain_provider("gnome-keyring").unwrap(),
            GNOME_KEYRING_CLASS
        );
        assert_eq!(resolve_keychain_provider("kde").unwrap(), KDE_WALLET_CLASS);
        assert_eq!(
            resolve_keychain_provider("kwallet").unwrap(),
            KDE_WALLET_CLASS
        );
        // A fully qualified class name passes through, so an unknown desktop provider survives.
        assert_eq!(
            resolve_keychain_provider("org.example.Other").unwrap(),
            "org.example.Other"
        );
        // Something that is neither is a usage error that names the aliases.
        let err = resolve_keychain_provider("nonsense").unwrap_err();
        assert!(err.to_string().contains("gnome-keyring"), "{err}");

        assert_eq!(alias_for_keychain(MAC_SYSTEM_CLASS), Some("macos"));
        assert_eq!(
            alias_for_keychain(GNOME_KEYRING_CLASS),
            Some("gnome-keyring")
        );
        assert_eq!(alias_for_keychain("org.example.Other"), None);
    }

    #[test]
    fn the_service_name_defaults_to_cryptomator_and_can_be_overridden() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var(SERVICE_ENV);
        assert_eq!(service_name(), DEFAULT_SERVICE);
        std::env::set_var(SERVICE_ENV, "Cryptomator-Test");
        assert_eq!(service_name(), "Cryptomator-Test");
        // An empty override is no override: Java's `getProperty(name, default)` would return "",
        // but an empty service name matches nothing, so we treat it as unset.
        std::env::set_var(SERVICE_ENV, "");
        assert_eq!(service_name(), DEFAULT_SERVICE);
        std::env::remove_var(SERVICE_ENV);
    }

    #[test]
    fn a_call_that_answers_in_time_is_passed_through() {
        assert_eq!(with_timeout("p", || Ok(7)).unwrap(), 7);
        let err = with_timeout::<(), _>("p", || {
            Err(KeychainError::Backend {
                provider: "p".to_string(),
                message: "boom".to_string(),
            })
        })
        .unwrap_err();
        assert!(matches!(err, KeychainError::Backend { .. }));
    }

    #[test]
    fn a_call_that_never_answers_becomes_a_timeout() {
        // The worker outlives the call on purpose -- a thread stuck in securityd cannot be
        // cancelled. It releases the barrier so the test itself does not leak a blocked thread
        // for longer than the test binary lives.
        let gate = Arc::new(std::sync::Barrier::new(2));
        let in_worker = Arc::clone(&gate);
        let started = std::time::Instant::now();
        let err = with_timeout_for("p", Duration::from_millis(150), move || {
            in_worker.wait();
            Ok(())
        })
        .unwrap_err();
        assert!(started.elapsed() >= Duration::from_millis(150));
        match err {
            KeychainError::TimedOut {
                ref provider,
                after,
            } => {
                assert_eq!(provider, "p");
                // The budget the call actually had, not the default -- see
                // `a_timeout_message_states_the_budget_the_call_actually_had`.
                assert_eq!(after, Duration::from_millis(150));
            }
            ref other => panic!("expected TimedOut, got {other}"),
        }
        assert!(
            err_hint_mentions_dialog(&KeychainError::TimedOut {
                provider: "p".to_string(),
                after: KEYCHAIN_TIMEOUT,
            }),
            "the message has to tell the user a dialog may be waiting"
        );
        gate.wait();
    }

    /// A probe gets 5 seconds, a real call 30. The message has to say which one ran out, or the
    /// warning `supported_or_skipped` logs sends whoever reads it looking for a 30-second hang
    /// that never happened.
    #[test]
    fn a_timeout_message_states_the_budget_the_call_actually_had() {
        let default = KeychainError::TimedOut {
            provider: "p".to_string(),
            after: KEYCHAIN_TIMEOUT,
        };
        assert!(default.to_string().contains("within 30 s"), "{default}");
        let probe = KeychainError::TimedOut {
            provider: "p".to_string(),
            after: KEYCHAIN_PROBE_TIMEOUT,
        };
        assert!(probe.to_string().contains("within 5 s"), "{probe}");
    }

    /// A late answer from a worker the caller gave up on must not be handed to the next call.
    #[test]
    fn a_late_answer_never_reaches_a_later_call() {
        let gate = Arc::new(std::sync::Barrier::new(2));
        let in_worker = Arc::clone(&gate);
        let timed_out = with_timeout_for("p", Duration::from_millis(150), move || {
            in_worker.wait();
            Ok(1_u32)
        })
        .unwrap_err();
        assert!(matches!(timed_out, KeychainError::TimedOut { .. }));
        // Let the abandoned worker finish while the next call is in flight.
        gate.wait();
        assert_eq!(with_timeout("p", || Ok(2_u32)).unwrap(), 2);
    }

    #[test]
    fn the_trait_reports_a_missing_entry_as_none_not_as_an_error() {
        let dummy = Dummy::default();
        assert!(dummy.load("known").unwrap().is_some());
        assert!(dummy.load("other").unwrap().is_none());
        assert!(dummy.delete("known").unwrap());
        assert!(!dummy.delete("other").unwrap());
        assert!(dummy.change("known", Some("V"), "pw").unwrap());
        assert!(!dummy.change("other", Some("V"), "pw").unwrap());
        // `store` is the one call with no answer to check, so the dummy counts it.
        dummy.store("known", Some("V"), "pw").unwrap();
        assert_eq!(dummy.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn the_fake_takes_over_the_whole_registry_when_it_is_switched_on() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().expect("temp dir");
        std::env::set_var(fake::FAKE_ENV, dir.path().join("kc.json"));
        let providers = all_providers();
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].java_class_name(), fake::FAKE_CLASS);
        std::env::remove_var(fake::FAKE_ENV);
    }

    #[test]
    fn for_settings_follows_the_desktop_apps_keychain_module() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var(fake::FAKE_UNSUPPORTED_ENV);
        let dir = tempfile::tempdir().expect("temp dir");
        std::env::set_var(fake::FAKE_ENV, dir.path().join("kc.json"));

        // useKeychain == false is Javas `return null`.
        let mut settings = crate::settings::SettingsJson {
            use_keychain: false,
            ..Default::default()
        };
        assert!(for_settings(&settings).is_none());

        // A provider nobody supports falls back to the first supported one.
        settings.use_keychain = true;
        settings.keychain_provider = KDE_WALLET_CLASS.to_string();
        assert_eq!(
            for_settings(&settings).expect("fallback").java_class_name(),
            fake::FAKE_CLASS
        );

        // And the matching one wins when it is there.
        settings.keychain_provider = fake::FAKE_CLASS.to_string();
        assert_eq!(
            for_settings(&settings).expect("exact").java_class_name(),
            fake::FAKE_CLASS
        );

        // Nothing supported at all is `None`, not the unsupported provider.
        std::env::set_var(fake::FAKE_UNSUPPORTED_ENV, "1");
        assert!(for_settings(&settings).is_none());
        std::env::remove_var(fake::FAKE_UNSUPPORTED_ENV);
        std::env::remove_var(fake::FAKE_ENV);
    }

    #[test]
    fn touch_id_in_the_settings_resolves_to_the_macos_backend() {
        // Ruling 6: the two Java providers write the same generic-password items, so the CLI
        // serves `TouchIdKeychainAccess` from the macOS backend instead of refusing it.
        assert_eq!(
            canonical_provider_class(MAC_TOUCH_ID_CLASS),
            MAC_SYSTEM_CLASS
        );
        assert_eq!(canonical_provider_class(MAC_SYSTEM_CLASS), MAC_SYSTEM_CLASS);
        assert_eq!(canonical_provider_class(KDE_WALLET_CLASS), KDE_WALLET_CLASS);
    }

    #[test]
    fn a_settings_value_may_be_an_alias_and_is_canonicalised() {
        let mut settings = crate::settings::SettingsJson {
            keychain_provider: "touchid".to_string(),
            ..Default::default()
        };
        assert_eq!(wanted_provider_class(&settings), MAC_SYSTEM_CLASS);
        settings.keychain_provider = MAC_TOUCH_ID_CLASS.to_string();
        assert_eq!(wanted_provider_class(&settings), MAC_SYSTEM_CLASS);
        settings.keychain_provider = "kwallet".to_string();
        assert_eq!(wanted_provider_class(&settings), KDE_WALLET_CLASS);
        // Something the CLI does not know is carried through and simply matches nothing.
        settings.keychain_provider = "nonsense".to_string();
        assert_eq!(wanted_provider_class(&settings), "nonsense");
    }

    #[test]
    fn providers_are_ordered_by_priority_descending() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var(fake::FAKE_ENV);
        let providers = all_providers();
        let priorities: Vec<u32> = providers.iter().map(|p| p.priority()).collect();
        assert!(
            priorities.windows(2).all(|w| w[0] >= w[1]),
            "{priorities:?}"
        );
        // The Linux back ends arrive in task 4; on macOS the registry is already populated.
        #[cfg(target_os = "macos")]
        {
            assert!(!priorities.is_empty());
            assert_eq!(priorities, vec![macos::MAC_PRIORITY]);
            assert_eq!(providers[0].java_class_name(), MAC_SYSTEM_CLASS);
        }
    }

    fn err_hint_mentions_dialog(err: &KeychainError) -> bool {
        let text = err.to_string();
        text.contains("30") && text.contains("dialog")
    }
}
