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
    /// The call did not answer within [`KEYCHAIN_TIMEOUT`] -- on macOS almost always an ACL
    /// dialog nobody is looking at.
    TimedOut { provider: String },
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
            // The wording the README documents, verbatim. It deliberately does not name the
            // provider: what the user has to act on is the dialog, and callers that want the
            // provider in their message have [`KeychainError::provider`].
            Self::TimedOut { .. } => write!(
                f,
                "the keychain did not answer within {} s; a system dialog may be waiting for you",
                KEYCHAIN_TIMEOUT.as_secs()
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
            | Self::TimedOut { provider }
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
        Err(mpsc::RecvTimeoutError::Timeout) => Err(KeychainError::TimedOut {
            provider: provider.to_string(),
        }),
        // The worker panicked and dropped its sender.
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(KeychainError::Backend {
            provider: provider.to_string(),
            message: "the keychain worker stopped unexpectedly".to_string(),
        }),
    }
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
            KeychainError::TimedOut { provider } => assert_eq!(provider, "p"),
            other => panic!("expected TimedOut, got {other}"),
        }
        assert!(
            err_hint_mentions_dialog(&KeychainError::TimedOut {
                provider: "p".to_string()
            }),
            "the message has to tell the user a dialog may be waiting"
        );
        gate.wait();
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

    fn err_hint_mentions_dialog(err: &KeychainError) -> bool {
        let text = err.to_string();
        text.contains("30") && text.contains("dialog")
    }
}
