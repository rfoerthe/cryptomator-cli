//! Passphrases in the FreeDesktop Secret Service (gnome-keyring, KeePassXC, KWallet's SS bridge).
//!
//! Shape of an item, matching what the desktop app's `integrations-linux` writes:
//!
//! | part       | value                                             |
//! |------------|---------------------------------------------------|
//! | collection | the default one, `login` when there is no default  |
//! | label      | `"Cryptomator"` (`$CRYPTO_KEYCHAIN_SERVICE`)       |
//! | attributes | `{"Vault": <vault id>, "Name": <display name>}`    |
//! | lookup     | `{"Vault": <vault id>}` -- never `Name`            |
//! | secret     | the passphrase, UTF-8, content type `text/plain`   |
//!
//! `GnomeKeyringKeychainAccess` is the same backend without the `Name` attribute, which is why
//! the lookup deliberately ignores `Name`: a renamed vault must still find its passphrase, and an
//! item written by either variant must be found by both.
//!
//! **Provenance:** `~/.m2/repository/org/cryptomator/integrations-linux/` does not exist on the
//! development machine, so this table comes from the design spec rather than from read Java
//! source. `crates/cryptomator-app/tests/keychain_e2e.rs` checks it against a live gnome-keyring,
//! and until that has run on Linux the shape is unverified.
//!
//! Blocking on purpose: `secret_service::blocking` drives zbus's blocking API, and with the
//! `tokio` feature `zbus::block_on` builds its own runtime in a `OnceLock`. That works outside a
//! tokio runtime -- which is where this always runs, namely on the worker thread of
//! [`crate::keychain::with_timeout`] -- and must never be called from inside one.
//!
//! One connection per operation: `Collection` and `Item` borrow the `SecretService` they came
//! from, so a connection cannot be stored in `self` (`SecretService<'static>` does not
//! borrow-check, and [`crate::keychain::Keychain`] is shared across threads). Every operation
//! therefore goes through [`SecretServiceKeychain::with_connection`], which connects, works and
//! disconnects again -- a Unix-socket handshake plus one DH exchange, and the CLI makes at most a
//! handful of keychain calls per run.
use super::{
    service_name, Keychain, KeychainError, KeychainResult, GNOME_KEYRING_CLASS,
    SECRET_SERVICE_CLASS,
};
use secret_service::blocking::{Collection, SecretService};
use secret_service::{EncryptionType, Error as SsError};
use std::collections::HashMap;
use zeroize::Zeroizing;

/// Our own order, not a Java annotation: `integrations-linux` sources are not available here.
/// GNOME Keyring goes first because `Settings.DEFAULT_KEYCHAIN_PROVIDER` picks it on Linux.
pub const GNOME_KEYRING_PRIORITY: u32 = 1010;
/// The generic Secret Service provider, one step below GNOME Keyring; see
/// [`GNOME_KEYRING_PRIORITY`].
pub const SECRET_SERVICE_PRIORITY: u32 = 1000;

/// The attribute every item is found by.
pub const VAULT_ATTRIBUTE: &str = "Vault";
/// The extra attribute `SecretServiceKeychainAccess` writes and `GnomeKeyringKeychainAccess` does
/// not.
pub const NAME_ATTRIBUTE: &str = "Name";
/// The secret's content type.
pub const CONTENT_TYPE: &str = "text/plain";
/// The collection to fall back to when the service names no default one.
pub const LOGIN_COLLECTION_ALIAS: &str = "login";

const SECRET_SERVICE_DISPLAY_NAME: &str = "FreeDesktop Secret Service";
const GNOME_KEYRING_DISPLAY_NAME: &str = "GNOME Keyring (secret service)";

/// What a missing Secret Service provider means for the user, and what to do about it.
const UNAVAILABLE_HINT: &str = "no secret service is running on the session bus; start \
                                gnome-keyring (or another Secret Service provider), or set \
                                useKeychain to false";
/// A prompt the user dismissed, or one that could not be shown at all.
const PROMPT_HINT: &str = "answer the keyring dialog instead of dismissing it, or unlock the \
                           keyring before running crypto";

/// Which of the two Java providers this instance is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    /// `SecretServiceKeychainAccess`: writes `Vault` **and** `Name`.
    SecretService,
    /// `GnomeKeyringKeychainAccess`: writes only `Vault`.
    GnomeKeyring,
}

/// One Secret Service backend. The two Java providers differ only in the attributes they write,
/// their class name and their priority -- the D-Bus interface behind them is the same one.
#[derive(Debug, Clone)]
pub struct SecretServiceKeychain {
    variant: Variant,
    service: String,
}

impl SecretServiceKeychain {
    /// `SecretServiceKeychainAccess`.
    pub fn secret_service() -> Self {
        Self::with_service(Variant::SecretService, service_name())
    }

    /// `GnomeKeyringKeychainAccess`.
    pub fn gnome_keyring() -> Self {
        Self::with_service(Variant::GnomeKeyring, service_name())
    }

    /// The same backend against an explicit label, for tests that must not depend on the
    /// environment.
    pub fn with_service(variant: Variant, service: String) -> Self {
        Self { variant, service }
    }

    /// Which of the two Java providers this is.
    pub fn variant(&self) -> Variant {
        self.variant
    }

    /// The item label, which is the service name -- `"Cryptomator"` unless overridden.
    pub fn label(&self) -> &str {
        &self.service
    }

    /// What `create_item` writes.
    pub fn attributes<'a>(
        &self,
        key: &'a str,
        display_name: Option<&'a str>,
    ) -> Vec<(&'static str, &'a str)> {
        let mut attributes = vec![(VAULT_ATTRIBUTE, key)];
        if self.variant == Variant::SecretService {
            if let Some(name) = display_name {
                attributes.push((NAME_ATTRIBUTE, name));
            }
        }
        attributes
    }

    /// What `search_items` looks for: the vault id alone, so a rename never hides an item.
    pub fn search_attributes<'a>(&self, key: &'a str) -> Vec<(&'static str, &'a str)> {
        vec![(VAULT_ATTRIBUTE, key)]
    }

    /// The `SsError` -> [`KeychainError`] mapping, pure so it can be tested without a bus.
    ///
    /// `Unavailable` is the only "this machine cannot do it" answer; `Locked` is the user's to
    /// fix; a dismissed prompt (and a connection that died while one was open) is the user saying
    /// no, which is [`KeychainError::AccessDenied`] -- the same shape the macOS backend gives a
    /// cancelled dialog. Everything else is the backend's own words.
    pub fn map(&self, err: SsError) -> KeychainError {
        let provider = self.display_name().to_string();
        let message = err.to_string();
        match err {
            SsError::Unavailable => KeychainError::Unsupported {
                provider,
                hint: UNAVAILABLE_HINT.to_string(),
            },
            SsError::Locked => KeychainError::Locked { provider },
            SsError::Prompt | SsError::PromptDisconnected => KeychainError::AccessDenied {
                provider,
                message,
                hint: PROMPT_HINT.to_string(),
            },
            _ => KeychainError::Backend { provider, message },
        }
    }

    /// Runs `f` against a fresh session-bus connection and drops it again; see the module docs for
    /// why the connection cannot live in `self`.
    fn with_connection<R>(
        &self,
        f: impl FnOnce(&SecretService<'_>) -> KeychainResult<R>,
    ) -> KeychainResult<R> {
        // `Dh`: the secret travels encrypted over the bus, like every other Secret Service client.
        let service = SecretService::connect(EncryptionType::Dh).map_err(|err| self.map(err))?;
        f(&service)
    }

    /// The default collection, or the one aliased `login`. `get_default_collection` already
    /// resolves the `default` alias; the fallback covers the keyrings that only have `login`.
    fn collection<'a>(&self, service: &'a SecretService<'a>) -> KeychainResult<Collection<'a>> {
        match service.get_default_collection() {
            Ok(collection) => Ok(collection),
            Err(SsError::NoResult) => service
                .get_collection_by_alias(LOGIN_COLLECTION_ALIAS)
                .map_err(|err| self.map(err)),
            Err(err) => Err(self.map(err)),
        }
    }

    /// The collection, refusing a locked one.
    ///
    /// `Collection::ensure_unlocked` reports `Locked` *without* prompting, which is what we want:
    /// `unlock()` raises a desktop dialog, and the CLI is often headless and never the right place
    /// to answer one. Javas providers do not unlock either -- they let the call fail and leave the
    /// keyring to the user. So a locked keyring is [`KeychainError::Locked`], every time.
    fn unlocked<'a>(&self, service: &'a SecretService<'a>) -> KeychainResult<Collection<'a>> {
        let collection = self.collection(service)?;
        collection.ensure_unlocked().map_err(|err| self.map(err))?;
        Ok(collection)
    }

    /// `CreateItem` with `replace = true`, plus the cleanup that keeps "one item per vault" true.
    ///
    /// `replace` only replaces an item whose attribute set is *identical*. The `Name` attribute is
    /// part of that set for [`Variant::SecretService`], so storing a renamed vault -- or storing
    /// with this variant over an item the GNOME one wrote -- would add a second item for the same
    /// `Vault` and leave `load` with two to choose from. The leftovers are therefore removed after
    /// the write. The passphrase is stored at that point, so a failing cleanup is a warning, not
    /// an error: the caller asked for the passphrase to be stored, and it is.
    fn write<'a>(
        &self,
        collection: &'a Collection<'a>,
        key: &str,
        display_name: Option<&str>,
        passphrase: &str,
    ) -> KeychainResult<()> {
        let attributes: HashMap<&str, &str> =
            self.attributes(key, display_name).into_iter().collect();
        let created = collection
            .create_item(
                self.label(),
                attributes,
                passphrase.as_bytes(),
                // `replace = true`: one item per vault, like the desktop app.
                true,
                CONTENT_TYPE,
            )
            .map_err(|err| self.map(err))?;
        match collection.search_items(self.search_attributes(key).into_iter().collect()) {
            Ok(items) => {
                for stale in items.iter().filter(|item| **item != created) {
                    if let Err(err) = stale.delete() {
                        // Neither branch can carry the passphrase: `map` only ever sees the
                        // Secret Service's own words, and the vault id is not part of them.
                        log::warn!(
                            "could not remove a superseded keychain item: {}",
                            self.map(err)
                        );
                    }
                }
            }
            Err(err) => log::warn!(
                "could not look for superseded keychain items: {}",
                self.map(err)
            ),
        }
        Ok(())
    }
}

impl Keychain for SecretServiceKeychain {
    fn java_class_name(&self) -> &'static str {
        match self.variant {
            Variant::SecretService => SECRET_SERVICE_CLASS,
            Variant::GnomeKeyring => GNOME_KEYRING_CLASS,
        }
    }

    fn display_name(&self) -> &'static str {
        match self.variant {
            Variant::SecretService => SECRET_SERVICE_DISPLAY_NAME,
            Variant::GnomeKeyring => GNOME_KEYRING_DISPLAY_NAME,
        }
    }

    fn priority(&self) -> u32 {
        match self.variant {
            Variant::SecretService => SECRET_SERVICE_PRIORITY,
            Variant::GnomeKeyring => GNOME_KEYRING_PRIORITY,
        }
    }

    /// "must not throw any exceptions and should fail fast": a connection attempt and nothing
    /// else. No session bus, or nothing serving `org.freedesktop.secrets` on it, is `false`.
    ///
    /// There is no timeout here on purpose -- the registry probes this through
    /// [`crate::keychain::KEYCHAIN_PROBE_TIMEOUT`], and a second one inside would only make the
    /// budget harder to reason about.
    fn is_supported(&self) -> bool {
        SecretService::connect(EncryptionType::Dh).is_ok()
    }

    /// Whether the collection this backend writes to is locked. Anything that stops us from even
    /// asking (no bus, no collection) is `false`: `isLocked()` answers a question about a keyring
    /// that is there, and a keyring that is not there is [`Keychain::is_supported`]'s business.
    fn is_locked(&self) -> bool {
        self.with_connection(|service| {
            let collection = self.collection(service)?;
            Ok(collection.is_locked().unwrap_or(false))
        })
        .unwrap_or(false)
    }

    fn store(&self, key: &str, display_name: Option<&str>, passphrase: &str) -> KeychainResult<()> {
        self.with_connection(|service| {
            let collection = self.unlocked(service)?;
            self.write(&collection, key, display_name, passphrase)
        })
    }

    fn load(&self, key: &str) -> KeychainResult<Option<Zeroizing<String>>> {
        self.with_connection(|service| {
            let collection = self.unlocked(service)?;
            let items = collection
                .search_items(self.search_attributes(key).into_iter().collect())
                .map_err(|err| self.map(err))?;
            let Some(item) = items.first() else {
                return Ok(None);
            };
            // An item can be locked on its own (KeePassXC does that per entry). Like the
            // collection, it is reported rather than unlocked.
            item.ensure_unlocked().map_err(|err| self.map(err))?;
            let secret = Zeroizing::new(item.get_secret().map_err(|err| self.map(err))?);
            let text = std::str::from_utf8(&secret).map_err(|_| KeychainError::Backend {
                provider: self.display_name().to_string(),
                message: "the stored passphrase is not valid UTF-8".to_string(),
            })?;
            Ok(Some(Zeroizing::new(text.to_string())))
        })
    }

    fn delete(&self, key: &str) -> KeychainResult<bool> {
        self.with_connection(|service| {
            let collection = self.unlocked(service)?;
            let items = collection
                .search_items(self.search_attributes(key).into_iter().collect())
                .map_err(|err| self.map(err))?;
            if items.is_empty() {
                return Ok(false);
            }
            // Several items for one vault should not happen ([`Self::write`] cleans them up), but
            // a keyring that has them from an older version must end up empty, not half empty.
            for item in &items {
                item.delete().map_err(|err| self.map(err))?;
            }
            Ok(true)
        })
    }

    fn change(
        &self,
        key: &str,
        display_name: Option<&str>,
        passphrase: &str,
    ) -> KeychainResult<bool> {
        self.with_connection(|service| {
            let collection = self.unlocked(service)?;
            // Javas `changePassphrase` is "Noop, if there is no item for the given key". The
            // *search* answers that without reading -- and without decrypting -- the passphrase
            // that is about to be overwritten anyway.
            let items = collection
                .search_items(self.search_attributes(key).into_iter().collect())
                .map_err(|err| self.map(err))?;
            if items.is_empty() {
                return Ok(false);
            }
            // No delete first: `create_item` replaces, and `write` removes whatever the replace
            // could not match (a changed `Name`).
            self.write(&collection, key, display_name, passphrase)?;
            Ok(true)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keychain::{DEFAULT_SERVICE, ENV_LOCK, SERVICE_ENV};

    #[test]
    fn the_two_variants_differ_only_in_the_name_attribute() {
        let ss = SecretServiceKeychain::secret_service();
        let gnome = SecretServiceKeychain::gnome_keyring();
        assert_eq!(ss.java_class_name(), SECRET_SERVICE_CLASS);
        assert_eq!(gnome.java_class_name(), GNOME_KEYRING_CLASS);
        assert_eq!(gnome.priority(), GNOME_KEYRING_PRIORITY);
        assert_eq!(ss.priority(), SECRET_SERVICE_PRIORITY);
        assert!(
            gnome.priority() > ss.priority(),
            "the desktop app's Linux default is GnomeKeyringKeychainAccess"
        );
        assert_eq!(ss.variant(), Variant::SecretService);
        assert_eq!(gnome.variant(), Variant::GnomeKeyring);

        assert_eq!(
            ss.attributes("v1", Some("Secret")),
            vec![(VAULT_ATTRIBUTE, "v1"), (NAME_ATTRIBUTE, "Secret")]
        );
        assert_eq!(
            gnome.attributes("v1", Some("Secret")),
            vec![(VAULT_ATTRIBUTE, "v1")],
            "GnomeKeyringKeychainAccess writes no Name"
        );
        // Without a display name even the Secret Service variant writes only `Vault`.
        assert_eq!(ss.attributes("v1", None), vec![(VAULT_ATTRIBUTE, "v1")]);
        // The *search* never uses `Name`: renaming a vault must not lose its passphrase.
        assert_eq!(ss.search_attributes("v1"), vec![(VAULT_ATTRIBUTE, "v1")]);
        assert_eq!(gnome.search_attributes("v1"), vec![(VAULT_ATTRIBUTE, "v1")]);
    }

    #[test]
    fn the_label_is_the_service_name() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var(SERVICE_ENV);
        assert_eq!(
            SecretServiceKeychain::secret_service().label(),
            DEFAULT_SERVICE
        );
        assert_eq!(
            SecretServiceKeychain::with_service(Variant::GnomeKeyring, "Other".to_string()).label(),
            "Other"
        );
        std::env::set_var(SERVICE_ENV, "From the environment");
        assert_eq!(
            SecretServiceKeychain::gnome_keyring().label(),
            "From the environment"
        );
        std::env::remove_var(SERVICE_ENV);
    }

    #[test]
    fn dbus_errors_are_mapped_to_the_right_keychain_error() {
        let gnome = SecretServiceKeychain::gnome_keyring();
        assert!(matches!(
            gnome.map(SsError::Unavailable),
            KeychainError::Unsupported { .. }
        ));
        assert!(matches!(
            gnome.map(SsError::Locked),
            KeychainError::Locked { .. }
        ));
        // A dismissed prompt is the user saying no: it is not a broken keychain, but it is also
        // not a missing entry, so it has to surface -- with the hint that says what to do next.
        assert!(matches!(
            gnome.map(SsError::Prompt),
            KeychainError::AccessDenied { .. }
        ));
        assert!(matches!(
            gnome.map(SsError::PromptDisconnected),
            KeychainError::AccessDenied { .. }
        ));
        assert!(matches!(
            gnome.map(SsError::NoResult),
            KeychainError::Backend { .. }
        ));
        let text = gnome.map(SsError::Unavailable).to_string();
        assert!(
            text.contains("gnome-keyring") || text.contains("secret service"),
            "{text}"
        );
        // No message this backend produces carries a passphrase or a vault id -- it only ever
        // repeats what the Secret Service itself said.
        for err in [
            gnome.map(SsError::Unavailable),
            gnome.map(SsError::Locked),
            gnome.map(SsError::Prompt),
            gnome.map(SsError::NoResult),
        ] {
            assert_eq!(err.provider(), GNOME_KEYRING_DISPLAY_NAME);
        }
        assert_eq!(
            SecretServiceKeychain::secret_service()
                .map(SsError::Locked)
                .provider(),
            SECRET_SERVICE_DISPLAY_NAME
        );
    }

    #[test]
    fn is_supported_is_false_without_a_session_bus() {
        // `isSupported()` "must not throw any exceptions and should fail fast" (integrations-api).
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let previous = std::env::var("DBUS_SESSION_BUS_ADDRESS").ok();
        std::env::set_var(
            "DBUS_SESSION_BUS_ADDRESS",
            "unix:path=/nonexistent/crypto-test",
        );
        let supported = SecretServiceKeychain::gnome_keyring().is_supported();
        match previous {
            Some(value) => std::env::set_var("DBUS_SESSION_BUS_ADDRESS", value),
            None => std::env::remove_var("DBUS_SESSION_BUS_ADDRESS"),
        }
        assert!(!supported);
    }
}
