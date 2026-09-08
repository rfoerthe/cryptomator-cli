//! The macOS login keychain, item-compatible with `org.cryptomator.macos.keychain.MacKeychain`.
//!
//! Java goes through JNI to `SecKeychainAddGenericPassword` / `SecKeychainFindGenericPassword`;
//! we go through `security-framework`'s `SecItemAdd` / `SecItemCopyMatching` / `SecItemDelete`.
//! Both address the same items: class `kSecClassGenericPassword`, `kSecAttrService` = the service
//! name (`"Cryptomator"`, or `$CRYPTO_KEYCHAIN_SERVICE`), `kSecAttrAccount` = the vault id, the
//! passphrase as UTF-8 in `kSecValueData`, and no `kSecUseDataProtectionKeychain`, which is what
//! keeps this on the file-based login keychain rather than the data-protection one.
//!
//! `kSecAttrLabel` is set explicitly, because that is the column Keychain Access shows and
//! `SecItemAdd` -- unlike `SecKeychainAddGenericPassword` -- leaves it empty. The label is the
//! vault's display name when the caller has one and the vault id otherwise, so a row is
//! recognisable instead of nameless.
//!
//! Reading an item that Cryptomator.app wrote makes macOS ask the user (the ACL lists that app,
//! not us). Spike B could not get past that dialog in a non-interactive session, which is why
//! every call from the CLI is wrapped in [`crate::keychain::with_timeout`], and why a refusal
//! (`errSecUserCanceled`, `errSecAuthFailed`, `errSecInteractionNotAllowed`) becomes
//! [`KeychainError::AccessDenied`] rather than a generic backend failure.
use super::{service_name, Keychain, KeychainError, KeychainResult, MAC_SYSTEM_CLASS};
use security_framework::os::macos::passwords::find_generic_password as find_legacy_password;
use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
    set_generic_password_options, PasswordOptions,
};
use zeroize::Zeroizing;

/// `@Priority(1000)` on `MacSystemKeychainAccess`.
pub const MAC_PRIORITY: u32 = 1000;
/// `MacKeychain.OSSTATUS_NOT_FOUND`; the normal "nothing stored here" answer.
pub const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
/// The user (or Touch ID) failed to authenticate.
pub const ERR_SEC_AUTH_FAILED: i32 = -25293;
/// The user dismissed the keychain prompt.
pub const ERR_SEC_USER_CANCELED: i32 = -128;
/// No prompt may be shown at all -- a headless session, or a locked keychain in one.
pub const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;
/// `NamedServiceProvider.getName()`; the desktop app localises it, we do not.
const MAC_DISPLAY_NAME: &str = "macOS Keychain";

/// The login keychain, addressed as generic passwords under one service name.
#[derive(Debug, Clone)]
pub struct MacKeychain {
    service: String,
}

/// Whether an `OSStatus` means "no such item" rather than "it went wrong".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Missing {
    Yes,
    No,
}

/// `errSecItemNotFound` is the one status that is not a failure: it is Javas `null` and our
/// `Ok(None)` / `Ok(false)`. Everything else has to surface, so a real failure is never mistaken
/// for an empty keychain.
pub fn classify(code: i32) -> Missing {
    if code == ERR_SEC_ITEM_NOT_FOUND {
        Missing::Yes
    } else {
        Missing::No
    }
}

/// The label Keychain Access shows for an item: the vault's display name when there is one, the
/// vault id otherwise. An empty or blank display name counts as none -- a nameless row is exactly
/// what the label is here to avoid.
pub fn label_for<'a>(account: &'a str, display_name: Option<&'a str>) -> &'a str {
    match display_name {
        Some(name) if !name.trim().is_empty() => name,
        _ => account,
    }
}

/// The service name items written before integrations-mac issue 13 carry: the service with a
/// trailing NUL byte, because the old JNI code handed `SecKeychainAddGenericPassword` a
/// NUL-terminated C string together with a length that counted the terminator.
///
/// Java hard-codes the literal `"Cryptomator\0"` (`MacKeychain.tryMigratePassword`) and only ever
/// migrates when the service is `"Cryptomator"`. Deriving the name from whatever service is active
/// is the same thing for the default and gives `$CRYPTO_KEYCHAIN_SERVICE` a legacy name of its own,
/// which is what lets the E2E exercise the migration without touching the real items.
///
/// Only the *legacy* `SecKeychain…` calls can address such an item, because they take the service
/// as a length-delimited byte range. The `SecItem` API converts the service through a C string and
/// drops everything from the first NUL, so a `get_generic_password` with this name would silently
/// look under the plain service name again -- verified on macOS 25.6: an item written that way
/// comes back with `"svce"<blob>="crypto-probe-nul"`.
pub fn legacy_service_name(service: &str) -> String {
    format!("{service}\0")
}

/// What [`Keychain::store`] does after `SecItemAdd` + `SecItemUpdate` failed. [`Keychain::change`]
/// goes through the same path: it never deletes and re-adds either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreFallback {
    /// Rewrite `kSecValueData` on the item that is already there, label untouched.
    UpdateValueInPlace,
    /// A real failure: surface it.
    Fail,
}

/// `set_generic_password_options` answers `errSecDuplicateItem` from `SecItemAdd` with a
/// `SecItemUpdate` whose query repeats every attribute it was given -- the label included
/// (`security-framework` 3.7.0, `passwords.rs::set_password_internal`). An item that is already
/// there under a *different* label (the desktop app's, or an earlier display name) therefore
/// matches nothing and the update comes back as `errSecItemNotFound`. That status is the one
/// signal that the item exists but our labelled query cannot see it.
pub fn store_fallback(code: i32) -> StoreFallback {
    if classify(code) == Missing::Yes {
        StoreFallback::UpdateValueInPlace
    } else {
        StoreFallback::Fail
    }
}

/// What the user can do about a refusal, which is not the same for every `OSStatus`.
///
/// `errSecInteractionNotAllowed` means no prompt *can* be shown -- telling that user to approve
/// one is advice they cannot act on.
pub fn access_denied_hint(code: i32) -> &'static str {
    if code == ERR_SEC_INTERACTION_NOT_ALLOWED {
        "the keychain cannot show a dialog in this session (no GUI); run from a graphical session or use --password-stdin"
    } else {
        "approve the keychain prompt (\"Always Allow\") and try again"
    }
}

/// The error the CLI shows for an `OSStatus` that is not `errSecItemNotFound`.
///
/// The code is part of the message on purpose: it is what a bug report can be looked up by. A
/// refusal the user can act on becomes [`KeychainError::AccessDenied`]; anything else is a
/// [`KeychainError::Backend`]. Neither ever carries the passphrase, and the account only reaches
/// the message through whatever `Security.framework` itself said.
pub fn keychain_error(code: i32, message: &str) -> KeychainError {
    let message = format!("{message} (OSStatus {code})");
    match code {
        ERR_SEC_AUTH_FAILED | ERR_SEC_USER_CANCELED | ERR_SEC_INTERACTION_NOT_ALLOWED => {
            KeychainError::AccessDenied {
                provider: MAC_DISPLAY_NAME.to_string(),
                message,
                hint: access_denied_hint(code).to_string(),
            }
        }
        _ => KeychainError::Backend {
            provider: MAC_DISPLAY_NAME.to_string(),
            message,
        },
    }
}

impl Default for MacKeychain {
    fn default() -> Self {
        Self::new()
    }
}

impl MacKeychain {
    /// The service from `$CRYPTO_KEYCHAIN_SERVICE`, else `"Cryptomator"` -- the desktop app's
    /// `cryptomator.integrationsMac.keychainServiceName` under another name.
    pub fn new() -> Self {
        Self {
            service: service_name(),
        }
    }

    /// The same backend against an explicit service name, for tests that must not touch the real
    /// `"Cryptomator"` items.
    pub fn with_service(service: String) -> Self {
        Self { service }
    }

    pub fn service(&self) -> &str {
        &self.service
    }

    fn options(&self, account: &str, display_name: Option<&str>) -> PasswordOptions {
        let mut options = PasswordOptions::new_generic_password(&self.service, account);
        // `SecItemAdd` leaves `kSecAttrLabel` empty, and an item without one shows up nameless in
        // Keychain Access next to the desktop app's rows.
        options.set_label(label_for(account, display_name));
        options
    }

    fn map(&self, err: security_framework::base::Error) -> KeychainError {
        keychain_error(err.code(), &err.to_string())
    }

    /// `SecItemAdd`, or `SecItemUpdate` when the item is already there. The raw `OSStatus` stays
    /// visible, because [`Keychain::store`] has to tell one particular status apart.
    fn add_or_update(
        &self,
        key: &str,
        display_name: Option<&str>,
        passphrase: &str,
    ) -> Result<(), security_framework::base::Error> {
        set_generic_password_options(passphrase.as_bytes(), self.options(key, display_name))
    }

    /// One `SecItemCopyMatching` under `service`, decoded. `Ok(None)` is `errSecItemNotFound`.
    fn load_from(&self, service: &str, key: &str) -> KeychainResult<Option<Zeroizing<String>>> {
        match get_generic_password(service, key) {
            Ok(bytes) => {
                let bytes = Zeroizing::new(bytes);
                let text = std::str::from_utf8(&bytes).map_err(|_| KeychainError::Backend {
                    provider: MAC_DISPLAY_NAME.to_string(),
                    message: "the stored passphrase is not valid UTF-8".to_string(),
                })?;
                Ok(Some(Zeroizing::new(text.to_string())))
            }
            Err(err) if classify(err.code()) == Missing::Yes => Ok(None),
            Err(err) => Err(self.map(err)),
        }
    }

    /// `MacKeychain.loadPassword`'s fallback: nothing under the service name, so look under
    /// [`legacy_service_name`] and, on a hit, migrate the item the way `tryMigratePassword` does
    /// -- write it under the current name, delete the old one, hand the passphrase back.
    ///
    /// This is the one place that uses `SecKeychainFindGenericPassword` instead of `SecItem`,
    /// because only it can express the NUL in the service name ([`legacy_service_name`]). It is
    /// also the call Java makes.
    fn load_legacy(&self, key: &str) -> KeychainResult<Option<Zeroizing<String>>> {
        let legacy = legacy_service_name(&self.service);
        let (data, item) = match find_legacy_password(None, &legacy, key) {
            Ok(found) => found,
            // Nothing under the old name either, which is the normal case.
            Err(err) if classify(err.code()) == Missing::Yes => return Ok(None),
            // A failing *probe* is not a failing load: Javas JNI `loadPassword` answers `null`
            // for every error, and turning "nothing found under either name" into an error would
            // stop the CLI from simply asking for the passphrase it could not read.
            Err(err) => {
                log::warn!(
                    "could not look for a legacy keychain item: {}",
                    self.map(err)
                );
                return Ok(None);
            }
        };
        let bytes = Zeroizing::new(data.to_vec());
        drop(data);
        let text = std::str::from_utf8(&bytes).map_err(|_| KeychainError::Backend {
            provider: MAC_DISPLAY_NAME.to_string(),
            message: "the stored passphrase is not valid UTF-8".to_string(),
        })?;
        let passphrase = Zeroizing::new(text.to_string());
        // The caller asked for the passphrase and it is in hand, so a migration that fails is
        // logged rather than returned; the next `load` tries again. No branch here can carry the
        // passphrase into the log: `self.map` only ever sees `Security.framework`'s own text.
        match self.add_or_update(key, None, passphrase.as_str()) {
            Ok(()) => {
                // `SecKeychainItem::delete` swallows its `OSStatus` (Javas `tryMigratePassword`
                // ignores it too), so the check that it worked is a second lookup.
                item.delete();
                if find_legacy_password(None, &legacy, key).is_ok() {
                    log::warn!(
                        "copied a legacy keychain item to {:?} but could not remove the old one",
                        self.service
                    );
                }
            }
            Err(err) => log::warn!(
                "could not migrate a legacy keychain item to {:?}: {}",
                self.service,
                self.map(err)
            ),
        }
        Ok(Some(passphrase))
    }
}

impl Keychain for MacKeychain {
    fn java_class_name(&self) -> &'static str {
        MAC_SYSTEM_CLASS
    }

    fn display_name(&self) -> &'static str {
        MAC_DISPLAY_NAME
    }

    fn priority(&self) -> u32 {
        MAC_PRIORITY
    }

    /// `MacSystemKeychainAccess.isSupported()` is a plain `true`: the login keychain is part of
    /// the operating system. No probe, so choosing a provider costs nothing here.
    fn is_supported(&self) -> bool {
        true
    }

    /// `MacSystemKeychainAccess.isLocked()` is a plain `false`: macOS unlocks the login keychain
    /// at login and prompts by itself if it ever is locked, so there is nothing for us to report.
    fn is_locked(&self) -> bool {
        false
    }

    fn store(&self, key: &str, display_name: Option<&str>, passphrase: &str) -> KeychainResult<()> {
        match self.add_or_update(key, display_name, passphrase) {
            Ok(()) => Ok(()),
            Err(err) => match store_fallback(err.code()) {
                // The item exists under another label ([`store_fallback`]). Update it *in place*
                // through a label-less query: `SecItemUpdate` then matches whatever label is
                // there and rewrites only `kSecValueData`, so the item, its ACL and its partition
                // list survive -- which matters because this is exactly the desktop app's item,
                // and deleting and re-adding it would make Cryptomator.app prompt for an entry it
                // used to read silently. The stale label stays; for a desktop-app row that is the
                // better outcome, and `storePassphrase`'s promise is about the passphrase.
                StoreFallback::UpdateValueInPlace => {
                    set_generic_password(&self.service, key, passphrase.as_bytes())
                        .map_err(|err| self.map(err))
                }
                StoreFallback::Fail => Err(self.map(err)),
            },
        }
    }

    fn load(&self, key: &str) -> KeychainResult<Option<Zeroizing<String>>> {
        if let Some(passphrase) = self.load_from(&self.service, key)? {
            return Ok(Some(passphrase));
        }
        self.load_legacy(key)
    }

    fn delete(&self, key: &str) -> KeychainResult<bool> {
        match delete_generic_password(&self.service, key) {
            Ok(()) => Ok(true),
            Err(err) if classify(err.code()) == Missing::Yes => Ok(false),
            Err(err) => Err(self.map(err)),
        }
    }

    fn change(
        &self,
        key: &str,
        display_name: Option<&str>,
        passphrase: &str,
    ) -> KeychainResult<bool> {
        // `MacSystemKeychainAccess.changePassphrase` is `if (deletePassword(...)) storePassword(...)`.
        // The *decision* is kept -- "Noop, if there is no item for the given key" -- but not the
        // delete: recreating an item throws away its ACL and its partition list, and the item this
        // most often belongs to is the desktop app's, which would then start prompting for a row
        // it used to read silently. So the existence check is a lookup, and the write goes through
        // [`Keychain::store`], whose fallback rewrites `kSecValueData` in place through a
        // label-less query ([`store_fallback`]).
        //
        // The lookup reads the old passphrase (into a `Zeroizing` buffer that is dropped right
        // here) rather than only its attributes, because that is the read `security-framework`
        // exposes -- and it is no more of a prompt than Javas `deletePassword` was. Like Java, it
        // looks under the current service only: an item still living under the legacy service name
        // is not "there" for a change, and any `load` migrates it first anyway.
        if self.load_from(&self.service, key)?.is_none() {
            return Ok(false);
        }
        self.store(key, display_name, passphrase)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keychain::{DEFAULT_SERVICE, ENV_LOCK, SERVICE_ENV};

    #[test]
    fn it_reports_the_java_metadata() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var(SERVICE_ENV);
        let keychain = MacKeychain::new();
        assert_eq!(keychain.java_class_name(), MAC_SYSTEM_CLASS);
        assert_eq!(keychain.display_name(), MAC_DISPLAY_NAME);
        assert_eq!(keychain.priority(), MAC_PRIORITY);
        assert!(
            keychain.is_supported(),
            "MacSystemKeychainAccess.isSupported() is `true`"
        );
        assert!(
            !keychain.is_locked(),
            "MacSystemKeychainAccess.isLocked() is `false`"
        );
        assert_eq!(keychain.service(), DEFAULT_SERVICE);
    }

    #[test]
    fn the_service_name_comes_from_the_environment_or_is_given_outright() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(SERVICE_ENV, "crypto-test-service");
        assert_eq!(MacKeychain::new().service(), "crypto-test-service");
        // An empty override is no override (`service_name`), so the default comes back.
        std::env::set_var(SERVICE_ENV, "");
        assert_eq!(MacKeychain::new().service(), DEFAULT_SERVICE);
        std::env::remove_var(SERVICE_ENV);
        assert_eq!(MacKeychain::new().service(), DEFAULT_SERVICE);
        // And an explicit one ignores the environment entirely.
        std::env::set_var(SERVICE_ENV, "crypto-test-service");
        assert_eq!(
            MacKeychain::with_service("Other".to_string()).service(),
            "Other"
        );
        std::env::remove_var(SERVICE_ENV);
    }

    #[test]
    fn item_not_found_is_none_and_everything_else_is_an_error() {
        // -25300 is `errSecItemNotFound`, the normal "nothing stored" answer (spike B,
        // observation 2). Anything else has to surface, so a real failure is never mistaken for
        // an empty keychain.
        assert_eq!(classify(ERR_SEC_ITEM_NOT_FOUND), Missing::Yes);
        assert_eq!(classify(ERR_SEC_INTERACTION_NOT_ALLOWED), Missing::No);
        assert_eq!(classify(ERR_SEC_USER_CANCELED), Missing::No);
        assert_eq!(classify(ERR_SEC_AUTH_FAILED), Missing::No);
        assert_eq!(classify(-25299), Missing::No, "errSecDuplicateItem");
        assert_eq!(classify(0), Missing::No);
    }

    #[test]
    fn a_refusal_the_user_can_act_on_is_told_apart_from_a_broken_backend() {
        for code in [
            ERR_SEC_INTERACTION_NOT_ALLOWED,
            ERR_SEC_USER_CANCELED,
            ERR_SEC_AUTH_FAILED,
        ] {
            let err = keychain_error(code, "User interaction is not allowed.");
            assert!(
                matches!(err, KeychainError::AccessDenied { .. }),
                "{code} should be AccessDenied, got {err:?}"
            );
            let text = err.to_string();
            assert!(text.contains("macOS"), "{text}");
            assert!(text.contains(&code.to_string()), "{text}");
        }
        // Anything else is a plain backend failure, still with the code in it.
        let err = keychain_error(-25299, "The specified item already exists in the keychain.");
        assert!(matches!(err, KeychainError::Backend { .. }), "{err:?}");
        let text = err.to_string();
        assert!(text.contains("macOS"), "{text}");
        assert!(text.contains("-25299"), "{text}");
        // Never the passphrase, and never the account either.
        assert!(!text.contains("test-password"), "{text}");
        assert!(!text.contains("vault-id"), "{text}");
        assert_eq!(err.provider(), MAC_DISPLAY_NAME);
    }

    #[test]
    fn an_item_under_another_label_is_updated_in_place_rather_than_recreated() {
        // The `SecItemUpdate` that `set_generic_password_options` falls back to repeats our label,
        // so an item written by the desktop app (label = the service name) makes it answer
        // `errSecItemNotFound`. That is the one status that means "it is there, our query just
        // cannot see it", and the answer is a label-less update -- never a delete and re-add,
        // which would throw the item's ACL and partition list away. `change` writes through this
        // same `store`, so it does not recreate an item either; its own delete is gone.
        assert_eq!(
            store_fallback(ERR_SEC_ITEM_NOT_FOUND),
            StoreFallback::UpdateValueInPlace
        );
        for code in [
            ERR_SEC_INTERACTION_NOT_ALLOWED,
            ERR_SEC_USER_CANCELED,
            ERR_SEC_AUTH_FAILED,
            -25299, // errSecDuplicateItem
            -34018,
        ] {
            assert_eq!(store_fallback(code), StoreFallback::Fail, "{code}");
        }
    }

    #[test]
    fn the_legacy_service_name_is_the_service_with_a_trailing_nul() {
        // `MacKeychain.tryMigratePassword`'s `oldServiceName`, byte for byte.
        assert_eq!(
            legacy_service_name(DEFAULT_SERVICE).as_bytes(),
            b"Cryptomator\0"
        );
        assert_eq!(legacy_service_name(DEFAULT_SERVICE), "Cryptomator\0");
        // Derived, so a test service gets a legacy name of its own and never collides with the
        // real one.
        assert_eq!(legacy_service_name("crypto-e2e-7"), "crypto-e2e-7\0");
        assert_ne!(legacy_service_name("crypto-e2e-7"), "crypto-e2e-7");
    }

    #[test]
    fn a_session_that_cannot_show_a_prompt_is_not_told_to_approve_one() {
        let headless = access_denied_hint(ERR_SEC_INTERACTION_NOT_ALLOWED);
        assert!(headless.contains("graphical session"), "{headless}");
        assert!(headless.contains("--password-stdin"), "{headless}");
        assert!(
            !headless.contains("Always Allow"),
            "advice nobody in this session can act on: {headless}"
        );
        for code in [ERR_SEC_USER_CANCELED, ERR_SEC_AUTH_FAILED] {
            let hint = access_denied_hint(code);
            assert!(hint.contains("Always Allow"), "{code}: {hint}");
        }
        // And the hint is what the user actually reads.
        let err = keychain_error(
            ERR_SEC_INTERACTION_NOT_ALLOWED,
            "User interaction is not allowed.",
        );
        assert!(err.to_string().contains("graphical session"), "{err}");
        let err = keychain_error(ERR_SEC_USER_CANCELED, "User canceled the operation.");
        assert!(err.to_string().contains("Always Allow"), "{err}");
    }

    #[test]
    fn the_label_is_the_display_name_and_falls_back_to_the_vault_id() {
        assert_eq!(label_for("vault-id", Some("My Vault")), "My Vault");
        assert_eq!(label_for("vault-id", None), "vault-id");
        // A blank name would leave a nameless row, which is the whole reason the label is set.
        assert_eq!(label_for("vault-id", Some("")), "vault-id");
        assert_eq!(label_for("vault-id", Some("   ")), "vault-id");
    }
}
