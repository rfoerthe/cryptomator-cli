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
use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password_options, PasswordOptions,
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
            // `set_generic_password_options` answers `errSecDuplicateItem` from `SecItemAdd` with
            // a `SecItemUpdate` whose query repeats every attribute it was given -- the label
            // included. An item that is already there under a *different* label (the desktop
            // app's "Cryptomator", or an earlier display name) therefore matches nothing and the
            // update comes back as `errSecItemNotFound`. Replacing it is what `storePassphrase`
            // promises, so delete and add once more; the passphrase is still in hand, so a
            // failure after the delete loses nothing the caller cannot retry.
            Err(err) if classify(err.code()) == Missing::Yes => {
                self.delete(key)?;
                self.add_or_update(key, display_name, passphrase)
                    .map_err(|err| self.map(err))
            }
            Err(err) => Err(self.map(err)),
        }
    }

    fn load(&self, key: &str) -> KeychainResult<Option<Zeroizing<String>>> {
        match get_generic_password(&self.service, key) {
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
        // `MacSystemKeychainAccess.changePassphrase`: delete, and store only if the delete found
        // something. "Noop, if there is no item for the given key."
        if !self.delete(key)? {
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
    fn the_label_is_the_display_name_and_falls_back_to_the_vault_id() {
        assert_eq!(label_for("vault-id", Some("My Vault")), "My Vault");
        assert_eq!(label_for("vault-id", None), "vault-id");
        // A blank name would leave a nameless row, which is the whole reason the label is set.
        assert_eq!(label_for("vault-id", Some("")), "vault-id");
        assert_eq!(label_for("vault-id", Some("   ")), "vault-id");
    }
}
