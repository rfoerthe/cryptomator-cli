//! `org.cryptomator.linux.keychain.KDEWalletKeychainAccess` as a stub.
//!
//! It exists so a `settings.json` that names KWallet is a clear "not supported here, do this
//! instead" rather than an unknown provider. KWallet speaks its own D-Bus interface
//! (`org.kde.kwalletd6`), not the Secret Service one, and porting it is not part of M6. Users on
//! KDE can point `keychainProvider` at the Secret Service provider, which KWallet's own bridge
//! (and KeePassXC, and gnome-keyring) serve.
use super::{Keychain, KeychainError, KeychainResult, KDE_WALLET_CLASS};
use zeroize::Zeroizing;

/// Bottom of the list: it never works, so it must never be the automatic choice. The registry
/// keeps it in the list all the same, so `crypto keychain test` can say *why* it is unusable.
pub const KDE_PRIORITY: u32 = 0;
const KDE_DISPLAY_NAME: &str = "KDE Wallet";
/// The way out, in the words `crypto config set` accepts.
const KDE_HINT: &str = "KDE Wallet is not supported by crypto; set keychainProvider to \
                        secret-service or gnome-keyring";

/// The provider that answers "no" to everything, with a reason.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KdeWalletKeychain;

impl KdeWalletKeychain {
    pub fn new() -> Self {
        Self
    }

    /// The one error every operation returns. `hint` is what the user can act on; KWallet's own
    /// Secret Service bridge serves the same passphrases, so switching the provider is enough --
    /// nothing has to be moved.
    fn unsupported(&self) -> KeychainError {
        KeychainError::Unsupported {
            provider: KDE_DISPLAY_NAME.to_string(),
            hint: KDE_HINT.to_string(),
        }
    }
}

impl Keychain for KdeWalletKeychain {
    fn java_class_name(&self) -> &'static str {
        KDE_WALLET_CLASS
    }

    fn display_name(&self) -> &'static str {
        KDE_DISPLAY_NAME
    }

    fn priority(&self) -> u32 {
        KDE_PRIORITY
    }

    fn is_supported(&self) -> bool {
        false
    }

    /// Not "no keyring is locked" but "there is nothing here to lock": `isLocked()` is only ever
    /// asked about a provider that works, and this one never does.
    fn is_locked(&self) -> bool {
        false
    }

    fn store(&self, _key: &str, _display_name: Option<&str>, _pw: &str) -> KeychainResult<()> {
        Err(self.unsupported())
    }

    fn load(&self, _key: &str) -> KeychainResult<Option<Zeroizing<String>>> {
        Err(self.unsupported())
    }

    fn delete(&self, _key: &str) -> KeychainResult<bool> {
        Err(self.unsupported())
    }

    fn change(&self, _key: &str, _display_name: Option<&str>, _pw: &str) -> KeychainResult<bool> {
        Err(self.unsupported())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kwallet_is_a_stub_that_explains_itself() {
        let kde = KdeWalletKeychain::new();
        assert_eq!(kde, KdeWalletKeychain);
        assert_eq!(kde.java_class_name(), KDE_WALLET_CLASS);
        assert_eq!(kde.display_name(), KDE_DISPLAY_NAME);
        assert_eq!(kde.priority(), KDE_PRIORITY);
        assert!(!kde.is_supported());
        assert!(!kde.is_locked());
        for err in [
            kde.store("v1", Some("V"), "pw").unwrap_err(),
            kde.load("v1").unwrap_err(),
            kde.delete("v1").unwrap_err(),
            kde.change("v1", Some("V"), "pw").unwrap_err(),
        ] {
            assert_eq!(err.provider(), KDE_DISPLAY_NAME);
            match err {
                KeychainError::Unsupported { hint, .. } => assert!(
                    hint.contains("keychainProvider") && hint.contains("secret-service"),
                    "the hint has to say how to get out of it: {hint}"
                ),
                other => panic!("expected Unsupported, got {other}"),
            }
        }
        // Nothing it says can carry a passphrase: the only text it produces is the constant hint.
        assert!(!kde.unsupported().to_string().contains("pw"));
    }
}
