//! Keychain tests against the *real* keychain of the machine they run on.
//!
//! Three locks. `#[ignore]` keeps `cargo test` out; `CRYPTO_E2E_KEYCHAIN=1` keeps
//! `cargo test -- --ignored` out unless the machine may be written to; and
//! `$CRYPTO_KEYCHAIN_SERVICE` is pointed at `crypto-e2e-<pid>`, so nothing here can see, change or
//! delete the real `"Cryptomator"` items the desktop app owns. Everything created is deleted
//! again through a guard that also runs when a test panics.
//!
//! Every call goes through `with_timeout_for`, so a macOS ACL dialog nobody answers ends a phase
//! with a printed "skipped:" instead of hanging the suite (spike B, observation 5: the API itself
//! has no timeout).
//!
//! It is **one** test with ordered phases rather than two, on purpose. macOS serialises keychain
//! access around a pending prompt, so a second test running next to the one that is waiting for a
//! dialog blocks too and reports a timeout of its own. One test means the phase that can provoke a
//! prompt runs last and only ever skips itself.
//!
//! Run:
//! `CRYPTO_E2E_KEYCHAIN=1 cargo test -p cryptomator-app --test keychain_e2e -- --ignored --nocapture`
//!
//! Afterwards `security find-generic-password -s crypto-e2e-<pid>` must fail with
//! "The specified item could not be found in the keychain."
use cryptomator_app::keychain::{all_providers, with_timeout_for, Keychain, KeychainError};
use std::sync::Arc;
use std::time::Duration;

/// Shorter than the CLI's 30 s: a test that has to give up should give up quickly.
const TEST_TIMEOUT: Duration = Duration::from_secs(10);

/// A service name no other program uses, so the run can only ever touch its own items and a
/// leftover is unmistakable. Set before any provider is constructed, because `MacKeychain::new()`
/// reads it once, at construction.
fn e2e_service() -> String {
    let service = format!("crypto-e2e-{}", std::process::id());
    std::env::set_var("CRYPTO_KEYCHAIN_SERVICE", &service);
    service
}

fn enabled() -> bool {
    if std::env::var("CRYPTO_E2E_KEYCHAIN").as_deref() == Ok("1") {
        return true;
    }
    eprintln!("skipped: set CRYPTO_E2E_KEYCHAIN=1 to touch the real keychain");
    false
}

/// Runs `op` under a timeout and turns "a dialog is waiting" into a skip.
fn attempt<T: Send + 'static>(
    what: &str,
    op: impl FnOnce() -> Result<T, KeychainError> + Send + 'static,
) -> Option<T> {
    match with_timeout_for("e2e", TEST_TIMEOUT, op) {
        Ok(value) => Some(value),
        Err(KeychainError::TimedOut { .. }) => {
            eprintln!(
                "skipped: {what} did not answer in {TEST_TIMEOUT:?}; a system dialog is probably waiting"
            );
            None
        }
        Err(KeychainError::AccessDenied { .. }) => {
            eprintln!("skipped: {what} was refused; a prompt was cancelled or cannot be shown");
            None
        }
        Err(KeychainError::Unsupported { hint, .. }) => {
            eprintln!("skipped: {what} is not supported here ({hint})");
            None
        }
        Err(KeychainError::Locked { .. }) => {
            eprintln!("skipped: {what} needs an unlocked keyring");
            None
        }
        Err(err) => panic!("{what} failed: {err}"),
    }
}

/// Removes every item this run could have created, however the test ends.
struct Cleanup {
    provider: Arc<dyn Keychain>,
    keys: Vec<String>,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        for key in std::mem::take(&mut self.keys) {
            let provider = Arc::clone(&self.provider);
            // Best effort, and still under a timeout: a hung delete must not hang the suite.
            let _ = with_timeout_for("e2e cleanup", TEST_TIMEOUT, move || provider.delete(&key));
        }
    }
}

#[test]
#[ignore = "touches the real keychain; needs CRYPTO_E2E_KEYCHAIN=1"]
fn the_real_keychain_behaves_like_the_fake_one() {
    if !enabled() {
        return;
    }
    let service = e2e_service();
    let Some(provider) = all_providers().into_iter().find(|p| p.is_supported()) else {
        eprintln!("skipped: no supported keychain provider on this machine");
        return;
    };
    eprintln!(
        "provider: {} ({}), service {service}",
        provider.display_name(),
        provider.java_class_name()
    );
    let provider = Arc::<dyn Keychain>::from(provider);
    if !round_trip(&provider) {
        return;
    }
    // Last, because it is the phase that can provoke a prompt: everything after a prompt nobody
    // answers would time out too.
    #[cfg(target_os = "macos")]
    a_foreign_entry(&service);
}

/// Store, load, change, delete -- on items this binary created itself, so nothing should prompt.
fn round_trip(provider: &Arc<dyn Keychain>) -> bool {
    let key = "round-trip".to_string();
    let mut cleanup = Cleanup {
        provider: Arc::clone(provider),
        keys: vec![key.clone()],
    };

    let (p, k) = (Arc::clone(provider), key.clone());
    if attempt("store", move || {
        p.store(&k, Some("crypto e2e"), "e2e-passphrase-1")
    })
    .is_none()
    {
        return false;
    }
    let (p, k) = (Arc::clone(provider), key.clone());
    let loaded = attempt("load", move || p.load(&k)).expect("load answered");
    assert_eq!(
        loaded.as_deref().map(String::as_str),
        Some("e2e-passphrase-1"),
        "what went in comes back out"
    );

    let (p, k) = (Arc::clone(provider), key.clone());
    let changed = attempt("change", move || {
        p.change(&k, Some("crypto e2e"), "e2e-passphrase-2")
    })
    .expect("change answered");
    assert!(changed, "the entry exists, so change is not a noop");
    let (p, k) = (Arc::clone(provider), key.clone());
    let loaded = attempt("load after change", move || p.load(&k)).expect("load answered");
    assert_eq!(
        loaded.as_deref().map(String::as_str),
        Some("e2e-passphrase-2")
    );

    let (p, k) = (Arc::clone(provider), key.clone());
    assert!(
        attempt("delete", move || p.delete(&k)).expect("delete answered"),
        "there was something to delete"
    );
    let (p, k) = (Arc::clone(provider), key.clone());
    assert!(
        attempt("load after delete", move || p.load(&k))
            .expect("load answered")
            .is_none(),
        "a missing entry is `None`, not an error"
    );
    // A second delete is `false`, not an error -- Javas `deletePassword` says so too.
    let (p, k) = (Arc::clone(provider), key.clone());
    assert!(!attempt("delete again", move || p.delete(&k)).expect("delete answered"));
    // The entry is gone, so the guard has nothing left to do.
    cleanup.keys.clear();
    eprintln!("round trip: ok");
    true
}

/// The one thing a unit test cannot show: an entry that some *other* program created, in the exact
/// shape the desktop app writes.
///
/// `security add-generic-password -A` gives the item an ACL with `applications: <null>` -- every
/// application may use it -- which is what lets an unsigned binary like this test read it without
/// a dialog. It is not a free pass: the item's partition list still says `apple-tool:` only, and
/// this read was observed to block indefinitely when it was the *first* keychain access the
/// process made. It stopped blocking once the round trip above had run first, which is why the
/// phases are ordered and why every call here has a timeout: in a session with nobody to answer a
/// prompt, `SecItemCopyMatching` simply never returns (spike B, observation 5), and the CLI has to
/// degrade rather than hang.
///
/// Writing is not gated the same way, and that half is worth having: the seeded label is the
/// service name while ours is the display name, so this is the only test that reaches
/// `MacKeychain::store`'s delete-and-add-again fallback.
#[cfg(target_os = "macos")]
fn a_foreign_entry(service: &str) {
    use cryptomator_app::keychain::macos::MacKeychain;

    /// `security add-generic-password`, in the shape the desktop app's items have.
    fn seed(service: &str, key: &str) -> bool {
        let seeded = std::process::Command::new("/usr/bin/security")
            .args([
                "add-generic-password",
                "-s",
                service,
                "-a",
                key,
                "-w",
                "seeded-passphrase",
                "-l",
                service,
                // Every application may use it: without this macOS asks even to delete it, and
                // nobody is here to answer (spike B, observation 5).
                "-A",
            ])
            .status()
            .expect("run /usr/bin/security");
        if seeded.success() {
            eprintln!("seeded {key} in {service} through /usr/bin/security");
            return true;
        }
        eprintln!("skipped: `security add-generic-password` failed ({seeded})");
        false
    }

    // The writing half first: it is the one that does not depend on a prompt.
    let replaced = "foreign-replaced".to_string();
    if !seed(service, &replaced) {
        return;
    }
    let mut cleanup = Cleanup {
        provider: Arc::new(MacKeychain::new()),
        keys: vec![replaced.clone()],
    };
    let k = replaced.clone();
    if attempt("store over a foreign entry", move || {
        MacKeychain::new().store(&k, Some("crypto e2e"), "replaced-passphrase")
    })
    .is_none()
    {
        return;
    }
    let k = replaced.clone();
    let Some(loaded) = attempt("load after replacing", move || MacKeychain::new().load(&k)) else {
        return;
    };
    assert_eq!(
        loaded.as_deref().map(String::as_str),
        Some("replaced-passphrase"),
        "a foreign entry is replaced, not duplicated"
    );
    eprintln!("foreign entry: replaced under our own label and read back");
    let k = replaced.clone();
    let Some(deleted) = attempt("delete a foreign entry", move || {
        MacKeychain::new().delete(&k)
    }) else {
        return;
    };
    assert!(deleted, "there was something to delete");
    cleanup.keys.clear();

    // And the read, dead last, because this is the one that can leave a prompt waiting: a second
    // seeded item, never written to, read exactly as the CLI would read a desktop-app entry.
    let untouched = "foreign-read".to_string();
    if !seed(service, &untouched) {
        return;
    }
    let mut cleanup = Cleanup {
        provider: Arc::new(MacKeychain::new()),
        keys: vec![untouched.clone()],
    };
    let k = untouched.clone();
    match attempt("load a foreign entry", move || MacKeychain::new().load(&k)) {
        Some(Some(passphrase)) => {
            assert_eq!(&*passphrase, "seeded-passphrase");
            eprintln!("foreign entry: read without a prompt");
        }
        Some(None) => panic!("the entry was seeded but not found -- service/account do not match"),
        // Skipped, already reported; the guard still removes it, which is not prompt-gated.
        None => return,
    }
    let k = untouched.clone();
    if attempt("delete an untouched foreign entry", move || {
        MacKeychain::new().delete(&k)
    }) == Some(true)
    {
        cleanup.keys.clear();
    }
}
