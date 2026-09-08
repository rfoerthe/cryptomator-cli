//! Keychain tests against the *real* keychain of the machine they run on.
//!
//! Three locks. `#[ignore]` keeps `cargo test` out; `CRYPTO_E2E_KEYCHAIN=1` keeps
//! `cargo test -- --ignored` out unless the machine may be written to; and
//! `$CRYPTO_KEYCHAIN_SERVICE` is pointed at `crypto-e2e-<pid>`, so nothing here can see, change or
//! delete the real `"Cryptomator"` items the desktop app owns. Everything created is deleted
//! again through a guard that also runs when a test panics.
//!
//! That service-name isolation is a macOS story, though (Minor 6): there, an item is addressed by
//! its service, so `crypto-e2e-<pid>` alone keeps two concurrent runs apart. On Linux an item is
//! addressed by its `Vault` attribute instead -- the service name is only the item *label* -- so
//! every *key* used here carries the pid too, not just `$CRYPTO_KEYCHAIN_SERVICE`; see
//! `round_trip`'s key and `linux_attributes`'s.
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
//! "The specified item could not be found in the keychain." The legacy-service phase also writes
//! an item under `crypto-e2e-<pid>\0`, which no `security` command can name (an argument cannot
//! carry a NUL): its guard goes through the backend, so `security dump-keychain | grep crypto-e2e`
//! is the check that covers both.
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
    // And the fake is switched off: with `$CRYPTO_KEYCHAIN_FAKE` set, `all_providers()` yields
    // only the file-backed fake and this whole test would pass against a JSON file.
    std::env::remove_var(cryptomator_app::keychain::fake::FAKE_ENV);
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

/// `/usr/bin/security`, under the same budget as everything else: a keychain dialog nobody
/// answers must end a phase with a printed "skipped:", not hang the suite.
///
/// The arguments are never printed -- one of them is a passphrase.
#[cfg(target_os = "macos")]
fn security(args: &[&str]) -> Option<std::process::Output> {
    let subcommand = args.first().copied().unwrap_or("security").to_string();
    let owned: Vec<String> = args.iter().map(|arg| (*arg).to_string()).collect();
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let _ = tx.send(
            std::process::Command::new("/usr/bin/security")
                .args(&owned)
                .output(),
        );
    });
    match rx.recv_timeout(TEST_TIMEOUT) {
        Ok(Ok(output)) => Some(output),
        Ok(Err(err)) => {
            eprintln!("skipped: /usr/bin/security {subcommand} could not be run ({err})");
            None
        }
        Err(_) => {
            eprintln!(
                "skipped: /usr/bin/security {subcommand} did not answer in {TEST_TIMEOUT:?}; a system dialog is probably waiting"
            );
            None
        }
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
    // Also on items we write ourselves, so still no prompt.
    #[cfg(target_os = "macos")]
    a_legacy_service_item(&service);
    // Last, because it is the phase that can provoke a prompt: everything after a prompt nobody
    // answers would time out too.
    #[cfg(target_os = "macos")]
    a_foreign_entry(&service);
    // The Linux counterpart: the attribute shape both variants have to agree on.
    #[cfg(target_os = "linux")]
    linux_attributes();
}

/// Store, load, change, delete -- on items this binary created itself, so nothing should prompt.
fn round_trip(provider: &Arc<dyn Keychain>) -> bool {
    // Pid-scoped (Minor 6): on Linux the item is found by this key alone, not by
    // `$CRYPTO_KEYCHAIN_SERVICE`, so a fixed key would let two concurrent runs on one machine
    // share -- and stomp on -- the same item.
    let key = format!("crypto-e2e-{}-round-trip", std::process::id());
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
    // Every step below ends the phase when `attempt` skipped it -- it has already printed why,
    // and a skip must never surface as a panic that reads like a failed assertion.
    let (p, k) = (Arc::clone(provider), key.clone());
    let Some(loaded) = attempt("load", move || p.load(&k)) else {
        return false;
    };
    assert_eq!(
        loaded.as_deref().map(String::as_str),
        Some("e2e-passphrase-1"),
        "what went in comes back out"
    );

    let (p, k) = (Arc::clone(provider), key.clone());
    let Some(changed) = attempt("change", move || {
        p.change(&k, Some("crypto e2e"), "e2e-passphrase-2")
    }) else {
        return false;
    };
    assert!(changed, "the entry exists, so change is not a noop");
    let (p, k) = (Arc::clone(provider), key.clone());
    let Some(loaded) = attempt("load after change", move || p.load(&k)) else {
        return false;
    };
    assert_eq!(
        loaded.as_deref().map(String::as_str),
        Some("e2e-passphrase-2")
    );

    let (p, k) = (Arc::clone(provider), key.clone());
    let Some(deleted) = attempt("delete", move || p.delete(&k)) else {
        return false;
    };
    assert!(deleted, "there was something to delete");
    let (p, k) = (Arc::clone(provider), key.clone());
    let Some(gone) = attempt("load after delete", move || p.load(&k)) else {
        return false;
    };
    assert!(gone.is_none(), "a missing entry is `None`, not an error");
    // A second delete is `false`, not an error -- Javas `deletePassword` says so too.
    let (p, k) = (Arc::clone(provider), key.clone());
    let Some(deleted_again) = attempt("delete again", move || p.delete(&k)) else {
        return false;
    };
    assert!(!deleted_again, "there was nothing left to delete");
    // The entry is gone, so the guard has nothing left to do.
    cleanup.keys.clear();
    eprintln!("round trip: ok");
    true
}

/// The migration `MacKeychain.loadPassword` does for integrations-mac issue 13: an item stored
/// under the *legacy* service name -- the service with a trailing NUL -- is found by a plain
/// `load`, moved to the current name and removed from the old one.
///
/// Neither `/usr/bin/security` nor the `SecItem` API can seed such an item: an argument cannot
/// carry a NUL, and `SecItemAdd` converts the service through a C string and drops everything from
/// the NUL on (an item written that way lands under the plain name -- observed). Only
/// `SecKeychainAddGenericPassword`, which takes a length-delimited byte range, can, and that is
/// exactly the call Java made when it created these items in the first place.
///
/// The desktop app only ever wrote `"Cryptomator\0"`; deriving the legacy name from the active
/// service is what keeps this phase inside `crypto-e2e-<pid>`.
#[cfg(target_os = "macos")]
fn a_legacy_service_item(service: &str) {
    use cryptomator_app::keychain::macos::{legacy_service_name, MacKeychain};
    use security_framework::os::macos::keychain::SecKeychain;
    use security_framework::os::macos::passwords::find_generic_password;

    /// The legacy item's own guard: `Cleanup` cannot serve, because deleting through the
    /// `SecItem` API would truncate the service at the NUL and hit the *migrated* item instead.
    struct LegacyCleanup {
        service: String,
        key: String,
        armed: bool,
    }

    impl Drop for LegacyCleanup {
        fn drop(&mut self) {
            if !self.armed {
                return;
            }
            let (service, key) = (self.service.clone(), self.key.clone());
            // Best effort, and still under a timeout, exactly like `Cleanup`.
            let _ = with_timeout_for("e2e cleanup", TEST_TIMEOUT, move || {
                if let Ok((_, item)) = find_generic_password(None, &service, &key) {
                    item.delete();
                }
                Ok::<(), KeychainError>(())
            });
        }
    }

    let key = "legacy-migrated".to_string();
    let legacy = legacy_service_name(service);
    let mut old_item = LegacyCleanup {
        service: legacy.clone(),
        key: key.clone(),
        armed: true,
    };
    let mut new_item = Cleanup {
        provider: Arc::new(MacKeychain::new()),
        keys: vec![key.clone()],
    };

    let (l, k) = (legacy.clone(), key.clone());
    if attempt("seed an item under the legacy service", move || {
        SecKeychain::default()
            .and_then(|keychain| keychain.set_generic_password(&l, &k, b"legacy-passphrase"))
            .map_err(|err| KeychainError::Backend {
                provider: "e2e".to_string(),
                message: err.to_string(),
            })
    })
    .is_none()
    {
        return;
    }
    eprintln!("seeded {key} under the legacy service name through SecKeychainAddGenericPassword");

    // Nothing under the current service name, so `load` has to fall back to the legacy one.
    let k = key.clone();
    let Some(loaded) = attempt("load a legacy entry", move || MacKeychain::new().load(&k)) else {
        return;
    };
    assert_eq!(
        loaded.as_deref().map(String::as_str),
        Some("legacy-passphrase"),
        "an item under `<service>\\0` is still found"
    );

    // Migrated, not just read: gone from the legacy name ...
    let (l, k) = (legacy.clone(), key.clone());
    let Some(left_behind) = attempt("look for the legacy entry again", move || {
        Ok(find_generic_password(None, &l, &k).is_ok())
    }) else {
        return;
    };
    assert!(
        !left_behind,
        "the legacy item is removed once it has been migrated"
    );
    old_item.armed = false;
    // ... and therefore under the current one, because this `load` has nowhere else to find it.
    let k = key.clone();
    let Some(migrated) = attempt("load after migrating", move || MacKeychain::new().load(&k))
    else {
        return;
    };
    assert_eq!(
        migrated.as_deref().map(String::as_str),
        Some("legacy-passphrase"),
        "the migrated item is under the current service name"
    );

    let k = key.clone();
    let Some(deleted) = attempt("delete the migrated entry", move || {
        MacKeychain::new().delete(&k)
    }) else {
        return;
    };
    assert!(deleted, "the migrated entry was there to delete");
    new_item.keys.clear();
    eprintln!("legacy service name: found, migrated and cleaned up");
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
/// `MacKeychain::store`'s update-in-place fallback.
#[cfg(target_os = "macos")]
fn a_foreign_entry(service: &str) {
    use cryptomator_app::keychain::macos::MacKeychain;

    /// `security add-generic-password`, in the shape the desktop app's items have.
    fn seed(service: &str, key: &str) -> bool {
        let Some(seeded) = security(&[
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
        ]) else {
            return false;
        };
        if seeded.status.success() {
            eprintln!("seeded {key} in {service} through /usr/bin/security");
            return true;
        }
        eprintln!(
            "skipped: `security add-generic-password` failed ({})",
            seeded.status
        );
        false
    }

    /// The item as `/usr/bin/security` sees it: its attributes (stdout) and, from `-g`, the
    /// `password: "..."` line (stderr). Reading a seeded `-A` item is not ACL-gated, and the call
    /// has a timeout either way.
    fn show(service: &str, key: &str) -> Option<(String, String)> {
        let found = security(&["find-generic-password", "-s", service, "-a", key, "-g"])?;
        if !found.status.success() {
            eprintln!(
                "skipped: `security find-generic-password` failed ({})",
                found.status
            );
            return None;
        }
        Some((
            String::from_utf8_lossy(&found.stdout).into_owned(),
            String::from_utf8_lossy(&found.stderr).into_owned(),
        ))
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
        "a foreign entry is updated, not duplicated"
    );
    // And it is still *that* item. `store` rewrites only `kSecValueData` through a label-less
    // query, so the label the seed gave it is untouched -- which is the observable proof that the
    // item was not deleted and added again, and therefore that its ACL and partition list (the
    // things that let Cryptomator.app read it without a prompt) came through as well.
    match show(service, &replaced) {
        Some((attributes, password)) => {
            let label = format!("0x00000007 <blob>=\"{service}\"");
            assert!(
                attributes.contains(&label),
                "the seeded label {label} survives our store:\n{attributes}"
            );
            assert!(
                password.contains("replaced-passphrase"),
                "the value was updated in place"
            );
            eprintln!("foreign entry: value updated in place, label kept, read back");
        }
        // `show` is the only call in this phase that reads a password through another program,
        // and reading one can raise an ACL dialog; it has already printed why it gave up. The
        // `load` above has confirmed the value from our side, so the phase carries on rather than
        // taking the delete and the read half down with it.
        None => eprintln!("skipped: the label could not be confirmed through /usr/bin/security"),
    }
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

/// Proof that the two Linux variants agree with each other -- *not* proof that either matches
/// what `integrations-linux` actually writes (Important 2, ruling): that jar is not on the
/// development machine (no `~/.m2/repository/org/cryptomator/integrations-linux/`), so this
/// phase can only write with the GNOME variant and read back with the Secret Service one, which
/// passes as long as both agree on the collection, the label and the `Vault` attribute. It would
/// pass unchanged if that shared attribute were misnamed, the label wrong or the content type
/// something other than `text/plain` -- none of that is read back and asserted on here.
/// Task 10: CI asserts the raw attribute names via `secret-tool`.
///
/// A phase of the test above rather than a test of its own, like the macOS ones: the file's rule
/// is one test with ordered phases, and here it also means the round trip has already proven the
/// basics before the attribute shape is put to the question.
///
/// Run it under a session bus of its own, so nothing touches the developer's real keyring:
/// `dbus-run-session -- sh -c 'eval "$(printf "" | gnome-keyring-daemon --unlock --components=secrets)"; \
///  CRYPTO_E2E_KEYCHAIN=1 cargo test -p cryptomator-app --test keychain_e2e -- --ignored --nocapture'`
#[cfg(target_os = "linux")]
fn linux_attributes() {
    use cryptomator_app::keychain::linux::{
        SecretServiceKeychain, NAME_ATTRIBUTE, VAULT_ATTRIBUTE,
    };

    let gnome = SecretServiceKeychain::gnome_keyring();
    if !gnome.is_supported() {
        eprintln!("skipped: no secret service on the session bus");
        return;
    }
    // The service name is only the item *label* here -- items are addressed by the `Vault`
    // attribute -- so the isolation this phase relies on is the key, which carries the pid.
    let key = format!("crypto-e2e-{}-attributes", std::process::id());
    let mut cleanup = Cleanup {
        provider: Arc::new(SecretServiceKeychain::gnome_keyring()),
        keys: vec![key.clone()],
    };

    let k = key.clone();
    if attempt("store (gnome variant)", move || {
        SecretServiceKeychain::gnome_keyring().store(&k, Some("Secret"), "e2e-linux-1")
    })
    .is_none()
    {
        return;
    }
    // Written by the GNOME variant, found by the Secret Service one: same collection, same
    // `Vault` attribute.
    let k = key.clone();
    let Some(loaded) = attempt("load (secret service variant)", move || {
        SecretServiceKeychain::secret_service().load(&k)
    }) else {
        return;
    };
    assert_eq!(loaded.as_deref().map(String::as_str), Some("e2e-linux-1"));

    // And the Secret Service variant adds `Name`, which the search must still ignore.
    let k = key.clone();
    if attempt("store (secret service variant)", move || {
        SecretServiceKeychain::secret_service().store(&k, Some("Renamed"), "e2e-linux-2")
    })
    .is_none()
    {
        return;
    }
    let k = key.clone();
    let Some(loaded) = attempt("load after rename", move || {
        SecretServiceKeychain::gnome_keyring().load(&k)
    }) else {
        return;
    };
    assert_eq!(
        loaded.as_deref().map(String::as_str),
        Some("e2e-linux-2"),
        "a renamed vault keeps its passphrase: the lookup uses {VAULT_ATTRIBUTE}, not {NAME_ATTRIBUTE}"
    );

    // `change` is a noop for a vault that has no item.
    let unknown = format!("{key}-unknown");
    let Some(changed) = attempt("change without an item", move || {
        SecretServiceKeychain::gnome_keyring().change(&unknown, None, "never-stored")
    }) else {
        return;
    };
    assert!(!changed, "changing a vault that has no item is a noop");

    let k = key.clone();
    let Some(deleted) = attempt("delete", move || {
        SecretServiceKeychain::gnome_keyring().delete(&k)
    }) else {
        return;
    };
    assert!(deleted, "there was something to delete");
    // One item per vault: the rename must not have left the first item behind, so a second
    // delete -- through the other variant, which searches by `Vault` all the same -- finds
    // nothing.
    let k = key.clone();
    let Some(deleted_again) = attempt("delete again", move || {
        SecretServiceKeychain::secret_service().delete(&k)
    }) else {
        return;
    };
    assert!(
        !deleted_again,
        "storing under a new display name must replace the item, not add a second one"
    );
    cleanup.keys.clear();
    eprintln!("linux attributes: ok");
}
