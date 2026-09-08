//! A keychain in a JSON file, switched on with `$CRYPTO_KEYCHAIN_FAKE`.
//!
//! It exists so that every CLI flow -- `--store-password`, the implicit keychain unlock,
//! `password store/forget`, `vault remove --forget-password`, `keychain test` -- is tested on
//! every operating system, in CI, without a real keyring, without a D-Bus session and without any
//! chance of a dialog. It is deliberately **not** behind `#[cfg(test)]`: the CLI tests run the
//! built binary, so the binary has to know it too.
//!
//! While the variable is set, this is the only provider the registry offers
//! ([`crate::keychain::all_providers`]), so a test can never reach the user's real keychain by
//! accident.
//!
//! The file is a JSON object keyed by the keychain key:
//!
//! ```json
//! {
//!   "vault-id": { "password": "…", "displayName": "…" }
//! }
//! ```
//!
//! `displayName` is absent when the caller passed none. The passphrases are in the clear, which is
//! why the file is created `0600` and written through a temporary file that is renamed over it --
//! the same way [`crate::state_dir`] writes its private state. The **path** never holds a
//! passphrase; only the values do.
//!
//! Concurrency stops there: every mutation is a plain read-modify-write of the whole file, so two
//! processes writing the same `$CRYPTO_KEYCHAIN_FAKE` at once simply have a last writer who wins
//! (a `store` can silently undo a concurrent `delete`). A test that spawns `crypto` more than once
//! against one fake path must serialize those runs -- this is a test double, not a database.
use super::{Keychain, KeychainError, KeychainResult};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{DirBuilder, Permissions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Once;
use zeroize::Zeroizing;

/// Points at the JSON file that holds the fake entries.
pub const FAKE_ENV: &str = "CRYPTO_KEYCHAIN_FAKE";
/// Set to `1` to make the fake report `is_locked() == true` and fail every call with
/// [`KeychainError::Locked`].
pub const FAKE_LOCKED_ENV: &str = "CRYPTO_KEYCHAIN_FAKE_LOCKED";
/// Set to `1` to make the fake report `is_supported() == false`.
pub const FAKE_UNSUPPORTED_ENV: &str = "CRYPTO_KEYCHAIN_FAKE_UNSUPPORTED";
/// Its `keychainProvider` value; the prefix is ours, so it can never collide with a real one.
pub const FAKE_CLASS: &str = "org.cryptomator.cli.FakeKeychainAccess";
/// Its `getName()`.
const FAKE_DISPLAY_NAME: &str = "Fake keychain (file)";
/// Above every real provider, because while it is on it is the only one.
const FAKE_PRIORITY: u32 = 10_000;
/// The file holds passphrases in the clear.
const FILE_MODE: u32 = 0o600;
/// A directory created for the file is not world-traversable either.
const DIR_MODE: u32 = 0o700;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct Entry {
    password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
}

/// Hand-written, because the derived one would print the passphrase. Nothing formats an `Entry`
/// today; the rule is that nothing *could* -- a `{:?}` added later (a `dbg!`, an error context, a
/// panic message from an assertion in a test) must not be the place a passphrase escapes.
impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("password", &"<redacted>")
            .field("display_name", &self.display_name)
            .finish()
    }
}

/// `BTreeMap` rather than `HashMap`, so the file is stable across runs and a diff is readable.
type Entries = BTreeMap<String, Entry>;

/// The file-backed test keychain. See the [module docs](self).
#[derive(Debug, Clone)]
pub struct FakeKeychain {
    path: PathBuf,
}

impl FakeKeychain {
    /// The fake for `$CRYPTO_KEYCHAIN_FAKE`, or `None` when the variable is unset or empty.
    ///
    /// Selecting it is announced once per process, exactly once -- on standard
    /// error for anything that runs the CLI's logger: a release binary that silently swaps the
    /// operating system's keychain for a cleartext file over an environment variable is a
    /// footgun, and the warning is what keeps it a *test* switch.
    pub fn from_env() -> Option<Self> {
        match std::env::var(FAKE_ENV) {
            Ok(path) if !path.is_empty() => {
                let fake = Self::at(path);
                fake.announce();
                Some(fake)
            }
            _ => None,
        }
    }

    /// Warns, once per process, that the passphrases of this run are in a file in the clear.
    ///
    /// `log::warn!` rather than `eprintln!`, so it reads like every other warning of the run
    /// (`warning: ...` through `crate::daemon::logging`) and so a library user who wants it in
    /// their own log gets it there. The path is named -- it is what has to be deleted afterwards
    /// -- and nothing else about the file is.
    fn announce(&self) {
        static ANNOUNCED: Once = Once::new();
        ANNOUNCED.call_once(|| {
            let path = self.path.display();
            log::warn!(
                "${FAKE_ENV} is set; passwords are stored in the clear in {path} - test use only"
            );
        });
    }

    /// The fake backed by `path`. The file does not have to exist yet; a missing file is an empty
    /// store, so a fresh fake is already "supported".
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The file this fake reads and writes.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The display name stored next to `key`, for the tests that check what `store` wrote.
    ///
    /// # Errors
    /// [`KeychainError::Backend`] when the file cannot be read or is not the expected JSON.
    pub fn display_name_of(&self, key: &str) -> KeychainResult<Option<String>> {
        Ok(self
            .read()?
            .get(key)
            .and_then(|entry| entry.display_name.clone()))
    }

    fn flag(name: &str) -> bool {
        std::env::var(name).is_ok_and(|value| value == "1")
    }

    fn guard(&self) -> KeychainResult<()> {
        if Self::flag(FAKE_UNSUPPORTED_ENV) {
            return Err(KeychainError::Unsupported {
                provider: FAKE_DISPLAY_NAME.to_string(),
                hint: format!("{FAKE_UNSUPPORTED_ENV} is set"),
            });
        }
        if Self::flag(FAKE_LOCKED_ENV) {
            return Err(KeychainError::Locked {
                provider: FAKE_DISPLAY_NAME.to_string(),
            });
        }
        Ok(())
    }

    fn failed(&self, message: impl std::fmt::Display) -> KeychainError {
        KeychainError::Backend {
            provider: FAKE_DISPLAY_NAME.to_string(),
            // The path, never the content: the content is passphrases.
            message: format!("{}: {message}", self.path.display()),
        }
    }

    fn read(&self) -> KeychainResult<Entries> {
        match std::fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|err| self.failed(err)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Entries::new()),
            Err(err) => Err(self.failed(err)),
        }
    }

    /// `tmp` + `rename`, so a reader never sees half a file, and `0600` from the first byte.
    fn write(&self, entries: &Entries) -> KeychainResult<()> {
        let json = serde_json::to_vec_pretty(entries).map_err(|err| self.failed(err))?;
        if let Some(parent) = self
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            DirBuilder::new()
                .recursive(true)
                .mode(DIR_MODE)
                .create(parent)
                .map_err(|err| self.failed(err))?;
        }
        let file_name = self.path.file_name().map_or_else(
            || "keychain".to_string(),
            |n| n.to_string_lossy().into_owned(),
        );
        let tmp = self
            .path
            .with_file_name(format!("{file_name}.{}.tmp", std::process::id()));
        // A crash (or a reused pid) may have left one behind, and `create_new` below refuses an
        // existing name. `remove_file` unlinks a symbolic link instead of following it.
        match std::fs::remove_file(&tmp) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(self.failed(err)),
        }
        let written = std::fs::File::options()
            .write(true)
            // `create_new` (`O_EXCL`) never follows a symbolic link planted at the temp path.
            .create_new(true)
            .mode(FILE_MODE)
            .open(&tmp)
            .and_then(|mut file| {
                file.write_all(&json)?;
                file.sync_all()
            });
        if let Err(err) = written {
            let _ = std::fs::remove_file(&tmp);
            return Err(self.failed(err));
        }
        // `mode()` is masked by the umask, so make sure the file really is 0600.
        let _ = std::fs::set_permissions(&tmp, Permissions::from_mode(FILE_MODE));
        std::fs::rename(&tmp, &self.path).map_err(|err| {
            let _ = std::fs::remove_file(&tmp);
            self.failed(err)
        })
    }
}

impl Keychain for FakeKeychain {
    fn java_class_name(&self) -> &'static str {
        FAKE_CLASS
    }

    fn display_name(&self) -> &'static str {
        FAKE_DISPLAY_NAME
    }

    fn priority(&self) -> u32 {
        FAKE_PRIORITY
    }

    fn is_supported(&self) -> bool {
        !Self::flag(FAKE_UNSUPPORTED_ENV)
    }

    fn is_locked(&self) -> bool {
        Self::flag(FAKE_LOCKED_ENV)
    }

    fn store(&self, key: &str, display_name: Option<&str>, passphrase: &str) -> KeychainResult<()> {
        self.guard()?;
        let mut entries = self.read()?;
        entries.insert(
            key.to_string(),
            Entry {
                password: passphrase.to_string(),
                display_name: display_name.map(str::to_string),
            },
        );
        self.write(&entries)
    }

    fn load(&self, key: &str) -> KeychainResult<Option<Zeroizing<String>>> {
        self.guard()?;
        Ok(self
            .read()?
            .get(key)
            .map(|entry| Zeroizing::new(entry.password.clone())))
    }

    fn delete(&self, key: &str) -> KeychainResult<bool> {
        self.guard()?;
        let mut entries = self.read()?;
        if entries.remove(key).is_none() {
            return Ok(false);
        }
        self.write(&entries)?;
        Ok(true)
    }

    fn change(
        &self,
        key: &str,
        display_name: Option<&str>,
        passphrase: &str,
    ) -> KeychainResult<bool> {
        self.guard()?;
        // Javas `changePassphrase`: "Noop, if there is no item for the given key".
        if !self.read()?.contains_key(key) {
            return Ok(false);
        }
        self.store(key, display_name, passphrase)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::MutexGuard;

    /// Every test here reads `$CRYPTO_KEYCHAIN_FAKE_*`, so every test holds the lock -- otherwise
    /// the switches one test sets would decide what a concurrent one sees.
    fn fake() -> (MutexGuard<'static, ()>, tempfile::TempDir, FakeKeychain) {
        let guard = crate::keychain::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::remove_var(FAKE_LOCKED_ENV);
        std::env::remove_var(FAKE_UNSUPPORTED_ENV);
        let dir = tempfile::tempdir().expect("temp dir");
        let keychain = FakeKeychain::at(dir.path().join("keychain.json"));
        (guard, dir, keychain)
    }

    #[test]
    fn an_entrys_debug_output_never_carries_the_passphrase() {
        let entry = Entry {
            password: "s3cret-passphrase".to_string(),
            display_name: Some("Vault".to_string()),
        };
        let shown = format!("{entry:?}");
        assert!(shown.contains("<redacted>"), "{shown}");
        assert!(!shown.contains("s3cret-passphrase"), "{shown}");
        // The rest of the entry is still there: redacting is not the same as saying nothing.
        assert!(shown.contains("Vault"), "{shown}");
    }

    #[test]
    fn an_empty_store_answers_none_and_is_still_supported() {
        let (_env, _dir, keychain) = fake();
        assert!(keychain.is_supported());
        assert!(!keychain.is_locked());
        assert_eq!(keychain.java_class_name(), FAKE_CLASS);
        assert_eq!(keychain.display_name(), FAKE_DISPLAY_NAME);
        assert_eq!(keychain.priority(), FAKE_PRIORITY);
        assert!(keychain.load("v1").expect("load").is_none());
        assert!(!keychain.delete("v1").expect("delete"));
        assert!(!keychain.change("v1", Some("V"), "pw").expect("change"));
    }

    #[test]
    fn store_load_change_delete_round_trip() {
        let (_env, _dir, keychain) = fake();
        keychain
            .store("v1", Some("Secret"), "pw-one")
            .expect("store");
        assert_eq!(
            *keychain.load("v1").expect("load").expect("an entry"),
            "pw-one"
        );
        // change only touches an existing entry, and it does exist now.
        assert!(keychain
            .change("v1", Some("Secret"), "pw-two")
            .expect("change"));
        assert_eq!(
            *keychain.load("v1").expect("load").expect("an entry"),
            "pw-two"
        );
        // A second store replaces rather than duplicating.
        keychain
            .store("v1", Some("Renamed"), "pw-three")
            .expect("store");
        assert_eq!(
            *keychain.load("v1").expect("load").expect("an entry"),
            "pw-three"
        );
        assert_eq!(
            keychain.display_name_of("v1").expect("read"),
            Some("Renamed".to_string())
        );
        assert!(keychain.delete("v1").expect("delete"));
        assert!(keychain.load("v1").expect("load").is_none());
        assert!(!keychain.delete("v1").expect("delete"), "gone for good");
    }

    #[test]
    fn several_keys_live_side_by_side_and_the_file_is_private() {
        let (_env, _dir, keychain) = fake();
        keychain.store("a", Some("A"), "pw-a").expect("store");
        keychain.store("b", None, "pw-b").expect("store");
        assert_eq!(*keychain.load("a").expect("load").expect("a"), "pw-a");
        assert_eq!(*keychain.load("b").expect("load").expect("b"), "pw-b");
        assert_eq!(keychain.display_name_of("b").expect("read"), None);
        let mode = std::fs::metadata(keychain.path())
            .expect("the file exists")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "it holds passphrases in the clear");
        // The path never contains a passphrase, only the caller's file name.
        assert!(!keychain.path().to_string_lossy().contains("pw-"));
        // The documented file format, so a later task can write one by hand.
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(keychain.path()).expect("read")).expect("json");
        assert_eq!(json["a"]["password"], "pw-a");
        assert_eq!(json["a"]["displayName"], "A");
        assert!(json["b"].get("displayName").is_none());
        // Nothing but the two entries is left lying around next to the file.
        let leftovers: Vec<_> = std::fs::read_dir(keychain.path().parent().expect("parent"))
            .expect("dir")
            .filter_map(|entry| entry.ok().map(|e| e.file_name()))
            .filter(|name| name.to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {leftovers:?}"
        );
    }

    #[test]
    fn a_corrupt_file_is_a_backend_error_not_a_panic() {
        let (_env, _dir, keychain) = fake();
        std::fs::write(keychain.path(), b"{ not json").expect("write");
        match keychain.load("a") {
            Err(KeychainError::Backend { message, .. }) => {
                assert!(message.contains("keychain.json"), "{message}");
                assert!(!message.contains("pw-"), "no secret in the message");
            }
            other => panic!("expected a Backend error, got {other:?}"),
        }
    }

    #[test]
    fn the_locked_and_unsupported_switches_are_honoured() {
        let (_env, _dir, keychain) = fake();
        std::env::set_var(FAKE_LOCKED_ENV, "1");
        assert!(keychain.is_locked());
        match keychain.load("a") {
            Err(KeychainError::Locked { .. }) => {}
            other => panic!("expected Locked, got {other:?}"),
        }
        std::env::remove_var(FAKE_LOCKED_ENV);
        std::env::set_var(FAKE_UNSUPPORTED_ENV, "1");
        assert!(!keychain.is_supported());
        match keychain.store("a", None, "pw") {
            Err(KeychainError::Unsupported { .. }) => {}
            other => panic!("expected Unsupported, got {other:?}"),
        }
        std::env::remove_var(FAKE_UNSUPPORTED_ENV);
        assert!(keychain.is_supported());
    }

    #[test]
    fn from_env_needs_a_non_empty_path() {
        let _guard = crate::keychain::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::remove_var(FAKE_ENV);
        assert!(FakeKeychain::from_env().is_none());
        std::env::set_var(FAKE_ENV, "");
        assert!(
            FakeKeychain::from_env().is_none(),
            "an empty value is unset"
        );
        std::env::set_var(FAKE_ENV, "/tmp/does-not-have-to-exist.json");
        assert_eq!(
            FakeKeychain::from_env().expect("some").path(),
            std::path::Path::new("/tmp/does-not-have-to-exist.json")
        );
        std::env::remove_var(FAKE_ENV);
    }

    #[test]
    fn a_missing_parent_directory_is_created_private() {
        let (_env, dir, _unused) = fake();
        let keychain = FakeKeychain::at(dir.path().join("nested/deeper/kc.json"));
        keychain.store("a", None, "pw-a").expect("store");
        assert_eq!(*keychain.load("a").expect("load").expect("a"), "pw-a");
        let mode = std::fs::metadata(dir.path().join("nested/deeper"))
            .expect("the directory exists")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }
}
