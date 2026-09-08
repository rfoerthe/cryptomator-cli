//! Locating, loading and atomically saving `settings.json` (`common/settings/SettingsProvider.java`
//! plus the per-OS `-Dcryptomator.settingsPath` values from the desktop packaging scripts).
use crate::error::{AppError, Result};
use crate::settings::SettingsJson;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const SETTINGS_PATH_ENV: &str = "CRYPTO_SETTINGS_PATH";
const WRITTEN_BY_VERSION: &str = concat!("crypto-", env!("CARGO_PKG_VERSION"));

/// Overrides the desktop app's IPC socket path; the tests point it at a socket of their own.
pub const DESKTOP_IPC_SOCKET_ENV: &str = "CRYPTO_DESKTOP_IPC_SOCKET";
/// The desktop app's IPC socket, which its packaging scripts put next to its `settings.json`.
const DESKTOP_IPC_SOCKET_NAME: &str = "ipc.socket";
/// How long the probe of that socket may take before the answer is "not running". Connecting to a
/// Unix socket normally answers at once; this is the bound for the case where it does not.
const DESKTOP_IPC_TIMEOUT: Duration = Duration::from_millis(200);
/// Appended to the settings path to get the lock file ([`SettingsStore::lock_path`]).
const LOCK_SUFFIX: &str = ".lock";
/// How long [`SettingsStore::save`] waits for the settings lock before it gives up.
const LOCK_TIMEOUT: Duration = Duration::from_secs(5);
/// How often it retries while it waits.
const LOCK_RETRY: Duration = Duration::from_millis(50);
/// The mode of the lock file; it lives next to the file that lists the user's vaults.
const LOCK_MODE: u32 = 0o600;

/// Where the Cryptomator desktop app listens for its single-instance IPC, per its packaging
/// scripts (`-Dcryptomator.ipcSocketPath`): `ipc.socket` in the directory that also holds
/// `settings.json`.
pub fn desktop_app_socket(home: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        home.join("Library/Application Support/Cryptomator")
    } else {
        home.join(".config/Cryptomator")
    }
    .join(DESKTOP_IPC_SOCKET_NAME)
}

/// macOS: `~/Library/Application Support/Cryptomator/settings.json`;
/// Linux: `~/.config/Cryptomator/settings.json`, then `~/.Cryptomator/settings.json`.
pub fn default_settings_candidates(home: &Path) -> Vec<PathBuf> {
    if cfg!(target_os = "macos") {
        vec![home.join("Library/Application Support/Cryptomator/settings.json")]
    } else {
        vec![
            home.join(".config/Cryptomator/settings.json"),
            home.join(".Cryptomator/settings.json"),
        ]
    }
}

/// `CRYPTO_SETTINGS_PATH` is a `:`-separated list like Java's `cryptomator.settingsPath`; empty entries are ignored.
pub fn candidates_from_env_value(value: &str) -> Vec<PathBuf> {
    value
        .split(':')
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        .collect()
}

#[derive(Debug, Clone)]
pub struct SettingsStore {
    candidates: Vec<PathBuf>,
    /// How long [`SettingsStore::with_lock`] waits for the lock; the tests shorten it.
    lock_timeout: Duration,
}

impl SettingsStore {
    pub fn with_paths(candidates: Vec<PathBuf>) -> Result<Self> {
        if candidates.is_empty() {
            return Err(AppError::InvalidValue {
                key: SETTINGS_PATH_ENV.to_string(),
                message: "at least one settings path is required".to_string(),
            });
        }
        Ok(Self {
            candidates,
            lock_timeout: LOCK_TIMEOUT,
        })
    }

    pub fn at(path: PathBuf) -> Self {
        Self {
            candidates: vec![path],
            lock_timeout: LOCK_TIMEOUT,
        }
    }

    /// The same store with a shorter lock timeout, so the test that waits one out stays fast.
    #[cfg(test)]
    fn with_lock_timeout(mut self, timeout: Duration) -> Self {
        self.lock_timeout = timeout;
        self
    }

    pub fn from_env_or_default() -> Result<Self> {
        if let Some(value) = std::env::var_os(SETTINGS_PATH_ENV) {
            return Self::with_paths(candidates_from_env_value(&value.to_string_lossy()));
        }
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or(AppError::NoHomeDirectory)?;
        Self::with_paths(default_settings_candidates(&home))
    }

    /// The first candidate: always the save target (`SettingsProvider.scheduleSave`).
    pub fn preferred_path(&self) -> &Path {
        &self.candidates[0]
    }

    pub fn candidates(&self) -> &[PathBuf] {
        &self.candidates
    }

    /// First candidate that exists wins. Unlike Java, a corrupt file is an error rather than a silent reset.
    pub fn load(&self) -> Result<SettingsJson> {
        for path in &self.candidates {
            match std::fs::read(path) {
                Ok(bytes) => {
                    return SettingsJson::parse(&bytes).map_err(|source| {
                        AppError::SettingsCorrupt {
                            path: path.clone(),
                            source,
                        }
                    })
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(source) => {
                    return Err(AppError::SettingsUnreadable {
                        path: path.clone(),
                        source,
                    })
                }
            }
        }
        Ok(SettingsJson::default())
    }

    /// Writes a process-unique `settings.json.<pid>.tmp` next to the preferred path and renames it
    /// over that path (`SettingsProvider.save`). The tmp name must not collide with the desktop
    /// app's fixed `settings.json.tmp`: a concurrent desktop save would otherwise truncate our tmp
    /// file and we would publish a partial file, which this crate reports as a corrupt settings
    /// file instead of silently resetting it. `create_new` additionally refuses to reuse a
    /// foreign tmp file, and every failure after creation removes the tmp file again.
    ///
    /// Everything below happens while this process holds the exclusive `flock` on
    /// [`SettingsStore::lock_path`], so two `crypto` processes never lose each other's changes.
    ///
    /// # Errors
    /// [`AppError::SettingsLocked`] when another process holds the lock for too long, plus
    /// [`AppError::Io`] for anything the write itself reports.
    pub fn save(&self, settings: &mut SettingsJson) -> Result<()> {
        self.with_lock(|| self.save_locked(settings))
    }

    /// The write itself, with the lock already held.
    fn save_locked(&self, settings: &mut SettingsJson) -> Result<()> {
        let path = self.preferred_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if settings.written_by_version.is_none() {
            settings.written_by_version = Some(WRITTEN_BY_VERSION.to_string());
        }
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "settings.json".to_string());
        let tmp_path = path.with_file_name(format!("{file_name}.{}.tmp", std::process::id()));
        let written = std::fs::File::options()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .and_then(|mut tmp| {
                tmp.write_all(settings.to_json_pretty().as_bytes())?;
                tmp.sync_all()
            });
        if let Err(e) = written {
            // Only remove the tmp file if we are the ones who created it.
            if e.kind() != std::io::ErrorKind::AlreadyExists {
                let _ = std::fs::remove_file(&tmp_path);
            }
            return Err(AppError::Io(e));
        }
        // `rename_durably`: `sync_all` above put the JSON on the platter, and the directory
        // entry that names it needs the directory's own fsync -- otherwise a crash can leave the
        // settings file missing altogether, which reads as "no vaults registered".
        if let Err(e) = cryptomator_core::durability::rename_durably(&tmp_path, path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(AppError::Io(e));
        }
        Ok(())
    }

    /// Loads, applies `f` and saves again -- all three under one lock, so a concurrent `crypto`
    /// cannot slip a write between the load and the save.
    ///
    /// # Errors
    /// Whatever [`SettingsStore::load`], `f` and [`SettingsStore::save`] report; nothing is
    /// written when any of them fails.
    pub fn update<T>(&self, f: impl FnOnce(&mut SettingsJson) -> Result<T>) -> Result<T> {
        self.with_lock(|| {
            let mut settings = self.load()?;
            let result = f(&mut settings)?;
            self.save_locked(&mut settings)?;
            Ok(result)
        })
    }

    /// The advisory lock file guarding the writes, `settings.json.lock` next to the preferred
    /// path.
    pub fn lock_path(&self) -> PathBuf {
        let mut path = self.preferred_path().as_os_str().to_os_string();
        path.push(LOCK_SUFFIX);
        PathBuf::from(path)
    }

    /// Runs `f` while this process holds an exclusive `flock` on [`SettingsStore::lock_path`].
    ///
    /// `flock` is advisory and per open file description, so two threads of this process contend
    /// for it exactly like two processes do. The lock is *not* taken on `settings.json` itself:
    /// the file is replaced by a rename, and a lock on the old inode would guard nothing. The
    /// lock file is never removed -- unlinking it while another process holds it open would hand
    /// the next writer a fresh inode and thus a lock nobody else contends for.
    ///
    /// The desktop app takes no lock at all; [`SettingsStore::desktop_app_running`] is what warns
    /// about that gap. See the README.
    ///
    /// # Errors
    /// [`AppError::Io`] if the lock file cannot be created or locked, and
    /// [`AppError::SettingsLocked`] when it is still held elsewhere after the timeout, plus
    /// whatever `f` reports.
    fn with_lock<T>(&self, f: impl FnOnce() -> Result<T>) -> Result<T> {
        let path = self.lock_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = std::fs::File::options()
            .write(true)
            .create(true)
            // Never truncate: the file has no contents, and another process may hold it open.
            .truncate(false)
            .mode(LOCK_MODE)
            .open(&path)?;
        let deadline = Instant::now() + self.lock_timeout;
        loop {
            match nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock) {
                Ok(guard) => {
                    let result = f();
                    // Explicit, so the unlock is visibly part of this function rather than an
                    // accident of where the guard happens to go out of scope.
                    drop(guard);
                    return result;
                }
                // `EINTR` is not contention at all, but a signal that arrived mid-call; both are
                // retried until the deadline.
                Err((returned, nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR))
                    if Instant::now() < deadline =>
                {
                    file = returned;
                    std::thread::sleep(LOCK_RETRY);
                }
                Err((_, nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR)) => {
                    return Err(AppError::SettingsLocked(path))
                }
                Err((_, errno)) => {
                    return Err(AppError::Io(std::io::Error::other(format!(
                        "cannot lock {}: {errno}",
                        path.display()
                    ))))
                }
            }
        }
    }

    /// Where the desktop app's IPC socket is expected: `$CRYPTO_DESKTOP_IPC_SOCKET` if set,
    /// otherwise `ipc.socket` next to the settings file this store writes.
    ///
    /// Deriving it from the settings path rather than from `$HOME` keeps the two in step: a
    /// `crypto --settings /elsewhere/settings.json` asks about the app instance that would write
    /// *that* file, and never about an unrelated one. For the default path the two are the same
    /// (see [`desktop_app_socket`]).
    pub fn desktop_ipc_socket(&self) -> PathBuf {
        if let Some(path) = std::env::var_os(DESKTOP_IPC_SOCKET_ENV) {
            return PathBuf::from(path);
        }
        self.preferred_path()
            .with_file_name(DESKTOP_IPC_SOCKET_NAME)
    }

    /// Whether the desktop app is running right now.
    ///
    /// Only a successful connect proves it: the app deletes its socket on exit, but a crash
    /// leaves the file behind, and a file that nobody listens on would otherwise raise a warning
    /// forever. The answer is best effort -- this only decides whether a warning is printed, so
    /// every failure means "not running".
    pub fn desktop_app_running(&self) -> bool {
        let socket = self.desktop_ipc_socket();
        let (tx, rx) = std::sync::mpsc::channel();
        // On a thread of its own: a connect to a socket whose backlog is full blocks, and a
        // warning must never be the reason a command hangs. The thread ends with its connect.
        if std::thread::Builder::new()
            .name("ipc-probe".to_string())
            .spawn(move || {
                let _ = tx.send(std::os::unix::net::UnixStream::connect(&socket).is_ok());
            })
            .is_err()
        {
            return false;
        }
        rx.recv_timeout(DESKTOP_IPC_TIMEOUT).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::VaultSettingsJson;

    #[test]
    fn default_candidates_per_os() {
        let home = Path::new("/home/u");
        let candidates = default_settings_candidates(home);
        if cfg!(target_os = "macos") {
            assert_eq!(
                candidates,
                vec![PathBuf::from(
                    "/home/u/Library/Application Support/Cryptomator/settings.json"
                )]
            );
        } else {
            assert_eq!(
                candidates,
                vec![
                    PathBuf::from("/home/u/.config/Cryptomator/settings.json"),
                    PathBuf::from("/home/u/.Cryptomator/settings.json")
                ]
            );
        }
        assert_eq!(
            candidates_from_env_value("/a/s.json::/b/s.json:"),
            vec![PathBuf::from("/a/s.json"), PathBuf::from("/b/s.json")]
        );
        assert!(SettingsStore::with_paths(Vec::new()).is_err());
    }

    #[test]
    fn missing_file_loads_defaults_and_save_creates_directories() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deep/er/settings.json");
        let store = SettingsStore::at(path.clone());
        let mut settings = store.load().unwrap();
        assert_eq!(settings, SettingsJson::default());
        settings.directories.push(VaultSettingsJson::new(
            "AAAAAAAAAAAA".into(),
            Path::new("/v"),
        ));
        store.save(&mut settings).unwrap();
        assert!(path.is_file());
        assert!(!dir.path().join("deep/er/settings.json.tmp").exists());
        assert_eq!(
            settings.written_by_version.as_deref(),
            Some(concat!("crypto-", env!("CARGO_PKG_VERSION")))
        );
        let loaded = store.load().unwrap();
        assert_eq!(loaded, settings);
    }

    #[test]
    fn existing_written_by_version_is_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(
            &path,
            br#"{"writtenByVersion":"1.19.3-dmg-6495","theme":"DARK"}"#,
        )
        .unwrap();
        let store = SettingsStore::at(path.clone());
        let mut settings = store.load().unwrap();
        settings.port = 5000;
        store.save(&mut settings).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"writtenByVersion\": \"1.19.3-dmg-6495\""));
        assert!(text.contains("\"theme\": \"DARK\""));
        assert!(text.contains("\"port\": 5000"));
    }

    #[test]
    fn falls_back_to_second_candidate_but_saves_to_first() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first/settings.json");
        let second = dir.path().join("second/settings.json");
        std::fs::create_dir_all(second.parent().unwrap()).unwrap();
        std::fs::write(&second, br#"{"port": 4711}"#).unwrap();
        let store = SettingsStore::with_paths(vec![first.clone(), second.clone()]).unwrap();
        let mut settings = store.load().unwrap();
        assert_eq!(settings.port, 4711);
        store.save(&mut settings).unwrap();
        assert!(first.is_file());
        assert_eq!(
            std::fs::read_to_string(&second).unwrap(),
            r#"{"port": 4711}"#,
            "second candidate untouched"
        );
    }

    #[test]
    fn corrupt_file_is_an_error_not_silently_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, b"{ not json").unwrap();
        let store = SettingsStore::at(path.clone());
        assert!(matches!(
            store.load(),
            Err(AppError::SettingsCorrupt { .. })
        ));
        assert!(store
            .update(|s| {
                s.port = 1;
                Ok(())
            })
            .is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"{ not json");
    }

    #[test]
    fn unreadable_first_candidate_is_an_error_not_a_fallthrough() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first/settings.json");
        let second = dir.path().join("second/settings.json");
        // A directory where a file is expected: readable entry, unreadable content.
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(second.parent().unwrap()).unwrap();
        std::fs::write(&second, br#"{"port": 1}"#).unwrap();
        let store = SettingsStore::with_paths(vec![first.clone(), second]).unwrap();
        match store.load() {
            Err(AppError::SettingsUnreadable { path, .. }) => assert_eq!(path, first),
            other => panic!("expected SettingsUnreadable, got {other:?}"),
        }
    }

    #[test]
    fn failed_save_leaves_no_tmp_behind() {
        let dir = tempfile::tempdir().unwrap();
        // The preferred path itself is a non-empty directory, so `create_dir_all` on its parent
        // and the tmp write both succeed, but the final rename fails (EISDIR/ENOTEMPTY).
        let path = dir.path().join("settings.json");
        std::fs::create_dir_all(path.join("occupied")).unwrap();
        let store = SettingsStore::at(path.clone());
        let mut settings = SettingsJson::default();
        assert!(store.save(&mut settings).is_err());
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "tmp files left behind: {leftovers:?}");
    }

    /// Serialises every test in this module that sets **or reads** process environment: the
    /// environment is process-wide, so a test that only reads `$CRYPTO_DESKTOP_IPC_SOCKET`
    /// (through [`SettingsStore::desktop_ipc_socket`]) sees whatever a parallel test happens to
    /// have set. Poison-tolerant: a test that panicked while holding it says nothing about
    /// whether the environment is usable, and the guard below puts it back either way.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Removes an environment variable again when the test ends -- including when it ends by
    /// panicking, which a plain `remove_var` at the end of the test body would skip, leaving the
    /// override in place for every test that runs afterwards.
    struct EnvVarGuard(&'static str);

    impl EnvVarGuard {
        fn set(name: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
            std::env::set_var(name, value);
            Self(name)
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            std::env::remove_var(self.0);
        }
    }

    /// Long enough for the waiting thread to retry a few times, short enough for a test.
    const SHORT_TIMEOUT: Duration = Duration::from_millis(300);

    /// Takes the lock the way another process would, without going through [`SettingsStore`].
    fn hold_the_lock(path: &Path) -> nix::fcntl::Flock<std::fs::File> {
        let file = std::fs::File::options()
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .expect("lock file");
        nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusive).expect("hold it")
    }

    #[test]
    fn concurrent_updates_do_not_lose_each_other() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = SettingsStore::at(dir.path().join("settings.json"));
        store
            .update(|settings| {
                settings.port = 0;
                Ok(())
            })
            .expect("seed");
        std::thread::scope(|scope| {
            for _ in 0..2 {
                let store = store.clone();
                scope.spawn(move || {
                    for _ in 0..10 {
                        store
                            .update(|settings| {
                                settings.port += 1;
                                Ok(())
                            })
                            .expect("update");
                    }
                });
            }
        });
        assert_eq!(
            store.load().expect("load").port,
            20,
            "every increment survived: load and save happen under one lock"
        );
    }

    #[test]
    fn the_lock_file_sits_next_to_the_settings_and_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("temp dir");
        let store = SettingsStore::at(dir.path().join("settings.json"));
        assert_eq!(store.lock_path(), dir.path().join("settings.json.lock"));
        store
            .update(|settings| {
                settings.port = 1;
                Ok(())
            })
            .expect("update");
        let mode = std::fs::metadata(store.lock_path())
            .expect("the lock file was created")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "it sits in the same directory as the vault list"
        );
        // The lock file stays: another process may be holding it open right now.
        assert!(store.lock_path().is_file());
    }

    #[test]
    fn a_lock_someone_else_holds_is_waited_for() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store =
            SettingsStore::at(dir.path().join("settings.json")).with_lock_timeout(SHORT_TIMEOUT);
        let held = hold_the_lock(&store.lock_path());
        let started = std::time::Instant::now();
        std::thread::scope(|scope| {
            let waiting = scope.spawn(|| {
                store.update(|settings| {
                    settings.port = 7;
                    Ok(())
                })
            });
            std::thread::sleep(SHORT_TIMEOUT / 3);
            held.unlock().expect("let go");
            waiting.join().expect("no panic").expect("once it is free");
        });
        assert!(
            started.elapsed() >= SHORT_TIMEOUT / 3,
            "it waited instead of failing right away"
        );
        assert_eq!(store.load().expect("load").port, 7);
    }

    #[test]
    fn a_lock_nobody_lets_go_of_is_given_up_on() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store =
            SettingsStore::at(dir.path().join("settings.json")).with_lock_timeout(SHORT_TIMEOUT);
        let held = hold_the_lock(&store.lock_path());
        let started = std::time::Instant::now();
        let err = store
            .update(|settings| {
                settings.port = 1;
                Ok(())
            })
            .expect_err("the lock is held elsewhere");
        assert!(
            started.elapsed() >= SHORT_TIMEOUT,
            "it waited the full {SHORT_TIMEOUT:?}, not less"
        );
        assert!(matches!(err, AppError::SettingsLocked(_)), "{err:?}");
        assert!(err.to_string().contains("settings.json.lock"), "{err}");
        assert!(
            !dir.path().join("settings.json").exists(),
            "nothing was written"
        );
        drop(held);
        store
            .update(|settings| {
                settings.port = 1;
                Ok(())
            })
            .expect("once the lock is free again");
    }

    #[test]
    fn the_desktop_socket_path_follows_the_packaging_scripts() {
        // Reads `$CRYPTO_DESKTOP_IPC_SOCKET` through `desktop_ipc_socket()`, so it has to be
        // serialised against the test that sets it.
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let home = Path::new("/home/u");
        let socket = desktop_app_socket(home);
        if cfg!(target_os = "macos") {
            assert_eq!(
                socket,
                Path::new("/home/u/Library/Application Support/Cryptomator/ipc.socket")
            );
        } else {
            assert_eq!(socket, Path::new("/home/u/.config/Cryptomator/ipc.socket"));
        }
        // The store derives the same path from the settings file it actually uses, so a
        // `--settings` elsewhere probes the socket belonging to *that* directory.
        let store = SettingsStore::with_paths(default_settings_candidates(home)).expect("store");
        assert_eq!(store.desktop_ipc_socket(), socket);
    }

    #[test]
    fn a_socket_someone_listens_on_means_the_desktop_app_is_running() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().expect("temp dir");
        let store = SettingsStore::at(dir.path().join("settings.json"));
        let socket = dir.path().join("ipc.socket");
        assert_eq!(store.desktop_ipc_socket(), socket);
        assert!(!store.desktop_app_running(), "nothing is there yet");
        let listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind");
        assert!(store.desktop_app_running());
        drop(listener);
        std::fs::remove_file(&socket).expect("remove");
        assert!(
            !store.desktop_app_running(),
            "a socket file alone proves nothing"
        );
        // A leftover socket file that nobody listens on must not count either.
        std::fs::write(&socket, b"").expect("plain file");
        assert!(!store.desktop_app_running());
    }

    #[test]
    fn the_environment_can_point_the_probe_at_another_socket() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().expect("temp dir");
        let store = SettingsStore::at(dir.path().join("settings.json"));
        let socket = dir.path().join("elsewhere.socket");
        let _env = EnvVarGuard::set(DESKTOP_IPC_SOCKET_ENV, &socket);
        assert_eq!(store.desktop_ipc_socket(), socket);
        assert!(!store.desktop_app_running());
        let listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind");
        assert!(store.desktop_app_running());
        drop(listener);
    }

    #[test]
    fn update_loads_applies_and_saves() {
        let dir = tempfile::tempdir().unwrap();
        let store = SettingsStore::at(dir.path().join("settings.json"));
        let id = store
            .update(|s| {
                s.directories.push(VaultSettingsJson::new(
                    "BBBBBBBBBBBB".into(),
                    Path::new("/b"),
                ));
                Ok(s.directories[0].id.clone())
            })
            .unwrap();
        assert_eq!(id, "BBBBBBBBBBBB");
        assert_eq!(store.load().unwrap().directories.len(), 1);
    }
}
