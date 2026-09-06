//! The state directory: one socket, pid, run-info and log file per unlocked vault.
//!
//! An unlocked vault is a detached daemon process, and the only thing tying the CLI to it is this
//! directory. It holds, per vault id:
//!
//! | file        | written by | meaning                                                     |
//! |-------------|------------|-------------------------------------------------------------|
//! | `<id>.sock` | daemon     | the control socket; connectable ⇒ the daemon is alive        |
//! | `<id>.pid`  | daemon     | the daemon's pid, written before the mount is up             |
//! | `<id>.json` | daemon     | [`RunInfo`]: what is mounted where, by which mount service   |
//! | `<id>.log`  | CLI/daemon | the daemon's stdout/stderr and log output                    |
//!
//! Everything in here is per user and short-lived, hence the run-time-ish default locations and
//! the 0700/0600 modes: the key never touches these files, but the mount point and the vault path
//! do, and the socket accepts the vault key.
use crate::error::{AppError, Result};
use serde::{Deserialize, Serialize};
use std::fs::Permissions;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Overrides the state directory (`crypto --state-dir`).
pub const STATE_DIR_ENV: &str = "CRYPTO_STATE_DIR";

/// The mode of the state directory: only its owner may look inside.
const DIR_MODE: u32 = 0o700;
/// The mode of every file in it.
const FILE_MODE: u32 = 0o600;

/// The platform's default state directory.
///
/// macOS has no per-user run-time directory, so the state lives next to `settings.json`; Linux
/// uses `$XDG_RUNTIME_DIR` when the session has one and falls back to a uid-suffixed directory in
/// `/tmp` (which is why `uid` is a parameter rather than read here -- this function stays pure so
/// the tests can check every branch on any host).
pub fn default_state_dir(home: &Path, xdg_runtime: Option<&Path>, uid: u32) -> PathBuf {
    if cfg!(target_os = "macos") {
        home.join("Library/Application Support/Cryptomator/cli-run")
    } else if let Some(runtime) = xdg_runtime.filter(|p| !p.as_os_str().is_empty()) {
        runtime.join("crypto")
    } else {
        PathBuf::from(format!("/tmp/crypto-{uid}"))
    }
}

/// The directory holding the [state files](VaultStateFiles) of every unlocked vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateDir {
    root: PathBuf,
}

impl StateDir {
    /// The state directory at `root`, whether or not it exists yet.
    pub fn at(root: PathBuf) -> Self {
        Self { root }
    }

    /// `$CRYPTO_STATE_DIR` if set and non-empty, else [`default_state_dir`].
    ///
    /// # Errors
    /// [`AppError::NoHomeDirectory`] if the default needs `$HOME` and there is none.
    pub fn from_env_or_default() -> Result<Self> {
        if let Some(value) = std::env::var_os(STATE_DIR_ENV) {
            if !value.is_empty() {
                return Ok(Self::at(PathBuf::from(value)));
            }
        }
        let home = std::env::var_os("HOME").map(PathBuf::from);
        let xdg = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
        let uid = nix::unistd::geteuid().as_raw();
        // Only the macOS default is derived from $HOME; the Linux one never looks at it, so a
        // session without $HOME still gets a state directory there.
        let home = match home {
            Some(home) => home,
            None if cfg!(target_os = "macos") => return Err(AppError::NoHomeDirectory),
            None => PathBuf::new(),
        };
        Ok(Self::at(default_state_dir(&home, xdg.as_deref(), uid)))
    }

    /// The directory itself.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Creates the directory (and its parents) and narrows it to 0700.
    ///
    /// The mode is only forced on a directory that belongs to us: `$XDG_RUNTIME_DIR` and `/tmp`
    /// are shared, and chmod-ing someone else's directory is both futile and rude. A pre-existing
    /// directory of another user is left as it is -- creating the state files in it will fail,
    /// which is the honest error.
    ///
    /// # Errors
    /// Any I/O error from creating the directory or reading its metadata.
    pub fn ensure(&self) -> Result<()> {
        std::fs::create_dir_all(&self.root)?;
        let metadata = std::fs::metadata(&self.root)?;
        if metadata.uid() == nix::unistd::geteuid().as_raw()
            && metadata.permissions().mode() & 0o777 != DIR_MODE
        {
            std::fs::set_permissions(&self.root, Permissions::from_mode(DIR_MODE))?;
        }
        Ok(())
    }

    /// The state files of `vault_id`.
    pub fn files(&self, vault_id: &str) -> VaultStateFiles {
        let stem = sanitize_id(vault_id);
        VaultStateFiles {
            socket: self.root.join(format!("{stem}.sock")),
            pid: self.root.join(format!("{stem}.pid")),
            info: self.root.join(format!("{stem}.json")),
            log: self.root.join(format!("{stem}.log")),
        }
    }

    /// Every readable [`RunInfo`] in the directory, in no particular order. A directory that does
    /// not exist yet holds no run infos; an unreadable or corrupt file is skipped rather than
    /// failing the whole listing -- a leftover from a crash must not break `crypto status`.
    ///
    /// # Errors
    /// I/O errors other than "the directory does not exist".
    pub fn list_run_infos(&self) -> Result<Vec<RunInfo>> {
        let entries = match std::fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(AppError::Io(e)),
        };
        let mut infos = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "json") {
                if let Some(info) = read_json(&path) {
                    infos.push(info);
                }
            }
        }
        Ok(infos)
    }
}

/// A vault id as a file-name stem: the generated ids are base64url already, so this only guards
/// against a hand-edited `settings.json` steering the state files out of the directory.
fn sanitize_id(vault_id: &str) -> String {
    let stem: String = vault_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if stem.is_empty() {
        "_".to_owned()
    } else {
        stem
    }
}

/// The four state files of one vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultStateFiles {
    /// `<id>.sock`, the daemon's control socket.
    pub socket: PathBuf,
    /// `<id>.pid`, the daemon's process id.
    pub pid: PathBuf,
    /// `<id>.json`, the [`RunInfo`].
    pub info: PathBuf,
    /// `<id>.log`, the daemon's log. Kept when the other three are removed.
    pub log: PathBuf,
}

impl VaultStateFiles {
    /// Writes the daemon's pid.
    ///
    /// # Errors
    /// Any I/O error while writing.
    pub fn write_pid(&self, pid: u32) -> Result<()> {
        write_private(&self.pid, format!("{pid}\n").as_bytes())
    }

    /// The pid, or `None` when the file is missing or does not hold a number.
    pub fn read_pid(&self) -> Option<u32> {
        std::fs::read_to_string(&self.pid)
            .ok()?
            .trim()
            .parse::<u32>()
            .ok()
    }

    /// Writes the run info.
    ///
    /// # Errors
    /// Any I/O error while writing.
    pub fn write_info(&self, info: &RunInfo) -> Result<()> {
        let json = serde_json::to_string_pretty(info).map_err(|e| AppError::InvalidValue {
            key: "runInfo".to_owned(),
            message: e.to_string(),
        })?;
        write_private(&self.info, json.as_bytes())
    }

    /// The run info, or `None` when the file is missing or unreadable.
    pub fn read_info(&self) -> Option<RunInfo> {
        read_json(&self.info)
    }

    /// Removes socket, pid and run info; the log stays, it is what a failed unlock is diagnosed
    /// from. Files that are already gone are not an error.
    ///
    /// # Errors
    /// The first I/O error other than "not found"; the remaining files are still attempted.
    pub fn remove_all(&self) -> Result<()> {
        let mut first_error = None;
        for path in [&self.socket, &self.pid, &self.info] {
            match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => first_error = first_error.or(Some(e)),
            }
        }
        match first_error {
            Some(e) => Err(AppError::Io(e)),
            None => Ok(()),
        }
    }
}

/// What a running daemon publishes about its mount.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunInfo {
    /// The vault's id in `settings.json`.
    pub vault_id: String,
    /// The vault directory.
    pub path: String,
    /// The Java class name of the mount service in use.
    pub mounter: String,
    /// Where the volume is mounted, if the service has a path for it.
    pub mountpoint: Option<String>,
    /// The daemon's process id.
    pub pid: u32,
    /// When the daemon mounted the vault, in seconds since the epoch.
    pub started_at: u64,
    /// Whether the volume was mounted read-only.
    pub read_only: bool,
}

/// Whether a process with this id exists, using signal 0 (`kill(pid, None)`).
///
/// A process we may not signal (`EPERM`) exists too. Pid 0 and negative values address process
/// *groups* and are never a daemon, so they count as gone.
pub fn process_alive(pid: u32) -> bool {
    let Ok(raw) = i32::try_from(pid) else {
        return false;
    };
    if raw <= 0 {
        return false;
    }
    match nix::sys::signal::kill(nix::unistd::Pid::from_raw(raw), None) {
        Ok(()) => true,
        Err(nix::errno::Errno::EPERM) => true,
        Err(_) => false,
    }
}

/// Writes `bytes` to `path` through a process-unique temporary file that is renamed over it, so a
/// reader never sees a half-written file. The file is created 0600 and the temporary one is
/// removed again on every failure.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "state".to_owned());
    let tmp = path.with_file_name(format!("{file_name}.{}.tmp", std::process::id()));
    let written = std::fs::File::options()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(FILE_MODE)
        .open(&tmp)
        .and_then(|mut file| {
            file.write_all(bytes)?;
            file.sync_all()
        });
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(AppError::Io(e));
    }
    // A tmp file created before this process changed its umask may still be too permissive.
    let _ = std::fs::set_permissions(&tmp, Permissions::from_mode(FILE_MODE));
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(AppError::Io(e));
    }
    Ok(())
}

/// A JSON file, or `None` if it is missing, unreadable or not a [`RunInfo`].
fn read_json(path: &Path) -> Option<RunInfo> {
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_info(id: &str) -> RunInfo {
        RunInfo {
            vault_id: id.to_owned(),
            path: "/vaults/Test".to_owned(),
            mounter: "org.cryptomator.cli.NullMountProvider".to_owned(),
            mountpoint: Some("/Users/me/mnt/Test".to_owned()),
            pid: 4242,
            started_at: 1_757_000_000,
            read_only: false,
        }
    }

    #[test]
    fn the_default_state_dir_follows_the_platform() {
        let home = Path::new("/home/u");
        let with_runtime = default_state_dir(home, Some(Path::new("/run/user/501")), 501);
        let without_runtime = default_state_dir(home, None, 501);
        if cfg!(target_os = "macos") {
            let expected = PathBuf::from("/home/u/Library/Application Support/Cryptomator/cli-run");
            assert_eq!(with_runtime, expected, "macOS ignores XDG_RUNTIME_DIR");
            assert_eq!(without_runtime, expected);
        } else {
            assert_eq!(with_runtime, PathBuf::from("/run/user/501/crypto"));
            assert_eq!(without_runtime, PathBuf::from("/tmp/crypto-501"));
            assert_eq!(
                default_state_dir(home, Some(Path::new("")), 7),
                PathBuf::from("/tmp/crypto-7"),
                "an empty XDG_RUNTIME_DIR is no runtime dir"
            );
        }
    }

    #[test]
    fn ensure_creates_the_directory_with_mode_0700() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().join("deep/state");
        let state = StateDir::at(root.clone());
        state.ensure().expect("ensure");
        assert!(root.is_dir());
        let mode = std::fs::metadata(&root)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "got {mode:o}");
        // Widening it again is undone by the next ensure.
        std::fs::set_permissions(&root, Permissions::from_mode(0o755)).expect("chmod");
        state.ensure().expect("ensure again");
        assert_eq!(
            std::fs::metadata(&root)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(state.root(), root.as_path());
    }

    #[test]
    fn state_files_are_named_after_the_vault_id() {
        let state = StateDir::at(PathBuf::from("/state"));
        let files = state.files("AbC-_123");
        assert_eq!(files.socket, PathBuf::from("/state/AbC-_123.sock"));
        assert_eq!(files.pid, PathBuf::from("/state/AbC-_123.pid"));
        assert_eq!(files.info, PathBuf::from("/state/AbC-_123.json"));
        assert_eq!(files.log, PathBuf::from("/state/AbC-_123.log"));
        assert_eq!(
            state.files("../../etc/x").socket,
            PathBuf::from("/state/______etc_x.sock"),
            "a hand-edited id cannot steer the files out of the directory"
        );
        assert_eq!(state.files("").pid, PathBuf::from("/state/_.pid"));
    }

    #[test]
    fn run_info_and_pid_round_trip_and_are_removed_together() {
        let dir = tempfile::tempdir().expect("temp dir");
        let state = StateDir::at(dir.path().to_path_buf());
        let files = state.files("AAAAAAAAAAAA");
        assert_eq!(files.read_info(), None, "nothing written yet");
        assert_eq!(files.read_pid(), None);

        let info = run_info("AAAAAAAAAAAA");
        files.write_info(&info).expect("write info");
        files.write_pid(4242).expect("write pid");
        assert_eq!(files.read_info(), Some(info.clone()));
        assert_eq!(files.read_pid(), Some(4242));
        for path in [&files.info, &files.pid] {
            let mode = std::fs::metadata(path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "{} has mode {mode:o}", path.display());
        }
        assert!(
            std::fs::read_to_string(&files.info)
                .expect("read info")
                .contains("\"vaultId\""),
            "the JSON is camelCase like the rest of the CLI"
        );
        assert_eq!(state.list_run_infos().expect("list"), vec![info]);

        std::fs::write(&files.socket, b"").expect("fake socket");
        std::fs::write(&files.log, b"log line").expect("log");
        files.remove_all().expect("remove");
        assert!(!files.socket.exists() && !files.pid.exists() && !files.info.exists());
        assert!(files.log.is_file(), "the log survives the cleanup");
        files.remove_all().expect("removing twice is fine");
        assert!(state.list_run_infos().expect("list").is_empty());
    }

    #[test]
    fn a_broken_run_info_is_skipped_and_a_missing_directory_is_empty() {
        let dir = tempfile::tempdir().expect("temp dir");
        let state = StateDir::at(dir.path().join("gone"));
        assert!(state.list_run_infos().expect("missing dir").is_empty());
        state.ensure().expect("ensure");
        let files = state.files("BBBBBBBBBBBB");
        std::fs::write(&files.info, b"{not json").expect("write");
        assert_eq!(files.read_info(), None);
        assert!(state.list_run_infos().expect("list").is_empty());
    }

    #[test]
    fn process_alive_knows_this_process_and_not_a_finished_one() {
        assert!(process_alive(std::process::id()));
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("spawn true");
        let pid = child.id();
        child.wait().expect("wait");
        // The pid is reaped, so it is free again -- the kernel may hand it out to someone else,
        // but not within these microseconds.
        assert!(!process_alive(pid));
        assert!(!process_alive(0), "pid 0 addresses a process group");
    }
}
