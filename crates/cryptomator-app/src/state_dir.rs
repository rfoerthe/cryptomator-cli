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
use crate::platform::Platform;
use serde::{Deserialize, Serialize};
use std::fs::{DirBuilder, Metadata, Permissions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
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
/// `/tmp`. Every input -- the platform included -- is a parameter rather than read here, so this
/// function stays pure and the tests can check every branch on any host.
pub fn default_state_dir(
    platform: Platform,
    home: &Path,
    xdg_runtime: Option<&Path>,
    uid: u32,
) -> PathBuf {
    if platform.is_macos() {
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
        let platform = Platform::current();
        let home = std::env::var_os("HOME").map(PathBuf::from);
        let xdg = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
        let uid = nix::unistd::geteuid().as_raw();
        // Only the macOS default is derived from $HOME; the Linux one never looks at it, so a
        // session without $HOME still gets a state directory there.
        let home = match home {
            Some(home) => home,
            None if platform.is_macos() => return Err(AppError::NoHomeDirectory),
            None => PathBuf::new(),
        };
        Ok(Self::at(default_state_dir(
            platform,
            &home,
            xdg.as_deref(),
            uid,
        )))
    }

    /// The directory itself.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Creates the directory (and its parents), refuses one that is not ours and narrows it to
    /// 0700.
    ///
    /// `create_dir_all` succeeds on a directory that is already there, and the default locations
    /// live in shared places (`$XDG_RUNTIME_DIR`, `/tmp/crypto-<uid>`): another local user can
    /// create `/tmp/crypto-<uid>` world-writable before the first run, or put a symbolic link
    /// there, and would then see the run infos and -- worse -- own the path the control socket is
    /// bound to. So the directory has to be a real directory that belongs to us before anything
    /// is written into it; anything else is refused instead of chmod-ed (see [`check_root`]).
    ///
    /// # Errors
    /// [`AppError::Io`] with [`std::io::ErrorKind::PermissionDenied`], naming the path, when the
    /// root is a symbolic link, is not a directory or belongs to someone else; plus any I/O error
    /// from creating the directory, reading its metadata or changing its mode.
    pub fn ensure(&self) -> Result<()> {
        std::fs::create_dir_all(&self.root)?;
        let Some(metadata) = self.check_existing_root()? else {
            // `create_dir_all` just succeeded, so it was there a moment ago and somebody has
            // removed it since -- exactly the kind of meddling this check is about.
            return Err(AppError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!(
                    "state directory {} disappeared while it was being created",
                    self.root.display()
                ),
            )));
        };
        if metadata.permissions().mode() & 0o777 != DIR_MODE {
            std::fs::set_permissions(&self.root, Permissions::from_mode(DIR_MODE))?;
        }
        Ok(())
    }

    /// Refuses a root that is not ours, **without** creating one.
    ///
    /// [`ensure`](Self::ensure) is the check of everything that writes into the directory
    /// (`crypto unlock` and the daemon). Everything that only *reads* it -- `status`, `lock`,
    /// `stats`, `events`, `fs` -- needs the same guarantee: on the shared default locations
    /// (`$XDG_RUNTIME_DIR`, `/tmp/crypto-<uid>`) another local user who wins the create race can
    /// otherwise plant a run info the CLI shows as fact and a socket that answers `hello`, so
    /// `crypto lock` would report success without anything being locked. No key and no signal is
    /// at risk, but the report is.
    ///
    /// A root that does not exist yet is fine and reports `Ok(())`: it holds no run infos and no
    /// sockets, and a read-only command must not create it.
    ///
    /// # Errors
    /// The same [`AppError::Io`] with [`std::io::ErrorKind::PermissionDenied`] as
    /// [`ensure`](Self::ensure), plus any I/O error from reading the root's metadata.
    pub fn validate(&self) -> Result<()> {
        self.check_existing_root().map(|_| ())
    }

    /// The root's metadata once [`check_root`] has accepted it, or `None` if there is no root yet.
    ///
    /// `symlink_metadata`, not `metadata`: the latter follows a symbolic link and would report the
    /// *target's* type and owner.
    fn check_existing_root(&self) -> Result<Option<Metadata>> {
        let metadata = match std::fs::symlink_metadata(&self.root) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(AppError::Io(e)),
        };
        if let Err(reason) = check_root(&metadata, nix::unistd::geteuid().as_raw()) {
            return Err(permission_denied(format!(
                "state directory {}: {reason}",
                self.root.display()
            )));
        }
        Ok(Some(metadata))
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
    /// Anything [`validate`](Self::validate) reports about a root that is not ours, plus I/O
    /// errors other than "the directory does not exist".
    pub fn list_run_infos(&self) -> Result<Vec<RunInfo>> {
        self.validate()?;
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

/// Whether the state directory's own metadata is acceptable: a real directory (not a symbolic
/// link, not a file) owned by `euid`.
///
/// Split out of [`StateDir::ensure`] and pure, so the ownership rule can be tested without
/// creating a directory of another user.
///
/// # Errors
/// [`AppError::Io`] with [`std::io::ErrorKind::PermissionDenied`] and the reason as its message.
pub fn check_root(metadata: &Metadata, euid: u32) -> Result<()> {
    if metadata.file_type().is_symlink() {
        return Err(permission_denied("is a symbolic link".to_owned()));
    }
    if !metadata.is_dir() {
        return Err(permission_denied("is not a directory".to_owned()));
    }
    let uid = metadata.uid();
    if uid != euid {
        return Err(permission_denied(format!(
            "belongs to uid {uid}, not to uid {euid}"
        )));
    }
    Ok(())
}

/// `EACCES`-flavoured [`AppError::Io`] carrying `message`.
fn permission_denied(message: String) -> AppError {
    AppError::Io(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        message,
    ))
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
    /// This is the **first** of the three state files a daemon publishes; see [`RunInfo`] for why
    /// the order matters.
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
    /// The **last** of the three files, written once the vault is mounted: it names the mount
    /// point, which only exists then. It must not run before [`VaultStateFiles::write_pid`] --
    /// a run info without a live pid and without a socket looks exactly like the leftover of a
    /// crashed daemon, and a concurrent `crypto status` removes it. See [`RunInfo`] for the whole
    /// order.
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
        self.remove(&[&self.socket, &self.pid, &self.info])
    }

    /// Removes socket and pid but **keeps the run info**, for a daemon that is giving up with its
    /// volume still mounted.
    ///
    /// That is exactly the leftover [`crate::registry::VaultRegistry::runtime_state`] reports as
    /// [`crate::registry::RuntimeState::StaleMount`]: nobody listens on the socket any more and
    /// the pid is gone, but `<id>.json` still names a mount point that is still mounted -- so
    /// `crypto status` says so and `crypto lock --force` has something to work with. Removing the
    /// run info too would leave a mounted volume nothing knows about.
    ///
    /// # Errors
    /// The first I/O error other than "not found"; the remaining file is still attempted.
    pub fn remove_for_stale(&self) -> Result<()> {
        self.remove(&[&self.socket, &self.pid])
    }

    fn remove(&self, paths: &[&PathBuf]) -> Result<()> {
        let mut first_error = None;
        for path in paths {
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
///
/// # Write order
///
/// A daemon publishes its state files in exactly this order:
///
/// 1. `<id>.pid` ([`VaultStateFiles::write_pid`]), as early as possible;
/// 2. `<id>.sock`, as soon as the control socket is bound -- the daemon has to be reachable
///    before it can be handed the vault key;
/// 3. `<id>.json` (this type, [`VaultStateFiles::write_info`]), right after the mount succeeded,
///    with [`RunInfo::mountpoint`] set to where the volume actually landed.
///
/// The reason is [`crate::registry::VaultRegistry::runtime_state`]: it recognises a starting
/// daemon by its live pid, and everything it finds without a live pid and without a listening
/// socket is a leftover it removes. Writing the run info first opens a window in which a
/// concurrent `crypto status` deletes the state of a perfectly healthy daemon; writing it before
/// the mount would leave stale-mount detection without the mount point it needs.
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
///
/// A missing parent directory is created 0700 rather than with the process umask, which would
/// leave the state directory world-traversable. This is a safety net only: the normal
/// precondition is [`StateDir::ensure`], which is the one place that also verifies the directory
/// is not a symbolic link and belongs to us.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        DirBuilder::new()
            .recursive(true)
            .mode(DIR_MODE)
            .create(parent)?;
    }
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "state".to_owned());
    let tmp = path.with_file_name(format!("{file_name}.{}.tmp", std::process::id()));
    // Remove a leftover first (a crash left one behind, or the pid was reused), because the open
    // below refuses an existing name. `remove_file` unlinks a symbolic link rather than following
    // it, so a planted one is taken away instead of being written through.
    match std::fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(AppError::Io(e)),
    }
    let written = std::fs::File::options()
        .write(true)
        // `create_new` (`O_EXCL`), not `create`: `O_EXCL` never follows a symbolic link, so a
        // link planted at the temp path cannot get its target truncated. This is the one write
        // that can run without `StateDir::ensure`/`validate` having vetted the directory.
        .create_new(true)
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
        let runtime = Some(Path::new("/run/user/501"));
        // Both branches are checked on every host: the platform is a parameter, not a `cfg!`.
        assert_eq!(
            default_state_dir(Platform::MacOs, home, runtime, 501),
            PathBuf::from("/home/u/Library/Application Support/Cryptomator/cli-run"),
            "macOS ignores XDG_RUNTIME_DIR"
        );
        assert_eq!(
            default_state_dir(Platform::MacOs, home, None, 501),
            PathBuf::from("/home/u/Library/Application Support/Cryptomator/cli-run")
        );
        assert_eq!(
            default_state_dir(Platform::Linux, home, runtime, 501),
            PathBuf::from("/run/user/501/crypto")
        );
        assert_eq!(
            default_state_dir(Platform::Linux, home, None, 501),
            PathBuf::from("/tmp/crypto-501")
        );
        assert_eq!(
            default_state_dir(Platform::Linux, home, Some(Path::new("")), 7),
            PathBuf::from("/tmp/crypto-7"),
            "an empty XDG_RUNTIME_DIR is no runtime dir"
        );
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
    fn ensure_refuses_a_state_directory_that_is_not_ours() {
        let dir = tempfile::tempdir().expect("temp dir");
        let target = dir.path().join("target");
        std::fs::create_dir(&target).expect("target");
        std::fs::set_permissions(&target, Permissions::from_mode(0o755)).expect("chmod");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        let err = StateDir::at(link.clone())
            .ensure()
            .expect_err("a symlinked state directory is refused");
        let AppError::Io(io) = &err else {
            panic!("expected an I/O error, got {err:?}")
        };
        assert_eq!(io.kind(), std::io::ErrorKind::PermissionDenied);
        let message = err.to_string();
        assert!(message.contains(&link.display().to_string()), "{message}");
        assert!(message.contains("symbolic link"), "{message}");
        assert_eq!(
            std::fs::metadata(&target)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o755,
            "the link's target was chmod-ed through the link"
        );
    }

    #[test]
    fn validate_accepts_a_missing_root_and_refuses_a_symlinked_one() {
        let dir = tempfile::tempdir().expect("temp dir");

        // A root that is not there yet holds no run infos and no sockets, and a read-only command
        // must not create one on the way.
        let missing = StateDir::at(dir.path().join("not-yet"));
        missing.validate().expect("a missing root is fine");
        assert!(!missing.root().exists(), "validate creates nothing");
        assert!(missing.list_run_infos().expect("list").is_empty());

        let target = dir.path().join("target");
        std::fs::create_dir(&target).expect("target");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        let planted = StateDir::at(link.clone());
        for err in [
            planted.validate().expect_err("a symlinked root"),
            planted.list_run_infos().expect_err("a symlinked root"),
        ] {
            let AppError::Io(io) = &err else {
                panic!("expected an I/O error, got {err:?}")
            };
            assert_eq!(io.kind(), std::io::ErrorKind::PermissionDenied);
            let message = err.to_string();
            assert!(message.contains(&link.display().to_string()), "{message}");
            assert!(message.contains("symbolic link"), "{message}");
        }

        // Our own directory passes, and nothing is created or changed by asking.
        let ours = StateDir::at(dir.path().join("ours"));
        ours.ensure().expect("ensure");
        ours.validate().expect("our own root");
    }

    #[test]
    fn write_private_does_not_follow_a_symlink_planted_at_the_temp_path() {
        let dir = tempfile::tempdir().expect("temp dir");
        let state = StateDir::at(dir.path().join("state"));
        state.ensure().expect("ensure");
        let files = state.files("CCCCCCCCCCCC");

        // The name `write_private` uses for its temporary file, plus a symbolic link pointing at
        // a file that must survive untouched.
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"do not truncate me").expect("victim");
        let tmp = files.pid.with_file_name(format!(
            "{}.{}.tmp",
            files.pid.file_name().expect("file name").to_string_lossy(),
            std::process::id()
        ));
        std::os::unix::fs::symlink(&victim, &tmp).expect("symlink");

        files.write_pid(4242).expect("the write still succeeds");
        assert_eq!(files.read_pid(), Some(4242));
        assert_eq!(
            std::fs::read(&victim).expect("victim"),
            b"do not truncate me",
            "the symlink's target was written through"
        );
        assert!(!tmp.exists(), "the temporary file is renamed away");
    }

    #[test]
    fn check_root_wants_our_own_directory() {
        let dir = tempfile::tempdir().expect("temp dir");
        let metadata = std::fs::symlink_metadata(dir.path()).expect("metadata");
        let euid = metadata.uid();
        check_root(&metadata, euid).expect("our own directory is fine");

        // The case that cannot be built in a test: a directory of another user.
        let err = check_root(&metadata, euid.wrapping_add(1)).expect_err("foreign owner");
        let AppError::Io(io) = &err else {
            panic!("expected an I/O error, got {err:?}")
        };
        assert_eq!(io.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(
            err.to_string().contains(&format!("belongs to uid {euid}")),
            "{err}"
        );

        // `create_dir_all` already fails on a plain file, so this branch only ever guards against
        // a future caller that skips it.
        let file = dir.path().join("file");
        std::fs::write(&file, b"x").expect("write");
        let metadata = std::fs::symlink_metadata(&file).expect("metadata");
        let err = check_root(&metadata, euid).expect_err("a file is no state directory");
        assert!(err.to_string().contains("not a directory"), "{err}");
    }

    #[test]
    fn a_pid_written_into_a_fresh_state_directory_creates_it_0700() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().join("fresh/state");
        // No `ensure()`: `write_private` must not leave the directory at the umask default.
        let files = StateDir::at(root.clone()).files("AAAAAAAAAAAA");
        files.write_pid(std::process::id()).expect("write pid");
        assert_eq!(files.read_pid(), Some(std::process::id()));
        for path in [root.as_path(), &dir.path().join("fresh")] {
            let mode = std::fs::metadata(path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o700, "{} has mode {mode:o}", path.display());
        }
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
