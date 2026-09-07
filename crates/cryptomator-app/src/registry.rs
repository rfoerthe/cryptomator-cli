//! What state a vault is in: what `settings.json` and the vault directory say, corrected by what
//! the [state directory](crate::state_dir) says about a running daemon.
//!
//! [`cryptomator_core::determine_vault_state`] only looks at the vault directory and therefore
//! cannot tell a locked vault from an unlocked one -- the ciphertext looks the same either way.
//! The runtime states come from the daemon's state files instead, in this order:
//!
//! 1. the control socket is connectable ⇒ `UNLOCKED`;
//! 2. no socket, but the pid is alive ⇒ `UNLOCKED` (the daemon is still starting up);
//! 3. neither, but the mount point is still in the mount table ⇒ `STALE_MOUNT` (the daemon died
//!    and left the volume behind; `crypto lock --force` takes it down);
//! 4. otherwise the files are leftovers: they are removed and the vault directory decides.
use crate::error::{AppError, Result};
use crate::settings::{resolve_vault_index, SettingsStore, VaultSettingsJson};
use crate::state_dir::{process_alive, RunInfo, StateDir};
use cryptomator_core::{determine_vault_state, VaultState};
use cryptomator_mount::mounttab::is_mountpoint;
use serde::Serialize;
use std::os::unix::net::UnixStream;
use std::path::Path;

/// A vault's state as the CLI reports it: [`VaultState`] plus the two states only a running
/// daemon can produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuntimeState {
    /// The vault directory is a vault and no daemon serves it.
    Locked,
    /// A daemon serves the vault (it may still be mounting).
    Unlocked,
    /// The daemon is gone but its volume is still mounted.
    StaleMount,
    /// The path is not a vault directory (or does not exist).
    Missing,
    /// `vault.cryptomator` is gone but a masterkey file is there.
    VaultConfigMissing,
    /// Neither `vault.cryptomator` nor `masterkey.cryptomator` is there.
    AllMissing,
    /// An older vault format that this version cannot open.
    NeedsMigration,
    /// The vault directory could not be inspected.
    Error,
}

impl RuntimeState {
    /// The name used in `--json` output and in messages.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Locked => "LOCKED",
            Self::Unlocked => "UNLOCKED",
            Self::StaleMount => "STALE_MOUNT",
            Self::Missing => "MISSING",
            Self::VaultConfigMissing => "VAULT_CONFIG_MISSING",
            Self::AllMissing => "ALL_MISSING",
            Self::NeedsMigration => "NEEDS_MIGRATION",
            Self::Error => "ERROR",
        }
    }

    /// Whether a daemon is serving this vault or has left a mount behind.
    pub fn is_mounted(self) -> bool {
        matches!(self, Self::Unlocked | Self::StaleMount)
    }
}

impl From<VaultState> for RuntimeState {
    fn from(state: VaultState) -> Self {
        match state {
            VaultState::Locked => Self::Locked,
            VaultState::Missing => Self::Missing,
            VaultState::VaultConfigMissing => Self::VaultConfigMissing,
            VaultState::AllMissing => Self::AllMissing,
            VaultState::NeedsMigration => Self::NeedsMigration,
        }
    }
}

impl std::fmt::Display for RuntimeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One row of `crypto status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultInfo {
    /// The vault's id in `settings.json`.
    pub id: String,
    /// Its display name, if it has one.
    pub display_name: Option<String>,
    /// The vault directory.
    pub path: Option<String>,
    /// The state, see [`RuntimeState`].
    pub state: RuntimeState,
    /// Where the volume is mounted (only when a daemon is running or left a mount behind).
    pub mountpoint: Option<String>,
    /// The Java class name of the mount service in use.
    pub mounter: Option<String>,
    /// The daemon's process id.
    pub pid: Option<u32>,
    /// Whether the volume is mounted read-only.
    pub read_only: Option<bool>,
}

/// The vaults in `settings.json`, each with its current [`RuntimeState`].
#[derive(Debug, Clone)]
pub struct VaultRegistry {
    store: SettingsStore,
    state_dir: StateDir,
}

impl VaultRegistry {
    /// The registry over `store`'s vaults and the daemons in `state_dir`.
    pub fn new(store: SettingsStore, state_dir: StateDir) -> Self {
        Self { store, state_dir }
    }

    /// The settings the registry reads.
    pub fn store(&self) -> &SettingsStore {
        &self.store
    }

    /// The state directory the registry watches.
    pub fn state_dir(&self) -> &StateDir {
        &self.state_dir
    }

    /// The state of the vault with this id, and the daemon's [`RunInfo`] if there is one.
    ///
    /// Leftover state files of a daemon that is gone are removed on the way, so a crashed daemon
    /// heals the next time anything asks for the state. Precisely: the files are removed when the
    /// pid file is absent or names a dead process **and** the socket does not accept a connection
    /// **and** the run info's mount point is no longer mounted. A *live* pid is a daemon that is
    /// still starting up and never reaches this branch (step 2 above reports it as
    /// [`RuntimeState::Unlocked`]), which is why a daemon writes `<id>.pid` first, then binds
    /// `<id>.sock`, and only writes `<id>.json` once the vault is mounted -- see [`RunInfo`]'s
    /// write order.
    ///
    /// # Errors
    /// Anything [`SettingsStore::load`] and [`StateDir::validate`] report.
    pub fn runtime_state(&self, vault_id: &str) -> Result<(RuntimeState, Option<RunInfo>)> {
        let settings = self.store.load()?;
        let vault = settings.directories.iter().find(|v| v.id == vault_id);
        self.runtime_state_of(
            vault_id,
            vault.and_then(VaultSettingsJson::path_buf).as_deref(),
        )
    }

    /// [`VaultRegistry::runtime_state`] for a vault that has already been looked up; `path` is the
    /// vault directory from `settings.json`, if it has one.
    ///
    /// # Errors
    /// [`StateDir::validate`]: everything below reads the state files, connects to the socket and
    /// deletes leftovers, so a state directory that is not ours is refused here rather than
    /// trusted -- see that method for what a foreign one could otherwise claim.
    fn runtime_state_of(
        &self,
        vault_id: &str,
        path: Option<&Path>,
    ) -> Result<(RuntimeState, Option<RunInfo>)> {
        self.state_dir.validate()?;
        let files = self.state_dir.files(vault_id);
        let info = files.read_info();
        // A socket file that nobody listens on is a leftover; only a successful connect proves
        // that a daemon is there.
        if files.socket.exists() && UnixStream::connect(&files.socket).is_ok() {
            return Ok((RuntimeState::Unlocked, info));
        }
        // Between fork and `bind` there is no socket yet, but there is a pid file.
        if files.read_pid().is_some_and(process_alive) {
            return Ok((RuntimeState::Unlocked, info));
        }
        if let Some(mountpoint) = info.as_ref().and_then(|i| i.mountpoint.as_deref()) {
            if is_local_path(mountpoint) && is_mountpoint(Path::new(mountpoint)) {
                return Ok((RuntimeState::StaleMount, info));
            }
        }
        // `files.info.exists()`, not `info.is_some()`: a corrupt `<id>.json` cannot be parsed but
        // is a leftover all the same, and would otherwise keep `list_run_infos` skipping it
        // forever.
        if files.info.exists() || files.pid.exists() || files.socket.exists() {
            log::debug!("removing leftover state files of vault {vault_id}");
            if let Err(e) = files.remove_all() {
                log::warn!("cannot remove the state files of vault {vault_id}: {e}");
            }
        }
        let Some(path) = path else {
            return Ok((RuntimeState::Missing, None));
        };
        Ok(match determine_vault_state(path) {
            Ok(state) => (state.into(), None),
            Err(e) => {
                log::debug!("cannot determine the state of {}: {e}", path.display());
                (RuntimeState::Error, None)
            }
        })
    }

    /// Every vault in `settings.json`, in the order the file lists them.
    ///
    /// # Errors
    /// Anything [`SettingsStore::load`] and [`StateDir::validate`] report.
    pub fn infos(&self) -> Result<Vec<VaultInfo>> {
        let settings = self.store.load()?;
        settings
            .directories
            .iter()
            .map(|v| self.info_of(v))
            .collect()
    }

    /// The vault matching `reference` (id, display name or path).
    ///
    /// # Errors
    /// [`AppError::VaultNotFound`] or [`AppError::AmbiguousVault`] from
    /// [`resolve_vault_index`], plus anything [`SettingsStore::load`] and [`StateDir::validate`]
    /// report.
    pub fn info(&self, reference: &str) -> Result<VaultInfo> {
        let settings = self.store.load()?;
        let index = resolve_vault_index(&settings, reference)?;
        self.info_of(&settings.directories[index])
    }

    /// The settings entry plus its runtime state.
    ///
    /// # Errors
    /// Anything [`runtime_state_of`](Self::runtime_state_of) reports.
    fn info_of(&self, vault: &VaultSettingsJson) -> Result<VaultInfo> {
        let path = vault.path_buf();
        let (state, info) = self.runtime_state_of(&vault.id, path.as_deref())?;
        let running = info.filter(|_| state.is_mounted());
        Ok(VaultInfo {
            id: vault.id.clone(),
            display_name: vault.display_name.clone(),
            path: vault.path.clone(),
            state,
            mountpoint: running.as_ref().and_then(|i| i.mountpoint.clone()),
            mounter: running.as_ref().map(|i| i.mounter.clone()),
            pid: running.as_ref().map(|i| i.pid),
            read_only: running.as_ref().map(|i| i.read_only),
        })
    }

    /// The mount-service class names of every vault that is currently unlocked, taken from the
    /// run infos in the state directory. The mounter uses them to refuse a mount service that
    /// conflicts with one already in use, see [`crate::mounting::conflicts_with`].
    ///
    /// # Errors
    /// Anything [`StateDir::list_run_infos`] reports.
    pub fn running_mounters(&self) -> Result<Vec<String>> {
        Ok(self
            .state_dir
            .list_run_infos()?
            .into_iter()
            .filter(|info| process_alive(info.pid))
            .map(|info| info.mounter)
            .collect())
    }

    /// Requires the vault to be locked: refuses one a daemon is already serving, or whose volume
    /// a crashed daemon left behind. Used by both the `fs` commands and `crypto unlock` -- a
    /// single wording for one condition, with the `crypto lock --force` hint that gets a stale
    /// mount out of the way.
    ///
    /// # Errors
    /// [`AppError::WrongState`] when a daemon serves the vault or left a mount behind, plus
    /// anything [`StateDir::validate`] reports.
    pub fn require_locked(&self, vault: &VaultSettingsJson) -> Result<()> {
        let path = vault.path_buf();
        let (state, info) = self.runtime_state_of(&vault.id, path.as_deref())?;
        if !state.is_mounted() {
            return Ok(());
        }
        let where_ = info
            .and_then(|i| i.mountpoint)
            .map(|mp| format!(" (mounted at {mp})"))
            .unwrap_or_default();
        let hint = if state == RuntimeState::StaleMount {
            format!(
                " -- a previous daemon left the volume behind; take it down with \
                 `crypto lock {} --force`",
                vault.id
            )
        } else {
            String::new()
        };
        Err(AppError::WrongState {
            expected: VaultState::Locked.to_string(),
            actual: format!("{state}{where_}{hint}"),
        })
    }
}

/// Whether a run info's `mountpoint` can be looked up in the mount table at all.
///
/// Only an absolute path can. A URL is what the WebDAV back ends report, and a crashed WebDAV
/// daemon leaves nothing to take down -- its server died with it -- so such a mount point is never
/// a stale mount, only a leftover state file.
fn is_local_path(mountpoint: &str) -> bool {
    mountpoint.starts_with('/')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::VaultSettingsJson;
    use crate::state_dir::RunInfo;
    use cryptomator_core::constants::DEFAULT_KEY_ID;
    use cryptomator_core::{initialize, CipherCombo, Masterkey, OsRng};
    use std::path::PathBuf;
    use tempfile::TempDir;

    struct Fixture {
        _dir: TempDir,
        registry: VaultRegistry,
        vault_path: PathBuf,
    }

    /// A settings file with one initialised vault ("V") and an empty state directory.
    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().expect("temp dir");
        let vault_path = dir.path().join("vaults/V");
        std::fs::create_dir_all(&vault_path).expect("vault dir");
        initialize(
            &vault_path,
            &Masterkey::from_raw([7u8; 64]),
            CipherCombo::SivGcm,
            220,
            DEFAULT_KEY_ID,
            &mut OsRng,
        )
        .expect("initialize");
        let mut settings = crate::settings::SettingsJson::default();
        let mut vault = VaultSettingsJson::new("AAAAAAAAAAAA".to_owned(), &vault_path);
        vault.display_name = Some("V".to_owned());
        settings.directories.push(vault);
        let store = SettingsStore::at(dir.path().join("settings.json"));
        store.save(&mut settings).expect("save settings");
        let state_dir = StateDir::at(dir.path().join("state"));
        state_dir.ensure().expect("ensure");
        Fixture {
            _dir: dir,
            registry: VaultRegistry::new(store, state_dir),
            vault_path,
        }
    }

    /// A state directory another local user planted: on the shared default locations the loser of
    /// the create race would otherwise read a forged run info and connect to a foreign socket.
    #[test]
    fn a_state_directory_that_is_not_ours_is_refused_by_every_read_path() {
        let f = fixture();
        let root = f.registry.state_dir().root().to_path_buf();
        let elsewhere = root.with_file_name("elsewhere");
        std::fs::create_dir_all(&elsewhere).expect("other directory");
        std::fs::remove_dir_all(&root).expect("remove the real one");
        std::os::unix::fs::symlink(&elsewhere, &root).expect("symlink");

        let vault = VaultSettingsJson::new("AAAAAAAAAAAA".to_owned(), Path::new("/vaults/V"));
        for err in [
            f.registry
                .runtime_state("AAAAAAAAAAAA")
                .expect_err("crypto status <vault>"),
            f.registry.infos().expect_err("crypto status"),
            f.registry.info("V").expect_err("crypto lock"),
            f.registry
                .running_mounters()
                .expect_err("the mounter's conflict check"),
            f.registry.require_locked(&vault).expect_err("crypto fs"),
        ] {
            let AppError::Io(io) = &err else {
                panic!("expected an I/O error, got {err:?}")
            };
            assert_eq!(io.kind(), std::io::ErrorKind::PermissionDenied);
            assert!(err.to_string().contains("symbolic link"), "{err}");
        }
    }

    /// The other half: a root that simply is not there yet must not turn every command into an
    /// error -- it holds no daemons, so the vault directory decides.
    #[test]
    fn a_missing_state_directory_reports_the_states_on_disk() {
        let f = fixture();
        std::fs::remove_dir_all(f.registry.state_dir().root()).expect("remove");
        assert_eq!(
            f.registry.runtime_state("AAAAAAAAAAAA").expect("state").0,
            RuntimeState::Locked
        );
        assert_eq!(
            f.registry.info("V").expect("info").state,
            RuntimeState::Locked
        );
        assert_eq!(f.registry.infos().expect("infos").len(), 1);
        assert!(f.registry.running_mounters().expect("mounters").is_empty());
        assert!(
            !f.registry.state_dir().root().exists(),
            "reading the registry does not create the state directory"
        );
    }

    fn run_info(pid: u32, mountpoint: Option<&str>) -> RunInfo {
        RunInfo {
            vault_id: "AAAAAAAAAAAA".to_owned(),
            path: "/vaults/V".to_owned(),
            mounter: "org.cryptomator.cli.NullMountProvider".to_owned(),
            mountpoint: mountpoint.map(str::to_owned),
            pid,
            started_at: 1_757_000_000,
            read_only: true,
        }
    }

    /// A pid that is certainly free: a child that has already been reaped.
    fn dead_pid() -> u32 {
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("spawn true");
        let pid = child.id();
        child.wait().expect("wait");
        pid
    }

    #[test]
    fn without_state_files_the_vault_directory_decides() {
        let f = fixture();
        let (state, info) = f.registry.runtime_state("AAAAAAAAAAAA").expect("state");
        assert_eq!(state, RuntimeState::Locked);
        assert!(info.is_none());

        let infos = f.registry.infos().expect("infos");
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].state, RuntimeState::Locked);
        assert_eq!(infos[0].display_name.as_deref(), Some("V"));
        assert!(infos[0].mountpoint.is_none() && infos[0].pid.is_none());
        assert_eq!(f.registry.info("V").expect("by name").id, "AAAAAAAAAAAA");
        assert!(matches!(
            f.registry.info("nope"),
            Err(AppError::VaultNotFound(_))
        ));

        // The vault directory is gone: MISSING, not LOCKED.
        std::fs::remove_dir_all(&f.vault_path).expect("remove vault");
        assert_eq!(
            f.registry.runtime_state("AAAAAAAAAAAA").expect("state").0,
            RuntimeState::Missing
        );
        assert_eq!(
            f.registry.runtime_state("no-such-vault").expect("state").0,
            RuntimeState::Missing,
            "an unknown id has no path to look at"
        );
    }

    #[test]
    fn a_dead_daemon_without_a_mount_leaves_a_locked_vault_and_no_files() {
        let f = fixture();
        let files = f.registry.state_dir().files("AAAAAAAAAAAA");
        let mountpoint = f._dir.path().join("mnt/V");
        std::fs::create_dir_all(&mountpoint).expect("mount dir");
        files
            .write_info(&run_info(dead_pid(), Some(&mountpoint.to_string_lossy())))
            .expect("write info");
        files.write_pid(dead_pid()).expect("write pid");
        std::fs::write(&files.socket, b"").expect("leftover socket");

        let (state, info) = f.registry.runtime_state("AAAAAAAAAAAA").expect("state");
        assert_eq!(state, RuntimeState::Locked);
        assert!(info.is_none());
        assert!(!files.info.exists(), "the leftovers are cleaned up");
        assert!(!files.pid.exists());
        assert!(!files.socket.exists());
        assert!(f.registry.running_mounters().expect("mounters").is_empty());
    }

    #[test]
    fn a_corrupt_run_info_is_removed_like_any_other_leftover() {
        let f = fixture();
        let files = f.registry.state_dir().files("AAAAAAAAAAAA");
        std::fs::write(&files.info, b"{not json").expect("write");
        assert!(files.read_info().is_none(), "nothing to parse");

        let (state, info) = f.registry.runtime_state("AAAAAAAAAAAA").expect("state");
        assert_eq!(state, RuntimeState::Locked);
        assert!(info.is_none());
        assert!(
            !files.info.exists(),
            "an unparsable run info is a leftover too"
        );
    }

    #[test]
    fn a_dead_daemon_with_a_live_mount_is_a_stale_mount() {
        let f = fixture();
        let files = f.registry.state_dir().files("AAAAAAAAAAAA");
        // `/` is a mount point on every system this runs on.
        files
            .write_info(&run_info(dead_pid(), Some("/")))
            .expect("write info");

        let (state, info) = f.registry.runtime_state("AAAAAAAAAAAA").expect("state");
        assert_eq!(state, RuntimeState::StaleMount);
        assert_eq!(info.expect("run info").mountpoint.as_deref(), Some("/"));
        assert!(files.info.is_file(), "a stale mount keeps its run info");

        let info = f.registry.info("V").expect("info");
        assert_eq!(info.state, RuntimeState::StaleMount);
        assert_eq!(info.mountpoint.as_deref(), Some("/"));
        assert_eq!(
            info.mounter.as_deref(),
            Some("org.cryptomator.cli.NullMountProvider")
        );
        assert_eq!(info.read_only, Some(true));

        let vault = VaultSettingsJson::new("AAAAAAAAAAAA".to_owned(), &f.vault_path);
        let err = f
            .registry
            .require_locked(&vault)
            .expect_err("the fs commands refuse a stale mount");
        assert!(matches!(err, AppError::WrongState { .. }), "{err:?}");
        assert!(err.to_string().contains("mounted at /"), "{err}");
    }

    /// A WebDAV daemon that crashed leaves nothing behind: there is no volume in the mount table,
    /// so the state files are leftovers and the vault is simply locked again.
    #[test]
    fn a_uri_mountpoint_is_never_a_stale_mount() {
        let f = fixture();
        let files = f.registry.state_dir().files("AAAAAAAAAAAA");
        let mut info = run_info(dead_pid(), Some("http://127.0.0.1:42427/AAAAAAAAAAAA"));
        info.mounter = "org.cryptomator.frontend.webdav.mount.FallbackMounter".to_owned();
        files.write_info(&info).expect("write info");

        let (state, info) = f.registry.runtime_state("AAAAAAAAAAAA").expect("state");
        assert_eq!(
            state,
            RuntimeState::Locked,
            "a URL is nothing `crypto lock --force` could take down"
        );
        assert!(info.is_none());
        assert!(!files.info.exists(), "the leftovers are gone");

        // Not STALE_MOUNT, so nothing blocks the next unlock either.
        let vault = VaultSettingsJson::new("AAAAAAAAAAAA".to_owned(), &f.vault_path);
        f.registry
            .require_locked(&vault)
            .expect("a URI mount point never blocks an unlock");
    }

    /// The rule behind it, on its own: only an absolute path is ever looked up in the mount table.
    #[test]
    fn only_an_absolute_path_is_looked_up_in_the_mount_table() {
        assert!(is_local_path("/mnt/v"));
        assert!(is_local_path("/"));
        assert!(!is_local_path("http://127.0.0.1:42427/AAAAAAAAAAAA"));
        assert!(!is_local_path("dav://localhost/v"));
        assert!(!is_local_path(""));
    }

    #[test]
    fn a_live_socket_means_unlocked() {
        let f = fixture();
        let files = f.registry.state_dir().files("AAAAAAAAAAAA");
        let listener =
            std::os::unix::net::UnixListener::bind(&files.socket).expect("bind the socket");
        files
            .write_info(&run_info(std::process::id(), Some("/mnt/V")))
            .expect("write info");

        let (state, info) = f.registry.runtime_state("AAAAAAAAAAAA").expect("state");
        assert_eq!(state, RuntimeState::Unlocked);
        assert_eq!(info.expect("run info").pid, std::process::id());
        assert_eq!(
            f.registry.running_mounters().expect("mounters"),
            vec!["org.cryptomator.cli.NullMountProvider".to_owned()]
        );
        let vault = VaultSettingsJson::new("AAAAAAAAAAAA".to_owned(), &f.vault_path);
        assert!(f.registry.require_locked(&vault).is_err());
        drop(listener);

        // Socket gone, but the daemon (this process) is still starting up.
        std::fs::remove_file(&files.socket).expect("remove socket");
        files.write_pid(std::process::id()).expect("write pid");
        assert_eq!(
            f.registry.runtime_state("AAAAAAAAAAAA").expect("state").0,
            RuntimeState::Unlocked
        );
    }

    #[test]
    fn runtime_states_carry_the_java_names() {
        assert_eq!(RuntimeState::StaleMount.as_str(), "STALE_MOUNT");
        assert_eq!(
            RuntimeState::from(VaultState::NeedsMigration).as_str(),
            "NEEDS_MIGRATION"
        );
        assert_eq!(
            RuntimeState::from(VaultState::AllMissing),
            RuntimeState::AllMissing
        );
        assert_eq!(
            serde_json::to_string(&RuntimeState::VaultConfigMissing).expect("serialize"),
            "\"VAULT_CONFIG_MISSING\""
        );
        assert!(RuntimeState::Unlocked.is_mounted() && !RuntimeState::Locked.is_mounted());
        assert_eq!(RuntimeState::Error.to_string(), "ERROR");
    }
}
