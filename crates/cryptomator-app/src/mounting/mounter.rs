//! Picking a mount service and configuring it, ported from the desktop app's
//! `common/mount/Mounter.java` (`SettledMounter.prepare` and `prepareMountPoint`).
//!
//! The vault's settings, `cli.json` and the command line together decide *which* service mounts
//! the vault and *how*; this module applies them the way the desktop app does, so a vault that the
//! GUI mounts at `~/…/mnt/Vault` read-only ends up in the same place with the same flags here.
use crate::cli_config::CliConfig;
use crate::error::{AppError, Result};
use crate::settings::{SettingsJson, VaultSettingsJson};
use cryptomator_core::fs::CryptoFs;
use cryptomator_mount::api::{MountBuilder, MountCapability, MountService, Mountpoint};
use cryptomator_mount::registry::conflicting_classes;
use cryptomator_mount::Mount;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// The `fsname` every Cryptomator mount reports (`SettledMounter.prepare`).
pub const FILE_SYSTEM_NAME: &str = "cryptoFs";

/// What a forced unmount of a service that has none is refused with, after `<service class>: `.
///
/// Shared by [`MountHandle::unmount`] and the daemon's `lock --force`, which refuses before it
/// takes the mount out of its state and would otherwise word the same refusal differently.
pub const FORCED_UNMOUNT_UNSUPPORTED: &str = "this mounter does not support forced unmount";

/// Everything the mounter needs about one vault: its settings, the two configuration files they
/// are read together with, the user's home directory (for the default mount-point base) and what
/// the command line overrides.
#[derive(Debug)]
pub struct MountRequest<'a> {
    /// The vault's entry in `settings.json`.
    pub vault: &'a VaultSettingsJson,
    /// The desktop app's settings, for the fallback mount service.
    pub settings: &'a SettingsJson,
    /// The CLI's own settings.
    pub cli: &'a CliConfig,
    /// The user's home directory; the default mount-point base is derived from it.
    pub home: &'a Path,
    /// What `crypto unlock` was told on the command line.
    pub overrides: MountOverrides,
    /// The Java class names of the mount services other unlocked vaults are using, from
    /// [`crate::registry::VaultRegistry::running_mounters`]. [`mount`] refuses a service that
    /// conflicts with one of them (macFUSE vs. FUSE-T); empty means "nothing else is mounted".
    pub running_services: Vec<String>,
}

/// The command line's say in how a vault is mounted. Every field that is `None`/empty leaves the
/// settings alone.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MountOverrides {
    /// The Java class name of the mount service (`--mounter`, aliases already resolved by
    /// [`crate::mounters::resolve_mounter`]).
    pub mounter: Option<String>,
    /// Where to mount (`--mount-point`).
    pub mount_point: Option<PathBuf>,
    /// Extra mount flags (`--mount-option=-o…`), appended to the configured ones.
    pub mount_options: Vec<String>,
    /// Mount read-only (`--read-only`); overrides `usesReadOnlyMode`.
    pub read_only: Option<bool>,
    /// The volume name (`--volume-name`); overrides the vault's mount name.
    pub volume_name: Option<String>,
}

/// A live mount plus what the CLI has to remember to take it down again.
pub struct MountHandle {
    /// The mount itself.
    pub mount: Box<dyn Mount>,
    /// Whether the service implements [`Mount::unmount_forced`].
    pub supports_forced: bool,
    /// The mount directory this mount created; removed by [`MountHandle::close`] once the volume
    /// is gone (Java's `specialCleanup`). `None` when the mount point was already there, whoever
    /// made it.
    pub cleanup: Option<PathBuf>,
    /// The Java class name of the mount service that produced this mount.
    pub service_class: String,
}

impl std::fmt::Debug for MountHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MountHandle")
            .field("mountpoint", &self.mount.mountpoint())
            .field("supports_forced", &self.supports_forced)
            .field("cleanup", &self.cleanup)
            .field("service_class", &self.service_class)
            .finish()
    }
}

impl MountHandle {
    /// Where the volume can be reached.
    pub fn mountpoint(&self) -> Mountpoint {
        self.mount.mountpoint()
    }

    /// Takes the volume down, forcefully if asked to.
    ///
    /// # Errors
    /// [`AppError::UnmountFailed`] if the volume is busy, if the unmount command fails, or if a
    /// forced unmount was asked of a service that has none.
    pub fn unmount(&mut self, forced: bool) -> Result<()> {
        let result = if forced {
            if !self.supports_forced {
                return Err(AppError::UnmountFailed(format!(
                    "{}: {FORCED_UNMOUNT_UNSUPPORTED}",
                    self.service_class
                )));
            }
            self.mount.unmount_forced()
        } else {
            self.mount.unmount()
        };
        result.map_err(|e| AppError::UnmountFailed(e.to_string()))
    }

    /// Releases the mount -- unmounting it if [`MountHandle::unmount`] has not already -- and
    /// removes the mount directory the mounter created.
    ///
    /// Removing the directory is best effort: it is empty exactly when the volume is gone, and a
    /// directory the user has meanwhile put something into is worth keeping over reporting an
    /// error nobody can act on.
    ///
    /// # Errors
    /// [`AppError::UnmountFailed`] if the volume could not be released.
    pub fn close(self) -> Result<()> {
        self.mount
            .close()
            .map_err(|e| AppError::UnmountFailed(e.to_string()))?;
        if let Some(dir) = &self.cleanup {
            if let Err(e) = std::fs::remove_dir(dir) {
                log::debug!("keeping the mount directory {}: {e}", dir.display());
            }
        }
        Ok(())
    }
}

/// Whether `class` must not be used while any of `running` is mounted (macFUSE vs. FUSE-T).
///
/// The desktop app keeps the services it has used in a set; the CLI's daemons are separate
/// processes, so the caller passes the mounters of the currently unlocked vaults instead (see
/// [`crate::registry::VaultRegistry::running_mounters`]).
pub fn conflicts_with(class: &str, running: &[String]) -> bool {
    conflicting_running(class, running).is_some()
}

/// The first of `running` that `class` must not be used alongside, for the error message.
fn conflicting_running<'a>(class: &str, running: &'a [String]) -> Option<&'a str> {
    let conflicting = conflicting_classes(class);
    running
        .iter()
        .map(String::as_str)
        .find(|other| conflicting.contains(other))
}

/// The first mount service named by the command line, the vault, `cli.json` or `settings.json`;
/// without any of those, the first supported one in `services` (they are ordered by priority).
///
/// `services` is expected to be [`cryptomator_mount::registry::all_services`], the *unfiltered*
/// list: a named service that this build knows but that does not work on this machine then gets
/// the accurate "not available on this system" instead of the misleading hint to run
/// `crypto mounters --all`. Passing the pre-filtered
/// [`cryptomator_mount::registry::services`] makes that branch unreachable.
///
/// # Errors
/// [`AppError::MountFailed`] if the named service is unknown to this build or does not work on
/// this machine, or if nothing in `services` works here.
pub fn choose_service<'a>(
    req: &MountRequest<'_>,
    services: &'a [Box<dyn MountService>],
) -> Result<&'a dyn MountService> {
    let named = named(req.overrides.mounter.as_deref())
        .or_else(|| named(req.vault.mount_service.as_deref()))
        .or_else(|| named(req.cli.default_mounter.as_deref()))
        .or_else(|| named(req.settings.mount_service.as_deref()));
    if let Some(class) = named {
        let service = services
            .iter()
            .find(|service| service.java_class_name() == class)
            .ok_or_else(|| {
                AppError::MountFailed(format!(
                    "mount service {class} not available; `crypto mounters --all` lists the known ones"
                ))
            })?;
        if !service.is_supported() {
            return Err(AppError::MountFailed(format!(
                "mount service {class} not available on this system"
            )));
        }
        return Ok(service.as_ref());
    }
    services
        .iter()
        .find(|service| service.is_supported())
        .map(Box::as_ref)
        .ok_or_else(|| {
            AppError::MountFailed(
                "no mount service is available; install FUSE-T or macFUSE (macOS) or fuse3 (Linux)"
                    .to_owned(),
            )
        })
}

/// A configured value: `None` and blank both mean "not configured".
fn named(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

/// Mounts `fs` as the vault's settings and the command line ask for.
///
/// Follows `Mounter.mount`: pick the service, refuse it if it conflicts with one another unlocked
/// vault is using (Java's `isConflictingMountService`, here over
/// [`MountRequest::running_services`]), configure the builder as far as its capabilities allow,
/// prepare the mount point and mount.
///
/// # Errors
/// [`AppError::MountFailed`] if no service fits, if the chosen one conflicts with a running one
/// or if the mount itself fails, and [`AppError::MountPointInvalid`] if the chosen mount point
/// cannot be used.
pub fn mount(
    req: &MountRequest<'_>,
    services: &[Box<dyn MountService>],
    fs: Arc<CryptoFs>,
) -> Result<MountHandle> {
    let service = choose_service(req, services)?;
    let class = service.java_class_name();
    if let Some(other) = conflicting_running(class, &req.running_services) {
        return Err(AppError::MountFailed(format!(
            "mount service {class} conflicts with running {other}"
        )));
    }
    let mut builder = service.for_file_system(fs);
    apply_capabilities(req, service, builder.as_mut())?;
    let cleanup = prepare_mount_point(req, service, builder.as_mut())?;
    log::debug!(
        "mounting vault {} with {}",
        req.vault.id,
        service.java_class_name()
    );
    let mount = builder.mount().map_err(|e| {
        // The directory this mounter created is of no use if the mount failed.
        if let Some(dir) = &cleanup {
            let _ = std::fs::remove_dir(dir);
        }
        AppError::MountFailed(e.to_string())
    })?;
    Ok(MountHandle {
        mount,
        supports_forced: service.has_capability(MountCapability::UnmountForced),
        cleanup,
        service_class: service.java_class_name().to_owned(),
    })
}

/// `SettledMounter.prepare`: every capability the service advertises is configured from the
/// vault's settings, the rest is left alone. `LOOPBACK_PORT`/`LOOPBACK_HOST_NAME` belong to the
/// WebDAV back end, which lands in M5.
fn apply_capabilities(
    req: &MountRequest<'_>,
    service: &dyn MountService,
    builder: &mut dyn MountBuilder,
) -> Result<()> {
    let read_only = req
        .overrides
        .read_only
        .unwrap_or(req.vault.uses_read_only_mode);
    let flags = mount_flags(req, service, read_only)?;
    let volume_name = req
        .overrides
        .volume_name
        .clone()
        .unwrap_or_else(|| req.vault.mount_name());
    for capability in service.capabilities().iter().copied() {
        let outcome = match capability {
            MountCapability::FileSystemName => builder.set_file_system_name(FILE_SYSTEM_NAME),
            MountCapability::ReadOnly => builder.set_read_only(read_only),
            MountCapability::MountFlags => builder.set_mount_flags(&flags),
            MountCapability::VolumeId => builder.set_volume_id(&req.vault.id),
            MountCapability::VolumeName => builder.set_volume_name(&volume_name),
            // The mount point is prepared separately, and network mounts are M5.
            MountCapability::LoopbackPort
            | MountCapability::LoopbackHostName
            | MountCapability::MountToExistingDir
            | MountCapability::MountWithinExistingParent
            | MountCapability::MountAsDriveLetter
            | MountCapability::MountToSystemChosenPath
            | MountCapability::UnmountForced => Ok(()),
        };
        outcome.map_err(|e| {
            AppError::MountFailed(format!("{}: {e}", capability.java_name().to_lowercase()))
        })?;
    }
    Ok(())
}

/// The vault's mount flags, or the service's defaults when it has none, plus the `--mount-option`
/// values.
///
/// A service without `READ_ONLY` gets `-oro` appended instead, which is how libfuse is told to
/// mount read-only; refusing to mount at all would be the only alternative, and silently mounting
/// a writable volume when the user asked for a read-only one is not one.
fn mount_flags(
    req: &MountRequest<'_>,
    service: &dyn MountService,
    read_only: bool,
) -> Result<String> {
    let supports_flags = service.has_capability(MountCapability::MountFlags);
    if !supports_flags {
        if !req.overrides.mount_options.is_empty() {
            return Err(AppError::MountFailed(format!(
                "{} takes no mount options",
                service.java_class_name()
            )));
        }
        if read_only && !service.has_capability(MountCapability::ReadOnly) {
            return Err(AppError::MountFailed(format!(
                "{} cannot mount read-only",
                service.java_class_name()
            )));
        }
        return Ok(String::new());
    }
    let mut flags: Vec<String> = Vec::new();
    if req.vault.mount_flags.trim().is_empty() {
        flags.push(service.default_mount_flags());
    } else {
        flags.push(req.vault.mount_flags.clone());
    }
    flags.extend(req.overrides.mount_options.iter().cloned());
    if read_only && !service.has_capability(MountCapability::ReadOnly) {
        flags.push("-oro".to_owned());
    }
    flags.retain(|flag| !flag.trim().is_empty());
    Ok(flags.join(" "))
}

/// `Mounter.prepareMountPoint`, without the Windows branches.
///
/// A mount point the user chose is validated here so the error names the path and says what is
/// wrong with it; without one, a service that picks its own mount point is left to do so and
/// every other service mounts to `<mountPointsDir>/<mountName>`, which is created and reported
/// back for [`MountHandle::close`] to remove again.
fn prepare_mount_point(
    req: &MountRequest<'_>,
    service: &dyn MountService,
    builder: &mut dyn MountBuilder,
) -> Result<Option<PathBuf>> {
    let can_mount_to_dir = service.has_capability(MountCapability::MountToExistingDir);
    let can_mount_to_system = service.has_capability(MountCapability::MountToSystemChosenPath);
    let chosen = req
        .overrides
        .mount_point
        .clone()
        .or_else(|| req.vault.mount_point.as_deref().map(PathBuf::from));

    if let Some(path) = chosen {
        if path.exists() {
            if !path.is_dir() {
                return Err(AppError::MountPointInvalid(
                    path,
                    "not a directory".to_owned(),
                ));
            }
            if !can_mount_to_dir {
                return Err(AppError::MountPointInvalid(
                    path,
                    format!(
                        "{} does not mount to an existing directory",
                        service.java_class_name()
                    ),
                ));
            }
        } else if !can_mount_to_system {
            // Only a service that chooses its own mount point (macFUSE under /Volumes) may be
            // handed a path that is not there yet.
            return Err(AppError::MountPointInvalid(
                path,
                "does not exist".to_owned(),
            ));
        }
        builder
            .set_mountpoint(&path)
            .map_err(|e| AppError::MountPointInvalid(path.clone(), e.to_string()))?;
        return Ok(None);
    }

    if can_mount_to_system {
        return Ok(None);
    }
    if !can_mount_to_dir {
        return Err(AppError::MountFailed(format!(
            "{} needs an explicit mount point",
            service.java_class_name()
        )));
    }
    let dir = req
        .cli
        .mount_points_dir(req.home)
        .join(req.vault.mount_name());
    // Only a directory this call created is ours to remove again: `<mountPointsDir>/<name>` may
    // well be a directory the user made himself, and Java never removes that one either.
    let created = !dir.exists();
    std::fs::create_dir_all(&dir)?;
    builder.set_mountpoint(&dir).map_err(|e| {
        if created {
            let _ = std::fs::remove_dir(&dir);
        }
        AppError::MountPointInvalid(dir.clone(), e.to_string())
    })?;
    Ok(created.then_some(dir))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::SettingsJson;
    use cryptomator_core::constants::DEFAULT_KEY_ID;
    use cryptomator_core::fs::CryptoFsOptions;
    use cryptomator_core::{initialize, open_vault_with_key, CipherCombo, Masterkey, OsRng};
    use cryptomator_mount::api::{MountError, UnmountError};
    use cryptomator_mount::registry::{NullMountProvider, NULL_MOUNTER_CLASS, NULL_MOUNT_MARKER};
    use std::sync::Mutex;
    use tempfile::TempDir;

    const CAPS_ALL: &[MountCapability] = &[
        MountCapability::FileSystemName,
        MountCapability::MountFlags,
        MountCapability::MountToExistingDir,
        MountCapability::ReadOnly,
        MountCapability::UnmountForced,
        MountCapability::VolumeId,
        MountCapability::VolumeName,
    ];

    /// What a [`FakeService`]'s builder was told.
    #[derive(Debug, Default, Clone, PartialEq, Eq)]
    struct Recorded {
        file_system_name: Option<String>,
        mountpoint: Option<PathBuf>,
        flags: Option<String>,
        read_only: Option<bool>,
        volume_id: Option<String>,
        volume_name: Option<String>,
    }

    /// A mount service that mounts nothing and only remembers how it was configured.
    struct FakeService {
        class: &'static str,
        supported: bool,
        capabilities: &'static [MountCapability],
        recorded: Arc<Mutex<Recorded>>,
    }

    impl FakeService {
        fn new(class: &'static str, supported: bool) -> Self {
            Self {
                class,
                supported,
                capabilities: CAPS_ALL,
                recorded: Arc::new(Mutex::new(Recorded::default())),
            }
        }
    }

    impl MountService for FakeService {
        fn java_class_name(&self) -> &'static str {
            self.class
        }
        fn display_name(&self) -> &'static str {
            "Fake"
        }
        fn priority(&self) -> u32 {
            50
        }
        fn is_supported(&self) -> bool {
            self.supported
        }
        fn capabilities(&self) -> &'static [MountCapability] {
            self.capabilities
        }
        fn default_mount_flags(&self) -> String {
            "-odefault".to_owned()
        }
        fn for_file_system(&self, _fs: Arc<CryptoFs>) -> Box<dyn MountBuilder> {
            Box::new(FakeBuilder {
                recorded: Arc::clone(&self.recorded),
            })
        }
    }

    struct FakeBuilder {
        recorded: Arc<Mutex<Recorded>>,
    }

    impl FakeBuilder {
        fn with(&self, f: impl FnOnce(&mut Recorded)) -> std::result::Result<(), MountError> {
            let mut recorded = self.recorded.lock().expect("recorded");
            f(&mut recorded);
            Ok(())
        }
    }

    impl MountBuilder for FakeBuilder {
        fn set_file_system_name(&mut self, name: &str) -> std::result::Result<(), MountError> {
            self.with(|r| r.file_system_name = Some(name.to_owned()))
        }
        fn set_mountpoint(&mut self, path: &Path) -> std::result::Result<(), MountError> {
            self.with(|r| r.mountpoint = Some(path.to_path_buf()))
        }
        fn set_mount_flags(&mut self, flags: &str) -> std::result::Result<(), MountError> {
            self.with(|r| r.flags = Some(flags.to_owned()))
        }
        fn set_read_only(&mut self, read_only: bool) -> std::result::Result<(), MountError> {
            self.with(|r| r.read_only = Some(read_only))
        }
        fn set_volume_id(&mut self, id: &str) -> std::result::Result<(), MountError> {
            self.with(|r| r.volume_id = Some(id.to_owned()))
        }
        fn set_volume_name(&mut self, name: &str) -> std::result::Result<(), MountError> {
            self.with(|r| r.volume_name = Some(name.to_owned()))
        }
        fn mount(self: Box<Self>) -> std::result::Result<Box<dyn Mount>, MountError> {
            Ok(Box::new(FakeMount {
                mountpoint: self
                    .recorded
                    .lock()
                    .expect("recorded")
                    .mountpoint
                    .clone()
                    .unwrap_or_else(|| PathBuf::from("/dev/null")),
            }))
        }
    }

    struct FakeMount {
        mountpoint: PathBuf,
    }

    impl Mount for FakeMount {
        fn mountpoint(&self) -> Mountpoint {
            Mountpoint::Path(self.mountpoint.clone())
        }
        fn unmount(&mut self) -> std::result::Result<(), UnmountError> {
            Ok(())
        }
        fn unmount_forced(&mut self) -> std::result::Result<(), UnmountError> {
            Ok(())
        }
        fn close(self: Box<Self>) -> std::result::Result<(), UnmountError> {
            Ok(())
        }
    }

    /// An initialised vault and its file system; the directory must outlive the file system.
    fn test_fs() -> (TempDir, Arc<CryptoFs>) {
        let dir = tempfile::tempdir().expect("temp dir");
        let key = Masterkey::from_raw([9u8; 64]);
        initialize(
            dir.path(),
            &key,
            CipherCombo::SivGcm,
            220,
            DEFAULT_KEY_ID,
            &mut OsRng,
        )
        .expect("initialize");
        let opened = open_vault_with_key(dir.path(), key).expect("open vault");
        (
            dir,
            Arc::new(CryptoFs::open(opened, CryptoFsOptions::default())),
        )
    }

    fn vault() -> VaultSettingsJson {
        let mut vault =
            VaultSettingsJson::new("AAAAAAAAAAAA".to_owned(), Path::new("/vaults/My Vault"));
        vault.display_name = Some("My Vault".to_owned());
        vault
    }

    #[test]
    fn the_mount_service_is_chosen_in_the_documented_order() {
        let mut vault = vault();
        let mut settings = SettingsJson::default();
        let mut cli = CliConfig::default();
        let services: Vec<Box<dyn MountService>> = vec![
            Box::new(FakeService::new("org.example.Unsupported", false)),
            Box::new(FakeService::new("org.example.First", true)),
            Box::new(FakeService::new("org.example.Second", true)),
        ];
        let home = PathBuf::from("/home/u");
        let choose = |vault: &VaultSettingsJson,
                      settings: &SettingsJson,
                      cli: &CliConfig,
                      overrides: MountOverrides| {
            let req = MountRequest {
                running_services: Vec::new(),
                vault,
                settings,
                cli,
                home: &home,
                overrides,
            };
            choose_service(&req, &services).map(|s| s.java_class_name())
        };

        assert_eq!(
            choose(&vault, &settings, &cli, MountOverrides::default()).expect("default"),
            "org.example.First",
            "without a configured service the first supported one wins"
        );

        settings.mount_service = Some("org.example.Second".to_owned());
        assert_eq!(
            choose(&vault, &settings, &cli, MountOverrides::default()).expect("settings"),
            "org.example.Second"
        );
        cli.default_mounter = Some("org.example.First".to_owned());
        assert_eq!(
            choose(&vault, &settings, &cli, MountOverrides::default()).expect("cli"),
            "org.example.First",
            "cli.json beats settings.json"
        );
        vault.mount_service = Some("org.example.Second".to_owned());
        assert_eq!(
            choose(&vault, &settings, &cli, MountOverrides::default()).expect("vault"),
            "org.example.Second",
            "the vault beats cli.json"
        );
        let overrides = MountOverrides {
            mounter: Some("org.example.First".to_owned()),
            ..MountOverrides::default()
        };
        assert_eq!(
            choose(&vault, &settings, &cli, overrides).expect("override"),
            "org.example.First",
            "--mounter beats everything"
        );

        vault.mount_service = Some("   ".to_owned());
        assert_eq!(
            choose(&vault, &settings, &cli, MountOverrides::default()).expect("blank"),
            "org.example.First",
            "a blank entry is no entry"
        );
    }

    #[test]
    fn an_unknown_or_unsupported_service_is_refused() {
        let vault = vault();
        let settings = SettingsJson::default();
        let cli = CliConfig::default();
        let home = PathBuf::from("/home/u");
        let services: Vec<Box<dyn MountService>> =
            vec![Box::new(FakeService::new("org.example.Unsupported", false))];
        let req = |mounter: &str| MountOverrides {
            mounter: Some(mounter.to_owned()),
            ..MountOverrides::default()
        };
        for (mounter, needle) in [
            ("org.example.Nope", "not available"),
            ("org.example.Unsupported", "not available on this system"),
        ] {
            let request = MountRequest {
                running_services: Vec::new(),
                vault: &vault,
                settings: &settings,
                cli: &cli,
                home: &home,
                overrides: req(mounter),
            };
            let Err(err) = choose_service(&request, &services) else {
                panic!("{mounter} must be refused")
            };
            assert!(matches!(err, AppError::MountFailed(_)), "{err:?}");
            assert!(err.to_string().contains(needle), "{err}");
        }
        // Nothing supported at all.
        let request = MountRequest {
            running_services: Vec::new(),
            vault: &vault,
            settings: &settings,
            cli: &cli,
            home: &home,
            overrides: MountOverrides::default(),
        };
        assert!(
            choose_service(&request, &services)
                .map(|s| s.java_class_name())
                .is_err(),
            "nothing supported, nothing to choose"
        );
    }

    #[test]
    fn conflicting_services_are_recognised() {
        let macfuse = cryptomator_mount::registry::MAC_FUSE_CLASS.to_owned();
        let fuse_t = cryptomator_mount::registry::FUSE_T_CLASS.to_owned();
        assert!(conflicts_with(&macfuse, std::slice::from_ref(&fuse_t)));
        assert!(conflicts_with(&fuse_t, std::slice::from_ref(&macfuse)));
        assert!(!conflicts_with(&fuse_t, std::slice::from_ref(&fuse_t)));
        assert!(!conflicts_with(&macfuse, &[]));
        assert!(!conflicts_with(NULL_MOUNTER_CLASS, &[macfuse]));
    }

    #[test]
    fn a_service_conflicting_with_a_running_one_is_refused() {
        let (_vault_dir, fs) = test_fs();
        let vault = vault();
        let settings = SettingsJson::default();
        let cli = CliConfig::default();
        let home = tempfile::tempdir().expect("home");
        let macfuse = cryptomator_mount::registry::MAC_FUSE_CLASS;
        let fuse_t = cryptomator_mount::registry::FUSE_T_CLASS;
        let services: Vec<Box<dyn MountService>> = vec![Box::new(FakeService::new(macfuse, true))];
        let request = |running: Vec<String>| MountRequest {
            vault: &vault,
            settings: &settings,
            cli: &cli,
            home: home.path(),
            overrides: MountOverrides::default(),
            running_services: running,
        };

        let err = mount(
            &request(vec![fuse_t.to_owned()]),
            &services,
            Arc::clone(&fs),
        )
        .expect_err("macFUSE cannot join a running FUSE-T");
        assert!(matches!(err, AppError::MountFailed(_)), "{err:?}");
        assert_eq!(
            err.to_string(),
            format!("mount failed: mount service {macfuse} conflicts with running {fuse_t}")
        );
        assert!(
            !home.path().join("Library").exists() && !home.path().join(".local").exists(),
            "the refusal comes before any mount directory is created"
        );

        // The same mount with nothing else running.
        let handle = mount(&request(Vec::new()), &services, fs).expect("mount");
        assert_eq!(handle.service_class, macfuse);
        handle.close().expect("close");

        // A vault using the same service is no conflict.
        let services: Vec<Box<dyn MountService>> = vec![Box::new(FakeService::new(fuse_t, true))];
        let (_second_dir, fs) = test_fs();
        let handle = mount(&request(vec![fuse_t.to_owned()]), &services, fs).expect("mount");
        handle.close().expect("close");
    }

    #[test]
    fn capabilities_are_applied_like_the_desktop_app() {
        let (_vault_dir, fs) = test_fs();
        let mut vault = vault();
        vault.uses_read_only_mode = true;
        let settings = SettingsJson::default();
        let cli = CliConfig::default();
        let home = tempfile::tempdir().expect("home");
        let service = FakeService::new("org.example.Fake", true);
        let recorded = Arc::clone(&service.recorded);
        let services: Vec<Box<dyn MountService>> = vec![Box::new(service)];
        let req = MountRequest {
            running_services: Vec::new(),
            vault: &vault,
            settings: &settings,
            cli: &cli,
            home: home.path(),
            overrides: MountOverrides {
                mount_options: vec!["-oallow_other".to_owned()],
                ..MountOverrides::default()
            },
        };
        let handle = mount(&req, &services, fs).expect("mount");
        let recorded = recorded.lock().expect("recorded").clone();
        assert_eq!(recorded.file_system_name.as_deref(), Some(FILE_SYSTEM_NAME));
        assert_eq!(recorded.read_only, Some(true), "usesReadOnlyMode");
        assert_eq!(
            recorded.flags.as_deref(),
            Some("-odefault -oallow_other"),
            "the service's defaults plus --mount-option"
        );
        assert_eq!(recorded.volume_id.as_deref(), Some("AAAAAAAAAAAA"));
        assert_eq!(recorded.volume_name.as_deref(), Some("My Vault"));
        assert_eq!(
            recorded.mountpoint,
            Some(
                home.path()
                    .join(if cfg!(target_os = "macos") {
                        "Library/Application Support/Cryptomator/mnt"
                    } else {
                        ".local/share/Cryptomator/mnt"
                    })
                    .join("My Vault")
            )
        );
        assert!(handle.supports_forced);
        assert_eq!(handle.service_class, "org.example.Fake");
        handle.close().expect("close");
    }

    #[test]
    fn the_vaults_own_flags_and_the_overrides_win() {
        let (_vault_dir, fs) = test_fs();
        let mut vault = vault();
        vault.mount_flags = "-ofrom_settings".to_owned();
        vault.uses_read_only_mode = true;
        let settings = SettingsJson::default();
        let cli = CliConfig::default();
        let home = tempfile::tempdir().expect("home");
        let service = FakeService::new("org.example.Fake", true);
        let recorded = Arc::clone(&service.recorded);
        let services: Vec<Box<dyn MountService>> = vec![Box::new(service)];
        let req = MountRequest {
            running_services: Vec::new(),
            vault: &vault,
            settings: &settings,
            cli: &cli,
            home: home.path(),
            overrides: MountOverrides {
                read_only: Some(false),
                volume_name: Some("Chosen".to_owned()),
                ..MountOverrides::default()
            },
        };
        let handle = mount(&req, &services, fs).expect("mount");
        let recorded = recorded.lock().expect("recorded").clone();
        assert_eq!(recorded.flags.as_deref(), Some("-ofrom_settings"));
        assert_eq!(recorded.read_only, Some(false), "--read-only=false wins");
        assert_eq!(recorded.volume_name.as_deref(), Some("Chosen"));
        handle.close().expect("close");
    }

    #[test]
    fn read_only_reaches_a_service_without_the_capability_as_a_mount_flag() {
        const FLAGS_ONLY: &[MountCapability] = &[
            MountCapability::MountFlags,
            MountCapability::MountToExistingDir,
        ];
        let (_vault_dir, fs) = test_fs();
        let mut vault = vault();
        vault.uses_read_only_mode = true;
        let settings = SettingsJson::default();
        let cli = CliConfig::default();
        let home = tempfile::tempdir().expect("home");
        let mut service = FakeService::new("org.example.Linux", true);
        service.capabilities = FLAGS_ONLY;
        let recorded = Arc::clone(&service.recorded);
        let services: Vec<Box<dyn MountService>> = vec![Box::new(service)];
        let req = MountRequest {
            running_services: Vec::new(),
            vault: &vault,
            settings: &settings,
            cli: &cli,
            home: home.path(),
            overrides: MountOverrides::default(),
        };
        let handle = mount(&req, &services, fs).expect("mount");
        assert_eq!(
            recorded.lock().expect("recorded").flags.as_deref(),
            Some("-odefault -oro")
        );
        handle.close().expect("close");
    }

    /// The setup the null mounter needs: a vault, a `cli.json` pointing at a temporary mount-point
    /// base, and the null mounter as the only service.
    struct NullSetup {
        _vault_dir: TempDir,
        home: TempDir,
        fs: Arc<CryptoFs>,
        cli: CliConfig,
        settings: SettingsJson,
        services: Vec<Box<dyn MountService>>,
    }

    fn null_setup() -> NullSetup {
        let (vault_dir, fs) = test_fs();
        let home = tempfile::tempdir().expect("home");
        let cli = CliConfig {
            mount_points_dir: Some(home.path().join("mnt").to_string_lossy().into_owned()),
            ..CliConfig::default()
        };
        NullSetup {
            _vault_dir: vault_dir,
            home,
            fs,
            cli,
            settings: SettingsJson::default(),
            services: vec![Box::new(NullMountProvider::enabled(true, false))],
        }
    }

    #[test]
    fn without_a_mount_point_the_mounter_creates_one_and_removes_it_again() {
        let setup = null_setup();
        let vault = vault();
        let req = MountRequest {
            running_services: Vec::new(),
            vault: &vault,
            settings: &setup.settings,
            cli: &setup.cli,
            home: setup.home.path(),
            overrides: MountOverrides {
                volume_name: Some("Volume".to_owned()),
                ..MountOverrides::default()
            },
        };
        let handle = mount(&req, &setup.services, Arc::clone(&setup.fs)).expect("mount");
        let expected = setup.home.path().join("mnt/My Vault");
        assert_eq!(handle.cleanup.as_deref(), Some(expected.as_path()));
        assert_eq!(handle.mountpoint(), Mountpoint::Path(expected.clone()));
        assert_eq!(handle.service_class, NULL_MOUNTER_CLASS);
        let marker = expected.join(NULL_MOUNT_MARKER);
        assert_eq!(
            std::fs::read_to_string(&marker).expect("marker"),
            "Volume",
            "the volume name reached the mount"
        );
        handle.close().expect("close");
        assert!(!expected.exists(), "the created mount directory is gone");
        assert!(setup.home.path().join("mnt").is_dir(), "the base stays");
    }

    #[test]
    fn a_mount_directory_that_was_already_there_is_kept() {
        let setup = null_setup();
        let vault = vault();
        // The very same path the mounter would create, but made by the user beforehand.
        let existing = setup.home.path().join("mnt/My Vault");
        std::fs::create_dir_all(&existing).expect("mkdir");
        let req = MountRequest {
            vault: &vault,
            settings: &setup.settings,
            cli: &setup.cli,
            home: setup.home.path(),
            overrides: MountOverrides::default(),
            running_services: Vec::new(),
        };
        let handle = mount(&req, &setup.services, Arc::clone(&setup.fs)).expect("mount");
        assert_eq!(handle.mountpoint(), Mountpoint::Path(existing.clone()));
        assert!(
            handle.cleanup.is_none(),
            "only a directory this mount created is removed again"
        );
        handle.close().expect("close");
        assert!(existing.is_dir(), "the user's directory stays");
    }

    #[test]
    fn a_mount_point_that_does_not_exist_is_reported_with_its_path() {
        let setup = null_setup();
        let mut vault = vault();
        let missing = setup.home.path().join("nowhere");
        vault.mount_point = Some(missing.to_string_lossy().into_owned());
        let req = MountRequest {
            running_services: Vec::new(),
            vault: &vault,
            settings: &setup.settings,
            cli: &setup.cli,
            home: setup.home.path(),
            overrides: MountOverrides::default(),
        };
        let err = mount(&req, &setup.services, Arc::clone(&setup.fs)).expect_err("no mount point");
        match err {
            AppError::MountPointInvalid(path, ref reason) => {
                assert_eq!(path, missing);
                assert_eq!(reason, "does not exist");
            }
            other => panic!("expected MountPointInvalid, got {other:?}"),
        }

        // A file where a directory should be.
        let file = setup.home.path().join("file");
        std::fs::write(&file, b"x").expect("write");
        let req = MountRequest {
            running_services: Vec::new(),
            vault: &vault,
            settings: &setup.settings,
            cli: &setup.cli,
            home: setup.home.path(),
            overrides: MountOverrides {
                mount_point: Some(file.clone()),
                ..MountOverrides::default()
            },
        };
        let err = mount(&req, &setup.services, Arc::clone(&setup.fs)).expect_err("not a directory");
        assert!(
            matches!(&err, AppError::MountPointInvalid(path, reason) if path == &file && reason == "not a directory"),
            "{err:?}"
        );
    }

    #[test]
    fn a_chosen_mount_point_is_used_as_is_and_never_removed() {
        let setup = null_setup();
        let mut vault = vault();
        let chosen = setup.home.path().join("here");
        std::fs::create_dir_all(&chosen).expect("mkdir");
        vault.mount_point = Some(chosen.to_string_lossy().into_owned());
        let req = MountRequest {
            running_services: Vec::new(),
            vault: &vault,
            settings: &setup.settings,
            cli: &setup.cli,
            home: setup.home.path(),
            overrides: MountOverrides::default(),
        };
        let mut handle = mount(&req, &setup.services, Arc::clone(&setup.fs)).expect("mount");
        assert!(handle.cleanup.is_none());
        assert!(chosen.join(NULL_MOUNT_MARKER).is_file());
        assert_eq!(
            std::fs::read_to_string(chosen.join(NULL_MOUNT_MARKER)).expect("marker"),
            "My Vault",
            "the vault's mount name is the volume name"
        );
        handle.unmount(false).expect("unmount");
        assert!(!chosen.join(NULL_MOUNT_MARKER).exists());
        handle.close().expect("close");
        assert!(chosen.is_dir(), "a directory the user chose stays");
    }

    #[test]
    fn a_busy_volume_only_gives_way_to_a_forced_unmount() {
        let mut setup = null_setup();
        setup.services = vec![Box::new(NullMountProvider::enabled(true, true))];
        let vault = vault();
        let req = MountRequest {
            running_services: Vec::new(),
            vault: &vault,
            settings: &setup.settings,
            cli: &setup.cli,
            home: setup.home.path(),
            overrides: MountOverrides::default(),
        };
        let mut handle = mount(&req, &setup.services, Arc::clone(&setup.fs)).expect("mount");
        let err = handle.unmount(false).expect_err("busy");
        assert!(matches!(err, AppError::UnmountFailed(_)), "{err:?}");
        handle.unmount(true).expect("forced unmount");
        let dir = handle.cleanup.clone().expect("created mount directory");
        handle.close().expect("close");
        assert!(!dir.exists());
    }

    #[test]
    fn a_service_without_forced_unmount_says_so() {
        let (_vault_dir, fs) = test_fs();
        const NO_FORCE: &[MountCapability] = &[
            MountCapability::MountFlags,
            MountCapability::MountToExistingDir,
        ];
        let home = tempfile::tempdir().expect("home");
        let vault = vault();
        let settings = SettingsJson::default();
        let cli = CliConfig::default();
        let mut service = FakeService::new("org.example.Gentle", true);
        service.capabilities = NO_FORCE;
        let services: Vec<Box<dyn MountService>> = vec![Box::new(service)];
        let req = MountRequest {
            running_services: Vec::new(),
            vault: &vault,
            settings: &settings,
            cli: &cli,
            home: home.path(),
            overrides: MountOverrides::default(),
        };
        let mut handle = mount(&req, &services, fs).expect("mount");
        assert!(!handle.supports_forced);
        let err = handle.unmount(true).expect_err("no forced unmount");
        assert!(
            err.to_string().contains(FORCED_UNMOUNT_UNSUPPORTED),
            "{err}"
        );
        handle.close().expect("close");
    }
}
