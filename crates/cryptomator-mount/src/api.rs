//! The mount service API, modelled on Cryptomator's `org.cryptomator.integrations.mount`
//! (`MountService`, `MountBuilder`, `Mount`, `MountCapability`).
//!
//! A [`MountService`] describes one way of exposing a vault to the operating system (FUSE-T,
//! macFUSE, libfuse3, WebDAV, …). The CLI picks a service, asks it for a [`MountBuilder`],
//! configures the builder as far as the service's [capabilities](MountCapability) allow, and
//! receives a live [`Mount`].
use cryptomator_core::fs::CryptoFs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Optional features of a [`MountService`]; a builder setter is only meaningful when the service
/// advertises the matching capability.
///
/// The names mirror Cryptomator's `MountCapability` enum constants so `crypto mount --list`
/// output stays comparable with the desktop app; [`MountCapability::java_name`] returns them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MountCapability {
    /// The name shown for the mounted volume's source (`fsname`).
    FileSystemName,
    /// The loopback host name of a network mount (WebDAV).
    LoopbackHostName,
    /// The TCP port of a network mount (WebDAV).
    LoopbackPort,
    /// Free-form mount flags, see [`crate::flags`].
    MountFlags,
    /// The mount point must exist and be an empty directory.
    MountToExistingDir,
    /// The mount point must not exist, but its parent must.
    MountWithinExistingParent,
    /// The mount point is a Windows drive letter.
    MountAsDriveLetter,
    /// The service chooses the mount point itself.
    MountToSystemChosenPath,
    /// The volume can be mounted read-only.
    ReadOnly,
    /// [`Mount::unmount_forced`] is implemented.
    UnmountForced,
    /// A stable volume identifier can be set.
    VolumeId,
    /// A human readable volume name can be set.
    VolumeName,
}

impl MountCapability {
    /// The Java constant name of this capability, e.g. `"MOUNT_TO_EXISTING_DIR"`.
    pub fn java_name(self) -> &'static str {
        match self {
            Self::FileSystemName => "FILE_SYSTEM_NAME",
            Self::LoopbackHostName => "LOOPBACK_HOST_NAME",
            Self::LoopbackPort => "LOOPBACK_PORT",
            Self::MountFlags => "MOUNT_FLAGS",
            Self::MountToExistingDir => "MOUNT_TO_EXISTING_DIR",
            Self::MountWithinExistingParent => "MOUNT_WITHIN_EXISTING_PARENT",
            Self::MountAsDriveLetter => "MOUNT_AS_DRIVE_LETTER",
            Self::MountToSystemChosenPath => "MOUNT_TO_SYSTEM_CHOSEN_PATH",
            Self::ReadOnly => "READ_ONLY",
            Self::UnmountForced => "UNMOUNT_FORCED",
            Self::VolumeId => "VOLUME_ID",
            Self::VolumeName => "VOLUME_NAME",
        }
    }
}

/// Where a mounted volume can be reached: a local path or, for network mounts, a URI.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Mountpoint {
    /// A local directory, e.g. `/Users/me/mnt/Vault`.
    Path(PathBuf),
    /// A URI, e.g. `http://localhost:42427/vault`.
    Uri(String),
}

/// Everything that can go wrong while configuring or establishing a mount.
#[derive(Debug, thiserror::Error)]
pub enum MountError {
    /// The mount point is unusable (missing, not empty, wrong type, …).
    #[error("mount point {0}: {1}")]
    MountPoint(PathBuf, String),
    /// A mount flag this service does not understand.
    #[error("unsupported mount flag {0}")]
    UnsupportedFlag(String),
    /// The mount itself failed.
    #[error("{0}")]
    Failed(String),
    /// An I/O error surfaced unchanged.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Everything that can go wrong while tearing a mount down.
#[derive(Debug, thiserror::Error)]
pub enum UnmountError {
    /// The unmount command failed.
    #[error("unmount failed: {0}")]
    Failed(String),
    /// The volume is still in use; a forced unmount may still work.
    #[error("filesystem busy")]
    Busy,
    /// An I/O error surfaced unchanged.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// The error returned by the default [`MountBuilder`] setters, i.e. by every setter whose
/// capability the service does not advertise.
pub fn unsupported() -> MountError {
    MountError::Failed("not supported by this mount service".to_owned())
}

/// A volume that is currently mounted.
pub trait Mount: Send {
    /// Where the volume can be reached.
    fn mountpoint(&self) -> Mountpoint;
    /// Unmounts gracefully; fails with [`UnmountError::Busy`] while files are still open.
    fn unmount(&mut self) -> Result<(), UnmountError>;
    /// Unmounts even if the volume is busy. Only implemented by services advertising
    /// [`MountCapability::UnmountForced`]; the default reports that.
    fn unmount_forced(&mut self) -> Result<(), UnmountError> {
        Err(UnmountError::Failed(
            "forced unmount not supported by this mount service".to_owned(),
        ))
    }
    /// Releases the mount: unmounts if still mounted and joins the serving session.
    fn close(self: Box<Self>) -> Result<(), UnmountError>;
}

/// Configures one mount. Every setter that the service does not support returns
/// [`unsupported()`]; callers check [`MountService::has_capability`] first.
pub trait MountBuilder: Send {
    /// Sets the volume's source name (`fsname`).
    fn set_file_system_name(&mut self, _name: &str) -> Result<(), MountError> {
        Err(unsupported())
    }
    /// Sets the TCP port for network mounts.
    fn set_loopback_port(&mut self, _port: u16) -> Result<(), MountError> {
        Err(unsupported())
    }
    /// Sets the directory to mount to.
    fn set_mountpoint(&mut self, _path: &Path) -> Result<(), MountError> {
        Err(unsupported())
    }
    /// Sets the raw mount flags, see [`crate::flags::parse_mount_flags`].
    fn set_mount_flags(&mut self, _flags: &str) -> Result<(), MountError> {
        Err(unsupported())
    }
    /// Mounts read-only.
    fn set_read_only(&mut self, _read_only: bool) -> Result<(), MountError> {
        Err(unsupported())
    }
    /// Sets a stable volume identifier.
    fn set_volume_id(&mut self, _id: &str) -> Result<(), MountError> {
        Err(unsupported())
    }
    /// Sets the displayed volume name.
    fn set_volume_name(&mut self, _name: &str) -> Result<(), MountError> {
        Err(unsupported())
    }
    /// Establishes the mount, consuming the builder.
    fn mount(self: Box<Self>) -> Result<Box<dyn Mount>, MountError>;
}

/// One way of mounting a vault. Services are registered in a registry and ranked by
/// [`MountService::priority`] (higher wins) among those that are [supported](MountService::is_supported).
pub trait MountService: Send + Sync {
    /// The fully qualified name of the Java class this service mirrors; the CLI accepts it as
    /// `--mounter` argument so scripts written against Cryptomator keep working.
    fn java_class_name(&self) -> &'static str;
    /// A human readable name, e.g. `"FUSE-T"`.
    fn display_name(&self) -> &'static str;
    /// Higher wins when the CLI picks a service automatically.
    fn priority(&self) -> u32;
    /// Whether this service can be used on this machine right now (libraries present, …).
    fn is_supported(&self) -> bool;
    /// The capabilities this service advertises.
    fn capabilities(&self) -> &'static [MountCapability];
    /// Whether `c` is among [`MountService::capabilities`].
    fn has_capability(&self, c: MountCapability) -> bool {
        self.capabilities().contains(&c)
    }
    /// The mount flags used when the user does not supply any.
    fn default_mount_flags(&self) -> String;
    /// The port used when the user does not supply one (network mounts only).
    fn default_loopback_port(&self) -> Option<u16> {
        None
    }
    /// Starts configuring a mount of `fs`.
    fn for_file_system(&self, fs: Arc<CryptoFs>) -> Box<dyn MountBuilder>;
    /// Takes down a mount this service left behind, addressed by its mount point alone.
    ///
    /// Recovering from a crashed daemon is the reason this exists: the [`Mount`] that owned the
    /// session is gone, but the volume is still in the mount table. Services that can unmount by
    /// path (every FUSE back end -- they shell out to `umount`/`fusermount3`) override this; the
    /// default reports that the caller has to take the mount down by hand.
    ///
    /// # Errors
    /// The unmount command's error, or [`UnmountError::Failed`] if this service cannot unmount by
    /// path.
    fn unmount_path(&self, _mountpoint: &Path, _forced: bool) -> Result<(), UnmountError> {
        Err(UnmountError::Failed(
            "unmounting by path is not supported by this mount service".to_owned(),
        ))
    }
}

/// A [`MountService`] rendered for `--json` output.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceInfo {
    /// [`MountService::java_class_name`].
    pub class_name: String,
    /// [`MountService::display_name`].
    pub display_name: String,
    /// The short name the CLI accepts instead of the class name, e.g. `"fuse-t"`.
    pub alias: Option<String>,
    /// [`MountService::is_supported`].
    pub supported: bool,
    /// [`MountService::priority`].
    pub priority: u32,
    /// [`MountCapability::java_name`] of every advertised capability.
    pub capabilities: Vec<String>,
    /// [`MountService::default_mount_flags`].
    pub default_mount_flags: String,
}

impl ServiceInfo {
    /// Snapshots `service`; `alias` is the registry's short name for it, if it has one.
    pub fn from_service(service: &dyn MountService, alias: Option<&str>) -> Self {
        Self {
            class_name: service.java_class_name().to_owned(),
            display_name: service.display_name().to_owned(),
            alias: alias.map(str::to_owned),
            supported: service.is_supported(),
            priority: service.priority(),
            capabilities: service
                .capabilities()
                .iter()
                .map(|c| c.java_name().to_owned())
                .collect(),
            default_mount_flags: service.default_mount_flags(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyService;

    const CAPS: &[MountCapability] = &[
        MountCapability::MountToExistingDir,
        MountCapability::ReadOnly,
        MountCapability::VolumeName,
    ];

    impl MountService for DummyService {
        fn java_class_name(&self) -> &'static str {
            "org.cryptomator.frontend.fuse.mount.FuseTMountProvider"
        }
        fn display_name(&self) -> &'static str {
            "FUSE-T"
        }
        fn priority(&self) -> u32 {
            100
        }
        fn is_supported(&self) -> bool {
            true
        }
        fn capabilities(&self) -> &'static [MountCapability] {
            CAPS
        }
        fn default_mount_flags(&self) -> String {
            "-orwsize=262144".to_owned()
        }
        fn for_file_system(&self, _fs: Arc<CryptoFs>) -> Box<dyn MountBuilder> {
            unimplemented!("no file system in this test")
        }
    }

    #[test]
    fn capabilities_use_the_java_constant_names() {
        assert_eq!(
            MountCapability::MountToExistingDir.java_name(),
            "MOUNT_TO_EXISTING_DIR"
        );
        assert_eq!(
            MountCapability::FileSystemName.java_name(),
            "FILE_SYSTEM_NAME"
        );
        assert_eq!(MountCapability::ReadOnly.java_name(), "READ_ONLY");
        assert_eq!(
            MountCapability::MountToSystemChosenPath.java_name(),
            "MOUNT_TO_SYSTEM_CHOSEN_PATH"
        );
        // The serde representation must not drift from `java_name`.
        for c in [
            MountCapability::FileSystemName,
            MountCapability::LoopbackHostName,
            MountCapability::LoopbackPort,
            MountCapability::MountFlags,
            MountCapability::MountToExistingDir,
            MountCapability::MountWithinExistingParent,
            MountCapability::MountAsDriveLetter,
            MountCapability::MountToSystemChosenPath,
            MountCapability::ReadOnly,
            MountCapability::UnmountForced,
            MountCapability::VolumeId,
            MountCapability::VolumeName,
        ] {
            let json = serde_json::to_string(&c).expect("serialize capability");
            assert_eq!(json, format!("\"{}\"", c.java_name()));
        }
    }

    #[test]
    fn mountpoint_serialises_externally_tagged() {
        let path = serde_json::to_string(&Mountpoint::Path(PathBuf::from("/mnt/Vault")))
            .expect("serialize path");
        assert_eq!(path, r#"{"path":"/mnt/Vault"}"#);
        let uri = serde_json::to_string(&Mountpoint::Uri("http://localhost:8080/".to_owned()))
            .expect("serialize uri");
        assert_eq!(uri, r#"{"uri":"http://localhost:8080/"}"#);
    }

    #[test]
    fn service_info_snapshots_a_service() {
        let info = ServiceInfo::from_service(&DummyService, Some("fuse-t"));
        assert_eq!(info.display_name, "FUSE-T");
        assert_eq!(info.alias.as_deref(), Some("fuse-t"));
        assert!(info.supported);
        assert_eq!(
            info.capabilities,
            vec!["MOUNT_TO_EXISTING_DIR", "READ_ONLY", "VOLUME_NAME"]
        );
        let json = serde_json::to_value(&info).expect("serialize service info");
        assert_eq!(
            json["className"],
            "org.cryptomator.frontend.fuse.mount.FuseTMountProvider"
        );
        assert_eq!(json["defaultMountFlags"], "-orwsize=262144");
        assert_eq!(json["displayName"], "FUSE-T");
    }

    #[test]
    fn unmount_path_is_unsupported_by_default() {
        let err = DummyService
            .unmount_path(Path::new("/mnt/Vault"), false)
            .expect_err("the default implementation refuses");
        assert!(matches!(err, UnmountError::Failed(_)), "{err:?}");
    }

    #[test]
    fn has_capability_follows_the_capability_list() {
        assert!(DummyService.has_capability(MountCapability::ReadOnly));
        assert!(!DummyService.has_capability(MountCapability::UnmountForced));
        assert_eq!(DummyService.default_loopback_port(), None);
    }
}
