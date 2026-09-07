//! The mount service registry: which services exist, which of them work here, and the null
//! mounter the tests use.
//!
//! Cryptomator discovers its providers through the Java service loader; there is no such thing
//! here, so the list is written out. The order is the order the CLI picks from: highest
//! [`MountService::priority`] first, with the null mounter -- which mounts nothing -- always last.
use crate::api::{
    Mount, MountBuilder, MountCapability, MountError, MountService, Mountpoint, ServiceInfo,
    UnmountError,
};
use crate::flags::{current_uid_gid, parse_mount_flags};
use cryptomator_core::fs::CryptoFs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// `org.cryptomator.frontend.fuse.mount.LinuxFuseMountProvider`.
pub const LINUX_FUSE_CLASS: &str = "org.cryptomator.frontend.fuse.mount.LinuxFuseMountProvider";
/// `org.cryptomator.frontend.fuse.mount.MacFuseMountProvider`.
pub const MAC_FUSE_CLASS: &str = "org.cryptomator.frontend.fuse.mount.MacFuseMountProvider";
/// `org.cryptomator.frontend.fuse.mount.FuseTMountProvider`.
pub const FUSE_T_CLASS: &str = "org.cryptomator.frontend.fuse.mount.FuseTMountProvider";
/// `org.cryptomator.frontend.webdav.mount.FallbackMounter`.
pub const FALLBACK_WEBDAV_CLASS: &str = "org.cryptomator.frontend.webdav.mount.FallbackMounter";
/// `org.cryptomator.frontend.webdav.mount.MacAppleScriptMounter`. Task 6 registers the service;
/// the name is here so a build without it can still recognise it in a stored `mounter` setting.
pub const MAC_APPLESCRIPT_CLASS: &str =
    "org.cryptomator.frontend.webdav.mount.MacAppleScriptMounter";
/// `org.cryptomator.frontend.webdav.mount.LinuxGioMounter`. Same as
/// [`MAC_APPLESCRIPT_CLASS`]: the constant exists before the service does.
pub const LINUX_GIO_CLASS: &str = "org.cryptomator.frontend.webdav.mount.LinuxGioMounter";
/// The null mounter has no Java counterpart; the name follows the CLI's own package.
pub const NULL_MOUNTER_CLASS: &str = "org.cryptomator.cli.NullMountProvider";

/// Set to `1` to make the [null mounter](NullMountProvider) available.
pub const ENABLE_NULL_MOUNTER_ENV: &str = "CRYPTO_ENABLE_NULL_MOUNTER";
/// Set to `1` to make the null mounter's graceful unmount report [`UnmountError::Busy`].
pub const NULL_MOUNT_BUSY_ENV: &str = "CRYPTO_NULL_MOUNT_BUSY";
/// The file a null mount leaves in its mount point, holding the volume name.
pub const NULL_MOUNT_MARKER: &str = ".crypto-null-mount";

/// The short names the CLI accepts instead of the class names. Mirrors
/// `cryptomator_app::mounters::MOUNTER_ALIASES` for the services this registry knows.
const ALIASES: &[(&str, &str)] = &[
    ("macfuse", MAC_FUSE_CLASS),
    ("fuse-t", FUSE_T_CLASS),
    ("fuse", LINUX_FUSE_CLASS),
    // `webdav` is the name scripts use; the two OS-integrated WebDAV mounters get their own
    // aliases in task 6, together with the services themselves.
    ("webdav", FALLBACK_WEBDAV_CLASS),
    ("null", NULL_MOUNTER_CLASS),
];

/// macFUSE and FUSE-T cannot serve the same vault at the same time -- FUSE-T's NFS mount and
/// macFUSE's kernel extension both claim the mount point (Cryptomator's
/// `CONFLICTING_MOUNT_SERVICES`).
const CONFLICTING: &[(&str, &[&str])] = &[
    (MAC_FUSE_CLASS, &[FUSE_T_CLASS]),
    (FUSE_T_CLASS, &[MAC_FUSE_CLASS]),
];

/// The registry's short name for `class`, if it has one.
pub fn alias_for_class(class: &str) -> Option<&'static str> {
    ALIASES
        .iter()
        .find(|(_, known)| *known == class)
        .map(|(alias, _)| *alias)
}

/// The class names of the services that must not be used while `class` is mounted.
pub fn conflicting_classes(class: &str) -> &'static [&'static str] {
    CONFLICTING
        .iter()
        .find(|(known, _)| *known == class)
        .map_or(&[], |(_, others)| *others)
}

/// Every service this build knows, whether or not it works here: the platform's FUSE services by
/// descending priority, then the WebDAV fallback, then the null mounter.
pub fn all_services() -> Vec<Box<dyn MountService>> {
    let mut services: Vec<Box<dyn MountService>> = Vec::new();
    #[cfg(all(feature = "fuse", target_os = "macos"))]
    {
        services.push(Box::new(crate::fuse::macfuse::MacFuseMountProvider));
        services.push(Box::new(crate::fuse::fuset::FuseTMountProvider));
    }
    #[cfg(all(feature = "fuse", target_os = "linux"))]
    {
        services.push(Box::new(crate::fuse::linux::LinuxFuseMountProvider));
    }
    // `@Priority(Priority.FALLBACK)`: below every FUSE back end, above nothing but the null
    // mounter. Pushed before the sort, which is stable, so it stays behind the equally ranked
    // services that came first.
    #[cfg(feature = "webdav")]
    services.push(Box::new(crate::webdav::fallback::FallbackMounter));
    services.sort_by_key(|service| std::cmp::Reverse(service.priority()));
    services.push(Box::new(NullMountProvider::new()));
    services
}

/// The services that can be used on this machine right now, in the order the CLI picks from.
pub fn services() -> Vec<Box<dyn MountService>> {
    all_services()
        .into_iter()
        .filter(|service| service.is_supported())
        .collect()
}

/// The service with this Java class name, if this build has it.
pub fn service_by_class(class: &str) -> Option<Box<dyn MountService>> {
    all_services()
        .into_iter()
        .find(|service| service.java_class_name() == class)
}

/// The services for `crypto mounters`: all of them, or only the supported ones.
pub fn service_infos(all: bool) -> Vec<ServiceInfo> {
    let services = if all { all_services() } else { services() };
    services
        .iter()
        .map(|service| {
            ServiceInfo::from_service(service.as_ref(), alias_for_class(service.java_class_name()))
        })
        .collect()
}

/// A mount service that mounts nothing.
///
/// It exists so the daemon and CLI life cycle -- unlock, status, lock, stale-mount recovery --
/// can be tested where no FUSE implementation is installed, and it is only offered when
/// [`ENABLE_NULL_MOUNTER_ENV`] says so. "Mounting" writes [`NULL_MOUNT_MARKER`] into the mount
/// point; unmounting removes it again, so a test can see the difference.
#[derive(Debug, Clone, Copy)]
pub struct NullMountProvider {
    enabled: bool,
    busy: bool,
}

impl NullMountProvider {
    /// The provider as the CLI builds it: available only with `CRYPTO_ENABLE_NULL_MOUNTER=1`, and
    /// pretending to be busy with `CRYPTO_NULL_MOUNT_BUSY=1`.
    pub fn new() -> Self {
        Self {
            enabled: env_flag(ENABLE_NULL_MOUNTER_ENV),
            busy: env_flag(NULL_MOUNT_BUSY_ENV),
        }
    }

    /// The provider with both switches given explicitly, for tests that must not touch the
    /// process environment. `busy` makes the graceful unmount fail with [`UnmountError::Busy`]
    /// while the forced one still works.
    pub fn enabled(enabled: bool, busy: bool) -> Self {
        Self { enabled, busy }
    }
}

impl Default for NullMountProvider {
    /// Same as [`NullMountProvider::new`]: the environment decides.
    fn default() -> Self {
        Self::new()
    }
}

fn env_flag(name: &str) -> bool {
    std::env::var(name).is_ok_and(|value| value == "1")
}

const NULL_CAPABILITIES: &[MountCapability] = &[
    MountCapability::MountFlags,
    MountCapability::MountToExistingDir,
    MountCapability::ReadOnly,
    MountCapability::VolumeName,
    MountCapability::UnmountForced,
];

impl MountService for NullMountProvider {
    fn java_class_name(&self) -> &'static str {
        NULL_MOUNTER_CLASS
    }

    fn display_name(&self) -> &'static str {
        "Null mounter (testing)"
    }

    fn priority(&self) -> u32 {
        0
    }

    fn is_supported(&self) -> bool {
        self.enabled
    }

    fn capabilities(&self) -> &'static [MountCapability] {
        NULL_CAPABILITIES
    }

    /// A null mount is a marker file, not a volume: it never reaches the mount table, and a
    /// caller waiting for it there would wait forever.
    fn appears_in_mount_table(&self) -> bool {
        false
    }

    fn default_mount_flags(&self) -> String {
        let (uid, gid) = current_uid_gid();
        format!("-ouid={uid} -ogid={gid}")
    }

    fn for_file_system(&self, fs: Arc<CryptoFs>) -> Box<dyn MountBuilder> {
        Box::new(NullMountBuilder {
            _fs: fs,
            busy: self.busy,
            mountpoint: None,
            flags: Vec::new(),
            read_only: false,
            volume_name: None,
        })
    }

    fn unmount_path(&self, mountpoint: &Path, _forced: bool) -> Result<(), UnmountError> {
        remove_marker(&mountpoint.join(NULL_MOUNT_MARKER))
    }
}

/// Removes a null mount's marker; a marker that is already gone is success, like an unmount of a
/// volume that is no longer mounted.
fn remove_marker(marker: &Path) -> Result<(), UnmountError> {
    match std::fs::remove_file(marker) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(UnmountError::Io(err)),
    }
}

/// The builder of a [null mount](NullMountProvider).
#[derive(Debug)]
struct NullMountBuilder {
    /// Held for the lifetime of the builder so a null mount behaves like a real one: the file
    /// system stays open until the mount is closed.
    _fs: Arc<CryptoFs>,
    busy: bool,
    mountpoint: Option<PathBuf>,
    flags: Vec<String>,
    read_only: bool,
    volume_name: Option<String>,
}

impl MountBuilder for NullMountBuilder {
    fn set_mountpoint(&mut self, path: &Path) -> Result<(), MountError> {
        if !path.is_dir() {
            return Err(MountError::MountPoint(
                path.to_path_buf(),
                "not an existing directory".to_owned(),
            ));
        }
        self.mountpoint = Some(path.to_path_buf());
        Ok(())
    }

    fn set_mount_flags(&mut self, flags: &str) -> Result<(), MountError> {
        self.flags = parse_mount_flags(flags);
        Ok(())
    }

    fn set_read_only(&mut self, read_only: bool) -> Result<(), MountError> {
        self.read_only = read_only;
        Ok(())
    }

    fn set_volume_name(&mut self, name: &str) -> Result<(), MountError> {
        self.volume_name = Some(name.to_owned());
        Ok(())
    }

    fn mount(self: Box<Self>) -> Result<Box<dyn Mount>, MountError> {
        let Some(mountpoint) = self.mountpoint.clone() else {
            return Err(MountError::Failed(
                "the null mounter needs a mount point".to_owned(),
            ));
        };
        let marker = mountpoint.join(NULL_MOUNT_MARKER);
        let volume_name = self
            .volume_name
            .clone()
            .unwrap_or_else(|| "null".to_owned());
        std::fs::write(&marker, volume_name.as_bytes())?;
        Ok(Box::new(NullMount {
            mountpoint,
            marker,
            busy: self.busy,
        }))
    }
}

/// A mount that only exists as its marker file.
#[derive(Debug)]
struct NullMount {
    mountpoint: PathBuf,
    marker: PathBuf,
    busy: bool,
}

impl Mount for NullMount {
    fn mountpoint(&self) -> Mountpoint {
        Mountpoint::Path(self.mountpoint.clone())
    }

    fn unmount(&mut self) -> Result<(), UnmountError> {
        if self.busy {
            return Err(UnmountError::Busy);
        }
        remove_marker(&self.marker)
    }

    fn unmount_forced(&mut self) -> Result<(), UnmountError> {
        remove_marker(&self.marker)
    }

    fn close(self: Box<Self>) -> Result<(), UnmountError> {
        remove_marker(&self.marker)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{env_lock, test_fs};
    use tempfile::TempDir;

    #[allow(clippy::type_complexity)]
    fn null_mount(
        busy: bool,
        volume_name: &str,
    ) -> (TempDir, TempDir, Arc<CryptoFs>, Box<dyn Mount>) {
        let (vault, fs) = test_fs();
        let mountpoint = tempfile::tempdir().expect("mount point");
        let service = NullMountProvider::enabled(true, busy);
        let mut builder = service.for_file_system(Arc::clone(&fs));
        builder
            .set_mountpoint(mountpoint.path())
            .expect("set mount point");
        builder
            .set_mount_flags(&service.default_mount_flags())
            .expect("set mount flags");
        builder.set_volume_name(volume_name).expect("set name");
        let mount = builder.mount().expect("mount");
        (vault, mountpoint, fs, mount)
    }

    #[test]
    fn the_null_mounter_advertises_the_capabilities_the_cli_needs() {
        let service = NullMountProvider::enabled(true, false);
        assert_eq!(
            service.capabilities(),
            &[
                MountCapability::MountFlags,
                MountCapability::MountToExistingDir,
                MountCapability::ReadOnly,
                MountCapability::VolumeName,
                MountCapability::UnmountForced,
            ]
        );
        let (uid, gid) = (
            nix::unistd::geteuid().as_raw(),
            nix::unistd::getegid().as_raw(),
        );
        assert_eq!(
            service.default_mount_flags(),
            format!("-ouid={uid} -ogid={gid}")
        );
        assert_eq!(service.java_class_name(), NULL_MOUNTER_CLASS);
        assert_eq!(service.priority(), 0);
        assert!(service.is_supported());
        assert!(!NullMountProvider::enabled(false, false).is_supported());
    }

    #[test]
    fn a_null_mount_writes_and_removes_its_marker() {
        let (_vault, mountpoint, _fs, mut mount) = null_mount(false, "Secret");
        let marker = mountpoint.path().join(NULL_MOUNT_MARKER);
        assert_eq!(
            std::fs::read_to_string(&marker).expect("read marker"),
            "Secret"
        );
        assert_eq!(
            mount.mountpoint(),
            Mountpoint::Path(mountpoint.path().to_path_buf())
        );
        mount.unmount().expect("unmount");
        assert!(!marker.exists(), "the marker is gone after the unmount");
        mount.close().expect("close after unmount is a no-op");
    }

    #[test]
    fn a_busy_null_mount_only_gives_way_to_a_forced_unmount() {
        let (_vault, mountpoint, _fs, mut mount) = null_mount(true, "Busy");
        let marker = mountpoint.path().join(NULL_MOUNT_MARKER);
        assert!(matches!(mount.unmount(), Err(UnmountError::Busy)));
        assert!(marker.exists(), "a refused unmount changes nothing");
        mount.unmount_forced().expect("forced unmount");
        assert!(!marker.exists());
    }

    #[test]
    fn unmount_path_removes_a_marker_left_behind_and_tolerates_a_missing_one() {
        let (_vault, mountpoint, _fs, mount) = null_mount(false, "Crashed");
        let marker = mountpoint.path().join(NULL_MOUNT_MARKER);
        // The daemon died: nothing ran the unmount, the marker is still there.
        std::mem::forget(mount);
        assert!(marker.exists());
        let service = NullMountProvider::enabled(true, false);
        service
            .unmount_path(mountpoint.path(), false)
            .expect("unmount by path");
        assert!(!marker.exists());
        service
            .unmount_path(mountpoint.path(), true)
            .expect("unmounting twice is fine");
    }

    #[test]
    fn a_null_mount_needs_an_existing_mount_point() {
        let (_vault, fs) = test_fs();
        let service = NullMountProvider::enabled(true, false);
        let mut builder = service.for_file_system(fs);
        let err = builder
            .set_mountpoint(Path::new("/definitely/not/here"))
            .expect_err("a missing directory is refused");
        assert!(matches!(err, MountError::MountPoint(_, _)), "{err:?}");
        assert!(builder.set_volume_id("id").is_err(), "no VOLUME_ID");
        let Err(err) = builder.mount() else {
            panic!("mounting without a mount point must fail")
        };
        assert!(matches!(err, MountError::Failed(_)), "{err:?}");
    }

    #[test]
    fn all_services_ranks_by_priority_and_ends_with_the_null_mounter() {
        let services = all_services();
        let classes: Vec<&str> = services.iter().map(|s| s.java_class_name()).collect();
        assert_eq!(classes.last(), Some(&NULL_MOUNTER_CLASS));
        let priorities: Vec<u32> = services
            .iter()
            .take(services.len() - 1)
            .map(|s| s.priority())
            .collect();
        assert!(
            priorities.windows(2).all(|w| w[0] >= w[1]),
            "descending priorities, got {priorities:?}"
        );
        // Spelled out per feature set rather than as one literal, so that every build this
        // crate has -- `--no-default-features` included -- pins the whole order.
        let mut expected: Vec<&str> = Vec::new();
        #[cfg(all(feature = "fuse", target_os = "macos"))]
        expected.extend([MAC_FUSE_CLASS, FUSE_T_CLASS]);
        #[cfg(all(feature = "fuse", target_os = "linux"))]
        expected.extend([LINUX_FUSE_CLASS]);
        #[cfg(feature = "webdav")]
        expected.extend([FALLBACK_WEBDAV_CLASS]);
        expected.extend([NULL_MOUNTER_CLASS]);
        assert_eq!(classes, expected);
    }

    #[test]
    fn services_only_lists_what_works_here() {
        let _guard = env_lock();
        std::env::remove_var(ENABLE_NULL_MOUNTER_ENV);
        assert!(
            !services()
                .iter()
                .any(|s| s.java_class_name() == NULL_MOUNTER_CLASS),
            "the null mounter stays out of the way unless it is asked for"
        );
        std::env::set_var(ENABLE_NULL_MOUNTER_ENV, "1");
        assert!(services()
            .iter()
            .any(|s| s.java_class_name() == NULL_MOUNTER_CLASS));
        std::env::set_var(ENABLE_NULL_MOUNTER_ENV, "0");
        assert!(!services()
            .iter()
            .any(|s| s.java_class_name() == NULL_MOUNTER_CLASS));
        std::env::remove_var(ENABLE_NULL_MOUNTER_ENV);
        for service in services() {
            assert!(service.is_supported(), "{}", service.java_class_name());
        }
    }

    #[test]
    fn services_are_addressable_by_class_name_and_alias() {
        assert!(service_by_class(NULL_MOUNTER_CLASS).is_some());
        assert!(service_by_class("org.example.Nope").is_none());
        assert_eq!(alias_for_class(NULL_MOUNTER_CLASS), Some("null"));
        assert_eq!(alias_for_class(FUSE_T_CLASS), Some("fuse-t"));
        assert_eq!(alias_for_class(MAC_FUSE_CLASS), Some("macfuse"));
        assert_eq!(alias_for_class(LINUX_FUSE_CLASS), Some("fuse"));
        assert_eq!(alias_for_class(FALLBACK_WEBDAV_CLASS), Some("webdav"));
        assert_eq!(alias_for_class("org.example.Nope"), None);
    }

    #[test]
    fn macfuse_and_fuse_t_are_declared_as_conflicting() {
        assert_eq!(conflicting_classes(MAC_FUSE_CLASS), &[FUSE_T_CLASS]);
        assert_eq!(conflicting_classes(FUSE_T_CLASS), &[MAC_FUSE_CLASS]);
        assert!(conflicting_classes(LINUX_FUSE_CLASS).is_empty());
        assert!(conflicting_classes(NULL_MOUNTER_CLASS).is_empty());
    }

    #[test]
    fn service_infos_carry_the_alias_and_follow_the_all_switch() {
        let _guard = env_lock();
        std::env::remove_var(ENABLE_NULL_MOUNTER_ENV);
        let all = service_infos(true);
        assert_eq!(all.len(), all_services().len());
        let null = all
            .iter()
            .find(|info| info.class_name == NULL_MOUNTER_CLASS)
            .expect("the null mounter is listed with --all");
        assert_eq!(null.alias.as_deref(), Some("null"));
        assert!(!null.supported);
        assert!(null.capabilities.contains(&"UNMOUNT_FORCED".to_owned()));
        assert!(!service_infos(false)
            .iter()
            .any(|info| info.class_name == NULL_MOUNTER_CLASS));
    }
}
