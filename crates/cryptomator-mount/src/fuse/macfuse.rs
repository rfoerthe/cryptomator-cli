//! The macFUSE mount service (macOS).
//!
//! **Unverified.** macFUSE is not installed on the machine this was written on, so this provider
//! is written from Cryptomator's `MacFuseMountProvider` and macFUSE's documented libfuse 2.x
//! entry points, and it has never mounted anything. Its display name says so, and the CLI's
//! `mounters` output repeats it. Everything below the mount -- the session, the adapter -- is the
//! code FUSE-T exercises; what is untried is the `fuse_mount_compat25` call into macFUSE and the
//! [`KernelAbi::Native`] struct layouts it implies.
use crate::api::{Mount, MountBuilder, MountCapability, MountError, MountService, UnmountError};
use crate::flags::{current_uid_gid, parse_mount_flags, MountFlags};
use crate::fuse::macos_dl::LibFuse;
use crate::fuse::mount::{push_flag, umount_macos, FuseMount};
use crate::fuse::ops::{VaultOps, VaultOpsConfig};
use crate::fuse::session::{FuseSessionHandle, Unmounter};
use crate::registry::MAC_FUSE_CLASS;
use crate::transcoder::{FuseNormalization, NameTranscoder};
use cryptomator_core::fs::CryptoFs;
use fuser::KernelAbi;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// The libraries macFUSE installs, newest name first.
pub const MACFUSE_DYLIBS: &[&str] = &[
    "/usr/local/lib/libosxfuse.2.dylib",
    "/usr/local/lib/libfuse.2.dylib",
];
/// Points the provider at another library; the tests use it to make [`is_supported`](MountService::is_supported)
/// answer without macFUSE being installed.
pub const MACFUSE_LIB_ENV: &str = "CRYPTO_MACFUSE_LIB";

/// Where macOS expects a volume that the system, not the user, placed.
const VOLUMES: &str = "/Volumes";
/// macFUSE 5 can serve through Apple's FSKit instead of the kernel extension. That backend speaks
/// a different protocol than the one this adapter implements, so it is refused rather than
/// silently mounted into a filesystem that would not answer.
const FSKIT_BACKEND: &str = "-obackend=fskit";

const CAPABILITIES: &[MountCapability] = &[
    MountCapability::MountFlags,
    MountCapability::UnmountForced,
    MountCapability::ReadOnly,
    MountCapability::MountToExistingDir,
    MountCapability::MountToSystemChosenPath,
    MountCapability::VolumeId,
    MountCapability::VolumeName,
];

/// Mounts vaults through macFUSE (unverified, see the module documentation).
#[derive(Debug, Clone, Copy, Default)]
pub struct MacFuseMountProvider;

impl MacFuseMountProvider {
    /// The library this provider loads: [`MACFUSE_LIB_ENV`] if set, otherwise the first of
    /// [`MACFUSE_DYLIBS`] that exists. The environment is read on every call, so a test can set
    /// it up after the provider exists.
    pub fn library_path() -> Option<PathBuf> {
        if let Some(override_path) = std::env::var_os(MACFUSE_LIB_ENV) {
            return Some(PathBuf::from(override_path));
        }
        MACFUSE_DYLIBS
            .iter()
            .map(PathBuf::from)
            .find(|path| path.exists())
    }
}

impl MountService for MacFuseMountProvider {
    fn java_class_name(&self) -> &'static str {
        MAC_FUSE_CLASS
    }

    fn display_name(&self) -> &'static str {
        "macFUSE (unverified)"
    }

    fn priority(&self) -> u32 {
        100
    }

    fn is_supported(&self) -> bool {
        Self::library_path().is_some_and(|path| path.exists())
    }

    fn capabilities(&self) -> &'static [MountCapability] {
        CAPABILITIES
    }

    fn default_mount_flags(&self) -> String {
        let (uid, gid) = current_uid_gid();
        format!(
            "-ouid={uid} -ogid={gid} -oatomic_o_trunc -oauto_xattr -oauto_cache -onoappledouble -odefault_permissions"
        )
    }

    fn for_file_system(&self, fs: Arc<CryptoFs>) -> Box<dyn MountBuilder> {
        Box::new(MacFuseMountBuilder {
            fs,
            mountpoint: None,
            flags: Vec::new(),
            read_only: false,
            volume_id: None,
            volume_name: None,
        })
    }

    fn unmount_path(&self, mountpoint: &Path, forced: bool) -> Result<(), UnmountError> {
        umount_macos(mountpoint, forced)
    }
}

/// Configures one macFUSE mount.
#[derive(Debug)]
pub struct MacFuseMountBuilder {
    fs: Arc<CryptoFs>,
    mountpoint: Option<PathBuf>,
    flags: Vec<String>,
    read_only: bool,
    volume_id: Option<String>,
    volume_name: Option<String>,
}

impl MacFuseMountBuilder {
    /// The user's flags plus `-r` for a read-only mount and `-ovolname=` for the volume name,
    /// each only if the user did not set that option already.
    pub fn combined_flags(&self) -> Vec<String> {
        let mut flags = self.flags.clone();
        if self.read_only {
            push_flag(&mut flags, "-r");
        }
        if let Some(name) = &self.volume_name {
            push_flag(&mut flags, &format!("-ovolname={name}"));
        }
        flags
    }

    /// Where this mount goes: the directory the user chose, or `/Volumes/<volume id>` -- the
    /// system-chosen path macFUSE advertises, which macOS creates and removes itself.
    ///
    /// # Errors
    /// [`MountError::Failed`] if neither a mount point nor a volume id was set.
    pub fn effective_mountpoint(&self) -> Result<PathBuf, MountError> {
        if let Some(path) = &self.mountpoint {
            return Ok(path.clone());
        }
        match &self.volume_id {
            Some(id) => Ok(PathBuf::from(VOLUMES).join(id)),
            None => Err(MountError::Failed(
                "macFUSE needs a mount point or a volume id".to_owned(),
            )),
        }
    }
}

/// Rejects the FSKit backend wherever flags arrive.
fn reject_unsupported(flags: &[String]) -> Result<(), MountError> {
    match flags.iter().find(|flag| *flag == FSKIT_BACKEND) {
        Some(flag) => Err(MountError::UnsupportedFlag(flag.clone())),
        None => Ok(()),
    }
}

impl MountBuilder for MacFuseMountBuilder {
    fn set_mountpoint(&mut self, path: &Path) -> Result<(), MountError> {
        // An existing directory, or a name macOS will create under /Volumes -- Cryptomator's
        // `MacFuseMountBuilder` accepts exactly these two.
        let acceptable = path.is_dir()
            || (!path.exists()
                && path.parent() == Some(Path::new(VOLUMES))
                && Path::new(VOLUMES).is_dir());
        if !acceptable {
            return Err(MountError::MountPoint(
                path.to_path_buf(),
                "not an existing directory and not a free name under /Volumes".to_owned(),
            ));
        }
        self.mountpoint = Some(path.to_path_buf());
        Ok(())
    }

    fn set_mount_flags(&mut self, flags: &str) -> Result<(), MountError> {
        let parsed = parse_mount_flags(flags);
        reject_unsupported(&parsed)?;
        self.flags = parsed;
        Ok(())
    }

    fn set_read_only(&mut self, read_only: bool) -> Result<(), MountError> {
        self.read_only = read_only;
        Ok(())
    }

    fn set_volume_id(&mut self, id: &str) -> Result<(), MountError> {
        self.volume_id = Some(id.to_owned());
        Ok(())
    }

    fn set_volume_name(&mut self, name: &str) -> Result<(), MountError> {
        self.volume_name = Some(name.to_owned());
        Ok(())
    }

    fn mount(self: Box<Self>) -> Result<Box<dyn Mount>, MountError> {
        let mountpoint = self.effective_mountpoint()?;
        let combined = self.combined_flags();
        reject_unsupported(&combined)?;
        let (uid, gid) = current_uid_gid();
        let flags = MountFlags::from_flags(&combined, uid, gid)?;
        let read_only = flags.read_only || self.read_only;

        // As for FUSE-T: the adapter applies uid/gid, the timeouts and the AppleDouble handling
        // itself, so only the remaining options and the volume name go to the mount.
        let mut options = flags.passthrough.clone();
        if let Some(volname) = &flags.adapter.volname {
            options.push(format!("volname={volname}"));
        }

        let Some(library_path) = MacFuseMountProvider::library_path() else {
            return Err(MountError::Failed(format!(
                "macFUSE is not installed (looked for {})",
                MACFUSE_DYLIBS.join(", ")
            )));
        };
        let library = LibFuse::load(&library_path)?;
        let fd = library.mount(&mountpoint, &options)?;

        let max_name_length =
            u32::try_from(self.fs.max_cleartext_name_length()).unwrap_or(u32::MAX);
        let ops = Arc::new(VaultOps::new(
            self.fs,
            VaultOpsConfig {
                transcoder: NameTranscoder::new(FuseNormalization::Nfd),
                options: flags.adapter,
                read_only,
                delete_apple_double: true,
                max_name_length,
            },
        ));

        let unmount_target = mountpoint.clone();
        let unmounter: Unmounter = Box::new(move |forced| {
            // Keeps the library loaded for the life of the session, see the FUSE-T provider.
            let _keep_loaded = &library;
            umount_macos(&unmount_target, forced)
        });

        // macFUSE is a kernel extension speaking the platform's own struct layouts, unlike FUSE-T.
        match FuseSessionHandle::spawn_from_fd(
            ops,
            mountpoint.clone(),
            fd,
            KernelAbi::Native,
            unmounter,
        ) {
            Ok(session) => Ok(Box::new(FuseMount::new(session, mountpoint, true))),
            Err(err) => {
                let _ = umount_macos(&mountpoint, true);
                Err(MountError::Io(err))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{env_lock, test_fs};

    fn builder() -> (tempfile::TempDir, Box<dyn MountBuilder>) {
        let (dir, fs) = test_fs();
        (dir, MacFuseMountProvider.for_file_system(fs))
    }

    #[test]
    fn the_service_matches_the_java_provider_and_says_it_is_unverified() {
        assert_eq!(
            MacFuseMountProvider.java_class_name(),
            "org.cryptomator.frontend.fuse.mount.MacFuseMountProvider"
        );
        assert_eq!(MacFuseMountProvider.display_name(), "macFUSE (unverified)");
        assert_eq!(MacFuseMountProvider.priority(), 100);
        assert_eq!(
            MacFuseMountProvider.capabilities(),
            &[
                MountCapability::MountFlags,
                MountCapability::UnmountForced,
                MountCapability::ReadOnly,
                MountCapability::MountToExistingDir,
                MountCapability::MountToSystemChosenPath,
                MountCapability::VolumeId,
                MountCapability::VolumeName,
            ]
        );
        let (uid, gid) = (
            nix::unistd::geteuid().as_raw(),
            nix::unistd::getegid().as_raw(),
        );
        assert_eq!(
            MacFuseMountProvider.default_mount_flags(),
            format!("-ouid={uid} -ogid={gid} -oatomic_o_trunc -oauto_xattr -oauto_cache -onoappledouble -odefault_permissions")
        );
    }

    #[test]
    fn the_fskit_backend_is_refused() {
        let (_vault, mut builder) = builder();
        let err = builder
            .set_mount_flags("-oauto_cache -obackend=fskit")
            .expect_err("fskit is refused");
        match err {
            MountError::UnsupportedFlag(flag) => assert_eq!(flag, "-obackend=fskit"),
            other => panic!("expected UnsupportedFlag, got {other:?}"),
        }
        builder
            .set_mount_flags("-obackend=nfs")
            .expect("other backends pass through");
    }

    #[test]
    fn the_mount_point_is_an_existing_directory_or_a_free_name_under_volumes() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (_vault, mut builder) = builder();
        builder
            .set_mountpoint(dir.path())
            .expect("an existing directory is fine");
        builder
            .set_mountpoint(Path::new("/Volumes/crypto-test-volume-that-does-not-exist"))
            .expect("a free name under /Volumes is fine");
        assert!(matches!(
            builder.set_mountpoint(&dir.path().join("missing")),
            Err(MountError::MountPoint(_, _))
        ));
    }

    #[test]
    fn without_a_mount_point_the_volume_id_names_the_path() {
        let (_vault, fs) = test_fs();
        let mut builder = MacFuseMountBuilder {
            fs,
            mountpoint: None,
            flags: Vec::new(),
            read_only: true,
            volume_id: None,
            volume_name: Some("My Vault".to_owned()),
        };
        assert!(matches!(
            builder.effective_mountpoint(),
            Err(MountError::Failed(_))
        ));
        builder.volume_id = Some("8f3b".to_owned());
        assert_eq!(
            builder.effective_mountpoint().expect("volume id path"),
            PathBuf::from("/Volumes/8f3b")
        );
        builder.mountpoint = Some(PathBuf::from("/mnt/chosen"));
        assert_eq!(
            builder.effective_mountpoint().expect("chosen path"),
            PathBuf::from("/mnt/chosen")
        );
        let combined = builder.combined_flags();
        assert!(combined.iter().any(|f| f == "-r"));
        assert!(combined.iter().any(|f| f == "-ovolname=My Vault"));
        assert!(
            !combined.iter().any(|f| f == "-ononamedattr"),
            "that one is FUSE-T's"
        );
    }

    #[test]
    fn support_follows_the_library_path() {
        let _guard = env_lock();
        let dir = tempfile::tempdir().expect("temp dir");
        let library = dir.path().join("libosxfuse.2.dylib");
        std::fs::write(&library, b"not really a library").expect("write file");

        std::env::set_var(MACFUSE_LIB_ENV, &library);
        assert_eq!(MacFuseMountProvider::library_path(), Some(library));
        assert!(MacFuseMountProvider.is_supported());

        std::env::set_var(MACFUSE_LIB_ENV, dir.path().join("missing.dylib"));
        assert!(!MacFuseMountProvider.is_supported());

        std::env::remove_var(MACFUSE_LIB_ENV);
        // Without the override the answer is whatever this machine has; macFUSE was not installed
        // when this was written, so only the shape of the answer is asserted.
        assert_eq!(
            MacFuseMountProvider::library_path().is_some(),
            MACFUSE_DYLIBS.iter().any(|p| Path::new(p).exists())
        );
    }

    #[test]
    fn mounting_without_a_library_fails_before_anything_is_touched() {
        let _guard = env_lock();
        let dir = tempfile::tempdir().expect("temp dir");
        std::env::set_var(MACFUSE_LIB_ENV, dir.path().join("missing.dylib"));
        let (_vault, mut builder) = builder();
        builder.set_mountpoint(dir.path()).expect("mount point");
        let Err(err) = builder.mount() else {
            panic!("mounting without a library must fail")
        };
        std::env::remove_var(MACFUSE_LIB_ENV);
        assert!(matches!(err, MountError::Failed(_)), "{err:?}");
    }

    #[test]
    fn unmounting_a_path_that_is_not_mounted_succeeds() {
        let dir = tempfile::tempdir().expect("temp dir");
        MacFuseMountProvider
            .unmount_path(dir.path(), false)
            .expect("nothing to unmount");
    }
}
