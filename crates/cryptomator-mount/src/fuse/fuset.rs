//! The FUSE-T mount service (macOS).
//!
//! FUSE-T needs no kernel extension: its library mounts an NFS share and speaks the FUSE protocol
//! over the socket it hands back. Two consequences shape this provider -- the session runs with
//! [`KernelAbi::Linux`], because FUSE-T decodes the Linux struct layouts (Spike C), and the volume
//! is taken down with `umount`, like any other NFS mount.
//!
//! `-obackend=smb` is deliberately not used: Spike A found the NFS backend to be the one that
//! works without further setup.
use crate::api::{Mount, MountBuilder, MountCapability, MountError, MountService, UnmountError};
use crate::flags::{current_uid_gid, parse_mount_flags, MountFlags};
use crate::fuse::macos_dl::LibFuse;
use crate::fuse::mount::{push_flag, umount_macos, FuseMount};
use crate::fuse::ops::{VaultOps, VaultOpsConfig};
use crate::fuse::session::{FuseSessionHandle, Unmounter};
use crate::registry::FUSE_T_CLASS;
use crate::transcoder::{FuseNormalization, NameTranscoder};
use cryptomator_core::fs::CryptoFs;
use fuser::KernelAbi;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Where FUSE-T installs its library.
pub const FUSE_T_DYLIB: &str = "/usr/local/lib/libfuse-t.dylib";
/// Points the provider at another library; the tests use it to make [`is_supported`](MountService::is_supported)
/// answer without FUSE-T being installed.
pub const FUSE_T_LIB_ENV: &str = "CRYPTO_FUSE_T_LIB";

/// FUSE-T tells the kernel it has no named attributes; without this it asks for `com.apple.*`
/// extended attributes on every single node.
const NO_NAMED_ATTR: &str = "-ononamedattr";

const CAPABILITIES: &[MountCapability] = &[
    MountCapability::MountFlags,
    MountCapability::UnmountForced,
    MountCapability::ReadOnly,
    MountCapability::MountToExistingDir,
    MountCapability::VolumeName,
];

/// Mounts vaults through FUSE-T.
#[derive(Debug, Clone, Copy, Default)]
pub struct FuseTMountProvider;

impl FuseTMountProvider {
    /// The library this provider loads: [`FUSE_T_LIB_ENV`] if set, [`FUSE_T_DYLIB`] otherwise.
    /// The environment is read on every call, so a test can set it up after the provider exists.
    pub fn library_path() -> PathBuf {
        std::env::var_os(FUSE_T_LIB_ENV).map_or_else(|| PathBuf::from(FUSE_T_DYLIB), PathBuf::from)
    }
}

impl MountService for FuseTMountProvider {
    fn java_class_name(&self) -> &'static str {
        FUSE_T_CLASS
    }

    fn display_name(&self) -> &'static str {
        "FUSE-T (Experimental)"
    }

    fn priority(&self) -> u32 {
        90
    }

    fn is_supported(&self) -> bool {
        Self::library_path().exists()
    }

    fn capabilities(&self) -> &'static [MountCapability] {
        CAPABILITIES
    }

    fn default_mount_flags(&self) -> String {
        let (uid, gid) = current_uid_gid();
        format!("-ononamedattr -orwsize=262144 -ouid={uid} -ogid={gid}")
    }

    fn for_file_system(&self, fs: Arc<CryptoFs>) -> Box<dyn MountBuilder> {
        Box::new(FuseTMountBuilder {
            fs,
            mountpoint: None,
            flags: Vec::new(),
            read_only: false,
            volume_name: None,
        })
    }

    fn unmount_path(&self, mountpoint: &Path, forced: bool) -> Result<(), UnmountError> {
        umount_macos(mountpoint, forced)
    }
}

/// Configures one FUSE-T mount.
#[derive(Debug)]
pub struct FuseTMountBuilder {
    fs: Arc<CryptoFs>,
    mountpoint: Option<PathBuf>,
    flags: Vec<String>,
    read_only: bool,
    volume_name: Option<String>,
}

impl FuseTMountBuilder {
    /// The user's flags plus what the other setters and this back end add: `-r` for a read-only
    /// mount, `-ovolname=` for the volume name, and always [`NO_NAMED_ATTR`] -- each of them only
    /// if the user did not set that option already.
    pub fn combined_flags(&self) -> Vec<String> {
        let mut flags = self.flags.clone();
        if self.read_only {
            push_flag(&mut flags, "-r");
        }
        if let Some(name) = &self.volume_name {
            push_flag(&mut flags, &format!("-ovolname={name}"));
        }
        push_flag(&mut flags, NO_NAMED_ATTR);
        flags
    }
}

impl MountBuilder for FuseTMountBuilder {
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
                "FUSE-T needs an existing directory to mount to".to_owned(),
            ));
        };
        let (uid, gid) = current_uid_gid();
        let flags = MountFlags::from_flags(&self.combined_flags(), uid, gid)?;
        let read_only = flags.read_only || self.read_only;

        // What the mount itself gets: every option the adapter does not handle, plus the volume
        // name -- FUSE-T puts that in the NFS mount, where the Finder reads it. `uid`/`gid`,
        // `attr_timeout`, `entry_timeout` and `noappledouble` stay out: this adapter applies them
        // itself, the way libfuse's high-level API does for Cryptomator.
        let mut options = flags.passthrough.clone();
        if let Some(volname) = &flags.adapter.volname {
            options.push(format!("volname={volname}"));
        }

        let library = LibFuse::load(&FuseTMountProvider::library_path())?;
        let fd = library.mount(&mountpoint, &options)?;

        let max_name_length =
            u32::try_from(self.fs.max_cleartext_name_length()).unwrap_or(u32::MAX);
        let ops = Arc::new(VaultOps::new(
            self.fs,
            VaultOpsConfig {
                // macOS hands FUSE decomposed names, whatever the vault stores.
                transcoder: NameTranscoder::new(FuseNormalization::Nfd),
                options: flags.adapter,
                read_only,
                delete_apple_double: true,
                max_name_length,
            },
        ));

        let unmount_target = mountpoint.clone();
        let unmounter: Unmounter = Box::new(move |forced| {
            // Holding the library here keeps it loaded for as long as the session lives: FUSE-T's
            // server threads run inside it, and unloading it under them would take the process
            // down.
            let _keep_loaded = &library;
            umount_macos(&unmount_target, forced)
        });

        match FuseSessionHandle::spawn_from_fd(
            ops,
            mountpoint.clone(),
            fd,
            KernelAbi::Linux,
            unmounter,
        ) {
            Ok(session) => Ok(Box::new(FuseMount::new(session, mountpoint, true))),
            Err(err) => {
                // The volume is mounted but nothing serves it; leaving it would strand the mount
                // point.
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

    /// A builder plus the vault directory it lives on; the directory must outlive it.
    fn builder() -> (tempfile::TempDir, Box<dyn MountBuilder>) {
        let (dir, fs) = test_fs();
        (dir, FuseTMountProvider.for_file_system(fs))
    }

    #[test]
    fn the_service_matches_the_java_provider() {
        assert_eq!(
            FuseTMountProvider.java_class_name(),
            "org.cryptomator.frontend.fuse.mount.FuseTMountProvider"
        );
        assert_eq!(FuseTMountProvider.display_name(), "FUSE-T (Experimental)");
        assert_eq!(FuseTMountProvider.priority(), 90);
        assert_eq!(
            FuseTMountProvider.capabilities(),
            &[
                MountCapability::MountFlags,
                MountCapability::UnmountForced,
                MountCapability::ReadOnly,
                MountCapability::MountToExistingDir,
                MountCapability::VolumeName,
            ]
        );
        let (uid, gid) = (
            nix::unistd::geteuid().as_raw(),
            nix::unistd::getegid().as_raw(),
        );
        assert_eq!(
            FuseTMountProvider.default_mount_flags(),
            format!("-ononamedattr -orwsize=262144 -ouid={uid} -ogid={gid}")
        );
        assert!(
            !FuseTMountProvider
                .default_mount_flags()
                .contains("backend=smb"),
            "the SMB backend is deliberately unused"
        );
    }

    #[test]
    fn the_combined_flags_add_nonamedattr_once_read_only_and_the_volume_name() {
        let (_dir, fs) = test_fs();
        let mut builder = FuseTMountBuilder {
            fs,
            mountpoint: None,
            flags: parse_mount_flags(&FuseTMountProvider.default_mount_flags()),
            read_only: false,
            volume_name: None,
        };
        let plain = builder.combined_flags();
        assert_eq!(
            plain.iter().filter(|f| *f == NO_NAMED_ATTR).count(),
            1,
            "already in the default flags: {plain:?}"
        );
        assert!(!plain.iter().any(|f| f == "-r"));

        builder.read_only = true;
        builder.volume_name = Some("My Vault".to_owned());
        let combined = builder.combined_flags();
        assert_eq!(combined.iter().filter(|f| *f == NO_NAMED_ATTR).count(), 1);
        assert!(combined.iter().any(|f| f == "-r"));
        assert!(combined.iter().any(|f| f == "-ovolname=My Vault"));

        // A user who names the volume themselves keeps their name.
        builder.flags = parse_mount_flags("-ovolname=Mine");
        let combined = builder.combined_flags();
        assert!(combined.iter().any(|f| f == "-ovolname=Mine"));
        assert!(!combined.iter().any(|f| f == "-ovolname=My Vault"));
        assert_eq!(combined.iter().filter(|f| *f == NO_NAMED_ATTR).count(), 1);
    }

    #[test]
    fn the_mount_point_must_be_an_existing_directory() {
        let dir = tempfile::tempdir().expect("temp dir");
        let file = dir.path().join("file");
        std::fs::write(&file, b"x").expect("write file");
        let (_vault, mut builder) = builder();
        builder
            .set_mountpoint(dir.path())
            .expect("an existing directory is fine");
        assert!(matches!(
            builder.set_mountpoint(&file),
            Err(MountError::MountPoint(_, _))
        ));
        assert!(matches!(
            builder.set_mountpoint(&dir.path().join("missing")),
            Err(MountError::MountPoint(_, _))
        ));
        assert!(
            builder.set_volume_id("id").is_err(),
            "FUSE-T has no VOLUME_ID capability"
        );
        assert!(builder.set_loopback_port(8080).is_err());
    }

    #[test]
    fn without_a_mount_point_there_is_no_mount() {
        let (_vault, builder) = builder();
        let Err(err) = builder.mount() else {
            panic!("mounting without a mount point must fail")
        };
        assert!(matches!(err, MountError::Failed(_)), "{err:?}");
    }

    #[test]
    fn support_follows_the_library_path() {
        let _guard = env_lock();
        let dir = tempfile::tempdir().expect("temp dir");
        let library = dir.path().join("libfuse-t.dylib");
        std::fs::write(&library, b"not really a library").expect("write file");

        std::env::set_var(FUSE_T_LIB_ENV, &library);
        assert_eq!(FuseTMountProvider::library_path(), library);
        assert!(FuseTMountProvider.is_supported());

        std::env::set_var(FUSE_T_LIB_ENV, dir.path().join("missing.dylib"));
        assert!(!FuseTMountProvider.is_supported());

        std::env::remove_var(FUSE_T_LIB_ENV);
        assert_eq!(
            FuseTMountProvider::library_path(),
            PathBuf::from(FUSE_T_DYLIB)
        );
    }

    #[test]
    fn unmounting_a_path_that_is_not_mounted_succeeds() {
        let dir = tempfile::tempdir().expect("temp dir");
        FuseTMountProvider
            .unmount_path(dir.path(), false)
            .expect("nothing to unmount");
        FuseTMountProvider
            .unmount_path(dir.path(), true)
            .expect("nothing to unmount, forced");
    }
}
