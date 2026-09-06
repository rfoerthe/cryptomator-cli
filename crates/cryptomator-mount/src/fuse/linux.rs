//! The libfuse3 mount service (Linux).
//!
//! Unlike the macOS back ends this one does not load a library: fuser mounts the volume itself,
//! through the `fusermount3` helper, and hands the session `/dev/fuse`. The helper is also what
//! takes the mount down again.
//!
//! The module is compiled everywhere so its flag handling is covered by the test suite on any
//! platform; only the registry restricts it to Linux, where `fusermount3` exists.
use crate::api::{Mount, MountBuilder, MountCapability, MountError, MountService, UnmountError};
use crate::flags::{current_uid_gid, parse_mount_flags, AdapterOptions, MountFlags};
use crate::fuse::mount::{probe_command, run_unmount_command, FuseMount};
use crate::fuse::ops::{VaultOps, VaultOpsConfig};
use crate::fuse::session::{FuseSessionHandle, Unmounter};
use crate::registry::LINUX_FUSE_CLASS;
use crate::transcoder::{FuseNormalization, NameTranscoder};
use cryptomator_core::fs::CryptoFs;
use fuser::{MountOption, SessionACL};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

/// The libfuse3 mount helper. Everything -- mounting, unmounting, supportedness -- goes through
/// it, because an unprivileged process may not call `mount(2)` itself.
const FUSERMOUNT: &str = "fusermount3";
/// How long the helper may take to answer `-V`. It is a tiny program; a machine that cannot run
/// it in two seconds cannot serve a file system either.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Java's `LinuxFuseMountProvider` advertises exactly these two -- notably no `READ_ONLY`: a
/// read-only mount is requested with the `-r`/`-oro` mount flag.
const CAPABILITIES: &[MountCapability] = &[
    MountCapability::MountFlags,
    MountCapability::MountToExistingDir,
];

/// Mounts vaults through libfuse3.
#[derive(Debug, Clone, Copy, Default)]
pub struct LinuxFuseMountProvider;

impl MountService for LinuxFuseMountProvider {
    fn java_class_name(&self) -> &'static str {
        LINUX_FUSE_CLASS
    }

    fn display_name(&self) -> &'static str {
        "FUSE"
    }

    fn priority(&self) -> u32 {
        100
    }

    fn is_supported(&self) -> bool {
        probe_command(FUSERMOUNT, &["-V"], PROBE_TIMEOUT)
    }

    fn capabilities(&self) -> &'static [MountCapability] {
        CAPABILITIES
    }

    fn default_mount_flags(&self) -> String {
        let (uid, gid) = current_uid_gid();
        format!("-oauto_unmount -ouid={uid} -ogid={gid} -oattr_timeout=5")
    }

    fn for_file_system(&self, fs: Arc<CryptoFs>) -> Box<dyn MountBuilder> {
        Box::new(LinuxFuseMountBuilder {
            fs,
            mountpoint: None,
            flags: Vec::new(),
        })
    }

    fn unmount_path(&self, mountpoint: &Path, forced: bool) -> Result<(), UnmountError> {
        fusermount_unmount(mountpoint, forced)
    }
}

/// Which processes the kernel lets at the mount, from the flags the user gave.
fn session_acl(options: &AdapterOptions) -> SessionACL {
    if options.allow_other {
        SessionACL::All
    } else if options.allow_root {
        SessionACL::RootAndOwner
    } else {
        SessionACL::Owner
    }
}

/// The mount options for fuser, with one correction.
///
/// `-oauto_unmount` is in the default flags (Cryptomator sets it too), but fuser refuses to pass
/// it to `fusermount3` unless the session ACL is wider than [`SessionACL::Owner`]: without
/// `allow_other`/`allow_root`, libfuse's auto-unmount would let any process see the mount. So the
/// option is dropped in that case rather than failing the mount -- the CLI unmounts the vault
/// itself when it locks it, and the daemon does so on shutdown, which is what `auto_unmount` was
/// asked for.
fn mount_options(flags: &MountFlags, acl: SessionACL) -> Vec<MountOption> {
    let mut options = flags.linux_mount_options();
    if matches!(acl, SessionACL::Owner) {
        options.retain(|option| !matches!(option, MountOption::AutoUnmount));
    }
    options
}

/// `fusermount3 -u <name>` (`-uz` when forced), run from the mount point's parent directory.
///
/// Running it from the parent with the bare name is what Cryptomator does: it keeps the helper
/// from resolving the full path, which would hang on a mount whose server is already gone.
fn fusermount_unmount(mountpoint: &Path, forced: bool) -> Result<(), UnmountError> {
    let mut command = Command::new(FUSERMOUNT);
    command.arg(if forced { "-uz" } else { "-u" });
    match (mountpoint.parent(), mountpoint.file_name()) {
        (Some(parent), Some(name)) if !parent.as_os_str().is_empty() => {
            command.current_dir(parent).arg("--").arg(name);
        }
        _ => {
            command.arg("--").arg(mountpoint);
        }
    }
    // `fusermount3: entry for /mnt/x not found in /etc/mtab` and `... is not mounted` both mean
    // the volume is already gone, which is what the caller wanted.
    run_unmount_command(command, &["not mounted", "not found"])
}

/// Configures one libfuse3 mount.
#[derive(Debug)]
pub struct LinuxFuseMountBuilder {
    fs: Arc<CryptoFs>,
    mountpoint: Option<PathBuf>,
    flags: Vec<String>,
}

impl MountBuilder for LinuxFuseMountBuilder {
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

    fn mount(self: Box<Self>) -> Result<Box<dyn Mount>, MountError> {
        let Some(mountpoint) = self.mountpoint.clone() else {
            return Err(MountError::Failed(
                "FUSE needs an existing directory to mount to".to_owned(),
            ));
        };
        let (uid, gid) = current_uid_gid();
        let flags = MountFlags::from_flags(&self.flags, uid, gid)?;
        let acl = session_acl(&flags.adapter);
        let options = mount_options(&flags, acl);

        let max_name_length =
            u32::try_from(self.fs.max_cleartext_name_length()).unwrap_or(u32::MAX);
        let ops = Arc::new(VaultOps::new(
            self.fs,
            VaultOpsConfig {
                // Linux hands FUSE the bytes an application used, and the vault stores NFC.
                transcoder: NameTranscoder::new(FuseNormalization::Nfc),
                options: flags.adapter.clone(),
                read_only: flags.read_only,
                delete_apple_double: false,
                refuse_apple_double: false,
                max_name_length,
            },
        ));

        let unmount_target = mountpoint.clone();
        let unmounter: Unmounter =
            Box::new(move |forced| fusermount_unmount(&unmount_target, forced));
        let session =
            FuseSessionHandle::spawn_mounted(ops, mountpoint.clone(), options, acl, unmounter)
                .map_err(MountError::Io)?;
        // No `UNMOUNT_FORCED` capability, like Java's provider: a forced unmount is available to
        // the CLI through `MountService::unmount_path`, not through the mount itself.
        Ok(Box::new(FuseMount::new(session, mountpoint, false)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::test_fs;

    fn parsed(flags: &str) -> MountFlags {
        MountFlags::from_flags(&parse_mount_flags(flags), 1000, 1000).expect("flags parse")
    }

    #[test]
    fn the_service_matches_the_java_provider() {
        assert_eq!(
            LinuxFuseMountProvider.java_class_name(),
            "org.cryptomator.frontend.fuse.mount.LinuxFuseMountProvider"
        );
        assert_eq!(LinuxFuseMountProvider.display_name(), "FUSE");
        assert_eq!(LinuxFuseMountProvider.priority(), 100);
        assert_eq!(
            LinuxFuseMountProvider.capabilities(),
            &[
                MountCapability::MountFlags,
                MountCapability::MountToExistingDir,
            ]
        );
        assert!(!LinuxFuseMountProvider.has_capability(MountCapability::ReadOnly));
        let (uid, gid) = (
            nix::unistd::geteuid().as_raw(),
            nix::unistd::getegid().as_raw(),
        );
        assert_eq!(
            LinuxFuseMountProvider.default_mount_flags(),
            format!("-oauto_unmount -ouid={uid} -ogid={gid} -oattr_timeout=5")
        );
    }

    #[test]
    fn the_session_acl_follows_allow_other_and_allow_root() {
        assert!(matches!(
            session_acl(&parsed("-oallow_other -oallow_root").adapter),
            SessionACL::All
        ));
        assert!(matches!(
            session_acl(&parsed("-oallow_root").adapter),
            SessionACL::RootAndOwner
        ));
        assert!(matches!(
            session_acl(&parsed("-oauto_unmount").adapter),
            SessionACL::Owner
        ));
    }

    #[test]
    fn auto_unmount_reaches_fuser_only_with_a_wider_acl() {
        // The default flags ask for auto_unmount without allow_other: fuser would refuse.
        let flags = parsed(&LinuxFuseMountProvider.default_mount_flags());
        let acl = session_acl(&flags.adapter);
        assert!(matches!(acl, SessionACL::Owner));
        assert!(
            flags
                .linux_mount_options()
                .contains(&MountOption::AutoUnmount),
            "the flag itself is parsed"
        );
        assert!(
            !mount_options(&flags, acl).contains(&MountOption::AutoUnmount),
            "but it is not handed to fuser"
        );

        let flags = parsed("-oauto_unmount -oallow_other -oro");
        let acl = session_acl(&flags.adapter);
        let options = mount_options(&flags, acl);
        assert!(matches!(acl, SessionACL::All));
        assert!(options.contains(&MountOption::AutoUnmount));
        assert!(options.contains(&MountOption::RO));
    }

    #[test]
    fn the_mount_point_must_be_an_existing_directory_and_is_required() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (_vault, fs) = test_fs();
        let mut builder = LinuxFuseMountProvider.for_file_system(fs);
        assert!(matches!(
            builder.set_mountpoint(&dir.path().join("missing")),
            Err(MountError::MountPoint(_, _))
        ));
        assert!(
            builder.set_read_only(true).is_err(),
            "read-only is a mount flag here, not a capability"
        );
        assert!(builder.set_volume_name("Secret").is_err());
        builder
            .set_mount_flags(&LinuxFuseMountProvider.default_mount_flags())
            .expect("default flags parse");
        let Err(err) = builder.mount() else {
            panic!("mounting without a mount point must fail")
        };
        assert!(matches!(err, MountError::Failed(_)), "{err:?}");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn without_fusermount3_the_service_is_unsupported() {
        assert!(
            !LinuxFuseMountProvider.is_supported(),
            "fusermount3 does not exist outside Linux"
        );
    }
}
