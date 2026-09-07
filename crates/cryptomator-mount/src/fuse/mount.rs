//! The [`Mount`] every FUSE back end hands back, and the process helpers they take it down with.
//!
//! The back ends differ only in how the volume got into the namespace (a mounted fd from a
//! dynamically loaded libfuse, or fuser's own mount) and in the command that removes it again.
//! Once the session runs, they all look the same: a [`FuseSessionHandle`] plus the mount point
//! it serves.
use crate::api::{Mount, Mountpoint, UnmountError};
#[cfg(target_os = "macos")]
use crate::flags::MountFlags;
#[cfg(target_os = "macos")]
use crate::fuse::ops::VaultOpsConfig;
use crate::fuse::session::FuseSessionHandle;
use crate::mounttab::is_mountpoint;
#[cfg(target_os = "macos")]
use crate::process::run_unmount_command;
#[cfg(target_os = "macos")]
use crate::transcoder::{FuseNormalization, NameTranscoder};
#[cfg(target_os = "macos")]
use std::path::Path;
use std::path::PathBuf;
#[cfg(target_os = "macos")]
use std::process::Command;
#[cfg(target_os = "macos")]
use std::time::Duration;
#[cfg(target_os = "macos")]
use std::time::Instant;

/// How long [`umount_macos`] keeps retrying a busy volume before it reports
/// [`UnmountError::Busy`], and how long it waits between attempts.
///
/// macOS' NFS client -- which is what a FUSE-T volume is -- holds the mount for a moment after
/// the last operation on it: `umount(8)` right after writing reports "filesystem busy" even
/// though nothing has the volume open any more, and succeeds a few hundred milliseconds later.
/// Reporting that as `Busy` would send the CLI (and the user) to `--force` for no reason, so a
/// graceful unmount insists for a while first. A volume that really is in use -- a shell sitting
/// in it -- still ends up as `Busy`, just five seconds later.
#[cfg(target_os = "macos")]
const UNMOUNT_BUSY_RETRY: Duration = Duration::from_secs(5);
#[cfg(target_os = "macos")]
const UNMOUNT_BUSY_RETRY_INTERVAL: Duration = Duration::from_millis(100);

/// A mounted vault served by a FUSE session.
#[derive(Debug)]
pub struct FuseMount {
    session: FuseSessionHandle,
    mountpoint: PathBuf,
    supports_forced: bool,
}

impl FuseMount {
    /// The mount of `mountpoint`, served by `session`. `supports_forced` mirrors the service's
    /// [`MountCapability::UnmountForced`](crate::api::MountCapability::UnmountForced): only a
    /// service advertising it may answer [`Mount::unmount_forced`].
    pub fn new(session: FuseSessionHandle, mountpoint: PathBuf, supports_forced: bool) -> Self {
        Self {
            session,
            mountpoint,
            supports_forced,
        }
    }

    /// Whether a file is still open on this mount; a graceful unmount would lose its buffered
    /// writes.
    pub fn is_in_use(&self) -> bool {
        self.session.is_in_use()
    }
}

impl Mount for FuseMount {
    fn mountpoint(&self) -> Mountpoint {
        Mountpoint::Path(self.mountpoint.clone())
    }

    fn unmount(&mut self) -> Result<(), UnmountError> {
        self.session.unmount(false)
    }

    fn unmount_forced(&mut self) -> Result<(), UnmountError> {
        if !self.supports_forced {
            return Err(UnmountError::Failed(
                "forced unmount not supported by this mount service".to_owned(),
            ));
        }
        self.session.unmount(true)
    }

    /// Unmounts if the volume is still mounted, then waits -- bounded by the same ten seconds
    /// [`unmount`](Self::unmount) allows -- for the session thread to end.
    ///
    /// # Errors
    /// The unmount's own error, or [`UnmountError::Busy`] if the session was still serving when
    /// the wait ran out. Closing is not allowed to block forever: a mount whose last request
    /// never comes back would hang the daemon's shutdown, so the caller is told it is busy and
    /// can force the unmount instead. The session thread is left waiting for its own end; nothing
    /// but that thread survives this.
    fn close(self: Box<Self>) -> Result<(), UnmountError> {
        let mut this = *self;
        // Only unmount what is still mounted: `close` also runs after a successful `unmount`, and
        // after someone typed `umount` in a shell.
        if is_mountpoint(&this.mountpoint) {
            this.session.unmount(false)?;
        }
        this.session.join_bounded()
    }
}

/// Adds `flag` to `flags` unless an equivalent one is already there.
///
/// Only the macOS back ends need this: they are the ones with the `READ_ONLY` and `VOLUME_NAME`
/// capabilities, i.e. the ones that add flags of their own to the user's.
///
/// "Equivalent" compares the part before a `=`, so a user's own `-ovolname=Mine` keeps the
/// builder from appending a second `-ovolname=`; Cryptomator's `AbstractMountBuilder` collects
/// its flags in a set for the same reason.
#[cfg(target_os = "macos")]
pub(crate) fn push_flag(flags: &mut Vec<String>, flag: &str) {
    fn key(flag: &str) -> &str {
        flag.split_once('=').map_or(flag, |(key, _)| key)
    }
    if !flags.iter().any(|existing| key(existing) == key(flag)) {
        flags.push(flag.to_owned());
    }
}

/// The `-o` values a macOS back end hands to `fuse_mount_compat25`.
///
/// Everything the adapter does not apply itself, plus the volume name -- FUSE-T puts that in the
/// NFS mount, where the Finder reads it -- and `ro` for a read-only mount, which Cryptomator
/// passes to libfuse as `-r`. `uid`/`gid`, `attr_timeout`, `entry_timeout`, `noappledouble` and
/// `volname` stay out of the passthrough list: [`MountFlags`] classified them as
/// [`AdapterOptions`](crate::flags::AdapterOptions), the way libfuse's high-level API applies
/// them for Cryptomator.
///
/// Two of those adapter options are deliberately no-ops on macOS, because this back end has
/// nothing to apply them to:
///
/// * `default_permissions` -- the kernel that would do the checking is macFUSE, or an NFS client
///   for FUSE-T, and the adapter answers `access` itself.
/// * `allow_other` / `allow_root` -- [`FuseSessionHandle::spawn_from_fd`] always runs with
///   `SessionACL::Owner`, so only the mounting user is served.
///
/// They are accepted rather than rejected so a flag string copied from a Linux setup still mounts.
#[cfg(target_os = "macos")]
pub(crate) fn macos_mount_options(flags: &MountFlags, read_only: bool) -> Vec<String> {
    let mut options = flags.passthrough.clone();
    if let Some(volname) = &flags.adapter.volname {
        options.push(format!("volname={volname}"));
    }
    if read_only {
        options.push("ro".to_owned());
    }
    options
}

/// The adapter configuration both macOS back ends build from their parsed flags.
///
/// macOS hands FUSE decomposed names, whatever the vault stores, hence [`FuseNormalization::Nfd`].
/// The `._*`/`.DS_Store` sweep on `rmdir` is on for both macOS back ends, like Cryptomator's
/// `deleteAppleDoubleFiles`, which is decided by the platform and not by a mount flag: Finder
/// leaves those side cars behind on macOS whichever back end serves the volume, and a directory
/// holding nothing but them cannot be removed otherwise. `-onoappledouble` is still parsed (it is
/// part of macFUSE's default flags), it just does not gate the sweep.
///
/// `refuse_apple_double` follows the back end instead, see
/// [`VaultOpsConfig::refuse_apple_double`]: macFUSE keeps the side cars away from userspace by
/// itself, FUSE-T cannot and needs the adapter to say no.
#[cfg(target_os = "macos")]
pub(crate) fn macos_ops_config(
    flags: MountFlags,
    read_only: bool,
    max_name_length: u32,
    refuse_apple_double: bool,
) -> VaultOpsConfig {
    VaultOpsConfig {
        transcoder: NameTranscoder::new(FuseNormalization::Nfd),
        delete_apple_double: true,
        refuse_apple_double,
        options: flags.adapter,
        read_only,
        max_name_length,
    }
}

/// Takes a macOS mount down: `umount -- <path>`, or `umount -f -- <path>` when forced.
///
/// Both FUSE-T (whose mount is an NFS mount) and macFUSE are unmounted this way, as Cryptomator
/// does it. A volume that is no longer mounted counts as success, and a *graceful* unmount of one
/// that is merely still settling is retried, see [`UNMOUNT_BUSY_RETRY`]. A forced unmount is not:
/// the caller has already decided not to wait, and `umount -f` is what one does *because* the
/// volume is busy -- retrying would only add five seconds before reporting the same failure.
///
/// # Errors
/// See [`run_unmount_command`].
#[cfg(target_os = "macos")]
pub(crate) fn umount_macos(mountpoint: &Path, forced: bool) -> Result<(), UnmountError> {
    let attempt = || {
        let mut command = Command::new("umount");
        if forced {
            command.arg("-f");
        }
        command.arg("--").arg(mountpoint);
        run_unmount_command(command, &["not currently mounted", "not mounted"])
    };
    if forced {
        attempt()
    } else {
        retry_while_busy(UNMOUNT_BUSY_RETRY, attempt)
    }
}

/// Runs `attempt` until it stops reporting [`UnmountError::Busy`], giving up after `retry_for`.
///
/// Every other outcome -- success included -- is returned from the first attempt that produces
/// it; only `Busy` is retried, and the last `Busy` is what the caller sees.
#[cfg(target_os = "macos")]
fn retry_while_busy(
    retry_for: Duration,
    mut attempt: impl FnMut() -> Result<(), UnmountError>,
) -> Result<(), UnmountError> {
    let deadline = Instant::now() + retry_for;
    loop {
        match attempt() {
            Err(UnmountError::Busy) if Instant::now() < deadline => {
                std::thread::sleep(UNMOUNT_BUSY_RETRY_INTERVAL);
            }
            other => return other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[test]
    fn push_flag_keeps_one_flag_per_key() {
        let mut flags = vec!["-orwsize=262144".to_owned(), "-ononamedattr".to_owned()];
        push_flag(&mut flags, "-ononamedattr");
        push_flag(&mut flags, "-r");
        push_flag(&mut flags, "-r");
        push_flag(&mut flags, "-ovolname=Secret");
        push_flag(&mut flags, "-ovolname=Other");
        assert_eq!(
            flags,
            vec!["-orwsize=262144", "-ononamedattr", "-r", "-ovolname=Secret"]
        );
    }

    /// The AppleDouble sweep is on for both macOS back ends, whatever the flags say: it follows
    /// the platform, like Cryptomator's `deleteAppleDoubleFiles`. `-onoappledouble` is still
    /// parsed, it just does not gate the sweep.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_apple_double_sweep_is_on_for_every_macos_back_end() {
        use crate::flags::parse_mount_flags;

        let parse = |flags: &str| {
            MountFlags::from_flags(&parse_mount_flags(flags), 501, 20).expect("flags parse")
        };
        let sweeps =
            |flags: &str| macos_ops_config(parse(flags), false, 255, false).delete_apple_double;

        assert!(
            sweeps("-ononamedattr -orwsize=262144 -ouid=501 -ogid=20"),
            "FUSE-T's default flags carry no -onoappledouble, the sweep is on regardless"
        );
        assert!(
            sweeps("-ouid=501 -ogid=20 -oatomic_o_trunc -oauto_xattr -oauto_cache -onoappledouble -odefault_permissions"),
            "and so do macFUSE's"
        );
        assert!(
            parse("-onoappledouble").adapter.no_apple_double,
            "the flag is still parsed"
        );

        let config = macos_ops_config(parse("-onoappledouble -ouid=7 -ogid=9"), true, 146, true);
        assert!(config.refuse_apple_double, "the back end asked for it");
        assert!(config.read_only);
        assert_eq!(config.max_name_length, 146);
        assert_eq!((config.options.uid, config.options.gid), (7, 9));
    }

    /// What reaches `fuse_mount_compat25`: the passthrough options, the volume name and `ro`.
    /// The adapter options must not be among them, the inert ones included.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_macos_mount_options_carry_ro_and_the_volume_name_but_no_adapter_options() {
        use crate::flags::parse_mount_flags;

        let flags = MountFlags::from_flags(
            &parse_mount_flags(
                "-ononamedattr -orwsize=262144 -ouid=501 -ogid=20 -oattr_timeout=5 -ovolname=e2e -onoappledouble -odefault_permissions -oallow_other -oallow_root",
            ),
            501,
            20,
        )
        .expect("flags parse");

        let rw = macos_mount_options(&flags, false);
        assert_eq!(rw, vec!["nonamedattr", "rwsize=262144", "volname=e2e"]);

        let ro = macos_mount_options(&flags, true);
        assert_eq!(
            ro,
            vec!["nonamedattr", "rwsize=262144", "volname=e2e", "ro"],
            "a read-only mount is asked for with `ro`, as Cryptomator's `-r` becomes"
        );

        // `-oro` in the flag string is the same request and must not produce a second `ro`.
        let from_flag = MountFlags::from_flags(&parse_mount_flags("-oro"), 0, 0).expect("parse");
        assert!(from_flag.read_only);
        assert_eq!(
            macos_mount_options(&from_flag, from_flag.read_only),
            vec!["ro"]
        );
    }

    /// A volume that is only settling becomes free within the retry window; one that is really in
    /// use is reported as busy once the window is over, and every other outcome is passed straight
    /// through.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_busy_unmount_is_retried_until_the_volume_is_free() {
        let attempts = std::cell::Cell::new(0);
        let settles_on_the_third_try = || {
            attempts.set(attempts.get() + 1);
            if attempts.get() < 3 {
                Err(UnmountError::Busy)
            } else {
                Ok(())
            }
        };
        assert!(retry_while_busy(Duration::from_secs(5), settles_on_the_third_try).is_ok());
        assert_eq!(
            attempts.get(),
            3,
            "it kept trying until the volume was free"
        );

        // A window of zero still allows one attempt, and its `Busy` is the answer.
        let tries = std::cell::Cell::new(0);
        let always_busy = || {
            tries.set(tries.get() + 1);
            Err(UnmountError::Busy)
        };
        assert!(matches!(
            retry_while_busy(Duration::ZERO, always_busy),
            Err(UnmountError::Busy)
        ));
        assert_eq!(tries.get(), 1);

        // Anything but `Busy` ends it at once, success included.
        let calls = std::cell::Cell::new(0);
        let fails = || {
            calls.set(calls.get() + 1);
            Err(UnmountError::Failed("permission denied".to_owned()))
        };
        assert!(matches!(
            retry_while_busy(Duration::from_secs(5), fails),
            Err(UnmountError::Failed(_))
        ));
        assert_eq!(calls.get(), 1, "a real failure is not retried");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn unmounting_a_directory_that_is_not_mounted_is_success() {
        let dir = tempfile::tempdir().expect("temp dir");
        umount_macos(dir.path(), false).expect("umount of an unmounted directory");
        umount_macos(dir.path(), true).expect("forced umount of an unmounted directory");
    }
}
