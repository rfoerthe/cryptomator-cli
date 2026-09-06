//! The [`Mount`] every FUSE back end hands back, and the process helpers they take it down with.
//!
//! The back ends differ only in how the volume got into the namespace (a mounted fd from a
//! dynamically loaded libfuse, or fuser's own mount) and in the command that removes it again.
//! Once the session runs, they all look the same: a [`FuseSessionHandle`] plus the mount point
//! it serves.
use crate::api::{Mount, Mountpoint, UnmountError};
use crate::fuse::session::FuseSessionHandle;
use crate::mounttab::is_mountpoint;
use std::io::Read;
#[cfg(target_os = "macos")]
use std::path::Path;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// How long an unmount command may take before it is killed and reported as failed. The session
/// handle waits the same ten seconds for the event loop, so a graceful unmount is bounded by
/// twice this.
pub const UNMOUNT_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

/// How often a waiting parent looks whether the child has exited. Short enough to be invisible
/// next to spawning a process, long enough not to spin a core.
const POLL_INTERVAL: Duration = Duration::from_millis(20);

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

    fn close(self: Box<Self>) -> Result<(), UnmountError> {
        let mut this = *self;
        // Only unmount what is still mounted: `close` also runs after a successful `unmount`, and
        // after someone typed `umount` in a shell.
        if is_mountpoint(&this.mountpoint) {
            this.session.unmount(false)?;
        }
        this.session.join()?;
        Ok(())
    }
}

/// Runs an unmount command and reports what it did.
///
/// `tolerated` holds lower-case fragments of stderr that mean "there was nothing to unmount"
/// (`umount` and `fusermount3` both fail in that case); they count as success, because the caller
/// wanted the mount gone and it is. Anything mentioning a busy file system becomes
/// [`UnmountError::Busy`] so the CLI can offer `--force`.
///
/// # Errors
/// [`UnmountError::Io`] if the command cannot be spawned, [`UnmountError::Busy`] if the volume is
/// in use, [`UnmountError::Failed`] with the command's stderr otherwise (including a timeout).
pub(crate) fn run_unmount_command(
    mut command: Command,
    tolerated: &[&str],
) -> Result<(), UnmountError> {
    let description = describe(&command);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = command.spawn()?;
    let Some(status) = wait_for_exit(&mut child, UNMOUNT_COMMAND_TIMEOUT)? else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(UnmountError::Failed(format!(
            "{description} did not finish within {} s",
            UNMOUNT_COMMAND_TIMEOUT.as_secs()
        )));
    };
    let stderr = read_stderr(&mut child);
    if status.success() {
        return Ok(());
    }
    let lowered = stderr.to_lowercase();
    if tolerated.iter().any(|fragment| lowered.contains(fragment)) {
        return Ok(());
    }
    if lowered.contains("busy") {
        return Err(UnmountError::Busy);
    }
    let detail = stderr.trim();
    Err(UnmountError::Failed(if detail.is_empty() {
        format!("{description} failed ({status})")
    } else {
        format!("{description} failed: {detail}")
    }))
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

/// Takes a macOS mount down: `umount -- <path>`, or `umount -f -- <path>` when forced.
///
/// Both FUSE-T (whose mount is an NFS mount) and macFUSE are unmounted this way, as Cryptomator
/// does it. A volume that is no longer mounted counts as success.
///
/// # Errors
/// See [`run_unmount_command`].
#[cfg(target_os = "macos")]
pub(crate) fn umount_macos(mountpoint: &Path, forced: bool) -> Result<(), UnmountError> {
    let mut command = Command::new("umount");
    if forced {
        command.arg("-f");
    }
    command.arg("--").arg(mountpoint);
    run_unmount_command(command, &["not currently mounted", "not mounted"])
}

/// Whether `program args…` exits successfully within `timeout`; used to probe for a helper binary
/// (`fusermount3 -V`). A program that cannot be spawned, fails or hangs is reported as absent.
pub(crate) fn probe_command(program: &str, args: &[&str], timeout: Duration) -> bool {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let Ok(mut child) = command.spawn() else {
        return false;
    };
    match wait_for_exit(&mut child, timeout) {
        Ok(Some(status)) => status.success(),
        _ => {
            let _ = child.kill();
            let _ = child.wait();
            false
        }
    }
}

/// Waits for `child`, giving up after `timeout` (`Ok(None)`). `std::process::Child` has no
/// deadline of its own, so this polls -- the alternative would be a helper thread per call.
fn wait_for_exit(child: &mut Child, timeout: Duration) -> std::io::Result<Option<ExitStatus>> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// The child's stderr, lossily decoded. An unmount helper writes one short line, well below the
/// pipe buffer, so reading it after the process ended cannot deadlock.
fn read_stderr(child: &mut Child) -> String {
    let Some(mut pipe) = child.stderr.take() else {
        return String::new();
    };
    let mut buffer = Vec::new();
    let _ = pipe.read_to_end(&mut buffer);
    String::from_utf8_lossy(&buffer).into_owned()
}

/// `program arg…` for error messages.
fn describe(command: &Command) -> String {
    let mut parts = vec![command.get_program().to_string_lossy().into_owned()];
    parts.extend(command.get_args().map(|a| a.to_string_lossy().into_owned()));
    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_successful_command_is_ok() {
        let mut command = Command::new("true");
        command.arg("--unused");
        assert!(run_unmount_command(command, &[]).is_ok());
    }

    #[test]
    fn a_tolerated_stderr_message_counts_as_success() {
        let mut command = Command::new("sh");
        command.args(["-c", "echo 'umount: /x: not currently mounted' >&2; exit 1"]);
        assert!(run_unmount_command(command, &["not currently mounted"]).is_ok());
    }

    #[test]
    fn a_busy_volume_is_reported_as_busy_and_other_failures_carry_the_stderr() {
        let mut command = Command::new("sh");
        command.args(["-c", "echo 'umount: /x: Resource busy' >&2; exit 1"]);
        assert!(matches!(
            run_unmount_command(command, &["not currently mounted"]),
            Err(UnmountError::Busy)
        ));

        let mut command = Command::new("sh");
        command.args(["-c", "echo 'umount: /x: permission denied' >&2; exit 1"]);
        let err = run_unmount_command(command, &[]).expect_err("the command failed");
        match err {
            UnmountError::Failed(message) => assert!(
                message.contains("permission denied") && message.contains("sh"),
                "{message}"
            ),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn a_missing_program_surfaces_as_io_error() {
        let command = Command::new("crypto-no-such-unmount-helper");
        assert!(matches!(
            run_unmount_command(command, &[]),
            Err(UnmountError::Io(_))
        ));
    }

    #[test]
    fn probe_command_answers_for_present_absent_and_failing_programs() {
        assert!(probe_command("true", &[], Duration::from_secs(2)));
        assert!(!probe_command("false", &[], Duration::from_secs(2)));
        assert!(!probe_command(
            "crypto-no-such-helper",
            &["-V"],
            Duration::from_secs(2)
        ));
    }

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

    #[cfg(target_os = "macos")]
    #[test]
    fn unmounting_a_directory_that_is_not_mounted_is_success() {
        let dir = tempfile::tempdir().expect("temp dir");
        umount_macos(dir.path(), false).expect("umount of an unmounted directory");
        umount_macos(dir.path(), true).expect("forced umount of an unmounted directory");
    }

    #[test]
    fn a_hanging_command_is_killed_and_reported() {
        let mut command = Command::new("sleep");
        command.arg("30");
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("spawn sleep");
        assert!(wait_for_exit(&mut child, Duration::from_millis(50))
            .expect("wait")
            .is_none());
        child.kill().expect("kill sleep");
        child.wait().expect("reap sleep");
        assert!(!probe_command("sleep", &["30"], Duration::from_millis(50)));
    }
}
