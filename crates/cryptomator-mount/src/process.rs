//! Running short-lived helper programs with a deadline.
//!
//! Both mount families shell out: FUSE to `umount`/`fusermount3`, WebDAV to `osascript`, `gio`
//! and `diskutil`. [`std::process::Child`] has no timeout of its own, so everything that waits
//! for one of them goes through here -- a helper that hangs (an unmount of a volume whose server
//! is gone can, for minutes) must not hang the daemon with it.
//!
//! The module is deliberately free of both features: `fuse` and `webdav` use it alike. Its items
//! are `pub` rather than `pub(crate)` for the same reason -- a build with neither feature calls
//! none of them, and a crate-private helper nobody calls is a `dead_code` warning.
use crate::api::{MountError, UnmountError};
use std::io::Read;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// How long an unmount command may take before it is killed and reported as failed. The FUSE
/// session handle waits the same ten seconds for the event loop, so a graceful unmount is bounded
/// by twice this; Java allows `diskutil` and `gio mount -u` exactly as much.
pub const UNMOUNT_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

/// How often a waiting parent looks whether the child has exited. Short enough to be invisible
/// next to spawning a process, long enough not to spin a core.
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// What a finished command left behind.
#[derive(Debug, Clone)]
pub struct CommandOutput {
    /// The exit status.
    pub status: ExitStatus,
    /// Standard output, lossily decoded.
    pub stdout: String,
    /// Standard error, lossily decoded.
    pub stderr: String,
}

impl CommandOutput {
    /// Whether the command exited with `0`.
    pub fn success(&self) -> bool {
        self.status.success()
    }
}

/// Runs `command`, waits at most `timeout` and collects both output streams.
///
/// Both pipes are read *after* the process ended, which is only safe for a command whose output
/// fits in the pipe buffer -- every caller here prints one line (`mount | grep`, `gio mount`).
/// A command that fills the buffer blocks, misses the deadline and is killed, which is the same
/// outcome as any other hang.
///
/// # Errors
/// [`MountError::Io`] if the command cannot be spawned and [`MountError::Failed`] if it does not
/// finish within `timeout`.
pub fn run_command(mut command: Command, timeout: Duration) -> Result<CommandOutput, MountError> {
    let description = describe(&command);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn()?;
    let Some(status) = wait_for_exit(&mut child, timeout)? else {
        let _ = child.kill();
        reap(child);
        return Err(MountError::Failed(format!(
            "{description} did not finish within {} s",
            timeout.as_secs()
        )));
    };
    Ok(CommandOutput {
        status,
        stdout: read_pipe(child.stdout.take()),
        stderr: read_pipe(child.stderr.take()),
    })
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
pub fn run_unmount_command(mut command: Command, tolerated: &[&str]) -> Result<(), UnmountError> {
    let description = describe(&command);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = command.spawn()?;
    let Some(status) = wait_for_exit(&mut child, UNMOUNT_COMMAND_TIMEOUT)? else {
        let _ = child.kill();
        reap(child);
        return Err(UnmountError::Failed(format!(
            "{description} did not finish within {} s",
            UNMOUNT_COMMAND_TIMEOUT.as_secs()
        )));
    };
    let stderr = read_pipe(child.stderr.take());
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

/// Whether `program args…` exits successfully within `timeout`; used to probe for a helper binary
/// (`fusermount3 -V`, `osascript -e 'return 1'`, `gio --version`). A program that cannot be
/// spawned, fails or hangs is reported as absent.
pub fn probe_command(program: &str, args: &[&str], timeout: Duration) -> bool {
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

/// Waits for `child`, giving up after `timeout` (`Ok(None)`). [`std::process::Child`] has no
/// deadline of its own, so this polls -- the alternative would be a helper thread per call.
///
/// # Errors
/// Whatever [`Child::try_wait`] reports.
pub fn wait_for_exit(child: &mut Child, timeout: Duration) -> std::io::Result<Option<ExitStatus>> {
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

/// Collects a killed child, without waiting for it here.
///
/// `SIGKILL` does not reach a process that is stuck in the kernel, and `umount` can be: an NFS
/// volume whose server has gone away leaves it in an uninterruptible wait, sometimes for minutes.
/// Waiting for it on this thread would hand exactly that delay to the caller -- the daemon
/// shutting down, or a test cleaning up -- so a throw-away thread does the waiting instead. It
/// holds nothing but the child, ends when the kernel lets go, and keeps the process table clean.
/// If even the thread cannot be spawned, the child is dropped and left as a zombie: this process
/// is on its way out anyway.
fn reap(child: Child) {
    let _ = thread::Builder::new()
        .name("crypto-unmount-reap".to_owned())
        .spawn(move || {
            let mut child = child;
            let _ = child.wait();
        });
}

/// One of the child's pipes, lossily decoded; a pipe that was never opened reads as empty.
///
/// An unmount helper writes one short line, well below the pipe buffer, so reading it after the
/// process ended cannot deadlock -- see [`run_command`] for the same caveat on `stdout`.
fn read_pipe(pipe: Option<impl Read>) -> String {
    let Some(mut pipe) = pipe else {
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

    /// [`run_command`] is the only helper that keeps the output: both streams, the exit status,
    /// and a missing program as [`MountError::Io`].
    #[test]
    fn run_command_collects_both_streams_and_the_status() {
        let mut command = Command::new("sh");
        command.args(["-c", "echo out; echo err >&2"]);
        let output = run_command(command, Duration::from_secs(5)).expect("sh runs");
        assert!(output.success(), "{output:?}");
        assert_eq!(output.stdout, "out\n");
        assert_eq!(output.stderr, "err\n");

        let mut command = Command::new("sh");
        command.args(["-c", "echo nope >&2; exit 3"]);
        let output = run_command(command, Duration::from_secs(5)).expect("sh runs");
        assert!(!output.success());
        assert_eq!(output.status.code(), Some(3));
        assert_eq!(output.stderr, "nope\n");
        assert!(output.stdout.is_empty());

        assert!(matches!(
            run_command(
                Command::new("crypto-no-such-helper"),
                Duration::from_secs(5)
            ),
            Err(MountError::Io(_))
        ));
    }

    /// A command that outlives its deadline is killed, and the caller is told which one it was.
    #[test]
    fn a_command_that_misses_its_deadline_is_killed_and_named() {
        let mut command = Command::new("sleep");
        command.arg("30");
        let err = run_command(command, Duration::from_millis(50)).expect_err("sleep 30 hangs");
        match err {
            MountError::Failed(message) => assert!(
                message.contains("sleep 30") && message.contains("did not finish"),
                "{message}"
            ),
            other => panic!("expected Failed, got {other:?}"),
        }
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
