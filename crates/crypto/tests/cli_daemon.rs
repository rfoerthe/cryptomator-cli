//! `crypto unlock` / `crypto lock` and the daemon behind them, driven through the null mounter.
//!
//! Every test here starts a real detached `crypto __daemon` process. Two rules keep that from
//! leaking out of the test run: the sandbox locks everything it unlocked when it is dropped, and
//! no wait is unbounded -- each one polls against a 10 second deadline instead of sleeping.
mod common;

use common::Sandbox;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

/// The longest any of these tests waits for the daemon to do something.
const DEADLINE: Duration = Duration::from_secs(10);
/// How often it looks while waiting.
const POLL: Duration = Duration::from_millis(20);
/// The class name of the mounter that mounts nothing.
const NULL_MOUNTER: &str = "org.cryptomator.cli.NullMountProvider";
/// The file a null mount leaves behind in its mount point.
const MARKER: &str = ".crypto-null-mount";

/// A sandbox with one created vault, whose daemons are stopped when the test ends -- also when it
/// panics half way through, so a failed assertion never leaves a mounted volume behind.
struct Fixture {
    sandbox: Sandbox,
    name: &'static str,
}

impl Fixture {
    fn new(name: &'static str) -> Self {
        let sandbox = Sandbox::new();
        sandbox.write_cli_config();
        sandbox
            .crypto(&["vault", "create", sandbox.path(name).to_str().unwrap()])
            .assert()
            .success();
        Self { sandbox, name }
    }

    fn id(&self) -> String {
        self.sandbox.vault_id(0)
    }
}

impl std::ops::Deref for Fixture {
    type Target = Sandbox;
    fn deref(&self) -> &Sandbox {
        &self.sandbox
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self
            .sandbox
            .crypto_daemon(&["lock", "--all", "--force"])
            .ok();
    }
}

fn json(out: &[u8]) -> Value {
    serde_json::from_slice(out).unwrap()
}

/// Polls `condition` until it holds, and fails the test if it does not within [`DEADLINE`].
fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + DEADLINE;
    while Instant::now() < deadline {
        if condition() {
            return;
        }
        std::thread::sleep(POLL);
    }
    panic!("timed out after {DEADLINE:?} waiting for {what}");
}

/// Whether a process still exists, asked the way a shell would.
fn alive(pid: u64) -> bool {
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Unlocks the fixture's vault with the null mounter and returns the JSON result.
fn unlock(fixture: &Fixture) -> Value {
    let out = fixture
        .crypto_daemon(&["--json", "unlock", fixture.name, "--mounter", "null"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    json(&out)
}

fn mountpoint_of(result: &Value) -> PathBuf {
    PathBuf::from(result["mountpoint"].as_str().unwrap())
}

#[test]
fn unlock_mounts_the_vault_and_lock_takes_it_down() {
    let fx = Fixture::new("v");
    let id = fx.id();
    let result = unlock(&fx);

    assert_eq!(result["id"], id);
    assert_eq!(result["mounter"], NULL_MOUNTER);
    let pid = result["pid"].as_u64().expect("the daemon's pid");
    assert!(pid > 1);
    let mountpoint = mountpoint_of(&result);
    assert_eq!(mountpoint, fx.mount_points_dir().join("v"));
    assert!(mountpoint.join(MARKER).is_file(), "the null mount's marker");

    // What `crypto status` will read: the run info and the control socket of a live daemon.
    let info = json(&std::fs::read(fx.state_file(".json")).unwrap());
    assert_eq!(info["vaultId"], id);
    assert_eq!(info["mounter"], NULL_MOUNTER);
    assert_eq!(info["mountpoint"], result["mountpoint"]);
    assert_eq!(info["pid"], pid);
    assert_eq!(info["readOnly"], false);
    assert!(fx.state_file(".sock").exists());
    assert!(alive(pid));

    // An unlocked vault belongs to its daemon: no second unlock, and no mount-less access either.
    // `unlock` and `fs` now share one WrongState wording (`VaultRegistry::require_locked`).
    fx.crypto_daemon(&["unlock", "v", "--mounter", "null"])
        .assert()
        .code(5)
        .stderr(predicates::str::contains("UNLOCKED (mounted at"));
    fx.crypto_daemon(&["fs", "ls", "v"]).assert().code(5);
    fx.crypto_daemon(&["fs", "mkdir", "v", "/x"])
        .assert()
        .code(5);

    fx.crypto_daemon(&["lock", "v"])
        .assert()
        .success()
        .stdout("Locked v\n");
    assert!(!mountpoint.join(MARKER).exists(), "the marker is removed");
    wait_until("the daemon to clean up its state files", || {
        !fx.state_file(".sock").exists() && !fx.state_file(".json").exists()
    });
    wait_until("the daemon to exit", || !alive(pid));

    // Locked again: `fs` works, and there is nothing left to lock.
    fx.crypto_daemon(&["fs", "ls", "v"]).assert().success();
    fx.crypto_daemon(&["lock", "v"]).assert().code(5);
}

#[test]
fn a_busy_volume_needs_lock_force() {
    let fx = Fixture::new("b");
    fx.crypto_daemon(&["unlock", "b", "--mounter", "null"])
        .env("CRYPTO_NULL_MOUNT_BUSY", "1")
        .assert()
        .success();
    let mountpoint = fx.mount_points_dir().join("b");
    assert!(mountpoint.join(MARKER).is_file());

    fx.crypto_daemon(&["lock", "b"]).assert().code(7);
    assert!(
        mountpoint.join(MARKER).is_file(),
        "a refused unmount leaves the volume alone"
    );
    // The daemon survived the failed lock and is still serving.
    fx.crypto_daemon(&["unlock", "b", "--mounter", "null"])
        .assert()
        .code(5);

    fx.crypto_daemon(&["lock", "b", "--force"])
        .assert()
        .success();
    assert!(!mountpoint.join(MARKER).exists());
}

#[test]
fn a_foreground_unlock_serves_until_it_is_locked() {
    let fx = Fixture::new("f");
    let mut child: Child = fx
        .crypto_daemon_cmd(&["unlock", "f", "--mounter", "null", "--foreground"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_until("the foreground daemon to mount", || {
        fx.state_file(".json").exists()
    });
    assert!(fx.mount_points_dir().join("f").join(MARKER).is_file());

    fx.crypto_daemon(&["lock", "f"]).assert().success();
    let status = wait_for_exit(&mut child);
    assert_eq!(status.code(), Some(0), "the foreground unlock ends cleanly");
    assert!(!fx.mount_points_dir().join("f").join(MARKER).exists());
}

/// Waits [`DEADLINE`] for `child` to exit and kills it rather than leaving it behind.
fn wait_for_exit(child: &mut Child) -> std::process::ExitStatus {
    let deadline = Instant::now() + DEADLINE;
    while Instant::now() < deadline {
        if let Ok(Some(status)) = child.try_wait() {
            return status;
        }
        std::thread::sleep(POLL);
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("the child did not end within {DEADLINE:?}");
}

#[test]
fn a_killed_daemon_leaves_a_vault_the_registry_heals() {
    let fx = Fixture::new("k");
    let result = unlock(&fx);
    let pid = result["pid"].as_u64().unwrap();
    let mountpoint = mountpoint_of(&result);

    std::process::Command::new("kill")
        .args(["-9", &pid.to_string()])
        .status()
        .unwrap();
    wait_until("the killed daemon to disappear", || !alive(pid));
    // The state files outlive the process; nothing unmounted the volume either.
    assert!(fx.state_file(".pid").exists());
    assert!(mountpoint.join(MARKER).is_file());

    // Nothing is really mounted, so the mount point is not in the mount table and the registry
    // treats the files as leftovers: the vault is LOCKED again and `fs` works.
    fx.crypto_daemon(&["fs", "ls", "k"]).assert().success();
    assert!(!fx.state_file(".pid").exists(), "leftovers are removed");
    assert!(!fx.state_file(".sock").exists());
    assert!(!fx.state_file(".json").exists());
    fx.crypto_daemon(&["lock", "k"]).assert().code(5);
    // And it can be unlocked again.
    let again = unlock(&fx);
    assert_eq!(mountpoint_of(&again), mountpoint);
}

#[test]
fn a_failed_unlock_starts_no_daemon() {
    let fx = Fixture::new("e");
    fx.crypto_daemon(&["unlock", "e", "--mounter", "null"])
        .env("CRYPTO_PASSWORD", "not-the-password-at-all")
        .assert()
        .code(4);
    assert!(!fx.state_file(".sock").exists());
    assert!(!fx.state_file(".pid").exists());
    assert!(!fx.mount_points_dir().join("e").exists());

    fx.crypto_daemon(&["unlock", "nope", "--mounter", "null"])
        .assert()
        .code(3);
    fx.crypto_daemon(&["unlock", "e", "--mounter", "bogus"])
        .assert()
        .code(2)
        .stderr(predicates::str::contains("unknown mounter"));
    // Naming nothing to lock is a usage error, and locking a locked vault is a state error.
    fx.crypto_daemon(&["lock"]).assert().code(2);
    fx.crypto_daemon(&["lock", "e"]).assert().code(5);
    fx.crypto_daemon(&["--json", "lock", "--all"])
        .assert()
        .success()
        .stdout(predicates::str::contains("\"locked\": []"));
}

#[test]
fn lock_all_locks_every_unlocked_vault() {
    let fx = Fixture::new("a1");
    fx.crypto(&["vault", "create", fx.path("a2").to_str().unwrap()])
        .assert()
        .success();
    fx.crypto_daemon(&["unlock", "a1", "--mounter", "null"])
        .assert()
        .success();
    fx.crypto_daemon(&["unlock", "a2", "--mounter", "null"])
        .assert()
        .success();

    let out = fx
        .crypto_daemon(&["--json", "lock", "--all"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let locked = json(&out);
    let ids: Vec<&str> = locked["locked"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(ids.len(), 2, "both vaults were locked: {locked}");
    assert!(locked.get("failed").is_none());
    for name in ["a1", "a2"] {
        assert!(!fx.mount_points_dir().join(name).join(MARKER).exists());
    }
    assert!(!Path::new(&fx.state_file(".sock")).exists());
}

#[test]
fn relative_settings_and_state_dir_still_reach_the_detached_daemon() {
    // Regression for a daemon spawned with `current_dir("/")`: a relative `--settings`/
    // `--state-dir` used to be handed to the child verbatim, so it tried to create its state
    // files under `/` and the parent timed out waiting for a socket that never appeared.
    let fx = Fixture::new("v");
    let id = fx.id();
    let out = fx
        .crypto_daemon_relative(&["--json", "unlock", "v", "--mounter", "null"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let result = json(&out);
    assert_eq!(result["id"], id);
    let mountpoint = mountpoint_of(&result);
    assert!(mountpoint.is_absolute());
    assert!(mountpoint.join(MARKER).is_file(), "the null mount's marker");

    fx.crypto_daemon_relative(&["lock", "v"])
        .assert()
        .success()
        .stdout("Locked v\n");
}

#[test]
fn a_relative_mount_point_resolves_against_the_shells_cwd() {
    let fx = Fixture::new("v");
    std::fs::create_dir_all(fx.path("rel/mp")).unwrap();
    let out = fx
        .crypto_daemon_relative(&[
            "--json",
            "unlock",
            "v",
            "--mounter",
            "null",
            "--mount-point",
            "rel/mp",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let result = json(&out);
    let mountpoint = mountpoint_of(&result);
    assert!(mountpoint.is_absolute());
    // `canonicalize`, not a plain string comparison: on macOS the sandbox's tmp dir is under
    // `/var`, a symlink to `/private/var`, and `std::path::absolute` (used by the fix) goes
    // through `std::env::current_dir()`, which resolves it -- so the two sides name the same
    // directory without being byte-identical.
    assert_eq!(
        mountpoint.canonicalize().unwrap(),
        fx.path("rel/mp").canonicalize().unwrap(),
        "resolved against the shell's cwd, not the daemon's `/`"
    );
    assert!(mountpoint.join(MARKER).is_file());

    fx.crypto_daemon_relative(&["lock", "v"]).assert().success();
}

#[test]
fn an_empty_crypto_state_dir_env_var_is_ignored() {
    let fx = Fixture::new("v");
    // No `--state-dir` on the command line: `StateDir::from_env_or_default` reads the variable
    // itself and, unlike clap's own `env` handling, treats an empty value as unset.
    fx.crypto(&["vault", "list"])
        .env("HOME", fx.root())
        .env("CRYPTO_STATE_DIR", "")
        .assert()
        .success();
}

#[test]
fn locking_the_same_vault_twice_dedupes() {
    let fx = Fixture::new("v");
    let id = fx.id();
    fx.crypto_daemon(&["unlock", "v", "--mounter", "null"])
        .assert()
        .success();

    let out = fx
        .crypto_daemon(&["--json", "lock", "v", "v"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let result = json(&out);
    assert!(result.get("failed").is_none(), "{result}");
    let locked: Vec<&str> = result["locked"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(
        locked,
        vec![id.as_str()],
        "the vault is locked exactly once"
    );
}

#[test]
fn unlock_grammar_applies_volume_name_read_only_and_mount_options() {
    let fx = Fixture::new("v");
    let out = fx
        .crypto_daemon(&[
            "unlock",
            "v",
            "--mounter",
            "null",
            "--volume-name",
            "Foo",
            "--read-only",
            "--mount-option=-onoappledouble",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let result = json(&out);
    let mountpoint = mountpoint_of(&result);
    assert_eq!(
        std::fs::read_to_string(mountpoint.join(MARKER)).unwrap(),
        "Foo",
        "the null mount's marker records --volume-name"
    );

    let info = json(&std::fs::read(fx.state_file(".json")).unwrap());
    assert_eq!(info["readOnly"], true);
}

#[test]
fn a_space_separated_mount_option_is_a_usage_error() {
    let fx = Fixture::new("v");
    // `require_equals` on `--mount-option` rejects the space-separated form so it cannot swallow
    // whatever token follows it.
    fx.crypto_daemon(&["unlock", "v", "--mounter", "null", "--mount-option", "-oro"])
        .assert()
        .code(2);
}

#[test]
fn lock_all_with_nothing_unlocked_prints_nothing_to_lock() {
    let fx = Fixture::new("v");
    fx.crypto_daemon(&["lock", "--all"])
        .assert()
        .success()
        .stdout("nothing to lock\n");
}

#[test]
fn a_mount_that_fails_reports_the_daemon_log() {
    let fx = Fixture::new("m");
    // Without `CRYPTO_ENABLE_NULL_MOUNTER` the null mounter is not supported, so the daemon has no
    // service to mount with and stops again. Its log is the only place the reason is written down,
    // which is why a failed unlock prints the tail of it.
    fx.crypto_daemon(&["unlock", "m", "--mounter", "null"])
        .env_remove("CRYPTO_ENABLE_NULL_MOUNTER")
        .assert()
        .code(6)
        .stderr(predicates::str::contains("unlock failed"));
    wait_until("the failed daemon to clean up after itself", || {
        !fx.state_file(".sock").exists() && !fx.state_file(".pid").exists()
    });
    assert!(!fx.mount_points_dir().join("m").exists());
    // The log survives the state files, so the failure can still be looked at.
    assert!(fx.state_file(".log").is_file());
}

/// Reads the first line of `stream` in a thread, so a test can give up instead of blocking on a
/// child that never says anything.
/// The stream comes back with the line, still open: whoever wants the child to see a closed pipe
/// drops it, and whoever does not keeps it alive.
fn first_line<R: std::io::Read + Send + 'static>(stream: R) -> (String, R) {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut reader = std::io::BufReader::new(stream);
        let mut line = String::new();
        let _ = std::io::BufRead::read_line(&mut reader, &mut line);
        let _ = tx.send((line, reader.into_inner()));
    });
    rx.recv_timeout(DEADLINE)
        .expect("the child says something within the deadline")
}

/// Runs `args` in the sandbox, requires exit code 0 and parses the `--json` output.
fn json_out(fx: &Fixture, args: &[&str]) -> Value {
    let out = fx
        .crypto_daemon(args)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    json(&out)
}

/// Ctrl-C, the way a shell sends it.
fn interrupt(pid: u32) {
    std::process::Command::new("kill")
        .args(["-INT", &pid.to_string()])
        .status()
        .unwrap();
}

#[test]
fn status_stats_and_events_follow_a_vault_through_unlock_and_lock() {
    let fx = Fixture::new("v");
    let id = fx.id();

    // Locked: `status` reads the registry only, so it works without any daemon.
    let before = json_out(&fx, &["--json", "status"]);
    let rows = before.as_array().expect("an array of vaults");
    assert_eq!(rows.len(), 1, "{before}");
    assert_eq!(rows[0]["id"], id);
    assert_eq!(rows[0]["state"], "LOCKED");
    assert!(rows[0]["mountpoint"].is_null());
    // With a vault argument it is that vault's object, not an array.
    let one = json_out(&fx, &["--json", "status", "v"]);
    assert_eq!(one["id"], id);
    assert_eq!(one["state"], "LOCKED");
    fx.crypto_daemon(&["status", "nope"]).assert().code(3);
    // A locked vault has no daemon to ask.
    fx.crypto_daemon(&["stats", "v"]).assert().code(5);
    fx.crypto_daemon(&["events", "v"]).assert().code(5);

    let result = unlock(&fx);
    let mountpoint = mountpoint_of(&result);

    let after = json_out(&fx, &["--json", "status", "v"]);
    assert_eq!(after["state"], "UNLOCKED");
    assert_eq!(after["mountpoint"], result["mountpoint"]);
    assert_eq!(after["mounter"], NULL_MOUNTER);
    assert_eq!(after["displayName"], "v");
    fx.crypto_daemon(&["status"])
        .assert()
        .success()
        .stdout(predicates::str::contains("MOUNTPOINT"))
        .stdout(predicates::str::contains("UNLOCKED"))
        .stdout(predicates::str::contains(mountpoint.to_str().unwrap()));

    // `stats` needs the daemon; every documented field is there.
    let stats = json_out(&fx, &["--json", "stats", "v"]);
    for field in [
        "bytesPerSecondRead",
        "bytesPerSecondWritten",
        "bytesPerSecondEncrypted",
        "bytesPerSecondDecrypted",
        "cacheHitRate",
        "totalBytesRead",
        "totalBytesWritten",
        "totalBytesEncrypted",
        "totalBytesDecrypted",
        "filesRead",
        "filesWritten",
        "totalFilesAccessed",
        "lastActivity",
    ] {
        assert!(stats.get(field).is_some(), "{field} missing in {stats}");
    }
    fx.crypto_daemon(&["stats", "v"])
        .assert()
        .success()
        .stdout(predicates::str::contains("read "))
        .stdout(predicates::str::contains("cache "))
        .stdout(predicates::str::contains("files "));

    // Nothing has gone wrong inside the vault, so the event log is empty.
    let events = json_out(&fx, &["--json", "events", "v"]);
    assert_eq!(events, serde_json::json!([]), "{events}");
    fx.crypto_daemon(&["events", "v"]).assert().success();

    fx.crypto_daemon(&["lock", "v"]).assert().success();
    let locked = json_out(&fx, &["--json", "status"]);
    assert_eq!(locked[0]["state"], "LOCKED");
    assert!(locked[0]["mountpoint"].is_null());
    fx.crypto_daemon(&["stats", "v"]).assert().code(5);
}

#[test]
fn stats_and_events_follow_until_they_are_interrupted() {
    let fx = Fixture::new("w");
    unlock(&fx);

    // `stats --follow` samples right away, so its first line proves the follow loop prints what
    // it promises; an idle `events --follow` has nothing to report and only its notice is checked.
    for (args, samples) in [
        (
            vec!["--json", "stats", "w", "--follow", "--interval", "1"],
            true,
        ),
        (vec!["--json", "events", "w", "--follow"], false),
    ] {
        let mut child = fx
            .crypto_daemon_cmd(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // The notice is printed *after* the SIGINT handler is installed, so seeing it means the
        // interrupt below cannot arrive too early and kill the child instead.
        let (notice, _stderr) = first_line(child.stderr.take().unwrap());
        assert!(notice.contains("Ctrl-C"), "{args:?}: {notice}");
        // The pipe is held open the whole time, so the child stops because of the signal and not
        // because its reader went away.
        let mut stdout = child.stdout.take().unwrap();
        if samples {
            let (line, rest) = first_line(stdout);
            stdout = rest;
            let sample: Value = serde_json::from_str(line.trim())
                .unwrap_or_else(|err| panic!("{args:?}: {line:?} is not one NDJSON object: {err}"));
            assert!(
                sample.get("bytesPerSecondRead").is_some(),
                "{args:?}: {sample}"
            );
        }
        interrupt(child.id());
        let status = wait_for_exit(&mut child);
        assert_eq!(status.code(), Some(0), "{args:?} ends cleanly on Ctrl-C");
        drop(stdout);
    }
}

#[test]
fn a_follow_stream_ends_with_code_0_when_its_reader_closes_the_pipe() {
    let fx = Fixture::new("h");
    unlock(&fx);

    // What `crypto stats h --follow --json | head -1` does: read one line, then close the pipe.
    // `events --follow` takes the same path, but an idle vault gives it nothing to write.
    let mut child = fx
        .crypto_daemon_cmd(&["--json", "stats", "h", "--follow", "--interval", "1"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let (notice, _stderr) = first_line(child.stderr.take().unwrap());
    assert!(notice.contains("Ctrl-C"), "{notice}");
    let (line, stdout) = first_line(child.stdout.take().unwrap());
    json(line.trim().as_bytes());
    drop(stdout);

    // The next sample hits the closed pipe: that is a normal end (0), not a panic (101).
    let status = wait_for_exit(&mut child);
    assert_eq!(
        status.code(),
        Some(0),
        "a closed stdout ends the follow loop cleanly"
    );
}

#[test]
fn the_mount_points_dir_from_cli_json_decides_where_a_vault_is_mounted() {
    let fx = Fixture::new("m");
    let elsewhere = fx.path("elsewhere");
    fx.crypto_daemon(&["config", "set", "mountPointsDir"])
        .arg(&elsewhere)
        .assert()
        .success();
    let result = unlock(&fx);
    assert_eq!(mountpoint_of(&result), elsewhere.join("m"));
    assert!(elsewhere.join("m").join(MARKER).is_file());
}
