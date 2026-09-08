//! `crypto unlock` / `crypto lock` and the daemon behind them, driven through the null mounter.
//!
//! Every test here starts a real detached `crypto __daemon` process. Two rules keep that from
//! leaking out of the test run: the sandbox locks everything it unlocked when it is dropped, and
//! no wait is unbounded -- each one polls against a 10 second deadline instead of sleeping.
mod common;

use common::Sandbox;
use cryptomator_mount::mounttab::is_mountpoint;
use serde_json::Value;
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
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
/// What the WebDAV tests write through the server and read back out of the locked vault.
const PUT_BODY: &str = "hello webdav";

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
        // The graceful one first: the WebDAV back ends have no `UNMOUNT_FORCED`, so `--force`
        // alone would be refused for them and leave the daemon running.
        if self.sandbox.crypto_daemon(&["lock", "--all"]).ok().is_err() {
            let _ = self
                .sandbox
                .crypto_daemon(&["lock", "--all", "--force"])
                .ok();
        }
    }
}

fn json(out: &[u8]) -> Value {
    serde_json::from_slice(out).unwrap()
}

/// Polls `condition` until it holds, and fails the test if it does not within [`DEADLINE`].
fn wait_until(what: &str, condition: impl FnMut() -> bool) {
    wait_for(DEADLINE, what, condition);
}

/// [`wait_until`] with an explicit limit, for a wait whose own duration is part of the assertion.
fn wait_for(limit: Duration, what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if condition() {
            return;
        }
        std::thread::sleep(POLL);
    }
    panic!("timed out after {limit:?} waiting for {what}");
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

    // The detached daemon -- the normal case, unlike `--foreground` -- writes the same log file,
    // and it stays behind after the lock so a mount that failed can still be read up on.
    let log = std::fs::read_to_string(fx.state_file(".log")).expect("the detached daemon log");
    assert!(
        log.contains("INFO"),
        "the daemon installed its logger: {log:?}"
    );
    assert!(
        log.contains("mounted at"),
        "the mount is in the log: {log:?}"
    );
    assert!(log.contains("stopped"), "and so is the shutdown: {log:?}");
    assert!(
        !log.contains(common::PW),
        "no passphrase ever reaches the log"
    );
}

/// Rewriting the masterkey of a vault a daemon is serving would leave that daemon holding a key
/// that no longer opens the vault, so the commands that touch it refuse the same way `fs` does.
#[test]
fn password_and_recovery_key_refuse_a_vault_a_daemon_is_serving() {
    let fixture = Fixture::new("pv");
    unlock(&fixture);
    for args in [
        vec!["password", "change", "pv"],
        vec!["recovery-key", "show", "pv"],
        // The recovery-key source is a required argument group, so it has to be there for the
        // command to reach the state check at all; nothing ever reads that empty stdin.
        vec![
            "recovery-key",
            "reset-password",
            "pv",
            "--recovery-key-stdin",
        ],
    ] {
        let assertion = fixture.crypto_daemon(&args).assert().code(5);
        let stderr = String::from_utf8_lossy(&assertion.get_output().stderr).into_owned();
        assert!(
            stderr.contains("UNLOCKED"),
            "{args:?} says what is wrong: {stderr}"
        );
    }
    fixture
        .crypto_daemon(&["lock", fixture.name])
        .assert()
        .success();
    // `lock` returns as soon as the daemon has unmounted, which is before that daemon has removed
    // its state files -- and until they are gone the registry still calls the vault UNLOCKED, so
    // the commands below would race it into the very exit code 5 they were just asserted to give.
    wait_until("the daemon to clean up its state files", || {
        !fixture.state_file(".sock").exists() && !fixture.state_file(".json").exists()
    });

    // Once it is locked again, every one of them works. The new password is the one the sandbox
    // already uses, so each command leaves the vault openable for the next.
    let key = fixture
        .crypto_daemon(&["recovery-key", "show", "pv"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    fixture
        .crypto_daemon(&[
            "recovery-key",
            "reset-password",
            "pv",
            "--recovery-key-stdin",
            "--new-password-env",
            "NEWPW",
        ])
        .env("NEWPW", common::PW)
        .write_stdin(key)
        .assert()
        .success();
    fixture
        .crypto_daemon(&["password", "change", "pv", "--new-password-env", "NEWPW"])
        .env("NEWPW", common::PW)
        .assert()
        .success();
}

/// `crypto health` opens the vault itself, so it needs the same exclusive access every other
/// mount-less command needs: a vault a daemon is serving is exit code 5, never a health report of
/// a vault that is being written underneath it.
#[test]
fn health_refuses_a_vault_a_daemon_is_serving() {
    let fixture = Fixture::new("hv");
    unlock(&fixture);
    let assertion = fixture
        .crypto_daemon(&["health", "hv", "--no-report"])
        .assert()
        .code(5);
    let stderr = String::from_utf8_lossy(&assertion.get_output().stderr).into_owned();
    assert!(
        stderr.contains("UNLOCKED"),
        "it says what is wrong: {stderr}"
    );

    fixture.crypto_daemon(&["lock", "hv"]).assert().success();
    wait_until("the daemon to clean up its state files", || {
        !fixture.state_file(".sock").exists() && !fixture.state_file(".json").exists()
    });
    // Locked again, the freshly created vault checks out clean -- and writes no report, because
    // `--no-report` said so.
    fixture
        .crypto_daemon(&["health", "hv", "--no-report"])
        .assert()
        .success()
        .stdout(predicates::str::contains("0 critical"));
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

    // `--foreground` runs the daemon inside the CLI process, which already has a logger installed
    // for its own warnings. The daemon's log file has to take that logger over -- a second
    // `set_boxed_logger` would be refused and this file would stay empty.
    let log = std::fs::read_to_string(fx.state_file(".log")).expect("the daemon log");
    assert!(
        log.contains("INFO") && log.contains("mounted at"),
        "the foreground daemon writes its own log file: {log:?}"
    );
    assert!(log.contains("stopped"), "including the shutdown: {log:?}");
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

/// One HTTP request written and read by hand: this test binary has no HTTP client, and a status
/// line needs none. `Connection: close` ends the response, so reading to the end terminates.
///
/// Byte-identical to `http` in `crates/cryptomator-app/src/daemon/server.rs`'s test module, and
/// deliberately so: the two live in different crates, and a `#[cfg(test)]` helper cannot be
/// shared across a crate boundary without turning it into a published API. Change one, change
/// the other.
fn http(addr: &str, request: &str) -> String {
    use std::io::{Read, Write};
    let mut stream = TcpStream::connect(addr).expect("connect to the WebDAV server");
    stream.set_read_timeout(Some(DEADLINE)).expect("timeout");
    stream.write_all(request.as_bytes()).expect("write");
    let mut response = Vec::new();
    // A timeout leaves whatever arrived, which the assertion then reports; it never hangs.
    let _ = stream.read_to_end(&mut response);
    String::from_utf8_lossy(&response).into_owned()
}

/// `host:port` of a `http://host:port/path` URL. The twin of `authority` in
/// `crates/cryptomator-app/src/daemon/server.rs`'s test module -- see the note on [`http`].
fn authority(url: &str) -> String {
    url.trim_start_matches("http://")
        .split('/')
        .next()
        .expect("an authority")
        .to_owned()
}

/// The whole WebDAV lifecycle through the CLI, with no operating-system mount anywhere: the
/// fallback mounter serves a URL, `status` reports it, the server answers real WebDAV, `--reveal`
/// opens nothing (a browser is not the vault) and `lock` gives the port back.
#[test]
fn a_webdav_unlock_serves_a_url_that_status_shows_and_lock_takes_down() {
    let fx = Fixture::new("w");
    let revealed = fx.path("revealed.txt");
    let script = fx.path("reveal.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$1\" >> \"{}\"\n",
            revealed.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

    let out = fx
        .crypto_daemon(&[
            "--json",
            "unlock",
            "w",
            "--mounter",
            "webdav",
            "--port",
            "0",
            "--reveal",
        ])
        .env("CRYPTO_REVEAL_CMD", &script)
        .assert()
        .success()
        // The hint how to mount the URL is on stderr, so `--json`'s document keeps its shape.
        .stderr(predicates::str::contains("Connect to Server"))
        .get_output()
        .stdout
        .clone();
    let result = json(&out);
    let url = result["mountpoint"].as_str().unwrap().to_owned();
    assert!(url.starts_with("http://127.0.0.1:"), "{url}");
    assert!(url.ends_with(&format!("/{}", fx.id())), "{url}");
    assert_eq!(
        result["mounter"],
        "org.cryptomator.frontend.webdav.mount.FallbackMounter"
    );

    // `crypto status` prints the URL in the MOUNTPOINT column, and `--json` carries it verbatim.
    let status = json_out(&fx, &["--json", "status", "w"]);
    assert_eq!(status["state"], "UNLOCKED");
    assert_eq!(status["mountpoint"], url);
    fx.crypto_daemon(&["status", "w"])
        .assert()
        .success()
        .stdout(predicates::str::contains(url.as_str()));

    // The server really serves the vault: a PROPFIND is answered, an OPTIONS advertises DAV.
    let addr = authority(&url);
    let path = format!("/{}", fx.id());
    let propfind = http(
        &addr,
        &format!(
            "PROPFIND {path} HTTP/1.1\r\nHost: {addr}\r\nDepth: 0\r\n\
             Content-Length: 0\r\nConnection: close\r\n\r\n"
        ),
    );
    assert!(propfind.starts_with("HTTP/1.1 207"), "{propfind}");
    let options = http(
        &addr,
        &format!("OPTIONS {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"),
    );
    assert!(options.starts_with("HTTP/1.1 2"), "{options}");
    assert!(options.to_lowercase().contains("dav:"), "{options}");
    // … and a write really lands in the vault: this is the whole point of serving it.
    let put = http(
        &addr,
        &format!(
            "PUT {path}/note.txt HTTP/1.1\r\nHost: {addr}\r\nContent-Type: text/plain\r\n\
             Content-Length: {len}\r\nConnection: close\r\n\r\n{PUT_BODY}",
            len = PUT_BODY.len()
        ),
    );
    assert!(
        put.starts_with("HTTP/1.1 201") || put.starts_with("HTTP/1.1 204"),
        "{put}"
    );

    assert!(
        !revealed.exists(),
        "a URL is not handed to the file manager, not even through the override"
    );

    // Nothing of a WebDAV mount is in the mount table, so the fallback has no forced unmount:
    // `--force` is refused (exit 7) and the plain `lock` is what takes it down.
    fx.crypto_daemon(&["lock", "w", "--force"])
        .assert()
        .code(7)
        .stderr(predicates::str::contains("does not support forced unmount"));
    fx.crypto_daemon(&["lock", "w"]).assert().success();
    let port: u16 = addr.rsplit(':').next().unwrap().parse().unwrap();
    // The listener is *kept* until the end of the test: a bind that is dropped again right away
    // would also succeed if the kernel had handed the port to somebody else in the meantime.
    // Holding it means nothing else has it while everything below is asserted.
    let mut freed = None;
    wait_until("the port to be free again", || {
        freed = std::net::TcpListener::bind(("127.0.0.1", port)).ok();
        freed.is_some()
    });
    let held = freed.expect("the port is ours now");
    // The server gives the port back while the daemon is still shutting down, so the state is only
    // LOCKED once that process is gone -- the same wait every other lock test does.
    wait_until("the daemon to clean up its state files", || {
        !fx.state_file(".sock").exists() && !fx.state_file(".json").exists()
    });
    assert_eq!(json_out(&fx, &["--json", "status", "w"])["state"], "LOCKED");

    // What the WebDAV client wrote is in the vault, readable with no mount at all.
    let listed = json_out(&fx, &["--json", "fs", "ls", "w", "/"]).to_string();
    assert!(
        listed.contains("note.txt"),
        "the PUT reached the vault: {listed}"
    );
    let read = fx
        .crypto_daemon(&["fs", "cat", "w", "/note.txt"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(String::from_utf8_lossy(&read), PUT_BODY);
    drop(held);
}

/// A port somebody else holds is a failed mount, with both ways out in the message.
#[test]
fn a_taken_webdav_port_fails_the_unlock_with_a_hint() {
    let fx = Fixture::new("t");
    let taken = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    let port = taken.local_addr().expect("addr").port().to_string();
    fx.crypto_daemon(&["unlock", "t", "--mounter", "webdav", "--port", &port])
        .assert()
        .code(6)
        .stderr(predicates::str::contains("already in use"))
        .stderr(predicates::str::contains("--port 0"))
        .stderr(predicates::str::contains("crypto vault set"))
        .stderr(predicates::str::contains(port.as_str()));
    assert_eq!(json_out(&fx, &["--json", "status", "t"])["state"], "LOCKED");
}

/// `cli.json`'s `webdavBind` decides which loopback address the daemon serves on -- and a value
/// the rest of the network could reach is a failed mount, not a served vault.
///
/// Its scope is a mount that binds a socket: a mounter without a loopback port never reads the
/// key, so a broken `webdavBind` does not stop a FUSE (here: null) unlock of the same daemon.
#[test]
fn the_webdav_bind_address_from_cli_json_reaches_the_server() {
    let fx = Fixture::new("b");
    let cli_json = |bind: &str| {
        std::fs::write(
            fx.path("cli.json"),
            serde_json::json!({
                "mountPointsDir": fx.mount_points_dir(),
                "webdavBind": bind,
            })
            .to_string(),
        )
        .unwrap();
    };

    // A hand-edited `cli.json` bypasses `config set`'s check, so the daemon repeats it: exit 6,
    // and the reason names the key.
    cli_json("10.0.0.1");
    fx.crypto_daemon(&["unlock", "b", "--mounter", "webdav", "--port", "0"])
        .assert()
        .code(6)
        .stderr(predicates::str::contains("webdavBind"))
        .stderr(predicates::str::contains("loopback"));
    assert_eq!(json_out(&fx, &["--json", "status", "b"])["state"], "LOCKED");

    // The very same `cli.json`, a mounter that binds nothing: the key is not its business, so the
    // unlock goes through. A typo in `webdavBind` must not take FUSE down with it.
    fx.crypto_daemon(&["unlock", "b", "--mounter", "null"])
        .assert()
        .success();
    assert_eq!(
        json_out(&fx, &["--json", "status", "b"])["state"],
        "UNLOCKED"
    );
    fx.crypto_daemon(&["lock", "b"]).assert().success();
    wait_until("the daemon to clean up its state files", || {
        !fx.state_file(".sock").exists() && !fx.state_file(".json").exists()
    });

    // And the other half: a configured loopback address is the one the server binds.
    if std::net::TcpListener::bind("[::1]:0").is_err() {
        println!("skipped the positive half: no IPv6 loopback on this machine");
        return;
    }
    cli_json("::1");
    let result = json_out(
        &fx,
        &[
            "--json",
            "unlock",
            "b",
            "--mounter",
            "webdav",
            "--port",
            "0",
        ],
    );
    let url = result["mountpoint"].as_str().unwrap().to_owned();
    assert!(url.starts_with("http://[::1]:"), "{url}");
    // `localhost` rather than the `[::1]` authority on purpose: the server's `Host` check
    // (`webdav::server::host_header_allowed`) allows a literal address or the name `localhost` and
    // refuses everything else, so this line is both a bind-address test and the proof that the
    // one name a client may send still gets through.
    let response = http(
        &authority(&url),
        &format!(
            "PROPFIND /{id} HTTP/1.1\r\nHost: localhost\r\nDepth: 0\r\n\
             Content-Length: 0\r\nConnection: close\r\n\r\n",
            id = fx.id()
        ),
    );
    assert!(response.starts_with("HTTP/1.1 207"), "{response}");
    fx.crypto_daemon(&["lock", "b"]).assert().success();
}

/// `--port` on a mounter that has no loopback port is refused by name, like `--mount-option` on a
/// mounter that has no mount flags.
#[test]
fn a_port_for_a_mounter_without_one_is_refused() {
    let fx = Fixture::new("p");
    fx.crypto_daemon(&["unlock", "p", "--mounter", "null", "--port", "1234"])
        .assert()
        .code(6)
        .stderr(predicates::str::contains(NULL_MOUNTER))
        .stderr(predicates::str::contains("--port"));
    assert_eq!(json_out(&fx, &["--json", "status", "p"])["state"], "LOCKED");
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
    signal(pid, "-INT");
}

/// Sends `signal` (`-TERM`, `-HUP`, …) to `pid`, the way a shell would.
fn signal(pid: u32, signal: &str) {
    let status = std::process::Command::new("kill")
        .args([signal, &pid.to_string()])
        .status()
        .unwrap();
    assert!(status.success(), "kill {signal} {pid} failed");
}

/// Spawns `args` in the sandbox with its three standard streams out of the way, wrapped so a
/// panic before the test itself takes the child down does not leave it running.
fn spawn(fx: &Fixture, args: &[&str]) -> Reaper {
    Reaper(
        fx.crypto_daemon_cmd(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    )
}

/// Guards a foreground daemon's `Child`: `Fixture::drop` (`lock --all --force`) reaps everything
/// that already published its state files when a test panics, but a panic between `spawn` and the
/// first `wait_until` -- before the daemon has published anything -- would otherwise leave the
/// process running with nothing left to find it by. `Drop` here closes that gap.
struct Reaper(Child);

impl std::ops::Deref for Reaper {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.0
    }
}

impl std::ops::DerefMut for Reaper {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}

impl Drop for Reaper {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The null mount's marker inside the fixture's mount point.
fn marker_of(fx: &Fixture) -> PathBuf {
    fx.mount_points_dir().join(fx.name).join(MARKER)
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

#[test]
fn a_foreground_unlock_takes_the_volume_down_on_sigterm() {
    let fx = Fixture::new("t");
    let mut child = spawn(&fx, &["unlock", "t", "--mounter", "null", "--foreground"]);
    wait_until("the foreground daemon to mount", || {
        fx.state_file(".json").exists()
    });
    let marker = marker_of(&fx);
    assert!(marker.is_file());

    // No `crypto lock` here: the signal alone has to run the whole teardown.
    signal(child.id(), "-TERM");
    let status = wait_for_exit(&mut child);
    assert_eq!(status.code(), Some(0), "SIGTERM is a clean stop");
    assert!(!marker.exists(), "the volume was unmounted");
    assert!(!fx.state_file(".sock").exists());
    assert!(!fx.state_file(".json").exists());
    assert!(!fx.state_file(".pid").exists());
}

#[test]
fn a_busy_volume_is_forced_down_after_the_configured_delay() {
    let fx = Fixture::new("u");
    fx.crypto_daemon(&["config", "set", "forceUnmountOnSignalAfterSecs", "1"])
        .assert()
        .success();
    let mut child = Reaper(
        fx.crypto_daemon_cmd(&["unlock", "u", "--mounter", "null", "--foreground"])
            // The graceful unmount of this volume fails; only the forced one gets through.
            .env("CRYPTO_NULL_MOUNT_BUSY", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait_until("the foreground daemon to mount", || {
        fx.state_file(".json").exists()
    });
    let marker = marker_of(&fx);
    assert!(marker.is_file());

    let signalled = Instant::now();
    signal(child.id(), "-TERM");
    let status = wait_for_exit(&mut child);
    let took = signalled.elapsed();
    assert_eq!(status.code(), Some(0), "the forced unmount got the volume");
    assert!(!marker.exists(), "the volume is gone after the escalation");
    assert!(
        took >= Duration::from_secs(1),
        "the forced unmount waits out forceUnmountOnSignalAfterSecs first, took {took:?}"
    );
    assert!(
        took < Duration::from_secs(5),
        "a regression that ignored forceUnmountOnSignalAfterSecs would flake against \
         wait_for_exit's 10s deadline instead of failing cleanly, took {took:?}"
    );
    assert!(
        !fx.state_file(".json").exists(),
        "an unmounted volume leaves nothing behind"
    );
}

#[test]
fn a_detached_daemon_takes_the_volume_down_on_sighup() {
    let fx = Fixture::new("g");
    let result = unlock(&fx);
    let pid = result["pid"].as_u64().expect("the daemon's pid");
    let mountpoint = mountpoint_of(&result);
    assert!(mountpoint.join(MARKER).is_file());

    // SIGHUP is what a closing terminal sends; the daemon treats it like SIGTERM.
    signal(u32::try_from(pid).unwrap(), "-HUP");
    wait_until("the daemon to clean up its state files", || {
        !fx.state_file(".sock").exists()
            && !fx.state_file(".json").exists()
            && !fx.state_file(".pid").exists()
    });
    wait_until("the daemon to exit", || !alive(pid));
    assert!(
        !mountpoint.join(MARKER).exists(),
        "the volume was unmounted"
    );
    assert_eq!(json_out(&fx, &["--json", "status", "g"])["state"], "LOCKED");
}

#[test]
fn an_idle_vault_locks_itself() {
    let fx = Fixture::new("i");
    // One second idle, and `CRYPTO_AUTOLOCK_TICK_SECS=1` (set for every daemon in these tests)
    // makes the daemon look that often instead of once a minute.
    fx.crypto(&["vault", "set", "i", "--auto-lock-idle", "1"])
        .assert()
        .success();
    let result = unlock(&fx);
    let pid = result["pid"].as_u64().expect("the daemon's pid");
    let mountpoint = mountpoint_of(&result);

    // Nothing touches the vault, so the very first tick past the idle time locks it.
    wait_for(
        Duration::from_secs(5),
        "the idle vault to lock itself",
        || !fx.state_file(".json").exists(),
    );
    wait_until("the auto-locked daemon to exit", || !alive(pid));
    assert!(
        !mountpoint.join(MARKER).exists(),
        "the volume was unmounted"
    );
    assert_eq!(json_out(&fx, &["--json", "status", "i"])["state"], "LOCKED");
}

#[test]
fn a_foreground_unlock_auto_locks_the_same_way() {
    let fx = Fixture::new("j");
    fx.crypto(&["vault", "set", "j", "--auto-lock-idle", "1"])
        .assert()
        .success();
    // The auto-lock thread is the daemon's, and `--foreground` runs the same daemon in this
    // process: it ends on its own, without anything locking it from outside.
    let mut child = spawn(&fx, &["unlock", "j", "--mounter", "null", "--foreground"]);
    let status = wait_for_exit(&mut child);
    assert_eq!(status.code(), Some(0), "an auto-lock is a clean stop");
    assert!(!marker_of(&fx).exists(), "the volume was unmounted");
    assert_eq!(json_out(&fx, &["--json", "status", "j"])["state"], "LOCKED");
}

#[test]
fn reveal_runs_the_command_from_the_environment() {
    let fx = Fixture::new("r");
    let revealed = fx.path("revealed.txt");
    let script = fx.path("reveal.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$1\" >> \"{}\"\n",
            revealed.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let lines = |path: &Path| {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };

    // `--reveal` on the command line. `$CRYPTO_REVEAL_CMD` replaces `open`/`xdg-open`, which is
    // also the only reason this is testable: nothing may pop up a file manager in a test run.
    let out = fx
        .crypto_daemon(&["--json", "unlock", "r", "--mounter", "null", "--reveal"])
        .env("CRYPTO_REVEAL_CMD", &script)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let mountpoint = mountpoint_of(&json(&out));
    wait_until("the reveal command to run", || {
        lines(&revealed) == vec![mountpoint.display().to_string()]
    });
    fx.crypto_daemon(&["lock", "r"]).assert().success();

    // The vault's own `actionAfterUnlock` does it without the flag.
    fx.crypto(&["vault", "set", "r", "--action-after-unlock", "REVEAL"])
        .assert()
        .success();
    fx.crypto_daemon(&["unlock", "r", "--mounter", "null"])
        .env("CRYPTO_REVEAL_CMD", &script)
        .assert()
        .success();
    wait_until("the second reveal", || lines(&revealed).len() == 2);
    assert_eq!(lines(&revealed)[1], mountpoint.display().to_string());
}

#[test]
fn an_unlock_without_reveal_opens_nothing() {
    let fx = Fixture::new("n");
    let revealed = fx.path("revealed.txt");
    let script = fx.path("reveal.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$1\" >> \"{}\"\n",
            revealed.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

    fx.crypto_daemon(&["unlock", "n", "--mounter", "null"])
        .env("CRYPTO_REVEAL_CMD", &script)
        .assert()
        .success();
    fx.crypto_daemon(&["lock", "n"]).assert().success();
    assert!(
        !revealed.exists(),
        "neither --reveal nor actionAfterUnlock asked for anything to be opened"
    );
}

#[test]
fn a_follow_stream_ends_with_code_0_when_the_vault_is_locked() {
    let fx = Fixture::new("q");
    unlock(&fx);
    let mut child = fx
        .crypto_daemon_cmd(&["--json", "stats", "q", "--follow", "--interval", "1"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let (notice, _stderr) = first_line(child.stderr.take().unwrap());
    assert!(notice.contains("Ctrl-C"), "{notice}");
    // One sample has been delivered, so the daemon going away afterwards is the end of the
    // stream and not a failure. The pipe stays open the whole time -- a closed reader would end
    // the child with 0 as well and prove nothing.
    let (line, stdout) = first_line(child.stdout.take().unwrap());
    json(line.trim().as_bytes());

    fx.crypto_daemon(&["lock", "q"]).assert().success();
    let status = wait_for_exit(&mut child);
    assert_eq!(
        status.code(),
        Some(0),
        "a follow stream whose vault is locked ends cleanly"
    );
    drop(stdout);
}

/// Set to `1` to allow the ignored test below to mount a real file system on this machine.
const E2E_ENV: &str = "CRYPTO_E2E_MOUNT";
/// Set to `1` to allow the ignored WebDAV test below to mount a real volume on this machine.
const E2E_WEBDAV_ENV: &str = "CRYPTO_E2E_WEBDAV";
/// What the test writes through the mount, and reads back out of the vault afterwards.
const E2E_CONTENT: &str = "written the instant unlock returned\n";

/// The alias of the first mount service that really mounts and works on this machine.
///
/// `crypto mounters` without `--all` lists exactly the *supported* ones, but that includes the
/// null mounter whenever `CRYPTO_ENABLE_NULL_MOUNTER=1` is set -- which the sandbox always sets
/// (`common::Sandbox`), for the non-E2E tests in this file that mount nothing on purpose. So this
/// filters the null mounter back out explicitly: without a real FUSE back end, every remaining
/// entry is gone and the test skips instead of "mounting" the null service and then failing with
/// a misleading assertion about the volume never appearing.
fn supported_real_mounter(fixture: &Fixture) -> Option<String> {
    let out = fixture
        .crypto(&["--json", "mounters"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    first_non_null_alias(&json(&out))
}

/// The pure part of [`supported_real_mounter`]: the first `alias` in a `crypto mounters --json`
/// array whose `className` is not the null mounter's. Split out so the null-mounter filter can be
/// unit-tested without a daemon or a real mount service.
fn first_non_null_alias(services: &Value) -> Option<String> {
    services.as_array()?.iter().find_map(|service| {
        if service["className"].as_str() == Some(NULL_MOUNTER) {
            return None;
        }
        service["alias"].as_str().map(str::to_owned)
    })
}

#[test]
fn supported_real_mounter_skips_the_null_service() {
    // Only the null mounter is present (as it is on a machine/CI runner with no FUSE back end,
    // once `CRYPTO_ENABLE_NULL_MOUNTER=1` lists it): the filter must leave nothing, so the E2E
    // test skips cleanly instead of "mounting" the null service.
    let only_null = serde_json::json!([
        { "className": NULL_MOUNTER, "alias": "null", "supported": true }
    ]);
    assert_eq!(first_non_null_alias(&only_null), None);
}

#[test]
fn supported_real_mounter_prefers_a_real_service_over_the_null_one() {
    let mixed = serde_json::json!([
        { "className": NULL_MOUNTER, "alias": "null", "supported": true },
        { "className": "org.cryptomator.cli.FuseTMountProvider", "alias": "fuse-t", "supported": true }
    ]);
    assert_eq!(first_non_null_alias(&mixed), Some("fuse-t".to_string()));
}

/// The bug this guards: `crypto unlock` used to answer as soon as the mount call had returned,
/// while FUSE-T's volume was not in the mount table yet. Everything written in that window landed
/// in the bare directory *underneath* the mount point -- beside the vault, with no error and no
/// trace. So this test writes **immediately** after the unlock returns, with no wait of its own,
/// and proves the bytes are inside the vault afterwards.
///
/// It mounts for real and is therefore ignored twice over: `cargo test` skips it, and even
/// `--ignored` only runs it when `CRYPTO_E2E_MOUNT=1` says this machine may be mounted on.
///
/// ```text
/// CRYPTO_E2E_MOUNT=1 cargo test -p crypto --test cli_daemon --locked -- --ignored
/// ```
///
/// Every exit path locks: the happy one explicitly, a panicking one through [`Fixture::drop`],
/// which runs `crypto lock --all --force`.
#[test]
#[ignore = "mounts a real file system; needs CRYPTO_E2E_MOUNT=1 and a FUSE back end"]
fn a_file_written_the_moment_unlock_returns_is_in_the_vault() {
    if std::env::var(E2E_ENV).as_deref() != Ok("1") {
        println!("skipped: {E2E_ENV} is not set to 1");
        return;
    }
    let fx = Fixture::new("e");
    let Some(mounter) = supported_real_mounter(&fx) else {
        println!("skipped: no FUSE service supported");
        return;
    };
    println!("mounter: {mounter}");
    // The FUSE back ends want an existing empty directory (MOUNT_TO_EXISTING_DIR).
    let mountpoint = fx.path("mp");
    std::fs::create_dir(&mountpoint).expect("the mount point");

    let result = json(
        &fx.crypto_daemon(&[
            "--json",
            "unlock",
            "e",
            "--mounter",
            &mounter,
            "--mount-point",
            mountpoint.to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone(),
    );
    assert_eq!(mountpoint_of(&result), mountpoint);

    // No sleep and no poll in between: the unlock answered, so the volume is up.
    assert!(
        is_mountpoint(&mountpoint),
        "the unlock answered before the volume was in the mount table"
    );
    std::fs::write(mountpoint.join("visible.txt"), E2E_CONTENT).expect("write through the mount");

    fx.crypto_daemon(&["lock", "e"]).assert().success();
    assert!(
        !is_mountpoint(&mountpoint),
        "the volume is gone after the lock"
    );
    fx.crypto_daemon(&["fs", "cat", "e", "/visible.txt"])
        .assert()
        .success()
        .stdout(E2E_CONTENT);
}

/// The alias of the OS-integrated WebDAV mounter of this platform: the one that does not stop at
/// the URL but hands it to Finder / `gio` and gives back a directory.
const OS_WEBDAV_ALIAS: &str = if cfg!(target_os = "macos") {
    "webdav-applescript"
} else {
    "webdav-gio"
};

/// Whether `alias` is listed as supported by `crypto mounters` on this machine.
fn mounter_is_supported(fixture: &Fixture, alias: &str) -> bool {
    let out = fixture
        .crypto(&["--json", "mounters", "--all"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    json(&out).as_array().is_some_and(|services| {
        services
            .iter()
            .any(|s| s["alias"] == alias && s["supported"] == true)
    })
}

/// The other half of the WebDAV story, the one no other test can reach: not the URL, but the
/// volume the operating system makes of it. `webdav-applescript` asks Finder to mount the
/// server's URL, so the answer is a `/Volumes/…` path -- a directory the shell can write into,
/// with the bytes travelling through the daemon's own WebDAV server into the vault.
///
/// It mounts for real and is therefore ignored twice over: `cargo test` skips it, and even
/// `--ignored` only runs it when `CRYPTO_E2E_WEBDAV=1` says this machine may be mounted on.
///
/// ```text
/// CRYPTO_E2E_WEBDAV=1 cargo test -p crypto --test cli_daemon --locked -- --ignored
/// ```
///
/// Every exit path locks: the happy one explicitly, a panicking one through [`Fixture::drop`].
/// A volume that outlives even that is a real `/Volumes/…` entry, so the test never leaves the
/// unmount to chance -- it is the very last thing it does.
#[test]
#[ignore = "mounts a real WebDAV volume; needs CRYPTO_E2E_WEBDAV=1"]
fn an_os_webdav_mount_carries_a_write_through_the_server_into_the_vault() {
    if std::env::var(E2E_WEBDAV_ENV).as_deref() != Ok("1") {
        println!("skipped: {E2E_WEBDAV_ENV} is not set to 1");
        return;
    }
    let fx = Fixture::new("wv");
    if !mounter_is_supported(&fx, OS_WEBDAV_ALIAS) {
        println!("skipped: {OS_WEBDAV_ALIAS} is not supported here");
        return;
    }
    // Port 0, so the test never fights the desktop app or a second run for 42427.
    let result = json(
        &fx.crypto_daemon(&[
            "--json",
            "unlock",
            "wv",
            "--mounter",
            OS_WEBDAV_ALIAS,
            "--port",
            "0",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone(),
    );
    let mountpoint = mountpoint_of(&result);
    println!("mounted at {}", mountpoint.display());
    assert!(
        mountpoint.is_absolute(),
        "an OS WebDAV mount answers with a directory, not with a URL: {}",
        mountpoint.display()
    );
    if cfg!(target_os = "macos") {
        assert!(
            mountpoint.starts_with("/Volumes/"),
            "Finder mounts into /Volumes: {}",
            mountpoint.display()
        );
    }
    assert!(
        is_mountpoint(&mountpoint),
        "the unlock answered before the volume was in the mount table"
    );

    // Through the volume, through the operating system's WebDAV client, through the daemon's own
    // server and into the vault.
    std::fs::write(mountpoint.join("dav.txt"), E2E_CONTENT).expect("write through the volume");

    fx.crypto_daemon(&["lock", "wv"]).assert().success();
    assert!(
        !is_mountpoint(&mountpoint),
        "the volume is gone after the lock"
    );
    fx.crypto_daemon(&["fs", "cat", "wv", "/dav.txt"])
        .assert()
        .success()
        .stdout(E2E_CONTENT);
}

/// The desktop app writes `settings.json` without taking the lock, so the CLI cannot serialise
/// against it -- it can only say so before it writes.
#[test]
fn a_running_desktop_app_is_warned_about_before_settings_are_written() {
    let sandbox = Sandbox::new();
    // Not next to `settings.json`, so this proves the override and not the derived path.
    std::fs::create_dir_all(sandbox.path("d")).expect("socket directory");
    let socket = sandbox.path("d/ipc.socket");
    let listener = std::os::unix::net::UnixListener::bind(&socket).expect("a fake desktop app");
    let assertion = sandbox
        .crypto(&["config", "set", "logLevel", "debug"])
        .env("CRYPTO_DESKTOP_IPC_SOCKET", &socket)
        .assert()
        .success();
    let stderr = String::from_utf8_lossy(&assertion.get_output().stderr).into_owned();
    assert!(stderr.contains("desktop app"), "{stderr}");
    assert!(stderr.contains("settings.json"), "{stderr}");

    // A read-only command says nothing: there is nothing to lose.
    let assertion = sandbox
        .crypto(&["--json", "config", "get", "logLevel"])
        .env("CRYPTO_DESKTOP_IPC_SOCKET", &socket)
        .assert()
        .success();
    assert!(
        String::from_utf8_lossy(&assertion.get_output().stderr).is_empty(),
        "a read does not warn"
    );

    // And with nobody listening, a write says nothing either.
    drop(listener);
    std::fs::remove_file(&socket).expect("remove the socket");
    let assertion = sandbox
        .crypto(&["config", "set", "logLevel", "info"])
        .env("CRYPTO_DESKTOP_IPC_SOCKET", &socket)
        .assert()
        .success();
    assert!(
        String::from_utf8_lossy(&assertion.get_output().stderr).is_empty(),
        "no app, no warning"
    );
}

/// The keychain as a passphrase source, end to end: the implicit step, the switch that takes it
/// away, and the explicit flag that refuses to fall back.
///
/// Everything runs against the file-backed fake keychain (`$CRYPTO_KEYCHAIN_FAKE`), which takes
/// over the whole provider registry, so nothing here can reach the machine's real one.
#[test]
fn a_stored_passphrase_unlocks_a_vault_without_any_other_source() {
    let fx = Fixture::new("v");
    let id = fx.id();
    // Seed the fake keychain the way `password store` will (task 6).
    fx.seed_keychain(&id, "v", common::PW);

    // No --password-* flag, no $CRYPTO_PASSWORD, no terminal: only the keychain can answer.
    fx.crypto_daemon_keychain(&["unlock", "v", "--mounter", "null"])
        .assert()
        .success();
    fx.crypto_daemon_keychain(&["lock", "v"]).assert().success();
    // `lock` returns as soon as the daemon acknowledges; the next unlock needs the vault LOCKED
    // both on disk and in the runtime sense (`locked_vault` -> `require_locked`), so it has to
    // wait for the daemon to actually finish tearing down its state files first.
    wait_until("the daemon to clean up its state files", || {
        !fx.state_file(".sock").exists() && !fx.state_file(".json").exists()
    });

    // --no-keychain takes that source away again, and without a terminal there is nothing left.
    fx.crypto_daemon_keychain(&["--no-keychain", "unlock", "v", "--mounter", "null"])
        .assert()
        .code(2)
        .stderr(predicates::str::contains("--password-stdin"));

    // So does useKeychain=false, which is what the desktop app writes when the user turns the
    // keychain off. `config set` needs a settings write, not a password.
    fx.crypto(&["config", "set", "useKeychain", "false"])
        .assert()
        .success();
    fx.crypto_daemon_keychain(&["unlock", "v", "--mounter", "null"])
        .assert()
        .code(2)
        .stderr(predicates::str::contains("--password-stdin"));
    // ... and the explicit flag is exit 8 rather than exit 2, because the source the user insisted
    // on is the one that is gone.
    fx.crypto_daemon_keychain(&["unlock", "v", "--mounter", "null", "--password-keychain"])
        .assert()
        .code(8)
        .stderr(predicates::str::contains("useKeychain"));
    fx.crypto(&["config", "set", "useKeychain", "true"])
        .assert()
        .success();

    // And an explicit --password-keychain for a vault with no entry is exit 8 too.
    fx.crypto(&["vault", "create", fx.path("w").to_str().unwrap()])
        .assert()
        .success();
    fx.crypto_daemon_keychain(&["unlock", "w", "--mounter", "null", "--password-keychain"])
        .assert()
        .code(8)
        .stderr(predicates::str::contains("no passphrase is stored"));

    // Nothing wrote to the keychain: `unlock` only reads it.
    assert_eq!(
        fx.fake_keychain_json(),
        serde_json::json!({ &id: { "password": common::PW, "displayName": "v" } })
    );
}

/// `--store-password` writes only once the vault is really mounted, and only when it is asked to.
#[test]
fn unlock_store_password_saves_only_after_the_mount_succeeded() {
    let fx = Fixture::new("v");
    let id = fx.id();

    // A mount that fails leaves the keychain untouched. The null mounter mounts into an existing
    // directory, so a mount point that is not there is `MountPointInvalid` -- exit 6, and the
    // password was already read and verified by then.
    fx.crypto_daemon_keychain(&[
        "unlock",
        "v",
        "--mounter",
        "null",
        "--mount-point",
        fx.path("not-here").to_str().unwrap(),
        "--store-password",
        "--password-stdin",
    ])
    .write_stdin(format!("{}\n", common::PW))
    .assert()
    .code(6);
    assert_eq!(
        fx.fake_keychain_json(),
        serde_json::json!({}),
        "nothing is stored for a vault that never mounted"
    );
    // The parent reaps the daemon it spawned, but the next unlock needs the vault LOCKED in the
    // runtime sense too, so wait for the state files to be gone first.
    wait_until("the daemon to clean up its state files", || {
        !fx.state_file(".sock").exists() && !fx.state_file(".json").exists()
    });

    // A mount that works stores it, after the mount point has been reported.
    let out = fx
        .crypto_daemon_keychain(&[
            "--json",
            "unlock",
            "v",
            "--mounter",
            "null",
            "--store-password",
            "--password-stdin",
        ])
        .write_stdin(format!("{}\n", common::PW))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8(out).expect("utf-8");
    assert!(
        !stdout.contains(common::PW),
        "the passphrase never reaches stdout"
    );
    assert_eq!(fx.fake_keychain_json()[&id]["password"], common::PW);
    assert_eq!(fx.fake_keychain_json()[&id]["displayName"], "v");
    fx.crypto_daemon_keychain(&["lock", "v"]).assert().success();
    wait_until("the daemon to clean up its state files", || {
        !fx.state_file(".sock").exists() && !fx.state_file(".json").exists()
    });

    // What was stored is what unlocks the vault next time, with no source given at all.
    fx.crypto_daemon_keychain(&["unlock", "v", "--mounter", "null"])
        .assert()
        .success();
    fx.crypto_daemon_keychain(&["lock", "v"]).assert().success();
    wait_until("the daemon to clean up its state files", || {
        !fx.state_file(".sock").exists() && !fx.state_file(".json").exists()
    });

    // And --no-store-password is the (current) default spelled out: nothing new is written.
    std::fs::write(fx.keychain_file(), "{}").unwrap();
    fx.crypto_daemon_keychain(&[
        "unlock",
        "v",
        "--mounter",
        "null",
        "--no-store-password",
        "--password-stdin",
    ])
    .write_stdin(format!("{}\n", common::PW))
    .assert()
    .success();
    assert_eq!(fx.fake_keychain_json(), serde_json::json!({}));
    fx.crypto_daemon_keychain(&["lock", "v"]).assert().success();
    wait_until("the daemon to clean up its state files", || {
        !fx.state_file(".sock").exists() && !fx.state_file(".json").exists()
    });

    // Without a keychain to store into, `--store-password` fails *before* anything is unlocked:
    // an unlocked vault plus an error is the worst of both answers.
    fx.crypto(&["config", "set", "useKeychain", "false"])
        .assert()
        .success();
    fx.crypto_daemon_keychain(&[
        "unlock",
        "v",
        "--mounter",
        "null",
        "--store-password",
        "--password-stdin",
    ])
    .write_stdin(format!("{}\n", common::PW))
    .assert()
    .code(8)
    .stderr(predicates::str::contains("useKeychain"));
    assert!(
        !fx.state_file(".pid").exists(),
        "no daemon was ever spawned"
    );
    fx.crypto_daemon(&["status", "v"])
        .assert()
        .success()
        .stdout(predicates::str::contains("LOCKED"));
    assert_eq!(fx.fake_keychain_json(), serde_json::json!({}));
}

/// A keychain that is present but refuses at store time: the vault stays mounted and the run stays
/// successful, because the unlock really did work -- only the saving of the password did not.
#[test]
fn unlock_store_password_warns_when_the_keychain_refuses() {
    let fx = Fixture::new("v");

    fx.crypto_daemon_keychain_locked(&[
        "unlock",
        "v",
        "--mounter",
        "null",
        "--store-password",
        "--password-stdin",
    ])
    .write_stdin(format!("{}\n", common::PW))
    .assert()
    .success()
    .stderr(predicates::str::contains(
        "warning: the password was not stored",
    ));
    // The vault is unlocked ...
    fx.crypto_daemon(&["status", "v"])
        .assert()
        .success()
        .stdout(predicates::str::contains("UNLOCKED"));
    // ... and nothing was written: `--store-password` warned instead of failing.
    assert_eq!(fx.fake_keychain_json(), serde_json::json!({}));
    fx.crypto_daemon(&["lock", "v"]).assert().success();
    wait_until("the daemon to clean up its state files", || {
        !fx.state_file(".sock").exists() && !fx.state_file(".json").exists()
    });
}
