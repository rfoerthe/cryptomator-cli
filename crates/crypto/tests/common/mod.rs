//! Shared helpers for the CLI integration tests.
// Each test binary compiles its own copy of this module and uses only part of it.
#![allow(dead_code)]

use assert_cmd::Command;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

pub const PW: &str = "test-password-123";

pub struct Sandbox {
    dir: TempDir,
}

impl Sandbox {
    pub fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
        }
    }
    pub fn settings(&self) -> PathBuf {
        self.dir.path().join("settings.json")
    }
    /// The sandbox directory itself.
    pub fn root(&self) -> &Path {
        self.dir.path()
    }
    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
    /// `crypto --settings <sandbox> <args>` with CRYPTO_PASSWORD set and no inherited password variables.
    pub fn crypto(&self, args: &[&str]) -> Command {
        let mut cmd = Command::cargo_bin("crypto").unwrap();
        cmd.env_remove("CRYPTO_SETTINGS_PATH")
            .env_remove("CRYPTO_MIN_PW_LENGTH")
            .env("CRYPTO_PASSWORD", PW);
        cmd.arg("--settings").arg(self.settings());
        cmd.args(args);
        cmd
    }
    pub fn settings_json(&self) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(self.settings()).unwrap()).unwrap()
    }
    /// The id of the vault registered at `index`.
    pub fn vault_id(&self, index: usize) -> String {
        self.settings_json()["directories"][index]["id"]
            .as_str()
            .unwrap()
            .to_string()
    }
    /// Where the daemons publish their socket, pid and run info. The name is one letter on
    /// purpose: a Unix socket path may be at most 104 bytes on macOS, and the sandbox already
    /// spends most of that.
    pub fn state_dir(&self) -> PathBuf {
        self.path("s")
    }
    /// The mount-point base written into `cli.json` by [`Sandbox::write_cli_config`].
    pub fn mount_points_dir(&self) -> PathBuf {
        self.path("mnt")
    }
    /// Writes `cli.json` next to `settings.json`, so no unlock ever mounts outside the sandbox.
    pub fn write_cli_config(&self) {
        let value = serde_json::json!({ "mountPointsDir": self.mount_points_dir() });
        std::fs::write(self.path("cli.json"), value.to_string()).unwrap();
    }
    /// The state file `<vault id><suffix>` of the vault registered first, e.g. `.sock`.
    pub fn state_file(&self, suffix: &str) -> PathBuf {
        self.state_dir()
            .join(format!("{}{suffix}", self.vault_id(0)))
    }
    /// `crypto --settings … --state-dir …` with `$HOME` inside the sandbox and the null mounter
    /// enabled, as a plain [`std::process::Command`] so the caller can spawn it.
    pub fn crypto_daemon_cmd(&self, args: &[&str]) -> std::process::Command {
        let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin("crypto"));
        cmd.env_remove("CRYPTO_SETTINGS_PATH")
            .env_remove("CRYPTO_MIN_PW_LENGTH")
            .env_remove("CRYPTO_NULL_MOUNT_BUSY")
            .env("CRYPTO_PASSWORD", PW)
            // The mount-point and state-dir defaults are derived from it; nothing may reach the
            // real one.
            .env("HOME", self.root())
            .env("CRYPTO_ENABLE_NULL_MOUNTER", "1")
            // The auto-lock thread wakes every minute by default, which no test can wait for.
            .env("CRYPTO_AUTOLOCK_TICK_SECS", "1");
        cmd.arg("--settings").arg(self.settings());
        cmd.arg("--state-dir").arg(self.state_dir());
        cmd.args(args);
        cmd
    }
    /// [`Sandbox::crypto_daemon_cmd`] ready for `assert()`.
    pub fn crypto_daemon(&self, args: &[&str]) -> Command {
        Command::from_std(self.crypto_daemon_cmd(args))
    }
    /// Like [`Sandbox::crypto_daemon_cmd`], but `--settings`/`--state-dir` are given as the
    /// relative names `settings.json`/`s` and the process itself runs with [`Sandbox::root`] as
    /// its current directory -- for testing that a relative path the user typed against the
    /// shell's cwd still reaches the detached daemon, whose own cwd is `/`.
    pub fn crypto_daemon_cmd_relative(&self, args: &[&str]) -> std::process::Command {
        let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin("crypto"));
        cmd.current_dir(self.root())
            .env_remove("CRYPTO_SETTINGS_PATH")
            .env_remove("CRYPTO_MIN_PW_LENGTH")
            .env_remove("CRYPTO_NULL_MOUNT_BUSY")
            .env("CRYPTO_PASSWORD", PW)
            .env("HOME", self.root())
            .env("CRYPTO_ENABLE_NULL_MOUNTER", "1")
            .env("CRYPTO_AUTOLOCK_TICK_SECS", "1");
        cmd.arg("--settings").arg("settings.json");
        cmd.arg("--state-dir").arg("s");
        cmd.args(args);
        cmd
    }
    /// [`Sandbox::crypto_daemon_cmd_relative`] ready for `assert()`.
    pub fn crypto_daemon_relative(&self, args: &[&str]) -> Command {
        Command::from_std(self.crypto_daemon_cmd_relative(args))
    }
    /// Copies a fixture vault into the sandbox and registers it under its name.
    pub fn add_fixture(&self, name: &str) -> PathBuf {
        let vault = self.path(name);
        std::fs::create_dir(&vault).unwrap();
        copy_recursively(&fixtures_root().join(name), &vault);
        self.crypto(&["vault", "add"])
            .arg(&vault)
            .assert()
            .success();
        vault
    }
}

impl Default for Sandbox {
    fn default() -> Self {
        Self::new()
    }
}

/// `tests/fixtures` at the repository root; the fixtures themselves are read-only.
pub fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

pub fn copy_recursively(src: &Path, dst: &Path) {
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let target = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            std::fs::create_dir(&target).unwrap();
            copy_recursively(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}
