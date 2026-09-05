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
