#![allow(dead_code)]
//! Shared helpers for integration tests: fixture copies and fast unlocks via the known raw masterkey.
use cryptomator_core::{open_vault_with_key, Masterkey, OpenedVault};
use data_encoding::HEXLOWER;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

pub const PASSPHRASE: &str = "test-password-123";

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

/// Fixtures are read-only; every test works on a copy.
pub fn copy_fixture(name: &str) -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    copy_recursively(&fixtures_root().join(name), dir.path());
    dir
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FixtureMeta {
    pub cipher_combo: String,
    pub shortening_threshold: u32,
    pub passphrase: String,
    pub masterkey_hex: String,
}

pub fn fixture_meta(vault: &Path) -> FixtureMeta {
    serde_json::from_slice(&std::fs::read(vault.join("fixture.json")).unwrap()).unwrap()
}

/// Unlocks a fixture copy with its raw masterkey (no scrypt), so tests stay fast.
pub fn open_fixture(name: &str) -> (TempDir, OpenedVault) {
    let dir = copy_fixture(name);
    let meta = fixture_meta(dir.path());
    let raw = HEXLOWER.decode(meta.masterkey_hex.as_bytes()).unwrap();
    let mut key = [0u8; 64];
    key.copy_from_slice(&raw);
    let opened = open_vault_with_key(dir.path(), Masterkey::from_raw(key)).unwrap();
    (dir, opened)
}

/// One node of `expected.json`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize, serde::Serialize)]
pub struct ExpectedEntry {
    pub path: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

pub fn expected_entries(vault: &Path) -> Vec<ExpectedEntry> {
    let mut entries: Vec<ExpectedEntry> =
        serde_json::from_slice(&std::fs::read(vault.join("expected.json")).unwrap()).unwrap();
    entries.sort();
    entries
}

pub const FIXTURE_NAMES: [&str; 8] = [
    "long_names",
    "nested",
    "siv_ctrmac_basic",
    "siv_gcm_basic",
    "sizes",
    "symlinks",
    "threshold_36",
    "unicode",
];
