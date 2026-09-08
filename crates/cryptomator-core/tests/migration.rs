//! The three legacy reference vaults (`tests/fixtures/legacy_v{5,6,7}`, written by cryptofs 1.3.2,
//! 1.8.9 and 1.9.15): what the version detection makes of them, and what their manifests promise the
//! later migration tests. Regenerate them with `tools/fixture-gen/legacy-v{5,6,7}` — see
//! `tools/fixture-gen/README.md`.
mod common;

use cryptomator_core::{
    determine_vault_state, determine_vault_version, needs_migration, MasterkeyFile,
    MasterkeyFileAccess, VaultState,
};
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::path::{Path, PathBuf};

/// The manifest of a legacy fixture. `format` and `vaultVersion` always carry the same number.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyMeta {
    name: String,
    kind: String,
    format: u32,
    vault_version: u32,
    shortening_threshold: u32,
    passphrase: String,
    passphrase_nfc: String,
    expected: Vec<ExpectedNode>,
}

#[derive(Debug, serde::Deserialize)]
struct ExpectedNode {
    path: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    size: Option<u64>,
    #[serde(default)]
    sha256: Option<String>,
    #[serde(default)]
    target: Option<String>,
}

const LEGACY_FIXTURES: [(&str, u32); 3] = [("legacy_v7", 7), ("legacy_v6", 6), ("legacy_v5", 5)];

fn legacy_vault(name: &str) -> PathBuf {
    common::fixtures_root().join(name)
}

fn legacy_meta(name: &str) -> LegacyMeta {
    let path = legacy_vault(name).join("fixture.json");
    serde_json::from_slice(&std::fs::read(&path).unwrap())
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn masterkey_file(vault: &Path) -> MasterkeyFile {
    MasterkeyFile::parse(&std::fs::read(vault.join("masterkey.cryptomator")).unwrap()).unwrap()
}

#[test]
fn the_legacy_fixtures_report_their_formats() {
    for (name, version) in LEGACY_FIXTURES {
        let vault = legacy_vault(name);
        assert_eq!(determine_vault_version(&vault).unwrap(), version, "{name}");
        assert!(needs_migration(&vault).unwrap(), "{name}");
        assert_eq!(
            determine_vault_state(&vault).unwrap(),
            VaultState::NeedsMigration,
            "{name}"
        );
        assert!(
            !vault.join("vault.cryptomator").exists(),
            "{name}: formats 5..7 have no vault config"
        );
    }
}

#[test]
fn only_the_pre_seven_formats_have_a_metadata_directory() {
    // Formats 5 and 6 keep inflated long names in `m/xx/yy/*.lng`; format 7 moved them into the
    // node itself (`<deflated>.c9s/name.c9s`) and dropped `m/` altogether.
    assert!(legacy_vault("legacy_v6").join("m").is_dir());
    assert!(legacy_vault("legacy_v5").join("m").is_dir());
    assert!(!legacy_vault("legacy_v7").join("m").exists());
    assert!(
        walk_names(&legacy_vault("legacy_v7").join("d")).any(|n| n.ends_with(".c9s")),
        "legacy_v7 has at least one shortened node"
    );
    for name in ["legacy_v6", "legacy_v5"] {
        assert!(
            walk_names(&legacy_vault(name).join("d")).any(|n| n.ends_with(".lng")),
            "{name} has at least one deflated name"
        );
    }
}

/// The `versionMac` cryptolib 1.1.x wrote next to `"version": 5` has to authenticate exactly that
/// number under the MAC key — this is the only place where our HMAC of the vault version is checked
/// against a file the reference implementation produced for a pre-format-8 vault.
#[test]
fn the_v5_masterkey_file_is_a_real_version_five() {
    let vault = legacy_vault("legacy_v5");
    let file = masterkey_file(&vault);
    assert_eq!(file.version, 5, "the alleged vault version");
    assert_eq!(
        MasterkeyFileAccess::read_alleged_vault_version(
            &std::fs::read(vault.join("masterkey.cryptomator")).unwrap()
        )
        .unwrap(),
        5
    );
    let meta = legacy_meta("legacy_v5");
    let key = MasterkeyFileAccess::new(Vec::new())
        .unlock(&file, &meta.passphrase)
        .unwrap();
    let mut mac = Hmac::<Sha256>::new_from_slice(key.mac_key()).unwrap();
    mac.update(&5u32.to_be_bytes());
    assert_eq!(
        mac.finalize().into_bytes().as_slice(),
        file.version_mac.as_slice(),
        "versionMac must authenticate the vault version the file claims"
    );
}

#[test]
fn the_v5_fixture_needs_an_nfd_passphrase() {
    let vault = legacy_vault("legacy_v5");
    let meta = legacy_meta("legacy_v5");
    assert_ne!(
        meta.passphrase, meta.passphrase_nfc,
        "the point of the v5 fixture is that the two forms differ"
    );
    let access = MasterkeyFileAccess::new(Vec::new());
    assert!(access
        .load(&vault.join("masterkey.cryptomator"), &meta.passphrase)
        .is_ok());
    assert!(
        access
            .load(&vault.join("masterkey.cryptomator"), &meta.passphrase_nfc)
            .is_err(),
        "before the 5 -> 6 migration only the NFD form opens the vault"
    );
}

#[test]
fn every_legacy_manifest_describes_its_fixture() {
    for (name, version) in LEGACY_FIXTURES {
        let meta = legacy_meta(name);
        assert_eq!(meta.name, name);
        assert_eq!(meta.kind, "legacy", "{name}");
        assert_eq!(meta.format, version, "{name}");
        assert_eq!(meta.vault_version, meta.format, "{name}: the two aliases");
        assert_eq!(
            meta.shortening_threshold,
            if version == 7 { 220 } else { 129 },
            "{name}"
        );
        assert!(!meta.passphrase.is_empty(), "{name}");
        // No masterkeyHex: unlike the clean fixtures these vaults are only ever opened with the
        // passphrase, so the enumerating fixture tests must skip them (`kind` = `legacy`).
        let raw = std::fs::read_to_string(legacy_vault(name).join("fixture.json")).unwrap();
        assert!(!raw.contains("masterkeyHex"), "{name}");

        let files = meta.expected.iter().filter(|e| e.kind == "file").count();
        assert!(files >= 6, "{name}: {files} files");
        assert!(
            meta.expected.iter().any(|e| e.size == Some(0)),
            "{name}: an empty file"
        );
        assert!(
            meta.expected.iter().any(|e| e.size == Some(1)),
            "{name}: a one-byte file"
        );
        assert!(
            meta.expected.iter().any(|e| e.size == Some(40 * 1024)),
            "{name}: a multi-chunk file"
        );
        assert!(
            meta.expected
                .iter()
                .any(|e| e.path.rsplit('/').next().is_some_and(|n| n.len() > 129)),
            "{name}: a name past the shortening threshold"
        );
        assert!(
            meta.expected.iter().any(|e| !e.path.is_ascii()),
            "{name}: a non-ASCII name"
        );
        assert_eq!(
            meta.expected.iter().filter(|e| e.kind == "symlink").count(),
            // cryptofs 1.6.2 cannot create symlinks yet, so legacy_v5 has none.
            usize::from(version > 5),
            "{name}"
        );
        for entry in &meta.expected {
            match entry.kind.as_str() {
                "file" => assert!(
                    entry.size.is_some() && entry.sha256.is_some(),
                    "{name}: {}",
                    entry.path
                ),
                "symlink" => assert!(entry.target.is_some(), "{name}: {}", entry.path),
                "dir" => {}
                other => panic!("{name}: unexpected node type {other}"),
            }
        }
    }
}

/// Every file and directory name below `root`, recursively.
fn walk_names(root: &Path) -> impl Iterator<Item = String> {
    let mut names = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            names.push(entry.file_name().to_string_lossy().into_owned());
            if entry.path().is_dir() {
                stack.push(entry.path());
            }
        }
    }
    names.into_iter()
}
