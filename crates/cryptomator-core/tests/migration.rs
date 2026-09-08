//! The three legacy reference vaults (`tests/fixtures/legacy_v{5,6,7}`, written by cryptofs 1.3.2,
//! 1.8.9 and 1.9.15): what the version detection makes of them, and what their manifests promise the
//! later migration tests. Regenerate them with `tools/fixture-gen/legacy-v{5,6,7}` — see
//! `tools/fixture-gen/README.md`.
//!
//! The second half of the file migrates copies of those vaults: version detection, the plan, the
//! 5 → 6 and 7 → 8 steps and what the chain leaves behind where the 6 → 7 step is still missing.
mod common;

use common::ExpectedEntry;
use cryptomator_core::fs::{CleartextPath, CryptoFs, CryptoFsOptions};
use cryptomator_core::migration::{self, MigrationEvent, MigrationStep, VaultVersion};
use cryptomator_core::{
    determine_vault_state, determine_vault_version, needs_migration, CoreError, MasterkeyFile,
    MasterkeyFileAccess, OsRng, VaultState,
};
use data_encoding::HEXLOWER;
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
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
    /// The cleartext tree, in the same node shape the format 8 fixtures use.
    expected: Vec<ExpectedEntry>,
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

// ---------------------------------------------------------------------------------------------
// Migration proper. Every test works on a copy; `tests/fixtures/` is read-only.
// ---------------------------------------------------------------------------------------------

/// Runs a migration and returns both its outcome and the progress events it reported.
fn migrate_collecting(
    vault: &Path,
    passphrase: &str,
) -> (Result<VaultVersion, CoreError>, Vec<MigrationEvent>) {
    let mut seen = Vec::new();
    let result = migration::migrate(vault, passphrase, &mut |event| seen.push(event));
    (result, seen)
}

/// SHA-256 of every file below `root`, keyed by its path relative to `root`.
fn digests(root: &Path) -> BTreeMap<PathBuf, String> {
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                stack.push(path);
            } else {
                let relative = path.strip_prefix(root).unwrap().to_path_buf();
                let digest = Sha256::digest(std::fs::read(&path).unwrap());
                out.insert(relative, HEXLOWER.encode(&digest));
            }
        }
    }
    out
}

/// The `.bkup` files a vault carries, with their contents' digests.
fn backups(vault: &Path) -> BTreeMap<PathBuf, String> {
    digests(vault)
        .into_iter()
        .filter(|(path, _)| path.to_string_lossy().ends_with(".bkup"))
        .collect()
}

/// The cleartext tree as `CryptoFs` sees it, in the shape of the fixture manifests.
fn crypto_fs_tree(fs: &CryptoFs, dir: &CleartextPath, out: &mut Vec<ExpectedEntry>) {
    for entry in fs.read_dir(dir).unwrap() {
        let path = dir.join(&entry.cleartext_name).unwrap();
        let attrs = fs.symlink_metadata(&path).unwrap();
        if attrs.is_symlink() {
            out.push(ExpectedEntry {
                path: path.to_string(),
                kind: "symlink".into(),
                size: None,
                sha256: None,
                target: Some(fs.read_link(&path).unwrap()),
            });
        } else if attrs.is_dir() {
            out.push(ExpectedEntry {
                path: path.to_string(),
                kind: "dir".into(),
                size: None,
                sha256: None,
                target: None,
            });
            crypto_fs_tree(fs, &path, out);
        } else {
            let data = fs.read_file(&path).unwrap();
            out.push(ExpectedEntry {
                path: path.to_string(),
                kind: "file".into(),
                size: Some(data.len() as u64),
                sha256: Some(HEXLOWER.encode(&Sha256::digest(&data))),
                target: None,
            });
        }
    }
}

#[test]
fn every_fixture_format_is_detected() {
    for (name, expected) in [
        ("legacy_v5", VaultVersion::V5),
        ("legacy_v6", VaultVersion::V6),
        ("legacy_v7", VaultVersion::V7),
        ("siv_gcm_basic", VaultVersion::V8),
    ] {
        let vault = legacy_vault(name);
        assert_eq!(
            migration::detect_version(&vault).unwrap(),
            expected,
            "{name}"
        );
        assert_eq!(
            migration::needs_migration(&vault).unwrap(),
            expected != VaultVersion::V8,
            "{name}"
        );
    }
    assert_eq!(VaultVersion::V7.to_string(), "7");
}

#[test]
fn the_plan_lists_every_step_up_to_format_eight() {
    for (name, steps) in [
        (
            "legacy_v5",
            vec![
                MigrationStep::FiveToSix,
                MigrationStep::SixToSeven,
                MigrationStep::SevenToEight,
            ],
        ),
        (
            "legacy_v6",
            vec![MigrationStep::SixToSeven, MigrationStep::SevenToEight],
        ),
        ("legacy_v7", vec![MigrationStep::SevenToEight]),
    ] {
        let meta = legacy_meta(name);
        let plan = migration::plan(&legacy_vault(name), &meta.passphrase).unwrap();
        assert_eq!(plan.steps, steps, "{name}");
        assert_eq!(plan.from.number(), meta.format, "{name}");
        assert_eq!(plan.to, VaultVersion::LATEST, "{name}");
        assert!(plan.renames.is_empty(), "{name}: filled by the 6->7 step");
    }
    // Nothing to do, and therefore no passphrase check either.
    let plan = migration::plan(&legacy_vault("siv_gcm_basic"), "not the passphrase").unwrap();
    assert!(plan.steps.is_empty());
    assert_eq!(plan.from, VaultVersion::V8);
}

#[test]
fn planning_a_migration_rejects_a_wrong_passphrase_before_anything_is_written() {
    let err = migration::plan(&legacy_vault("legacy_v7"), "wrong").unwrap_err();
    assert!(matches!(err, CoreError::InvalidPassphrase), "{err}");
}

/// The whole chain on the format 5 vault: 5 → 6 runs, 6 → 7 does not exist yet, and what the run
/// leaves behind is a valid format 6 vault keyed with the NFC passphrase.
#[test]
fn the_chain_migrates_five_to_six_and_then_stops_at_the_missing_step() {
    let (_tmp, vault) = common::fixture_copy_at("legacy_v5");
    let meta = legacy_meta("legacy_v5");
    let access = MasterkeyFileAccess::new(Vec::new());
    let before = access
        .load(&vault.join("masterkey.cryptomator"), &meta.passphrase)
        .unwrap();
    let library_backups = backups(&vault);
    assert_eq!(library_backups.len(), 1, "{library_backups:?}");

    let (result, seen) = migrate_collecting(&vault, &meta.passphrase);

    let err = result.unwrap_err();
    assert!(
        matches!(&err, CoreError::MigrationBlocked(msg) if msg.contains("6->7")),
        "{err}"
    );
    assert_eq!(
        seen,
        [
            MigrationEvent::StepStarted {
                step: MigrationStep::FiveToSix
            },
            MigrationEvent::StepFinished {
                step: MigrationStep::FiveToSix,
                version: VaultVersion::V6
            }
        ]
    );

    assert_eq!(determine_vault_version(&vault).unwrap(), 6);
    assert_eq!(migration::detect_version(&vault).unwrap(), VaultVersion::V6);
    let after = access
        .load(&vault.join("masterkey.cryptomator"), &meta.passphrase_nfc)
        .expect("the NFC form opens it now");
    assert_eq!(
        before.raw(),
        after.raw(),
        "the masterkey itself is unchanged"
    );
    assert!(
        access
            .load(&vault.join("masterkey.cryptomator"), &meta.passphrase)
            .is_err(),
        "the NFD form no longer opens the vault"
    );

    // The old key file is backed up under our own SHA-256 name, next to the one cryptofs 1.3.2
    // left behind — which is untouched.
    let now = backups(&vault);
    assert_eq!(now.len(), 2, "{now:?}");
    for (path, digest) in &library_backups {
        assert_eq!(now.get(path), Some(digest), "{}", path.display());
    }
}

#[test]
fn seven_to_eight_writes_a_vault_config_with_siv_ctrmac_and_the_vault_opens() {
    let (_tmp, vault) = common::fixture_copy_at("legacy_v7");
    let meta = legacy_meta("legacy_v7");
    let library_backups = backups(&vault);

    let (result, seen) = migrate_collecting(&vault, &meta.passphrase);

    assert_eq!(result.unwrap(), VaultVersion::V8);
    assert_eq!(
        seen,
        [
            MigrationEvent::StepStarted {
                step: MigrationStep::SevenToEight
            },
            MigrationEvent::StepFinished {
                step: MigrationStep::SevenToEight,
                version: VaultVersion::V8
            }
        ]
    );

    let config = cryptomator_core::read_vault_config(&vault).unwrap();
    assert_eq!(config.alleged_vault_version(), Some(8));
    assert_eq!(config.alleged_cipher_combo().as_deref(), Some("SIV_CTRMAC"));
    assert_eq!(config.alleged_shortening_threshold(), Some(220));
    assert_eq!(
        config.key_id().unwrap().require_masterkey_file().unwrap(),
        "masterkey.cryptomator"
    );
    // The masterkey file carries the format 8 placeholder and opens with the same passphrase.
    assert_eq!(
        MasterkeyFileAccess::read_alleged_vault_version(
            &std::fs::read(vault.join("masterkey.cryptomator")).unwrap()
        )
        .unwrap(),
        999
    );
    assert_eq!(determine_vault_state(&vault).unwrap(), VaultState::Locked);

    // The full content check: the migrated vault reads back as the manifest describes it.
    let opened = cryptomator_core::open_vault(
        &vault,
        &MasterkeyFileAccess::new(Vec::new()),
        &meta.passphrase,
    )
    .unwrap();
    let fs = CryptoFs::open(
        opened,
        CryptoFsOptions {
            read_only: true,
            ..Default::default()
        },
    );
    let mut actual = Vec::new();
    crypto_fs_tree(&fs, &CleartextPath::root(), &mut actual);
    fs.close().unwrap();
    actual.sort();
    let mut expected = meta.expected;
    expected.sort();
    assert_eq!(actual, expected);

    for (path, digest) in &library_backups {
        assert_eq!(
            backups(&vault).get(path),
            Some(digest),
            "{}: the library's own backup is untouched",
            path.display()
        );
    }
}

#[test]
fn seven_to_eight_refuses_to_overwrite_an_existing_config() {
    let (_tmp, vault) = common::fixture_copy_at("legacy_v7");
    let meta = legacy_meta("legacy_v7");
    std::fs::write(vault.join("vault.cryptomator"), b"not a jwt").unwrap();
    let err = migration::v8::migrate(&vault, &meta.passphrase, &mut OsRng).unwrap_err();
    assert!(
        matches!(&err, CoreError::MigrationBlocked(msg) if msg.contains("vault.cryptomator")),
        "{err}"
    );
    assert_eq!(
        std::fs::read(vault.join("vault.cryptomator")).unwrap(),
        b"not a jwt"
    );
}

#[test]
fn a_wrong_passphrase_changes_nothing() {
    let (_tmp, vault) = common::fixture_copy_at("legacy_v7");
    let before = digests(&vault);
    let (result, seen) = migrate_collecting(&vault, "wrong");
    assert!(matches!(result, Err(CoreError::InvalidPassphrase)));
    assert!(seen.is_empty());
    assert_eq!(digests(&vault), before, "not a byte moved");
    assert!(!vault.join("vault.cryptomator").exists());
}

#[test]
fn migrating_a_format_eight_vault_is_a_no_op() {
    let (_tmp, vault) = common::fixture_copy_at("siv_gcm_basic");
    let before = digests(&vault);
    let (result, seen) = migrate_collecting(&vault, common::PASSPHRASE);
    assert_eq!(result.unwrap(), VaultVersion::V8);
    assert!(seen.is_empty(), "{seen:?}");
    assert_eq!(
        digests(&vault),
        before,
        "an up-to-date vault is not touched"
    );
}
