//! The three legacy reference vaults (`tests/fixtures/legacy_v{5,6,7}`, written by cryptofs 1.3.2,
//! 1.8.9 and 1.9.15): what the version detection makes of them, and what their manifests promise the
//! later migration tests. Regenerate them with `tools/fixture-gen/legacy-v{5,6,7}` — see
//! `tools/fixture-gen/README.md`.
//!
//! The second half of the file migrates copies of those vaults: version detection, the plan and
//! the dry run, the three steps one by one and the whole 5 → 8 chain.
mod common;

use common::ExpectedEntry;
use cryptomator_core::fs::{CleartextPath, CryptoFs, CryptoFsOptions};
use cryptomator_core::migration::{
    self, MigrationEvent, MigrationOptions, MigrationStep, VaultVersion,
};
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

/// A migration that may walk the whole vault if it has to — what `crypto migrate --yes` asks for.
const FULL_SCAN: MigrationOptions = MigrationOptions {
    full_scan_allowed: true,
    dry_run: false,
};

/// Runs a migration and returns both its outcome and the progress events it reported.
fn migrate_collecting(
    vault: &Path,
    passphrase: &str,
) -> (Result<VaultVersion, CoreError>, Vec<MigrationEvent>) {
    migrate_collecting_with(vault, passphrase, FULL_SCAN)
}

fn migrate_collecting_with(
    vault: &Path,
    passphrase: &str,
    options: MigrationOptions,
) -> (Result<VaultVersion, CoreError>, Vec<MigrationEvent>) {
    let mut seen = Vec::new();
    let result = migration::migrate(vault, passphrase, options, &mut |event| seen.push(event));
    (result, seen)
}

/// The steps a run reported, without the per-file progress of the 6 → 7 pass.
fn step_events(seen: &[MigrationEvent]) -> Vec<MigrationEvent> {
    seen.iter()
        .filter(|e| !matches!(e, MigrationEvent::StepProgress { .. }))
        .copied()
        .collect()
}

/// Every path below `d/`, relative to the vault, sorted.
fn data_paths(vault: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![vault.join("d")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let path = entry.path();
            out.push(path.strip_prefix(vault).unwrap().to_path_buf());
            if entry.file_type().unwrap().is_dir() {
                stack.push(path);
            }
        }
    }
    out.sort();
    out
}

/// Opens a migrated vault and returns its cleartext tree in the manifest's shape.
fn migrated_tree(vault: &Path, passphrase: &str) -> Vec<ExpectedEntry> {
    let opened =
        cryptomator_core::open_vault(vault, &MasterkeyFileAccess::new(Vec::new()), passphrase)
            .expect("the migrated vault opens");
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
    actual
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
        // Only a chain containing the 6 -> 7 step renames anything; formats 5 and 6 share the
        // on-disk layout, so a format 5 vault can already be listed.
        assert_eq!(
            plan.renames.is_empty(),
            !steps.contains(&MigrationStep::SixToSeven),
            "{name}: {} renames",
            plan.renames.len()
        );
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

/// The 5 → 6 step on its own: the key file is re-wrapped with the NFC passphrase and nothing else
/// moves. Backups included, because this is the first step of the chain to write one.
#[test]
fn five_to_six_rewraps_the_key_file_with_the_nfc_passphrase() {
    let (_tmp, vault) = common::fixture_copy_at("legacy_v5");
    let meta = legacy_meta("legacy_v5");
    let access = MasterkeyFileAccess::new(Vec::new());
    let before = access
        .load(&vault.join("masterkey.cryptomator"), &meta.passphrase)
        .unwrap();
    let library_backups = backups(&vault);
    assert_eq!(library_backups.len(), 1, "{library_backups:?}");
    let data_before = digests(&vault.join("d"));

    migration::v6::migrate(&vault, &meta.passphrase, &mut OsRng).unwrap();

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
    assert_eq!(
        digests(&vault.join("d")),
        data_before,
        "no ciphertext moved"
    );

    // The old key file is backed up under our own SHA-256 name, next to the one cryptofs 1.3.2
    // left behind — which is untouched.
    let now = backups(&vault);
    assert_eq!(now.len(), 2, "{now:?}");
    for (path, digest) in &library_backups {
        assert_eq!(now.get(path), Some(digest), "{}", path.display());
    }
}

/// The 6 → 7 step against the reference vault: every BASE32 name is gone, the metadata directory
/// with it, and the masterkey file carries version 7.
#[test]
fn six_to_seven_renames_every_node_and_drops_the_metadata_dir() {
    let (_tmp, vault) = common::fixture_copy_at("legacy_v6");
    let meta = legacy_meta("legacy_v6");
    let planned = migration::v7::plan_renames(&vault).unwrap();
    assert!(planned.len() >= 6, "{planned:#?}");
    assert!(
        planned.iter().all(|r| name_of(&r.to).ends_with(".c9r")
            || name_of(&r.to).ends_with(".c9s")
            || r.to
                .parent()
                .is_some_and(|p| name_of(p).ends_with(".c9r") || name_of(p).ends_with(".c9s"))),
        "{planned:#?}"
    );
    let long_node = planned
        .iter()
        .find(|r| r.from.to_string_lossy().ends_with(".lng"))
        .expect("legacy_v6 has a shortened name");
    assert!(
        name_of(long_node.to.parent().unwrap()).ends_with(".c9s"),
        "a 272-character BASE32 name is 232 characters as base64 and must be shortened again: {long_node:#?}"
    );

    migration::v7::migrate(&vault, &meta.passphrase, true, &mut OsRng).unwrap();

    assert_eq!(determine_vault_version(&vault).unwrap(), 7);
    assert_eq!(migration::detect_version(&vault).unwrap(), VaultVersion::V7);
    assert!(!vault.join("m").exists(), "the metadata directory is gone");
    // Nothing below `d/` is a legacy name any more: the two- and thirty-character hash directories
    // stay, everything else is a `.c9r`/`.c9s` node or one of the four files inside one.
    for path in data_paths(&vault) {
        let name = name_of(&path);
        let depth = path.components().count();
        assert!(
            depth <= 3 && (name.len() == 2 || name.len() == 30)
                || name.ends_with(".c9r")
                || name.ends_with(".c9s"),
            "{path:?} is still a legacy name"
        );
    }
    // Every rename the plan announced happened.
    for rename in &planned {
        assert!(
            vault.join(&rename.to).exists(),
            "{rename:?} was planned but is not there"
        );
        assert!(
            !vault.join(&rename.from).exists(),
            "{rename:?} is still there"
        );
    }
}

/// `plan` is the dry run: it lists every rename and leaves the vault exactly as it found it.
#[test]
fn the_dry_run_lists_every_rename_and_writes_nothing() {
    let (_tmp, vault) = common::fixture_copy_at("legacy_v6");
    let meta = legacy_meta("legacy_v6");
    let before = digests(&vault);

    let plan = migration::plan(&vault, &meta.passphrase).unwrap();
    assert_eq!(
        plan.steps,
        [MigrationStep::SixToSeven, MigrationStep::SevenToEight]
    );
    // One rename per file below `d/`.
    let files_below_d = data_paths(&vault)
        .iter()
        .filter(|p| vault.join(p).is_file())
        .count();
    assert_eq!(plan.renames.len(), files_below_d, "{:#?}", plan.renames);
    assert!(plan.renames.iter().all(|r| r.from.starts_with("d")
        && r.to.starts_with("d")
        && r.from.is_relative()
        && r.to.is_relative()));
    // Sorted, deduplicated and deterministic: a second run says exactly the same.
    assert_eq!(
        migration::plan(&vault, &meta.passphrase).unwrap().renames,
        plan.renames
    );

    // `migrate` with `dry_run` is the same promise from the other entry point.
    let (result, seen) = migrate_collecting_with(
        &vault,
        &meta.passphrase,
        MigrationOptions {
            full_scan_allowed: true,
            dry_run: true,
        },
    );
    assert_eq!(result.unwrap(), VaultVersion::V6);
    assert!(seen.is_empty(), "{seen:?}");
    assert_eq!(digests(&vault), before, "not a byte moved");
    assert!(
        vault.join("m").is_dir(),
        "the metadata directory is still there"
    );
}

/// The whole chain, on all three legacy vaults: the migrated vault opens with the (NFC) passphrase
/// and holds exactly the tree its manifest describes.
#[test]
fn the_whole_chain_from_five_to_eight_produces_a_readable_vault() {
    for (name, expected_steps) in [
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
        let (_tmp, vault) = common::fixture_copy_at(name);
        let meta = legacy_meta(name);

        let (result, seen) = migrate_collecting(&vault, &meta.passphrase);

        assert_eq!(result.unwrap(), VaultVersion::V8, "{name}");
        assert_eq!(determine_vault_version(&vault).unwrap(), 8, "{name}");
        let expected_events: Vec<MigrationEvent> = expected_steps
            .iter()
            .flat_map(|step| {
                [
                    MigrationEvent::StepStarted { step: *step },
                    MigrationEvent::StepFinished {
                        step: *step,
                        version: step.to(),
                    },
                ]
            })
            .collect();
        assert_eq!(step_events(&seen), expected_events, "{name}");
        assert_eq!(
            seen.iter()
                .any(|e| matches!(e, MigrationEvent::StepProgress { .. })),
            expected_steps.contains(&MigrationStep::SixToSeven),
            "{name}: only the 6 -> 7 step reports per-file progress"
        );
        assert!(!vault.join("m").exists(), "{name}: no metadata directory");

        // The NFC form is the one that opens a migrated vault; for v5 that is not what the user
        // typed, and the chain carried the normalised form forward on its own.
        let mut expected = meta.expected;
        expected.sort();
        assert_eq!(
            migrated_tree(&vault, &meta.passphrase_nfc),
            expected,
            "{name}: the migrated vault holds a different tree"
        );

        // And the health checks find nothing worse than the directory ID backups the pre-format-8
        // formats never wrote (`dirid.c9r` arrived with format 8).
        let opened = cryptomator_core::open_vault(
            &vault,
            &MasterkeyFileAccess::new(Vec::new()),
            &meta.passphrase_nfc,
        )
        .unwrap();
        let ctx = cryptomator_core::CheckContext::from_opened(opened);
        let results =
            cryptomator_core::run_checks(&cryptomator_core::CHECK_IDS, &ctx, &mut |_| {}).unwrap();
        let unexpected: Vec<_> = results
            .iter()
            .filter(|r| {
                r.severity > cryptomator_core::Severity::Good && r.kind != "MissingDirIdBackup"
            })
            .collect();
        assert!(unexpected.is_empty(), "{name}: {unexpected:#?}");
    }
}

/// A target that is already taken gets the `_1` suffix a later Cryptomator resolves as a conflict.
#[test]
fn a_taken_target_name_gets_an_attempt_suffix() {
    let (_tmp, vault) = common::fixture_copy_at("legacy_v6");
    let meta = legacy_meta("legacy_v6");
    // A plain file rename: the target is the node itself, not a directory around it.
    let plan = migration::v7::plan_renames(&vault).unwrap();
    let rename = plan
        .iter()
        .find(|r| name_of(&r.to).ends_with(".c9r") && !r.from.to_string_lossy().ends_with(".lng"))
        .expect("a regular file")
        .clone();
    let source_bytes = std::fs::read(vault.join(&rename.from)).unwrap();
    std::fs::write(vault.join(&rename.to), b"squatter").unwrap();

    migration::v7::migrate(&vault, &meta.passphrase, true, &mut OsRng).unwrap();

    let with_suffix = rename
        .to
        .with_file_name(name_of(&rename.to).replace(".c9r", "_1.c9r"));
    assert_eq!(
        std::fs::read(vault.join(&with_suffix)).unwrap(),
        source_bytes,
        "{with_suffix:?} should hold the migrated node"
    );
    assert_eq!(
        std::fs::read(vault.join(&rename.to)).unwrap(),
        b"squatter",
        "the file that was in the way is untouched"
    );
    assert!(!vault.join(&rename.from).exists());
}

/// Resumability: a run that was interrupted halfway leaves a vault whose names are half migrated.
/// The next run has to skip what is done and finish the rest.
#[test]
fn a_half_migrated_vault_is_picked_up_where_it_stopped() {
    let (_tmp, vault) = common::fixture_copy_at("legacy_v6");
    let meta = legacy_meta("legacy_v6");

    // Migrate every second node by hand, exactly as an interrupted run would have left them.
    let files: Vec<PathBuf> = data_paths(&vault)
        .into_iter()
        .map(|p| vault.join(p))
        .filter(|p| p.is_file())
        .collect();
    let mut migrated_by_hand = 0;
    for file in files.iter().step_by(2) {
        let migration = cryptomator_core::migration::v7::FilePathMigration::parse(&vault, file)
            .unwrap()
            .expect("a legacy name");
        migration.migrate().unwrap();
        migrated_by_hand += 1;
    }
    assert!(
        migrated_by_hand >= 3,
        "{migrated_by_hand} nodes pre-migrated"
    );
    assert_eq!(
        determine_vault_version(&vault).unwrap(),
        6,
        "the interrupted run never got to the masterkey file"
    );
    // The planner now only lists what is left.
    assert_eq!(
        migration::v7::plan_renames(&vault).unwrap().len(),
        files.len() - migrated_by_hand
    );

    let (result, _) = migrate_collecting(&vault, &meta.passphrase);
    assert_eq!(result.unwrap(), VaultVersion::V8);

    let mut expected = meta.expected;
    expected.sort();
    assert_eq!(migrated_tree(&vault, &meta.passphrase_nfc), expected);
}

/// The masterkey file is stamped as the *last* action of the 6 → 7 step: a run that dies in the
/// middle of the renames leaves a format 6 vault, which the next run migrates from the start.
#[test]
fn the_masterkey_is_stamped_only_after_every_rename() {
    if is_root() {
        return; // root writes into a read-only directory, so there is nothing to interrupt
    }
    use std::os::unix::fs::PermissionsExt;
    let (_tmp, vault) = common::fixture_copy_at("legacy_v6");
    let meta = legacy_meta("legacy_v6");
    // The content directory with the most nodes; making it read-only fails the rename pass in the
    // middle, after the earlier directories have been migrated.
    let content_dir = std::fs::read_dir(vault.join("d"))
        .unwrap()
        .flatten()
        .flat_map(|hash_dir| std::fs::read_dir(hash_dir.path()).unwrap().flatten())
        .max_by_key(|d| std::fs::read_dir(d.path()).unwrap().count())
        .unwrap()
        .path();
    std::fs::set_permissions(&content_dir, std::fs::Permissions::from_mode(0o500)).unwrap();

    let (result, _) = migrate_collecting(&vault, &meta.passphrase);

    std::fs::set_permissions(&content_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let err = result.unwrap_err();
    assert!(matches!(&err, CoreError::Io(_)), "{err}");
    assert_eq!(
        determine_vault_version(&vault).unwrap(),
        6,
        "the vault is still at format 6"
    );
    assert!(
        vault.join("m").is_dir(),
        "the metadata directory survives an interrupted run"
    );
    assert!(!vault.join("vault.cryptomator").exists());

    // With the directory writable again the chain finishes, half-migrated names and all.
    let (result, _) = migrate_collecting(&vault, &meta.passphrase);
    assert_eq!(result.unwrap(), VaultVersion::V8);
    let mut expected = meta.expected;
    expected.sort();
    assert_eq!(migrated_tree(&vault, &meta.passphrase_nfc), expected);
}

/// Without `full_scan_allowed` a storage that cannot hold 220-character names is refused rather
/// than half migrated. The local file system can hold them, so the refusal is asserted where it is
/// decided: `filename_limit >= 220` means no scan is needed at all.
#[test]
fn a_vault_that_needs_a_full_scan_is_refused_without_permission() {
    let (_tmp, vault) = common::fixture_copy_at("legacy_v6");
    let meta = legacy_meta("legacy_v6");
    // The probe finds the full 220 characters here, so the migration proceeds without asking.
    let (result, _) = migrate_collecting_with(
        &vault,
        &meta.passphrase,
        MigrationOptions {
            full_scan_allowed: false,
            dry_run: false,
        },
    );
    assert_eq!(result.unwrap(), VaultVersion::V8);
}

/// The unreferenced `m/xx/yy/*.lng` the 1.x releases left behind is not a migration error: `d/` is
/// the only tree that is walked, and `m/` is deleted wholesale.
#[test]
fn an_unreferenced_metadata_entry_is_ignored() {
    let (_tmp, vault) = common::fixture_copy_at("legacy_v5");
    let meta = legacy_meta("legacy_v5");
    let referenced: Vec<String> = walk_names(&vault.join("d"))
        .filter(|n| n.ends_with(".lng"))
        .collect();
    let in_metadata: Vec<String> = walk_names(&vault.join("m")).collect();
    let unreferenced: Vec<&String> = in_metadata
        .iter()
        .filter(|n| n.ends_with(".lng") && !referenced.contains(n))
        .collect();
    assert_eq!(unreferenced.len(), 1, "{in_metadata:?}");

    let (result, _) = migrate_collecting(&vault, &meta.passphrase);
    assert_eq!(result.unwrap(), VaultVersion::V8);
    assert!(!vault.join("m").exists());
}

fn name_of(path: &Path) -> String {
    path.file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned()
}

/// Tests that turn permission bits into an expectation are meaningless as root.
fn is_root() -> bool {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).trim() == "0")
        .unwrap_or(false)
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
