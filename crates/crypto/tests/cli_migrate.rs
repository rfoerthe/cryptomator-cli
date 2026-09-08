//! `crypto migrate` end to end: the three legacy fixtures, the dry run, the confirmation and the
//! exit codes.
//!
//! Every run passes the passphrase through `--password-stdin`, which outranks the
//! `$CRYPTO_PASSWORD` that [`Sandbox::crypto`] sets -- the legacy fixtures have passphrases of
//! their own. The keychain tests use the *fake* keychain; nothing here ever touches the real one.
mod common;

use common::Sandbox;
use predicates::prelude::*;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Tests that turn permission bits into an expectation are meaningless as root, which ignores
/// them outright.
fn is_root() -> bool {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).trim() == "0")
        .unwrap_or(false)
}

/// The fixture's manifest: the passphrase(s) it was created with and the cleartext tree it holds.
fn manifest(fixture: &str) -> Value {
    let path = common::fixtures_root().join(fixture).join("fixture.json");
    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap()
}

fn passphrase(fixture: &str) -> String {
    manifest(fixture)["passphrase"]
        .as_str()
        .unwrap()
        .to_string()
}

/// `path -> {type, sha256}` of the manifest's `expected` tree, in the shape `crypto fs tree --hash`
/// reports it.
fn expected_tree(fixture: &str) -> BTreeMap<String, Value> {
    manifest(fixture)["expected"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            (
                entry["path"].as_str().unwrap().to_string(),
                serde_json::json!({
                    "type": entry["type"],
                    "sha256": entry.get("sha256").cloned().unwrap_or(Value::Null),
                    "target": entry.get("target").cloned().unwrap_or(Value::Null),
                }),
            )
        })
        .collect()
}

/// The same map, read out of the migrated vault with `crypto fs tree --hash`.
fn actual_tree(fx: &Sandbox, vault: &str, pw: &str) -> BTreeMap<String, Value> {
    let out = fx
        .crypto(&[
            "--json",
            "fs",
            "tree",
            vault,
            "/",
            "--hash",
            "--password-stdin",
        ])
        .write_stdin(format!("{pw}\n"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    serde_json::from_slice::<Value>(&out)
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            (
                entry["path"].as_str().unwrap().to_string(),
                serde_json::json!({
                    "type": entry["type"],
                    "sha256": entry.get("sha256").cloned().unwrap_or(Value::Null),
                    "target": entry.get("target").cloned().unwrap_or(Value::Null),
                }),
            )
        })
        .collect()
}

/// Every path below `vault`, relative and sorted -- what a `--dry-run` must leave exactly as it was.
fn layout(vault: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![vault.to_path_buf()];
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

/// `crypto migrate <args>` with `passphrase` on stdin.
fn migrate(fx: &Sandbox, args: &[&str], pw: &str) -> assert_cmd::Command {
    let mut cmd = fx.crypto(args);
    cmd.arg("--password-stdin").write_stdin(format!("{pw}\n"));
    cmd
}

fn json(out: &[u8]) -> Value {
    serde_json::from_slice(out).unwrap()
}

#[test]
fn migrating_a_v7_vault_makes_it_a_format_8_vault() {
    let fx = Sandbox::new();
    let path = fx.add_fixture("legacy_v7");
    let pw = passphrase("legacy_v7");

    let out = migrate(&fx, &["--json", "migrate", "legacy_v7", "--yes"], &pw)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value = json(&out);
    assert_eq!(value["vault"], fx.vault_id(0));
    assert_eq!(value["from"], 7);
    assert_eq!(value["to"], 8);
    assert_eq!(value["migrated"], true);
    assert_eq!(value["steps"], serde_json::json!(["7->8"]));
    assert_eq!(value["renamed"], 0, "the 7 -> 8 step renames nothing");
    assert!(path.join("vault.cryptomator").is_file());

    // An ordinary format 8 vault from here on: LOCKED, readable, and the tree its manifest promises.
    fx.crypto(&["--json", "vault", "info", "legacy_v7"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"LOCKED\""));
    assert_eq!(
        actual_tree(&fx, "legacy_v7", &pw),
        expected_tree("legacy_v7")
    );

    // The health checks pass: only the `MissingDirIdBackup` findings a format 7 vault cannot have
    // are left, and those are INFO.
    let out = fx
        .crypto(&[
            "--json",
            "health",
            "legacy_v7",
            "--no-report",
            "--password-stdin",
        ])
        .write_stdin(format!("{pw}\n"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let health = json(&out);
    assert_eq!(health["summary"]["critical"], 0, "{health:#}");
    assert_eq!(health["summary"]["warn"], 0, "{health:#}");
    assert!(
        health["summary"]["info"].as_u64().unwrap() > 0,
        "the missing dirid backups are reported as INFO: {health:#}"
    );
}

#[test]
fn migrating_a_v6_vault_renames_the_file_names_and_keeps_the_content() {
    let fx = Sandbox::new();
    fx.add_fixture("legacy_v6");
    let pw = passphrase("legacy_v6");

    let out = migrate(&fx, &["--json", "migrate", "legacy_v6", "--yes"], &pw)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value = json(&out);
    assert_eq!(value["from"], 6);
    assert_eq!(value["to"], 8);
    assert_eq!(value["steps"], serde_json::json!(["6->7", "7->8"]));
    assert!(
        value["renamed"].as_u64().unwrap() > 0,
        "the 6 -> 7 step renamed something: {value:#}"
    );
    // The backups the run itself wrote, and only those: the fixture carries one of its own from
    // the cryptofs release that built it.
    let backups = value["backups"].as_array().unwrap();
    assert!(!backups.is_empty(), "{value:#}");
    for backup in backups {
        let backup = Path::new(backup.as_str().unwrap());
        assert!(backup.is_file(), "{backup:?}");
        assert!(backup.to_string_lossy().ends_with(".bkup"), "{backup:?}");
        assert!(
            !backup.ends_with("masterkey.cryptomator.4E780CE6.bkup"),
            "the fixture's own backup is not one this run wrote"
        );
    }

    // The bytes came through: one file read back through `fs cat` against the manifest's digest.
    let expected = expected_tree("legacy_v6");
    let out = fx
        .crypto(&["fs", "cat", "legacy_v6", "/hello.txt", "--password-stdin"])
        .write_stdin(format!("{pw}\n"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(
        data_encoding::HEXLOWER.encode(&Sha256::digest(&out)),
        expected["/hello.txt"]["sha256"].as_str().unwrap()
    );
    assert_eq!(actual_tree(&fx, "legacy_v6", &pw), expected);
}

/// The 5 → 6 step normalises the passphrase to NFC. The CLI normalises everything it reads to NFC
/// as well, so the NFD form the fixture was created with only ever reaches the vault through
/// `migrate`'s own retry -- and afterwards the NFC form is the passphrase of the vault.
#[test]
fn migrating_a_v5_vault_runs_all_three_steps_and_normalises_the_passphrase() {
    let fx = Sandbox::new();
    fx.add_fixture("legacy_v5");
    let meta = manifest("legacy_v5");
    let nfd = meta["passphrase"].as_str().unwrap().to_string();
    let nfc = meta["passphraseNfc"].as_str().unwrap().to_string();
    assert_ne!(nfd, nfc, "the fixture's two forms differ");

    let out = migrate(&fx, &["--json", "migrate", "legacy_v5", "--yes"], &nfd)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value = json(&out);
    assert_eq!(value["from"], 5);
    assert_eq!(value["to"], 8);
    assert_eq!(value["steps"], serde_json::json!(["5->6", "6->7", "7->8"]));

    // The migrated vault opens with the composed form -- which is what the CLI makes of either
    // spelling from now on.
    assert_eq!(
        actual_tree(&fx, "legacy_v5", &nfc),
        expected_tree("legacy_v5")
    );
}

#[test]
fn a_dry_run_lists_the_renames_and_changes_nothing() {
    let fx = Sandbox::new();
    let path = fx.add_fixture("legacy_v6");
    let pw = passphrase("legacy_v6");
    let before = layout(&path);
    let masterkey_before = std::fs::read(path.join("masterkey.cryptomator")).unwrap();

    let out = migrate(&fx, &["--json", "migrate", "legacy_v6", "--dry-run"], &pw)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value = json(&out);
    assert_eq!(value["dryRun"], true);
    assert_eq!(value["from"], 6);
    assert_eq!(value["to"], 8);
    assert_eq!(value["steps"], serde_json::json!(["6->7", "7->8"]));
    assert!(value.get("migrated").is_none(), "{value:#}");
    let renames = value["renames"].as_array().unwrap();
    assert!(renames.len() >= 6, "{renames:#?}");
    for rename in renames {
        let old = rename["old"].as_str().expect("an old path");
        let new = rename["new"].as_str().expect("a new path");
        assert!(old.starts_with("d/"), "{old}");
        assert!(new.starts_with("d/") && new.contains(".c9"), "{new}");
    }

    assert_eq!(layout(&path), before, "not a file was touched");
    assert!(
        path.join("m").is_dir(),
        "the metadata directory is still there"
    );
    assert!(!path.join("vault.cryptomator").exists());
    // `layout` covers every name, so a backup this run wrote would show up as a new `.bkup` entry
    // -- the fixture brings one of its own from cryptofs 1.x, which is why the assertion is "the
    // same names" rather than "no .bkup at all". The key file itself is compared byte for byte.
    assert_eq!(
        std::fs::read(path.join("masterkey.cryptomator")).unwrap(),
        masterkey_before,
        "the key file was not rewritten"
    );

    // The human form names every rename and says that nothing happened.
    migrate(&fx, &["migrate", "legacy_v6", "--dry-run"], &pw)
        .assert()
        .success()
        .stdout(predicate::str::contains("→"))
        .stdout(predicate::str::contains("--dry-run"));
}

/// A node whose `m/` entry is gone is reported -- by `--dry-run` before anything happens, and by
/// the migration itself afterwards -- and `m/` survives, because it holds the only copy of that
/// node's long name.
#[test]
fn a_node_that_cannot_be_migrated_is_reported_and_keeps_the_metadata_directory() {
    let fx = Sandbox::new();
    let path = fx.add_fixture("legacy_v6");
    let pw = passphrase("legacy_v6");
    let node = break_the_long_name(&path);

    // `--dry-run` first: the skip is announced before a single file is touched.
    let assertion = migrate(&fx, &["--json", "migrate", "legacy_v6", "--dry-run"], &pw)
        .assert()
        .success();
    let value = json(&assertion.get_output().stdout);
    assert_eq!(value["skipped"], serde_json::json!([node]), "{value:#}");
    assert!(
        !value["renames"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["old"] == node.as_str()),
        "{value:#}"
    );
    let stderr = String::from_utf8_lossy(&assertion.get_output().stderr).into_owned();
    assert!(stderr.contains(&node), "{stderr}");
    assert!(stderr.contains("old names"), "{stderr}");
    // The remediation line is wrapped across several string literals in the source; make sure
    // that never leaves a run of two spaces in the rendered text (the path lines above it are
    // deliberately indented by two spaces, so this checks only the remediation sentence itself).
    let remediation = stderr
        .lines()
        .find(|line| line.contains("metadata directory"))
        .unwrap_or_default();
    assert!(!remediation.contains("  "), "{remediation}");

    // And now for real.
    let assertion = migrate(&fx, &["--json", "migrate", "legacy_v6", "--yes"], &pw)
        .assert()
        .success();
    let value = json(&assertion.get_output().stdout);
    assert_eq!(value["to"], 8, "{value:#}");
    assert_eq!(value["migrated"], true, "{value:#}");
    assert_eq!(value["skipped"], serde_json::json!([node]), "{value:#}");
    let stderr = String::from_utf8_lossy(&assertion.get_output().stderr).into_owned();
    assert!(stderr.contains(&node), "{stderr}");

    assert!(
        path.join("m").is_dir(),
        "the metadata directory holds the only copy of the skipped node's name"
    );
    assert!(path.join(&node).is_file(), "{node} was moved after all");

    // The human rendering carries the same summary on stdout.
    let fx2 = Sandbox::new();
    let path2 = fx2.add_fixture("legacy_v6");
    break_the_long_name(&path2);
    migrate(&fx2, &["migrate", "legacy_v6", "--yes"], &pw)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "1 node(s) were left with their old names; see above",
        ));

    // Everything else came through: the manifest's tree minus the one entry whose name is gone.
    let mut expected = expected_tree("legacy_v6");
    expected.retain(|path, _| !path.starts_with("/llll"));
    assert_eq!(actual_tree(&fx, "legacy_v6", &pw), expected);
}

/// Deletes the `m/xx/yy/<32 chars>.lng` entry of `legacy_v6`'s single shortened node and returns
/// that node's vault-relative path.
fn break_the_long_name(vault: &Path) -> String {
    let mut hits: Vec<PathBuf> = layout(vault)
        .into_iter()
        .filter(|path| {
            path.starts_with("d")
                && path
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().ends_with(".lng"))
        })
        .collect();
    hits.sort();
    assert_eq!(hits.len(), 1, "legacy_v6 has exactly one shortened name");
    let node = hits.remove(0);
    let name = node.file_name().unwrap().to_string_lossy().into_owned();
    let deflated = &name[..name.len() - 4];
    let metadata_file = vault
        .join("m")
        .join(&deflated[0..2])
        .join(&deflated[2..4])
        .join(&name);
    std::fs::remove_file(&metadata_file).unwrap();
    node.to_string_lossy().into_owned()
}

#[test]
fn without_yes_and_without_a_terminal_it_is_a_usage_error() {
    let fx = Sandbox::new();
    let path = fx.add_fixture("legacy_v7");
    let before = layout(&path);

    migrate(&fx, &["migrate", "legacy_v7"], &passphrase("legacy_v7"))
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "refusing to migrate without --yes",
        ))
        // Whenever a confirmation would be asked (with `--yes` or `--dry-run` absent, as here),
        // the announcement above the prompt is skipped: `confirm`'s own sentence -- unreachable
        // on this no-terminal path, but the *decision* to skip is made before that check -- would
        // otherwise say the same "format 7, migrating to 8 via 7->8" twice.
        .stderr(predicate::str::contains("migrating to 8 via").not());

    assert_eq!(layout(&path), before, "nothing was migrated");
    assert!(!path.join("vault.cryptomator").exists());
}

#[test]
fn a_vault_that_is_already_current_exits_zero() {
    let fx = Sandbox::new();
    fx.add_fixture("siv_gcm_basic");

    fx.crypto(&["migrate", "siv_gcm_basic", "--yes"])
        .assert()
        .success()
        .stdout(predicate::str::contains("already at format 8"));

    let out = fx
        .crypto(&["--json", "migrate", "siv_gcm_basic", "--yes"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value = json(&out);
    assert_eq!(value["vault"], fx.vault_id(0));
    assert_eq!(value["from"], 8);
    assert_eq!(value["to"], 8);
    assert_eq!(value["migrated"], false);
}

#[test]
fn a_wrong_passphrase_is_exit_four_and_leaves_the_vault_alone() {
    let fx = Sandbox::new();
    let path = fx.add_fixture("legacy_v7");
    let before = layout(&path);

    migrate(&fx, &["migrate", "legacy_v7", "--yes"], "not-the-password")
        .assert()
        .code(4);

    assert_eq!(layout(&path), before, "not a file was touched");
    assert!(!path.join("vault.cryptomator").exists());
}

/// A vault a daemon is serving is refused before the format is even looked at -- the migration
/// renames every file the running mount holds open, and a format 8 vault must be refused for that
/// reason rather than waved through as "already at format 8".
#[test]
fn a_vault_a_daemon_is_serving_is_refused() {
    /// Locks whatever the test unlocked, also when an assertion panicked half way through.
    struct Unlocked(Sandbox);
    impl Drop for Unlocked {
        fn drop(&mut self) {
            let _ = self.0.crypto_daemon(&["lock", "--all"]).ok();
        }
    }

    let fx = Sandbox::new();
    fx.write_cli_config();
    fx.crypto(&["vault", "create", fx.path("v").to_str().unwrap()])
        .assert()
        .success();
    fx.crypto_daemon(&["unlock", "v", "--mounter", "null"])
        .assert()
        .success();
    let fx = Unlocked(fx);

    fx.0.crypto_daemon(&["migrate", "v", "--yes"])
        .assert()
        .code(5)
        .stderr(predicate::str::contains("UNLOCKED"));
}

/// The other half of the same state rule: every command that needs a *locked* vault sends the user
/// to `crypto migrate` when it finds a legacy one.
#[test]
fn a_legacy_vault_points_at_the_migrate_command() {
    let fx = Sandbox::new();
    fx.add_fixture("legacy_v7");
    let pw = passphrase("legacy_v7");

    for args in [
        vec!["fs", "ls", "legacy_v7", "/"],
        vec!["health", "legacy_v7", "--no-report"],
    ] {
        let mut cmd = fx.crypto(&args);
        cmd.arg("--password-stdin").write_stdin(format!("{pw}\n"));
        cmd.assert()
            .code(5)
            .stderr(predicate::str::contains("crypto migrate legacy_v7"));
    }
}

/// A stored passphrase follows the normalisation of the 5 → 6 step, or the next unlock would fail
/// with a password the user never got wrong.
#[test]
fn a_stored_password_follows_the_nfc_normalisation() {
    let fx = Sandbox::new();
    fx.add_fixture("legacy_v5");
    let meta = manifest("legacy_v5");
    let nfd = meta["passphrase"].as_str().unwrap().to_string();
    let nfc = meta["passphraseNfc"].as_str().unwrap().to_string();
    let id = fx.vault_id(0);
    fx.seed_keychain(&id, "legacy_v5", &nfd);

    // No `--password-stdin` here: the seeded entry is the source, as it would be for an unlock.
    let out = fx
        .crypto_keychain(&["--json", "migrate", "legacy_v5", "--yes"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value = json(&out);
    assert_eq!(value["to"], 8);
    assert_eq!(value["keychainUpdated"], true);

    let stored = fx.fake_keychain_json();
    assert_eq!(
        stored[&id]["password"], nfc,
        "the keychain entry followed the migration"
    );
    // And it really opens the migrated vault.
    fx.crypto_keychain(&["fs", "ls", "legacy_v5", "/"])
        .assert()
        .success()
        .stdout(predicate::str::contains("hello.txt"));
}

/// A `--password-stdin` run never reads the keychain for the passphrase (it does not need to),
/// and the NFD retry of a format 5 vault must not turn that into a keychain *write* either: a
/// keychain that is resolved but refuses every call (`crypto_keychain_locked`) would otherwise
/// surface as a warning here, proving the update step probed it even though the read never did.
#[test]
fn a_password_stdin_run_does_not_probe_the_keychain_it_never_read_from() {
    let fx = Sandbox::new();
    fx.add_fixture("legacy_v5");
    let nfd = manifest("legacy_v5")["passphrase"]
        .as_str()
        .unwrap()
        .to_string();

    let assert = fx
        .crypto_keychain_locked(&[
            "--json",
            "migrate",
            "legacy_v5",
            "--yes",
            "--password-stdin",
        ])
        .write_stdin(format!("{nfd}\n"))
        .assert()
        .success();
    let output = assert.get_output();
    let value = json(&output.stdout);
    assert_eq!(value["to"], 8);
    assert_eq!(
        value["keychainUpdated"], false,
        "nothing was stored to begin with, so there is nothing to update either way"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("could not be updated"),
        "the locked keychain was never asked, so it never got the chance to refuse: {stderr}"
    );
}

/// The one command that cannot be undone by re-running it: a chain that dies between two steps
/// must say where the vault ended up, not just what went wrong -- and the next run has to be able
/// to pick it up from there.
#[test]
fn a_run_that_fails_mid_chain_names_the_format_it_stopped_at_and_a_retry_finishes_it() {
    if is_root() {
        return; // root ignores the permission bits, so there is nothing to observe
    }
    use std::os::unix::fs::PermissionsExt;

    let fx = Sandbox::new();
    let path = fx.add_fixture("legacy_v7");
    let pw = passphrase("legacy_v7");

    // `assert_all_capabilities` probes `<vault>/c`, creating it first if it is not there; with it
    // already present that probe never needs to write into the vault root, so making the root
    // read-only fails only the 7 -> 8 step's own write (a new `vault.cryptomator`) -- not the
    // capability check ahead of it, and not the version detection before and after.
    std::fs::create_dir(path.join("c")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o500)).unwrap();

    let assert = migrate(&fx, &["migrate", "legacy_v7", "--yes"], &pw).assert();
    // Restored before any predicate below can panic, so a failing assertion still leaves a
    // directory `Sandbox`'s own `TempDir` can clean up afterwards.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let _ = std::fs::remove_dir_all(path.join("c"));

    assert
        .code(1)
        .stderr(predicate::str::contains("the vault is now at format 7"))
        .stderr(predicate::str::contains("crypto migrate legacy_v7"));
    assert!(
        !path.join("vault.cryptomator").exists(),
        "the 7 -> 8 step never got to write it"
    );

    // The core resumes from whatever format the vault is actually at, exactly as the error said.
    let out = migrate(&fx, &["--json", "migrate", "legacy_v7", "--yes"], &pw)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value = json(&out);
    assert_eq!(value["from"], 7);
    assert_eq!(value["to"], 8);
    assert_eq!(value["migrated"], true);
}
