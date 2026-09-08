//! `crypto recovery-key restore` end to end: the three modes, the cipher-combo detection, the
//! backups and the exit codes.
//!
//! Every vault is a temp copy of a fixture (`Sandbox::add_fixture`) or a vault created for the
//! test; the fixtures themselves are read-only. Recovery keys and passwords travel through stdin,
//! files or a named environment variable -- never on the command line.
mod common;

use common::{Sandbox, PW};
use predicates::prelude::*;
use serde_json::Value;
use std::path::Path;

const NEW_PW: &str = "brand-new-pass-1";

/// The vault's recovery key, as `crypto recovery-key show` prints it.
fn recovery_key(fx: &Sandbox, vault: &str) -> String {
    let out = fx
        .crypto(&["recovery-key", "show", vault])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    String::from_utf8(out).unwrap().trim().to_string()
}

/// Removes every `<prefix>*.bkup` in `vault`.
///
/// Load-bearing in every test that deletes a key file: `determine_vault_state` restores a missing
/// `vault.cryptomator` / `masterkey.cryptomator` from the newest backup next to it
/// (`BackupRestorer.restoreIfBackupPresent`), so a fixture's own `.bkup` would undo the damage
/// before `restore` ever runs.
fn remove_backups(vault: &Path, prefix: &str) {
    for entry in std::fs::read_dir(vault).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(prefix) && name.ends_with(".bkup") {
            std::fs::remove_file(entry.path()).unwrap();
        }
    }
}

fn delete_key_file(vault: &Path, name: &str) {
    std::fs::remove_file(vault.join(name)).unwrap();
    remove_backups(vault, name);
}

fn json_of(output: &[u8]) -> Value {
    serde_json::from_slice(output).unwrap()
}

/// A masterkey file that is gone comes back from the recovery key, with a password of the user's
/// choosing; the old one stops working.
#[test]
fn restore_masterkey_rebuilds_a_lost_masterkey_file() {
    let fx = Sandbox::new();
    let path = fx.add_fixture("siv_gcm_basic");
    let key = recovery_key(&fx, "siv_gcm_basic");
    delete_key_file(&path, "masterkey.cryptomator");

    let out = fx
        .crypto(&[
            "--json",
            "recovery-key",
            "restore",
            "siv_gcm_basic",
            "--masterkey",
            "--recovery-key-stdin",
            "--new-password-env",
            "NP",
        ])
        .env("NP", NEW_PW)
        .write_stdin(format!("{key}\n"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value = json_of(&out);
    assert_eq!(value["restored"], serde_json::json!(["masterkey"]));
    // Only `--all` and `--config` write a config, so there is no combo to report here.
    assert!(value["cipherCombo"].is_null());
    assert!(value["shorteningThreshold"].is_null());
    // The file was gone, so nothing was replaced and nothing was backed up.
    assert_eq!(value["backups"], serde_json::json!([]));
    assert_eq!(value["keychainUpdated"], false);
    assert!(path.join("masterkey.cryptomator").is_file());

    fx.crypto(&["fs", "ls", "siv_gcm_basic", "/"])
        .env("CRYPTO_PASSWORD", NEW_PW)
        .assert()
        .success()
        .stdout(predicate::str::contains("hello.txt"));
    fx.crypto(&["fs", "ls", "siv_gcm_basic", "/"])
        .assert()
        .code(4);
}

/// A lost `vault.cryptomator` is rebuilt from the masterkey file and the vault password, and the
/// cipher combo is read out of the vault rather than guessed.
#[test]
fn restore_config_rebuilds_a_lost_vault_config_and_detects_the_combo() {
    for (fixture, combo) in [
        ("siv_gcm_basic", "SIV_GCM"),
        ("siv_ctrmac_basic", "SIV_CTRMAC"),
    ] {
        let fx = Sandbox::new();
        let path = fx.add_fixture(fixture);
        delete_key_file(&path, "vault.cryptomator");

        let out = fx
            .crypto(&[
                "--json",
                "recovery-key",
                "restore",
                fixture,
                "--config",
                "--password-stdin",
            ])
            .write_stdin(format!("{PW}\n"))
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let value = json_of(&out);
        assert_eq!(
            value["restored"],
            serde_json::json!(["config"]),
            "{fixture}"
        );
        assert_eq!(value["cipherCombo"], combo, "{fixture}");
        assert_eq!(value["shorteningThreshold"], 220, "{fixture}");
        assert_eq!(value["keychainUpdated"], false);

        fx.crypto(&["fs", "ls", fixture, "/"])
            .assert()
            .success()
            .stdout(predicate::str::contains("hello.txt"));
    }
}

/// Both files at once, from the recovery key alone.
#[test]
fn restore_all_rebuilds_both_files_from_the_recovery_key() {
    let fx = Sandbox::new();
    let path = fx.add_fixture("siv_ctrmac_basic");
    let key = recovery_key(&fx, "siv_ctrmac_basic");
    for name in ["masterkey.cryptomator", "vault.cryptomator"] {
        delete_key_file(&path, name);
    }

    let out = fx
        .crypto(&[
            "--json",
            "recovery-key",
            "restore",
            "siv_ctrmac_basic",
            "--all",
            "--recovery-key-stdin",
            "--new-password-env",
            "NP",
        ])
        .env("NP", NEW_PW)
        .write_stdin(format!("{key}\n"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value = json_of(&out);
    assert_eq!(
        value["restored"],
        serde_json::json!(["masterkey", "config"])
    );
    assert_eq!(value["cipherCombo"], "SIV_CTRMAC", "detected, not guessed");
    assert_eq!(value["shorteningThreshold"], 220);
    assert!(path.join("masterkey.cryptomator").is_file());
    assert!(path.join("vault.cryptomator").is_file());

    fx.crypto(&["fs", "cat", "siv_ctrmac_basic", "/hello.txt"])
        .env("CRYPTO_PASSWORD", NEW_PW)
        .assert()
        .success()
        .stdout(predicate::str::contains("Hello, Cryptomator!"));
}

/// The recovery key of *another* vault is refused before anything is written -- the surviving
/// `vault.cryptomator` is what proves the key belongs here.
#[test]
fn a_foreign_recovery_key_is_exit_four_and_writes_nothing() {
    let fx = Sandbox::new();
    let path = fx.add_fixture("siv_gcm_basic");
    let other = fx.path("other");
    let out = fx
        .crypto(&["--json", "vault", "create", "--show-recovery-key"])
        .arg(&other)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let foreign = json_of(&out)["recoveryKey"].as_str().unwrap().to_string();
    delete_key_file(&path, "masterkey.cryptomator");

    for key in [foreign.as_str(), "pathway lift"] {
        fx.crypto(&[
            "recovery-key",
            "restore",
            "siv_gcm_basic",
            "--masterkey",
            "--recovery-key-stdin",
            "--new-password-env",
            "NP",
        ])
        .env("NP", NEW_PW)
        .write_stdin(format!("{key}\n"))
        .assert()
        .code(4);
        assert!(
            !path.join("masterkey.cryptomator").exists(),
            "a rejected key must not leave a masterkey file behind"
        );
    }
}

/// A vault that holds nothing but its (empty) root directory gives the detection nothing to work
/// with; the command says which flag settles it, and with that flag it works.
#[test]
fn a_vault_without_files_needs_the_cipher_combo_to_be_named() {
    let fx = Sandbox::new();
    let vault = fx.path("v");
    fx.crypto(&["vault", "create"])
        .arg(&vault)
        .assert()
        .success();
    fx.crypto(&["fs", "rm", "v", "/WELCOME.rtf"])
        .assert()
        .success();
    delete_key_file(&vault, "vault.cryptomator");

    fx.crypto(&["recovery-key", "restore", "v", "--config"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--cipher-combo"));
    assert!(!vault.join("vault.cryptomator").exists());

    let out = fx
        .crypto(&[
            "--json",
            "recovery-key",
            "restore",
            "v",
            "--config",
            "--cipher-combo",
            "SIV_GCM",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(json_of(&out)["cipherCombo"], "SIV_GCM");
    fx.crypto(&["fs", "ls", "v", "/"]).assert().success();
}

/// `--shortening-threshold` reaches the new config, and the vault still opens with it.
#[test]
fn the_shortening_threshold_reaches_the_restored_config() {
    let fx = Sandbox::new();
    let path = fx.add_fixture("siv_gcm_basic");
    delete_key_file(&path, "vault.cryptomator");

    let out = fx
        .crypto(&[
            "--json",
            "recovery-key",
            "restore",
            "siv_gcm_basic",
            "--config",
            "--shortening-threshold",
            "100",
            "--password-stdin",
        ])
        .write_stdin(format!("{PW}\n"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(json_of(&out)["shorteningThreshold"], 100);

    let info = fx
        .crypto(&["--json", "vault", "info", "siv_gcm_basic"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(json_of(&info)["shorteningThreshold"], 100);
}

/// A config that is *replaced* rather than missing is copied to a `.bkup` first, and the command
/// says where.
#[test]
fn a_replaced_file_is_backed_up_and_reported() {
    let fx = Sandbox::new();
    let path = fx.add_fixture("siv_gcm_basic");
    // The fixture ships a backup of exactly this config; `attempt_backup` never overwrites, so
    // without this the run would find its backup already there and report none.
    remove_backups(&path, "vault.cryptomator");
    let before = std::fs::read(path.join("vault.cryptomator")).unwrap();

    let out = fx
        .crypto(&[
            "--json",
            "recovery-key",
            "restore",
            "siv_gcm_basic",
            "--config",
            "--password-stdin",
        ])
        .write_stdin(format!("{PW}\n"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let backups = json_of(&out)["backups"].as_array().unwrap().clone();
    assert_eq!(backups.len(), 1, "one file was replaced");
    // The reported path is the one the settings hold, which may be the canonicalised form of the
    // sandbox path (`/private/var/...` on macOS); compare the file name and the content, not the
    // prefix.
    let backup = Path::new(backups[0].as_str().unwrap()).to_path_buf();
    assert!(backup
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("vault.cryptomator."));
    assert!(backup.is_file(), "{} does not exist", backup.display());
    assert_eq!(
        std::fs::read(&backup).unwrap(),
        before,
        "the backup holds the config that was replaced"
    );
    assert_ne!(
        std::fs::read(path.join("vault.cryptomator")).unwrap(),
        before,
        "and a new one was written"
    );
}

/// A stored password follows the restore, exactly as it follows `password change` and
/// `recovery-key reset-password`; otherwise every later unlock would fail with a stale entry.
#[test]
fn a_stored_password_follows_a_masterkey_restore() {
    let fx = Sandbox::new();
    let path = fx.add_fixture("siv_gcm_basic");
    let key = recovery_key(&fx, "siv_gcm_basic");
    let id = fx.vault_id(0);
    fx.seed_keychain(&id, "siv_gcm_basic", PW);
    delete_key_file(&path, "masterkey.cryptomator");

    let out = fx
        .crypto_keychain(&[
            "--json",
            "recovery-key",
            "restore",
            "siv_gcm_basic",
            "--masterkey",
            "--recovery-key-stdin",
            "--new-password-env",
            "NP",
        ])
        .env("NP", NEW_PW)
        .write_stdin(format!("{key}\n"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(json_of(&out)["keychainUpdated"], true);
    assert_eq!(fx.fake_keychain_json()[&id]["password"], NEW_PW);
    // The stored password is the only source here, and it opens the restored vault.
    fx.crypto_keychain(&["fs", "ls", "siv_gcm_basic", "/"])
        .assert()
        .success()
        .stdout(predicate::str::contains("hello.txt"));
}

/// A vault a daemon is serving keeps its key files: its key is live in another process.
#[test]
fn restore_refuses_a_vault_a_daemon_is_serving() {
    /// Locks whatever the test unlocked, also when an assertion panicked half way through.
    struct Unlocked(Sandbox);
    impl Drop for Unlocked {
        fn drop(&mut self) {
            let _ = self.0.crypto_daemon(&["lock", "--all"]).ok();
        }
    }

    let fx = Sandbox::new();
    fx.write_cli_config();
    fx.crypto(&["vault", "create"])
        .arg(fx.path("v"))
        .assert()
        .success();
    fx.crypto_daemon(&["unlock", "v", "--mounter", "null"])
        .assert()
        .success();
    let fx = Unlocked(fx);

    fx.0.crypto_daemon(&["recovery-key", "restore", "v", "--config"])
        .assert()
        .code(5)
        .stderr(predicate::str::contains("UNLOCKED"));
}

/// The grammar: exactly one mode, and a recovery key exactly where one belongs.
#[test]
fn restore_rejects_the_combinations_that_cannot_work() {
    let fx = Sandbox::new();
    fx.add_fixture("siv_gcm_basic");

    // No mode at all, and two modes at once.
    fx.crypto(&["recovery-key", "restore", "siv_gcm_basic"])
        .assert()
        .code(2);
    fx.crypto(&[
        "recovery-key",
        "restore",
        "siv_gcm_basic",
        "--all",
        "--config",
    ])
    .assert()
    .code(2);
    // Both recovery key sources at once.
    fx.crypto(&[
        "recovery-key",
        "restore",
        "siv_gcm_basic",
        "--all",
        "--recovery-key-stdin",
        "--recovery-key-file",
        "/nonexistent",
    ])
    .assert()
    .code(2);
    // A recovery key where the vault password belongs …
    fx.crypto(&[
        "recovery-key",
        "restore",
        "siv_gcm_basic",
        "--config",
        "--recovery-key-stdin",
    ])
    .write_stdin("x\n")
    .assert()
    .code(2)
    .stderr(predicate::str::contains("--all"));
    // … and the other way round.
    fx.crypto(&[
        "recovery-key",
        "restore",
        "siv_gcm_basic",
        "--masterkey",
        "--new-password-env",
        "NP",
    ])
    .env("NP", NEW_PW)
    .assert()
    .code(2)
    .stderr(predicate::str::contains("--recovery-key-stdin"));
    // An unknown cipher combo is a usage error too.
    fx.crypto(&[
        "recovery-key",
        "restore",
        "siv_gcm_basic",
        "--config",
        "--cipher-combo",
        "SIV_CBC",
    ])
    .assert()
    .code(2);
    // The two config settings say nothing about a masterkey file, so `--masterkey` refuses them
    // instead of ignoring them.
    for flag in [
        vec!["--cipher-combo", "SIV_GCM"],
        vec!["--shortening-threshold", "100"],
    ] {
        let mut args = vec![
            "recovery-key",
            "restore",
            "siv_gcm_basic",
            "--masterkey",
            "--recovery-key-stdin",
        ];
        args.extend(flag.iter().copied());
        fx.crypto(&args)
            .write_stdin("x\n")
            .assert()
            .code(2)
            .stderr(predicate::str::contains(flag[0]));
    }
}

/// A legacy vault has no format 8 key files to restore; it is sent to `crypto migrate` instead.
#[test]
fn a_legacy_vault_points_at_the_migrate_command() {
    let fx = Sandbox::new();
    fx.add_fixture("legacy_v7");
    fx.crypto(&["recovery-key", "restore", "legacy_v7", "--config"])
        .assert()
        .code(5)
        .stderr(predicate::str::contains("crypto migrate legacy_v7"));
}
