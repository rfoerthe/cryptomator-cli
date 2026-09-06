mod common;

use assert_cmd::Command;
use common::Sandbox;
use predicates::prelude::*;

#[test]
fn version_flag_prints_name_and_version() {
    Command::cargo_bin("crypto")
        .unwrap()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::starts_with("crypto 0.1.0"));
}

#[test]
fn no_arguments_prints_help_and_exits_with_usage_code() {
    Command::cargo_bin("crypto")
        .unwrap()
        .assert()
        .code(2)
        .stderr(predicate::str::contains("Usage: crypto"));
}

const VALID_KEY: &str = "pathway lift abuse plenty export texture gentleman landscape beyond ceiling around leaf cafe charity border breakdown victory surely computer cat linger restrict infer crowd live computer true written amazed investor boot depth left theory snow whereby terminal weekly reject happiness circuit partial cup ad";

#[test]
fn recovery_key_validate_accepts_valid_key_from_stdin() {
    Command::cargo_bin("crypto")
        .unwrap()
        .args(["recovery-key", "validate", "--recovery-key-stdin"])
        .write_stdin(format!("{VALID_KEY}\n"))
        .assert()
        .success()
        .stdout("valid\n");
}

#[test]
fn recovery_key_validate_rejects_invalid_key_with_exit_code_4() {
    Command::cargo_bin("crypto")
        .unwrap()
        .args(["recovery-key", "validate", "--recovery-key-stdin"])
        .write_stdin("pathway lift\n")
        .assert()
        .code(4)
        .stdout("invalid\n");
}

#[test]
fn recovery_key_validate_json_output() {
    let out = Command::cargo_bin("crypto")
        .unwrap()
        .args(["--json", "recovery-key", "validate", "--recovery-key-stdin"])
        .write_stdin(format!("{VALID_KEY}\n"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&out).unwrap()["valid"],
        true
    );
    let out = Command::cargo_bin("crypto")
        .unwrap()
        .args(["--json", "recovery-key", "validate", "--recovery-key-stdin"])
        .write_stdin("pathway lift\n")
        .assert()
        .code(4)
        .get_output()
        .stdout
        .clone();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&out).unwrap()["valid"],
        false
    );
}

#[test]
fn recovery_key_validate_requires_a_source() {
    Command::cargo_bin("crypto")
        .unwrap()
        .args(["recovery-key", "validate"])
        .assert()
        .code(2);
}

use std::path::{Path, PathBuf};

fn bkup_count(vault: &Path) -> usize {
    std::fs::read_dir(vault)
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".bkup")
        })
        .count()
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

#[test]
fn vault_create_registers_and_writes_vault_files() {
    let sb = Sandbox::new();
    let vault = sb.path("MyVault");
    sb.crypto(&["vault", "create", vault.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Created vault"));
    assert!(vault.join("vault.cryptomator").is_file());
    assert!(vault.join("masterkey.cryptomator").is_file());
    assert!(vault.join("IMPORTANT.rtf").is_file());
    assert!(vault.join("d").is_dir());
    let json = sb.settings_json();
    let dirs = json["directories"].as_array().unwrap();
    assert_eq!(dirs.len(), 1);
    assert_eq!(dirs[0]["id"].as_str().unwrap().len(), 12);
    assert_eq!(dirs[0]["displayName"], "MyVault");
    assert_eq!(
        dirs[0]["path"],
        vault.canonicalize().unwrap().to_str().unwrap()
    );
    assert_eq!(dirs[0]["lastKnownKeyLoader"], "masterkeyfile");
    assert_eq!(
        json["useKeychain"], true,
        "new files carry the Java defaults"
    );
}

#[test]
fn vault_create_json_output_and_recovery_key() {
    let sb = Sandbox::new();
    let vault = sb.path("v");
    let out = sb
        .crypto(&[
            "--json",
            "vault",
            "create",
            "--name",
            "Nice Name",
            "--shortening-threshold",
            "100",
            "--show-recovery-key",
            vault.to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(json["displayName"], "Nice Name");
    assert_eq!(json["cipherCombo"], "SIV_GCM");
    assert_eq!(json["shorteningThreshold"], 100);
    assert_eq!(json["recoveryKey"].as_str().unwrap().split(' ').count(), 44);
    assert_eq!(json["id"].as_str().unwrap().len(), 12);
}

#[test]
fn vault_create_rejects_existing_dir_short_password_and_missing_source() {
    let sb = Sandbox::new();
    sb.crypto(&["vault", "create", sb.root().to_str().unwrap()])
        .assert()
        .code(1);
    sb.crypto(&["vault", "create", sb.path("x").to_str().unwrap()])
        .env("CRYPTO_PASSWORD", "short")
        .assert()
        .code(4);
    sb.crypto(&["vault", "create", sb.path("y").to_str().unwrap()])
        .env_remove("CRYPTO_PASSWORD")
        .assert()
        .code(2);
    assert!(!sb.path("x").exists() && !sb.path("y").exists());
}

#[test]
fn vault_add_list_info_remove() {
    let sb = Sandbox::new();
    let fixture_path = fixture("siv_gcm_basic");
    let out = sb
        .crypto(&[
            "--json",
            "vault",
            "add",
            "--name",
            "Basic",
            fixture_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let id = serde_json::from_slice::<serde_json::Value>(&out).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    sb.crypto(&["vault", "add", fixture_path.to_str().unwrap()])
        .assert()
        .code(5)
        .stderr(predicate::str::contains("already registered"));
    sb.crypto(&["vault", "add", sb.root().to_str().unwrap()])
        .assert()
        .code(12);

    sb.crypto(&["vault", "list"]).assert().success().stdout(
        predicate::str::contains(&id)
            .and(predicate::str::contains("LOCKED"))
            .and(predicate::str::contains("Basic")),
    );
    let out = sb
        .crypto(&["--json", "vault", "list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let list: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert_eq!(list[0]["state"], "LOCKED");

    let out = sb
        .crypto(&["--json", "vault", "info", "Basic"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let info: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(info["id"], id);
    assert_eq!(info["cipherCombo"], "SIV_GCM");
    assert_eq!(info["shorteningThreshold"], 220);
    assert_eq!(info["format"], 8);
    assert_eq!(info["keyType"], "masterkeyfile");
    assert_eq!(info["keyId"], "masterkeyfile:masterkey.cryptomator");
    assert_eq!(info["port"], 42427);
    sb.crypto(&["vault", "info", "basic"]).assert().success();
    sb.crypto(&["vault", "info", "nope"]).assert().code(3);

    sb.crypto(&["vault", "remove", &id]).assert().success();
    assert!(sb.settings_json()["directories"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(
        fixture_path.join("vault.cryptomator").is_file(),
        "remove never deletes vault files"
    );
}

#[test]
fn vault_info_detects_hub_vaults() {
    let sb = Sandbox::new();
    let vault = sb.path("hub");
    std::fs::create_dir_all(vault.join("d")).unwrap();
    // header {"kid":"hub+https://hub.example.com/api/vaults/1","alg":"HS256","typ":"JWT"}, unsigned-looking payload; info never verifies
    std::fs::write(vault.join("vault.cryptomator"), "eyJraWQiOiJodWIraHR0cHM6Ly9odWIuZXhhbXBsZS5jb20vYXBpL3ZhdWx0cy8xIiwiYWxnIjoiSFMyNTYiLCJ0eXAiOiJKV1QifQ.eyJqdGkiOiJ4IiwiZm9ybWF0Ijo4LCJjaXBoZXJDb21ibyI6IlNJVl9HQ00iLCJzaG9ydGVuaW5nVGhyZXNob2xkIjoyMjB9.AAAA").unwrap();
    sb.crypto(&["vault", "add", vault.to_str().unwrap()])
        .assert()
        .success();
    let out = sb
        .crypto(&["--json", "vault", "info", "hub"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let info: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(info["keyType"], "hub");
    assert_eq!(
        sb.settings_json()["directories"][0]["lastKnownKeyLoader"],
        "hub+https"
    );
}

#[test]
fn vault_create_names_the_path_in_errors() {
    let sb = Sandbox::new();
    sb.crypto(&["vault", "create", sb.root().to_str().unwrap()])
        .assert()
        .code(1)
        .stderr(
            predicate::str::contains("cannot create vault at")
                .and(predicate::str::contains(sb.root().to_str().unwrap())),
        );
}

#[test]
fn vault_create_without_flag_prints_no_recovery_key() {
    let sb = Sandbox::new();
    let out = sb
        .crypto(&["--json", "vault", "create", sb.path("j").to_str().unwrap()])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert!(json["recoveryKey"].is_null());

    sb.crypto(&["vault", "create", sb.path("h").to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Recovery key").not());
}

#[test]
fn vault_create_no_register_writes_no_settings() {
    let sb = Sandbox::new();
    let vault = sb.path("solo");
    sb.crypto(&["vault", "create", "--no-register", vault.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Registered as").not());
    assert!(vault.join("vault.cryptomator").is_file());
    assert!(
        !sb.settings().exists(),
        "--no-register never touches settings.json"
    );
}

#[test]
fn vault_set_updates_settings() {
    let sb = Sandbox::new();
    sb.crypto(&[
        "vault",
        "add",
        "--name",
        "B",
        fixture("siv_gcm_basic").to_str().unwrap(),
    ])
    .assert()
    .success();
    sb.crypto(&[
        "vault",
        "set",
        "B",
        "--name",
        "Renamed",
        "--mount-point",
        "/tmp/mnt-b",
        "--read-only",
        "true",
        "--mount-flags=-o foo",
        "--mounter",
        "webdav",
        "--port",
        "8080",
        "--auto-lock-idle",
        "300",
        "--max-filename-length",
        "146",
        "--action-after-unlock",
        "REVEAL",
    ])
    .assert()
    .success();
    let v = sb.settings_json()["directories"][0].clone();
    assert_eq!(v["displayName"], "Renamed");
    assert_eq!(v["mountPoint"], "/tmp/mnt-b");
    assert_eq!(v["usesReadOnlyMode"], true);
    assert_eq!(v["mountFlags"], "-o foo");
    assert_eq!(
        v["mountService"],
        "org.cryptomator.frontend.webdav.mount.FallbackMounter"
    );
    assert_eq!(v["port"], 8080);
    assert_eq!(v["autoLockWhenIdle"], true);
    assert_eq!(v["autoLockIdleSeconds"], 300);
    assert_eq!(v["maxCleartextFilenameLength"], 146);
    assert_eq!(v["actionAfterUnlock"], "REVEAL");

    sb.crypto(&[
        "vault",
        "set",
        "Renamed",
        "--no-mount-point",
        "--default-mount-flags",
        "--mounter",
        "default",
        "--no-auto-lock",
        "--max-filename-length",
        "auto",
        "--read-only",
        "false",
    ])
    .assert()
    .success();
    let v = sb.settings_json()["directories"][0].clone();
    assert!(v.get("mountPoint").is_none());
    assert_eq!(v["mountFlags"], "");
    assert!(v.get("mountService").is_none());
    assert_eq!(v["autoLockWhenIdle"], false);
    assert_eq!(v["maxCleartextFilenameLength"], -1);
    assert_eq!(v["usesReadOnlyMode"], false);

    sb.crypto(&["vault", "set", "Renamed", "--mounter", "bogus"])
        .assert()
        .code(2);
    sb.crypto(&["vault", "set", "Renamed", "--action-after-unlock", "DANCE"])
        .assert()
        .code(2);
    sb.crypto(&["vault", "set", "missing", "--name", "x"])
        .assert()
        .code(3);
}

#[test]
fn config_get_and_set() {
    let sb = Sandbox::new();
    let out = sb
        .crypto(&["--json", "config", "get"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let cfg: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(cfg["port"], 42427);
    assert_eq!(cfg["useKeychain"], true);
    assert!(cfg["mountService"].is_null());

    sb.crypto(&["config", "set", "mountService", "fuse-t"])
        .assert()
        .success();
    sb.crypto(&["config", "set", "port", "42428"])
        .assert()
        .success();
    sb.crypto(&["config", "set", "useKeychain", "false"])
        .assert()
        .success();
    sb.crypto(&["config", "set", "debugMode", "true"])
        .assert()
        .success();
    sb.crypto(&["config", "set", "keychainProvider", "org.example.Keychain"])
        .assert()
        .success();
    sb.crypto(&["config", "get", "mountService"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "org.cryptomator.frontend.fuse.mount.FuseTMountProvider",
        ));
    let json = sb.settings_json();
    assert_eq!(json["port"], 42428);
    assert_eq!(json["useKeychain"], false);
    assert_eq!(json["debugMode"], true);
    assert_eq!(json["keychainProvider"], "org.example.Keychain");

    sb.crypto(&["config", "set", "mountService", "default"])
        .assert()
        .success();
    assert!(sb.settings_json().get("mountService").is_none());
    sb.crypto(&["config", "set", "port", "70000"])
        .assert()
        .code(2);
    sb.crypto(&["config", "set", "theme", "DARK"])
        .assert()
        .code(2);
    sb.crypto(&["config", "get", "theme"]).assert().code(2);
}

#[test]
fn password_change_and_recovery_key_flows() {
    let sb = Sandbox::new();
    let vault = sb.path("pw");
    sb.crypto(&["vault", "create", vault.to_str().unwrap()])
        .assert()
        .success();

    // change password: old from CRYPTO_PASSWORD, new from --new-password-env
    sb.crypto(&["password", "change", "pw", "--new-password-env", "NEWPW"])
        .env("NEWPW", "brand-new-passphrase")
        .assert()
        .success()
        .stdout(predicate::str::contains("Password changed"));
    assert_eq!(bkup_count(&vault), 1);
    sb.crypto(&["recovery-key", "show", "pw"])
        .assert()
        .code(4)
        .stderr(predicate::str::contains("invalid passphrase"));
    let out = sb
        .crypto(&["--json", "recovery-key", "show", "pw"])
        .env("CRYPTO_PASSWORD", "brand-new-passphrase")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let recovery_key = serde_json::from_slice::<serde_json::Value>(&out).unwrap()["recoveryKey"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(recovery_key.split(' ').count(), 44);
    sb.crypto(&["password", "change", "pw", "--new-password-env", "NEWPW"])
        .env("NEWPW", "short")
        .env("CRYPTO_PASSWORD", "brand-new-passphrase")
        .assert()
        .code(4);

    // reset via recovery key from stdin, new password from --new-password-env
    sb.crypto(&[
        "recovery-key",
        "reset-password",
        "pw",
        "--recovery-key-stdin",
        "--new-password-env",
        "NP",
    ])
    .env("NP", "reset-passphrase-1")
    .write_stdin(format!("{recovery_key}\n"))
    .assert()
    .success();
    sb.crypto(&["recovery-key", "show", "pw"])
        .env("CRYPTO_PASSWORD", "reset-passphrase-1")
        .assert()
        .success()
        .stdout(predicate::str::contains(&recovery_key));

    // a recovery key of another vault is rejected before anything is written
    let other = sb.path("other");
    let out = sb
        .crypto(&[
            "--json",
            "vault",
            "create",
            "--show-recovery-key",
            other.to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let foreign_key = serde_json::from_slice::<serde_json::Value>(&out).unwrap()["recoveryKey"]
        .as_str()
        .unwrap()
        .to_string();
    let before = std::fs::read(vault.join("masterkey.cryptomator")).unwrap();
    sb.crypto(&[
        "recovery-key",
        "reset-password",
        "pw",
        "--recovery-key-stdin",
        "--new-password-env",
        "NP",
    ])
    .env("NP", "reset-passphrase-2")
    .write_stdin(format!("{foreign_key}\n"))
    .assert()
    .code(4);
    assert_eq!(
        std::fs::read(vault.join("masterkey.cryptomator")).unwrap(),
        before
    );
    sb.crypto(&[
        "recovery-key",
        "reset-password",
        "pw",
        "--recovery-key-stdin",
        "--new-password-env",
        "NP",
    ])
    .env("NP", "reset-passphrase-2")
    .write_stdin("pathway lift\n")
    .assert()
    .code(4);
}

#[test]
fn password_change_never_takes_the_new_password_from_crypto_password() {
    // CRYPTO_PASSWORD supplies the *current* password; without an explicit --new-password-* flag
    // the new one has to be typed, so a non-interactive run must fail without touching the vault.
    let sb = Sandbox::new();
    let vault = sb.path("v");
    sb.crypto(&["vault", "create", vault.to_str().unwrap()])
        .assert()
        .success();
    let masterkey = vault.join("masterkey.cryptomator");
    let before = std::fs::read(&masterkey).unwrap();

    sb.crypto(&["password", "change", "v"])
        .write_stdin("")
        .assert()
        .failure()
        .stdout(predicate::str::contains("Password changed").not());

    assert_eq!(std::fs::read(&masterkey).unwrap(), before);
    assert_eq!(bkup_count(&vault), 0, "nothing was written");
    // The original password still opens the vault.
    sb.crypto(&["recovery-key", "show", "v"])
        .assert()
        .success()
        .stdout(predicate::str::contains(" "));
}

#[test]
fn reset_password_reads_the_recovery_key_from_a_file() {
    let sb = Sandbox::new();
    let vault = sb.path("v");
    let out = sb
        .crypto(&[
            "--json",
            "vault",
            "create",
            "--show-recovery-key",
            vault.to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let recovery_key = serde_json::from_slice::<serde_json::Value>(&out).unwrap()["recoveryKey"]
        .as_str()
        .unwrap()
        .to_string();
    let key_file = sb.path("recovery.txt");
    std::fs::write(&key_file, format!("{recovery_key}\n")).unwrap();

    sb.crypto(&[
        "recovery-key",
        "reset-password",
        "v",
        "--recovery-key-file",
        key_file.to_str().unwrap(),
        "--new-password-env",
        "NP",
    ])
    .env("NP", "from-file-passphrase")
    .assert()
    .success()
    .stdout(predicate::str::contains("Password reset"));
    sb.crypto(&["recovery-key", "show", "v"])
        .env("CRYPTO_PASSWORD", "from-file-passphrase")
        .assert()
        .success()
        .stdout(predicate::str::contains(&recovery_key));

    // Oversized and non-UTF-8 key files are usage errors naming the flag, not bare io errors.
    std::fs::write(&key_file, vec![b'a'; 5001]).unwrap();
    sb.crypto(&[
        "recovery-key",
        "reset-password",
        "v",
        "--recovery-key-file",
        key_file.to_str().unwrap(),
        "--new-password-env",
        "NP",
    ])
    .env("NP", "from-file-passphrase")
    .assert()
    .code(2)
    .stderr(predicate::str::contains("--recovery-key-file"));
    std::fs::write(&key_file, [0xff, 0xfe, 0x00]).unwrap();
    sb.crypto(&[
        "recovery-key",
        "reset-password",
        "v",
        "--recovery-key-file",
        key_file.to_str().unwrap(),
        "--new-password-env",
        "NP",
    ])
    .env("NP", "from-file-passphrase")
    .assert()
    .code(2)
    .stderr(predicate::str::contains("--recovery-key-file"));
}

#[test]
fn password_change_refuses_a_vault_that_is_not_locked() {
    let sb = Sandbox::new();
    let vault = sb.path("v");
    sb.crypto(&["vault", "create", vault.to_str().unwrap()])
        .assert()
        .success();
    // No vault config and no masterkey file: the vault resolves to ALL_MISSING, not LOCKED.
    std::fs::remove_file(vault.join("vault.cryptomator")).unwrap();
    std::fs::remove_file(vault.join("masterkey.cryptomator")).unwrap();
    sb.crypto(&["password", "change", "v", "--new-password-env", "NP"])
        .env("NP", "brand-new-passphrase")
        .assert()
        .code(5)
        .stderr(predicate::str::contains("LOCKED"));
}

#[test]
fn password_and_recovery_commands_refuse_hub_and_missing_vaults() {
    let sb = Sandbox::new();
    let hub = sb.path("hub");
    std::fs::create_dir_all(hub.join("d")).unwrap();
    std::fs::write(hub.join("vault.cryptomator"), "eyJraWQiOiJodWIraHR0cHM6Ly9odWIuZXhhbXBsZS5jb20vYXBpL3ZhdWx0cy8xIiwiYWxnIjoiSFMyNTYiLCJ0eXAiOiJKV1QifQ.eyJqdGkiOiJ4IiwiZm9ybWF0Ijo4LCJjaXBoZXJDb21ibyI6IlNJVl9HQ00iLCJzaG9ydGVuaW5nVGhyZXNob2xkIjoyMjB9.AAAA").unwrap();
    sb.crypto(&["vault", "add", hub.to_str().unwrap()])
        .assert()
        .success();
    sb.crypto(&["recovery-key", "show", "hub"]).assert().code(9);
    sb.crypto(&["password", "change", "hub", "--new-password-env", "X"])
        .env("X", "whatever-long")
        .assert()
        .code(9);
    // The key id check comes first, so no recovery key and no password are read.
    sb.crypto(&[
        "recovery-key",
        "reset-password",
        "hub",
        "--recovery-key-stdin",
        "--new-password-env",
        "X",
    ])
    .env("X", "whatever-long")
    .write_stdin("")
    .assert()
    .code(9);
    std::fs::remove_dir_all(&hub).unwrap();
    sb.crypto(&["recovery-key", "show", "hub"])
        .assert()
        .code(5)
        .stderr(predicate::str::contains("MISSING"));
}

#[test]
fn vault_add_reports_non_vault_paths_with_an_explanation_and_code_12() {
    let sb = Sandbox::new();
    // A regular file: used to print `error: /path` with no explanation at all.
    let file = sb.path("just-a-file.txt");
    std::fs::write(&file, b"not a vault\n").unwrap();
    sb.crypto(&["vault", "add", file.to_str().unwrap()])
        .assert()
        .code(12)
        .stderr(
            predicate::str::contains("not a vault directory")
                .and(predicate::str::contains(file.to_str().unwrap()))
                .and(predicate::str::contains("NOT_A_DIRECTORY")),
        );

    // A path that does not exist: used to be a bare `No such file or directory (os error 2)`
    // with exit code 1, while an unrelated *directory* already exited 12.
    let missing = sb.path("nowhere");
    sb.crypto(&["vault", "add", missing.to_str().unwrap()])
        .assert()
        .code(12)
        .stderr(
            predicate::str::contains(missing.to_str().unwrap())
                .and(predicate::str::contains("cannot register vault at")),
        );
    assert!(!sb.settings().exists(), "nothing was registered");
}

#[test]
fn config_set_rejects_empty_values() {
    let sb = Sandbox::new();
    sb.crypto(&["config", "set", "keychainProvider", ""])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("must not be empty"));
    sb.crypto(&["config", "set", "mountService", ""])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("must not be empty"));
    // The explicit keyword still clears the setting.
    sb.crypto(&["config", "set", "mountService", "default"])
        .assert()
        .success();
    assert!(sb.settings_json().get("mountService").is_none());
    assert!(
        sb.settings_json()["keychainProvider"].as_str().is_some(),
        "the OS default keychain provider is still there"
    );
}

#[test]
fn vault_set_accepts_action_after_unlock_case_insensitively() {
    let sb = Sandbox::new();
    sb.crypto(&[
        "vault",
        "add",
        "--name",
        "B",
        fixture("siv_gcm_basic").to_str().unwrap(),
    ])
    .assert()
    .success();
    sb.crypto(&["vault", "set", "B", "--action-after-unlock", "reveal"])
        .assert()
        .success();
    assert_eq!(
        sb.settings_json()["directories"][0]["actionAfterUnlock"],
        "REVEAL",
        "stored in the canonical upper-case spelling the desktop app expects"
    );
    sb.crypto(&["vault", "set", "B", "--action-after-unlock", "Ignore"])
        .assert()
        .success();
    assert_eq!(
        sb.settings_json()["directories"][0]["actionAfterUnlock"],
        "IGNORE"
    );
    sb.crypto(&["vault", "set", "B", "--action-after-unlock", "dance"])
        .assert()
        .code(2);
}

#[test]
fn mount_flags_without_a_value_do_not_swallow_the_next_flag() {
    let sb = Sandbox::new();
    sb.crypto(&[
        "vault",
        "add",
        "--name",
        "B",
        fixture("siv_gcm_basic").to_str().unwrap(),
    ])
    .assert()
    .success();
    // `--mount-flags` requires `=`, so a forgotten value is a usage error instead of quietly
    // consuming `--read-only` as the flag string.
    sb.crypto(&["vault", "set", "B", "--mount-flags", "--read-only", "true"])
        .assert()
        .code(2);
    let v = sb.settings_json()["directories"][0].clone();
    assert_eq!(v["mountFlags"], "");
    assert_eq!(v["usesReadOnlyMode"], false);
}

#[test]
fn password_change_names_a_leftover_tmp_file() {
    let sb = Sandbox::new();
    let vault = sb.path("v");
    sb.crypto(&["vault", "create", vault.to_str().unwrap()])
        .assert()
        .success();
    let tmp = vault.join("masterkey.cryptomator.tmp");
    std::fs::write(&tmp, b"leftover").unwrap();
    sb.crypto(&["password", "change", "v", "--new-password-env", "NP"])
        .env("NP", "brand-new-passphrase")
        .assert()
        .failure()
        .stderr(
            predicate::str::contains(tmp.to_str().unwrap())
                .and(predicate::str::contains("temporary masterkey file")),
        );
}

#[test]
fn password_change_reports_the_backup_it_verified() {
    let sb = Sandbox::new();
    let vault = sb.path("v");
    sb.crypto(&["vault", "create", vault.to_str().unwrap()])
        .assert()
        .success();
    let out = sb
        .crypto(&[
            "--json",
            "password",
            "change",
            "v",
            "--new-password-env",
            "NP",
        ])
        .env("NP", "brand-new-passphrase")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let backup = json["backup"].as_str().expect("backup path in JSON");
    assert!(std::fs::read(backup).unwrap().starts_with(b"{"));
    assert_eq!(bkup_count(&vault), 1);

    // Human output: the "kept as" line is printed only for a backup that was verified, and no
    // warning is emitted for it.
    sb.crypto(&["password", "change", "v", "--new-password-env", "NP2"])
        .env("CRYPTO_PASSWORD", "brand-new-passphrase")
        .env("NP2", "third-passphrase-42")
        .assert()
        .success()
        .stdout(predicate::str::contains("Previous masterkey file kept as"))
        .stderr(predicate::str::contains("warning").not());
}

#[test]
fn password_change_new_password_error_names_the_new_password_flags() {
    let sb = Sandbox::new();
    sb.crypto(&["vault", "create", sb.path("v").to_str().unwrap()])
        .assert()
        .success();
    // CRYPTO_PASSWORD holds the *current* password, so the message must not suggest it.
    sb.crypto(&["password", "change", "v"])
        .write_stdin("")
        .assert()
        .code(2)
        .stderr(
            predicate::str::contains("--new-password-stdin")
                .and(predicate::str::contains(
                    "CRYPTO_PASSWORD supplies only the current password",
                ))
                .and(predicate::str::contains("set CRYPTO_PASSWORD").not()),
        );
}

/// The class name of the mount service that mounts nothing.
const NULL_MOUNTER: &str = "org.cryptomator.cli.NullMountProvider";
/// Makes the null mounter usable; without it, it is listed but not supported.
const ENABLE_NULL: &str = "CRYPTO_ENABLE_NULL_MOUNTER";

fn json_of(cmd: &mut Command) -> serde_json::Value {
    let out = cmd.assert().success().get_output().stdout.clone();
    serde_json::from_slice(&out).unwrap()
}

/// The entry for `class` in a `crypto mounters --json` array, if it is listed at all.
fn service<'a>(list: &'a serde_json::Value, class: &str) -> Option<&'a serde_json::Value> {
    list.as_array()
        .expect("an array of services")
        .iter()
        .find(|s| s["className"] == class)
}

#[test]
fn mounters_lists_the_mount_services() {
    let sb = Sandbox::new();

    // Without `--all` only the services that work here are listed, and without the environment
    // variable the null mounter does not work.
    let supported = json_of(sb.crypto(&["--json", "mounters"]).env_remove(ENABLE_NULL));
    assert!(service(&supported, NULL_MOUNTER).is_none(), "{supported}");
    for entry in supported.as_array().unwrap() {
        assert_eq!(entry["supported"], true, "{entry}");
    }

    // `--all` lists it, as unsupported.
    let all = json_of(
        sb.crypto(&["--json", "mounters", "--all"])
            .env_remove(ENABLE_NULL),
    );
    let null = service(&all, NULL_MOUNTER).expect("the null mounter is listed by --all");
    assert_eq!(null["supported"], false, "{null}");
    assert_eq!(null["alias"], "null");
    assert!(null["capabilities"].is_array());
    assert!(null["displayName"].is_string());

    // With the environment variable it becomes usable, and then it is listed without `--all` too.
    let enabled = json_of(
        sb.crypto(&["--json", "mounters", "--all"])
            .env(ENABLE_NULL, "1"),
    );
    assert_eq!(service(&enabled, NULL_MOUNTER).unwrap()["supported"], true);
    let usable = json_of(sb.crypto(&["--json", "mounters"]).env(ENABLE_NULL, "1"));
    assert!(service(&usable, NULL_MOUNTER).is_some(), "{usable}");

    sb.crypto(&["mounters", "--all"])
        .env(ENABLE_NULL, "1")
        .assert()
        .success()
        .stdout(predicate::str::contains("ALIAS"))
        .stdout(predicate::str::contains("CAPABILITIES"))
        .stdout(predicate::str::contains("null"))
        .stdout(predicate::str::contains(NULL_MOUNTER));
}

#[test]
fn config_get_and_set_the_cli_settings() {
    let sb = Sandbox::new();
    let cli_json = || -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(sb.path("cli.json")).unwrap()).unwrap()
    };

    // Defaults, without a cli.json existing at all.
    sb.crypto(&["config", "get", "logLevel"])
        .assert()
        .success()
        .stdout("info\n");
    sb.crypto(&["config", "get", "forceUnmountOnSignalAfterSecs"])
        .assert()
        .success()
        .stdout("10\n");
    // The effective mount-point base, i.e. the platform default while nothing is configured.
    let dir = sb
        .crypto(&["config", "get", "mountPointsDir"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let dir = String::from_utf8(dir).unwrap();
    assert!(dir.trim().ends_with("Cryptomator/mnt"), "{dir}");
    assert!(!sb.path("cli.json").exists(), "reading writes nothing");

    sb.crypto(&["config", "set", "logLevel", "bogus"])
        .assert()
        .code(2);
    sb.crypto(&["config", "set", "logLevel", "debug"])
        .assert()
        .success()
        .stdout("logLevel=debug\n");
    assert_eq!(cli_json()["logLevel"], "debug");

    // A relative path is resolved against the shell's cwd, like every other path argument.
    sb.crypto(&["config", "set", "mountPointsDir", "relative/mnt"])
        .assert()
        .success();
    let configured = cli_json()["mountPointsDir"].as_str().unwrap().to_string();
    assert!(
        std::path::Path::new(&configured).is_absolute() && configured.ends_with("relative/mnt"),
        "{configured}"
    );
    sb.crypto(&["config", "get", "mountPointsDir"])
        .assert()
        .success()
        .stdout(format!("{configured}\n"));

    // An alias is stored as the Java class name; "default" clears the setting again.
    sb.crypto(&["config", "set", "defaultMounter", "fuse-t"])
        .assert()
        .success();
    assert_eq!(
        cli_json()["defaultMounter"],
        "org.cryptomator.frontend.fuse.mount.FuseTMountProvider"
    );
    sb.crypto(&["config", "set", "defaultMounter", "bogus"])
        .assert()
        .code(2);
    sb.crypto(&["config", "set", "defaultMounter", "default"])
        .assert()
        .success();
    assert!(cli_json()["defaultMounter"].is_null());

    sb.crypto(&["config", "set", "forceUnmountOnSignalAfterSecs", "30"])
        .assert()
        .success();
    assert_eq!(cli_json()["forceUnmountOnSignalAfterSecs"], 30);
    sb.crypto(&["config", "set", "forceUnmountOnSignalAfterSecs", "-1"])
        .assert()
        .code(2);
    sb.crypto(&["config", "set", "mountPointsDir", ""])
        .assert()
        .code(2);

    // One `config get` shows the settings.json keys and the cli.json keys together.
    let all = json_of(&mut sb.crypto(&["--json", "config", "get"]));
    assert_eq!(all["port"], 42427);
    assert_eq!(all["logLevel"], "debug");
    assert_eq!(all["forceUnmountOnSignalAfterSecs"], 30);
    assert!(all["defaultMounter"].is_null());
    sb.crypto(&["config", "get"])
        .assert()
        .success()
        .stdout(predicate::str::contains("logLevel=debug"))
        .stdout(predicate::str::contains("port=42427"));

    // Unknown keys are still refused, and the message names the cli.json keys too.
    sb.crypto(&["config", "get", "nosuchkey"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("logLevel"));
}
