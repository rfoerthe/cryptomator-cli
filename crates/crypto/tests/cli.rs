use assert_cmd::Command;
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
fn recovery_key_validate_requires_a_source() {
    Command::cargo_bin("crypto")
        .unwrap()
        .args(["recovery-key", "validate"])
        .assert()
        .code(2);
}

use std::path::{Path, PathBuf};
use tempfile::TempDir;

const PW: &str = "test-password-123";

struct Sandbox {
    dir: TempDir,
}

impl Sandbox {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
        }
    }
    fn settings(&self) -> PathBuf {
        self.dir.path().join("settings.json")
    }
    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
    /// `crypto --settings <sandbox> <args>` with CRYPTO_PASSWORD set and no inherited password variables.
    fn crypto(&self, args: &[&str]) -> Command {
        let mut cmd = Command::cargo_bin("crypto").unwrap();
        cmd.env_remove("CRYPTO_SETTINGS_PATH")
            .env_remove("CRYPTO_MIN_PW_LENGTH")
            .env("CRYPTO_PASSWORD", PW);
        cmd.arg("--settings").arg(self.settings());
        cmd.args(args);
        cmd
    }
    fn settings_json(&self) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(self.settings()).unwrap()).unwrap()
    }
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
    sb.crypto(&["vault", "create", sb.dir.path().to_str().unwrap()])
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
    sb.crypto(&["vault", "add", sb.dir.path().to_str().unwrap()])
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
    sb.crypto(&["vault", "create", sb.dir.path().to_str().unwrap()])
        .assert()
        .code(1)
        .stderr(
            predicate::str::contains("cannot create vault at")
                .and(predicate::str::contains(sb.dir.path().to_str().unwrap())),
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
        "--mount-flags",
        "-o foo",
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
    assert_eq!(
        std::fs::read_dir(&vault)
            .unwrap()
            .filter(|e| e
                .as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".bkup"))
            .count(),
        1
    );
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
    std::fs::remove_dir_all(&hub).unwrap();
    sb.crypto(&["recovery-key", "show", "hub"])
        .assert()
        .code(5)
        .stderr(predicate::str::contains("MISSING"));
}
