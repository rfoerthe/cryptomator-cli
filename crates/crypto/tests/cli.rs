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
