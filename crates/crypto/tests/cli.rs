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
