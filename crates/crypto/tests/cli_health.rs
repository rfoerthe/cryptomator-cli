//! `crypto health` end to end: exit code 11, the JSON shape, and the text report.
//!
//! Every run reads the passphrase from `$CRYPTO_PASSWORD` (set by [`Sandbox::crypto`]) -- no test
//! here ever touches a keychain, real or fake.
mod common;

use common::Sandbox;
use predicates::prelude::*;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Copies a fixture into the sandbox, registers it under its directory name and returns its path.
fn vault(fx: &Sandbox, fixture: &str) -> PathBuf {
    fx.add_fixture(fixture)
}

/// A working directory of its own, so a run that writes its report into the current directory can
/// be checked by listing that directory.
fn empty_cwd(fx: &Sandbox, name: &str) -> PathBuf {
    let cwd = fx.path(name);
    std::fs::create_dir_all(&cwd).unwrap();
    cwd
}

fn file_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// `kind -> how many findings of it` for everything the run reported above `GOOD`.
fn damage_by_kind(findings: &[Value]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for finding in findings {
        if finding["severity"] == "GOOD" {
            continue;
        }
        let kind = finding["kind"].as_str().expect("a kind").to_string();
        *counts.entry(kind).or_insert(0) += 1;
    }
    counts
}

/// The same map read out of the fixture's own manifest, which is what the generator wrote and what
/// the real cryptofs health checks were verified against.
fn manifest_damage_by_kind(fixture: &str) -> BTreeMap<String, usize> {
    let path = common::fixtures_root()
        .join(fixture)
        .join("expected-findings.json");
    let manifest: Vec<Value> = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let mut counts = BTreeMap::new();
    for finding in &manifest {
        let kind = finding["result"].as_str().expect("a result").to_string();
        *counts.entry(kind).or_insert(0) += 1;
    }
    counts
}

#[test]
fn a_healthy_vault_exits_zero_and_reports_only_good_findings() {
    let fx = Sandbox::new();
    vault(&fx, "siv_gcm_basic");
    let out = fx
        .crypto(&["--json", "health", "siv_gcm_basic", "--no-report"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&out).unwrap();

    assert_eq!(value["vault"], fx.vault_id(0));
    assert_eq!(
        value["checks"],
        serde_json::json!(["dirid", "type", "shortened"])
    );
    assert_eq!(value["failOn"], "CRITICAL");
    assert_eq!(value["report"], Value::Null, "--no-report writes nothing");

    let findings = value["findings"].as_array().expect("an array of findings");
    assert!(!findings.is_empty(), "a healthy vault still reports GOOD");
    assert!(
        findings.iter().all(|f| f["severity"] == "GOOD"),
        "{findings:#?}"
    );
    assert!(
        findings.iter().all(|f| f["fixed"].is_null()),
        "nothing was fixed without --fix"
    );
    assert!(
        findings.iter().all(|f| f["fixable"] == false),
        "a GOOD finding has nothing to repair"
    );
    for key in ["check", "kind", "severity", "message", "paths", "fixable"] {
        assert!(findings[0].get(key).is_some(), "missing {key}");
    }
    assert_eq!(
        value["summary"],
        serde_json::json!({
            "critical": 0, "warn": 0, "info": 0, "good": findings.len(),
        })
    );
}

#[test]
fn a_broken_vault_exits_eleven_with_the_damage_of_its_manifest_and_a_report() {
    let fx = Sandbox::new();
    vault(&fx, "broken_health");
    let cwd = empty_cwd(&fx, "cwd");
    let out = fx
        .crypto(&["--json", "health", "broken_health"])
        .current_dir(&cwd)
        .assert()
        .code(11)
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&out).unwrap();
    let findings = value["findings"].as_array().expect("an array of findings");

    assert_eq!(
        damage_by_kind(findings),
        manifest_damage_by_kind("broken_health"),
        "the findings of the run and of the fixture manifest disagree"
    );
    // GOOD findings are reported too -- the damaged vault has healthy nodes as well.
    assert!(findings.iter().any(|f| f["severity"] == "GOOD"));
    assert_eq!(value["summary"]["critical"], 3);

    // The report is the one file the run left in its working directory.
    let written = file_names(&cwd);
    assert_eq!(written.len(), 1, "{written:?}");
    assert!(
        written[0].starts_with("healthReport_broken_health_") && written[0].ends_with(".log"),
        "{written:?}"
    );
    // An absolute path, ending in that file. Not `cwd.join(..)`: the command resolves its working
    // directory, and on macOS the sandbox's `/var/...` resolves to `/private/var/...`.
    let reported = Path::new(value["report"].as_str().expect("the report path"));
    assert!(reported.is_absolute(), "{reported:?}");
    assert!(reported.is_file(), "{reported:?}");
    assert_eq!(reported.file_name().unwrap(), written[0].as_str());
}

#[test]
fn the_human_output_names_the_damage_and_counts_it() {
    let fx = Sandbox::new();
    vault(&fx, "broken_health");
    let cwd = empty_cwd(&fx, "cwd");
    let out = fx
        .crypto(&["health", "broken_health", "--no-report"])
        .current_dir(&cwd)
        .assert()
        .code(11)
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).unwrap();

    assert!(text.starts_with("SEVERITY"), "{text}");
    assert!(text.contains("CRITICAL"), "{text}");
    assert!(text.contains("DirIdCollision"), "{text}");
    assert!(text.contains("dir.c9r"), "the path of a finding: {text}");
    assert!(
        !text.contains("    GOOD "),
        "GOOD rows stay out of the terminal table: {text}"
    );
    let summary = text
        .lines()
        .find(|line| line.contains("findings:"))
        .unwrap_or_else(|| panic!("a summary line in {text}"));
    assert!(summary.contains("3 critical"), "{summary}");
    assert!(summary.contains("good"), "{summary}");
    assert!(file_names(&cwd).is_empty(), "--no-report writes nothing");
}

#[test]
fn fail_on_warn_catches_what_fail_on_critical_lets_pass() {
    let fx = Sandbox::new();
    vault(&fx, "broken_health");
    fx.crypto(&[
        "health",
        "broken_health",
        "--check",
        "shortened",
        "--fail-on",
        "WARN",
        "--no-report",
    ])
    .assert()
    .code(11);
    // A healthy vault is below every threshold, which is what shows the threshold is a threshold.
    vault(&fx, "nested");
    fx.crypto(&["health", "nested", "--fail-on", "WARN", "--no-report"])
        .assert()
        .success();
}

#[test]
fn check_selects_and_an_unknown_check_is_a_usage_error() {
    let fx = Sandbox::new();
    vault(&fx, "broken_health");
    let out = fx
        .crypto(&[
            "--json",
            "health",
            "broken_health",
            "--check",
            "type,dirid",
            "--no-report",
        ])
        .assert()
        .code(11)
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&out).unwrap();
    // The order is the catalogue's, not the one the flag was typed in.
    assert_eq!(value["checks"], serde_json::json!(["dirid", "type"]));
    assert!(value["findings"]
        .as_array()
        .unwrap()
        .iter()
        .all(|f| f["check"] == "dirid" || f["check"] == "type"));
    assert!(
        !value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["check"] == "shortened"),
        "a check that was not selected reports nothing"
    );

    fx.crypto(&["health", "broken_health", "--check", "bogus", "--no-report"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("dirid"));
}

#[test]
fn the_report_lands_where_it_was_asked_for_and_the_next_run_replaces_it() {
    let fx = Sandbox::new();
    vault(&fx, "broken_health");
    let dir = empty_cwd(&fx, "reports");
    let report = dir.join("r.log");

    for _ in 0..2 {
        fx.crypto(&["health", "broken_health", "--report"])
            .arg(&report)
            .assert()
            .code(11);
    }
    // The user named the path, so the report is there -- not next to it under `r-1.log`.
    assert_eq!(file_names(&dir), vec!["r.log".to_string()]);

    let text = std::fs::read_to_string(&report).expect("the report was written");
    assert!(
        text.starts_with("*******************************************"),
        "{text}"
    );
    assert!(text.contains("Check Directory Check"), "{text}");
    assert!(text.contains("STATUS: SUCCESS"), "{text}");
    assert!(text.contains("CRITICAL - "), "{text}");
    // Every selected check gets a section, and GOOD findings are in the file even though the
    // terminal table leaves them out.
    assert!(text.contains("Check Resource Type Check"), "{text}");
    assert!(text.contains("Check Shortened Names Check"), "{text}");
    assert!(text.contains("    GOOD - "), "{text}");
    assert!(
        !text.contains("test-password"),
        "no secret reaches the report"
    );
}

#[test]
fn without_report_flags_the_file_appears_in_the_working_directory() {
    let fx = Sandbox::new();
    vault(&fx, "siv_gcm_basic");
    let cwd = empty_cwd(&fx, "cwd");
    fx.crypto(&["health", "siv_gcm_basic"])
        .current_dir(&cwd)
        .assert()
        .success();
    let written = file_names(&cwd);
    assert_eq!(written.len(), 1, "{written:?}");
    assert!(
        written[0].starts_with("healthReport_siv_gcm_basic_") && written[0].ends_with(".log"),
        "{written:?}"
    );
    // The automatic name never overwrites: a second run in the same second steps aside.
    fx.crypto(&["health", "siv_gcm_basic"])
        .current_dir(&cwd)
        .assert()
        .success();
    assert_eq!(file_names(&cwd).len(), 2, "{:?}", file_names(&cwd));
}

#[test]
fn a_wrong_password_is_exit_four_and_writes_no_report() {
    let fx = Sandbox::new();
    vault(&fx, "siv_gcm_basic");
    let cwd = empty_cwd(&fx, "cwd");
    fx.crypto(&["health", "siv_gcm_basic"])
        .current_dir(&cwd)
        .env("CRYPTO_PASSWORD", "not-the-password")
        .assert()
        .code(4);
    assert!(
        file_names(&cwd).is_empty(),
        "a vault that never opened has nothing to report on"
    );
}

#[test]
fn fix_is_announced_but_not_implemented_yet() {
    let fx = Sandbox::new();
    vault(&fx, "broken_health");
    fx.crypto(&["health", "broken_health", "--fix", "--no-report"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("not implemented yet"));
}

#[test]
fn a_vault_that_is_not_locked_is_exit_five() {
    // A vault a daemon is serving is the other half of this and lives in `cli_daemon.rs`; here it
    // is a vault whose config is gone, which is `VAULT_CONFIG_MISSING` rather than `LOCKED`.
    let fx = Sandbox::new();
    let path = vault(&fx, "siv_gcm_basic");
    std::fs::remove_file(path.join("vault.cryptomator")).unwrap();
    for entry in std::fs::read_dir(&path).unwrap() {
        let entry = entry.unwrap();
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with("vault.cryptomator.")
        {
            // Otherwise the state probe restores the config from its backup.
            std::fs::remove_file(entry.path()).unwrap();
        }
    }
    fx.crypto(&["health", "siv_gcm_basic", "--no-report"])
        .assert()
        .code(5);
}
