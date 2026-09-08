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
    // The message embeds the paths; the table has no column of its own for them any more.
    assert!(text.contains("dir.c9r"), "the path of a finding: {text}");
    assert!(!text.contains("PATH(S)"), "{text}");
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
fn fail_on_stays_warn_or_critical_only() {
    // Unlike `--fix-severity`, `--fail-on` never accepts `INFO`: failing on it would make every
    // report a failure.
    let fx = Sandbox::new();
    vault(&fx, "broken_health");
    fx.crypto(&[
        "health",
        "broken_health",
        "--fail-on",
        "INFO",
        "--no-report",
    ])
    .assert()
    .code(2)
    .stderr(predicate::str::contains("WARN"));
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

/// `--fix --json` on a sandbox copy of a fixture: the parsed object of the run.
fn fix_run(fx: &Sandbox, args: &[&str], code: i32) -> Value {
    let out = fx
        .crypto(args)
        .assert()
        .code(code)
        .get_output()
        .stdout
        .clone();
    serde_json::from_slice(&out).expect("a JSON object")
}

/// `kind -> outcome` of every repair the run attempted, in the order it attempted them.
fn attempts(value: &Value) -> Vec<(String, String)> {
    value["fixes"]
        .as_array()
        .expect("the fix log")
        .iter()
        .map(|fix| {
            (
                fix["kind"].as_str().expect("a kind").to_string(),
                fix["outcome"].as_str().expect("an outcome").to_string(),
            )
        })
        .collect()
}

#[test]
fn fix_repairs_what_it_can_and_reports_every_attempt() {
    let fx = Sandbox::new();
    vault(&fx, "broken_health");
    // Still 11: `DirIdCollision` and `MissingLongName` have no fix at all and the `UnknownType`
    // node is not empty, so three CRITICALs survive a full repair.
    let value = fix_run(
        &fx,
        &["--json", "health", "broken_health", "--fix", "--no-report"],
        11,
    );
    assert_eq!(value["fixSeverity"], "WARN");

    let attempts = attempts(&value);
    let fixed: Vec<&String> = attempts
        .iter()
        .filter(|(_, outcome)| outcome == "fixed")
        .map(|(kind, _)| kind)
        .collect();
    assert_eq!(
        fixed,
        vec![
            "LongShortNamesMismatch",
            "MissingContentDir",
            "TrailingBytesInNameFile",
            "OrphanContentDir",
        ],
        "{attempts:#?}"
    );
    // A fix may legitimately fail: the node of unknown type holds a file, and `Files.delete` --
    // like `remove_dir` -- refuses a non-empty directory. It is logged and the run goes on.
    let failed: Vec<&(String, String)> = attempts
        .iter()
        .filter(|(_, outcome)| outcome.starts_with("failed: "))
        .collect();
    assert_eq!(failed.len(), 1, "{attempts:#?}");
    assert_eq!(failed[0].0, "UnknownType");
    assert!(failed[0].1.contains("Directory not empty"), "{failed:#?}");
    // Every fixable finding at or above WARN was attempted exactly once, and the follow-up
    // findings the adoption creates (`/LOST+FOUND` without its dir id backup) are INFO, so the
    // second round has nothing left to do and never runs.
    assert_eq!(value["rounds"], 1, "{attempts:#?}");

    // What the repairs removed, and what they could not.
    let findings = value["findings"].as_array().expect("the findings");
    assert_eq!(damage_by_kind(findings).get("OrphanContentDir"), None);
    assert_eq!(value["summary"]["warn"], 0, "{findings:#?}");
    assert_eq!(value["summary"]["critical"], 3, "{findings:#?}");
    let unknown = findings
        .iter()
        .find(|f| f["kind"] == "UnknownType")
        .expect("the node of unknown type survived");
    assert_eq!(unknown["fixed"], false, "the fix for it failed");
    let collision = findings
        .iter()
        .find(|f| f["kind"] == "DirIdCollision")
        .expect("the collision survived");
    assert_eq!(
        collision["fixed"],
        Value::Null,
        "nothing was attempted for a finding without a fix"
    );
    assert_eq!(collision["fixable"], false);
}

#[test]
fn a_second_fix_run_changes_nothing() {
    let fx = Sandbox::new();
    vault(&fx, "broken_health");
    let args = &["--json", "health", "broken_health", "--fix", "--no-report"];
    let first = fix_run(&fx, args, 11);
    let second = fix_run(&fx, args, 11);

    assert_eq!(first["summary"], second["summary"], "{second:#?}");
    assert_eq!(first["findings"], second["findings"], "{second:#?}");
    // The one fix that cannot succeed is tried again -- a fresh process has no memory of the last
    // run -- and fails again. Nothing else is: the repairs of the first run stuck.
    assert_eq!(
        attempts(&second),
        vec![(
            "UnknownType".to_string(),
            attempts(&first)
                .into_iter()
                .find(|(kind, _)| kind == "UnknownType")
                .expect("the failed attempt of the first run")
                .1,
        )],
        "a second --fix run repairs nothing"
    );
}

#[test]
fn fix_severity_critical_leaves_the_warnings_alone() {
    let fx = Sandbox::new();
    vault(&fx, "broken_health");
    let value = fix_run(
        &fx,
        &[
            "--json",
            "health",
            "broken_health",
            "--fix",
            "--fix-severity",
            "CRITICAL",
            "--no-report",
        ],
        11,
    );
    assert_eq!(value["fixSeverity"], "CRITICAL");
    // The only CRITICAL of the manifest that has a fix at all.
    assert_eq!(
        attempts(&value)
            .iter()
            .map(|(kind, _)| kind.as_str())
            .collect::<Vec<_>>(),
        vec!["UnknownType"]
    );
    // The four WARN findings are exactly the ones the default threshold would have repaired.
    assert_eq!(value["summary"]["warn"], 4);
    let findings = value["findings"].as_array().expect("the findings");
    assert!(
        findings.iter().any(|f| f["kind"] == "OrphanContentDir"),
        "{findings:#?}"
    );

    fx.crypto(&[
        "health",
        "broken_health",
        "--fix",
        "--fix-severity",
        "nonsense",
        "--no-report",
    ])
    .assert()
    .code(2)
    .stderr(predicate::str::contains("WARN"));
}

#[test]
fn fix_severity_info_reaches_the_desktop_parity_fixes_over_a_second_round() {
    let fx = Sandbox::new();
    vault(&fx, "broken_health");
    let value = fix_run(
        &fx,
        &[
            "--json",
            "health",
            "broken_health",
            "--fix",
            "--fix-severity",
            "INFO",
            "--no-report",
        ],
        // The three unfixable CRITICALs (`DirIdCollision`, `UnknownType`, `MissingLongName`) still
        // survive a full repair, whatever --fix-severity is.
        11,
    );
    assert_eq!(value["fixSeverity"], "INFO");

    let attempts = attempts(&value);
    let fixed_kinds: Vec<&str> = attempts
        .iter()
        .filter(|(_, outcome)| outcome == "fixed")
        .map(|(kind, _)| kind.as_str())
        .collect();
    assert!(
        fixed_kinds
            .iter()
            .any(|kind| *kind == "MissingDirIdBackup" || *kind == "LooseDirFile"),
        "an INFO-only fix was attempted and succeeded: {attempts:#?}"
    );
    // Round 1 adopts the orphan into /LOST+FOUND; that step-parent's missing dir id backup is
    // itself an INFO finding the adoption leaves behind, so a second round is needed to reach it.
    let rounds = value["rounds"].as_u64().expect("a round count");
    assert!(rounds >= 2, "{attempts:#?} ran in {rounds} rounds");

    assert_eq!(value["summary"]["critical"], 3, "{value:#?}");
}

#[test]
fn fix_repairs_only_the_selected_checks() {
    let fx = Sandbox::new();
    vault(&fx, "broken_health");
    let value = fix_run(
        &fx,
        &[
            "--json",
            "health",
            "broken_health",
            "--fix",
            "--check",
            "shortened",
            "--no-report",
        ],
        11,
    );
    assert_eq!(
        attempts(&value)
            .iter()
            .map(|(kind, _)| kind.as_str())
            .collect::<Vec<_>>(),
        vec!["LongShortNamesMismatch", "TrailingBytesInNameFile"],
        "a check that was not selected neither reports nor repairs"
    );
    // The orphan of the `dirid` check is still there, untouched by this run.
    let value = fix_run(
        &fx,
        &["--json", "health", "broken_health", "--no-report"],
        11,
    );
    assert!(value["findings"]
        .as_array()
        .expect("the findings")
        .iter()
        .any(|f| f["kind"] == "OrphanContentDir"));
}

#[test]
fn a_fixed_vault_is_still_readable() {
    let fx = Sandbox::new();
    vault(&fx, "broken_health");
    fx.crypto(&["health", "broken_health", "--fix", "--no-report"])
        .assert()
        .code(11);
    // The intact file is untouched, and the adopted orphan is reachable again under /LOST+FOUND.
    fx.crypto(&["fs", "cat", "broken_health", "/healthy.txt"])
        .assert()
        .success()
        .stdout(predicate::str::contains("this file stays intact"));
    fx.crypto(&["fs", "ls", "broken_health", "/LOST+FOUND"])
        .assert()
        .success()
        .stdout(predicate::str::contains("CUJUVHHOHR37XSFJOOJJKFUPSLEJNPVQ"));
}

#[test]
fn a_healthy_vault_has_nothing_to_fix() {
    let fx = Sandbox::new();
    vault(&fx, "siv_gcm_basic");
    let value = fix_run(
        &fx,
        &["--json", "health", "siv_gcm_basic", "--fix", "--no-report"],
        0,
    );
    assert_eq!(value["fixes"], serde_json::json!([]));
    assert_eq!(value["rounds"], 0);
}

#[test]
fn without_fix_the_json_carries_no_fix_log_at_all() {
    let fx = Sandbox::new();
    vault(&fx, "siv_gcm_basic");
    let value = fix_run(
        &fx,
        &["--json", "health", "siv_gcm_basic", "--no-report"],
        0,
    );
    // A script that never asked for repairs sees the object it has always seen.
    assert!(value.get("fixes").is_none(), "{value:#?}");
    assert!(value.get("rounds").is_none(), "{value:#?}");
    assert!(value.get("fixSeverity").is_none(), "{value:#?}");
}

#[test]
fn fix_without_json_logs_every_attempt_and_counts_them() {
    let fx = Sandbox::new();
    vault(&fx, "broken_health");
    let out = fx
        .crypto(&["health", "broken_health", "--fix", "--no-report"])
        .assert()
        .code(11)
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).unwrap();
    let lines: Vec<&str> = text.lines().collect();

    // The log comes first, one line per attempt, and says what was tried rather than what broke.
    assert_eq!(
        lines.iter().filter(|l| l.starts_with("FIXED   ")).count(),
        4,
        "{text}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("FAILED  ") && l.contains("Directory not empty")),
        "{text}"
    );
    assert!(text.contains("adopt the contents of"), "{text}");
    assert!(
        text.trim_end().ends_with("fixed 4, failed 1 in 1 rounds"),
        "{text}"
    );
    // …and the table below it describes the vault as it is now.
    assert!(!text.contains("OrphanContentDir"), "{text}");
    assert!(text.contains("DirIdCollision"), "{text}");
}

#[test]
fn a_relative_report_path_is_reported_absolute() {
    let fx = Sandbox::new();
    vault(&fx, "broken_health");
    let cwd = empty_cwd(&fx, "cwd");
    let out = fx
        .crypto(&["--json", "health", "broken_health", "--report", "r.log"])
        .current_dir(&cwd)
        .assert()
        .code(11)
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&out).unwrap();

    let reported = Path::new(value["report"].as_str().expect("the report path"));
    assert!(reported.is_absolute(), "{reported:?}");
    assert!(reported.is_file(), "{reported:?}");
    assert_eq!(reported.file_name().unwrap(), "r.log");
    assert_eq!(file_names(&cwd), vec!["r.log".to_string()]);
}

#[test]
fn an_automatic_report_that_cannot_be_written_is_a_warning() {
    let fx = Sandbox::new();
    vault(&fx, "broken_health");
    let cwd = empty_cwd(&fx, "cwd");
    let mut permissions = std::fs::metadata(&cwd).unwrap().permissions();
    let writable = permissions.clone();
    permissions.set_readonly(true);
    std::fs::set_permissions(&cwd, permissions).unwrap();
    // A user who may write anywhere (root, or a platform that ignores the bit) would see the
    // report written after all; there is nothing to assert then.
    if std::fs::write(cwd.join("probe"), b"x").is_ok() {
        std::fs::set_permissions(&cwd, writable).unwrap();
        return;
    }

    // The findings are the result of the run; the report file is a convenience. A working
    // directory nobody may write to must not turn exit 11 into exit 1 and swallow them.
    fx.crypto(&["health", "broken_health"])
        .current_dir(&cwd)
        .assert()
        .code(11)
        .stdout(predicate::str::contains("DirIdCollision"))
        .stderr(predicate::str::contains(
            "warning: could not write the health report",
        ));
    // An explicit --report is what the user asked for, so failing to write it fails the run.
    fx.crypto(&["health", "broken_health", "--report"])
        .arg(cwd.join("r.log"))
        .current_dir(&cwd)
        .assert()
        .code(1)
        .stderr(predicate::str::contains("cannot write the health report"));

    std::fs::set_permissions(&cwd, writable).unwrap();
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
