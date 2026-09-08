//! `crypto health`: run the vault health checks, repair what can be repaired, report what is left.
//!
//! A finding is not an error. The command succeeds at what it was asked to do even when the vault
//! is in pieces, so the findings travel as data (stdout, the report file, the exit code) and never
//! as an [`anyhow::Error`] -- only a vault that could not be opened at all does that. A fix that
//! fails is data too: it is logged and the run continues.
//!
//! Three outputs, on purpose:
//!
//! * the **terminal table**, which leaves the `GOOD` findings out: on a healthy vault of any size
//!   they are thousands of lines saying nothing happened, and the summary already counts them;
//! * the **report file**, which is the desktop app's `ReportWriter` format including every `GOOD`
//!   line, so a report from `crypto health` and one from the health window can be `diff`ed -- and
//!   which therefore describes the *final* state of the vault, with no section of its own about the
//!   repairs (Java's format has none);
//! * `--json`, which carries everything the other two do plus the paths of each finding and, with
//!   `--fix`, the log of every attempted repair.
use crate::cli::HealthArgs;
use crate::commands::{keychain_source, locked_vault, Ctx};
use crate::exit;
use anyhow::{Context, Result};
use cryptomator_app::{read_passphrase_with_keychain, SystemIo};
use cryptomator_core::{
    checks_by_ids, open_vault, read_vault_config, render_report, report_file_name, run_checks,
    write_report, write_report_to, CheckContext, DiagnosticResult, MasterkeyFileAccess, Severity,
    CHECK_IDS,
};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Column widths of the human table. A value that does not fit pushes the row wider rather than
/// being cut off, so a ciphertext path stays copy-pasteable -- the same rule `crypto status` uses.
const SEVERITY_WIDTH: usize = 8;
const CHECK_WIDTH: usize = 9;
const KIND_WIDTH: usize = 24;

/// How often `--fix` applies fixes before it stops, however much work is left.
///
/// Repairing is not guaranteed to terminate: a fix creates nodes the next check run has an opinion
/// about -- adopting an orphan builds `/LOST+FOUND` -- so a vault damaged in the right way could
/// keep the loop busy. Three rounds is the cap; in practice `broken_health` is done after one,
/// because everything the adoption leaves behind is `INFO` and therefore below `--fix-severity`.
const MAX_FIX_ROUNDS: usize = 3;

pub fn run(ctx: &Ctx, args: HealthArgs) -> Result<u8> {
    let (vault, path) = locked_vault(ctx, &args.vault)?;
    // The thresholds and the check names are validated before anything asks for a password: a
    // typo should not cost the user a prompt (or a keychain dialog) first.
    let fail_on = Severity::parse_threshold(&args.fail_on)?;
    // `--fix-severity` is a documented no-op without `--fix`, so it is parsed -- and a bogus value
    // rejected -- only when the repairs actually run.
    let fix_severity = args
        .fix
        .then(|| Severity::parse_threshold(&args.fix_severity))
        .transpose()?;
    let ids: Vec<String> = if args.check.is_empty() {
        CHECK_IDS.iter().map(|id| (*id).to_string()).collect()
    } else {
        args.check.clone()
    };
    let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
    // Resolved here as well as inside `run_checks`, because the report needs the display name of
    // every check that ran and the selection has to be rejected before the password is read.
    let checks = checks_by_ids(&ids)?;
    // Reject Hub and unsupported key ids before asking for any passphrase, as `fs` and
    // `recovery-key` do.
    read_vault_config(&path)?
        .key_id()?
        .require_masterkey_file()?;
    // Lazy: the keychain provider is only probed once the source order actually reaches it, so a
    // scripted `--password-stdin` run never pays for the probe.
    let passphrase = read_passphrase_with_keychain(
        &args.password,
        "Password: ",
        || Ok(keychain_source(ctx.keychain()?.as_ref(), &vault)),
        &mut SystemIo,
    )?;
    let opened = open_vault(&path, &MasterkeyFileAccess::new(Vec::new()), &passphrase)?;
    let check_ctx = CheckContext::from_opened(opened);
    // The sink reports every finding the moment it is made; nothing needs that here, because the
    // table is printed once at the end in the order the core sorted the results into.
    let mut results = run_checks(&ids, &check_ctx, &mut |_| {})?;
    // `--fix` replaces `results` with the findings of the last check run: everything below --
    // report, table, summary, exit code -- describes the vault as it is *now*, and the fix log is
    // the only record of the way there.
    let repairs = fix_severity
        .map(|severity| apply_fixes(&ids, &check_ctx, &mut results, severity))
        .transpose()?;

    let label = vault.display_name.as_deref().unwrap_or(&vault.id);
    let report = write_the_report(&args, &checks, &results, label, &check_ctx)?;

    let summary = Summary::of(&results);
    let mut value = json!({
        "vault": vault.id,
        "path": path,
        "checks": checks.iter().map(|check| check.id()).collect::<Vec<_>>(),
        "failOn": fail_on.as_str(),
        "report": report,
        "summary": summary.to_json(),
        "findings": results
            .iter()
            .map(|result| to_json(result, repairs.as_ref().and_then(|r| r.outcome_of(result))))
            .collect::<Vec<_>>(),
    });
    // Only with `--fix`: a script that never asked for repairs sees the object of Task 8, byte for
    // byte, and one that did distinguishes the two forms by the flag it set itself.
    if let Some(repairs) = &repairs {
        value["fixSeverity"] = json!(args.fix_severity.to_ascii_uppercase());
        value["fixes"] = repairs.to_json();
        value["rounds"] = json!(repairs.rounds);
    }
    ctx.out.emit(value, || {
        render_human(&results, &summary, repairs.as_ref(), report.as_deref())
    })?;

    Ok(if summary.worst >= fail_on {
        exit::HEALTH_FINDINGS
    } else {
        exit::OK
    })
}

/// Applies the fixes of every finding at or above `fix_severity`, re-runs the checks, and repeats
/// while the last round repaired something and left work behind.
///
/// `results` is replaced by the findings of the last check run.
///
/// Three properties, all of them deliberate:
///
/// * a fix that fails is recorded and the loop moves on -- one unremovable node must not stop the
///   repair of everything else, and the finding it belongs to simply survives;
/// * a finding is attempted **once** per run, identified by its kind and its paths. That is what
///   "new fixable findings appeared" means: a fix that failed is not retried in the next round
///   (`ENOTEMPTY` will not have changed), and neither is one that reported success while its
///   finding stayed;
/// * the order is the core's report order -- severity first, then path -- so the fix log and the
///   table below it name the findings in the same order. A directory a fix creates is never
///   adopted away as an orphan by a later fix of the same round: the orphans of a round were
///   determined before any of it ran.
fn apply_fixes(
    ids: &[&str],
    ctx: &CheckContext,
    results: &mut Vec<DiagnosticResult>,
    fix_severity: Severity,
) -> Result<Repairs> {
    let mut repairs = Repairs::default();
    for _ in 0..MAX_FIX_ROUNDS {
        let pending: Vec<usize> = results
            .iter()
            .enumerate()
            .filter(|(_, result)| result.severity >= fix_severity && result.fixable())
            .filter(|(_, result)| !repairs.attempted(result))
            .map(|(index, _)| index)
            .collect();
        if pending.is_empty() {
            break;
        }
        repairs.rounds += 1;
        let mut any_fixed = false;
        for index in pending {
            let result = &results[index];
            let Some(fix) = result.fix.as_ref() else {
                continue;
            };
            repairs.outcomes.push(FixOutcome {
                kind: result.kind,
                paths: result.paths.clone(),
                describe: fix.describe(),
                error: match fix.apply(ctx) {
                    Ok(()) => {
                        any_fixed = true;
                        None
                    }
                    Err(err) => Some(err.to_string()),
                },
            });
        }
        *results = run_checks(ids, ctx, &mut |_| {})?;
        if !any_fixed {
            break;
        }
    }
    Ok(repairs)
}

/// One attempted repair.
struct FixOutcome {
    /// The kind of the finding it belongs to, e.g. `OrphanContentDir`.
    kind: &'static str,
    /// The paths of that finding; together with `kind` the identity of the attempt.
    paths: Vec<PathBuf>,
    /// `Fix::describe`, the line that says what was tried.
    describe: String,
    /// `None` when the fix reported success, the I/O error otherwise.
    error: Option<String>,
}

impl FixOutcome {
    fn outcome(&self) -> String {
        match &self.error {
            None => "fixed".to_string(),
            Some(error) => format!("failed: {error}"),
        }
    }
}

/// Everything one `--fix` run did.
#[derive(Default)]
struct Repairs {
    /// In the order the attempts were made, across all rounds.
    outcomes: Vec<FixOutcome>,
    rounds: usize,
}

impl Repairs {
    /// Was a fix for this exact finding already attempted in this run?
    fn attempted(&self, result: &DiagnosticResult) -> bool {
        self.outcomes
            .iter()
            .any(|outcome| outcome.kind == result.kind && outcome.paths == result.paths)
    }

    /// How the attempt for this finding ended, for the `fixed` field of `--json`. `None` means the
    /// finding was never touched -- because it has no fix, because it is below `--fix-severity`, or
    /// because it only appeared in the final run.
    fn outcome_of(&self, result: &DiagnosticResult) -> Option<bool> {
        self.outcomes
            .iter()
            .rev()
            .find(|outcome| outcome.kind == result.kind && outcome.paths == result.paths)
            .map(|outcome| outcome.error.is_none())
    }

    fn fixed(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|outcome| outcome.error.is_none())
            .count()
    }

    fn failed(&self) -> usize {
        self.outcomes.len() - self.fixed()
    }

    fn to_json(&self) -> Value {
        Value::Array(
            self.outcomes
                .iter()
                .map(|outcome| {
                    json!({
                        "kind": outcome.kind,
                        "paths": outcome.paths,
                        "describe": outcome.describe,
                        "outcome": outcome.outcome(),
                    })
                })
                .collect(),
        )
    }

    /// One line per attempt, in the order they were made.
    fn log(&self) -> Vec<String> {
        self.outcomes
            .iter()
            .map(|outcome| match &outcome.error {
                None => format!("FIXED   {}", outcome.describe),
                Some(error) => format!("FAILED  {}: {error}", outcome.describe),
            })
            .collect()
    }

    fn line(&self) -> String {
        format!(
            "fixed {}, failed {} in {} rounds",
            self.fixed(),
            self.failed(),
            self.rounds
        )
    }
}

/// One finding as `--json` shows it.
///
/// `fixed` is `null` without `--fix`, and with it the outcome of the repair that was attempted for
/// this very finding -- `false` for the fix that failed and left it in place. A finding the final
/// run reports that nothing was attempted for stays `null`.
pub(crate) fn to_json(result: &DiagnosticResult, fixed: Option<bool>) -> Value {
    json!({
        "check": result.check,
        "kind": result.kind,
        "severity": result.severity.as_str(),
        "message": result.message,
        "paths": result.paths,
        "fixable": result.fixable(),
        "fixed": fixed,
    })
}

/// Writes the text report unless `--no-report` said not to, and returns where it landed.
///
/// The two targets differ in two points, and deliberately. `--report FILE` replaces an existing
/// file, because the user named that path and the next command in the script reads it, and a
/// failure to write it fails the run for the same reason. The automatic name in the working
/// directory never replaces anything -- yesterday's evidence about a damaged vault outranks today's
/// convenience -- and a failure to write it is a warning: a read-only working directory must not
/// swallow the findings the run just made.
fn write_the_report(
    args: &HealthArgs,
    checks: &[Box<dyn cryptomator_core::HealthCheck>],
    results: &[DiagnosticResult],
    label: &str,
    check_ctx: &CheckContext,
) -> Result<Option<PathBuf>> {
    if args.no_report {
        return Ok(None);
    }
    // Every check that ran gets a section, even one that found nothing -- as in Java.
    let sections: Vec<(&str, Vec<&DiagnosticResult>)> = checks
        .iter()
        .map(|check| {
            let findings = results.iter().filter(|r| r.check == check.id()).collect();
            (check.name(), findings)
        })
        .collect();
    let text = render_report(
        &check_ctx.config.id,
        label,
        &check_ctx.vault_path,
        &sections,
    );
    let written = match &args.report {
        Some(target) => {
            // `absolute`, not `canonicalize`: the file need not exist yet. It makes the path in
            // `--json` and on stdout usable from anywhere, as the automatic name already is.
            let target = std::path::absolute(target).with_context(|| {
                format!("cannot resolve the health report path {}", target.display())
            })?;
            Some(write_report_to(&target, &text, true).with_context(|| {
                format!("cannot write the health report to {}", target.display())
            })?)
        }
        None => match automatic_report(&text, label) {
            Ok(written) => Some(written),
            Err(err) => {
                eprintln!("warning: could not write the health report: {err:#}");
                None
            }
        },
    };
    Ok(written)
}

/// `./healthReport_<vault>_<stamp>.log`, in the working directory resolved to an absolute path.
///
/// The context messages are phrased to read after the caller's `could not write the health report:`
/// -- this error only ever reaches the user as that warning.
fn automatic_report(text: &str, label: &str) -> Result<PathBuf> {
    let dir = std::env::current_dir().context("the working directory cannot be resolved")?;
    let name = report_file_name(label, SystemTime::now());
    write_report(&dir, &name, text).with_context(|| dir.join(&name).display().to_string())
}

/// How many findings of each severity, and the worst one seen.
struct Summary {
    critical: usize,
    warn: usize,
    info: usize,
    good: usize,
    worst: Severity,
}

impl Summary {
    fn of(results: &[DiagnosticResult]) -> Self {
        let count = |severity: Severity| results.iter().filter(|r| r.severity == severity).count();
        Self {
            critical: count(Severity::Critical),
            warn: count(Severity::Warn),
            info: count(Severity::Info),
            good: count(Severity::Good),
            // A vault with no findings at all is as healthy as one with only GOOD ones.
            worst: results
                .iter()
                .map(|r| r.severity)
                .max()
                .unwrap_or(Severity::Good),
        }
    }

    fn total(&self) -> usize {
        self.critical + self.warn + self.info + self.good
    }

    fn to_json(&self) -> Value {
        json!({
            "critical": self.critical,
            "warn": self.warn,
            "info": self.info,
            "good": self.good,
        })
    }

    fn line(&self) -> String {
        format!(
            "{} findings: {} critical, {} warn, {} info, {} good",
            self.total(),
            self.critical,
            self.warn,
            self.info,
            self.good
        )
    }
}

/// The terminal output: the fix log, a table of everything above `GOOD`, the summary, and the
/// report path.
///
/// The table has no path column: every message of the ported checks already embeds the paths of its
/// finding, so the column repeated them and pushed a `DirIdCollision` row past 250 characters. The
/// paths are still in `--json`, where a script reads them without parsing a message.
fn render_human(
    results: &[DiagnosticResult],
    summary: &Summary,
    repairs: Option<&Repairs>,
    report: Option<&Path>,
) -> String {
    let mut lines = Vec::new();
    if let Some(repairs) = repairs {
        if !repairs.outcomes.is_empty() {
            lines.extend(repairs.log());
            lines.push(String::new());
        }
    }
    let damage: Vec<&DiagnosticResult> = results
        .iter()
        .filter(|result| result.severity > Severity::Good)
        .collect();
    if !damage.is_empty() {
        lines.push(format!(
            "{:<SEVERITY_WIDTH$}  {:<CHECK_WIDTH$}  {:<KIND_WIDTH$}  {}",
            "SEVERITY", "CHECK", "KIND", "MESSAGE"
        ));
        for result in damage {
            lines.push(format!(
                "{:<SEVERITY_WIDTH$}  {:<CHECK_WIDTH$}  {:<KIND_WIDTH$}  {}",
                result.severity.as_str(),
                result.check,
                result.kind,
                result.message
            ));
        }
        lines.push(String::new());
    }
    lines.push(summary.line());
    if let Some(repairs) = repairs {
        lines.push(repairs.line());
    }
    if let Some(report) = report {
        lines.push(format!("Report written to {}", report.display()));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(severity: Severity, kind: &'static str, paths: Vec<&str>) -> DiagnosticResult {
        DiagnosticResult::new(
            "dirid",
            kind,
            severity,
            format!("something about {kind}"),
            paths.into_iter().map(PathBuf::from).collect(),
        )
    }

    fn outcome(kind: &'static str, paths: Vec<&str>, error: Option<&str>) -> FixOutcome {
        FixOutcome {
            kind,
            paths: paths.into_iter().map(PathBuf::from).collect(),
            describe: format!("repair {kind}"),
            error: error.map(str::to_string),
        }
    }

    #[test]
    fn the_table_leaves_out_what_is_good_and_the_summary_counts_it() {
        let results = vec![
            result(
                Severity::Critical,
                "DirIdCollision",
                vec!["d/AA/BB/dir.c9r"],
            ),
            result(Severity::Warn, "LooseDirFile", vec![]),
            result(Severity::Good, "Good", vec!["d/AA/CC"]),
            result(Severity::Good, "Good", vec!["d/AA/DD"]),
        ];
        let summary = Summary::of(&results);
        assert_eq!(summary.worst, Severity::Critical);
        assert_eq!(
            summary.line(),
            "4 findings: 1 critical, 1 warn, 0 info, 2 good"
        );

        let text = render_human(&results, &summary, None, Some(Path::new("/tmp/r.log")));
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines[0].starts_with("SEVERITY"), "{}", lines[0]);
        assert!(lines[0].ends_with("MESSAGE"), "{}", lines[0]);
        // No path column: the message carries the paths, and it is the last field of the row.
        assert!(!lines[0].contains("PATH"), "{}", lines[0]);
        assert!(lines[1].starts_with("CRITICAL"), "{}", lines[1]);
        assert!(
            !lines[1].contains("d/AA/BB/dir.c9r"),
            "the path column is gone: {}",
            lines[1]
        );
        assert!(lines[1].ends_with("something about DirIdCollision"));
        assert!(
            lines[2].ends_with("something about LooseDirFile"),
            "{}",
            lines[2]
        );
        assert_eq!(lines.len(), 6, "{text}");
        assert!(!text.contains("GOOD"), "{text}");
        assert!(text.ends_with("Report written to /tmp/r.log"), "{text}");
    }

    #[test]
    fn a_healthy_vault_is_a_summary_and_nothing_else() {
        let results = vec![result(Severity::Good, "Good", vec!["d/AA/CC"])];
        let summary = Summary::of(&results);
        assert_eq!(summary.worst, Severity::Good);
        assert_eq!(
            render_human(&results, &summary, None, None),
            "1 findings: 0 critical, 0 warn, 0 info, 1 good"
        );
    }

    #[test]
    fn a_finding_carries_its_paths_and_its_fixability_into_json() {
        let value = to_json(
            &result(Severity::Warn, "LooseDirFile", vec!["d/AA/BB/dir.c9r"]),
            None,
        );
        assert_eq!(value["check"], "dirid");
        assert_eq!(value["kind"], "LooseDirFile");
        assert_eq!(value["severity"], "WARN");
        assert_eq!(value["paths"], json!(["d/AA/BB/dir.c9r"]));
        assert_eq!(value["fixable"], false);
        assert_eq!(value["fixed"], Value::Null);
        assert_eq!(
            to_json(&result(Severity::Good, "Good", vec![]), Some(true))["fixed"],
            true
        );
    }

    #[test]
    fn the_fix_log_names_every_attempt_and_the_summary_counts_them() {
        let repairs = Repairs {
            outcomes: vec![
                outcome("OrphanContentDir", vec!["d/CU/JU"], None),
                outcome(
                    "UnknownType",
                    vec!["d/6U/4K/x.c9r"],
                    Some("Directory not empty"),
                ),
            ],
            rounds: 2,
        };
        assert_eq!(repairs.fixed(), 1);
        assert_eq!(repairs.failed(), 1);
        assert_eq!(repairs.line(), "fixed 1, failed 1 in 2 rounds");
        assert_eq!(
            repairs.log(),
            vec![
                "FIXED   repair OrphanContentDir".to_string(),
                "FAILED  repair UnknownType: Directory not empty".to_string(),
            ]
        );

        let fixes = repairs.to_json();
        let fixes = fixes.as_array().expect("an array of attempts");
        assert_eq!(fixes[0]["outcome"], "fixed");
        assert_eq!(fixes[0]["kind"], "OrphanContentDir");
        assert_eq!(fixes[0]["paths"], json!(["d/CU/JU"]));
        assert_eq!(fixes[0]["describe"], "repair OrphanContentDir");
        assert_eq!(fixes[1]["outcome"], "failed: Directory not empty");

        // The findings of the final run learn from the log what was tried on them.
        let failed = result(Severity::Critical, "UnknownType", vec!["d/6U/4K/x.c9r"]);
        assert_eq!(repairs.outcome_of(&failed), Some(false));
        assert!(repairs.attempted(&failed));
        let untouched = result(Severity::Warn, "MissingContentDir", vec!["d/AA/BB"]);
        assert_eq!(repairs.outcome_of(&untouched), None);
        assert!(!repairs.attempted(&untouched));
        // Same kind, other path: a finding of its own.
        let elsewhere = result(Severity::Critical, "UnknownType", vec!["d/6U/4K/y.c9r"]);
        assert!(!repairs.attempted(&elsewhere));

        // The human output puts the log above the table and the counts below the summary.
        let results = vec![result(Severity::Critical, "UnknownType", vec![])];
        let text = render_human(&results, &Summary::of(&results), Some(&repairs), None);
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines[0].starts_with("FIXED"), "{text}");
        assert!(lines[1].starts_with("FAILED"), "{text}");
        assert_eq!(
            lines[3],
            format!("{:<8}  {:<9}  {:<24}  MESSAGE", "SEVERITY", "CHECK", "KIND")
        );
        assert!(text.ends_with("fixed 1, failed 1 in 2 rounds"), "{text}");
    }

    /// A run without a single attempt prints no empty block above the table, and still says so.
    #[test]
    fn a_run_with_nothing_to_fix_logs_nothing() {
        let repairs = Repairs::default();
        let results = vec![result(Severity::Good, "Good", vec!["d/AA/CC"])];
        assert_eq!(
            render_human(&results, &Summary::of(&results), Some(&repairs), None),
            "1 findings: 0 critical, 0 warn, 0 info, 1 good\nfixed 0, failed 0 in 0 rounds"
        );
        assert_eq!(repairs.to_json(), json!([]));
    }
}
