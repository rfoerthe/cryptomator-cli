//! `crypto health`: run the vault health checks, report what they found, exit 11 if it matters.
//!
//! A finding is not an error. The command succeeds at what it was asked to do even when the vault
//! is in pieces, so the findings travel as data (stdout, the report file, the exit code) and never
//! as an [`anyhow::Error`] -- only a vault that could not be opened at all does that.
//!
//! Three outputs, on purpose:
//!
//! * the **terminal table**, which leaves the `GOOD` findings out: on a healthy vault of any size
//!   they are thousands of lines saying nothing happened, and the summary already counts them;
//! * the **report file**, which is the desktop app's `ReportWriter` format including every `GOOD`
//!   line, so a report from `crypto health` and one from the health window can be `diff`ed;
//! * `--json`, which carries everything the other two do plus the paths of each finding.
use crate::cli::HealthArgs;
use crate::commands::{keychain_source, locked_vault, Ctx};
use crate::exit;
use anyhow::{Context, Result};
use cryptomator_app::{read_passphrase_with_keychain, AppError, SystemIo};
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
const PATHS_WIDTH: usize = 44;

pub fn run(ctx: &Ctx, args: HealthArgs) -> Result<u8> {
    if args.fix {
        // Task 9 implements the repairs. Until then `--fix` is an honest usage error instead of a
        // run that reports findings and quietly leaves them in place.
        Severity::parse_threshold(&args.fix_severity)?;
        return Err(AppError::InvalidValue {
            key: "--fix".to_string(),
            message: "not implemented yet".to_string(),
        }
        .into());
    }
    let (vault, path) = locked_vault(ctx, &args.vault)?;
    // The thresholds and the check names are validated before anything asks for a password: a
    // typo should not cost the user a prompt (or a keychain dialog) first.
    let fail_on = Severity::parse_threshold(&args.fail_on)?;
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
    let results = run_checks(&ids, &check_ctx, &mut |_| {})?;

    let label = vault.display_name.as_deref().unwrap_or(&vault.id);
    let report = write_the_report(&args, &checks, &results, label, &check_ctx)?;

    let summary = Summary::of(&results);
    let value = json!({
        "vault": vault.id,
        "path": path,
        "checks": checks.iter().map(|check| check.id()).collect::<Vec<_>>(),
        "failOn": fail_on.as_str(),
        "report": report,
        "summary": summary.to_json(),
        "findings": results
            .iter()
            .map(|result| to_json(result, None))
            .collect::<Vec<_>>(),
    });
    ctx.out.emit(value, || {
        render_human(&results, &summary, report.as_deref())
    })?;

    Ok(if summary.worst >= fail_on {
        exit::HEALTH_FINDINGS
    } else {
        exit::OK
    })
}

/// One finding as `--json` shows it.
///
/// `fixed` is `null` without `--fix` and the outcome of the repair with it (Task 9), so the shape
/// of the object does not change between the two runs a script may compare.
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
/// The two targets differ in exactly one point, and deliberately: `--report FILE` replaces an
/// existing file, because the user named that path and the next command in the script reads it,
/// while the automatic name in the working directory never replaces anything -- yesterday's
/// evidence about a damaged vault outranks today's convenience.
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
        Some(target) => write_report_to(target, &text, true)
            .with_context(|| format!("cannot write the health report to {}", target.display()))?,
        None => {
            let dir = std::env::current_dir()
                .context("cannot resolve the working directory for the health report")?;
            let name = report_file_name(label, SystemTime::now());
            write_report(&dir, &name, &text).with_context(|| {
                format!(
                    "cannot write the health report to {}",
                    dir.join(&name).display()
                )
            })?
        }
    };
    Ok(Some(written))
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

/// The terminal output: a table of everything above `GOOD`, the summary, and the report path.
fn render_human(results: &[DiagnosticResult], summary: &Summary, report: Option<&Path>) -> String {
    let mut lines = Vec::new();
    let damage: Vec<&DiagnosticResult> = results
        .iter()
        .filter(|result| result.severity > Severity::Good)
        .collect();
    if !damage.is_empty() {
        lines.push(format!(
            "{:<SEVERITY_WIDTH$}  {:<CHECK_WIDTH$}  {:<KIND_WIDTH$}  {:<PATHS_WIDTH$}  {}",
            "SEVERITY", "CHECK", "KIND", "PATH(S)", "MESSAGE"
        ));
        for result in damage {
            lines.push(format!(
                "{:<SEVERITY_WIDTH$}  {:<CHECK_WIDTH$}  {:<KIND_WIDTH$}  {:<PATHS_WIDTH$}  {}",
                result.severity.as_str(),
                result.check,
                result.kind,
                render_paths(&result.paths),
                result.message
            ));
        }
        lines.push(String::new());
    }
    lines.push(summary.line());
    if let Some(report) = report {
        lines.push(format!("Report written to {}", report.display()));
    }
    lines.join("\n")
}

/// The affected nodes of one finding, or `-` for a finding that names none (the root
/// `MissingContentDir`, for one).
fn render_paths(paths: &[PathBuf]) -> String {
    if paths.is_empty() {
        return "-".to_string();
    }
    paths
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
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

        let text = render_human(&results, &summary, Some(Path::new("/tmp/r.log")));
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines[0].starts_with("SEVERITY"), "{}", lines[0]);
        assert!(lines[1].starts_with("CRITICAL"), "{}", lines[1]);
        assert!(lines[1].contains("d/AA/BB/dir.c9r"), "{}", lines[1]);
        assert!(lines[1].ends_with("something about DirIdCollision"));
        // A finding without paths still fills its column.
        assert!(lines[2].contains(" -  "), "{}", lines[2]);
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
            render_human(&results, &summary, None),
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
}
