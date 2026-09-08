//! The text report, ported from the desktop app's `org.cryptomator.ui.health.ReportWriter`.
//!
//! `crypto health` writes the same file the desktop app's health window writes: same banner, same
//! per-check sections, same right-aligned severity column. Two vaults checked with the two programs
//! produce reports that `diff` can be pointed at, which is the whole point of copying the layout
//! byte for byte instead of inventing a nicer one.
//!
//! Java builds the text from `String.format` on text blocks whose line terminator is `\n` on every
//! platform, and writes it through an `OutputStreamWriter` that does not translate line endings --
//! so the report is LF-only even on Windows, and so is this one.
//!
//! Two deliberate deviations, both from the milestone's rulings:
//!
//! * The timestamp in the file name is **UTC**, not the system time zone (Ruling 5): the workspace
//!   has no time zone database and M7 takes no new dependency for one.
//! * Java's `CANCELED` state has no counterpart -- `crypto health` cannot be cancelled -- while its
//!   `FAILED` state does: a check that cannot finish reports a `CheckFailed` finding, and a section
//!   holding one is rendered as `STATUS: FAILED` with Java's tab-indented `REASON:` block. Unlike
//!   Java, whose failed check has no results at all, ours may already have reported findings before
//!   it broke; those follow the reason under `RESULTS:` rather than being dropped on the floor.

use super::{DiagnosticResult, CHECK_FAILED_KIND};
use std::fmt::Write as _;
use std::fs::File;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// `ReportWriter.REPORT_HEADER`, without its two `%s` lines (they need the vault).
pub const REPORT_HEADER: &str = "\
*******************************************
*     Cryptomator Vault Health Report     *
*******************************************
";

/// The rule under every check heading: exactly 30 hyphens, as in Java's `REPORT_CHECK_HEADER`.
pub const CHECK_SEPARATOR: &str = "------------------------------";

/// How many `-1`, `-2`, … variants [`write_report`] tries before it gives up.
const MAX_NAME_COLLISIONS: u32 = 100;

/// Renders `ReportWriter.writeReport`.
///
/// `sections` pairs the display name of every check that ran (`HealthCheck.name()`) with its
/// findings in report order; a check that found nothing still gets its section, exactly as in Java.
///
/// Only the severity and the message of a finding reach the report -- Java prints
/// `result.getDescription()` and nothing else, so a finding without paths and one with three render
/// alike. The machine-readable form with the paths is `crypto health --json`.
pub fn render_report(
    vault_id: &str,
    vault_name: &str,
    vault_path: &Path,
    sections: &[(&str, Vec<&DiagnosticResult>)],
) -> String {
    let mut out = String::from(REPORT_HEADER);
    // `Analyzed vault: %s (Current name "%s")` -- the id from the vault config, then the name the
    // vault is known under here.
    let _ = writeln!(
        out,
        "Analyzed vault: {vault_id} (Current name \"{vault_name}\")"
    );
    let _ = writeln!(out, "Vault storage path: {}", vault_path.display());
    for (check_name, results) in sections {
        // `REPORT_CHECK_HEADER`: two empty lines (Java's text block strips the trailing spaces of
        // its two indented lines), the heading, the rule.
        let _ = write!(out, "\n\nCheck {check_name}\n{CHECK_SEPARATOR}\n");
        let (failures, findings): (Vec<&DiagnosticResult>, Vec<&DiagnosticResult>) = results
            .iter()
            .copied()
            .partition(|result| result.kind == CHECK_FAILED_KIND);
        if failures.is_empty() {
            out.push_str("STATUS: SUCCESS\nRESULTS:\n");
            write_results(&mut out, &findings);
        } else {
            // Java indents every line of the stack trace with two tabs; our reason is the message
            // of the `CheckFailed` finding, indented the same way.
            out.push_str("STATUS: FAILED\nREASON:\n");
            let mut reasons = 0;
            for failure in &failures {
                for line in failure.message.lines() {
                    let _ = writeln!(out, "\t\t{line}");
                    reasons += 1;
                }
            }
            if reasons == 0 {
                // `ReportWriter.prepareFailureMsg` when the check carries no throwable.
                out.push_str("Unknown reason of failure.");
            }
            if !findings.is_empty() {
                if reasons == 0 {
                    out.push('\n');
                }
                out.push_str("RESULTS:\n");
                write_results(&mut out, &findings);
            }
        }
    }
    out
}

/// `REPORT_CHECK_RESULT`, `"%8s - %s\n"`.
///
/// The width has to be applied to the *string*: [`super::Severity`]'s `Display` writes through
/// `Formatter::pad`, but spelling `as_str()` out here keeps the format string as literal a copy of
/// Java's as the rest of the module.
fn write_results(out: &mut String, findings: &[&DiagnosticResult]) {
    for finding in findings {
        let _ = writeln!(
            out,
            "{:>8} - {}",
            finding.severity.as_str(),
            finding.message
        );
    }
}

/// `healthReport_<vaultName>_<yyyyMMdd-HHmmss>.log`, Java's file name with a UTC stamp (Ruling 5).
///
/// The name of a vault is user input from `settings.json`, so the characters that could make it
/// address a different directory -- the two path separators -- and the control characters (NUL
/// included, which no file system accepts) become `_`. Everything else is kept: a report for
/// "Meine Bilder" should say so.
///
/// An instant before the epoch cannot come from a clock read at a health run and has nothing useful
/// to print, so it is clamped to the epoch.
pub fn report_file_name(vault_name: &str, at: SystemTime) -> String {
    let safe: String = vault_name
        .chars()
        .map(|c| {
            if c == '/' || c == '\\' || c.is_control() {
                '_'
            } else {
                c
            }
        })
        .collect();
    let (year, month, day, hour, minute, second) = civil_utc(epoch_seconds(at));
    format!("healthReport_{safe}_{year:04}{month:02}{day:02}-{hour:02}{minute:02}{second:02}.log")
}

/// Writes `contents` into `dir` under `file_name` and returns the path it ended up at.
///
/// Two properties Java's `CREATE, TRUNCATE_EXISTING` does not have, both of them worth the few
/// extra lines here:
///
/// * **Nothing is ever overwritten.** A report is evidence about a damaged vault; silently
///   replacing yesterday's is the one thing this must not do. The name is reserved with
///   `create_new`, and on a collision the next free `<stem>-1.log`, `<stem>-2.log`, … is taken --
///   the suffix goes before the extension so the file stays a `.log`.
/// * **The file is complete or absent.** The text goes into a temporary file next to the
///   destination and is moved onto it, so a crash or a full disk cannot leave a half-written report
///   that looks like a finished one.
///
/// # Errors
/// [`io::Error`] if the directory is not writable, if the disk fills up, or if all
/// [`MAX_NAME_COLLISIONS`] candidate names are taken.
pub fn write_report(dir: &Path, file_name: &str, contents: &str) -> io::Result<PathBuf> {
    let path = reserve_name(dir, file_name)?;
    // The rename inside replaces the empty file the reservation created; that file is ours, so
    // nobody else's report is lost by it.
    match replace_with_temp(dir, file_name, contents, &path) {
        Ok(()) => Ok(path),
        Err(e) => {
            let _ = std::fs::remove_file(&path);
            Err(e)
        }
    }
}

/// [`write_report`] for a report file the caller names in full, with a say over the collision rule.
///
/// `crypto health` has two report targets and they answer "the file is already there" differently:
///
/// * the automatic report in the working directory keeps [`write_report`]'s rule -- `overwrite =
///   false`, nothing is ever replaced, yesterday's evidence survives;
/// * `--report FILE` passes `overwrite = true`, because the user named that path and expects the
///   report *there*. A surprise `FILE-1.log` would break the obvious `crypto health v --report
///   r.log && cat r.log`.
///
/// Both stay atomic: the text is written to a temporary file next to the target and moved onto it,
/// so a crash never leaves half a report behind -- and with `overwrite = true` never destroys the
/// previous one either, which a plain truncating write would do the moment it opened the file.
///
/// # Errors
/// [`io::ErrorKind::InvalidInput`] if `path` does not end in a file name, or if that name is not
/// UTF-8 (the temporary file is derived from it); otherwise whatever the file system reports.
pub fn write_report_to(path: &Path, contents: &str, overwrite: bool) -> io::Result<PathBuf> {
    let (dir, file_name) = split_target(path)?;
    if !overwrite {
        return write_report(dir, file_name, contents);
    }
    replace_with_temp(dir, file_name, contents, path)?;
    Ok(path.to_path_buf())
}

/// The directory a report goes into and the name it takes there.
///
/// `Path::new("report.log").parent()` is `Some("")`, and joining onto an empty path yields the
/// relative name again -- so a bare file name lands in the working directory, as typed.
fn split_target(path: &Path) -> io::Result<(&Path, &str)> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} does not name a report file", path.display()),
            )
        })?;
    Ok((path.parent().unwrap_or(Path::new("")), file_name))
}

/// Writes `contents` into a temporary file in `dir` and moves it onto `target`, leaving no
/// temporary file behind on either failure.
fn replace_with_temp(dir: &Path, file_name: &str, contents: &str, target: &Path) -> io::Result<()> {
    let temp = write_temp_file(dir, file_name, contents)?;
    // `rename_durably`, not `std::fs::rename`: `write_temp_file` synced the text itself, and the
    // entry that names it needs the directory's own fsync. A report is evidence about a damaged
    // vault, and a crash minutes later must not be able to make it vanish again.
    if let Err(e) = crate::durability::rename_durably(&temp, target) {
        let _ = std::fs::remove_file(&temp);
        return Err(e);
    }
    Ok(())
}

/// Creates the first free candidate name exclusively and returns it, leaving the empty file behind
/// as the reservation.
fn reserve_name(dir: &Path, file_name: &str) -> io::Result<PathBuf> {
    for attempt in 0..=MAX_NAME_COLLISIONS {
        let path = dir.join(candidate_name(file_name, attempt));
        match File::options().write(true).create_new(true).open(&path) {
            Ok(_) => return Ok(path),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!("{file_name} and its first {MAX_NAME_COLLISIONS} variants all exist"),
    ))
}

/// `report.log` for attempt 0, then `report-1.log`, `report-2.log`, …
fn candidate_name(file_name: &str, attempt: u32) -> String {
    if attempt == 0 {
        return file_name.to_string();
    }
    let path = Path::new(file_name);
    match (path.file_stem(), path.extension()) {
        (Some(stem), Some(extension)) => format!(
            "{}-{attempt}.{}",
            stem.to_string_lossy(),
            extension.to_string_lossy()
        ),
        _ => format!("{file_name}-{attempt}"),
    }
}

/// Writes `contents` to a hidden temporary file in `dir` and returns its path.
///
/// The process id keeps two `crypto health` runs in the same directory apart; the counter keeps a
/// leftover from a killed run of *this* process from blocking the write.
fn write_temp_file(dir: &Path, file_name: &str, contents: &str) -> io::Result<PathBuf> {
    for attempt in 0..=MAX_NAME_COLLISIONS {
        let path = dir.join(format!(".{file_name}.{}.{attempt}.tmp", std::process::id()));
        let mut file = match File::options().write(true).create_new(true).open(&path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        };
        // Both errors leave no temporary file behind: a report that could not be written must not
        // turn into litter next to the one that could.
        if let Err(e) = file
            .write_all(contents.as_bytes())
            .and_then(|()| file.sync_all())
        {
            let _ = std::fs::remove_file(&path);
            return Err(e);
        }
        return Ok(path);
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "no free temporary file name next to the report",
    ))
}

/// Seconds since the epoch, clamped at 0 for anything before it.
fn epoch_seconds(at: SystemTime) -> i64 {
    at.duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
        .min(i64::MAX as u64) as i64
}

/// `(year, month, day, hour, minute, second)` of `unix_secs` in UTC.
///
/// The one calendar of the workspace: the report's file name, the daemon's log lines and
/// `crypto events` all format their timestamps from here, and none of them pulls in a date crate to
/// do it. Negative inputs are dated correctly (`-1` is 1969-12-31T23:59:59Z); the callers that have
/// nothing to say about a pre-epoch instant clamp before they call.
pub fn civil_utc(unix_secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = unix_secs.div_euclid(86_400);
    let time_of_day = unix_secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    (
        year,
        month,
        day,
        (time_of_day / 3600) as u32,
        (time_of_day % 3600 / 60) as u32,
        (time_of_day % 60) as u32,
    )
}

/// Howard Hinnant's `civil_from_days`: the Gregorian date of a day number counted from 1970-01-01.
/// Shifting the era to start in March makes the leap day the last day of the year, which is what
/// removes every special case for February.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    // 719468 = days from 0000-03-01 to 1970-01-01; 146097 = days in a 400-year era.
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    // `month_prime` counts March as 0; days 0..=152 are the first five 31/30-day months, and
    // (5*doy + 2)/153 is the exact inverse of that pattern.
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    let year = if month <= 2 { year + 1 } else { year };
    (year, month as u32, day as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::{DiagnosticResult, Severity};
    use std::time::Duration;

    fn result(severity: Severity, kind: &'static str, message: &str) -> DiagnosticResult {
        DiagnosticResult::new("dirid", kind, severity, message.to_string(), vec![])
    }

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    /// The expected text is written out by hand from `ReportWriter`'s three format strings, not
    /// produced by the function under test: a golden string that came out of the code would only
    /// prove the code is consistent with itself.
    #[test]
    fn the_report_matches_the_desktop_apps_layout() {
        let good = result(
            Severity::Good,
            "HealthyDir",
            "Good directory d/AB/CD (x) -> d/EF/GH",
        );
        let mut critical = result(
            Severity::Critical,
            "MissingContentDir",
            "File d/AB/CD/dir.c9r is empty, expected content",
        );
        // Two paths in one finding and none in the other: neither reaches the report.
        critical.paths = vec![PathBuf::from("d/AB/CD"), PathBuf::from("d/EF/GH")];
        let info = result(Severity::Info, "LooseDirFile", "Loose dir file d/AB/CD");

        let text = render_report(
            "5bc0384b-14ac-4fdc-aed0-62e7bc08fd5a",
            "Secret",
            Path::new("/vaults/Secret"),
            &[
                ("Directory Check", vec![&good, &critical, &info]),
                ("Resource Type Check", vec![]),
            ],
        );

        let expected = "\
*******************************************
*     Cryptomator Vault Health Report     *
*******************************************
Analyzed vault: 5bc0384b-14ac-4fdc-aed0-62e7bc08fd5a (Current name \"Secret\")
Vault storage path: /vaults/Secret


Check Directory Check
------------------------------
STATUS: SUCCESS
RESULTS:
    GOOD - Good directory d/AB/CD (x) -> d/EF/GH
CRITICAL - File d/AB/CD/dir.c9r is empty, expected content
    INFO - Loose dir file d/AB/CD


Check Resource Type Check
------------------------------
STATUS: SUCCESS
RESULTS:
";
        assert_eq!(text, expected);
        assert!(!text.contains('\r'), "the report is LF-only, as Java's is");
    }

    /// `%8s`: the column is eight wide, so the four severities line up under each other.
    #[test]
    fn the_severity_column_is_right_aligned_on_eight() {
        let findings: Vec<DiagnosticResult> = [
            Severity::Good,
            Severity::Info,
            Severity::Warn,
            Severity::Critical,
        ]
        .into_iter()
        .map(|severity| result(severity, "X", "m"))
        .collect();
        let borrowed: Vec<&DiagnosticResult> = findings.iter().collect();
        let text = render_report("id", "V", Path::new("/v"), &[("C", borrowed)]);
        let lines: Vec<&str> = text
            .lines()
            .skip_while(|l| *l != "RESULTS:")
            .skip(1)
            .collect();
        assert_eq!(
            lines,
            vec![
                "    GOOD - m",
                "    INFO - m",
                "    WARN - m",
                "CRITICAL - m",
            ]
        );
    }

    /// A check that broke mid-traversal is Java's `ERROR` state: `STATUS: FAILED` and a tab-indented
    /// reason. What it managed to find before it broke still makes it into the report.
    #[test]
    fn a_failed_check_reports_its_reason_and_keeps_its_partial_findings() {
        let failed = result(
            Severity::Critical,
            "CheckFailed",
            "Check failed: Traversal of data dir failed: d/AB (Permission denied (os error 13))",
        );
        let good = result(
            Severity::Good,
            "KnownType",
            "Node d/AB/CD.c9r with type FILE.",
        );

        let with_findings = render_report(
            "id",
            "V",
            Path::new("/v"),
            &[("Resource Type Check", vec![&good, &failed])],
        );
        assert!(
            with_findings.ends_with(
                "\
STATUS: FAILED
REASON:
\t\tCheck failed: Traversal of data dir failed: d/AB (Permission denied (os error 13))
RESULTS:
    GOOD - Node d/AB/CD.c9r with type FILE.
"
            ),
            "{with_findings}"
        );

        // Nothing found before the failure: byte for byte Java's own `FAILED` section, which has no
        // `RESULTS:` block at all.
        let alone = render_report(
            "id",
            "V",
            Path::new("/v"),
            &[("Resource Type Check", vec![&failed])],
        );
        assert!(
            alone.ends_with(
                "\
STATUS: FAILED
REASON:
\t\tCheck failed: Traversal of data dir failed: d/AB (Permission denied (os error 13))
"
            ),
            "{alone}"
        );
        assert!(!alone.contains("RESULTS:"), "{alone}");

        // A `CheckFailed` without a message is Java's "no throwable" case, down to the missing
        // newline after the sentence.
        let mute = result(Severity::Critical, "CheckFailed", "");
        let text = render_report("id", "V", Path::new("/v"), &[("C", vec![&mute])]);
        assert!(
            text.ends_with("STATUS: FAILED\nREASON:\nUnknown reason of failure."),
            "{text}"
        );
    }

    #[test]
    fn the_file_name_is_javas_with_a_utc_stamp() {
        // `date -u -r 1788534245 +%Y%m%d-%H%M%S` -> 20260904-150405
        assert_eq!(
            report_file_name("Secret", at(1_788_534_245)),
            "healthReport_Secret_20260904-150405.log"
        );
        assert_eq!(
            report_file_name("Secret", UNIX_EPOCH),
            "healthReport_Secret_19700101-000000.log"
        );
    }

    #[test]
    fn a_vault_name_with_separators_cannot_escape_the_directory() {
        let name = report_file_name("../../etc/pw", UNIX_EPOCH);
        assert_eq!(name, "healthReport_.._.._etc_pw_19700101-000000.log");
        assert!(!name.contains('/') && !name.contains('\\'), "{name}");
        assert!(name.starts_with("healthReport_"), "{name}");
        // Windows separators and control characters go too; anything else survives.
        assert_eq!(
            report_file_name("a\\b\u{0}c\nd Ü", UNIX_EPOCH),
            "healthReport_a_b_c_d Ü_19700101-000000.log"
        );
    }

    #[test]
    fn the_report_is_written_whole_and_leaves_no_temporary_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_report(dir.path(), "healthReport_V_19700101-000000.log", "hello\n")
            .expect("the report is written");
        assert_eq!(path, dir.path().join("healthReport_V_19700101-000000.log"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "hello\n");
        let left: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(left, vec!["healthReport_V_19700101-000000.log".to_string()]);
    }

    #[test]
    fn an_existing_report_is_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let name = "healthReport_V_19700101-000000.log";
        let first = write_report(dir.path(), name, "first").unwrap();
        let second = write_report(dir.path(), name, "second").unwrap();
        let third = write_report(dir.path(), name, "third").unwrap();
        assert_eq!(first.file_name().unwrap(), name);
        // The suffix goes before the extension, so every report is still a `.log`.
        assert_eq!(
            second.file_name().unwrap(),
            "healthReport_V_19700101-000000-1.log"
        );
        assert_eq!(
            third.file_name().unwrap(),
            "healthReport_V_19700101-000000-2.log"
        );
        assert_eq!(std::fs::read_to_string(&first).unwrap(), "first");
        assert_eq!(std::fs::read_to_string(&second).unwrap(), "second");
        assert_eq!(std::fs::read_to_string(&third).unwrap(), "third");
    }

    /// The `--report FILE` rule: the report lands at the path the user named, every time.
    #[test]
    fn a_named_target_is_replaced_while_the_automatic_name_still_steps_aside() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("r.log");
        assert_eq!(write_report_to(&target, "first", true).unwrap(), target);
        assert_eq!(write_report_to(&target, "second", true).unwrap(), target);
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "second");
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            1,
            "no sibling and no leftover temporary file"
        );
        // The same call with `overwrite = false` is `write_report`, suffix and all.
        let stepped_aside = write_report_to(&target, "third", false).unwrap();
        assert_eq!(stepped_aside.file_name().unwrap(), "r-1.log");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "second");
        assert_eq!(std::fs::read_to_string(&stepped_aside).unwrap(), "third");
    }

    #[test]
    fn a_target_without_a_file_name_is_rejected() {
        let err = write_report_to(Path::new("/"), "x", true).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn a_name_without_an_extension_takes_the_suffix_at_the_end() {
        assert_eq!(candidate_name("report.log", 0), "report.log");
        assert_eq!(candidate_name("report.log", 7), "report-7.log");
        assert_eq!(candidate_name("report", 1), "report-1");
        assert_eq!(candidate_name("a.b.log", 1), "a.b-1.log");
    }

    #[test]
    fn a_missing_directory_is_an_error_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let err = write_report(&dir.path().join("nope"), "r.log", "x").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn the_calendar_agrees_with_the_pinned_instants() {
        assert_eq!(civil_utc(1_788_534_245), (2026, 9, 4, 15, 4, 5));
        assert_eq!(civil_utc(0), (1970, 1, 1, 0, 0, 0));
        // A leap day, the one date the March-based era arithmetic exists for.
        assert_eq!(civil_utc(951_782_400), (2000, 2, 29, 0, 0, 0));
        assert_eq!(civil_utc(951_782_400 - 1), (2000, 2, 28, 23, 59, 59));
        // Before the epoch the arithmetic still dates correctly; only the callers clamp.
        assert_eq!(civil_utc(-1), (1969, 12, 31, 23, 59, 59));
    }
}
