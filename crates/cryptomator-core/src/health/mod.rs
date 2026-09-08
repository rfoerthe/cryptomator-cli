//! The health check framework, ported from cryptofs 2.10.0
//! (`org.cryptomator.cryptofs.health.api`).
//!
//! A [`HealthCheck`] traverses the ciphertext of an unlocked vault and reports [`DiagnosticResult`]s
//! through a sink. Every result carries the [`Severity`] and the message of its Java counterpart
//! verbatim, plus the name of that counterpart in [`DiagnosticResult::kind`] so tests can match the
//! findings of `tests/fixtures/broken_health/expected-findings.json` by result class. Results that
//! can be repaired carry a [`Fix`].
//!
//! Unlike Java, which streams the results of a check over an `ExecutorService`, the checks run
//! sequentially: a deterministic report is worth more than the parallelism, and the vault
//! traversals are I/O bound anyway.
use crate::constants::DATA_DIR_NAME;
use crate::crypto::cryptor::Cryptor;
use crate::error::{CoreError, Result};
use crate::vault::open::OpenedVault;
use crate::vault_config::VaultConfig;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub mod dir_id;
pub mod file_type;
pub mod orphan;
pub mod report;
pub mod shortened;

/// The ids of all checks, in the order they run and are reported.
pub const CHECK_IDS: [&str; 3] = ["dirid", "type", "shortened"];

/// [`DiagnosticResult::kind`] of the result a check reports when it could not finish (Java's
/// `CheckFailed`). It is the one kind the report renders differently -- as Java's `STATUS: FAILED`
/// section -- so it is named here rather than spelled out at both ends.
pub const CHECK_FAILED_KIND: &str = "CheckFailed";

/// How bad a finding is (`DiagnosticResult.Severity`).
///
/// The declaration order is the Java order and is what `Ord` compares: `Good < Info < Warn <
/// Critical`. The `--fail-on` and `--fix-severity` thresholds of the CLI depend on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// No complaints.
    Good,
    /// Noteworthy, but neither structural damage nor data loss.
    Info,
    /// The vault structure is compromised, no apparent data loss.
    Warn,
    /// The vault structure is compromised and data was lost.
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Good => "GOOD",
            Severity::Info => "INFO",
            Severity::Warn => "WARN",
            Severity::Critical => "CRITICAL",
        }
    }

    /// Parses a `--fail-on` threshold. Only `WARN` and `CRITICAL` are thresholds: failing on `GOOD`
    /// or `INFO` would make every report a failure.
    pub fn parse_threshold(input: &str) -> Result<Severity> {
        match input.to_ascii_uppercase().as_str() {
            "WARN" => Ok(Severity::Warn),
            "CRITICAL" => Ok(Severity::Critical),
            _ => Err(CoreError::InvalidArgument(format!(
                "unknown severity {input:?}; expected WARN or CRITICAL"
            ))),
        }
    }

    /// Parses a `--fix-severity` threshold. Unlike `--fail-on`, `INFO` is a legitimate threshold
    /// here: `--fix` repairs a finding, it does not fail the report, so asking it to also repair
    /// every `INFO` finding -- e.g. the desktop app's `LooseDirFile` and `MissingDirIdBackup` fixes
    /// -- is a sensible request rather than a report that always fails. `GOOD` stays excluded: it
    /// never carries a fix, so accepting it would only invite a `--fix-severity GOOD` that silently
    /// fixes nothing.
    pub fn parse_fix_severity(input: &str) -> Result<Severity> {
        match input.to_ascii_uppercase().as_str() {
            "INFO" => Ok(Severity::Info),
            "WARN" => Ok(Severity::Warn),
            "CRITICAL" => Ok(Severity::Critical),
            _ => Err(CoreError::InvalidArgument(format!(
                "unknown severity {input:?}; expected INFO, WARN or CRITICAL"
            ))),
        }
    }
}

impl fmt::Display for Severity {
    /// Through [`fmt::Formatter::pad`], not `write_str`: the report's severity column is a `{:>8}`,
    /// and a `Display` that writes straight to the formatter silently ignores width and alignment.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
    }
}

/// A repair for a single [`DiagnosticResult`] (`DiagnosticResult.Fix`).
///
/// "Fix" does not mean lost data comes back; it means the reported inconsistency is gone
/// afterwards. Applying a fix twice must not fail — the CLI may re-run `--fix` on a report.
pub trait Fix: fmt::Debug + Send {
    /// One line for the report, e.g. `move d/AA/BBB… to the recovery directory`.
    fn describe(&self) -> String;

    /// Performs the repair. Only I/O errors are reported; anything else is a bug in the fix.
    fn apply(&self, ctx: &CheckContext) -> io::Result<()>;
}

/// One finding of one check.
#[derive(Debug)]
pub struct DiagnosticResult {
    pub severity: Severity,
    /// The id of the reporting check, one of [`CHECK_IDS`].
    pub check: &'static str,
    /// The name of the Java `DiagnosticResult` class, e.g. `OrphanContentDir`. The fixture manifest
    /// `expected-findings.json` names the findings by this, so it is part of the contract.
    pub kind: &'static str,
    /// Human-readable summary, word for word Java's `toString()`.
    pub message: String,
    /// The affected nodes, vault-relative (`d/AA/BBBB…/foo.c9r`).
    pub paths: Vec<PathBuf>,
    pub fix: Option<Box<dyn Fix>>,
}

impl DiagnosticResult {
    pub fn new(
        check: &'static str,
        kind: &'static str,
        severity: Severity,
        message: String,
        paths: Vec<PathBuf>,
    ) -> Self {
        Self {
            severity,
            check,
            kind,
            message,
            paths,
            fix: None,
        }
    }

    pub fn with_fix(mut self, fix: Box<dyn Fix>) -> Self {
        self.fix = Some(fix);
        self
    }

    pub fn fixable(&self) -> bool {
        self.fix.is_some()
    }
}

/// One check of the catalogue (`HealthCheck`).
pub trait HealthCheck: fmt::Debug {
    /// The stable id used by `--check`, one of [`CHECK_IDS`].
    fn id(&self) -> &'static str;

    /// The display name for the report, Java's `HealthCheck.name()`.
    fn name(&self) -> &'static str;

    /// Traverses the vault and hands every finding to `sink`. A check reports its own failures as
    /// `CRITICAL` results (Java's `CheckFailed`) instead of returning an error; a panic is a bug,
    /// not a finding, and is not caught.
    fn run(&self, ctx: &CheckContext, sink: &mut dyn FnMut(DiagnosticResult));
}

/// Everything a check or a fix needs about the unlocked vault.
#[derive(Debug)]
pub struct CheckContext {
    /// Absolute path of the vault directory (the parent of `d/`).
    pub vault_path: PathBuf,
    /// Shared so a fix can hand it to helpers without borrowing the whole context.
    pub cryptor: Arc<Cryptor>,
    pub config: VaultConfig,
    /// `config.shortening_threshold` as a `usize`, the unit every name-length comparison uses.
    pub shortening_threshold: usize,
}

impl CheckContext {
    pub fn new(vault_path: PathBuf, cryptor: Arc<Cryptor>, config: VaultConfig) -> Self {
        let shortening_threshold = config.shortening_threshold as usize;
        Self {
            vault_path,
            cryptor,
            config,
            shortening_threshold,
        }
    }

    /// Takes the vault by value: [`Cryptor`] is deliberately not `Clone` (it holds key material),
    /// so the context adopts the one the unlock produced instead of deriving a second one.
    pub fn from_opened(opened: OpenedVault) -> Self {
        let OpenedVault {
            path,
            config,
            cryptor,
            ..
        } = opened;
        Self::new(path, Arc::new(cryptor), config)
    }

    /// `<vault>/d`.
    pub fn data_dir(&self) -> PathBuf {
        self.vault_path.join(DATA_DIR_NAME)
    }

    /// Turns a vault-relative path from a [`DiagnosticResult`] back into an absolute one.
    pub fn resolve(&self, relative: &Path) -> PathBuf {
        self.vault_path.join(relative)
    }

    /// Vault-relative form of `absolute`; paths outside the vault are passed through unchanged.
    pub fn relativize(&self, absolute: &Path) -> PathBuf {
        absolute
            .strip_prefix(&self.vault_path)
            .unwrap_or(absolute)
            .to_path_buf()
    }
}

/// The catalogue, in report order.
pub fn all_checks() -> Vec<Box<dyn HealthCheck>> {
    vec![
        Box::new(dir_id::DirIdCheck),
        Box::new(file_type::CiphertextFileTypeCheck),
        Box::new(shortened::ShortenedNamesCheck),
    ]
}

/// Selects the checks named by `ids`, always in catalogue order and without duplicates, no matter
/// how the user ordered or repeated them.
pub fn checks_by_ids(ids: &[&str]) -> Result<Vec<Box<dyn HealthCheck>>> {
    for id in ids {
        if !CHECK_IDS.contains(id) {
            return Err(unknown_check(id));
        }
    }
    Ok(all_checks()
        .into_iter()
        .filter(|check| ids.contains(&check.id()))
        .collect())
}

/// Runs the checks named by `ids` in catalogue order.
///
/// Every finding is handed to `sink` the moment it is reported (the CLI prints progress from it),
/// while the returned vector is sorted by severity descending and then by path, which is the order
/// of the report.
pub fn run_checks(
    ids: &[&str],
    ctx: &CheckContext,
    sink: &mut dyn FnMut(&DiagnosticResult),
) -> Result<Vec<DiagnosticResult>> {
    let checks = checks_by_ids(ids)?;
    Ok(run_selected(&checks, ctx, sink))
}

/// The body of [`run_checks`] once the ids are resolved; also the seam the tests use to run checks
/// that actually report something while the catalogue is still made of placeholders.
fn run_selected(
    checks: &[Box<dyn HealthCheck>],
    ctx: &CheckContext,
    sink: &mut dyn FnMut(&DiagnosticResult),
) -> Vec<DiagnosticResult> {
    let mut results = Vec::new();
    for check in checks {
        check.run(ctx, &mut |result| {
            sink(&result);
            results.push(result);
        });
    }
    // `sort_by` is stable, so findings of equal severity and path keep the order they were found in.
    results.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.paths.cmp(&b.paths))
    });
    results
}

fn unknown_check(id: &str) -> CoreError {
    CoreError::InvalidArgument(format!(
        "unknown check {id:?}; valid checks are {}",
        CHECK_IDS.join(", ")
    ))
}

// ------------------------------------------------------------------------------------------------
// Traversal bits shared by all three checks.
// ------------------------------------------------------------------------------------------------

/// An I/O error paired with the node that was being visited when it happened.
///
/// Java's `walkFileTree` throws a `FileSystemException` that names the file and the checks log it;
/// we have no log, so the path travels with the error up to the single [`check_failed`] result the
/// aborted traversal produces. Without it one unreadable node anywhere below `d/` would yield
/// nothing but "Permission denied" — nothing a repair could act on.
#[derive(Debug)]
pub(crate) struct VisitError {
    /// Absolute; the reporting side relativizes it.
    pub path: PathBuf,
    pub error: io::Error,
}

/// The result of one visited node. Spelled out because this module's `Result` is
/// [`crate::error::Result`].
pub(crate) type VisitResult = std::result::Result<(), VisitError>;

/// `Err(error)` at `path`, for `map_err`.
pub(crate) fn at(path: &Path) -> impl FnOnce(io::Error) -> VisitError + '_ {
    move |error| VisitError {
        path: path.to_path_buf(),
        error,
    }
}

/// `CheckFailed`: the traversal itself broke. Java logs the cause and prints only a hint at the
/// log; a CLI has no log to point at, so the error text goes into the message.
pub(crate) fn check_failed(
    check: &'static str,
    path: &Path,
    error: &io::Error,
) -> DiagnosticResult {
    DiagnosticResult::new(
        check,
        CHECK_FAILED_KIND,
        Severity::Critical,
        format!(
            "Check failed: Traversal of data dir failed: {} ({error})",
            path.display()
        ),
        vec![path.to_path_buf()],
    )
}

/// `Files.walkFileTree(dataDir, Set.of(), max_depth, visitor)`, reduced to what the `type` and the
/// `shortened` check need: `visit` is called for every entry at exactly `max_depth` that is a
/// directory.
///
/// That is not a shortcut but the same set of nodes Java sees: a directory *below* the maximum depth
/// reaches `preVisitDirectory` (which neither visitor overrides) and only one at the maximum depth
/// reaches `visitFile`; regular files reach `visitFile` at every depth but are dropped by both
/// visitors' `attrs.isDirectory()` guard.
///
/// Entries are sorted by name so that the same vault always produces the same report; Java takes the
/// order of the directory stream. Symlinks are never followed (`walkFileTree` without
/// `FOLLOW_LINKS`), so a symlinked directory is a "file" and is skipped.
pub(crate) fn walk_leaf_dirs(
    dir: &Path,
    depth: usize,
    max_depth: usize,
    visit: &mut dyn FnMut(&Path) -> VisitResult,
) -> VisitResult {
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(at(dir))? {
        let entry = entry.map_err(at(dir))?;
        let file_type = entry
            .file_type()
            .map_err(at(&dir.join(entry.file_name())))?;
        entries.push((entry.file_name(), file_type));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, file_type) in entries {
        if !file_type.is_dir() {
            continue;
        }
        let path = dir.join(&name);
        if depth + 1 < max_depth {
            walk_leaf_dirs(&path, depth + 1, max_depth, visit)?;
        } else {
            visit(&path)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::cryptor::CipherCombo;
    use crate::crypto::masterkey::Masterkey;

    /// A check that reports the results it was built with, in the given order.
    #[derive(Debug)]
    struct Canned {
        id: &'static str,
        results: Vec<(Severity, &'static str)>,
    }

    impl HealthCheck for Canned {
        fn id(&self) -> &'static str {
            self.id
        }

        fn name(&self) -> &'static str {
            "Canned Check"
        }

        fn run(&self, _ctx: &CheckContext, sink: &mut dyn FnMut(DiagnosticResult)) {
            for (severity, path) in &self.results {
                sink(DiagnosticResult::new(
                    self.id,
                    "Canned",
                    *severity,
                    format!("{path} is {severity}"),
                    vec![PathBuf::from(path)],
                ));
            }
        }
    }

    fn ctx() -> CheckContext {
        let masterkey = Masterkey::from_raw([0x42; 64]);
        let config = VaultConfig::create_new(CipherCombo::SivGcm, 220);
        let cryptor = Cryptor::new(config.cipher_combo, &masterkey);
        CheckContext::new(PathBuf::from("/vault"), Arc::new(cryptor), config)
    }

    #[test]
    fn severities_order_from_good_to_critical() {
        assert!(Severity::Good < Severity::Info);
        assert!(Severity::Info < Severity::Warn);
        assert!(Severity::Warn < Severity::Critical);
        assert_eq!(Severity::Critical.as_str(), "CRITICAL");
        assert_eq!(Severity::Good.to_string(), "GOOD");
        // The report's severity column is a `{:>8}`; `Display` has to honour it.
        assert_eq!(format!("{:>8}", Severity::Good), "    GOOD");
        assert_eq!(format!("{:>8}", Severity::Critical), "CRITICAL");
    }

    #[test]
    fn only_warn_and_critical_are_thresholds() {
        assert_eq!(Severity::parse_threshold("warn").unwrap(), Severity::Warn);
        assert_eq!(
            Severity::parse_threshold("CRITICAL").unwrap(),
            Severity::Critical
        );
        assert!(Severity::parse_threshold("INFO").is_err());
        assert!(Severity::parse_threshold("").is_err());
    }

    #[test]
    fn fix_severity_also_accepts_info_but_not_good() {
        assert_eq!(
            Severity::parse_fix_severity("info").unwrap(),
            Severity::Info
        );
        assert_eq!(
            Severity::parse_fix_severity("WARN").unwrap(),
            Severity::Warn
        );
        assert_eq!(
            Severity::parse_fix_severity("CRITICAL").unwrap(),
            Severity::Critical
        );
        assert!(Severity::parse_fix_severity("GOOD").is_err());
        assert!(Severity::parse_fix_severity("").is_err());
    }

    #[test]
    fn the_catalogue_has_three_checks_in_a_fixed_order() {
        let ids: Vec<_> = all_checks().iter().map(|c| c.id()).collect();
        assert_eq!(ids, vec!["dirid", "type", "shortened"]);
        assert_eq!(ids, CHECK_IDS.to_vec());
        assert!(all_checks().iter().all(|c| !c.name().is_empty()));
    }

    #[test]
    fn checks_by_ids_keeps_the_catalogue_order_and_dedupes() {
        let selected = checks_by_ids(&["shortened", "dirid", "dirid"]).unwrap();
        let ids: Vec<_> = selected.iter().map(|c| c.id()).collect();
        assert_eq!(ids, vec!["dirid", "shortened"]);
    }

    #[test]
    fn an_unknown_check_names_the_valid_ones() {
        let err = checks_by_ids(&["bogus"]).unwrap_err().to_string();
        assert!(
            err.ends_with(r#"unknown check "bogus"; valid checks are dirid, type, shortened"#),
            "{err}"
        );
        assert!(matches!(
            run_checks(&["dirid", "bogus"], &ctx(), &mut |_| {}),
            Err(CoreError::InvalidArgument(_))
        ));
    }

    #[test]
    fn every_check_turns_an_unreadable_vault_into_one_check_failed() {
        // `/vault` does not exist, so all three traversals fail at their first `read_dir`. Each
        // check reports that once and stops, instead of returning an error or panicking.
        let mut seen = 0;
        let results = run_checks(&CHECK_IDS, &ctx(), &mut |_| seen += 1).unwrap();
        assert_eq!(seen, CHECK_IDS.len());
        assert_eq!(results.len(), CHECK_IDS.len(), "{results:#?}");
        let checks: Vec<&str> = results.iter().map(|r| r.check).collect();
        for id in CHECK_IDS {
            assert!(checks.contains(&id), "{results:#?}");
        }
        assert!(
            results
                .iter()
                .all(|r| r.kind == "CheckFailed" && r.severity == Severity::Critical),
            "{results:#?}"
        );
    }

    #[test]
    fn the_report_is_sorted_by_severity_then_path_while_the_sink_streams() {
        let checks: Vec<Box<dyn HealthCheck>> = vec![
            Box::new(Canned {
                id: "dirid",
                results: vec![
                    (Severity::Info, "d/b"),
                    (Severity::Critical, "d/z"),
                    (Severity::Warn, "d/c"),
                ],
            }),
            Box::new(Canned {
                id: "type",
                results: vec![(Severity::Critical, "d/a"), (Severity::Good, "d/a")],
            }),
        ];
        let mut streamed = Vec::new();
        let results = run_selected(&checks, &ctx(), &mut |r| {
            streamed.push(r.paths[0].display().to_string())
        });

        let ordered: Vec<_> = results
            .iter()
            .map(|r| (r.severity, r.paths[0].display().to_string()))
            .collect();
        assert_eq!(
            ordered,
            vec![
                (Severity::Critical, "d/a".to_string()),
                (Severity::Critical, "d/z".to_string()),
                (Severity::Warn, "d/c".to_string()),
                (Severity::Info, "d/b".to_string()),
                (Severity::Good, "d/a".to_string()),
            ]
        );
        // The sink sees the findings as they are reported, check by check, not in report order.
        assert_eq!(streamed, vec!["d/b", "d/z", "d/c", "d/a", "d/a"]);
        assert!(results.iter().all(|r| !r.fixable()));
    }

    #[test]
    fn a_result_carries_its_fix() {
        #[derive(Debug)]
        struct Noop;
        impl Fix for Noop {
            fn describe(&self) -> String {
                "do nothing".into()
            }
            fn apply(&self, _ctx: &CheckContext) -> io::Result<()> {
                Ok(())
            }
        }
        let result = DiagnosticResult::new(
            "dirid",
            "MissingContentDir",
            Severity::Warn,
            "gone".into(),
            vec![PathBuf::from("d/AA/BB")],
        )
        .with_fix(Box::new(Noop));

        assert!(result.fixable());
        let fix = result.fix.as_ref().unwrap();
        assert_eq!(fix.describe(), "do nothing");
        fix.apply(&ctx()).unwrap();
    }

    #[test]
    fn the_context_resolves_and_relativizes_paths() {
        let ctx = ctx();
        assert_eq!(ctx.data_dir(), PathBuf::from("/vault/d"));
        assert_eq!(ctx.shortening_threshold, 220);
        assert_eq!(
            ctx.resolve(Path::new("d/AA/BB")),
            PathBuf::from("/vault/d/AA/BB")
        );
        assert_eq!(
            ctx.relativize(Path::new("/vault/d/AA/BB")),
            PathBuf::from("d/AA/BB")
        );
        // Outside the vault: unchanged rather than a panic or a bogus relative path.
        assert_eq!(
            ctx.relativize(Path::new("/elsewhere/x")),
            PathBuf::from("/elsewhere/x")
        );
    }
}
