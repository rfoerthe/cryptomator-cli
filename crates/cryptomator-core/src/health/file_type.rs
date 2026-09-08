//! The `type` check, ported from cryptofs 2.10.0
//! (`org.cryptomator.cryptofs.health.type.CiphertextFileTypeCheck`).
//!
//! Every `.c9r`/`.c9s` *directory* of the vault must say what it is through exactly one type file:
//! `dir.c9r` makes it a directory, `symlink.c9r` a symlink and — only inside a `.c9s` directory —
//! `contents.c9r` a file. None of them is [`UnknownType`](unknown_type), more than one is
//! [`AmbiguousType`](ambiguous_type); the good case is [`KnownType`](known_type).
//!
//! Like Java, the check reads nothing but directory entries and metadata: it never decrypts a name
//! and never opens a type file, so it works on a vault whose masterkey is fine but whose structure
//! is not.
use super::{
    walk_leaf_dirs, CheckContext, DiagnosticResult, Fix, HealthCheck, Severity, VisitResult,
};
use crate::constants::{
    CONTENTS_FILE_NAME, CRYPTOMATOR_FILE_SUFFIX, DEFLATED_FILE_SUFFIX, DIR_FILE_NAME,
    SYMLINK_FILE_NAME,
};
use crate::fs::CiphertextFileType;
use std::io;
use std::path::{Path, PathBuf};

/// The id `--check type` selects, `CHECK_IDS[1]`.
pub const TYPE_CHECK_ID: &str = "type";
/// `CiphertextFileTypeCheck.name()`.
pub const TYPE_CHECK_NAME: &str = "Resource Type Check";
/// `CiphertextFileTypeCheck.MAX_TRAVERSAL_DEPTH`: `d/2/30/Fo0==.c9r`, counted from `d` = 0. An entry
/// at exactly this depth is visited but never descended into.
pub const MAX_TRAVERSAL_DEPTH: usize = 3;

/// Determines the [`CiphertextFileType`] of every node directory from the type files it holds.
#[derive(Debug)]
pub struct CiphertextFileTypeCheck;

impl HealthCheck for CiphertextFileTypeCheck {
    fn id(&self) -> &'static str {
        TYPE_CHECK_ID
    }

    fn name(&self) -> &'static str {
        TYPE_CHECK_NAME
    }

    fn run(&self, ctx: &CheckContext, sink: &mut dyn FnMut(DiagnosticResult)) {
        let data_dir = ctx.data_dir();
        // `DirVisitor.visitFile`: a directory named `*.c9r` is checked without `contents.c9r`, one
        // named `*.c9s` with it. Everything else is not a node and is ignored.
        let mut visit = |dir: &Path| -> VisitResult {
            let name = dir
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            if name.ends_with(CRYPTOMATOR_FILE_SUFFIX) {
                sink(check_ciphertext_type(ctx, dir, false));
            } else if name.ends_with(DEFLATED_FILE_SUFFIX) {
                sink(check_ciphertext_type(ctx, dir, true));
            }
            Ok(())
        };
        // Java lets any IOException escape `walkFileTree` and turns it into a single `CheckFailed`.
        if let Err(e) = walk_leaf_dirs(&data_dir, 0, MAX_TRAVERSAL_DEPTH, &mut visit) {
            sink(super::check_failed(
                TYPE_CHECK_ID,
                &ctx.relativize(&e.path),
                &e.error,
            ));
        }
    }
}

/// `DirVisitor.checkCiphertextType`.
fn check_ciphertext_type(
    ctx: &CheckContext,
    dir: &Path,
    check_for_contents_c9r: bool,
) -> DiagnosticResult {
    let types = contained_ciphertext_file_types(dir, check_for_contents_c9r);
    let rel = ctx.relativize(dir);
    match types.as_slice() {
        [] => unknown_type(&rel),
        [only] => known_type(&rel, *only),
        many => ambiguous_type(&rel, many),
    }
}

/// `DirVisitor.containedCiphertextFileTypes`, in the declaration order of Java's `CiphertextFileType`
/// — the order an `EnumSet` iterates and prints in, no matter how it was filled.
fn contained_ciphertext_file_types(
    dir: &Path,
    check_for_contents_c9r: bool,
) -> Vec<CiphertextFileType> {
    let mut types = Vec::new();
    if check_for_contents_c9r && is_regular_file(&dir.join(CONTENTS_FILE_NAME)) {
        types.push(CiphertextFileType::File);
    }
    if is_regular_file(&dir.join(DIR_FILE_NAME)) {
        types.push(CiphertextFileType::Directory);
    }
    if is_regular_file(&dir.join(SYMLINK_FILE_NAME)) {
        types.push(CiphertextFileType::Symlink);
    }
    types
}

/// `Files.isRegularFile(path, NOFOLLOW_LINKS)`: a symlink named `dir.c9r` does not make a directory,
/// and an unreadable node is "no type file" rather than a failed traversal — exactly as in Java,
/// where `isRegularFile` swallows its `IOException`.
fn is_regular_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.is_file())
}

/// `CiphertextFileType.name()`.
fn type_name(file_type: CiphertextFileType) -> &'static str {
    match file_type {
        CiphertextFileType::File => "FILE",
        CiphertextFileType::Directory => "DIRECTORY",
        CiphertextFileType::Symlink => "SYMLINK",
    }
}

fn result(
    kind: &'static str,
    severity: Severity,
    message: String,
    paths: Vec<PathBuf>,
) -> DiagnosticResult {
    DiagnosticResult::new(TYPE_CHECK_ID, kind, severity, message, paths)
}

/// `KnownType`: exactly one valid type file.
fn known_type(cipher_dir: &Path, file_type: CiphertextFileType) -> DiagnosticResult {
    result(
        "KnownType",
        Severity::Good,
        format!(
            "Node {} with determined type {}.",
            cipher_dir.display(),
            type_name(file_type)
        ),
        vec![cipher_dir.to_path_buf()],
    )
}

/// `UnknownType`: a node directory without any type file. The fix frees the name it occupies.
fn unknown_type(cipher_dir: &Path) -> DiagnosticResult {
    result(
        "UnknownType",
        Severity::Critical,
        format!("C9r dir {} of unknown type.", cipher_dir.display()),
        vec![cipher_dir.to_path_buf()],
    )
    .with_fix(Box::new(DeleteUnknownNode {
        cipher_dir: cipher_dir.to_path_buf(),
    }))
}

/// `AmbiguousType`: two or three type files, so the node is a directory *and* a symlink (and maybe a
/// file). Java has no fix — which of them is the truth is not decidable from the ciphertext.
fn ambiguous_type(cipher_dir: &Path, types: &[CiphertextFileType]) -> DiagnosticResult {
    // `EnumSet.toString()`, e.g. `[DIRECTORY, SYMLINK]`.
    let printed: Vec<&str> = types.iter().copied().map(type_name).collect();
    result(
        "AmbiguousType",
        Severity::Critical,
        format!(
            "Node {} of ambiguous type. Possible types are: [{}]",
            cipher_dir.display(),
            printed.join(", ")
        ),
        vec![cipher_dir.to_path_buf()],
    )
}

/// `UnknownType.fix`: `Files.delete(pathToVault.resolve(cipherDir))`.
///
/// `remove_dir`, never `remove_dir_all`: Java's `Files.delete` refuses a non-empty directory, and so
/// do we. A node of unknown type may well hold payload — a `contents.c9r` below a `.c9r` instead of a
/// `.c9s` directory, say — and a fix must never delete what it does not understand. The finding then
/// survives the repair, which is the honest outcome.
#[derive(Debug)]
struct DeleteUnknownNode {
    cipher_dir: PathBuf,
}

impl Fix for DeleteUnknownNode {
    fn describe(&self) -> String {
        format!(
            "delete the empty node {} of unknown type",
            self.cipher_dir.display()
        )
    }

    fn apply(&self, ctx: &CheckContext) -> io::Result<()> {
        match std::fs::remove_dir(ctx.resolve(&self.cipher_dir)) {
            // Already gone: what makes a second `--fix` run a no-op.
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::testutil::new_vault;
    use crate::health::CHECK_IDS;
    use crate::vault::open::root_content_dir;

    fn vault() -> (tempfile::TempDir, CheckContext) {
        let (dir, cryptor, config) = new_vault(220);
        let ctx = CheckContext::new(dir.path().to_path_buf(), cryptor, config);
        (dir, ctx)
    }

    fn run(ctx: &CheckContext) -> Vec<DiagnosticResult> {
        let mut results = Vec::new();
        CiphertextFileTypeCheck.run(ctx, &mut |r| results.push(r));
        results
    }

    /// Creates `<root content dir>/<name>` and the type files listed in `type_files`.
    fn node(ctx: &CheckContext, name: &str, type_files: &[&str]) -> PathBuf {
        let dir = root_content_dir(&ctx.vault_path, &ctx.cryptor).join(name);
        std::fs::create_dir_all(&dir).unwrap();
        for file in type_files {
            std::fs::write(dir.join(file), b"x").unwrap();
        }
        dir
    }

    #[test]
    fn the_check_is_the_second_of_the_catalogue() {
        assert_eq!(CiphertextFileTypeCheck.id(), CHECK_IDS[1]);
        assert_eq!(CiphertextFileTypeCheck.id(), TYPE_CHECK_ID);
        assert_eq!(CiphertextFileTypeCheck.name(), "Resource Type Check");
    }

    #[test]
    fn a_fresh_vault_has_no_nodes_at_all() {
        let (_dir, ctx) = vault();
        assert!(run(&ctx).is_empty());
    }

    #[test]
    fn each_type_file_determines_the_type() {
        let (_dir, ctx) = vault();
        node(&ctx, "a.c9r", &[DIR_FILE_NAME]);
        node(&ctx, "b.c9r", &[SYMLINK_FILE_NAME]);
        node(&ctx, "c.c9s", &[CONTENTS_FILE_NAME]);
        let results = run(&ctx);
        let messages: Vec<&str> = results.iter().map(|r| r.message.as_str()).collect();
        assert_eq!(results.len(), 3, "{results:#?}");
        assert!(
            results.iter().all(|r| r.kind == "KnownType"),
            "{results:#?}"
        );
        assert!(results.iter().all(|r| r.severity == Severity::Good));
        assert!(results.iter().all(|r| !r.fixable()));
        assert!(
            messages
                .iter()
                .any(|m| m.ends_with("a.c9r with determined type DIRECTORY.")),
            "{messages:#?}"
        );
        assert!(
            messages
                .iter()
                .any(|m| m.ends_with("b.c9r with determined type SYMLINK.")),
            "{messages:#?}"
        );
        assert!(
            messages
                .iter()
                .any(|m| m.ends_with("c.c9s with determined type FILE.")),
            "{messages:#?}"
        );
        assert!(
            messages.iter().all(|m| m.starts_with("Node d/")),
            "{messages:#?}"
        );
    }

    #[test]
    fn contents_c9r_counts_only_inside_a_c9s_directory() {
        let (_dir, ctx) = vault();
        // A `contents.c9r` below a `.c9r` directory is not a type file: Java passes
        // `checkForContentsC9r = false` there, so the node stays of unknown type.
        node(&ctx, "a.c9r", &[CONTENTS_FILE_NAME]);
        let results = run(&ctx);
        assert_eq!(results.len(), 1, "{results:#?}");
        assert_eq!(results[0].kind, "UnknownType");
        assert_eq!(results[0].severity, Severity::Critical);
        assert!(results[0].message.starts_with("C9r dir d/"), "{results:#?}");
        assert!(results[0].message.ends_with("a.c9r of unknown type."));
    }

    #[test]
    fn two_type_files_are_ambiguous_and_print_the_java_enum_order() {
        let (_dir, ctx) = vault();
        node(&ctx, "a.c9r", &[SYMLINK_FILE_NAME, DIR_FILE_NAME]);
        node(
            &ctx,
            "b.c9s",
            &[SYMLINK_FILE_NAME, CONTENTS_FILE_NAME, DIR_FILE_NAME],
        );
        let results = run(&ctx);
        assert!(
            results.iter().all(|r| r.kind == "AmbiguousType"
                && r.severity == Severity::Critical
                && !r.fixable()),
            "{results:#?}"
        );
        let messages: Vec<&str> = results.iter().map(|r| r.message.as_str()).collect();
        assert!(
            messages.iter().any(|m| m
                .ends_with("a.c9r of ambiguous type. Possible types are: [DIRECTORY, SYMLINK]")),
            "{messages:#?}"
        );
        assert!(
            messages.iter().any(|m| m.ends_with(
                "b.c9s of ambiguous type. Possible types are: [FILE, DIRECTORY, SYMLINK]"
            )),
            "{messages:#?}"
        );
    }

    #[test]
    fn a_directory_named_like_a_type_file_is_no_type_file() {
        let (_dir, ctx) = vault();
        let dir = node(&ctx, "a.c9r", &[]);
        std::fs::create_dir(dir.join(DIR_FILE_NAME)).unwrap();
        let results = run(&ctx);
        assert_eq!(results.len(), 1, "{results:#?}");
        assert_eq!(results[0].kind, "UnknownType");
    }

    #[test]
    fn an_empty_unknown_node_is_deleted_by_its_fix_and_a_full_one_is_not() {
        let (_dir, ctx) = vault();
        let empty = node(&ctx, "a.c9r", &[]);
        let full = node(&ctx, "b.c9r", &["x"]);

        let results = run(&ctx);
        assert_eq!(results.len(), 2, "{results:#?}");
        for result in &results {
            let fix = result.fix.as_ref().expect("UnknownType is fixable");
            let outcome = fix.apply(&ctx);
            if result.paths[0].ends_with("a.c9r") {
                outcome.expect("the empty node is deleted");
            } else {
                // `Files.delete` on a non-empty directory throws; so does `remove_dir`.
                assert!(outcome.is_err(), "a non-empty node is never deleted");
            }
        }
        assert!(!empty.exists());
        assert!(full.join("x").is_file(), "nothing below it was touched");

        // Applying the fix a second time is a no-op, not a `NotFound` error.
        for result in &results {
            if result.paths[0].ends_with("a.c9r") {
                result
                    .fix
                    .as_ref()
                    .unwrap()
                    .apply(&ctx)
                    .expect("idempotent");
            }
        }
    }

    #[test]
    fn only_nodes_at_the_maximum_depth_are_checked() {
        let (_dir, ctx) = vault();
        // A `.c9r` directory one level too high is descended into, not checked (Java's
        // `preVisitDirectory` does nothing).
        let shallow = ctx.data_dir().join("XX.c9r");
        std::fs::create_dir_all(shallow.join("YY.c9r")).unwrap();
        // …and one level too deep is never reached.
        node(&ctx, "a.c9r", &[DIR_FILE_NAME]);
        std::fs::create_dir(
            root_content_dir(&ctx.vault_path, &ctx.cryptor)
                .join("a.c9r")
                .join("deep.c9r"),
        )
        .unwrap();

        let results = run(&ctx);
        assert_eq!(results.len(), 1, "{results:#?}");
        assert!(results[0].paths[0].ends_with("a.c9r"), "{results:#?}");
    }

    #[test]
    fn a_broken_traversal_is_reported_once_and_names_the_node() {
        let (_dir, ctx) = vault();
        // The data dir is gone: `walkFileTree` throws right away.
        std::fs::remove_dir_all(ctx.data_dir()).unwrap();
        let results = run(&ctx);
        assert_eq!(results.len(), 1, "{results:#?}");
        assert_eq!(results[0].kind, "CheckFailed");
        assert_eq!(results[0].check, TYPE_CHECK_ID);
        assert_eq!(results[0].severity, Severity::Critical);
        assert!(
            results[0]
                .message
                .starts_with("Check failed: Traversal of data dir failed: d"),
            "{}",
            results[0].message
        );
    }
}
