//! The `shortened` check, ported from cryptofs 2.10.0
//! (`org.cryptomator.cryptofs.health.shortened.ShortenedNamesCheck`).
//!
//! A name longer than the shortening threshold is stored as a directory
//! `BASE64URL(SHA1(name)).c9s` whose `name.c9s` holds the full ciphertext name. The check visits
//! every `.c9s` directory and verifies that promise, in Java's order: the name file must exist and
//! be a regular file, must be at most [`MAX_FILENAME_BUFFER_SIZE`] bytes, must contain a
//! base64url-encoded name ending in `.c9r` and nothing after it, and the directory must be named
//! after the SHA-1 of exactly that content.
//!
//! Two of the six results carry a fix: the trailing bytes of cryptofs#121 are cut off, and a
//! directory whose name does not match its `name.c9s` is renamed to the name it should have.
use super::{
    at, walk_leaf_dirs, CheckContext, DiagnosticResult, Fix, HealthCheck, Severity, VisitError,
    VisitResult,
};
use crate::constants::{CRYPTOMATOR_FILE_SUFFIX, DEFLATED_FILE_SUFFIX, INFLATED_FILE_NAME};
use crate::fs::long_names::{deflate_str, MAX_FILENAME_BUFFER_SIZE};
use std::io;
use std::path::{Path, PathBuf};

/// The id `--check shortened` selects, `CHECK_IDS[2]`.
pub const SHORTENED_CHECK_ID: &str = "shortened";
/// `ShortenedNamesCheck.name()`.
pub const SHORTENED_CHECK_NAME: &str = "Shortened Names Check";
/// `ShortenedNamesCheck.MAX_TRAVERSAL_DEPTH`, the same depth the `type` check uses.
pub const MAX_TRAVERSAL_DEPTH: usize = 3;

/// Checks every `.c9s` directory against the vault specification.
#[derive(Debug)]
pub struct ShortenedNamesCheck;

impl HealthCheck for ShortenedNamesCheck {
    fn id(&self) -> &'static str {
        SHORTENED_CHECK_ID
    }

    fn name(&self) -> &'static str {
        SHORTENED_CHECK_NAME
    }

    fn run(&self, ctx: &CheckContext, sink: &mut dyn FnMut(DiagnosticResult)) {
        let data_dir = ctx.data_dir();
        let mut visit = |dir: &Path| -> VisitResult {
            let deflated = dir
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .ends_with(DEFLATED_FILE_SUFFIX);
            if deflated {
                sink(check_shortened_name(ctx, dir)?);
            }
            Ok(())
        };
        // Java lets any IOException escape `walkFileTree` and turns it into a single `CheckFailed`.
        if let Err(e) = walk_leaf_dirs(&data_dir, 0, MAX_TRAVERSAL_DEPTH, &mut visit) {
            sink(super::check_failed(
                SHORTENED_CHECK_ID,
                &ctx.relativize(&e.path),
                &e.error,
            ));
        }
    }
}

/// `DirVisitor.checkShortenedName`: the first condition that holds decides, exactly as in Java,
/// where every branch returns.
fn check_shortened_name(
    ctx: &CheckContext,
    dir: &Path,
) -> std::result::Result<DiagnosticResult, VisitError> {
    let name_file = dir.join(INFLATED_FILE_NAME);
    let rel_dir = ctx.relativize(dir);
    let rel_name_file = ctx.relativize(&name_file);

    // `readAttributes(NOFOLLOW_LINKS)`: a missing name file is a finding, any other I/O error is a
    // broken traversal.
    let attrs = match std::fs::symlink_metadata(&name_file) {
        Ok(attrs) => attrs,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(missing_long_name(&rel_dir)),
        Err(e) => return Err(at(&name_file)(e)),
    };
    if !attrs.is_file() {
        return Ok(missing_long_name(&rel_dir));
    }
    if attrs.len() > MAX_FILENAME_BUFFER_SIZE {
        return Ok(obese_name_file(&rel_name_file, attrs.len()));
    }

    // `Files.readString(nameFile, UTF_8)` throws on malformed input, and that exception ends the
    // whole traversal in a `CheckFailed`; a non-UTF-8 name file does the same here.
    let bytes = std::fs::read(&name_file).map_err(at(&name_file))?;
    let long_name = String::from_utf8(bytes).map_err(|_| {
        at(&name_file)(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is not valid UTF-8", name_file.display()),
        ))
    })?;

    match check_syntax(&long_name) {
        SyntaxResult::Invalid => return Ok(not_decodable_long_name(&rel_name_file, &long_name)),
        SyntaxResult::TrailingBytes => {
            return Ok(trailing_bytes_in_name_file(&rel_name_file, &long_name))
        }
        SyntaxResult::Valid => {}
    }

    let expected_short_name = deflate_name(&long_name);
    if dir.file_name().unwrap_or_default().to_string_lossy() == expected_short_name {
        Ok(valid_shortened_file(&rel_dir))
    } else {
        Ok(long_short_names_mismatch(&rel_dir, expected_short_name))
    }
}

/// What [`check_syntax`] found in a `name.c9s`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyntaxResult {
    /// A base64url name followed by `.c9r` and nothing else.
    Valid,
    /// No `.c9r` at all, or a name that is not base64url.
    Invalid,
    /// Valid, but with bytes after the `.c9r` — <https://github.com/cryptomator/cryptofs/issues/121>.
    TrailingBytes,
}

/// `DirVisitor.checkSyntax`: is the stored string a base64url name ending in `.c9r`?
///
/// Java's `BaseEncoding.base64Url().canDecode` accepts padded *and* unpadded input while
/// [`data_encoding::BASE64URL`] insists on padding. Every real Cryptomator name is padded (its length
/// is a multiple of four), so the two agree on everything a healthy vault contains; they can only
/// differ on damaged input, where both are meant to say "invalid" and we are the stricter of the two.
pub fn check_syntax(to_analyse: &str) -> SyntaxResult {
    let Some(pos) = to_analyse.find(CRYPTOMATOR_FILE_SUFFIX) else {
        return SyntaxResult::Invalid;
    };
    if data_encoding::BASE64URL
        .decode(&to_analyse.as_bytes()[..pos])
        .is_err()
    {
        return SyntaxResult::Invalid;
    }
    if to_analyse.len() > pos + CRYPTOMATOR_FILE_SUFFIX.len() {
        return SyntaxResult::TrailingBytes;
    }
    SyntaxResult::Valid
}

/// `DirVisitor.deflate`: the `.c9s` directory name a long name must have,
/// `BASE64URL(SHA1(longName)).c9s`. The same arithmetic [`crate::fs::long_names::deflate`] uses.
pub fn deflate_name(long_name: &str) -> String {
    deflate_str(long_name)
}

fn result(
    kind: &'static str,
    severity: Severity,
    message: String,
    paths: Vec<PathBuf>,
) -> DiagnosticResult {
    DiagnosticResult::new(SHORTENED_CHECK_ID, kind, severity, message, paths)
}

/// `ValidShortenedFile`.
fn valid_shortened_file(c9s_dir: &Path) -> DiagnosticResult {
    result(
        "ValidShortenedFile",
        Severity::Good,
        format!("Found valid shortened resource at {}.", c9s_dir.display()),
        vec![c9s_dir.to_path_buf()],
    )
}

/// `MissingLongName`: no `name.c9s`, or not a regular file. Java offers no fix — the ciphertext name
/// it held is unrecoverable, and the `dirid` check's orphan adoption is what rescues such a node.
fn missing_long_name(c9s_dir: &Path) -> DiagnosticResult {
    result(
        "MissingLongName",
        Severity::Critical,
        format!(
            "Shortened resource {} either misses {INFLATED_FILE_NAME} or the file has invalid content.",
            c9s_dir.display()
        ),
        vec![c9s_dir.to_path_buf()],
    )
}

/// `ObeseNameFile`: "no sane person gives a file a 10kb long name". No fix in Java either.
fn obese_name_file(name_file: &Path, size: u64) -> DiagnosticResult {
    result(
        "ObeseNameFile",
        Severity::Critical,
        format!(
            "Long filename file {} with size {size} exceeds limit of {MAX_FILENAME_BUFFER_SIZE} for this type.",
            name_file.display()
        ),
        vec![name_file.to_path_buf()],
    )
}

/// `NotDecodableLongName`: the stored string is not a Cryptomator file name. No fix — guessing what
/// it was meant to be is not a repair.
fn not_decodable_long_name(name_file: &Path, long_name: &str) -> DiagnosticResult {
    result(
        "NotDecodableLongName",
        Severity::Critical,
        format!(
            "String \"{long_name}\" stored in {} is not a valid Cryptomator filename.",
            name_file.display()
        ),
        vec![name_file.to_path_buf()],
    )
}

/// `TrailingBytesInNameFile`: cryptofs#121 appended bytes behind the `.c9r`. The fix cuts them off.
fn trailing_bytes_in_name_file(name_file: &Path, long_name: &str) -> DiagnosticResult {
    result(
        "TrailingBytesInNameFile",
        Severity::Warn,
        format!(
            "Encrypted filename \"{long_name}\" stored in {} contains trailing bytes.",
            name_file.display()
        ),
        vec![name_file.to_path_buf()],
    )
    .with_fix(Box::new(TruncateTrailingBytes {
        name_file: name_file.to_path_buf(),
        long_name: long_name.to_owned(),
    }))
}

/// `LongShortNamesMismatch`: the directory is not named after the SHA-1 of its `name.c9s`, so nobody
/// looking for that long name finds it. The fix renames the directory to the expected name.
fn long_short_names_mismatch(c9s_dir: &Path, expected: String) -> DiagnosticResult {
    result(
        "LongShortNamesMismatch",
        Severity::Warn,
        format!(
            "Name of {} is not a base64url encoded SHA1 hash of String inside {INFLATED_FILE_NAME}.",
            c9s_dir.display()
        ),
        vec![c9s_dir.to_path_buf()],
    )
    .with_fix(Box::new(RenameToExpectedShortName {
        c9s_dir: c9s_dir.to_path_buf(),
        expected,
    }))
}

/// `TrailingBytesInNameFile.fix`: rewrite the name file with everything up to and including `.c9r`.
#[derive(Debug)]
struct TruncateTrailingBytes {
    name_file: PathBuf,
    long_name: String,
}

impl Fix for TruncateTrailingBytes {
    fn describe(&self) -> String {
        format!("cut the trailing bytes off {}", self.name_file.display())
    }

    fn apply(&self, ctx: &CheckContext) -> io::Result<()> {
        // The finding only exists because the suffix is there; `unwrap_or` keeps the fix total.
        let end = self
            .long_name
            .find(CRYPTOMATOR_FILE_SUFFIX)
            .map(|pos| pos + CRYPTOMATOR_FILE_SUFFIX.len())
            .unwrap_or(self.long_name.len());
        // Not `std::fs::write` over the original, which truncates first and writes second: a
        // crash in that window leaves an empty `name.c9s`, turning a WARN
        // (`TrailingBytesInNameFile`, still holding the long name) into a CRITICAL
        // (`MissingLongName`) that no fix can undo. The staged file plus `rename` is the same
        // pattern `health::report` uses, and it is what makes this the only fix in the module
        // that could otherwise lose data.
        //
        // Writing the truncated name over the old one is what makes the fix idempotent: a second
        // run writes the same bytes again.
        let target = ctx.resolve(&self.name_file);
        let mut staged = target.clone().into_os_string();
        staged.push(".tmp");
        let staged = PathBuf::from(staged);
        if let Err(e) = std::fs::write(&staged, &self.long_name.as_bytes()[..end]) {
            let _ = std::fs::remove_file(&staged);
            return Err(e);
        }
        // `rename` replaces the original in one step; a leftover `<name>.c9s.tmp` from a killed
        // run is overwritten by the next attempt rather than blocking it.
        if let Err(e) = std::fs::rename(&staged, &target) {
            let _ = std::fs::remove_file(&staged);
            return Err(e);
        }
        Ok(())
    }
}

/// `LongShortNamesMismatch.fix`: `Files.move(c9sDir, resolveSibling(expectedShortName))`.
#[derive(Debug)]
struct RenameToExpectedShortName {
    c9s_dir: PathBuf,
    expected: String,
}

impl Fix for RenameToExpectedShortName {
    fn describe(&self) -> String {
        format!("rename {} to {}", self.c9s_dir.display(), self.expected)
    }

    fn apply(&self, ctx: &CheckContext) -> io::Result<()> {
        let from = ctx.resolve(&self.c9s_dir);
        let to = from.with_file_name(&self.expected);
        match (
            crate::health::orphan::exists_no_follow(&from)?,
            crate::health::orphan::exists_no_follow(&to)?,
        ) {
            // Already renamed by an earlier `--fix` run: nothing left to do.
            (false, true) => Ok(()),
            // Java's `Files.move` without `REPLACE_EXISTING` throws here, and so do we: the node
            // that already occupies the expected name is a resource of its own, never scrap.
            (true, true) => Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} already exists", to.display()),
            )),
            _ => std::fs::rename(from, to),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::CONTENTS_FILE_NAME;
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
        ShortenedNamesCheck.run(ctx, &mut |r| results.push(r));
        results
    }

    /// A `.c9s` node below the root content dir, named `<name>` and holding `name.c9s` with
    /// `long_name` (unless that is `None`).
    fn c9s(ctx: &CheckContext, name: &str, long_name: Option<&[u8]>) -> PathBuf {
        let dir = root_content_dir(&ctx.vault_path, &ctx.cryptor).join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(CONTENTS_FILE_NAME), b"payload").unwrap();
        if let Some(long_name) = long_name {
            std::fs::write(dir.join(INFLATED_FILE_NAME), long_name).unwrap();
        }
        dir
    }

    /// A long ciphertext name of `len` base64url characters plus `.c9r`.
    fn long_name(len: usize) -> String {
        format!("{}{CRYPTOMATOR_FILE_SUFFIX}", "A".repeat(len))
    }

    #[test]
    fn the_check_is_the_third_of_the_catalogue() {
        assert_eq!(ShortenedNamesCheck.id(), CHECK_IDS[2]);
        assert_eq!(ShortenedNamesCheck.id(), SHORTENED_CHECK_ID);
        assert_eq!(ShortenedNamesCheck.name(), "Shortened Names Check");
    }

    #[test]
    fn check_syntax_matches_the_java_cases() {
        assert_eq!(check_syntax("abcd.c9r"), SyntaxResult::Valid);
        assert_eq!(check_syntax("abcd.c9r\n"), SyntaxResult::TrailingBytes);
        assert_eq!(check_syntax("abcd.c9rgarbage"), SyntaxResult::TrailingBytes);
        assert_eq!(check_syntax("abcd"), SyntaxResult::Invalid);
        assert_eq!(check_syntax(""), SyntaxResult::Invalid);
        assert_eq!(check_syntax("!!!!.c9r"), SyntaxResult::Invalid);
        assert_eq!(check_syntax(".c9r"), SyntaxResult::Valid);
        // Base64url, not base64: `+` and `/` are not part of the alphabet.
        assert_eq!(check_syntax("ab+/.c9r"), SyntaxResult::Invalid);
        assert_eq!(check_syntax("ab-_.c9r"), SyntaxResult::Valid);
        // Only the first `.c9r` counts, the rest is trailing.
        assert_eq!(check_syntax("abcd.c9r.c9r"), SyntaxResult::TrailingBytes);
    }

    #[test]
    fn deflate_name_is_the_long_name_providers_arithmetic() {
        let name = long_name(300);
        assert!(deflate_name(&name).ends_with(DEFLATED_FILE_SUFFIX));
        assert_eq!(
            deflate_name(&name),
            crate::fs::long_names::deflate(Path::new("/x").join(&name).as_path())
                .c9s_path
                .file_name()
                .unwrap()
                .to_string_lossy()
        );
        // 20 SHA-1 bytes are 28 base64 characters including the padding, plus `.c9s`.
        assert_eq!(deflate_name(&name).len(), 32);
    }

    #[test]
    fn a_well_formed_c9s_directory_is_good() {
        let (_dir, ctx) = vault();
        let name = long_name(300);
        c9s(&ctx, &deflate_name(&name), Some(name.as_bytes()));
        let results = run(&ctx);
        assert_eq!(results.len(), 1, "{results:#?}");
        assert_eq!(results[0].kind, "ValidShortenedFile");
        assert_eq!(results[0].severity, Severity::Good);
        assert!(!results[0].fixable());
        assert!(
            results[0]
                .message
                .starts_with("Found valid shortened resource at d/"),
            "{}",
            results[0].message
        );
        // A `.c9r` node is none of this check's business.
        c9s(&ctx, "AAAA.c9r", Some(name.as_bytes()));
        assert_eq!(run(&ctx).len(), 1);
    }

    #[test]
    fn a_missing_or_irregular_name_file_is_critical() {
        let (_dir, ctx) = vault();
        c9s(&ctx, "AAAA.c9s", None);
        // A directory named `name.c9s` is not a regular file either.
        let second = c9s(&ctx, "BBBB.c9s", None);
        std::fs::create_dir(second.join(INFLATED_FILE_NAME)).unwrap();

        let results = run(&ctx);
        assert_eq!(results.len(), 2, "{results:#?}");
        for result in &results {
            assert_eq!(result.kind, "MissingLongName");
            assert_eq!(result.severity, Severity::Critical);
            assert!(!result.fixable(), "Java offers no fix");
            assert!(
                result
                    .message
                    .ends_with("either misses name.c9s or the file has invalid content."),
                "{}",
                result.message
            );
        }
    }

    #[test]
    fn an_obese_name_file_is_reported_with_both_sizes() {
        let (_dir, ctx) = vault();
        let oversized = vec![b'A'; MAX_FILENAME_BUFFER_SIZE as usize + 1];
        c9s(&ctx, "AAAA.c9s", Some(&oversized));
        let results = run(&ctx);
        assert_eq!(results.len(), 1, "{results:#?}");
        assert_eq!(results[0].kind, "ObeseNameFile");
        assert_eq!(results[0].severity, Severity::Critical);
        assert!(!results[0].fixable());
        assert!(
            results[0]
                .message
                .ends_with("/name.c9s with size 10241 exceeds limit of 10240 for this type."),
            "{}",
            results[0].message
        );
        // The finding names the name file, not the directory.
        assert!(results[0].paths[0].ends_with(INFLATED_FILE_NAME));
    }

    #[test]
    fn a_name_file_that_is_no_ciphertext_name_is_not_decodable() {
        let (_dir, ctx) = vault();
        c9s(&ctx, "AAAA.c9s", Some(b"not a name"));
        let results = run(&ctx);
        assert_eq!(results.len(), 1, "{results:#?}");
        assert_eq!(results[0].kind, "NotDecodableLongName");
        assert_eq!(results[0].severity, Severity::Critical);
        assert!(!results[0].fixable());
        assert!(
            results[0]
                .message
                .starts_with("String \"not a name\" stored in d/"),
            "{}",
            results[0].message
        );
        assert!(results[0]
            .message
            .ends_with("is not a valid Cryptomator filename."));
    }

    #[test]
    fn trailing_bytes_are_reported_and_cut_off() {
        let (_dir, ctx) = vault();
        let name = long_name(300);
        let dir = c9s(
            &ctx,
            &deflate_name(&name),
            Some(format!("{name}garbage").as_bytes()),
        );

        let results = run(&ctx);
        assert_eq!(results.len(), 1, "{results:#?}");
        assert_eq!(results[0].kind, "TrailingBytesInNameFile");
        assert_eq!(results[0].severity, Severity::Warn);
        assert!(
            results[0].message.starts_with(&format!(
                "Encrypted filename \"{name}garbage\" stored in d/"
            )),
            "{}",
            results[0].message
        );
        assert!(results[0].message.ends_with("contains trailing bytes."));

        let fix = results[0].fix.as_ref().expect("the trailing bytes are cut");
        fix.apply(&ctx).expect("the fix applies");
        assert_eq!(
            std::fs::read_to_string(dir.join(INFLATED_FILE_NAME)).unwrap(),
            name
        );
        // The directory was already named after the *clean* name, so the node is good now — and a
        // second application changes nothing.
        fix.apply(&ctx).expect("idempotent");
        let after = run(&ctx);
        assert_eq!(after.len(), 1, "{after:#?}");
        assert_eq!(after[0].kind, "ValidShortenedFile");
        // The fix stages the truncated bytes next to the name file and renames over it, so the
        // original is replaced in one step and never sits there empty. Nothing of that staging is
        // left behind -- a `name.c9s.tmp` would be the only entry the check does not know.
        let mut left: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(left, [CONTENTS_FILE_NAME, INFLATED_FILE_NAME]);
    }

    /// A leftover `name.c9s.tmp` from a run that was killed between the write and the rename does
    /// not block the next attempt: the fix overwrites it and renames over the original.
    #[test]
    fn a_leftover_staging_file_does_not_block_the_fix() {
        let (_dir, ctx) = vault();
        let name = long_name(300);
        let dir = c9s(
            &ctx,
            &deflate_name(&name),
            Some(format!("{name}garbage").as_bytes()),
        );
        let staged = dir.join(format!("{INFLATED_FILE_NAME}.tmp"));
        std::fs::write(&staged, b"leftover from a killed run").unwrap();

        let results = run(&ctx);
        let fix = results[0].fix.as_ref().expect("the trailing bytes are cut");
        fix.apply(&ctx).expect("the fix applies over the leftover");
        assert_eq!(
            std::fs::read_to_string(dir.join(INFLATED_FILE_NAME)).unwrap(),
            name
        );
        assert!(!staged.exists(), "the staging file was renamed away");
    }

    #[test]
    fn a_mismatched_directory_is_renamed_to_the_expected_short_name() {
        let (_dir, ctx) = vault();
        let name = long_name(300);
        let expected = deflate_name(&name);
        let dir = c9s(&ctx, "AAAA.c9s", Some(name.as_bytes()));

        let results = run(&ctx);
        assert_eq!(results.len(), 1, "{results:#?}");
        assert_eq!(results[0].kind, "LongShortNamesMismatch");
        assert_eq!(results[0].severity, Severity::Warn);
        assert!(
            results[0]
                .message
                .ends_with("is not a base64url encoded SHA1 hash of String inside name.c9s."),
            "{}",
            results[0].message
        );
        let fix = results[0].fix.as_ref().expect("a mismatch is fixable");
        assert!(fix.describe().contains(&expected), "{}", fix.describe());
        fix.apply(&ctx).expect("the rename succeeds");

        let renamed = dir.with_file_name(&expected);
        assert!(!dir.exists(), "the old name is gone");
        assert!(
            renamed.join(CONTENTS_FILE_NAME).is_file(),
            "content moved along"
        );
        // Idempotent: the second run finds the source gone and the target in place.
        fix.apply(&ctx).expect("idempotent");
        let after = run(&ctx);
        assert_eq!(after.len(), 1, "{after:#?}");
        assert_eq!(after[0].kind, "ValidShortenedFile");
    }

    #[test]
    fn the_rename_never_replaces_an_existing_node() {
        let (_dir, ctx) = vault();
        let name = long_name(300);
        let expected = deflate_name(&name);
        c9s(&ctx, "AAAA.c9s", Some(name.as_bytes()));
        // Someone else already occupies the expected name. Its own `name.c9s` is deliberately
        // syntactically invalid, so it yields a `NotDecodableLongName` and not a second mismatch.
        let occupied = c9s(&ctx, &expected, Some(b"occupied"));

        let mismatch = run(&ctx)
            .into_iter()
            .find(|r| r.kind == "LongShortNamesMismatch")
            .expect("the mismatch is reported");
        let error = mismatch
            .fix
            .as_ref()
            .expect("fixable")
            .apply(&ctx)
            .expect_err("the occupied name is not overwritten");
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            std::fs::read_to_string(occupied.join(INFLATED_FILE_NAME)).unwrap(),
            "occupied",
            "the other node is untouched"
        );
    }

    #[test]
    fn a_broken_traversal_is_reported_once() {
        let (_dir, ctx) = vault();
        std::fs::remove_dir_all(ctx.data_dir()).unwrap();
        let results = run(&ctx);
        assert_eq!(results.len(), 1, "{results:#?}");
        assert_eq!(results[0].kind, "CheckFailed");
        assert_eq!(results[0].check, SHORTENED_CHECK_ID);
        assert_eq!(results[0].severity, Severity::Critical);
    }

    #[test]
    fn a_name_file_that_is_not_utf8_ends_the_traversal() {
        let (_dir, ctx) = vault();
        // Java's `Files.readString` throws a `MalformedInputException`, which `walkFileTree`
        // propagates into the single `CheckFailed`.
        c9s(
            &ctx,
            "AAAA.c9s",
            Some(&[0xff, 0xfe, b'.', b'c', b'9', b'r']),
        );
        let results = run(&ctx);
        assert_eq!(results.len(), 1, "{results:#?}");
        assert_eq!(results[0].kind, "CheckFailed");
        assert!(
            results[0].message.contains("not valid UTF-8"),
            "{}",
            results[0].message
        );
    }
}
