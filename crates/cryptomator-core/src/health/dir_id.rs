//! The `dirid` check, ported from cryptofs 2.10.0 `org.cryptomator.cryptofs.health.dirid`.
//!
//! It reads every `dir.c9r` file of the vault and pairs the directory ids they contain with the
//! content directories `d/<2 chars>/<30 chars>` those ids hash to. Every pairing that does not work
//! out is a finding; the eight result kinds are the eight Java `DiagnosticResult` classes of that
//! package, with their severities and their `toString()` messages word for word.
//!
//! Two deliberate differences to Java, both consequences of the "paths in results are
//! vault-relative" rule of this port:
//!
//! * Java's visitor collects absolute paths and prints them; ours prints `d/XX/YYYY…/name.c9r`.
//!   `OrphanContentDir` is affected twice over — Java prints the path *relative to the data dir*
//!   (`XX/YYYY…`), we print `d/XX/YYYY…` like every other result.
//! * The root directory has no `dir.c9r` at all (Java stores `null` for it and prints `null` in
//!   `HealthyDir`/`MissingContentDir`); we print `-`, which reads better than Rust's `None`.
//!
//! The traversal itself is `std::fs` only and never writes; only a [`Fix`] touches the vault.
use super::{CheckContext, DiagnosticResult, Fix, HealthCheck, Severity};
use crate::constants::{
    CRYPTOMATOR_FILE_SUFFIX, DATA_DIR_NAME, DEFLATED_FILE_SUFFIX, DIR_FILE_NAME,
    DIR_ID_BACKUP_FILE_NAME, MAX_DIR_ID_LENGTH,
};
use crate::crypto::cryptor::Cryptor;
use crate::crypto::rng::OsRng;
use crate::fs::dir_id::write_dir_id_backup;
use crate::fs::CiphertextDirectory;
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};

/// The id `--check dirid` selects, `CHECK_IDS[0]`.
pub const DIR_ID_CHECK_ID: &str = "dirid";
/// `DirIdCheck.CHECK_NAME`.
pub const DIR_ID_CHECK_NAME: &str = "Directory Check";
/// `DirIdCheck.MAX_TRAVERSAL_DEPTH`: `d/2/30/Fo0==.c9r/dir.c9r`, counted from `d` = 0. An entry at
/// exactly this depth is never descended into, it is visited as a file — that is what Java's
/// `Files.walkFileTree(dataDir, Set.of(), 4, visitor)` does.
pub const MAX_TRAVERSAL_DEPTH: usize = 4;

/// Reads all `dir.c9r` files and checks whether the content directory they point at exists.
#[derive(Debug)]
pub struct DirIdCheck;

impl HealthCheck for DirIdCheck {
    fn id(&self) -> &'static str {
        DIR_ID_CHECK_ID
    }

    fn name(&self) -> &'static str {
        DIR_ID_CHECK_NAME
    }

    fn run(&self, ctx: &CheckContext, sink: &mut dyn FnMut(DiagnosticResult)) {
        let data_dir = ctx.data_dir();
        let mut visitor = DirVisitor::new();
        // Java lets any IOException escape `walkFileTree` and turns it into a single `CheckFailed`;
        // a half-traversed vault would produce phantom `MissingContentDir`s, so we abort as well.
        if let Err(e) = visitor.walk(ctx, &data_dir, &data_dir, 0, sink) {
            sink(check_failed(&ctx.relativize(&data_dir), &e));
            return;
        }
        let DirVisitor {
            dir_ids,
            mut second_level_dirs,
        } = visitor;

        // Remove matching pairs: every directory id whose content dir exists.
        for (dir_id, dir_file) in dir_ids {
            let expected = content_dir_name(&ctx.cryptor, &dir_id);
            if second_level_dirs.remove(&expected) {
                let content_dir = Path::new(DATA_DIR_NAME).join(&expected);
                if ctx
                    .resolve(&content_dir)
                    .join(DIR_ID_BACKUP_FILE_NAME)
                    .exists()
                {
                    sink(healthy_dir(&dir_id, dir_file.as_deref(), &content_dir));
                } else {
                    sink(missing_dir_id_backup(&dir_id, &content_dir));
                }
            } else {
                // Remaining dir ids, i.e. missing content dirs.
                sink(missing_content_dir(&dir_id, dir_file.as_deref(), expected));
            }
        }

        // Remaining content dirs, i.e. missing `dir.c9r` files.
        for dir in second_level_dirs {
            sink(orphan_content_dir(&Path::new(DATA_DIR_NAME).join(dir)));
        }
    }
}

/// `d/XX/YYYY…` for a directory id, without the `d/`.
fn content_dir_name(cryptor: &Cryptor, dir_id: &str) -> PathBuf {
    // The hash is always 32 base32 characters, so the split is infallible.
    let hash = cryptor.file_name_cryptor().hash_directory_id(dir_id);
    let (prefix, rest) = hash.split_at(2);
    Path::new(prefix).join(rest)
}

/// What the sibling loop does after a `dir.c9r` was visited (Java's `FileVisitResult`).
#[derive(Debug, PartialEq, Eq)]
enum Flow {
    Continue,
    /// Inside a `.c9r` node directory there is nothing left to look at once `dir.c9r` was read.
    SkipSiblings,
}

/// `DirIdCheck.DirVisitor`. Both collections are ordered so that the same vault always yields the
/// same report; Java uses `HashMap`/`HashSet` and accepts an arbitrary order.
#[derive(Debug)]
struct DirVisitor {
    /// Directory id → the vault-relative `dir.c9r` that contains it (`None` for the root).
    dir_ids: BTreeMap<String, Option<PathBuf>>,
    /// Every `XX/YYYY…` below `d/`, relative to `d/`.
    second_level_dirs: BTreeSet<PathBuf>,
}

impl DirVisitor {
    fn new() -> Self {
        let mut dir_ids = BTreeMap::new();
        // We always have the "empty string" dir id for the root dir.
        dir_ids.insert(String::new(), None);
        Self {
            dir_ids,
            second_level_dirs: BTreeSet::new(),
        }
    }

    /// `preVisitDirectory` plus the directory loop of `walkFileTree`. `dir` is absolute and sits at
    /// `depth` below `data_dir`; the caller only ever descends while `depth < MAX_TRAVERSAL_DEPTH`,
    /// so entries at exactly the maximum depth are visited as files even if they are directories.
    ///
    /// Entries are sorted by name: `read_dir` order decides which of two colliding `dir.c9r` files
    /// is named as the culprit, and an unpredictable report is worse than Java parity here.
    fn walk(
        &mut self,
        ctx: &CheckContext,
        data_dir: &Path,
        dir: &Path,
        depth: usize,
        sink: &mut dyn FnMut(DiagnosticResult),
    ) -> io::Result<()> {
        if let Ok(rel) = dir.strip_prefix(data_dir) {
            if rel.components().count() == 2 {
                self.second_level_dirs.insert(rel.to_path_buf());
            }
        }
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            // `DirEntry::file_type` does not follow symlinks, just like a `walkFileTree` without
            // `FOLLOW_LINKS`: a symlinked directory is visited as a file, not descended into.
            entries.push((entry.file_name(), entry.file_type()?));
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, file_type) in entries {
            let path = dir.join(&name);
            if file_type.is_dir() && depth + 1 < MAX_TRAVERSAL_DEPTH {
                self.walk(ctx, data_dir, &path, depth + 1, sink)?;
            } else if name == DIR_FILE_NAME
                && self.visit_dir_file(ctx, &path, sink)? == Flow::SkipSiblings
            {
                break;
            }
        }
        Ok(())
    }

    /// `DirVisitor.visitDirFile`.
    fn visit_dir_file(
        &mut self,
        ctx: &CheckContext,
        dir_file: &Path,
        sink: &mut dyn FnMut(DiagnosticResult),
    ) -> io::Result<Flow> {
        let rel = ctx.relativize(dir_file);
        let parent_name = dir_file
            .parent()
            .and_then(Path::file_name)
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        if !(parent_name.ends_with(CRYPTOMATOR_FILE_SUFFIX)
            || parent_name.ends_with(DEFLATED_FILE_SUFFIX))
        {
            sink(loose_dir_file(&rel));
            return Ok(Flow::Continue);
        }

        let size = std::fs::symlink_metadata(dir_file)?.len();
        if size > MAX_DIR_ID_LENGTH as u64 {
            sink(obese_dir_file(&rel, size));
        } else if size == 0 {
            sink(empty_dir_file(&rel));
        } else {
            // Java reads the bytes as UTF-8 without validating them; a lossy conversion keeps a
            // garbled dir id comparable instead of aborting the whole traversal.
            let dir_id = String::from_utf8_lossy(&std::fs::read(dir_file)?).into_owned();
            match self.dir_ids.get(&dir_id) {
                Some(other) => sink(dir_id_collision(&dir_id, &rel, other.as_deref())),
                None => {
                    self.dir_ids.insert(dir_id, Some(rel));
                }
            }
        }
        Ok(Flow::SkipSiblings)
    }
}

/// `dirFile` as Java prints it; the root has none.
fn show(path: Option<&Path>) -> String {
    match path {
        Some(path) => path.display().to_string(),
        None => "-".to_string(),
    }
}

fn result(
    kind: &'static str,
    severity: Severity,
    message: String,
    paths: Vec<PathBuf>,
) -> DiagnosticResult {
    DiagnosticResult::new(DIR_ID_CHECK_ID, kind, severity, message, paths)
}

/// `HealthyDir`: valid `dir.c9r` file, existing target dir, `dirid.c9r` present.
fn healthy_dir(dir_id: &str, dir_file: Option<&Path>, dir: &Path) -> DiagnosticResult {
    let mut paths: Vec<PathBuf> = dir_file.map(Path::to_path_buf).into_iter().collect();
    paths.push(dir.to_path_buf());
    result(
        "HealthyDir",
        Severity::Good,
        format!(
            "Good directory {} ({dir_id}) -> {}",
            show(dir_file),
            dir.display()
        ),
        paths,
    )
}

/// `MissingDirIdBackup`: the content dir exists but has no `dirid.c9r`.
fn missing_dir_id_backup(dir_id: &str, content_dir: &Path) -> DiagnosticResult {
    result(
        "MissingDirIdBackup",
        Severity::Info,
        format!(
            "Directory ID backup for directory {} is missing.",
            content_dir.display()
        ),
        vec![content_dir.to_path_buf()],
    )
    .with_fix(Box::new(WriteDirIdBackup {
        dir_id: dir_id.to_owned(),
        content_dir: content_dir.to_path_buf(),
    }))
}

/// `LooseDirFile`: a `dir.c9r` whose parent is not a `.c9r`/`.c9s` node directory.
///
/// The message ends in `". ."` — a typo in cryptofs that is reproduced verbatim so reports of the
/// two implementations stay comparable.
fn loose_dir_file(dir_file: &Path) -> DiagnosticResult {
    result(
        "LooseDirFile",
        Severity::Info,
        format!(
            "A dir.c9r without proper parent found: ({}). .",
            dir_file.display()
        ),
        vec![dir_file.to_path_buf()],
    )
    .with_fix(Box::new(DeleteLooseDirFile {
        dir_file: dir_file.to_path_buf(),
    }))
}

/// `ObeseDirFile`: larger than a UUID, so it cannot be a directory id. Java has no fix either
/// ("potential fix: assign new dir id, move target dir").
fn obese_dir_file(dir_file: &Path, size: u64) -> DiagnosticResult {
    result(
        "ObeseDirFile",
        Severity::Critical,
        format!(
            "Unexpected file size of {}: {size} should be ≤ {MAX_DIR_ID_LENGTH}",
            dir_file.display()
        ),
        vec![dir_file.to_path_buf()],
    )
}

/// `EmptyDirFile`: the empty dir id is reserved for the root, which has no `dir.c9r`. Java's fix is
/// commented out (it would delete the node), so there is none here either.
fn empty_dir_file(dir_file: &Path) -> DiagnosticResult {
    result(
        "EmptyDirFile",
        Severity::Critical,
        format!("File {} is empty, expected content", dir_file.display()),
        vec![dir_file.to_path_buf()],
    )
}

/// `DirIdCollision`: two `dir.c9r` files claim the same directory id, so two cleartext paths lead
/// into one content dir. Java offers no fix — which of the two nodes is the right one is not
/// decidable from the ciphertext.
fn dir_id_collision(dir_id: &str, dir_file: &Path, other: Option<&Path>) -> DiagnosticResult {
    let mut paths = vec![dir_file.to_path_buf()];
    paths.extend(other.map(Path::to_path_buf));
    result(
        "DirIdCollision",
        Severity::Critical,
        format!(
            "Directory ID reused: {dir_id} found in {} and {}",
            dir_file.display(),
            show(other)
        ),
        paths,
    )
}

/// `MissingContentDir`: a valid `dir.c9r` pointing at a content dir that does not exist.
fn missing_content_dir(
    dir_id: &str,
    dir_file: Option<&Path>,
    content_dir_name: PathBuf,
) -> DiagnosticResult {
    result(
        "MissingContentDir",
        Severity::Warn,
        format!(
            "dir.c9r file ({}) points to non-existing directory.",
            show(dir_file)
        ),
        dir_file.map(Path::to_path_buf).into_iter().collect(),
    )
    .with_fix(Box::new(CreateContentDir {
        dir_id: dir_id.to_owned(),
        content_dir: Path::new(DATA_DIR_NAME).join(content_dir_name),
    }))
}

/// `OrphanContentDir`: a content dir no `dir.c9r` points at. Its fix moves the contents into
/// `LOST+FOUND` and arrives with Task 5.
fn orphan_content_dir(content_dir: &Path) -> DiagnosticResult {
    result(
        "OrphanContentDir",
        Severity::Warn,
        format!("Orphan directory: {}", content_dir.display()),
        vec![content_dir.to_path_buf()],
    )
    // Task 5 attaches the LOST+FOUND adoption fix here.
}

/// `CheckFailed`: the traversal itself broke. Java logs the cause and prints only a hint at the
/// log; a CLI has no log to point at, so the error text goes into the message.
fn check_failed(data_dir: &Path, error: &io::Error) -> DiagnosticResult {
    result(
        "CheckFailed",
        Severity::Critical,
        format!(
            "Check failed: Traversal of data dir failed: {} ({error})",
            data_dir.display()
        ),
        vec![data_dir.to_path_buf()],
    )
}

/// `LooseDirFile.fix`: `Files.deleteIfExists`.
#[derive(Debug)]
struct DeleteLooseDirFile {
    dir_file: PathBuf,
}

impl Fix for DeleteLooseDirFile {
    fn describe(&self) -> String {
        format!("delete the loose {}", self.dir_file.display())
    }

    fn apply(&self, ctx: &CheckContext) -> io::Result<()> {
        match std::fs::remove_file(ctx.resolve(&self.dir_file)) {
            // `deleteIfExists`, and what makes a second `--fix` run a no-op.
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            other => other,
        }
    }
}

/// `MissingDirIdBackup.fix`: `DirectoryIdBackup.write` into the existing content dir.
#[derive(Debug)]
struct WriteDirIdBackup {
    dir_id: String,
    content_dir: PathBuf,
}

impl Fix for WriteDirIdBackup {
    fn describe(&self) -> String {
        format!(
            "write {DIR_ID_BACKUP_FILE_NAME} into {}",
            self.content_dir.display()
        )
    }

    fn apply(&self, ctx: &CheckContext) -> io::Result<()> {
        write_backup(ctx, &self.dir_id, &self.content_dir)
    }
}

/// `MissingContentDir.fix`: `createDirectories` plus `DirectoryIdBackup.write`. The lost content is
/// not restored — only the structure the `dir.c9r` promises.
#[derive(Debug)]
struct CreateContentDir {
    dir_id: String,
    content_dir: PathBuf,
}

impl Fix for CreateContentDir {
    fn describe(&self) -> String {
        format!(
            "create the missing content directory {} with its {DIR_ID_BACKUP_FILE_NAME}",
            self.content_dir.display()
        )
    }

    fn apply(&self, ctx: &CheckContext) -> io::Result<()> {
        std::fs::create_dir_all(ctx.resolve(&self.content_dir))?;
        write_backup(ctx, &self.dir_id, &self.content_dir)
    }
}

/// Writes `dirid.c9r` and tolerates an existing one. `write_dir_id_backup` opens the file with
/// `CREATE_NEW` like Java, which throws there; tolerating `AlreadyExists` is what makes `--fix`
/// idempotent (Java does the same only in `prepareStepParent`).
fn write_backup(ctx: &CheckContext, dir_id: &str, content_dir: &Path) -> io::Result<()> {
    let dir = CiphertextDirectory {
        dir_id: dir_id.to_owned(),
        path: ctx.resolve(content_dir),
    };
    let mut rng = OsRng;
    match write_dir_id_backup(&ctx.cryptor, &dir, &mut rng) {
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::ROOT_DIR_ID;
    use crate::fs::testutil::new_vault;
    use crate::health::CHECK_IDS;
    use crate::vault::open::root_content_dir;

    /// A freshly initialised, empty vault plus the context a check needs for it.
    fn vault() -> (tempfile::TempDir, CheckContext) {
        let (dir, cryptor, config) = new_vault(220);
        let ctx = CheckContext::new(dir.path().to_path_buf(), cryptor, config);
        (dir, ctx)
    }

    fn run(ctx: &CheckContext) -> Vec<DiagnosticResult> {
        let mut results = Vec::new();
        DirIdCheck.run(ctx, &mut |r| results.push(r));
        results
    }

    fn kinds(results: &[DiagnosticResult]) -> Vec<&'static str> {
        let mut kinds: Vec<_> = results.iter().map(|r| r.kind).collect();
        kinds.sort_unstable();
        kinds
    }

    /// Creates `d/XX/YYY…` for `dir_id` and the `dir.c9r` naming it, under the root content dir.
    fn add_dir(ctx: &CheckContext, node_name: &str, dir_id: &str) -> PathBuf {
        let root = root_content_dir(&ctx.vault_path, &ctx.cryptor);
        let node = root.join(node_name);
        std::fs::create_dir_all(&node).unwrap();
        std::fs::write(node.join(DIR_FILE_NAME), dir_id).unwrap();
        let content = ctx.data_dir().join(content_dir_name(&ctx.cryptor, dir_id));
        std::fs::create_dir_all(&content).unwrap();
        let mut rng = OsRng;
        write_dir_id_backup(
            &ctx.cryptor,
            &CiphertextDirectory {
                dir_id: dir_id.to_owned(),
                path: content.clone(),
            },
            &mut rng,
        )
        .unwrap();
        content
    }

    #[test]
    fn the_check_is_the_first_of_the_catalogue() {
        assert_eq!(DirIdCheck.id(), CHECK_IDS[0]);
        assert_eq!(DirIdCheck.id(), DIR_ID_CHECK_ID);
        assert_eq!(DirIdCheck.name(), "Directory Check");
    }

    #[test]
    fn a_fresh_vault_reports_one_healthy_root() {
        let (_dir, ctx) = vault();
        let results = run(&ctx);
        assert_eq!(kinds(&results), vec!["HealthyDir"]);
        assert_eq!(results[0].severity, Severity::Good);
        // The root has no dir.c9r, so it prints `-` and carries only the content dir.
        let hash = ctx
            .cryptor
            .file_name_cryptor()
            .hash_directory_id(ROOT_DIR_ID);
        assert_eq!(
            results[0].message,
            format!("Good directory - () -> d/{}/{}", &hash[..2], &hash[2..])
        );
        assert_eq!(results[0].paths.len(), 1);
    }

    #[test]
    fn a_missing_data_dir_is_a_check_failure_not_a_panic() {
        let (dir, ctx) = vault();
        std::fs::remove_dir_all(dir.path().join(DATA_DIR_NAME)).unwrap();
        let results = run(&ctx);
        assert_eq!(kinds(&results), vec!["CheckFailed"]);
        assert_eq!(results[0].severity, Severity::Critical);
        assert!(results[0].message.starts_with("Check failed: "));
    }

    #[test]
    fn an_oversized_dir_file_is_obese_and_an_empty_one_is_empty() {
        let (_dir, ctx) = vault();
        let root = root_content_dir(&ctx.vault_path, &ctx.cryptor);
        let obese = root.join("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.c9r");
        std::fs::create_dir_all(&obese).unwrap();
        std::fs::write(obese.join(DIR_FILE_NAME), vec![b'x'; MAX_DIR_ID_LENGTH + 1]).unwrap();
        let empty = root.join("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB.c9s");
        std::fs::create_dir_all(&empty).unwrap();
        std::fs::write(empty.join(DIR_FILE_NAME), b"").unwrap();

        let results = run(&ctx);
        assert_eq!(
            kinds(&results),
            vec!["EmptyDirFile", "HealthyDir", "ObeseDirFile"]
        );
        let obese = results.iter().find(|r| r.kind == "ObeseDirFile").unwrap();
        assert!(
            obese.message.ends_with(&format!(
                ": {} should be ≤ {MAX_DIR_ID_LENGTH}",
                MAX_DIR_ID_LENGTH + 1
            )),
            "{}",
            obese.message
        );
        // Neither is fixable, exactly as in Java.
        assert!(results.iter().all(|r| !r.fixable()));
    }

    #[test]
    fn a_dir_file_shadows_its_siblings_but_a_loose_one_does_not() {
        let (_dir, ctx) = vault();
        let content = add_dir(&ctx, "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC.c9r", "sub-dir-id");
        // A second dir.c9r inside the *content* dir is loose: its parent is not a node dir. Java
        // continues with the siblings there, so the node behind it is still seen.
        std::fs::write(content.join(DIR_FILE_NAME), b"loose").unwrap();
        let nested = content.join("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD.c9r");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join(DIR_FILE_NAME), b"sub-dir-id").unwrap();

        let results = run(&ctx);
        assert_eq!(
            kinds(&results),
            vec!["DirIdCollision", "HealthyDir", "HealthyDir", "LooseDirFile"]
        );
        let loose = results.iter().find(|r| r.kind == "LooseDirFile").unwrap();
        assert!(loose.message.ends_with("). ."), "{}", loose.message);
        assert!(loose.fixable());
    }

    #[test]
    fn the_three_simple_fixes_are_idempotent() {
        let (_dir, ctx) = vault();
        let content = add_dir(&ctx, "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE.c9r", "backup-less");
        std::fs::remove_file(content.join(DIR_ID_BACKUP_FILE_NAME)).unwrap();
        let gone = add_dir(&ctx, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF.c9r", "content-less");
        std::fs::remove_dir_all(&gone).unwrap();
        let root = root_content_dir(&ctx.vault_path, &ctx.cryptor);
        std::fs::write(root.join(DIR_FILE_NAME), b"loose").unwrap();

        let before = run(&ctx);
        assert_eq!(
            kinds(&before),
            vec![
                "HealthyDir",
                "LooseDirFile",
                "MissingContentDir",
                "MissingDirIdBackup"
            ]
        );
        for result in &before {
            if let Some(fix) = &result.fix {
                assert!(!fix.describe().is_empty());
                fix.apply(&ctx).unwrap();
                // Twice: applying an already applied fix must not fail.
                fix.apply(&ctx).unwrap();
            }
        }
        let after = run(&ctx);
        assert_eq!(
            kinds(&after),
            vec!["HealthyDir", "HealthyDir", "HealthyDir"],
            "{after:#?}"
        );
        assert!(gone.is_dir());
        assert_eq!(
            crate::fs::dir_id::read_dir_id_backup(&ctx.cryptor, &gone).unwrap(),
            "content-less"
        );
        assert_eq!(
            crate::fs::dir_id::read_dir_id_backup(&ctx.cryptor, &content).unwrap(),
            "backup-less"
        );
        assert!(!root.join(DIR_FILE_NAME).exists());
    }

    #[test]
    fn a_content_dir_nobody_points_at_is_an_orphan() {
        let (_dir, ctx) = vault();
        let orphan = ctx
            .data_dir()
            .join("AA")
            .join("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
        std::fs::create_dir_all(&orphan).unwrap();
        let results = run(&ctx);
        assert_eq!(kinds(&results), vec!["HealthyDir", "OrphanContentDir"]);
        let orphan = results
            .iter()
            .find(|r| r.kind == "OrphanContentDir")
            .unwrap();
        assert_eq!(orphan.severity, Severity::Warn);
        assert_eq!(
            orphan.message,
            "Orphan directory: d/AA/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        );
        // Task 5 adds the LOST+FOUND adoption.
        assert!(!orphan.fixable());
    }

    #[test]
    fn nothing_deeper_than_the_traversal_depth_is_looked_at() {
        let (_dir, ctx) = vault();
        // d/XX/YYY/node.c9r/deeper/dir.c9r is at depth 5 and therefore invisible, exactly as in
        // Java, where `walkFileTree` stops descending at depth 4.
        let deep = root_content_dir(&ctx.vault_path, &ctx.cryptor)
            .join("GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG.c9r")
            .join("deeper");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join(DIR_FILE_NAME), b"invisible").unwrap();
        assert_eq!(kinds(&run(&ctx)), vec!["HealthyDir"]);
    }
}
