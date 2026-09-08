//! 6 → 7, a port of `migration/v7/{Version7Migrator,FilePathMigration,PreMigrationVisitor,
//! MigratingVisitor}.java`.
//!
//! This is the only step that touches the ciphertext. Every name below `d/` is rewritten:
//!
//! | format 6 | format 7 |
//! |---|---|
//! | `BASE32==` | `base64url==.c9r` |
//! | `0BASE32==` (directory) | `base64url==.c9r/dir.c9r` |
//! | `1SBASE32==` (symlink) | `base64url==.c9r/symlink.c9r` |
//! | `<32 chars>.lng` + `m/xx/yy/<32 chars>.lng` | the inflated name, migrated as above |
//! | a name longer than 220 characters | `BASE64URL(SHA1(name)).c9s/` with `name.c9s` |
//!
//! and the `m/` directory disappears, because format 7 keeps the inflated name inside the node --
//! unless at least one node had to be skipped, in which case `m/` is kept, because it holds the
//! only copy of those nodes' long names (see [`migrate_reporting`]; Java deletes it regardless).
//!
//! Nothing is re-encrypted: the ciphertext of a name is the same bytes in both formats, only its
//! encoding and the way its type is expressed change. That is why the masterkey is loaded merely
//! to check the passphrase and to re-stamp the key file with version 7 at the very end.
use crate::constants::{
    CONTENTS_FILE_NAME, CRYPTOMATOR_FILE_SUFFIX, DATA_DIR_NAME, DEFLATED_FILE_SUFFIX,
    DIR_FILE_NAME, INFLATED_FILE_NAME, MASTERKEY_FILENAME, MAX_ADDITIONAL_PATH_LENGTH,
    SYMLINK_FILE_NAME,
};
use crate::crypto::rng::Rng;
use crate::error::{CoreError, Result};
use crate::fs::capabilities::determine_supported_ciphertext_file_name_length;
use crate::fs::long_names::{deflate_str, MAX_FILENAME_BUFFER_SIZE};
use crate::masterkey_file::MasterkeyFileAccess;
use crate::migration::{back_up, MigrationEvent, MigrationStep, PlannedRename};
use data_encoding::{BASE32, BASE64URL};
use std::path::{Path, PathBuf};

/// Suffix of a format 5/6 shortened name (`FilePathMigration.OLD_SHORTENED_FILENAME_SUFFIX`).
pub const OLD_SHORTENED_FILENAME_SUFFIX: &str = ".lng";
/// A format 5/6 directory file starts with this (`OLD_DIRECTORY_PREFIX`).
pub const OLD_DIRECTORY_PREFIX: &str = "0";
/// A format 5/6 symlink starts with this (`OLD_SYMLINK_PREFIX`).
pub const OLD_SYMLINK_PREFIX: &str = "1S";
/// Names longer than this get a `.c9s` node (`FilePathMigration.SHORTENING_THRESHOLD`, see
/// cryptofs issue #60). Format 7 has no configurable threshold; 220 is *the* value.
pub const SHORTENING_THRESHOLD: usize = 220;
/// `FilePathMigration.migrate` tries the canonical name and then `_1` and `_2`.
pub const MIGRATION_ATTEMPTS: usize = 3;
/// The directory holding the inflated long names of formats 5 and 6.
pub const OLD_METADATA_DIR_NAME: &str = "m";
/// `Files.walkFileTree(dataDir, …, 3, visitor)`: `d/`, `d/XX/`, `d/XX/YYY…/` and its entries.
const DATA_DIR_DEPTH_LIMIT: usize = 3;
/// The vault version this step stamps into the masterkey file, as its last action.
const TARGET_VAULT_VERSION: u32 = 7;
/// `PreMigrationVisitor.getMaxCiphertextNameLength/PathLength` without a full scan: the values a
/// correctly migrated vault cannot exceed anyway.
const ASSUMED_MAX_NAME_LENGTH: usize = 220;
const ASSUMED_MAX_PATH_LENGTH: usize = 268;

/// A character of Guava's `BaseEncoding.base32()` alphabet — Java's `[A-Z2-7]`.
fn is_base32_char(byte: u8) -> bool {
    byte.is_ascii_uppercase() || (b'2'..=b'7').contains(&byte)
}

/// Java's `OLD_CANONICAL_FILENAME_PATTERN.matcher(name).find()`, i.e. the part of `file_name` that
/// satisfies `(0|1S)?([A-Z2-7]{8})*[A-Z2-7=]{8}`.
///
/// Java searches at *every* position; we anchor at position 0. For real format 5/6 names the two
/// agree: a conflicting copy carries its suffix at the end (`NAME (1)`), never at the front, and a
/// hit in the middle of a name would be one Java migrates only by accident. Anchoring also keeps a
/// name that merely *contains* eight base32 characters (`my report ABCDEFGH.txt`) out of the
/// migration instead of renaming it to garbage.
///
/// The asymmetry to [`find_32_base32_chars`] below — which does scan every position, like Java —
/// is deliberate, so do not "fix" one half to match the other: the shortened pattern has to find
/// the 32 characters inside `<name>.lng` (and inside whatever a syncer prefixed to it, e.g. a
/// macOS AppleDouble companion `._<32 chars>.lng`), while the canonical pattern decides what a
/// *whole* name is, where a hit at position 0 is the only one that can be trusted.
fn canonical(file_name: &str) -> Option<String> {
    for prefix in [OLD_SYMLINK_PREFIX, OLD_DIRECTORY_PREFIX, ""] {
        let Some(rest) = file_name.strip_prefix(prefix) else {
            continue;
        };
        if let Some(len) = canonical_body_len(rest) {
            return Some(format!("{prefix}{}", &rest[..len]));
        }
    }
    None
}

/// The length of the longest prefix of `rest` matching `([A-Z2-7]{8})*[A-Z2-7=]{8}`.
///
/// Java's `*` is greedy and backtracks until the mandatory final block fits, so we take as many
/// full base32 blocks as there are and then hand them back one at a time.
fn canonical_body_len(rest: &str) -> Option<usize> {
    let bytes = rest.as_bytes();
    let mut blocks = 0;
    while bytes.len() >= (blocks + 1) * 8
        && bytes[blocks * 8..(blocks + 1) * 8]
            .iter()
            .all(|b| is_base32_char(*b))
    {
        blocks += 1;
    }
    // The last block may carry '=' anywhere, exactly like Java's `[A-Z2-7=]{8}`. Such a name is
    // not decodable; `decoded_ciphertext` reports it, just as Java's `BASE32.decode` does.
    (0..=blocks).rev().find_map(|kept| {
        let end = kept * 8 + 8;
        (bytes.len() >= end
            && bytes[kept * 8..end]
                .iter()
                .all(|b| is_base32_char(*b) || *b == b'='))
        .then_some(end)
    })
}

/// Java's `OLD_SHORTENED_FILENAME_PATTERN.matcher(name).find()` (`[A-Z2-7]{32}`): the first run of
/// 32 base32 characters anywhere in the name.
fn find_32_base32_chars(file_name: &str) -> Option<&str> {
    let bytes = file_name.as_bytes();
    // Every matched byte is ASCII, so `start` and `start + 32` are always char boundaries.
    (0..bytes.len().saturating_sub(31))
        .find(|start| {
            bytes[*start..*start + 32]
                .iter()
                .all(|b| is_base32_char(*b))
        })
        .map(|start| &file_name[start..start + 32])
}

/// A single file name before the migration. Port of `migration/v7/FilePathMigration.java`.
#[derive(Debug, Clone)]
pub struct FilePathMigration {
    old_path: PathBuf,
    old_canonical_name: String,
}

impl FilePathMigration {
    /// `None` when the name is already migrated or is not a Cryptomator name at all.
    ///
    /// `vault_root` is the parent of `d/` and `m/`; `old_path` an existing file below `d/`.
    pub fn parse(vault_root: &Path, old_path: &Path) -> Result<Option<Self>> {
        let name = old_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        // BASE32 is a subset of BASE64URL, so a pure pattern match would migrate an already
        // migrated name a second time. Java guards against it with the same two suffixes.
        if name.ends_with(CRYPTOMATOR_FILE_SUFFIX) || name.ends_with(DEFLATED_FILE_SUFFIX) {
            return Ok(None);
        }
        let old_canonical_name = if name.ends_with(OLD_SHORTENED_FILENAME_SUFFIX) {
            match find_32_base32_chars(&name) {
                Some(hit) => inflate(vault_root, &format!("{hit}{OLD_SHORTENED_FILENAME_SUFFIX}"))?,
                None => return Ok(None),
            }
        } else {
            match canonical(&name) {
                Some(hit) => hit,
                None => return Ok(None),
            }
        };
        Ok(Some(Self {
            old_path: old_path.to_path_buf(),
            old_canonical_name,
        }))
    }

    pub fn old_path(&self) -> &Path {
        &self.old_path
    }

    /// The inflated old name including its type prefix.
    pub fn old_canonical_name(&self) -> &str {
        &self.old_canonical_name
    }

    /// Whether the node is a directory (`oldCanonicalName` starts with `"0"`).
    pub fn is_directory(&self) -> bool {
        self.old_canonical_name.starts_with(OLD_DIRECTORY_PREFIX)
    }

    /// Whether the node is a symlink (`oldCanonicalName` starts with `"1S"`).
    pub fn is_symlink(&self) -> bool {
        self.old_canonical_name.starts_with(OLD_SYMLINK_PREFIX)
    }

    pub fn old_canonical_name_without_type_prefix(&self) -> &str {
        if self.is_directory() {
            &self.old_canonical_name[OLD_DIRECTORY_PREFIX.len()..]
        } else if self.is_symlink() {
            &self.old_canonical_name[OLD_SYMLINK_PREFIX.len()..]
        } else {
            &self.old_canonical_name
        }
    }

    /// `BASE32.decode(oldCanonicalNameWithoutTypePrefix)`; Java's `InvalidOldFilenameException`
    /// becomes [`CoreError::InvalidArgument`].
    pub fn decoded_ciphertext(&self) -> Result<Vec<u8>> {
        let encoded = self.old_canonical_name_without_type_prefix();
        BASE32.decode(encoded.as_bytes()).map_err(|e| {
            CoreError::InvalidArgument(format!(
                "can't base32-decode '{encoded}' in file {}: {e}",
                self.old_path.display()
            ))
        })
    }

    /// `BASE64URL(decodedCiphertext) + ".c9r"`.
    pub fn new_inflated_name(&self) -> Result<String> {
        Ok(format!(
            "{}{CRYPTOMATOR_FILE_SUFFIX}",
            BASE64URL.encode(&self.decoded_ciphertext()?)
        ))
    }

    /// The inflated name, or `BASE64URL(SHA1(inflatedName)) + ".c9s"` when it is longer than
    /// [`SHORTENING_THRESHOLD`].
    pub fn new_deflated_name(&self) -> Result<String> {
        let inflated = self.new_inflated_name()?;
        if inflated.len() > SHORTENING_THRESHOLD {
            Ok(deflate_str(&inflated))
        } else {
            Ok(inflated)
        }
    }

    /// Where [`migrate`](Self::migrate) would move the file, with `attempt_suffix` (`""`, `"_1"`,
    /// `"_2"`) inserted before the extension.
    pub fn target_path(&self, attempt_suffix: &str) -> Result<PathBuf> {
        let inflated = self.new_inflated_name()?;
        let deflated = self.new_deflated_name()?;
        let shortened = inflated != deflated;
        let named = |name: &str, suffix: &str| {
            format!("{}{attempt_suffix}{suffix}", &name[..name.len() - 4])
        };
        let parent = self.old_path.parent().ok_or_else(|| {
            CoreError::InvalidArgument(format!("{} has no parent", self.old_path.display()))
        })?;
        let node = if shortened {
            parent.join(named(&deflated, DEFLATED_FILE_SUFFIX))
        } else {
            parent.join(named(&inflated, CRYPTOMATOR_FILE_SUFFIX))
        };
        Ok(match (shortened, self.is_directory(), self.is_symlink()) {
            (_, true, _) => node.join(DIR_FILE_NAME),
            (_, _, true) => node.join(SYMLINK_FILE_NAME),
            (true, _, _) => node.join(CONTENTS_FILE_NAME),
            (false, _, _) => node,
        })
    }

    /// Moves the file to its format 7 place and returns the new path.
    ///
    /// A target that already exists is retried with `_1` and then `_2`; the suffix triggers the
    /// conflict resolver of a later Cryptomator. After [`MIGRATION_ATTEMPTS`] failures the file is
    /// left where it is (Java throws the collected `FileAlreadyExistsException`).
    pub fn migrate(&self) -> Result<PathBuf> {
        let inflated = self.new_inflated_name()?;
        let deflated = self.new_deflated_name()?;
        let shortened = inflated != deflated;
        let mut attempt_suffix = String::new();
        for attempt in 1..=MIGRATION_ATTEMPTS {
            let new_path = self.target_path(&attempt_suffix)?;
            let moved = (|| -> std::io::Result<PathBuf> {
                if shortened || self.is_directory() || self.is_symlink() {
                    let node = new_path
                        .parent()
                        .ok_or_else(|| std::io::Error::other("the target has no parent"))?;
                    std::fs::create_dir(node)?;
                }
                if shortened {
                    std::fs::write(
                        new_path.with_file_name(INFLATED_FILE_NAME),
                        inflated.as_bytes(),
                    )?;
                }
                move_without_replacing(&self.old_path, &new_path)?;
                Ok(new_path)
            })();
            match moved {
                Ok(path) => return Ok(path),
                // Java sets the suffix *after* the failure, so the attempts are "", "_1", "_2".
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    attempt_suffix = format!("_{attempt}");
                }
                Err(e) => return Err(CoreError::Io(e)),
            }
        }
        Err(CoreError::MigrationBlocked(format!(
            "{} could not be migrated after {MIGRATION_ATTEMPTS} attempts",
            self.old_path.display()
        )))
    }
}

/// `rename(2)` replaces an existing target without a word, while Java's `Files.move` without
/// `REPLACE_EXISTING` raises the `FileAlreadyExistsException` that drives the retry loop. The
/// check is not atomic, but the migration is the only writer of the vault while it runs.
fn move_without_replacing(from: &Path, to: &Path) -> std::io::Result<()> {
    if to.symlink_metadata().is_ok() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            to.display().to_string(),
        ));
    }
    std::fs::rename(from, to)
}

/// `FilePathMigration.inflate`: the content of `<vault>/m/<xx>/<yy>/<longFileName>`.
///
/// Java's `UninflatableFileException` — a missing, unreadable or absurdly large metadata file —
/// becomes [`CoreError::MigrationBlocked`], which both visitors answer with a skip.
pub fn inflate(vault_root: &Path, long_file_name: &str) -> Result<String> {
    if long_file_name.len() < 4
        || !long_file_name.is_char_boundary(2)
        || !long_file_name.is_char_boundary(4)
    {
        return Err(CoreError::InvalidArgument(format!(
            "not a shortened file name: {long_file_name}"
        )));
    }
    let metadata_file = vault_root
        .join(OLD_METADATA_DIR_NAME)
        .join(&long_file_name[0..2])
        .join(&long_file_name[2..4])
        .join(long_file_name);
    read_metadata_file(&metadata_file).ok_or_else(|| {
        CoreError::MigrationBlocked(format!(
            "failed to read metadata file {}",
            metadata_file.display()
        ))
    })
}

fn read_metadata_file(path: &Path) -> Option<String> {
    let metadata = std::fs::metadata(path).ok()?;
    if metadata.len() > MAX_FILENAME_BUFFER_SIZE {
        return None;
    }
    // Java decodes with `UTF_8.decode`, which replaces malformed input instead of failing; such a
    // name then fails the BASE32 decoding a moment later.
    Some(String::from_utf8_lossy(&std::fs::read(path).ok()?).into_owned())
}

/// Java's two `catch` blocks in the visitors: a name that cannot be inflated
/// (`UninflatableFileException`) is skipped and logged, never fatal.
///
/// Unlike Java, the skip is not only logged: `on_skip` is told about it, so the migration can keep
/// `m/` and the caller can name the node. `parse` fails only when `inflate` does, so the error arm
/// *is* the skip; a name that is simply not a Cryptomator name (`Ok(None)`) is no skip at all.
fn parse_or_skip(
    vault_root: &Path,
    file: &Path,
    on_skip: &mut dyn FnMut(&Path, &CoreError),
) -> Option<FilePathMigration> {
    match FilePathMigration::parse(vault_root, file) {
        Ok(parsed) => parsed,
        Err(reason) => {
            on_skip(file, &reason);
            None
        }
    }
}

/// The sink the two passes that report skips share: warn, and remember the vault-relative path.
///
/// Sorted-and-deduplicated is the caller's job; the walk visits every node once, so neither is
/// needed in practice.
fn note_skip(
    vault_root: &Path,
    skipped: &mut Vec<PathBuf>,
    file: &Path,
    reason: &dyn std::fmt::Display,
) {
    log::warn!(
        "SKIP {}: {reason}; the node keeps its old name",
        file.display()
    );
    skipped.push(relativize(vault_root, file));
}

/// `SimpleFileVisitor`, reduced to the two callbacks the two v7 passes override.
trait DataDirVisitor {
    fn visit_file(&mut self, file: &Path) -> Result<()>;
    fn post_visit_directory(&mut self, _dir: &Path) -> Result<()> {
        Ok(())
    }
}

/// `Files.walkFileTree(dir, EnumSet.noneOf(FileVisitOption.class), 3, visitor)`.
///
/// Entries at the depth limit go to `visit_file` whether they are directories or not — that is
/// what Java does, and it is what makes a re-run skip the `.c9r` directories a previous run
/// created. Entries are visited in sorted order so a migration is reproducible.
fn walk_data_dir(dir: &Path, depth: usize, visitor: &mut dyn DataDirVisitor) -> Result<()> {
    let mut entries = std::fs::read_dir(dir)?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        if entry.file_type()?.is_dir() && depth + 1 < DATA_DIR_DEPTH_LIMIT {
            walk_data_dir(&path, depth + 1, visitor)?;
        } else {
            visitor.visit_file(&path)?;
        }
    }
    visitor.post_visit_directory(dir)
}

/// What `PreMigrationVisitor` collects.
#[derive(Debug, Default)]
struct PreMigrationStats {
    total_files: u64,
    determined_lengths: bool,
    max_name_length: usize,
    max_path_length: usize,
    path_with_longest_name: Option<PathBuf>,
    longest_path: Option<PathBuf>,
}

impl PreMigrationStats {
    fn max_ciphertext_name_length(&self) -> usize {
        if self.determined_lengths {
            self.max_name_length
        } else {
            ASSUMED_MAX_NAME_LENGTH
        }
    }

    fn max_ciphertext_path_length(&self) -> usize {
        if self.determined_lengths {
            self.max_path_length
        } else {
            ASSUMED_MAX_PATH_LENGTH
        }
    }

    /// `PreMigrationVisitor.updateMaxCiphertextPathLength`. A malformed name is only logged there,
    /// so a `target_path` that fails is skipped here.
    fn update(&mut self, vault_root: &Path, migration: &FilePathMigration) {
        let Ok(new_path) = migration.target_path("") else {
            return;
        };
        let relative = new_path.strip_prefix(vault_root).unwrap_or(&new_path);
        let path_length = relative.to_string_lossy().chars().count();
        if path_length > self.max_path_length {
            self.max_path_length = path_length;
            self.longest_path = Some(new_path.clone());
        }
        // Java's `relativeToVaultRoot.getName(3)`: the node name in `d/XX/YYY…/<name>`. A target
        // with fewer than four components -- a migratable file sitting directly in `d/` or
        // `d/XX` -- has no such name, and is deliberately left out of the measurement rather than
        // aborting the migration: Java's `getName(3)` throws `IllegalArgumentException` there,
        // which `updateMaxCiphertextPathLength` does not catch (it catches only
        // `InvalidOldFilenameException`), so such a vault cannot be migrated by Cryptomator at
        // all. The file is still migrated here, only its name never meets `filename_limit` -- the
        // path length above, which every target has, still does.
        if let Some(name) = relative.components().nth(3) {
            let name_length = name.as_os_str().to_string_lossy().chars().count();
            if name_length > self.max_name_length {
                self.max_name_length = name_length;
                self.path_with_longest_name = Some(new_path);
            }
        }
    }
}

/// Java's `BLACKLISTED_NAMES`: unsynced iCloud placeholders, whose content the user has to
/// download before the vault can be migrated at all.
fn assert_not_blacklisted(file: &Path) -> Result<()> {
    let name = file.file_name().unwrap_or_default().to_string_lossy();
    if name.ends_with(".icloud") {
        return Err(CoreError::MigrationBlocked(format!(
            "migration impossible due to file: {name}"
        )));
    }
    Ok(())
}

/// The `PreMigrationVisitor` pass over `d/`.
fn pre_migration_scan(vault_root: &Path, determine_lengths: bool) -> Result<PreMigrationStats> {
    struct Visitor<'a> {
        vault_root: &'a Path,
        stats: PreMigrationStats,
    }
    impl DataDirVisitor for Visitor<'_> {
        fn visit_file(&mut self, file: &Path) -> Result<()> {
            assert_not_blacklisted(file)?;
            self.stats.total_files += 1;
            if self.stats.determined_lengths {
                // The skips are not recorded here: this pass measures name lengths and is walked
                // again by `migrate_file_names`, which reports the very same set. Recording both
                // would list every skipped node twice.
                if let Some(migration) = parse_or_skip(self.vault_root, file, &mut |_, _| {}) {
                    let vault_root = self.vault_root;
                    self.stats.update(vault_root, &migration);
                }
            }
            Ok(())
        }
    }
    let mut visitor = Visitor {
        vault_root,
        stats: PreMigrationStats {
            determined_lengths: determine_lengths,
            ..PreMigrationStats::default()
        },
    };
    walk_data_dir(&vault_root.join(DATA_DIR_NAME), 0, &mut visitor)?;
    Ok(visitor.stats)
}

/// The renames the 6 → 7 step would perform and the nodes it would skip, all paths relative to
/// the vault directory.
///
/// This is the `--dry-run` at core level: nothing is written, not even the `c/` probe directory.
/// Collisions are *not* resolved — two sources landing on the same target are both listed with
/// that target, and the migration gives the second one a `_1` suffix when it gets there. The
/// skips, on the other hand, are exactly the ones the migration itself would report, minus the
/// ones only a real rename can discover (three occupied targets in a row).
pub fn plan_renames(vault_root: &Path) -> Result<(Vec<PlannedRename>, Vec<PathBuf>)> {
    struct Visitor<'a> {
        vault_root: &'a Path,
        renames: Vec<PlannedRename>,
        skipped: Vec<PathBuf>,
    }
    impl DataDirVisitor for Visitor<'_> {
        fn visit_file(&mut self, file: &Path) -> Result<()> {
            let vault_root = self.vault_root;
            let skipped = &mut self.skipped;
            let Some(migration) = parse_or_skip(vault_root, file, &mut |file, reason| {
                note_skip(vault_root, skipped, file, reason)
            }) else {
                return Ok(());
            };
            // A name that is not valid BASE32 has no target, and the migration cannot move it
            // either: it is a skip there and is listed as one here.
            match migration.target_path("") {
                Ok(target) => self.renames.push(PlannedRename {
                    from: relativize(self.vault_root, file),
                    to: relativize(self.vault_root, &target),
                }),
                Err(reason) => note_skip(self.vault_root, &mut self.skipped, file, &reason),
            }
            Ok(())
        }
    }
    let mut visitor = Visitor {
        vault_root,
        renames: Vec::new(),
        skipped: Vec::new(),
    };
    walk_data_dir(&vault_root.join(DATA_DIR_NAME), 0, &mut visitor)?;
    Ok((visitor.renames, visitor.skipped))
}

fn relativize(vault_root: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(vault_root).unwrap_or(path).to_path_buf()
}

/// The `MigratingVisitor` pass: collect per directory, rename in `postVisitDirectory`.
///
/// Renaming while the directory is being read would make the walk stumble over the `.c9r`
/// directories it just created, which is why Java defers the moves — and why we do.
///
/// Returns the vault-relative paths of the nodes that were left with their old names; each of them
/// is also reported as a [`MigrationEvent::NodeSkipped`] the moment it is skipped.
fn migrate_file_names(
    vault_root: &Path,
    total_files: u64,
    progress: &mut dyn FnMut(MigrationEvent),
) -> Result<Vec<PathBuf>> {
    struct Visitor<'a> {
        vault_root: &'a Path,
        progress: &'a mut dyn FnMut(MigrationEvent),
        total_files: u64,
        migrated_files: u64,
        in_current_dir: Vec<FilePathMigration>,
        skipped: Vec<PathBuf>,
    }
    impl Visitor<'_> {
        fn skip(&mut self, file: &Path, reason: &dyn std::fmt::Display) {
            note_skip(self.vault_root, &mut self.skipped, file, reason);
            if let Some(path) = self.skipped.last() {
                (self.progress)(MigrationEvent::NodeSkipped { path: path.clone() });
            }
        }
    }
    impl DataDirVisitor for Visitor<'_> {
        fn visit_file(&mut self, file: &Path) -> Result<()> {
            let vault_root = self.vault_root;
            let mut reason: Option<String> = None;
            let parsed = parse_or_skip(vault_root, file, &mut |_, why| {
                reason = Some(why.to_string())
            });
            match (parsed, reason) {
                (Some(migration), _) => self.in_current_dir.push(migration),
                (None, Some(reason)) => self.skip(file, &reason),
                (None, None) => {}
            }
            Ok(())
        }

        fn post_visit_directory(&mut self, _dir: &Path) -> Result<()> {
            for migration in std::mem::take(&mut self.in_current_dir) {
                self.migrated_files += 1;
                (self.progress)(MigrationEvent::StepProgress {
                    step: MigrationStep::SixToSeven,
                    done: self.migrated_files,
                    total: self.total_files,
                });
                match migration.migrate() {
                    Ok(_) => {}
                    // Java's `catch (FileAlreadyExistsException)`: a sync conflict or a node that
                    // another machine has already migrated -- and, unlike Java, a name that does
                    // not base32-decode, which cannot be moved anywhere either. Java logs both and
                    // carries on; we also remember them, so `m/` survives and the caller can name
                    // them.
                    Err(e @ (CoreError::MigrationBlocked(_) | CoreError::InvalidArgument(_))) => {
                        let path = migration.old_path().to_path_buf();
                        self.skip(&path, &e);
                    }
                    Err(e) => return Err(e),
                }
            }
            Ok(())
        }
    }
    let mut visitor = Visitor {
        vault_root,
        progress,
        total_files,
        migrated_files: 0,
        in_current_dir: Vec::new(),
        skipped: Vec::new(),
    };
    walk_data_dir(&vault_root.join(DATA_DIR_NAME), 0, &mut visitor)?;
    Ok(visitor.skipped)
}

/// Java's `continuationListener.continueMigrationOnEvent(REQUIRES_FULL_VAULT_DIR_SCAN)`.
///
/// Storage that can hold the full 220 characters needs no scan at all: no migrated name can be
/// longer, so `PreMigrationVisitor` reports its constants and the length checks pass by
/// construction. Below that the vault has to be walked to find out whether it fits, and Java asks
/// the user first — where we take the answer from the caller (`--yes`) and refuse otherwise, since
/// `CANCEL` in Java also means "return, having changed nothing".
fn needs_full_scan(filename_limit: usize, full_scan_allowed: bool) -> Result<bool> {
    if filename_limit >= SHORTENING_THRESHOLD {
        Ok(false)
    } else if full_scan_allowed {
        Ok(true)
    } else {
        Err(CoreError::MigrationBlocked(format!(
            "this storage supports only {filename_limit} characters per name ({SHORTENING_THRESHOLD} required); \
             a full scan of the vault is needed to tell whether migration is possible -- rerun with --yes"
        )))
    }
}

/// Migrates the vault's names from format 6 to format 7 and stamps the masterkey file.
///
/// # Preconditions
///
/// The vault is at format 5 or 6 (both share the on-disk layout) and `passphrase` is its
/// passphrase in the form the key file was locked with — the NFC form, once the 5 → 6 step has
/// run. Call [`crate::migration::migrate`] to dispatch; this function does not check the version
/// it is pointed at.
///
/// `full_scan_allowed` answers Java's `ContinuationEvent.REQUIRES_FULL_VAULT_DIR_SCAN`: when the
/// storage cannot hold 220-character names, the only way to find out whether the vault can be
/// migrated at all is to walk it completely, which the caller has to permit (`--yes`).
pub fn migrate(
    vault_root: &Path,
    passphrase: &str,
    full_scan_allowed: bool,
    rng: &mut dyn Rng,
) -> Result<()> {
    migrate_reporting(vault_root, passphrase, full_scan_allowed, &mut |_| {}, rng)
}

/// [`migrate`] with the per-file progress the chain forwards to its listener.
pub(crate) fn migrate_reporting(
    vault_root: &Path,
    passphrase: &str,
    full_scan_allowed: bool,
    progress: &mut dyn FnMut(MigrationEvent),
    rng: &mut dyn Rng,
) -> Result<()> {
    let masterkey_file = vault_root.join(MASTERKEY_FILENAME);
    let access = MasterkeyFileAccess::new(Vec::new());
    // Load first: the backup is only written once the passphrase is known to be correct.
    let masterkey = access.load(&masterkey_file, passphrase)?;
    back_up(&masterkey_file)?;

    // `determineSupportedCiphertextFileNameLength(vaultRoot.resolve("c"), 46, 28, 220)` — our
    // helper carries the same three arguments as constants.
    let filename_limit = determine_supported_ciphertext_file_name_length(vault_root)? as usize;
    let path_limit = filename_limit + MAX_ADDITIONAL_PATH_LENGTH;
    let full_scan = needs_full_scan(filename_limit, full_scan_allowed)?;

    let stats = pre_migration_scan(vault_root, full_scan)?;
    let (max_path, max_name) = (
        stats.max_ciphertext_path_length(),
        stats.max_ciphertext_name_length(),
    );
    if max_path > path_limit {
        return Err(CoreError::FileNameTooLong {
            path: stats.longest_path.unwrap_or_else(|| vault_root.to_owned()),
            needed: max_path,
            allowed: path_limit,
        });
    }
    if max_name > filename_limit {
        return Err(CoreError::FileNameTooLong {
            path: stats
                .path_with_longest_name
                .unwrap_or_else(|| vault_root.to_owned()),
            needed: max_name,
            allowed: filename_limit,
        });
    }

    let skipped = if stats.total_files > 0 {
        migrate_file_names(vault_root, stats.total_files, progress)?
    } else {
        Vec::new()
    };

    // `Files.walkFileTree(vaultRoot.resolve("m"), DeletingFileVisitor.INSTANCE)`. Format 7 keeps
    // the inflated names inside the nodes, so the metadata directory has no purpose any more —
    // including the unreferenced `.lng` files the 1.x releases left behind in it.
    //
    // **Deliberate deviation from Java**, which deletes `m/` unconditionally: every node this pass
    // could not migrate still carries its format 5/6 `<32 chars>.lng` name, and `m/` holds the only
    // copy of what that name inflates to. Deleting it would make those names unrecoverable — the
    // node would keep its data but lose its identity, in the one command that rewrites every name
    // in the vault. A leftover `m/` costs nothing: formats 7 and 8 never look at it, and a later
    // run of this step (after the user repaired whatever blocked the node) removes it.
    if skipped.is_empty() {
        match std::fs::remove_dir_all(vault_root.join(OLD_METADATA_DIR_NAME)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(CoreError::Io(e)),
        }
    } else {
        log::warn!(
            "{} node(s) kept their old names, so {}/{OLD_METADATA_DIR_NAME} is kept as well",
            skipped.len(),
            vault_root.display()
        );
    }

    // Last, so that an interrupted run is picked up again as a format 6 vault and simply repeats
    // (every rename it already made is skipped by `parse`).
    access.persist(
        &masterkey,
        &masterkey_file,
        passphrase,
        TARGET_VAULT_VERSION,
        rng,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn migration(name: &str) -> FilePathMigration {
        FilePathMigration {
            old_path: PathBuf::from("/v/d/AB/CD").join(name),
            old_canonical_name: canonical(name).expect("a canonical name"),
        }
    }

    #[test]
    fn the_canonical_name_is_found_inside_a_conflicting_name() {
        assert_eq!(
            canonical("MFRGGZDFMZTWQ2LK").as_deref(),
            Some("MFRGGZDFMZTWQ2LK")
        );
        assert_eq!(
            canonical("MFRGGZDFMZTWQ2LK (1)").as_deref(),
            Some("MFRGGZDFMZTWQ2LK")
        );
        assert_eq!(
            canonical("0MFRGGZDFMZTWQ2LK").as_deref(),
            Some("0MFRGGZDFMZTWQ2LK")
        );
        assert_eq!(
            canonical("1SMFRGGZDFMZTWQ2LK").as_deref(),
            Some("1SMFRGGZDFMZTWQ2LK")
        );
        // Padding is only allowed in the last block.
        assert_eq!(
            canonical("MFRGGZDFMZTWQ2L=").as_deref(),
            Some("MFRGGZDFMZTWQ2L=")
        );
        assert_eq!(
            canonical("MFRGGZDF=ZTWQ2LK").as_deref(),
            Some("MFRGGZDF=ZTWQ2LK")
        );
        assert_eq!(canonical("nope").as_deref(), None);
        // Fewer than eight characters.
        assert_eq!(canonical("SHORT").as_deref(), None);
        // A trailing block that is neither full nor padded is dropped, as in Java.
        assert_eq!(
            canonical("MFRGGZDFMZTWQ2LKABC").as_deref(),
            Some("MFRGGZDFMZTWQ2LK")
        );
        // The prefix alone is not a name.
        assert_eq!(canonical("0").as_deref(), None);
        assert_eq!(canonical("1S").as_deref(), None);
    }

    #[test]
    fn base32_becomes_base64url_with_a_c9r_suffix() {
        // BASE32("JBSWY3DPEHPK3PXP") -> the bytes -> BASE64URL
        let m = migration("JBSWY3DPEHPK3PXP");
        assert_eq!(m.new_inflated_name().unwrap(), "SGVsbG8h3q2-7w==.c9r");
        assert_eq!(m.new_deflated_name().unwrap(), "SGVsbG8h3q2-7w==.c9r");
    }

    #[test]
    fn the_type_prefix_is_stripped_before_decoding() {
        let dir = migration("0JBSWY3DPEHPK3PXP");
        assert!(dir.is_directory() && !dir.is_symlink());
        assert_eq!(
            dir.old_canonical_name_without_type_prefix(),
            "JBSWY3DPEHPK3PXP"
        );
        assert_eq!(dir.old_canonical_name(), "0JBSWY3DPEHPK3PXP");
        let link = migration("1SJBSWY3DPEHPK3PXP");
        assert!(link.is_symlink() && !link.is_directory());
        assert_eq!(
            link.old_canonical_name_without_type_prefix(),
            "JBSWY3DPEHPK3PXP"
        );
        // All three decode to the same ciphertext.
        assert_eq!(
            dir.decoded_ciphertext().unwrap(),
            migration("JBSWY3DPEHPK3PXP").decoded_ciphertext().unwrap()
        );
    }

    #[test]
    fn a_name_that_is_not_base32_is_reported_rather_than_migrated() {
        // The last block may carry '=' anywhere; BASE32 then refuses it, as in Java.
        let broken = migration("MFRGGZDF=ZTWQ2LK");
        let err = broken.new_inflated_name().unwrap_err();
        assert!(matches!(err, CoreError::InvalidArgument(_)), "{err}");
    }

    #[test]
    fn a_long_name_is_deflated_to_a_c9s_name() {
        let long = migration(&"A".repeat(8 * 40)); // 320 base32 chars -> 200 bytes -> 268 base64
        let inflated = long.new_inflated_name().unwrap();
        assert!(inflated.len() > SHORTENING_THRESHOLD, "{}", inflated.len());
        let deflated = long.new_deflated_name().unwrap();
        assert!(deflated.ends_with(DEFLATED_FILE_SUFFIX));
        assert_eq!(deflated.len(), 28 + 4, "base64(sha1) = 28 plus \".c9s\"");
        assert_ne!(inflated, deflated);
    }

    #[test]
    fn target_paths_follow_the_type() {
        assert!(migration("JBSWY3DPEHPK3PXP")
            .target_path("")
            .unwrap()
            .ends_with("SGVsbG8h3q2-7w==.c9r"));
        assert!(migration("0JBSWY3DPEHPK3PXP")
            .target_path("")
            .unwrap()
            .ends_with("SGVsbG8h3q2-7w==.c9r/dir.c9r"));
        assert!(migration("1SJBSWY3DPEHPK3PXP")
            .target_path("")
            .unwrap()
            .ends_with("SGVsbG8h3q2-7w==.c9r/symlink.c9r"));
        // A shortened regular file becomes a node directory with a contents file.
        let long = migration(&"A".repeat(8 * 40));
        assert!(long.target_path("").unwrap().ends_with("contents.c9r"));
        assert_eq!(
            long.target_path("")
                .unwrap()
                .parent()
                .and_then(|p| p.file_name())
                .map(|n| n.to_string_lossy().into_owned()),
            Some(long.new_deflated_name().unwrap())
        );
    }

    #[test]
    fn the_attempt_suffix_goes_before_the_extension() {
        let p = migration("JBSWY3DPEHPK3PXP").target_path("_1").unwrap();
        assert!(p.ends_with("SGVsbG8h3q2-7w==_1.c9r"), "{p:?}");
        let long = migration(&"A".repeat(8 * 40)).target_path("_2").unwrap();
        assert!(
            long.parent()
                .and_then(|p| p.file_name())
                .is_some_and(|n| n.to_string_lossy().ends_with("_2.c9s")),
            "{long:?}"
        );
    }

    #[test]
    fn thirty_two_base32_characters_are_found_anywhere_in_a_name() {
        let hit = "A".repeat(32);
        assert_eq!(find_32_base32_chars(&hit), Some(hit.as_str()));
        assert_eq!(
            find_32_base32_chars(&format!("{hit} (1).lng")),
            Some(hit.as_str())
        );
        assert_eq!(find_32_base32_chars(&format!("x{hit}")), Some(hit.as_str()));
        assert_eq!(find_32_base32_chars(&"A".repeat(31)), None);
        assert_eq!(find_32_base32_chars("Grüße.lng"), None);
    }

    /// A synthetic `.lng` node whose inflated name is long enough to be shortened again: the whole
    /// `m/xx/yy/` → `.c9s` path in one test, without needing a real vault.
    #[test]
    fn a_shortened_name_is_inflated_and_deflated_again() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let short = "A".repeat(32);
        let long = "B".repeat(400); // 400 base32 chars -> 250 bytes -> 336 base64 chars
        std::fs::create_dir_all(root.join("m/AA/AA")).unwrap();
        std::fs::write(root.join(format!("m/AA/AA/{short}.lng")), long.as_bytes()).unwrap();
        let content_dir = root.join("d/XX/YYYYYY");
        std::fs::create_dir_all(&content_dir).unwrap();
        let old_path = content_dir.join(format!("{short}.lng"));
        std::fs::write(&old_path, b"ciphertext").unwrap();

        assert_eq!(inflate(root, &format!("{short}.lng")).unwrap(), long);
        let migration = FilePathMigration::parse(root, &old_path).unwrap().unwrap();
        assert_eq!(migration.old_canonical_name(), long);
        let inflated_name = migration.new_inflated_name().unwrap();
        assert!(inflated_name.len() > SHORTENING_THRESHOLD);

        let new_path = migration.migrate().unwrap();
        assert!(!old_path.exists(), "the old node is gone");
        assert_eq!(new_path.file_name().unwrap(), CONTENTS_FILE_NAME);
        assert_eq!(std::fs::read(&new_path).unwrap(), b"ciphertext");
        let node = new_path.parent().unwrap();
        assert_eq!(
            node.file_name().unwrap().to_string_lossy(),
            migration.new_deflated_name().unwrap()
        );
        // The `.c9s` node inflates back to the full name with the very reader `CryptoFs` uses.
        assert_eq!(crate::fs::long_names::inflate(node).unwrap(), inflated_name);
    }

    #[test]
    fn a_missing_metadata_file_is_skipped_rather_than_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let content_dir = root.join("d/XX/YYYYYY");
        std::fs::create_dir_all(&content_dir).unwrap();
        let orphan = content_dir.join(format!("{}.lng", "A".repeat(32)));
        std::fs::write(&orphan, b"ciphertext").unwrap();
        let err = FilePathMigration::parse(root, &orphan).unwrap_err();
        assert!(
            matches!(&err, CoreError::MigrationBlocked(m) if m.contains("failed to read metadata file")),
            "{err}"
        );
        // The sink is told about it, once, with the path it was given.
        let mut seen: Vec<PathBuf> = Vec::new();
        assert!(
            parse_or_skip(root, &orphan, &mut |file, _| seen.push(file.to_path_buf())).is_none()
        );
        assert_eq!(seen, std::slice::from_ref(&orphan));
        // An oversized metadata file is refused just as loudly.
        std::fs::create_dir_all(root.join("m/AA/AA")).unwrap();
        std::fs::write(
            root.join(format!("m/AA/AA/{}.lng", "A".repeat(32))),
            vec![b'A'; MAX_FILENAME_BUFFER_SIZE as usize + 1],
        )
        .unwrap();
        seen.clear();
        assert!(
            parse_or_skip(root, &orphan, &mut |file, _| seen.push(file.to_path_buf())).is_none()
        );
        assert_eq!(seen, std::slice::from_ref(&orphan));
        // A name that is simply not a Cryptomator name is no skip: the sink stays untouched.
        let plain = content_dir.join("notes.txt");
        std::fs::write(&plain, b"x").unwrap();
        seen.clear();
        assert!(
            parse_or_skip(root, &plain, &mut |file, _| seen.push(file.to_path_buf())).is_none()
        );
        assert!(seen.is_empty());
    }

    #[test]
    fn an_already_migrated_name_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["SGVsbG8h3q2-7w==.c9r", "AAAAAAAAAAAAAAAAAAAAAAAAAAA=.c9s"] {
            let path = dir.path().join(name);
            assert_eq!(
                FilePathMigration::parse(dir.path(), &path)
                    .unwrap()
                    .map(|m| m.old_canonical_name().to_owned()),
                None,
                "{name}"
            );
        }
    }

    #[test]
    fn a_storage_that_cannot_hold_220_characters_needs_permission_to_be_scanned() {
        assert!(!needs_full_scan(220, false).unwrap());
        assert!(!needs_full_scan(255, false).unwrap());
        assert!(needs_full_scan(120, true).unwrap());
        let err = needs_full_scan(120, false).unwrap_err();
        assert!(
            matches!(&err, CoreError::MigrationBlocked(m)
                if m.contains("only 120 characters") && m.contains("--yes")),
            "{err}"
        );
    }

    /// The `PreMigrationVisitor` pass on a hand-built `d/`: the counts and the two lengths Java
    /// takes from `getName(3)` and the whole relative path.
    #[test]
    fn the_pre_migration_scan_counts_and_measures() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // A real content directory: two hash characters and the remaining thirty.
        let content_dir = root.join("d").join("XX").join("Y".repeat(30));
        std::fs::create_dir_all(&content_dir).unwrap();
        // 16 base32 chars -> 10 bytes -> 16 base64 chars, and a directory twice as long.
        std::fs::write(content_dir.join("JBSWY3DPEHPK3PXP"), b"x").unwrap();
        std::fs::write(content_dir.join("0JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"), b"x").unwrap();
        // Neither a legacy name nor a migrated one: counted, but not measured.
        std::fs::write(content_dir.join("notes.txt"), b"x").unwrap();

        let scanned = pre_migration_scan(root, true).unwrap();
        assert_eq!(scanned.total_files, 3);
        // "SGVsbG8h3q2-7w==.c9r" is 20 characters, the directory's name 32.
        assert_eq!(scanned.max_ciphertext_name_length(), 32);
        assert!(scanned
            .path_with_longest_name
            .as_ref()
            .is_some_and(|p| p.ends_with(DIR_FILE_NAME)));
        // "d/XX/<30 chars>/<32 chars>/dir.c9r" = 1+1+2+1+30+1+32+1+7
        assert_eq!(scanned.max_ciphertext_path_length(), 76);
        assert_eq!(
            scanned.longest_path, scanned.path_with_longest_name,
            "the directory node is both the longest name and the longest path"
        );

        // Without the scan the visitor reports Java's two constants and only counts.
        let assumed = pre_migration_scan(root, false).unwrap();
        assert_eq!(assumed.total_files, 3);
        assert_eq!(
            assumed.max_ciphertext_name_length(),
            ASSUMED_MAX_NAME_LENGTH
        );
        assert_eq!(
            assumed.max_ciphertext_path_length(),
            ASSUMED_MAX_PATH_LENGTH
        );
        assert!(assumed.longest_path.is_none());

        // A blacklisted name stops the pass wherever it sits.
        std::fs::write(content_dir.join("MFRGGZDF.icloud"), b"x").unwrap();
        let err = pre_migration_scan(root, false).unwrap_err();
        assert!(matches!(err, CoreError::MigrationBlocked(_)), "{err}");
    }

    #[test]
    fn an_icloud_placeholder_stops_the_migration() {
        let err = assert_not_blacklisted(Path::new("/v/d/AB/CD/.MFRGGZDF.icloud")).unwrap_err();
        assert!(
            matches!(&err, CoreError::MigrationBlocked(m) if m.contains("migration impossible due to file")),
            "{err}"
        );
        assert!(assert_not_blacklisted(Path::new("/v/d/AB/CD/MFRGGZDF")).is_ok());
    }
}
