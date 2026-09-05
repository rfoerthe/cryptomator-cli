//! Directory listing pipeline (`dir/*`): filter → `C9rDecryptor` → `C9rConflictResolver` /
//! `C9sInflator` → `BrokenDirectoryFilter`. `.c9u` in-use markers (Hub) are never listed.
use super::ciphertext_path::CiphertextDirectory;
use super::events::{EventSink, FilesystemEvent};
use super::long_names::inflate;
use super::path::{child_display, CleartextPath};
use super::path_mapper::CryptoPathMapper;
use crate::constants::{
    CRYPTOMATOR_FILE_SUFFIX, DEFLATED_FILE_SUFFIX, DIR_FILE_NAME, INUSE_FILE_SUFFIX,
    MIN_CIPHER_NAME_LENGTH, SYMLINK_FILE_NAME,
};
use crate::Cryptor;
use regex::Regex;
use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

/// `Constants.BASE64_PATTERN`
static BASE64_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[A-Za-z0-9_-]{20}(?:[A-Za-z0-9_-]{4})*(?:[A-Za-z0-9_-]{4}|[A-Za-z0-9_-]{3}=|[A-Za-z0-9_-]{2}==)")
        .expect("valid regex")
});

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    pub cleartext_name: String,
    /// The node: `.c9r` file, `.c9r` node directory or `.c9s` directory.
    pub ciphertext_path: PathBuf,
    /// The base64 part of the canonical name.
    pub extracted_ciphertext: String,
}

/// `DirectoryStreamFactory.matchesEncryptedContentPattern`
pub fn matches_encrypted_content_pattern(name: &str) -> bool {
    name.chars().count() >= MIN_CIPHER_NAME_LENGTH
        && [
            CRYPTOMATOR_FILE_SUFFIX,
            DEFLATED_FILE_SUFFIX,
            INUSE_FILE_SUFFIX,
        ]
        .iter()
        .any(|s| name.ends_with(s))
}

pub struct DirectoryLister<'a> {
    pub mapper: &'a CryptoPathMapper,
    pub cryptor: &'a Cryptor,
    pub events: &'a EventSink,
    pub read_only: bool,
}

impl std::fmt::Debug for DirectoryLister<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectoryLister")
            .field("read_only", &self.read_only)
            .finish_non_exhaustive()
    }
}

impl DirectoryLister<'_> {
    pub fn list(&self, cleartext_dir: &CleartextPath) -> io::Result<Vec<DirEntry>> {
        let dir = self.mapper.ciphertext_dir(cleartext_dir)?;
        self.list_ciphertext_dir(cleartext_dir, &dir)
    }

    pub fn list_ciphertext_dir(
        &self,
        cleartext_dir: &CleartextPath,
        dir: &CiphertextDirectory,
    ) -> io::Result<Vec<DirEntry>> {
        let mut nodes: Vec<(String, PathBuf)> = std::fs::read_dir(&dir.path)?
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| {
                let name = entry.file_name().to_str()?.to_owned();
                matches_encrypted_content_pattern(&name).then(|| (name, entry.path()))
            })
            .collect();
        nodes.sort();
        // both subtractions saturate: a manipulated vault config may carry a threshold below 25,
        // which `CryptoPathMapper` accepts unchecked.
        let threshold = self.mapper.shortening_threshold();
        let max_cleartext_file_name_length =
            (threshold.saturating_sub(4) / 4 * 3).saturating_sub(16);
        let ctx = NodeContext {
            lister: self,
            dir_id: &dir.dir_id,
            cleartext_dir,
            max_cleartext_file_name_length,
        };
        let mut out = Vec::new();
        for (name, path) in nodes {
            if let Some(entry) = ctx.process(name, path)? {
                out.push(entry);
            }
        }
        out.sort_by(|a, b| a.cleartext_name.cmp(&b.cleartext_name));
        Ok(out)
    }
}

struct NodeContext<'a> {
    lister: &'a DirectoryLister<'a>,
    dir_id: &'a str,
    cleartext_dir: &'a CleartextPath,
    /// math from `FileSystemCapabilityChecker.determineSupportedCleartextFileNameLength`
    max_cleartext_file_name_length: usize,
}

impl NodeContext<'_> {
    fn cryptor(&self) -> &Cryptor {
        self.lister.cryptor
    }

    fn emit(&self, event: FilesystemEvent) {
        (self.lister.events)(event)
    }

    /// `NodeProcessor.process`
    fn process(&self, name: String, path: PathBuf) -> io::Result<Option<DirEntry>> {
        let node = if name.ends_with(CRYPTOMATOR_FILE_SUFFIX) {
            self.process_c9r(&name, path)?
        } else if name.ends_with(DEFLATED_FILE_SUFFIX) {
            self.process_c9s(path)
        } else {
            None // `.c9u`: in-use markers are skipped (Hub-only; never created by us)
        };
        Ok(node.filter(|n| self.is_not_broken_directory(n)))
    }

    /// `C9rProcessor`: decrypt (with narrowing) then resolve conflicts.
    fn process_c9r(&self, name: &str, path: PathBuf) -> io::Result<Option<DirEntry>> {
        let basename = name.strip_suffix(CRYPTOMATOR_FILE_SUFFIX).unwrap_or(name);
        let Some((cleartext_name, extracted)) =
            self.extract_ciphertext(basename, 0, basename.len(), &mut HashSet::new())
        else {
            return Ok(None);
        };
        self.resolve_conflict(
            DirEntry {
                cleartext_name,
                ciphertext_path: path,
                extracted_ciphertext: extracted,
            },
            name,
        )
    }

    /// `C9rDecryptor.extractCiphertext`: the first base64 run that decrypts; on failure narrow the
    /// search region at the `_`/`-` delimiters, first from the start, then from the end.
    ///
    /// The result only depends on `(start, end)`, so `visited` records the regions already explored.
    /// Without it the two recursive calls shrink the region by as little as one byte each and the
    /// call tree grows exponentially — a name of 220 `-` characters would never finish. A region is
    /// only re-entered after it yielded `None` (a hit short-circuits all the way out), so skipping
    /// it returns exactly what the unmemoized search would.
    fn extract_ciphertext(
        &self,
        basename: &str,
        start: usize,
        end: usize,
        visited: &mut HashSet<(usize, usize)>,
    ) -> Option<(String, String)> {
        if !visited.insert((start, end)) {
            return None;
        }
        let m = BASE64_PATTERN.find(&basename[start..end])?;
        let (m_start, m_end) = (start + m.start(), start + m.end());
        let valid = &basename[m_start..m_end];
        match self
            .cryptor()
            .file_name_cryptor()
            .decrypt_filename(valid, &[self.dir_id.as_bytes()])
        {
            Ok(cleartext) => Some((cleartext, valid.to_string())),
            Err(_) => {
                let first_delim = valid.find(['_', '-'])?; // fail fast: no other subsequence possible
                let last_delim = valid.rfind(['_', '-']).unwrap_or(first_delim);
                let new_start = m_start + first_delim.max(1);
                if let Some(found) = self.extract_ciphertext(basename, new_start, end, visited) {
                    return Some(found);
                }
                let delim_distance_from_end = valid.len() - last_delim;
                let new_end = m_end - delim_distance_from_end.max(1);
                self.extract_ciphertext(basename, start, new_end, visited)
            }
        }
    }

    /// `C9rConflictResolver.process`
    fn resolve_conflict(&self, node: DirEntry, full_name: &str) -> io::Result<Option<DirEntry>> {
        let canonical_name = format!("{}{CRYPTOMATOR_FILE_SUFFIX}", node.extracted_ciphertext);
        if full_name == canonical_name {
            return Ok(Some(node));
        }
        if full_name.starts_with('.') {
            return Ok(None); // hidden files are ignored
        }
        let canonical_path = node.ciphertext_path.with_file_name(&canonical_name);
        let canonical_cleartext = child_display(self.cleartext_dir, &node.cleartext_name);
        if self.lister.read_only {
            // Deviation from Java: cryptofs would try the rename regardless; we do not modify a vault opened read-only.
            self.emit(FilesystemEvent::ConflictResolutionFailed {
                canonical_cleartext_path: canonical_cleartext,
                conflicting_ciphertext_path: node.ciphertext_path.clone(),
                reason: "vault is opened read-only".into(),
            });
            return Ok(None);
        }
        match self.resolve_conflict_on_disk(&node, &canonical_path) {
            Ok(resolved) => Ok(resolved),
            Err(e) => {
                self.emit(FilesystemEvent::ConflictResolutionFailed {
                    canonical_cleartext_path: canonical_cleartext,
                    conflicting_ciphertext_path: node.ciphertext_path.clone(),
                    reason: e.to_string(),
                });
                Ok(None)
            }
        }
    }

    fn resolve_conflict_on_disk(
        &self,
        conflicting: &DirEntry,
        canonical_path: &Path,
    ) -> io::Result<Option<DirEntry>> {
        match self.resolve_conflict_trivially(canonical_path, &conflicting.ciphertext_path)? {
            TrivialResolution::MovedToCanonical => Ok(Some(DirEntry {
                cleartext_name: conflicting.cleartext_name.clone(),
                ciphertext_path: canonical_path.to_path_buf(),
                extracted_ciphertext: conflicting.extracted_ciphertext.clone(),
            })),
            // The canonical node still exists and is listed on its own; reporting the removed
            // duplicate as well would yield the same cleartext name twice.
            TrivialResolution::RemovedDuplicate => Ok(None),
            TrivialResolution::NotTrivial => {
                self.rename_conflicting_file(canonical_path, conflicting)
            }
        }
    }

    /// Moves the conflicting node onto the canonical path when that is free, or drops it when it is
    /// a directory/symlink node identical to the canonical one.
    fn resolve_conflict_trivially(
        &self,
        canonical: &Path,
        conflicting: &Path,
    ) -> io::Result<TrivialResolution> {
        if std::fs::symlink_metadata(canonical).is_err() {
            std::fs::rename(conflicting, canonical)?; // boom. conflict solved.
            return Ok(TrivialResolution::MovedToCanonical);
        }
        if has_same_file_content(
            &conflicting.join(DIR_FILE_NAME),
            &canonical.join(DIR_FILE_NAME),
        )? || has_same_file_content(
            &conflicting.join(SYMLINK_FILE_NAME),
            &canonical.join(SYMLINK_FILE_NAME),
        )? {
            std::fs::remove_dir_all(conflicting)?;
            return Ok(TrivialResolution::RemovedDuplicate);
        }
        Ok(TrivialResolution::NotTrivial)
    }

    /// `C9rConflictResolver.renameConflictingFile`
    fn rename_conflicting_file(
        &self,
        canonical_path: &Path,
        conflicting: &DirEntry,
    ) -> io::Result<Option<DirEntry>> {
        let cleartext = conflicting.cleartext_name.as_str();
        let full_name = conflicting
            .ciphertext_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let (basename, ext) = match cleartext.rfind('.') {
            Some(i) if i > 0 => (&cleartext[..i], &cleartext[i..]),
            _ => (cleartext, ""),
        };
        // assume the sync conflict string was appended after the ciphertext, before .c9r
        let end_of_ciphertext = full_name
            .find(&conflicting.extracted_ciphertext)
            .unwrap_or(0)
            + conflicting.extracted_ciphertext.len();
        let original_conflict_suffix =
            &full_name[end_of_ciphertext..full_name.len() - CRYPTOMATOR_FILE_SUFFIX.len()];
        // split the available cleartext length between basename, conflict suffix and extension
        let net_cleartext = self
            .max_cleartext_file_name_length
            .saturating_sub(ext.chars().count());
        let conflict_suffix: String = original_conflict_suffix
            .chars()
            .take(net_cleartext / 2)
            .collect();
        let conflict_suffix_len = conflict_suffix.chars().count().max(4); // reserve " (9)"
        let restricted_basename: String = basename
            .chars()
            .take(net_cleartext.saturating_sub(conflict_suffix_len))
            .collect();
        let dir_id = self.dir_id.as_bytes();
        let encrypt = |name: &str| {
            self.cryptor()
                .file_name_cryptor()
                .encrypt_filename(name, &[dir_id])
        };
        let mut alternative_cleartext = format!("{restricted_basename}{conflict_suffix}{ext}");
        let mut alternative_ciphertext = encrypt(&alternative_cleartext);
        let mut alternative_path = canonical_path
            .with_file_name(format!("{alternative_ciphertext}{CRYPTOMATOR_FILE_SUFFIX}"));
        let mut i = 1;
        while i < 10 && std::fs::symlink_metadata(&alternative_path).is_ok() {
            alternative_cleartext = format!("{restricted_basename} ({i}){ext}");
            alternative_ciphertext = encrypt(&alternative_cleartext);
            alternative_path = canonical_path
                .with_file_name(format!("{alternative_ciphertext}{CRYPTOMATOR_FILE_SUFFIX}"));
            i += 1;
        }
        if std::fs::symlink_metadata(&alternative_path).is_ok() {
            return Ok(None); // no free alternative name: keep the original
        }
        std::fs::rename(&conflicting.ciphertext_path, &alternative_path)?;
        self.emit(FilesystemEvent::ConflictResolved {
            canonical_cleartext_path: child_display(self.cleartext_dir, cleartext),
            conflicting_ciphertext_path: conflicting.ciphertext_path.clone(),
            resolved_cleartext_path: child_display(self.cleartext_dir, &alternative_cleartext),
            resolved_ciphertext_path: alternative_path.clone(),
        });
        Ok(Some(DirEntry {
            cleartext_name: alternative_cleartext,
            ciphertext_path: alternative_path,
            extracted_ciphertext: alternative_ciphertext,
        }))
    }

    /// `C9sInflator.process`: undecryptable or uninflatable `.c9s` nodes are skipped.
    fn process_c9s(&self, path: PathBuf) -> Option<DirEntry> {
        let c9r_name = inflate(&path).ok()?;
        let extracted = c9r_name
            .strip_suffix(CRYPTOMATOR_FILE_SUFFIX)
            .unwrap_or(&c9r_name)
            .to_string();
        let cleartext_name = self
            .cryptor()
            .file_name_cryptor()
            .decrypt_filename(&extracted, &[self.dir_id.as_bytes()])
            .ok()?;
        Some(DirEntry {
            cleartext_name,
            ciphertext_path: path,
            extracted_ciphertext: extracted,
        })
    }

    /// `BrokenDirectoryFilter`: a directory node whose content directory cannot be resolved or is missing.
    fn is_not_broken_directory(&self, node: &DirEntry) -> bool {
        let dir_file = node.ciphertext_path.join(DIR_FILE_NAME);
        if dir_file.is_file() {
            match self.lister.mapper.resolve_directory(&dir_file) {
                Ok(dir) => dir.path.is_dir(),
                Err(_) => false,
            }
        } else {
            true
        }
    }
}

/// Outcome of `C9rConflictResolver.resolveConflictTrivially`.
enum TrivialResolution {
    /// The canonical name was free and the conflicting node was moved onto it.
    MovedToCanonical,
    /// The conflicting node was a byte-identical directory/symlink node and got removed.
    RemovedDuplicate,
    /// Not resolvable without inventing a new name.
    NotTrivial,
}

/// `C9rConflictResolver.hasSameFileContent`: both parents are directories, both files exist and are byte-identical.
fn has_same_file_content(conflicting: &Path, canonical: &Path) -> io::Result<bool> {
    let is_dir = |p: &Path| p.parent().map(|d| d.is_dir()).unwrap_or(false);
    if !is_dir(conflicting) || !is_dir(canonical) {
        return Ok(false);
    }
    match (std::fs::read(conflicting), std::fs::read(canonical)) {
        (Ok(a), Ok(b)) => Ok(a == b),
        (Err(e), _) | (_, Err(e)) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        (Err(e), _) | (_, Err(e)) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{DIR_FILE_NAME, SYMLINK_FILE_NAME};
    use crate::crypto::rng::DetRng;
    use crate::crypto::stream::encrypt_all;
    use crate::fs::dir_id::DirIdLoader;
    use crate::fs::events::EventCollector;
    use crate::fs::testutil::new_vault;
    use crate::fs::{CleartextPath, CryptoPathMapper};
    use std::sync::Arc;

    struct Fx {
        _dir: tempfile::TempDir,
        cryptor: Arc<Cryptor>,
        mapper: CryptoPathMapper,
        events: EventCollector,
    }

    fn fx(threshold: u32) -> Fx {
        let (dir, cryptor, config) = new_vault(threshold);
        let events = EventCollector::new();
        let mapper = CryptoPathMapper::new(
            dir.path(),
            cryptor.clone(),
            Arc::new(DirIdLoader::new(events.sink())),
            config.shortening_threshold,
            events.sink(),
        );
        Fx {
            _dir: dir,
            cryptor,
            mapper,
            events,
        }
    }

    impl Fx {
        fn write_file(&self, name: &str, content: &[u8]) -> PathBuf {
            let p = self
                .mapper
                .ciphertext_file_path(&CleartextPath::root().join(name).unwrap())
                .unwrap();
            if p.is_shortened() {
                std::fs::create_dir_all(p.raw_path()).unwrap();
                p.persist_long_file_name().unwrap();
            }
            std::fs::write(
                p.file_path(),
                encrypt_all(&self.cryptor, &mut DetRng::default(), content).unwrap(),
            )
            .unwrap();
            p.raw_path().to_path_buf()
        }
        fn make_dir(&self, name: &str, dir_id: &str) -> PathBuf {
            let p = self
                .mapper
                .ciphertext_file_path(&CleartextPath::root().join(name).unwrap())
                .unwrap();
            std::fs::create_dir_all(p.raw_path()).unwrap();
            std::fs::write(p.dir_file_path(), dir_id).unwrap();
            let content = self.mapper.resolve_directory_id(dir_id);
            std::fs::create_dir_all(&content.path).unwrap();
            p.raw_path().to_path_buf()
        }
        fn names(&self, read_only: bool) -> Vec<String> {
            let lister = DirectoryLister {
                mapper: &self.mapper,
                cryptor: &self.cryptor,
                events: &self.events.sink(),
                read_only,
            };
            lister
                .list(&CleartextPath::root())
                .unwrap()
                .into_iter()
                .map(|e| e.cleartext_name)
                .collect()
        }
    }

    #[test]
    fn pattern_filter() {
        assert!(matches_encrypted_content_pattern(&format!(
            "{}.c9r",
            "a".repeat(24)
        )));
        assert!(matches_encrypted_content_pattern(&format!(
            "{}.c9s",
            "a".repeat(24)
        )));
        assert!(matches_encrypted_content_pattern(&format!(
            "{}.c9u",
            "a".repeat(24)
        )));
        assert!(!matches_encrypted_content_pattern("dirid.c9r"));
        assert!(!matches_encrypted_content_pattern(&format!(
            "{}.txt",
            "a".repeat(30)
        )));
    }

    #[test]
    fn lists_plain_shortened_dirs_and_skips_others() {
        let fx = fx(220);
        fx.write_file("b.txt", b"b");
        fx.write_file(&"x".repeat(200), b"long");
        fx.make_dir("a-dir", "2f3a8f2e-0b8a-4e6f-9c5d-1a2b3c4d5e6f");
        let root = fx.mapper.root().path.clone();
        std::fs::write(root.join("random.txt"), b"?").unwrap();
        std::fs::write(root.join(format!("{}.c9u", "A".repeat(30))), b"inuse").unwrap();
        // renamed in-use marker: skipped, never touched
        assert_eq!(
            fx.names(false),
            vec!["a-dir".to_string(), "b.txt".into(), "x".repeat(200)]
        );
        assert!(root.join(format!("{}.c9u", "A".repeat(30))).exists());
        assert!(fx.events.take().is_empty());
    }

    #[test]
    fn broken_directories_are_filtered() {
        let fx = fx(220);
        // a readable dir.c9r whose content directory is gone
        fx.make_dir("d", "aaaaaaaa-0b8a-4e6f-9c5d-1a2b3c4d5e6f");
        std::fs::remove_dir_all(
            fx.mapper
                .resolve_directory_id("aaaaaaaa-0b8a-4e6f-9c5d-1a2b3c4d5e6f")
                .path,
        )
        .unwrap();
        assert!(fx.names(false).is_empty());
        assert!(fx.events.take().is_empty());
        // an unreadable (empty) dir.c9r, on a node whose id `DirIdLoader` has not cached yet
        let node = fx.make_dir("e", "bbbbbbbb-0b8a-4e6f-9c5d-1a2b3c4d5e6f");
        std::fs::write(node.join(DIR_FILE_NAME), b"").unwrap();
        assert!(fx.names(false).is_empty());
        assert_eq!(fx.events.kinds(), vec!["BROKEN_DIR_FILE"]);
    }

    #[test]
    fn conflict_without_canonical_file_is_renamed_back() {
        let fx = fx(220);
        let canonical = fx.write_file("hello.txt", b"hi");
        let name = canonical
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let conflicting = canonical.with_file_name(name.replace(".c9r", " (conflicted copy).c9r"));
        std::fs::rename(&canonical, &conflicting).unwrap();
        assert_eq!(fx.names(false), vec!["hello.txt"]);
        assert!(canonical.exists() && !conflicting.exists());
        assert!(fx.events.take().is_empty());
    }

    #[test]
    fn conflicting_copy_gets_the_conflict_suffix_then_numbers() {
        let fx = fx(220);
        let canonical = fx.write_file("hello.txt", b"hi");
        let name = canonical
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let conflicting = canonical.with_file_name(name.replace(".c9r", " (1).c9r"));
        std::fs::copy(&canonical, &conflicting).unwrap();
        assert_eq!(fx.names(false), vec!["hello (1).txt", "hello.txt"]);
        assert!(!conflicting.exists());
        assert!(
            matches!(&fx.events.take()[..], [FilesystemEvent::ConflictResolved { resolved_cleartext_path, .. }] if resolved_cleartext_path == "/hello (1).txt")
        );
        // a second conflict with the same suffix falls back to " (1)", " (2)", …
        std::fs::copy(&canonical, &conflicting).unwrap();
        assert_eq!(
            fx.names(false),
            vec!["hello (1).txt", "hello (2).txt", "hello.txt"]
        );
        // hidden files are ignored, not resolved
        let hidden = canonical.with_file_name(format!(".{name}"));
        std::fs::copy(&canonical, &hidden).unwrap();
        assert_eq!(fx.names(false).len(), 3);
        assert!(hidden.exists());
    }

    #[test]
    fn identical_conflicting_directory_and_symlink_are_removed() {
        let fx = fx(220);
        let dir_node = fx.make_dir("d", "2f3a8f2e-0b8a-4e6f-9c5d-1a2b3c4d5e6f");
        let dup = dir_node.with_file_name(format!(
            "{} (1).c9r",
            dir_node
                .file_name()
                .unwrap()
                .to_string_lossy()
                .trim_end_matches(".c9r")
        ));
        std::fs::create_dir(&dup).unwrap();
        std::fs::copy(dir_node.join(DIR_FILE_NAME), dup.join(DIR_FILE_NAME)).unwrap();
        let link = fx
            .mapper
            .ciphertext_file_path(&CleartextPath::parse("/l"))
            .unwrap();
        std::fs::create_dir(link.raw_path()).unwrap();
        std::fs::write(link.symlink_file_path(), b"target").unwrap();
        let link_dup = link.raw_path().with_file_name(format!(
            "{} (1).c9r",
            link.raw_path()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .trim_end_matches(".c9r")
        ));
        std::fs::create_dir(&link_dup).unwrap();
        std::fs::write(link_dup.join(SYMLINK_FILE_NAME), b"target").unwrap();
        assert_eq!(fx.names(false), vec!["d", "l"]);
        assert!(!dup.exists() && !link_dup.exists());
    }

    #[test]
    fn read_only_skips_conflicts_and_reports() {
        let fx = fx(220);
        let canonical = fx.write_file("hello.txt", b"hi");
        let name = canonical
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let conflicting = canonical.with_file_name(name.replace(".c9r", " (1).c9r"));
        std::fs::copy(&canonical, &conflicting).unwrap();
        assert_eq!(fx.names(true), vec!["hello.txt"]);
        assert!(conflicting.exists());
        assert_eq!(fx.events.kinds(), vec!["CONFLICT_RESOLUTION_FAILED"]);
    }

    #[test]
    fn narrowing_finds_the_ciphertext_inside_sync_suffixes() {
        let fx = fx(220);
        let canonical = fx.write_file("a.txt", b"a");
        let name = canonical
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        // suffix made of base64 characters glued directly to the ciphertext: only narrowing can find it
        let conflicting = canonical.with_file_name(name.replace(".c9r", "_conflict-2024.c9r"));
        std::fs::copy(&canonical, &conflicting).unwrap();
        let names = fx.names(false);
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"a.txt".to_string()));
        assert!(
            names
                .iter()
                .any(|n| n.starts_with("a_conflict-2024") || n == "a (1).txt"),
            "{names:?}"
        );
    }

    #[test]
    fn narrowing_terminates_on_a_pathological_name() {
        let fx = fx(220);
        fx.write_file("sibling.txt", b"s");
        // every `-` is a narrowing delimiter: without memoisation the search tree is exponential
        let root = fx.mapper.root().path.clone();
        std::fs::write(root.join(format!("{}.c9r", "-".repeat(220))), b"?").unwrap();
        let started = std::time::Instant::now();
        let names = fx.names(false);
        let elapsed = started.elapsed();
        assert_eq!(names, vec!["sibling.txt".to_string()]);
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "listing took {elapsed:?}"
        );
    }

    #[test]
    fn out_of_range_shortening_threshold_does_not_underflow() {
        let (dir, cryptor, _config) = new_vault(36);
        let events = EventCollector::new();
        // a threshold below 25 underflows `(t - 4) / 4 * 3 - 16` unless the subtraction saturates
        let mapper = CryptoPathMapper::new(
            dir.path(),
            cryptor.clone(),
            Arc::new(DirIdLoader::new(events.sink())),
            20,
            events.sink(),
        );
        let lister = DirectoryLister {
            mapper: &mapper,
            cryptor: &cryptor,
            events: &events.sink(),
            read_only: false,
        };
        assert!(lister.list(&CleartextPath::root()).unwrap().is_empty());
    }
}
