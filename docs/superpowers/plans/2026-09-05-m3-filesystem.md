# M3: File system + mount-less operations – Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `cryptomator-core` gains the cleartext file system layer of cryptofs 2.10.0 (path mapping, directory listing with conflict resolution, long names, open files with chunk cache, symlinks, attributes, events, statistics), and `crypto` can use it to read and write vault contents without a mount (`fs ls|tree|cat|get|put|rm|mkdir|mv`) as well as translate names (`name decrypt|locate`). Both directions are verified against the real Java library.

**Architecture:** New module `cryptomator_core::fs` with a facade `CryptoFs` (`&self` API, `Send + Sync`, interior mutability via `Mutex`) so that M4 can place it directly behind `fuser::Filesystem`. All errors of the fs layer are `std::io::Error` with meaningful `ErrorKind`s (errno mapping in M4). Cleartext paths are their own type `CleartextPath` (absolute, NFC-normalized). The `crypto` binary opens the vault with a password per command, performs the operation and exits; the CLI commands are thin wrappers around `CryptoFs`.

**Tech Stack:** Rust stable ≥ 1.85; existing crates; new in `cryptomator-core`: `regex` 1 (BASE64_PATTERN), `unicode-normalization` 0.1 (cleartext names NFC), `proptest` 1 (dev). Java 21+/Maven for interop.

**Spec:** `docs/superpowers/specs/2026-09-04-crypto-cli-design.md` (table `cryptomator-core` → `fs/*`, command grammar `fs`/`name`, exit codes, milestone M3)

## Global Constraints

- Working directory `/Users/rfoerthe/work/cryptomator-cli`, branch `feature/m3-filesystem` (from `main@2bf7eb3`).
- License AGPL-3.0-only; `#![forbid(unsafe_code)]`; no `unwrap()`/`expect()` on input data in library and binary code (tests may). MSRV 1.85: do not use `io::ErrorKind` variants that were stabilized only later (`FilesystemLoop`, `InvalidFilename` → use `Other`/`InvalidInput` with text instead; allowed: `NotFound`, `AlreadyExists`, `NotADirectory`, `IsADirectory`, `DirectoryNotEmpty`, `ReadOnlyFilesystem`, `InvalidInput`, `InvalidData`, `PermissionDenied`, `Unsupported`, `UnexpectedEof`, `Other`). If clippy reports `incompatible_msrv`, fall back to `Other`.
- `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo test --workspace --locked` clean before every commit; commit message ends with `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.
- `tests/fixtures/` is read-only: tests copy fixtures into a tempdir. Change nothing under `~/.m2` or in the desktop checkout.
- Java parity (cryptofs 2.10.0) is the benchmark: directory format `d/XX/YYYY…/<base64url>.c9r`, `.c9s` directories with `name.c9s` (+ `contents.c9r`/`dir.c9r`/`symlink.c9r`), `dirid.c9r` per content dir, `dir.c9r` = cleartext UUID (missing → random UUID), shortening from `ciphertextName.len() > shorteningThreshold`, never list and never create `.c9u`, ignore hidden conflict files (`.` prefix), conflict resolution like `C9rConflictResolver` (rename with original suffix or ` (1)`…` (9)`), `BASE64_PATTERN` = `[A-Za-z0-9_-]{20}(?:[A-Za-z0-9_-]{4})*(?:[A-Za-z0-9_-]{4}|[A-Za-z0-9_-]{3}=|[A-Za-z0-9_-]{2}==)`, chunk cache 5 chunks, the header is written on flush for writable files (empty file = header only), `cleartextSize` error ⇒ size 0, `maxCleartextFileNameLength = (threshold - 4) / 4 * 3 - 16` for conflict names, default name limit 10240 characters (`CryptoFileSystemProperties.DEFAULT_MAX_CLEARTEXT_NAME_LENGTH`).
- Deliberate deviations from Java (comment them in the code, document them in Task 14): (1) relative symlink targets are resolved against the parent directory of the link (POSIX), not against the root; (2) in read-only mode conflicts are not renamed but skipped (event `ConflictResolutionFailed`); (3) the directory cache has no 20 s expiry (the process is short-lived; M4 adds expiry); (4) `fs mv` never moves "into" a destination directory (Java `Files.move` semantics); (5) `.c9s` directories are only created on write access, not on read access.
- Cleartext names are NFC-normalized when parsed (`CryptoPathFactory`); listing returns names exactly as they are decrypted.
- Passwords, recovery keys, masterkeys, content keys and cleartext chunks never appear in error messages/logs; cleartext chunks live in `Zeroizing<Vec<u8>>`.
- Exit codes as in M2: 0 ok, 1 general (including cleartext path errors such as "not found"), 2 usage, 3 vault not found, 4 password invalid, 5 wrong state (including `usesReadOnlyMode=true` for write commands), 9 Hub, 12 no vault directory. `fs`/`name` commands require state `LOCKED` and read the password as in M2 (`PasswordArgs`); Hub check before the password.
- All `fs` write commands respect `usesReadOnlyMode` of the vault settings; `maxCleartextFilenameLength > 0` from the settings limits new names, `-1` ⇒ 10240.

---

## File structure

```
crates/cryptomator-core/Cargo.toml                    + regex, unicode-normalization; dev: proptest
crates/cryptomator-core/src/lib.rs                     + pub mod fs; re-exports
crates/cryptomator-core/src/fs/mod.rs                  module tree, io error helpers, lock(), testutil
crates/cryptomator-core/src/fs/path.rs                 CleartextPath (absolute, NFC, normalized)
crates/cryptomator-core/src/fs/events.rs               FilesystemEvent, EventSink, EventCollector
crates/cryptomator-core/src/fs/stats.rs                CryptoFsStats, StatsSnapshot
crates/cryptomator-core/src/fs/long_names.rs           deflate/inflate/DeflatedFileName (LongFileNameProvider)
crates/cryptomator-core/src/fs/ciphertext_path.rs      CiphertextFileType, CiphertextDirectory, CiphertextFilePath
crates/cryptomator-core/src/fs/dir_id.rs               DirIdLoader (+cache), dirid.c9r read/write (DirectoryIdLoader/-Backup)
crates/cryptomator-core/src/fs/path_mapper.rs          CryptoPathMapper (+CiphertextDirCache)
crates/cryptomator-core/src/fs/dir_stream.rs           DirectoryLister: C9rDecryptor, C9rConflictResolver, C9sInflator, BrokenDirectoryFilter
crates/cryptomator-core/src/fs/open_file.rs            OpenOptions, OpenCryptoFile, ChunkCache (fh/*, ch/CleartextFileChannel)
crates/cryptomator-core/src/fs/open_files.rs           OpenCryptoFiles, FileHandle, TwoPhaseMove
crates/cryptomator-core/src/fs/symlinks.rs             Symlinks
crates/cryptomator-core/src/fs/attrs.rs                FileAttributes (attr/*)
crates/cryptomator-core/src/fs/crypto_fs.rs            CryptoFs facade (CryptoFileSystemImpl)
crates/cryptomator-core/src/fs/name_decryptor.rs       decrypt_filename (FileNameDecryptor)
crates/cryptomator-core/src/fs/capabilities.rs         determine_supported_cleartext_file_name_length
crates/cryptomator-core/tests/common/mod.rs            fixture helpers (copy, masterkey from fixture.json, expected.json)
crates/cryptomator-core/tests/crypto_fs_fixtures.rs    all 8 fixtures via CryptoFs == expected.json
crates/crypto/src/cli.rs                               + Fs/Name grammar
crates/crypto/src/commands/{mod,fs,name}.rs            open_fs, fs/name commands
crates/crypto/src/output.rs                            + format_timestamp
crates/crypto/tests/common/mod.rs                      Sandbox (moved out of cli.rs) + fixture copy
crates/crypto/tests/cli_fs.rs, cli_name.rs             assert_cmd tests
crates/crypto/tests/java_interop.rs                    + Rust-written tree → Java verify; fixtures → fs tree
README.md, CHANGELOG.md, Spec                          updated
```

Shared types (all in `cryptomator_core::fs`, re-exported in `lib.rs`):

- `CleartextPath` (Task 1) – the key to all cleartext APIs.
- `EventSink = Arc<dyn Fn(FilesystemEvent) + Send + Sync>` (Task 1).
- `CiphertextFileType { File, Directory, Symlink }`, `CiphertextDirectory { dir_id, path }`, `CiphertextFilePath` (Task 2).
- `DirEntry { cleartext_name, ciphertext_path, extracted_ciphertext }` (Task 5).
- `OpenOptions`, `OpenCryptoFile` (Task 6); `OpenCryptoFiles`, `FileHandle` (Task 7).
- `FileAttributes` (Task 8); `CryptoFs`, `CryptoFsOptions` (Task 9/10).

---

### Task 1: Foundations – `fs` module, `CleartextPath`, events, statistics

**Files:**
- Modify: `crates/cryptomator-core/Cargo.toml`, `Cargo.toml` (workspace deps), `crates/cryptomator-core/src/lib.rs`
- Create: `crates/cryptomator-core/src/fs/mod.rs`, `fs/path.rs`, `fs/events.rs`, `fs/stats.rs`

**Interfaces:**
- Produces: `CleartextPath::{root, parse, elements, is_root, depth, parent, file_name, join, join_path, starts_with, rebase}`, `Display` (`/a/b`, root `/`); `fs::child_display(dir, name) -> String`; `FilesystemEvent` + `kind()` + `Display`; `EventSink`, `discard_events()`, `EventCollector::{new, sink, take, kinds}`; `CryptoFsStats` + `StatsSnapshot`; `fs::lock(&Mutex<T>)`; io helpers `fs::{not_found, already_exists, not_a_directory, is_a_directory, directory_not_empty, invalid_input, invalid_data, read_only_fs, name_too_long, not_a_link, fs_loop}`; `fs::testutil::new_vault(threshold) -> (TempDir, Arc<Cryptor>, VaultConfig)` (cfg(test)).

- [ ] **Step 1: Dependencies**

`Cargo.toml` (workspace), add under `[workspace.dependencies]`:

```toml
regex = "1"
proptest = "1"
```

`crates/cryptomator-core/Cargo.toml`: under `[dependencies]` `regex.workspace = true` and `unicode-normalization.workspace = true`; under `[dev-dependencies]` `proptest.workspace = true`.

- [ ] **Step 2: Failing tests for `CleartextPath`**

`crates/cryptomator-core/src/fs/path.rs` (tests at the end of the file):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_normalises() {
        assert_eq!(CleartextPath::parse("/").to_string(), "/");
        assert_eq!(CleartextPath::parse("").to_string(), "/");
        assert_eq!(CleartextPath::parse("a/b").to_string(), "/a/b");
        assert_eq!(CleartextPath::parse("/a//b/./c/../d").to_string(), "/a/b/d");
        assert_eq!(CleartextPath::parse("/../../x").to_string(), "/x");
        // NFD "café" (e + combining acute) becomes NFC
        let nfd = "cafe\u{301}.txt";
        assert_eq!(CleartextPath::parse(nfd).file_name(), Some("caf\u{e9}.txt"));
    }

    #[test]
    fn parent_and_file_name() {
        let p = CleartextPath::parse("/docs/notes.md");
        assert_eq!(p.file_name(), Some("notes.md"));
        assert_eq!(p.parent().unwrap().to_string(), "/docs");
        assert_eq!(p.parent().unwrap().parent().unwrap(), CleartextPath::root());
        assert!(CleartextPath::root().parent().is_none());
        assert!(CleartextPath::root().file_name().is_none());
        assert_eq!(p.depth(), 2);
    }

    #[test]
    fn join_rejects_bad_names() {
        let root = CleartextPath::root();
        assert_eq!(root.join("a").unwrap().to_string(), "/a");
        for bad in ["", ".", "..", "a/b"] {
            assert!(root.join(bad).is_err(), "{bad:?}");
        }
        assert_eq!(root.join("cafe\u{301}").unwrap().file_name(), Some("caf\u{e9}"));
    }

    #[test]
    fn join_path_resolves_relative_and_absolute() {
        let dir = CleartextPath::parse("/a/b");
        assert_eq!(dir.join_path("c/d").to_string(), "/a/b/c/d");
        assert_eq!(dir.join_path("../x").to_string(), "/a/x");
        assert_eq!(dir.join_path("/y").to_string(), "/y");
    }

    #[test]
    fn prefix_and_rebase() {
        let a = CleartextPath::parse("/a");
        let ab = CleartextPath::parse("/a/b");
        let abc = CleartextPath::parse("/a/b/c");
        assert!(abc.starts_with(&ab));
        assert!(abc.starts_with(&CleartextPath::root()));
        assert!(!ab.starts_with(&abc));
        assert!(!CleartextPath::parse("/ab").starts_with(&a));
        let moved = abc.rebase(&ab, &CleartextPath::parse("/x")).unwrap();
        assert_eq!(moved.to_string(), "/x/c");
        assert!(abc.rebase(&CleartextPath::parse("/z"), &a).is_none());
        assert_eq!(child_display(&CleartextPath::root(), "f"), "/f");
        assert_eq!(child_display(&ab, "f"), "/a/b/f");
    }
}
```

- [ ] **Step 3: Implementation `fs/mod.rs`, `fs/path.rs`, `fs/events.rs`, `fs/stats.rs`**

`crates/cryptomator-core/src/fs/mod.rs`:

```rust
//! Cleartext file system layer, ported from cryptofs 2.10.0 (`CryptoFileSystemImpl` and friends).
//! Errors are `std::io::Error` so a FUSE adapter can map them to errnos.
pub mod attrs;
pub mod capabilities;
pub mod ciphertext_path;
pub mod crypto_fs;
pub mod dir_id;
pub mod dir_stream;
pub mod events;
pub mod long_names;
pub mod name_decryptor;
pub mod open_file;
pub mod open_files;
pub mod path;
pub mod path_mapper;
pub mod stats;
pub mod symlinks;

pub use attrs::FileAttributes;
pub use capabilities::determine_supported_cleartext_file_name_length;
pub use ciphertext_path::{CiphertextDirectory, CiphertextFilePath, CiphertextFileType};
pub use crypto_fs::{CryptoFs, CryptoFsOptions, DEFAULT_MAX_CLEARTEXT_NAME_LENGTH};
pub use dir_id::DirIdLoader;
pub use dir_stream::DirEntry;
pub use events::{discard_events, EventCollector, EventSink, FilesystemEvent};
pub use name_decryptor::decrypt_filename;
pub use open_file::{OpenCryptoFile, OpenOptions};
pub use open_files::{FileHandle, OpenCryptoFiles};
pub use path::{child_display, CleartextPath};
pub use path_mapper::CryptoPathMapper;
pub use stats::{CryptoFsStats, StatsSnapshot};

use std::fmt::Display;
use std::io;
use std::sync::{Mutex, MutexGuard, PoisonError};

/// Locks without propagating poisoning: the protected data are caches and counters that stay
/// consistent even if a panic interrupted a holder.
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

pub(crate) fn not_found(path: impl Display) -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, format!("{path}: no such file or directory"))
}
pub(crate) fn already_exists(path: impl Display) -> io::Error {
    io::Error::new(io::ErrorKind::AlreadyExists, format!("{path}: already exists"))
}
pub(crate) fn not_a_directory(path: impl Display) -> io::Error {
    io::Error::new(io::ErrorKind::NotADirectory, format!("{path}: not a directory"))
}
pub(crate) fn is_a_directory(path: impl Display) -> io::Error {
    io::Error::new(io::ErrorKind::IsADirectory, format!("{path}: is a directory"))
}
pub(crate) fn directory_not_empty(path: impl Display) -> io::Error {
    io::Error::new(io::ErrorKind::DirectoryNotEmpty, format!("{path}: directory not empty"))
}
pub(crate) fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}
pub(crate) fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
pub(crate) fn read_only_fs() -> io::Error {
    io::Error::new(io::ErrorKind::ReadOnlyFilesystem, "vault is opened read-only")
}
pub(crate) fn name_too_long(path: impl Display, max: usize) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, format!("{path}: file name longer than {max} characters"))
}
pub(crate) fn not_a_link(path: impl Display, detail: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, format!("{path}: not a symbolic link ({detail})"))
}
pub(crate) fn fs_loop(path: impl Display) -> io::Error {
    io::Error::new(io::ErrorKind::Other, format!("{path}: too many levels of symbolic links"))
}

#[cfg(test)]
pub(crate) mod testutil {
    use crate::constants::DEFAULT_KEY_ID;
    use crate::crypto::rng::DetRng;
    use crate::{initialize, CipherCombo, Cryptor, Masterkey, VaultConfig};
    use std::sync::Arc;

    pub fn masterkey() -> Masterkey {
        let mut raw = [0u8; 64];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = i as u8;
        }
        Masterkey::from_raw(raw)
    }

    /// Initialises an empty format-8 vault (no scrypt: the raw masterkey is used directly).
    pub fn new_vault(threshold: u32) -> (tempfile::TempDir, Arc<Cryptor>, VaultConfig) {
        let dir = tempfile::tempdir().unwrap();
        let key = masterkey();
        let config = initialize(
            dir.path(),
            &key,
            CipherCombo::SivGcm,
            threshold,
            DEFAULT_KEY_ID,
            &mut DetRng::default(),
        )
        .unwrap();
        (dir, Arc::new(Cryptor::new(CipherCombo::SivGcm, &key)), config)
    }
}
```

The submodules that only come into existence in later tasks are created in this task as **empty files with just a doc comment** (`//! Task N`) so that `mod.rs` compiles; the `pub use` lines for types that do not exist yet are **commented out** in this task and activated in the respective tasks.

`crates/cryptomator-core/src/fs/path.rs`:

```rust
//! Cleartext paths inside a vault (`CryptoPath` + `CryptoPathFactory`): always absolute, every
//! component NFC-normalised, empty and `.` components dropped, `..` resolved lexically and never
//! above the root.
use crate::error::{CoreError, Result};
use std::fmt;
use unicode_normalization::UnicodeNormalization;

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CleartextPath {
    elements: Vec<String>,
}

impl CleartextPath {
    pub fn root() -> Self {
        Self { elements: Vec::new() }
    }

    /// A leading `/` is optional; `a/b` and `/a/b` are the same path.
    pub fn parse(path: &str) -> Self {
        Self::root().join_path(path)
    }

    pub fn elements(&self) -> &[String] {
        &self.elements
    }

    pub fn is_root(&self) -> bool {
        self.elements.is_empty()
    }

    pub fn depth(&self) -> usize {
        self.elements.len()
    }

    /// `None` for the root.
    pub fn parent(&self) -> Option<CleartextPath> {
        if self.elements.is_empty() {
            None
        } else {
            Some(Self { elements: self.elements[..self.elements.len() - 1].to_vec() })
        }
    }

    pub fn file_name(&self) -> Option<&str> {
        self.elements.last().map(String::as_str)
    }

    /// Appends one name (NFC-normalised). Rejects empty names, `.`, `..` and names containing `/`.
    pub fn join(&self, name: &str) -> Result<CleartextPath> {
        if name.is_empty() || name == "." || name == ".." || name.contains('/') {
            return Err(CoreError::InvalidArgument(format!("invalid file name {name:?}")));
        }
        let mut elements = self.elements.clone();
        elements.push(name.nfc().collect());
        Ok(Self { elements })
    }

    /// Resolves a relative path against `self`; an absolute path (leading `/`) replaces it.
    pub fn join_path(&self, path: &str) -> CleartextPath {
        let mut elements = if path.starts_with('/') { Vec::new() } else { self.elements.clone() };
        for raw in path.split('/') {
            match raw {
                "" | "." => {}
                ".." => {
                    elements.pop();
                }
                other => elements.push(other.nfc().collect()),
            }
        }
        Self { elements }
    }

    pub fn starts_with(&self, prefix: &CleartextPath) -> bool {
        self.elements.starts_with(&prefix.elements)
    }

    /// Replaces the prefix `old` by `new`; `None` if `self` does not start with `old`.
    pub fn rebase(&self, old: &CleartextPath, new: &CleartextPath) -> Option<CleartextPath> {
        let rest = self.elements.strip_prefix(old.elements.as_slice())?;
        let mut elements = new.elements.clone();
        elements.extend_from_slice(rest);
        Some(Self { elements })
    }
}

impl fmt::Display for CleartextPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.elements.is_empty() {
            f.write_str("/")
        } else {
            for element in &self.elements {
                write!(f, "/{element}")?;
            }
            Ok(())
        }
    }
}

/// `dir.resolve(name)` for display purposes (the name is not validated, it comes from a listing).
pub fn child_display(dir: &CleartextPath, name: &str) -> String {
    if dir.is_root() {
        format!("/{name}")
    } else {
        format!("{dir}/{name}")
    }
}
```

`crates/cryptomator-core/src/fs/events.rs`:

```rust
//! `org.cryptomator.cryptofs.event.*` (without `FileIsInUseEvent`: `.c9u` markers exist only with Hub).
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilesystemEvent {
    DecryptionFailed {
        ciphertext_path: PathBuf,
        reason: String,
    },
    ConflictResolved {
        canonical_cleartext_path: String,
        conflicting_ciphertext_path: PathBuf,
        resolved_cleartext_path: String,
        resolved_ciphertext_path: PathBuf,
    },
    ConflictResolutionFailed {
        canonical_cleartext_path: String,
        conflicting_ciphertext_path: PathBuf,
        reason: String,
    },
    BrokenDirFile {
        ciphertext_path: PathBuf,
    },
    BrokenFileNode {
        cleartext_path: String,
        ciphertext_path: PathBuf,
    },
}

impl FilesystemEvent {
    pub fn kind(&self) -> &'static str {
        match self {
            FilesystemEvent::DecryptionFailed { .. } => "DECRYPTION_FAILED",
            FilesystemEvent::ConflictResolved { .. } => "CONFLICT_RESOLVED",
            FilesystemEvent::ConflictResolutionFailed { .. } => "CONFLICT_RESOLUTION_FAILED",
            FilesystemEvent::BrokenDirFile { .. } => "BROKEN_DIR_FILE",
            FilesystemEvent::BrokenFileNode { .. } => "BROKEN_FILE_NODE",
        }
    }
}

impl fmt::Display for FilesystemEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FilesystemEvent::DecryptionFailed { ciphertext_path, reason } => {
                write!(f, "decryption of {} failed: {reason}", ciphertext_path.display())
            }
            FilesystemEvent::ConflictResolved { canonical_cleartext_path, resolved_cleartext_path, .. } => {
                write!(f, "conflicting copy of {canonical_cleartext_path} renamed to {resolved_cleartext_path}")
            }
            FilesystemEvent::ConflictResolutionFailed { canonical_cleartext_path, reason, .. } => {
                write!(f, "conflict for {canonical_cleartext_path} could not be resolved: {reason}")
            }
            FilesystemEvent::BrokenDirFile { ciphertext_path } => {
                write!(f, "broken directory file {}", ciphertext_path.display())
            }
            FilesystemEvent::BrokenFileNode { cleartext_path, ciphertext_path } => {
                write!(f, "{cleartext_path}: ciphertext node {} has no dir.c9r, symlink.c9r or contents.c9r", ciphertext_path.display())
            }
        }
    }
}

pub type EventSink = Arc<dyn Fn(FilesystemEvent) + Send + Sync>;

pub fn discard_events() -> EventSink {
    Arc::new(|_| {})
}

/// Collects events for assertions.
#[derive(Clone, Debug, Default)]
pub struct EventCollector {
    events: Arc<Mutex<Vec<FilesystemEvent>>>,
}

impl EventCollector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn sink(&self) -> EventSink {
        let events = self.events.clone();
        Arc::new(move |event| super::lock(&events).push(event))
    }

    pub fn take(&self) -> Vec<FilesystemEvent> {
        std::mem::take(&mut *super::lock(&self.events))
    }

    pub fn kinds(&self) -> Vec<&'static str> {
        super::lock(&self.events).iter().map(FilesystemEvent::kind).collect()
    }
}
```

`crates/cryptomator-core/src/fs/stats.rs`:

```rust
//! `CryptoFileSystemStats`: monotonic counters; the daemon (M4) derives rates from snapshots.
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct CryptoFsStats {
    bytes_read: AtomicU64,
    bytes_written: AtomicU64,
    bytes_decrypted: AtomicU64,
    bytes_encrypted: AtomicU64,
    chunk_cache_accesses: AtomicU64,
    chunk_cache_misses: AtomicU64,
    accesses_read: AtomicU64,
    accesses_written: AtomicU64,
    accesses: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatsSnapshot {
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub bytes_decrypted: u64,
    pub bytes_encrypted: u64,
    pub chunk_cache_accesses: u64,
    pub chunk_cache_hits: u64,
    pub chunk_cache_misses: u64,
    pub accesses_read: u64,
    pub accesses_written: u64,
    pub accesses: u64,
}

macro_rules! adder {
    ($name:ident, $field:ident) => {
        pub fn $name(&self, n: u64) {
            self.$field.fetch_add(n, Ordering::Relaxed);
        }
    };
}

impl CryptoFsStats {
    adder!(add_bytes_read, bytes_read);
    adder!(add_bytes_written, bytes_written);
    adder!(add_bytes_decrypted, bytes_decrypted);
    adder!(add_bytes_encrypted, bytes_encrypted);

    pub fn add_chunk_cache_access(&self) {
        self.chunk_cache_accesses.fetch_add(1, Ordering::Relaxed);
    }
    pub fn add_chunk_cache_miss(&self) {
        self.chunk_cache_misses.fetch_add(1, Ordering::Relaxed);
    }
    pub fn increment_accesses_read(&self) {
        self.accesses_read.fetch_add(1, Ordering::Relaxed);
    }
    pub fn increment_accesses_written(&self) {
        self.accesses_written.fetch_add(1, Ordering::Relaxed);
    }
    pub fn increment_accesses(&self) {
        self.accesses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> StatsSnapshot {
        let get = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let accesses = get(&self.chunk_cache_accesses);
        let misses = get(&self.chunk_cache_misses);
        StatsSnapshot {
            bytes_read: get(&self.bytes_read),
            bytes_written: get(&self.bytes_written),
            bytes_decrypted: get(&self.bytes_decrypted),
            bytes_encrypted: get(&self.bytes_encrypted),
            chunk_cache_accesses: accesses,
            chunk_cache_hits: accesses.saturating_sub(misses),
            chunk_cache_misses: misses,
            accesses_read: get(&self.accesses_read),
            accesses_written: get(&self.accesses_written),
            accesses: get(&self.accesses),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hits_are_accesses_minus_misses() {
        let s = CryptoFsStats::default();
        s.add_chunk_cache_access();
        s.add_chunk_cache_access();
        s.add_chunk_cache_miss();
        s.add_bytes_read(10);
        let snap = s.snapshot();
        assert_eq!((snap.chunk_cache_accesses, snap.chunk_cache_hits, snap.chunk_cache_misses), (2, 1, 1));
        assert_eq!(snap.bytes_read, 10);
    }
}
```

`crates/cryptomator-core/src/lib.rs`: add `pub mod fs;` and `pub use fs::CleartextPath;` (further re-exports arrive with the tasks).

- [ ] **Step 4: Run the tests**

Run: `cargo test -p cryptomator-core fs::`
Expected: PASS (5 path tests, 1 stats test)

- [ ] **Step 5: Gate + Commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked
git add Cargo.toml Cargo.lock crates/cryptomator-core
git commit -m "Add fs module skeleton with CleartextPath, events and stats

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 2: Long names and ciphertext paths

**Files:**
- Create: `crates/cryptomator-core/src/fs/long_names.rs`, `crates/cryptomator-core/src/fs/ciphertext_path.rs`
- Modify: `crates/cryptomator-core/src/fs/mod.rs` (activate re-exports)

**Interfaces:**
- Consumes: `constants::{CRYPTOMATOR_FILE_SUFFIX, DEFLATED_FILE_SUFFIX, INFLATED_FILE_NAME, CONTENTS_FILE_NAME, DIR_FILE_NAME, SYMLINK_FILE_NAME}`, `FileNameCryptor::encrypt_filename`.
- Produces: `long_names::{MAX_FILENAME_BUFFER_SIZE, DeflatedFileName{c9s_path, long_name}::persist, is_deflated, deflate(&Path) -> DeflatedFileName, inflate(&Path) -> io::Result<String>}`; `CiphertextFileType::{File, Directory, Symlink}::as_str` (`"file"|"dir"|"symlink"`); `CiphertextDirectory { dir_id: String, path: PathBuf }`; `CiphertextFilePath::{new(PathBuf, Option<DeflatedFileName>), raw_path, is_shortened, file_path, dir_file_path, symlink_file_path, inflated_name_path, persist_long_file_name}`.

- [ ] **Step 1: Failing test against the `long_names` fixture**

At the end of `fs/long_names.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{DATA_DIR_NAME, ROOT_DIR_ID};
    use crate::{CipherCombo, Cryptor, Masterkey};
    use data_encoding::HEXLOWER;
    use std::path::PathBuf;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures").join(name)
    }

    fn fixture_cryptor(vault: &Path) -> Cryptor {
        let meta: serde_json::Value =
            serde_json::from_slice(&std::fs::read(vault.join("fixture.json")).unwrap()).unwrap();
        let raw = HEXLOWER.decode(meta["masterkeyHex"].as_str().unwrap().as_bytes()).unwrap();
        let mut key = [0u8; 64];
        key.copy_from_slice(&raw);
        Cryptor::new(CipherCombo::SivGcm, &Masterkey::from_raw(key))
    }

    #[test]
    fn deflate_matches_the_c9s_directory_java_created() {
        let vault = fixture("long_names");
        let cryptor = fixture_cryptor(&vault);
        let hash = cryptor.file_name_cryptor().hash_directory_id(ROOT_DIR_ID);
        let root = vault.join(DATA_DIR_NAME).join(&hash[..2]).join(&hash[2..]);
        let long_name = format!("{}.txt", "c".repeat(200));
        let c9r_name = format!(
            "{}{CRYPTOMATOR_FILE_SUFFIX}",
            cryptor.file_name_cryptor().encrypt_filename(&long_name, &[ROOT_DIR_ID.as_bytes()])
        );
        assert!(c9r_name.len() > 220);
        let deflated = deflate(&root.join(&c9r_name));
        assert!(is_deflated(deflated.c9s_path.file_name().unwrap().to_str().unwrap()));
        assert!(deflated.c9s_path.is_dir(), "{}", deflated.c9s_path.display());
        assert_eq!(deflated.long_name, c9r_name);
        assert_eq!(inflate(&deflated.c9s_path).unwrap(), c9r_name);
    }

    #[test]
    fn persist_and_inflate_round_trip_and_size_cap() {
        let dir = tempfile::tempdir().unwrap();
        let deflated = deflate(&dir.path().join(format!("{}.c9r", "A".repeat(300))));
        deflated.persist().unwrap();
        assert_eq!(inflate(&deflated.c9s_path).unwrap(), deflated.long_name);
        // persisting twice truncates (Java: TRUNCATE_EXISTING)
        deflated.persist().unwrap();
        std::fs::write(deflated.c9s_path.join(INFLATED_FILE_NAME), vec![b'x'; 10 * 1024 + 1]).unwrap();
        assert_eq!(inflate(&deflated.c9s_path).unwrap_err().kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(inflate(&dir.path().join("missing.c9s")).unwrap_err().kind(), std::io::ErrorKind::NotFound);
    }
}
```

- [ ] **Step 2: Implementation**

`fs/long_names.rs`:

```rust
//! `LongFileNameProvider`: names longer than the shortening threshold are stored as
//! `BASE64URL(SHA1(name)).c9s/` directories holding the full name in `name.c9s`.
use crate::constants::{DEFLATED_FILE_SUFFIX, INFLATED_FILE_NAME};
use data_encoding::BASE64URL;
use sha1::{Digest, Sha1};
use std::io;
use std::path::{Path, PathBuf};

/// "no sane person gives a file a 10kb long name."
pub const MAX_FILENAME_BUFFER_SIZE: u64 = 10 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeflatedFileName {
    pub c9s_path: PathBuf,
    pub long_name: String,
}

impl DeflatedFileName {
    /// Creates the `.c9s` directory (if needed) and (re)writes `name.c9s`.
    pub fn persist(&self) -> io::Result<()> {
        std::fs::create_dir_all(&self.c9s_path)?;
        std::fs::write(self.c9s_path.join(INFLATED_FILE_NAME), self.long_name.as_bytes())
    }
}

pub fn is_deflated(name: &str) -> bool {
    name.ends_with(DEFLATED_FILE_SUFFIX)
}

/// `LongFileNameProvider.deflate`: `<parent>/<BASE64URL(SHA1(longName))>.c9s`.
pub fn deflate(c9r_path: &Path) -> DeflatedFileName {
    let long_name = c9r_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let short_name = format!("{}{DEFLATED_FILE_SUFFIX}", BASE64URL.encode(&Sha1::digest(long_name.as_bytes())));
    DeflatedFileName { c9s_path: c9r_path.with_file_name(short_name), long_name }
}

/// `LongFileNameProvider.inflate`: reads `<c9s>/name.c9s` (at most 10 KiB, UTF-8).
pub fn inflate(c9s_path: &Path) -> io::Result<String> {
    let long_name_file = c9s_path.join(INFLATED_FILE_NAME);
    if std::fs::metadata(&long_name_file)?.len() > MAX_FILENAME_BUFFER_SIZE {
        return Err(super::invalid_data(format!("Unexpectedly large file: {}", long_name_file.display())));
    }
    String::from_utf8(std::fs::read(&long_name_file)?)
        .map_err(|_| super::invalid_data(format!("{}: not valid UTF-8", long_name_file.display())))
}
```

`fs/ciphertext_path.rs`:

```rust
//! `CiphertextFilePath`, `CiphertextDirectory`, `CiphertextFileType`.
use super::long_names::DeflatedFileName;
use crate::constants::{CONTENTS_FILE_NAME, DIR_FILE_NAME, INFLATED_FILE_NAME, SYMLINK_FILE_NAME};
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CiphertextFileType {
    File,
    Directory,
    Symlink,
}

impl CiphertextFileType {
    /// Matches the `type` field of the fixture manifests.
    pub fn as_str(&self) -> &'static str {
        match self {
            CiphertextFileType::File => "file",
            CiphertextFileType::Directory => "dir",
            CiphertextFileType::Symlink => "symlink",
        }
    }
}

/// A directory id together with its content directory `d/XX/YYYY…`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiphertextDirectory {
    pub dir_id: String,
    pub path: PathBuf,
}

/// The ciphertext node of a cleartext path: a `.c9r` file or directory, or a `.c9s` directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiphertextFilePath {
    path: PathBuf,
    deflated: Option<DeflatedFileName>,
}

impl CiphertextFilePath {
    pub fn new(path: PathBuf, deflated: Option<DeflatedFileName>) -> Self {
        Self { path, deflated }
    }
    pub fn raw_path(&self) -> &Path {
        &self.path
    }
    pub fn is_shortened(&self) -> bool {
        self.deflated.is_some()
    }
    /// The regular-file ciphertext: the node itself, or `contents.c9r` inside a `.c9s` directory.
    pub fn file_path(&self) -> PathBuf {
        if self.is_shortened() { self.path.join(CONTENTS_FILE_NAME) } else { self.path.clone() }
    }
    pub fn dir_file_path(&self) -> PathBuf {
        self.path.join(DIR_FILE_NAME)
    }
    pub fn symlink_file_path(&self) -> PathBuf {
        self.path.join(SYMLINK_FILE_NAME)
    }
    pub fn inflated_name_path(&self) -> PathBuf {
        self.path.join(INFLATED_FILE_NAME)
    }
    pub fn persist_long_file_name(&self) -> io::Result<()> {
        match &self.deflated {
            Some(deflated) => deflated.persist(),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::long_names::deflate;

    #[test]
    fn shortened_paths_point_into_the_c9s_directory() {
        let plain = CiphertextFilePath::new(PathBuf::from("/v/d/AB/CD/x.c9r"), None);
        assert_eq!(plain.file_path(), PathBuf::from("/v/d/AB/CD/x.c9r"));
        assert_eq!(plain.dir_file_path(), PathBuf::from("/v/d/AB/CD/x.c9r/dir.c9r"));
        let deflated = deflate(Path::new("/v/d/AB/CD/long.c9r"));
        let short = CiphertextFilePath::new(deflated.c9s_path.clone(), Some(deflated.clone()));
        assert!(short.is_shortened());
        assert_eq!(short.file_path(), deflated.c9s_path.join("contents.c9r"));
        assert_eq!(short.symlink_file_path(), deflated.c9s_path.join("symlink.c9r"));
        assert_eq!(short.inflated_name_path(), deflated.c9s_path.join("name.c9s"));
        assert_eq!(CiphertextFileType::Directory.as_str(), "dir");
    }
}
```

- [ ] **Step 3: Tests**

Run: `cargo test -p cryptomator-core fs::long_names fs::ciphertext_path`
Expected: PASS (3 tests)

- [ ] **Step 4: Gate + Commit** (`git add crates/cryptomator-core`; message "Add long file name handling and ciphertext path types" with trailer)

---

### Task 3: Directory IDs – loader with cache and `dirid.c9r` backup

**Files:**
- Create: `crates/cryptomator-core/src/fs/dir_id.rs`
- Modify: `crates/cryptomator-core/src/fs/mod.rs`

**Interfaces:**
- Consumes: `EventSink`, `encrypt_all`/`decrypt_all`, `constants::{DIR_ID_BACKUP_FILE_NAME, MAX_DIR_ID_LENGTH}`, `CiphertextDirectory`.
- Produces: `dir_id::MAX_DIR_FILE_LENGTH = 1000`; `DirIdLoader::{new(EventSink), load(&Path) -> io::Result<String>, delete(&Path), move_id(src, dst)}`; `dir_id::is_ciphertext_content_dir(&Path) -> bool`; `dir_id::write_dir_id_backup(&Cryptor, &CiphertextDirectory, &mut dyn Rng) -> io::Result<()>`; `dir_id::read_dir_id_backup(&Cryptor, content_dir: &Path) -> crate::Result<String>`.

- [ ] **Step 1: Failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{DATA_DIR_NAME, ROOT_DIR_ID};
    use crate::crypto::rng::DetRng;
    use crate::fs::events::EventCollector;
    use crate::fs::testutil::new_vault;
    use crate::fs::FilesystemEvent;

    #[test]
    fn load_reads_cached_deletes_and_moves() {
        let dir = tempfile::tempdir().unwrap();
        let events = EventCollector::new();
        let loader = DirIdLoader::new(events.sink());
        let dir_file = dir.path().join("dir.c9r");
        std::fs::write(&dir_file, "2f3a8f2e-0b8a-4e6f-9c5d-1a2b3c4d5e6f").unwrap();
        assert_eq!(loader.load(&dir_file).unwrap(), "2f3a8f2e-0b8a-4e6f-9c5d-1a2b3c4d5e6f");
        // cached: a changed file is not re-read until delete()
        std::fs::write(&dir_file, "changed").unwrap();
        assert_eq!(loader.load(&dir_file).unwrap(), "2f3a8f2e-0b8a-4e6f-9c5d-1a2b3c4d5e6f");
        let moved = dir.path().join("moved.c9r");
        loader.move_id(&dir_file, &moved);
        assert_eq!(loader.load(&moved).unwrap(), "2f3a8f2e-0b8a-4e6f-9c5d-1a2b3c4d5e6f");
        loader.delete(&dir_file);
        assert_eq!(loader.load(&dir_file).unwrap(), "changed");
        assert!(events.take().is_empty());
    }

    #[test]
    fn missing_dir_file_yields_a_random_uuid_that_is_cached() {
        let dir = tempfile::tempdir().unwrap();
        let loader = DirIdLoader::new(crate::fs::discard_events());
        let missing = dir.path().join("dir.c9r");
        let id = loader.load(&missing).unwrap();
        assert_eq!(id.len(), 36);
        assert!(uuid::Uuid::parse_str(&id).is_ok());
        assert_eq!(loader.load(&missing).unwrap(), id);
    }

    #[test]
    fn empty_and_oversized_dir_files_are_broken() {
        let dir = tempfile::tempdir().unwrap();
        let events = EventCollector::new();
        let loader = DirIdLoader::new(events.sink());
        let empty = dir.path().join("empty.c9r");
        std::fs::write(&empty, b"").unwrap();
        let huge = dir.path().join("huge.c9r");
        std::fs::write(&huge, vec![b'a'; 1001]).unwrap();
        assert_eq!(loader.load(&empty).unwrap_err().kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(loader.load(&huge).unwrap_err().kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(events.kinds(), vec!["BROKEN_DIR_FILE", "BROKEN_DIR_FILE"]);
        assert!(matches!(&events.take()[0], FilesystemEvent::BrokenDirFile { ciphertext_path } if ciphertext_path == &empty));
    }

    #[test]
    fn dir_id_backup_round_trip_and_validation() {
        let (vault, cryptor, _) = new_vault(220);
        let hash = cryptor.file_name_cryptor().hash_directory_id(ROOT_DIR_ID);
        let root = vault.path().join(DATA_DIR_NAME).join(&hash[..2]).join(&hash[2..]);
        assert!(is_ciphertext_content_dir(&root));
        assert!(!is_ciphertext_content_dir(vault.path()));
        // initialize() already wrote the root backup
        assert_eq!(read_dir_id_backup(&cryptor, &root).unwrap(), ROOT_DIR_ID);
        let child = CiphertextDirectory {
            dir_id: "2f3a8f2e-0b8a-4e6f-9c5d-1a2b3c4d5e6f".into(),
            path: vault.path().join(DATA_DIR_NAME).join("AA").join("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"),
        };
        std::fs::create_dir_all(&child.path).unwrap();
        write_dir_id_backup(&cryptor, &child, &mut DetRng::default()).unwrap();
        assert_eq!(read_dir_id_backup(&cryptor, &child.path).unwrap(), child.dir_id);
        // CREATE_NEW: a second write fails
        assert!(write_dir_id_backup(&cryptor, &child, &mut DetRng::default()).is_err());
        // tampered backup is an authentication failure, not an io error
        let backup = child.path.join(DIR_ID_BACKUP_FILE_NAME);
        let mut bytes = std::fs::read(&backup).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        std::fs::write(&backup, bytes).unwrap();
        assert!(matches!(read_dir_id_backup(&cryptor, &child.path), Err(crate::CoreError::AuthenticationFailed(_))));
    }
}
```

- [ ] **Step 2: Implementation**

```rust
//! `DirectoryIdLoader`/`DirectoryIdProvider` (dir.c9r → directory id, cached) and `DirectoryIdBackup`
//! (`dirid.c9r`: the directory id encrypted like file content, inside its own content directory).
use super::ciphertext_path::CiphertextDirectory;
use super::events::{EventSink, FilesystemEvent};
use crate::constants::{DIR_ID_BACKUP_FILE_NAME, MAX_DIR_ID_LENGTH};
use crate::crypto::rng::Rng;
use crate::crypto::stream::{decrypt_all, encrypt_all};
use crate::error::{CoreError, Result};
use crate::Cryptor;
use data_encoding::BASE32;
use std::collections::HashMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// `DirectoryIdLoader.MAX_DIR_ID_LENGTH` (the loader tolerates more than the 36 chars of a UUID).
pub const MAX_DIR_FILE_LENGTH: u64 = 1000;

#[derive(Debug)]
pub struct DirIdLoader {
    events: EventSink,
    cache: Mutex<HashMap<PathBuf, String>>,
}

impl std::fmt::Debug for EventSinkDebug<'_> { /* not needed */ }
```

(Do **not** adopt the `EventSinkDebug` placeholder above – `DirIdLoader` gets a manual `Debug` that only shows the cache size:)

```rust
pub struct DirIdLoader {
    events: EventSink,
    cache: Mutex<HashMap<PathBuf, String>>,
}

impl std::fmt::Debug for DirIdLoader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirIdLoader").field("cached", &super::lock(&self.cache).len()).finish()
    }
}

impl DirIdLoader {
    pub fn new(events: EventSink) -> Self {
        Self { events, cache: Mutex::new(HashMap::new()) }
    }

    /// Reads `dir.c9r`. A missing file yields a fresh random UUID (which is cached, so a later
    /// `create_dir` writes exactly that id); empty or oversized files are broken.
    pub fn load(&self, dir_file: &Path) -> io::Result<String> {
        if let Some(id) = super::lock(&self.cache).get(dir_file) {
            return Ok(id.clone());
        }
        let id = self.load_uncached(dir_file)?;
        super::lock(&self.cache).insert(dir_file.to_path_buf(), id.clone());
        Ok(id)
    }

    fn load_uncached(&self, dir_file: &Path) -> io::Result<String> {
        let size = match std::fs::metadata(dir_file) {
            Ok(meta) => meta.len(),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(uuid::Uuid::new_v4().to_string()),
            Err(e) => return Err(e),
        };
        if size == 0 {
            (self.events)(FilesystemEvent::BrokenDirFile { ciphertext_path: dir_file.to_path_buf() });
            return Err(super::invalid_data(format!("Invalid, empty directory file: {}", dir_file.display())));
        }
        if size > MAX_DIR_FILE_LENGTH {
            (self.events)(FilesystemEvent::BrokenDirFile { ciphertext_path: dir_file.to_path_buf() });
            return Err(super::invalid_data(format!("Unexpectedly large directory file: {}", dir_file.display())));
        }
        Ok(String::from_utf8_lossy(&std::fs::read(dir_file)?).into_owned())
    }

    pub fn delete(&self, dir_file: &Path) {
        super::lock(&self.cache).remove(dir_file);
    }

    /// `DirectoryIdProvider.move`: transfers a cached id to the new dir file path.
    pub fn move_id(&self, src: &Path, dst: &Path) {
        let mut cache = super::lock(&self.cache);
        if let Some(id) = cache.remove(src) {
            cache.insert(dst.to_path_buf(), id);
        }
    }
}

/// `CiphertextPathValidations.isCiphertextContentDir`: `<2 chars>/<30 chars>` that decode as BASE32.
pub fn is_ciphertext_content_dir(path: &Path) -> bool {
    let (Some(parent), Some(name)) = (path.parent().and_then(Path::file_name), path.file_name()) else {
        return false;
    };
    let joined = format!("{}{}", parent.to_string_lossy(), name.to_string_lossy());
    joined.len() == 32 && BASE32.decode(joined.as_bytes()).is_ok()
}

/// `DirectoryIdBackup.write`: `dirid.c9r` (CREATE_NEW) with the id as encrypted file content.
pub fn write_dir_id_backup(cryptor: &Cryptor, dir: &CiphertextDirectory, rng: &mut dyn Rng) -> io::Result<()> {
    let ciphertext = encrypt_all(cryptor, rng, dir.dir_id.as_bytes())?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dir.path.join(DIR_ID_BACKUP_FILE_NAME))?;
    file.write_all(&ciphertext)
}

/// `DirectoryIdBackup.read`: decrypts `dirid.c9r` of a content directory (at most 36 chars).
pub fn read_dir_id_backup(cryptor: &Cryptor, content_dir: &Path) -> Result<String> {
    if !is_ciphertext_content_dir(content_dir) {
        return Err(CoreError::InvalidArgument(format!(
            "Directory {} is not a ciphertext content dir",
            content_dir.display()
        )));
    }
    let bytes = std::fs::read(content_dir.join(DIR_ID_BACKUP_FILE_NAME))?;
    let cleartext = decrypt_all(cryptor, &bytes).map_err(|e| match e.kind() {
        io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof => CoreError::AuthenticationFailed(e.to_string()),
        _ => CoreError::Io(e),
    })?;
    if cleartext.len() > MAX_DIR_ID_LENGTH {
        return Err(CoreError::InvalidArgument(format!(
            "Read directory id exceeds the maximum length of {MAX_DIR_ID_LENGTH} characters"
        )));
    }
    String::from_utf8(cleartext).map_err(|_| CoreError::AuthenticationFailed("directory id is not UTF-8".into()))
}
```

- [ ] **Step 3: Tests**

Run: `cargo test -p cryptomator-core fs::dir_id`
Expected: PASS (4 tests)

- [ ] **Step 4: Gate + Commit** ("Add directory id loader and dirid.c9r backup")

---

### Task 4: `CryptoPathMapper` and test helpers for fixtures

**Files:**
- Create: `crates/cryptomator-core/src/fs/path_mapper.rs`, `crates/cryptomator-core/tests/common/mod.rs`
- Modify: `crates/cryptomator-core/src/fs/mod.rs`, `crates/cryptomator-core/src/lib.rs`

**Interfaces:**
- Consumes: Tasks 1–3.
- Produces: `CryptoPathMapper::{new(vault_path: &Path, cryptor: Arc<Cryptor>, dir_ids: Arc<DirIdLoader>, shortening_threshold: u32, events: EventSink), root() -> &CiphertextDirectory, shortening_threshold() -> usize, ciphertext_file_name(dir_id, cleartext_name) -> String, assert_non_existing(&CleartextPath) -> io::Result<()>, ciphertext_file_type(&CleartextPath) -> io::Result<CiphertextFileType>, ciphertext_file_path(&CleartextPath) -> io::Result<CiphertextFilePath>, ciphertext_file_path_in(parent_dir: &Path, parent_dir_id: &str, name: &str) -> CiphertextFilePath, ciphertext_dir(&CleartextPath) -> io::Result<CiphertextDirectory>, resolve_directory(dir_file: &Path) -> io::Result<CiphertextDirectory>, resolve_directory_id(&str) -> CiphertextDirectory, invalidate_path_mapping(&CleartextPath), move_path_mapping(src, dst)}`.
- Test helpers `tests/common/mod.rs`: `PASSPHRASE`, `fixtures_root()`, `copy_recursively(src, dst)`, `copy_fixture(name) -> TempDir`, `FixtureMeta { cipher_combo, shortening_threshold, passphrase, masterkey_hex }`, `fixture_meta(vault)`, `open_fixture(name) -> (TempDir, OpenedVault)` (masterkey from `masterkeyHex`, no scrypt), `ExpectedEntry { path, kind, size, sha256, target }` (Ord), `expected_entries(vault) -> Vec<ExpectedEntry>`.

- [ ] **Step 1: Test helpers**

`crates/cryptomator-core/tests/common/mod.rs`:

```rust
#![allow(dead_code)]
//! Shared helpers for integration tests: fixture copies and fast unlocks via the known raw masterkey.
use cryptomator_core::{open_vault_with_key, Masterkey, OpenedVault};
use data_encoding::HEXLOWER;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

pub const PASSPHRASE: &str = "test-password-123";

pub fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

pub fn copy_recursively(src: &Path, dst: &Path) {
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let target = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            std::fs::create_dir(&target).unwrap();
            copy_recursively(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

/// Fixtures are read-only; every test works on a copy.
pub fn copy_fixture(name: &str) -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    copy_recursively(&fixtures_root().join(name), dir.path());
    dir
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FixtureMeta {
    pub cipher_combo: String,
    pub shortening_threshold: u32,
    pub passphrase: String,
    pub masterkey_hex: String,
}

pub fn fixture_meta(vault: &Path) -> FixtureMeta {
    serde_json::from_slice(&std::fs::read(vault.join("fixture.json")).unwrap()).unwrap()
}

/// Unlocks a fixture copy with its raw masterkey (no scrypt), so tests stay fast.
pub fn open_fixture(name: &str) -> (TempDir, OpenedVault) {
    let dir = copy_fixture(name);
    let meta = fixture_meta(dir.path());
    let raw = HEXLOWER.decode(meta.masterkey_hex.as_bytes()).unwrap();
    let mut key = [0u8; 64];
    key.copy_from_slice(&raw);
    let opened = open_vault_with_key(dir.path(), Masterkey::from_raw(key)).unwrap();
    (dir, opened)
}

/// One node of `expected.json`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize, serde::Serialize)]
pub struct ExpectedEntry {
    pub path: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

pub fn expected_entries(vault: &Path) -> Vec<ExpectedEntry> {
    let mut entries: Vec<ExpectedEntry> =
        serde_json::from_slice(&std::fs::read(vault.join("expected.json")).unwrap()).unwrap();
    entries.sort();
    entries
}

pub const FIXTURE_NAMES: [&str; 8] = [
    "long_names", "nested", "siv_ctrmac_basic", "siv_gcm_basic", "sizes", "symlinks", "threshold_36", "unicode",
];
```

- [ ] **Step 2: Failing tests** (unit tests in `path_mapper.rs` with `testutil::new_vault`)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{DIR_FILE_NAME, ROOT_DIR_ID};
    use crate::fs::{discard_events, testutil::new_vault, CiphertextFileType, CleartextPath};

    fn mapper(threshold: u32) -> (tempfile::TempDir, CryptoPathMapper) {
        let (dir, cryptor, config) = new_vault(threshold);
        let loader = Arc::new(DirIdLoader::new(discard_events()));
        let mapper = CryptoPathMapper::new(dir.path(), cryptor, loader, config.shortening_threshold, discard_events());
        (dir, mapper)
    }

    #[test]
    fn root_maps_to_the_hashed_empty_dir_id() {
        let (dir, mapper) = mapper(220);
        let root = mapper.ciphertext_dir(&CleartextPath::root()).unwrap();
        assert_eq!(root.dir_id, ROOT_DIR_ID);
        assert!(root.path.starts_with(dir.path().join("d")));
        assert!(root.path.is_dir());
        assert_eq!(mapper.ciphertext_file_type(&CleartextPath::root()).unwrap(), CiphertextFileType::Directory);
        assert!(mapper.ciphertext_file_path(&CleartextPath::root()).is_err());
    }

    #[test]
    fn file_paths_are_encrypted_per_parent_dir_id_and_shortened_above_threshold() {
        let (_dir, mapper) = mapper(220);
        let short = mapper.ciphertext_file_path(&CleartextPath::parse("/a.txt")).unwrap();
        assert!(!short.is_shortened());
        assert_eq!(short.raw_path().parent().unwrap(), mapper.root().path);
        assert!(short.raw_path().to_string_lossy().ends_with(".c9r"));
        let long = mapper.ciphertext_file_path(&CleartextPath::parse(&format!("/{}", "x".repeat(200)))).unwrap();
        assert!(long.is_shortened());
        assert!(long.raw_path().to_string_lossy().ends_with(".c9s"));
        // same name, other parent dir id → other ciphertext name
        let a = mapper.ciphertext_file_path_in(&mapper.root().path, "id-1", "a.txt");
        let b = mapper.ciphertext_file_path_in(&mapper.root().path, "id-2", "a.txt");
        assert_ne!(a, b);
        assert_eq!(mapper.ciphertext_file_name("id-1", "a.txt").len(), 32 + 4);
    }

    #[test]
    fn missing_nodes_and_types() {
        let (_dir, mapper) = mapper(220);
        let p = CleartextPath::parse("/missing");
        assert_eq!(mapper.ciphertext_file_type(&p).unwrap_err().kind(), io::ErrorKind::NotFound);
        assert!(mapper.assert_non_existing(&p).is_ok());
        // a regular ciphertext file is a FILE, a node dir with dir.c9r a DIRECTORY, with symlink.c9r a SYMLINK
        let file = mapper.ciphertext_file_path(&CleartextPath::parse("/f")).unwrap();
        std::fs::write(file.raw_path(), b"x").unwrap();
        assert_eq!(mapper.ciphertext_file_type(&CleartextPath::parse("/f")).unwrap(), CiphertextFileType::File);
        assert_eq!(mapper.assert_non_existing(&CleartextPath::parse("/f")).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        let dir = mapper.ciphertext_file_path(&CleartextPath::parse("/d")).unwrap();
        std::fs::create_dir(dir.raw_path()).unwrap();
        std::fs::write(dir.dir_file_path(), "2f3a8f2e-0b8a-4e6f-9c5d-1a2b3c4d5e6f").unwrap();
        assert_eq!(mapper.ciphertext_file_type(&CleartextPath::parse("/d")).unwrap(), CiphertextFileType::Directory);
        let link = mapper.ciphertext_file_path(&CleartextPath::parse("/l")).unwrap();
        std::fs::create_dir(link.raw_path()).unwrap();
        std::fs::write(link.symlink_file_path(), b"x").unwrap();
        assert_eq!(mapper.ciphertext_file_type(&CleartextPath::parse("/l")).unwrap(), CiphertextFileType::Symlink);
        // empty node dir: broken
        let broken = mapper.ciphertext_file_path(&CleartextPath::parse("/b")).unwrap();
        std::fs::create_dir(broken.raw_path()).unwrap();
        assert_eq!(mapper.ciphertext_file_type(&CleartextPath::parse("/b")).unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn dir_cache_invalidation_and_move() {
        let (_dir, mapper) = mapper(220);
        let d = CleartextPath::parse("/d");
        let node = mapper.ciphertext_file_path(&d).unwrap();
        std::fs::create_dir(node.raw_path()).unwrap();
        std::fs::write(node.join_dir_file(), "id-one").unwrap();
        let resolved = mapper.ciphertext_dir(&d).unwrap();
        assert_eq!(resolved.dir_id, "id-one");
        assert_eq!(resolved, mapper.resolve_directory(&node.dir_file_path()).unwrap());
        // cached: changing dir.c9r on disk is invisible until invalidated
        std::fs::write(node.dir_file_path(), "id-two").unwrap();
        assert_eq!(mapper.ciphertext_dir(&d).unwrap().dir_id, "id-one");
        mapper.move_path_mapping(&d, &CleartextPath::parse("/e"));
        assert_eq!(mapper.ciphertext_dir(&CleartextPath::parse("/e")).unwrap().dir_id, "id-one");
        mapper.invalidate_path_mapping(&d);
        // the dir id loader also caches; drop its entry to see the new id
        mapper.dir_ids.delete(&node.dir_file_path());
        assert_eq!(mapper.ciphertext_dir(&d).unwrap().dir_id, "id-two");
    }
}
```

(`node.join_dir_file()` in the test is a typo guard: use **`node.dir_file_path()`**.)

- [ ] **Step 3: Implementation `fs/path_mapper.rs`**

```rust
//! `CryptoPathMapper` + `CiphertextDirCache`: cleartext path ↔ ciphertext node / content directory.
use super::ciphertext_path::{CiphertextDirectory, CiphertextFilePath, CiphertextFileType};
use super::dir_id::DirIdLoader;
use super::events::{EventSink, FilesystemEvent};
use super::long_names::deflate;
use super::path::CleartextPath;
use crate::constants::{CRYPTOMATOR_FILE_SUFFIX, DATA_DIR_NAME, ROOT_DIR_ID};
use crate::Cryptor;
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub struct CryptoPathMapper {
    data_root: PathBuf,
    cryptor: Arc<Cryptor>,
    pub(crate) dir_ids: Arc<DirIdLoader>,
    shortening_threshold: usize,
    events: EventSink,
    /// `CiphertextDirCache` (without the 20 s expiry: the CLI process is short-lived; M4 adds it).
    dir_cache: Mutex<HashMap<CleartextPath, CiphertextDirectory>>,
    root: CiphertextDirectory,
}

impl std::fmt::Debug for CryptoPathMapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoPathMapper").field("data_root", &self.data_root).finish_non_exhaustive()
    }
}

impl CryptoPathMapper {
    pub fn new(vault_path: &Path, cryptor: Arc<Cryptor>, dir_ids: Arc<DirIdLoader>, shortening_threshold: u32, events: EventSink) -> Self {
        let data_root = vault_path.join(DATA_DIR_NAME);
        let root = Self::directory_for_id(&data_root, &cryptor, ROOT_DIR_ID);
        Self {
            data_root,
            cryptor,
            dir_ids,
            shortening_threshold: shortening_threshold as usize,
            events,
            dir_cache: Mutex::new(HashMap::new()),
            root,
        }
    }

    fn directory_for_id(data_root: &Path, cryptor: &Cryptor, dir_id: &str) -> CiphertextDirectory {
        let hash = cryptor.file_name_cryptor().hash_directory_id(dir_id);
        CiphertextDirectory { dir_id: dir_id.to_string(), path: data_root.join(&hash[..2]).join(&hash[2..]) }
    }

    pub fn root(&self) -> &CiphertextDirectory {
        &self.root
    }

    pub fn shortening_threshold(&self) -> usize {
        self.shortening_threshold
    }

    /// `<base64url(SIV(name, dirId))>.c9r`
    pub fn ciphertext_file_name(&self, dir_id: &str, cleartext_name: &str) -> String {
        format!(
            "{}{CRYPTOMATOR_FILE_SUFFIX}",
            self.cryptor.file_name_cryptor().encrypt_filename(cleartext_name, &[dir_id.as_bytes()])
        )
    }

    /// `AlreadyExists` if any node (file, dir, symlink, broken) exists for the path.
    pub fn assert_non_existing(&self, cleartext: &CleartextPath) -> io::Result<()> {
        let ciphertext = self.ciphertext_file_path(cleartext)?;
        match std::fs::symlink_metadata(ciphertext.raw_path()) {
            Ok(_) => Err(super::already_exists(cleartext)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// `NotFound` if the node does not exist; `InvalidData` (+ `BrokenFileNode` event) for a node
    /// directory without `dir.c9r`, `symlink.c9r` or (shortened) `contents.c9r`.
    pub fn ciphertext_file_type(&self, cleartext: &CleartextPath) -> io::Result<CiphertextFileType> {
        if cleartext.is_root() {
            return Ok(CiphertextFileType::Directory);
        }
        let ciphertext = self.ciphertext_file_path(cleartext)?;
        let attr = std::fs::symlink_metadata(ciphertext.raw_path()).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound { super::not_found(cleartext) } else { e }
        })?;
        if !attr.is_dir() {
            // assume "file" if not a directory (even if it isn't a "regular" file, see cryptofs issue #81)
            return Ok(CiphertextFileType::File);
        }
        let exists = |p: PathBuf| std::fs::symlink_metadata(p).is_ok();
        if exists(ciphertext.dir_file_path()) {
            Ok(CiphertextFileType::Directory)
        } else if exists(ciphertext.symlink_file_path()) {
            Ok(CiphertextFileType::Symlink)
        } else if ciphertext.is_shortened() && exists(ciphertext.file_path()) {
            Ok(CiphertextFileType::File)
        } else {
            (self.events)(FilesystemEvent::BrokenFileNode {
                cleartext_path: cleartext.to_string(),
                ciphertext_path: ciphertext.raw_path().to_path_buf(),
            });
            Err(super::invalid_data(format!(
                "{cleartext}: ciphertext directory {} has no clear type (missing dir.c9r, symlink.c9r or contents.c9r)",
                ciphertext.raw_path().display()
            )))
        }
    }

    pub fn ciphertext_file_path(&self, cleartext: &CleartextPath) -> io::Result<CiphertextFilePath> {
        let (Some(parent), Some(name)) = (cleartext.parent(), cleartext.file_name()) else {
            return Err(super::invalid_input(format!("Invalid file path (must have a parent): {cleartext}")));
        };
        let parent_dir = self.ciphertext_dir(&parent)?;
        Ok(self.ciphertext_file_path_in(&parent_dir.path, &parent_dir.dir_id, name))
    }

    pub fn ciphertext_file_path_in(&self, parent_ciphertext_dir: &Path, parent_dir_id: &str, cleartext_name: &str) -> CiphertextFilePath {
        let ciphertext_name = self.ciphertext_file_name(parent_dir_id, cleartext_name);
        let c9r_path = parent_ciphertext_dir.join(&ciphertext_name);
        if ciphertext_name.len() > self.shortening_threshold {
            let deflated = deflate(&c9r_path);
            CiphertextFilePath::new(deflated.c9s_path.clone(), Some(deflated))
        } else {
            CiphertextFilePath::new(c9r_path, None)
        }
    }

    /// Removes the mapping of `cleartext` and everything below it.
    pub fn invalidate_path_mapping(&self, cleartext: &CleartextPath) {
        super::lock(&self.dir_cache).retain(|key, _| !key.starts_with(cleartext));
    }

    /// Re-keys every mapping below `src` to live below `dst`.
    pub fn move_path_mapping(&self, src: &CleartextPath, dst: &CleartextPath) {
        let mut cache = super::lock(&self.dir_cache);
        let moved: Vec<(CleartextPath, CiphertextDirectory)> = cache
            .iter()
            .filter(|(key, _)| key.starts_with(src))
            .filter_map(|(key, dir)| key.rebase(src, dst).map(|k| (k, dir.clone())))
            .collect();
        cache.retain(|key, _| !key.starts_with(src));
        cache.extend(moved);
    }

    /// The content directory of a cleartext directory (root without I/O; others via `dir.c9r`).
    pub fn ciphertext_dir(&self, cleartext: &CleartextPath) -> io::Result<CiphertextDirectory> {
        if cleartext.is_root() {
            return Ok(self.root.clone());
        }
        if let Some(dir) = super::lock(&self.dir_cache).get(cleartext) {
            return Ok(dir.clone());
        }
        // not holding the lock: the lookup recurses into the parent directory
        let dir_file = self.ciphertext_file_path(cleartext)?.dir_file_path();
        let dir = self.resolve_directory(&dir_file)?;
        super::lock(&self.dir_cache).entry(cleartext.clone()).or_insert_with(|| dir.clone());
        Ok(dir)
    }

    pub fn resolve_directory(&self, dir_file: &Path) -> io::Result<CiphertextDirectory> {
        let dir_id = self.dir_ids.load(dir_file)?;
        Ok(self.resolve_directory_id(&dir_id))
    }

    pub fn resolve_directory_id(&self, dir_id: &str) -> CiphertextDirectory {
        Self::directory_for_id(&self.data_root, &self.cryptor, dir_id)
    }
}
```

`lib.rs`: `pub use fs::{CiphertextDirectory, CiphertextFilePath, CiphertextFileType, CleartextPath, CryptoPathMapper, DirIdLoader, EventSink, FilesystemEvent};`

- [ ] **Step 4: Tests**

Run: `cargo test -p cryptomator-core fs::path_mapper`
Expected: PASS (4 tests)

- [ ] **Step 5: Gate + Commit** ("Add CryptoPathMapper with directory cache")

---

### Task 5: Directory listing with conflict resolution

**Files:**
- Create: `crates/cryptomator-core/src/fs/dir_stream.rs`
- Modify: `crates/cryptomator-core/src/fs/mod.rs`

**Interfaces:**
- Consumes: `CryptoPathMapper`, `long_names::inflate`, `EventSink`, `constants`.
- Produces: `DirEntry { cleartext_name: String, ciphertext_path: PathBuf, extracted_ciphertext: String }`; `dir_stream::matches_encrypted_content_pattern(name) -> bool`; `DirectoryLister<'a> { mapper: &'a CryptoPathMapper, cryptor: &'a Cryptor, events: &'a EventSink, read_only: bool }` with `list(&CleartextPath) -> io::Result<Vec<DirEntry>>` (sorted by `cleartext_name`) and `list_ciphertext_dir(&CleartextPath, &CiphertextDirectory)`.

- [ ] **Step 1: Failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{DIR_FILE_NAME, SYMLINK_FILE_NAME};
    use crate::crypto::rng::DetRng;
    use crate::crypto::stream::encrypt_all;
    use crate::fs::dir_id::DirIdLoader;
    use crate::fs::events::EventCollector;
    use crate::fs::testutil::new_vault;
    use crate::fs::{discard_events, CleartextPath, CryptoPathMapper};

    struct Fx {
        _dir: tempfile::TempDir,
        cryptor: Arc<Cryptor>,
        mapper: CryptoPathMapper,
        events: EventCollector,
    }

    fn fx(threshold: u32) -> Fx {
        let (dir, cryptor, config) = new_vault(threshold);
        let events = EventCollector::new();
        let mapper = CryptoPathMapper::new(dir.path(), cryptor.clone(), Arc::new(DirIdLoader::new(events.sink())), config.shortening_threshold, events.sink());
        Fx { _dir: dir, cryptor, mapper, events }
    }

    impl Fx {
        fn lister(&self, read_only: bool) -> DirectoryLister<'_> {
            DirectoryLister { mapper: &self.mapper, cryptor: &self.cryptor, events: &self.events_sink(), read_only }
        }
        fn events_sink(&self) -> EventSink { self.events.sink() }
        fn write_file(&self, name: &str, content: &[u8]) -> PathBuf {
            let p = self.mapper.ciphertext_file_path(&CleartextPath::root().join(name).unwrap()).unwrap();
            if p.is_shortened() { std::fs::create_dir_all(p.raw_path()).unwrap(); p.persist_long_file_name().unwrap(); }
            std::fs::write(p.file_path(), encrypt_all(&self.cryptor, &mut DetRng::default(), content).unwrap()).unwrap();
            p.raw_path().to_path_buf()
        }
        fn make_dir(&self, name: &str, dir_id: &str) -> PathBuf {
            let p = self.mapper.ciphertext_file_path(&CleartextPath::root().join(name).unwrap()).unwrap();
            std::fs::create_dir_all(p.raw_path()).unwrap();
            std::fs::write(p.dir_file_path(), dir_id).unwrap();
            let content = self.mapper.resolve_directory_id(dir_id);
            std::fs::create_dir_all(&content.path).unwrap();
            p.raw_path().to_path_buf()
        }
        fn names(&self, read_only: bool) -> Vec<String> {
            let lister = DirectoryLister { mapper: &self.mapper, cryptor: &self.cryptor, events: &self.events.sink(), read_only };
            lister.list(&CleartextPath::root()).unwrap().into_iter().map(|e| e.cleartext_name).collect()
        }
    }

    #[test]
    fn pattern_filter() {
        assert!(matches_encrypted_content_pattern(&format!("{}.c9r", "a".repeat(24))));
        assert!(matches_encrypted_content_pattern(&format!("{}.c9s", "a".repeat(24))));
        assert!(matches_encrypted_content_pattern(&format!("{}.c9u", "a".repeat(24))));
        assert!(!matches_encrypted_content_pattern("dirid.c9r"));
        assert!(!matches_encrypted_content_pattern(&format!("{}.txt", "a".repeat(30))));
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
        assert_eq!(fx.names(false), vec!["a-dir".to_string(), "b.txt".into(), "x".repeat(200)]);
        assert!(root.join(format!("{}.c9u", "A".repeat(30))).exists());
        assert!(fx.events.take().is_empty());
    }

    #[test]
    fn broken_directories_are_filtered() {
        let fx = fx(220);
        let node = fx.make_dir("d", "aaaaaaaa-0b8a-4e6f-9c5d-1a2b3c4d5e6f");
        std::fs::remove_dir_all(fx.mapper.resolve_directory_id("aaaaaaaa-0b8a-4e6f-9c5d-1a2b3c4d5e6f").path).unwrap();
        assert!(fx.names(false).is_empty());
        std::fs::write(node.join(DIR_FILE_NAME), b"").unwrap();
        assert!(fx.names(false).is_empty());
        assert_eq!(fx.events.kinds(), vec!["BROKEN_DIR_FILE"]);
    }

    #[test]
    fn conflict_without_canonical_file_is_renamed_back() {
        let fx = fx(220);
        let canonical = fx.write_file("hello.txt", b"hi");
        let name = canonical.file_name().unwrap().to_string_lossy().into_owned();
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
        let name = canonical.file_name().unwrap().to_string_lossy().into_owned();
        let conflicting = canonical.with_file_name(name.replace(".c9r", " (1).c9r"));
        std::fs::copy(&canonical, &conflicting).unwrap();
        assert_eq!(fx.names(false), vec!["hello (1).txt", "hello.txt"]);
        assert!(!conflicting.exists());
        assert!(matches!(&fx.events.take()[..], [FilesystemEvent::ConflictResolved { resolved_cleartext_path, .. }] if resolved_cleartext_path == "/hello (1).txt"));
        // a second conflict with the same suffix falls back to " (1)", " (2)", …
        std::fs::copy(&canonical, &conflicting).unwrap();
        assert_eq!(fx.names(false), vec!["hello (1).txt", "hello (2).txt", "hello.txt"]);
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
        let dup = dir_node.with_file_name(format!("{} (1).c9r", dir_node.file_name().unwrap().to_string_lossy().trim_end_matches(".c9r")));
        std::fs::create_dir(&dup).unwrap();
        std::fs::copy(dir_node.join(DIR_FILE_NAME), dup.join(DIR_FILE_NAME)).unwrap();
        let link = fx.mapper.ciphertext_file_path(&CleartextPath::parse("/l")).unwrap();
        std::fs::create_dir(link.raw_path()).unwrap();
        std::fs::write(link.symlink_file_path(), b"target").unwrap();
        let link_dup = link.raw_path().with_file_name(format!("{} (1).c9r", link.raw_path().file_name().unwrap().to_string_lossy().trim_end_matches(".c9r")));
        std::fs::create_dir(&link_dup).unwrap();
        std::fs::write(link_dup.join(SYMLINK_FILE_NAME), b"target").unwrap();
        assert_eq!(fx.names(false), vec!["d", "l"]);
        assert!(!dup.exists() && !link_dup.exists());
    }

    #[test]
    fn read_only_skips_conflicts_and_reports() {
        let fx = fx(220);
        let canonical = fx.write_file("hello.txt", b"hi");
        let name = canonical.file_name().unwrap().to_string_lossy().into_owned();
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
        let name = canonical.file_name().unwrap().to_string_lossy().into_owned();
        // suffix made of base64 characters glued directly to the ciphertext: only narrowing can find it
        let conflicting = canonical.with_file_name(name.replace(".c9r", "_conflict-2024.c9r"));
        std::fs::copy(&canonical, &conflicting).unwrap();
        let names = fx.names(false);
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"a.txt".to_string()));
        assert!(names.iter().any(|n| n.starts_with("a_conflict-2024") || n == "a (1).txt"), "{names:?}");
    }
}
```

(`fx.lister`/`events_sink` can be dropped if `names()` is enough – the implementer cleans up whatever is unused.)

- [ ] **Step 2: Implementation `fs/dir_stream.rs`**

```rust
//! Directory listing pipeline (`dir/*`): filter → `C9rDecryptor` → `C9rConflictResolver` /
//! `C9sInflator` → `BrokenDirectoryFilter`. `.c9u` in-use markers (Hub) are never listed.
use super::ciphertext_path::CiphertextDirectory;
use super::events::{EventSink, FilesystemEvent};
use super::long_names::inflate;
use super::path::{child_display, CleartextPath};
use super::path_mapper::CryptoPathMapper;
use crate::constants::{CRYPTOMATOR_FILE_SUFFIX, DEFLATED_FILE_SUFFIX, DIR_FILE_NAME, INUSE_FILE_SUFFIX, MIN_CIPHER_NAME_LENGTH, SYMLINK_FILE_NAME};
use crate::Cryptor;
use regex::Regex;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

/// `Constants.BASE64_PATTERN`
static BASE64_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[A-Za-z0-9_-]{20}(?:[A-Za-z0-9_-]{4})*(?:[A-Za-z0-9_-]{4}|[A-Za-z0-9_-]{3}=|[A-Za-z0-9_-]{2}==)").expect("valid regex")
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
        && [CRYPTOMATOR_FILE_SUFFIX, DEFLATED_FILE_SUFFIX, INUSE_FILE_SUFFIX].iter().any(|s| name.ends_with(s))
}

pub struct DirectoryLister<'a> {
    pub mapper: &'a CryptoPathMapper,
    pub cryptor: &'a Cryptor,
    pub events: &'a EventSink,
    pub read_only: bool,
}

impl std::fmt::Debug for DirectoryLister<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectoryLister").field("read_only", &self.read_only).finish_non_exhaustive()
    }
}

impl DirectoryLister<'_> {
    pub fn list(&self, cleartext_dir: &CleartextPath) -> io::Result<Vec<DirEntry>> {
        let dir = self.mapper.ciphertext_dir(cleartext_dir)?;
        self.list_ciphertext_dir(cleartext_dir, &dir)
    }

    pub fn list_ciphertext_dir(&self, cleartext_dir: &CleartextPath, dir: &CiphertextDirectory) -> io::Result<Vec<DirEntry>> {
        let mut nodes: Vec<(String, PathBuf)> = std::fs::read_dir(&dir.path)?
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| {
                let name = entry.file_name().to_str()?.to_owned();
                matches_encrypted_content_pattern(&name).then(|| (name, entry.path()))
            })
            .collect();
        nodes.sort();
        let ctx = NodeContext {
            lister: self,
            dir_id: &dir.dir_id,
            cleartext_dir,
            max_cleartext_file_name_length: (self.mapper.shortening_threshold().saturating_sub(4)) / 4 * 3 - 16,
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
        let Some((cleartext_name, extracted)) = self.extract_ciphertext(basename, 0, basename.len()) else {
            return Ok(None);
        };
        self.resolve_conflict(DirEntry { cleartext_name, ciphertext_path: path, extracted_ciphertext: extracted }, name)
    }

    /// `C9rDecryptor.extractCiphertext`: the first base64 run that decrypts; on failure narrow the
    /// search region at the `_`/`-` delimiters, first from the start, then from the end.
    fn extract_ciphertext(&self, basename: &str, start: usize, end: usize) -> Option<(String, String)> {
        let m = BASE64_PATTERN.find(&basename[start..end])?;
        let (m_start, m_end) = (start + m.start(), start + m.end());
        let valid = &basename[m_start..m_end];
        match self.cryptor().file_name_cryptor().decrypt_filename(valid, &[self.dir_id.as_bytes()]) {
            Ok(cleartext) => Some((cleartext, valid.to_string())),
            Err(_) => {
                let first_delim = valid.find(['_', '-'])?; // fail fast: no other subsequence possible
                let last_delim = valid.rfind(['_', '-']).unwrap_or(first_delim);
                let new_start = m_start + first_delim.max(1);
                if let Some(found) = self.extract_ciphertext(basename, new_start, end) {
                    return Some(found);
                }
                let delim_distance_from_end = valid.len() - last_delim;
                let new_end = m_end - delim_distance_from_end.max(1);
                self.extract_ciphertext(basename, start, new_end)
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

    fn resolve_conflict_on_disk(&self, conflicting: &DirEntry, canonical_path: &Path) -> io::Result<Option<DirEntry>> {
        if self.resolve_conflict_trivially(canonical_path, &conflicting.ciphertext_path)? {
            return Ok(Some(DirEntry {
                cleartext_name: conflicting.cleartext_name.clone(),
                ciphertext_path: canonical_path.to_path_buf(),
                extracted_ciphertext: conflicting.extracted_ciphertext.clone(),
            }));
        }
        self.rename_conflicting_file(canonical_path, conflicting)
    }

    /// Moves the conflicting node onto the canonical path when that is free, or drops it when it is
    /// a directory/symlink node identical to the canonical one.
    fn resolve_conflict_trivially(&self, canonical: &Path, conflicting: &Path) -> io::Result<bool> {
        if std::fs::symlink_metadata(canonical).is_err() {
            std::fs::rename(conflicting, canonical)?; // boom. conflict solved.
            return Ok(true);
        }
        if has_same_file_content(&conflicting.join(DIR_FILE_NAME), &canonical.join(DIR_FILE_NAME))?
            || has_same_file_content(&conflicting.join(SYMLINK_FILE_NAME), &canonical.join(SYMLINK_FILE_NAME))?
        {
            std::fs::remove_dir_all(conflicting)?;
            return Ok(true);
        }
        Ok(false)
    }

    /// `C9rConflictResolver.renameConflictingFile`
    fn rename_conflicting_file(&self, canonical_path: &Path, conflicting: &DirEntry) -> io::Result<Option<DirEntry>> {
        let cleartext = conflicting.cleartext_name.as_str();
        let full_name = conflicting.ciphertext_path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let (basename, ext) = match cleartext.rfind('.') {
            Some(i) if i > 0 => (&cleartext[..i], &cleartext[i..]),
            _ => (cleartext, ""),
        };
        // assume the sync conflict string was appended after the ciphertext, before .c9r
        let end_of_ciphertext = full_name.find(&conflicting.extracted_ciphertext).unwrap_or(0) + conflicting.extracted_ciphertext.len();
        let original_conflict_suffix = &full_name[end_of_ciphertext..full_name.len() - CRYPTOMATOR_FILE_SUFFIX.len()];
        // split the available cleartext length between basename, conflict suffix and extension
        let net_cleartext = self.max_cleartext_file_name_length.saturating_sub(ext.chars().count());
        let conflict_suffix: String = original_conflict_suffix.chars().take(net_cleartext / 2).collect();
        let conflict_suffix_len = conflict_suffix.chars().count().max(4); // reserve " (9)"
        let restricted_basename: String = basename.chars().take(net_cleartext.saturating_sub(conflict_suffix_len)).collect();
        let dir_id = self.dir_id.as_bytes();
        let encrypt = |name: &str| self.cryptor().file_name_cryptor().encrypt_filename(name, &[dir_id]);
        let mut alternative_cleartext = format!("{restricted_basename}{conflict_suffix}{ext}");
        let mut alternative_ciphertext = encrypt(&alternative_cleartext);
        let mut alternative_path = canonical_path.with_file_name(format!("{alternative_ciphertext}{CRYPTOMATOR_FILE_SUFFIX}"));
        let mut i = 1;
        while i < 10 && std::fs::symlink_metadata(&alternative_path).is_ok() {
            alternative_cleartext = format!("{restricted_basename} ({i}){ext}");
            alternative_ciphertext = encrypt(&alternative_cleartext);
            alternative_path = canonical_path.with_file_name(format!("{alternative_ciphertext}{CRYPTOMATOR_FILE_SUFFIX}"));
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
        Ok(Some(DirEntry { cleartext_name: alternative_cleartext, ciphertext_path: alternative_path, extracted_ciphertext: alternative_ciphertext }))
    }

    /// `C9sInflator.process`: undecryptable or uninflatable `.c9s` nodes are skipped.
    fn process_c9s(&self, path: PathBuf) -> Option<DirEntry> {
        let c9r_name = inflate(&path).ok()?;
        let extracted = c9r_name.strip_suffix(CRYPTOMATOR_FILE_SUFFIX).unwrap_or(&c9r_name).to_string();
        let cleartext_name = self.cryptor().file_name_cryptor().decrypt_filename(&extracted, &[self.dir_id.as_bytes()]).ok()?;
        Some(DirEntry { cleartext_name, ciphertext_path: path, extracted_ciphertext: extracted })
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
```

- [ ] **Step 3: Tests**

Run: `cargo test -p cryptomator-core fs::dir_stream`
Expected: PASS (8 tests)

- [ ] **Step 4: Gate + Commit** ("Add directory listing with conflict resolution")


---

### Task 6: `OpenCryptoFile` with chunk cache

**Files:**
- Create: `crates/cryptomator-core/src/fs/open_file.rs`
- Modify: `crates/cryptomator-core/src/fs/mod.rs`, `crates/cryptomator-core/src/crypto/stream.rs` (if `read_fully_at` is shared – optional)

**Interfaces:**
- Consumes: `Cryptor`, `FileHeader`, `Rng`, `CryptoFsStats`, `EventSink`.
- Produces: `OpenOptions { read, write, create, create_new, truncate }` with `::read_only()`, `::write_new()`, `::write_truncate()`, `::read_write()`, `normalized()`; `open_file::MAX_CACHED_CLEARTEXT_CHUNKS = 5`; `OpenCryptoFile::{open(cryptor: Arc<Cryptor>, rng: Box<dyn Rng + Send>, stats: Arc<CryptoFsStats>, events: EventSink, path: &Path, options: OpenOptions) -> io::Result<Self>, path() -> Option<&Path>, set_path(Option<PathBuf>), is_writable(), reopen_writable() -> io::Result<()>, size() -> u64, read_at(&mut self, &mut [u8], u64) -> io::Result<usize>, write_at(&mut self, &[u8], u64) -> io::Result<usize>, truncate(&mut self, u64) -> io::Result<()>, flush(&mut self) -> io::Result<()>, sync(&mut self, metadata: bool) -> io::Result<()>, last_modified() -> Option<SystemTime>, set_last_modified(SystemTime), persist_last_modified() -> io::Result<()>, handles() -> usize, retain(), release() -> usize}`.

- [ ] **Step 1: Failing tests** (end of `open_file.rs`)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rng::DetRng;
    use crate::crypto::stream::{decrypt_all, encrypt_all};
    use crate::fs::{discard_events, testutil};
    use crate::{CipherCombo, Cryptor};
    use proptest::prelude::*;

    fn cryptor(combo: CipherCombo) -> Arc<Cryptor> {
        Arc::new(Cryptor::new(combo, &testutil::masterkey()))
    }

    fn open(cryptor: &Arc<Cryptor>, path: &Path, options: OpenOptions) -> io::Result<OpenCryptoFile> {
        OpenCryptoFile::open(cryptor.clone(), Box::new(DetRng::default()), Arc::new(CryptoFsStats::default()), discard_events(), path, options)
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 7) as u8).collect()
    }

    #[test]
    fn reads_java_written_files_at_arbitrary_offsets() {
        let (dir, cryptor, _) = testutil::new_vault(220);
        let data = pattern(100_000);
        let path = dir.path().join("f");
        std::fs::write(&path, encrypt_all(&cryptor, &mut DetRng::default(), &data).unwrap()).unwrap();
        let mut f = open(&cryptor, &path, OpenOptions::read_only()).unwrap();
        assert_eq!(f.size(), 100_000);
        for (pos, len) in [(0, 10), (32_760, 20), (65_535, 2), (99_990, 100), (100_000, 5), (200_000, 1)] {
            let mut buf = vec![0u8; len];
            let n = f.read_at(&mut buf, pos).unwrap();
            let expected_len = (100_000u64.saturating_sub(pos) as usize).min(len);
            assert_eq!(n, expected_len, "pos {pos}");
            assert_eq!(&buf[..n], &data[pos as usize..pos as usize + n]);
        }
        assert!(f.write_at(b"x", 0).is_err(), "read-only handle");
    }

    #[test]
    fn empty_file_is_header_only_and_reads_as_empty() {
        let (dir, cryptor, _) = testutil::new_vault(220);
        let path = dir.path().join("empty");
        let mut f = open(&cryptor, &path, OpenOptions::write_new()).unwrap();
        f.flush().unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), cryptor.file_header_cryptor().header_size() as u64);
        drop(f);
        let f = open(&cryptor, &path, OpenOptions::read_only()).unwrap();
        assert_eq!(f.size(), 0);
        // Java writes header + empty chunk via streams; that file has cleartext size 0 too
        std::fs::write(&path, encrypt_all(&cryptor, &mut DetRng::default(), b"").unwrap()).unwrap();
        let f = open(&cryptor, &path, OpenOptions::read_only()).unwrap();
        assert_eq!(f.size(), 0);
    }

    #[test]
    fn writes_across_chunks_gaps_and_truncates_like_java() {
        for combo in [CipherCombo::SivGcm, CipherCombo::SivCtrMac] {
            let dir = tempfile::tempdir().unwrap();
            let cryptor = cryptor(combo);
            let path = dir.path().join("f");
            let mut f = open(&cryptor, &path, OpenOptions::write_new()).unwrap();
            let data = pattern(70_000);
            assert_eq!(f.write_at(&data[..40_000], 0).unwrap(), 40_000);
            assert_eq!(f.write_at(&data[40_000..], 40_000).unwrap(), 30_000);
            assert_eq!(f.size(), 70_000);
            // overwrite in the middle of chunk 1
            f.write_at(&[0xFF; 100], 33_000).unwrap();
            // gap: zero fill between EOF and the new position
            assert_eq!(f.write_at(b"tail", 80_000).unwrap(), 4);
            assert_eq!(f.size(), 80_004);
            f.flush().unwrap();
            let mut expected = data.clone();
            expected[33_000..33_100].copy_from_slice(&[0xFF; 100]);
            expected.resize(80_000, 0);
            expected.extend_from_slice(b"tail");
            assert_eq!(decrypt_all(&cryptor, &std::fs::read(&path).unwrap()).unwrap(), expected);
            let ciphertext_len = cryptor.file_header_cryptor().header_size() as u64 + cryptor.file_content_cryptor().ciphertext_size(80_004);
            assert_eq!(std::fs::metadata(&path).unwrap().len(), ciphertext_len);
            // truncate inside chunk 1, then to a chunk boundary, then to 0
            f.truncate(33_050).unwrap();
            assert_eq!(f.size(), 33_050);
            expected.truncate(33_050);
            assert_eq!(decrypt_all(&cryptor, &std::fs::read(&path).unwrap()).unwrap(), expected);
            f.truncate(32_768).unwrap();
            expected.truncate(32_768);
            assert_eq!(decrypt_all(&cryptor, &std::fs::read(&path).unwrap()).unwrap(), expected);
            f.truncate(0).unwrap();
            assert_eq!(std::fs::metadata(&path).unwrap().len(), cryptor.file_header_cryptor().header_size() as u64);
            // growing again after truncate to 0 reuses the header (no size 0 file)
            f.write_at(b"again", 0).unwrap();
            f.flush().unwrap();
            assert_eq!(decrypt_all(&cryptor, &std::fs::read(&path).unwrap()).unwrap(), b"again");
        }
    }

    #[test]
    fn cache_evicts_least_recently_used_and_saves_dirty_chunks() {
        let (dir, cryptor, _) = testutil::new_vault(220);
        let path = dir.path().join("f");
        let mut f = open(&cryptor, &path, OpenOptions::write_new()).unwrap();
        let chunk = cryptor.file_content_cryptor().cleartext_chunk_size();
        let data = pattern(chunk * 8 + 5);
        // write chunk by chunk, out of order: more than MAX_CACHED chunks are dirty at once
        for i in (0..9).rev() {
            let start = i * chunk;
            let end = (start + chunk).min(data.len());
            f.write_at(&data[start..end], start as u64).unwrap();
        }
        assert!(f.chunks.len() <= MAX_CACHED_CLEARTEXT_CHUNKS);
        let stats = f.stats.snapshot();
        assert!(stats.bytes_encrypted > 0, "evictions wrote chunks before flush");
        f.flush().unwrap();
        assert_eq!(decrypt_all(&cryptor, &std::fs::read(&path).unwrap()).unwrap(), data);
        assert_eq!(f.stats.snapshot().bytes_written, data.len() as u64);
    }

    #[test]
    fn open_options_semantics() {
        let (dir, cryptor, _) = testutil::new_vault(220);
        let path = dir.path().join("f");
        assert_eq!(open(&cryptor, &path, OpenOptions::read_only()).unwrap_err().kind(), io::ErrorKind::NotFound);
        let mut f = open(&cryptor, &path, OpenOptions::write_new()).unwrap();
        f.write_at(b"hello", 0).unwrap();
        f.flush().unwrap();
        drop(f);
        assert_eq!(open(&cryptor, &path, OpenOptions::write_new()).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        let f = open(&cryptor, &path, OpenOptions::read_write()).unwrap();
        assert_eq!(f.size(), 5);
        drop(f);
        let mut f = open(&cryptor, &path, OpenOptions::write_truncate()).unwrap();
        assert_eq!(f.size(), 0);
        f.write_at(b"x", 0).unwrap();
        f.flush().unwrap();
        drop(f);
        assert_eq!(decrypt_all(&cryptor, &std::fs::read(&path).unwrap()).unwrap(), b"x");
        // a file with a garbage header cannot be opened for reading
        std::fs::write(&path, vec![0u8; 200]).unwrap();
        assert_eq!(open(&cryptor, &path, OpenOptions::read_only()).unwrap_err().kind(), io::ErrorKind::InvalidData);
        // truncated header
        std::fs::write(&path, vec![0u8; 10]).unwrap();
        assert!(open(&cryptor, &path, OpenOptions::read_only()).is_err());
    }

    #[derive(Debug, Clone)]
    enum Op {
        Write { pos: u64, len: usize },
        Truncate(u64),
    }

    fn ops() -> impl Strategy<Value = Vec<Op>> {
        prop::collection::vec(
            prop_oneof![
                (0u64..120_000, 1usize..40_000).prop_map(|(pos, len)| Op::Write { pos, len }),
                (0u64..120_000).prop_map(Op::Truncate),
            ],
            1..12,
        )
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(24))]
        #[test]
        fn random_writes_and_truncates_match_an_in_memory_model(ops in ops()) {
            let dir = tempfile::tempdir().unwrap();
            let cryptor = cryptor(CipherCombo::SivGcm);
            let path = dir.path().join("f");
            let mut f = open(&cryptor, &path, OpenOptions::write_new()).unwrap();
            let mut model: Vec<u8> = Vec::new();
            for (i, op) in ops.iter().enumerate() {
                match *op {
                    Op::Write { pos, len } => {
                        let data: Vec<u8> = (0..len).map(|j| (i * 31 + j) as u8).collect();
                        prop_assert_eq!(f.write_at(&data, pos).unwrap(), len);
                        let end = pos as usize + len;
                        if model.len() < end { model.resize(end, 0); }
                        model[pos as usize..end].copy_from_slice(&data);
                    }
                    Op::Truncate(size) => {
                        f.truncate(size).unwrap();
                        model.truncate(size as usize);
                    }
                }
                prop_assert_eq!(f.size(), model.len() as u64);
                let mut buf = vec![0u8; model.len()];
                let n = f.read_at(&mut buf, 0).unwrap();
                prop_assert_eq!(&buf[..n], &model[..]);
            }
            f.flush().unwrap();
            prop_assert_eq!(decrypt_all(&cryptor, &std::fs::read(&path).unwrap()).unwrap(), model);
        }
    }
}
```

- [ ] **Step 2: Implementation `fs/open_file.rs`**

```rust
//! One open ciphertext file (`fh/OpenCryptoFile`, `fh/ChunkCache`, `fh/ChunkLoader`, `fh/ChunkSaver`,
//! `ch/CleartextFileChannel`): positional cleartext reads/writes over a cache of at most five
//! decrypted chunks. Not thread-safe by itself; `OpenCryptoFiles` wraps it in a `Mutex`.
use super::events::{EventSink, FilesystemEvent};
use super::stats::CryptoFsStats;
use crate::crypto::header::FileHeader;
use crate::crypto::rng::Rng;
use crate::Cryptor;
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
use zeroize::Zeroizing;

pub const MAX_CACHED_CLEARTEXT_CHUNKS: usize = 5;

/// `EffectiveOpenOptions` (subset: no APPEND/DSYNC/DELETE_ON_CLOSE – positional API).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OpenOptions {
    pub read: bool,
    pub write: bool,
    pub create: bool,
    pub create_new: bool,
    pub truncate: bool,
}

impl OpenOptions {
    pub fn read_only() -> Self {
        Self { read: true, ..Self::default() }
    }
    pub fn read_write() -> Self {
        Self { read: true, write: true, ..Self::default() }
    }
    pub fn write_new() -> Self {
        Self { write: true, create_new: true, ..Self::default() }
    }
    pub fn write_truncate() -> Self {
        Self { write: true, create: true, truncate: true, ..Self::default() }
    }
    /// `EffectiveOpenOptions.cleanAndValidate`: no WRITE ⇒ READ and no create/truncate; CREATE_NEW wins over CREATE.
    pub fn normalized(mut self) -> Self {
        if !self.write {
            self.read = true;
            self.create = false;
            self.create_new = false;
            self.truncate = false;
        }
        if self.create_new {
            self.create = false;
        }
        self
    }
}

struct Chunk {
    data: Zeroizing<Vec<u8>>,
    dirty: bool,
}

/// LRU cache keyed by chunk index (`ChunkCache` with `MAX_CACHED_CLEARTEXT_CHUNKS`).
#[derive(Default)]
struct ChunkCache {
    chunks: HashMap<u64, Chunk>,
    lru: VecDeque<u64>, // front = least recently used
}

impl ChunkCache {
    fn len(&self) -> usize {
        self.chunks.len()
    }
    fn contains(&self, index: u64) -> bool {
        self.chunks.contains_key(&index)
    }
    fn touch(&mut self, index: u64) -> &mut Chunk {
        self.lru.retain(|i| *i != index);
        self.lru.push_back(index);
        self.chunks.get_mut(&index).expect("touched chunk is cached")
    }
    fn insert(&mut self, index: u64, chunk: Chunk) {
        self.lru.retain(|i| *i != index);
        self.lru.push_back(index);
        self.chunks.insert(index, chunk);
    }
    fn pop_lru(&mut self) -> Option<(u64, Chunk)> {
        let index = self.lru.pop_front()?;
        self.chunks.remove(&index).map(|c| (index, c))
    }
    fn get_mut(&mut self, index: u64) -> Option<&mut Chunk> {
        self.chunks.get_mut(&index)
    }
    fn indices(&self) -> Vec<u64> {
        let mut v: Vec<u64> = self.chunks.keys().copied().collect();
        v.sort_unstable();
        v
    }
    fn clear(&mut self) {
        self.chunks.clear();
        self.lru.clear();
    }
}

/// Zeroes followed by the caller's bytes (`ByteSource.repeatingZeroes(gap).followedBy(src)`).
struct ByteSource<'a> {
    zeroes: u64,
    src: &'a [u8],
}

impl ByteSource<'_> {
    fn remaining(&self) -> u64 {
        self.zeroes + self.src.len() as u64
    }
    fn copy_to(&mut self, dst: &mut [u8]) {
        let zeroes = (self.zeroes.min(dst.len() as u64)) as usize;
        dst[..zeroes].fill(0);
        self.zeroes -= zeroes as u64;
        let n = dst.len() - zeroes;
        dst[zeroes..].copy_from_slice(&self.src[..n]);
        self.src = &self.src[n..];
    }
}

pub struct OpenCryptoFile {
    cryptor: Arc<Cryptor>,
    rng: Box<dyn Rng + Send>,
    stats: Arc<CryptoFsStats>,
    events: EventSink,
    /// `None` once the file was deleted while open.
    path: Option<PathBuf>,
    file: File,
    writable: bool,
    header: FileHeader,
    encrypted_header: Vec<u8>,
    header_persisted: bool,
    size: u64,
    chunks: ChunkCache,
    last_modified: Option<SystemTime>,
    handles: usize,
}

impl std::fmt::Debug for OpenCryptoFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenCryptoFile").field("path", &self.path).field("size", &self.size).field("handles", &self.handles).finish_non_exhaustive()
    }
}

fn read_fully_at(file: &File, buf: &mut [u8], position: u64) -> io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match file.read_at(&mut buf[total..], position + total as u64) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

impl OpenCryptoFile {
    pub fn open(cryptor: Arc<Cryptor>, mut rng: Box<dyn Rng + Send>, stats: Arc<CryptoFsStats>, events: EventSink, path: &Path, options: OpenOptions) -> io::Result<Self> {
        let options = options.normalized();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(options.write)
            .create(options.create)
            .create_new(options.create_new)
            .open(path)?;
        let ciphertext_size = file.metadata()?.len();
        let header_cryptor = cryptor.file_header_cryptor();
        let (header, encrypted_header, header_persisted, last_modified) = if options.create_new || (options.create && ciphertext_size == 0) {
            // `FileHeaderHolder.createNew`: encrypt right away so the nonce is never reused
            let header = header_cryptor.create(&mut *rng);
            let encrypted = header_cryptor.encrypt_header(&header).map_err(|e| super::invalid_data(e.to_string()))?;
            (header, encrypted, false, Some(SystemTime::now()))
        } else {
            let mut buf = vec![0u8; header_cryptor.header_size()];
            let read = read_fully_at(&file, &mut buf, 0)?;
            if read != buf.len() {
                events(FilesystemEvent::DecryptionFailed { ciphertext_path: path.to_path_buf(), reason: "truncated file header".into() });
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, format!("Unable to read header of file {}", path.display())));
            }
            let header = header_cryptor.decrypt_header(&buf).map_err(|e| {
                events(FilesystemEvent::DecryptionFailed { ciphertext_path: path.to_path_buf(), reason: e.to_string() });
                super::invalid_data(format!("Unable to decrypt header of file {}: {e}", path.display()))
            })?;
            (header, buf, true, file.metadata().and_then(|m| m.modified()).ok())
        };
        let size = Self::initial_size(&cryptor, ciphertext_size);
        let mut this = Self {
            cryptor,
            rng,
            stats,
            events,
            path: Some(path.to_path_buf()),
            file,
            writable: options.write,
            header,
            encrypted_header,
            header_persisted,
            size,
            chunks: ChunkCache::default(),
            last_modified,
            handles: 1,
        };
        if options.truncate {
            this.truncate(0)?;
        }
        Ok(this)
    }

    /// `OpenCryptoFile.initFileSize`: an undefined ciphertext size counts as an empty file.
    fn initial_size(cryptor: &Cryptor, ciphertext_size: u64) -> u64 {
        if ciphertext_size == 0 {
            return 0;
        }
        let header = cryptor.file_header_cryptor().header_size() as u64;
        match ciphertext_size.checked_sub(header).map(|payload| cryptor.file_content_cryptor().cleartext_size(payload)) {
            Some(Ok(size)) => size,
            _ => 0, // "Invalid cipher text file size. Assuming empty file."
        }
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }
    pub fn set_path(&mut self, path: Option<PathBuf>) {
        self.path = path;
    }
    pub fn is_writable(&self) -> bool {
        self.writable
    }
    /// Re-opens the ciphertext with write access (a second, writable handle joined a read-only one).
    pub fn reopen_writable(&mut self) -> io::Result<()> {
        if self.writable {
            return Ok(());
        }
        let Some(path) = &self.path else {
            return Err(super::invalid_input("file was deleted"));
        };
        self.file = std::fs::OpenOptions::new().read(true).write(true).open(path)?;
        self.writable = true;
        Ok(())
    }
    pub fn size(&self) -> u64 {
        self.size
    }
    pub fn last_modified(&self) -> Option<SystemTime> {
        self.last_modified
    }
    pub fn set_last_modified(&mut self, time: SystemTime) {
        self.last_modified = Some(time);
    }
    pub fn handles(&self) -> usize {
        self.handles
    }
    pub fn retain(&mut self) {
        self.handles += 1;
    }
    /// Returns the remaining handle count.
    pub fn release(&mut self) -> usize {
        self.handles = self.handles.saturating_sub(1);
        self.handles
    }

    /// `CleartextFileChannel.readLocked`: returns 0 at or beyond EOF.
    pub fn read_at(&mut self, dst: &mut [u8], position: u64) -> io::Result<usize> {
        if position >= self.size {
            return Ok(0);
        }
        let limit = (self.size - position).min(dst.len() as u64) as usize;
        let chunk_size = self.cryptor.file_content_cryptor().cleartext_chunk_size() as u64;
        let mut read = 0usize;
        while read < limit {
            let pos = position + read as u64;
            let index = pos / chunk_size;
            let offset = (pos % chunk_size) as usize;
            let chunk = self.chunk(index)?;
            let available = chunk.data.len().saturating_sub(offset);
            if available == 0 {
                break; // inconsistent ciphertext: shorter than its size claims
            }
            let len = available.min(limit - read);
            dst[read..read + len].copy_from_slice(&chunk.data[offset..offset + len]);
            read += len;
        }
        self.stats.add_bytes_read(read as u64);
        Ok(read)
    }

    /// `CleartextFileChannel.writeLocked`: a position beyond EOF zero-fills the gap first.
    pub fn write_at(&mut self, src: &[u8], position: u64) -> io::Result<usize> {
        if !self.writable {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "file not opened for writing"));
        }
        let old_size = self.size;
        if position > old_size {
            let gap = position - old_size;
            let written = self.write_internal(ByteSource { zeroes: gap, src }, old_size)?;
            Ok((written - gap) as usize)
        } else {
            Ok(self.write_internal(ByteSource { zeroes: 0, src }, position)? as usize)
        }
    }

    fn write_internal(&mut self, mut src: ByteSource<'_>, position: u64) -> io::Result<u64> {
        self.write_header_if_needed()?;
        let chunk_size = self.cryptor.file_content_cryptor().cleartext_chunk_size();
        let mut written: u64 = 0;
        while src.remaining() > 0 {
            let current = position + written;
            let index = current / chunk_size as u64;
            let offset = (current % chunk_size as u64) as usize;
            let len = src.remaining().min((chunk_size - offset) as u64) as usize;
            if offset == 0 && len == chunk_size {
                // complete chunk: no need to load and decrypt it first
                let mut data = Zeroizing::new(vec![0u8; chunk_size]);
                src.copy_to(&mut data);
                self.put_chunk(index, Chunk { data, dirty: true })?;
            } else {
                let chunk = self.chunk(index)?;
                if chunk.data.len() < offset + len {
                    chunk.data.resize(offset + len, 0);
                }
                src.copy_to(&mut chunk.data[offset..offset + len]);
                chunk.dirty = true;
            }
            written += len as u64;
        }
        self.size = self.size.max(position + written);
        self.last_modified = Some(SystemTime::now());
        self.stats.add_bytes_written(written);
        Ok(written)
    }

    /// `CleartextFileChannel.truncateLocked`
    pub fn truncate(&mut self, new_size: u64) -> io::Result<()> {
        if !self.writable {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "file not opened for writing"));
        }
        if new_size >= self.size {
            return Ok(());
        }
        let chunk_size = self.cryptor.file_content_cryptor().cleartext_chunk_size() as u64;
        let size_of_incomplete_chunk = (new_size % chunk_size) as usize;
        if size_of_incomplete_chunk > 0 {
            let chunk = self.chunk(new_size / chunk_size)?;
            chunk.data.truncate(size_of_incomplete_chunk);
            chunk.dirty = true;
        }
        let ciphertext_size = self.cryptor.file_header_cryptor().header_size() as u64 + self.cryptor.file_content_cryptor().ciphertext_size(new_size);
        self.flush()?;
        self.chunks.clear(); // no chunk after new_size may be written during a later eviction
        self.file.set_len(ciphertext_size)?;
        self.size = new_size;
        self.last_modified = Some(SystemTime::now());
        Ok(())
    }

    /// Persists the header (if new) and every dirty chunk; a no-op for read-only files.
    pub fn flush(&mut self) -> io::Result<()> {
        if !self.writable {
            return Ok(());
        }
        self.write_header_if_needed()?;
        for index in self.chunks.indices() {
            if let Some(chunk) = self.chunks.get_mut(index) {
                if chunk.dirty {
                    encrypt_and_write(&self.cryptor, &mut *self.rng, &self.file, &self.header, &self.stats, index, &chunk.data)?;
                    chunk.dirty = false;
                }
            }
        }
        Ok(())
    }

    /// `force`: flush + fsync (+ mtime when `metadata`).
    pub fn sync(&mut self, metadata: bool) -> io::Result<()> {
        self.flush()?;
        if metadata {
            self.file.sync_all()?;
            self.persist_last_modified()
        } else {
            self.file.sync_data()
        }
    }

    /// `CleartextFileChannel.persistLastModified`: writes chunk by chunk changed the ciphertext's
    /// mtime; restore the cleartext one and touch atime.
    pub fn persist_last_modified(&mut self) -> io::Result<()> {
        let mut times = std::fs::FileTimes::new().set_accessed(SystemTime::now());
        if let (true, Some(modified)) = (self.writable, self.last_modified) {
            times = times.set_modified(modified);
        }
        self.file.set_times(times)
    }

    fn write_header_if_needed(&mut self) -> io::Result<()> {
        if !self.header_persisted {
            self.file.write_all_at(&self.encrypted_header, 0)?;
            self.header_persisted = true;
        }
        Ok(())
    }

    /// `ChunkCache.getChunk`
    fn chunk(&mut self, index: u64) -> io::Result<&mut Chunk> {
        self.stats.add_chunk_cache_access();
        if !self.chunks.contains(index) {
            self.stats.add_chunk_cache_miss();
            let data = self.load_chunk(index)?;
            self.put_chunk(index, Chunk { data, dirty: false })?;
        }
        Ok(self.chunks.touch(index))
    }

    /// `ChunkLoader.load`: beyond EOF the chunk is empty.
    fn load_chunk(&mut self, index: u64) -> io::Result<Zeroizing<Vec<u8>>> {
        let content = self.cryptor.file_content_cryptor();
        let ciphertext_chunk_size = content.ciphertext_chunk_size();
        let position = index * ciphertext_chunk_size as u64 + self.cryptor.file_header_cryptor().header_size() as u64;
        let mut buf = vec![0u8; ciphertext_chunk_size];
        let read = read_fully_at(&self.file, &mut buf, position)?;
        if read == 0 {
            return Ok(Zeroizing::new(Vec::new()));
        }
        let cleartext = content.decrypt_chunk(&buf[..read], index, &self.header).map_err(|e| {
            (self.events)(FilesystemEvent::DecryptionFailed { ciphertext_path: self.path.clone().unwrap_or_default(), reason: e.to_string() });
            super::invalid_data(format!("Unauthentic ciphertext in chunk {index}: {e}"))
        })?;
        self.stats.add_bytes_decrypted(cleartext.len() as u64);
        Ok(cleartext)
    }

    /// `ChunkCache.putChunk` + eviction: the least recently used chunk is saved before it leaves the cache.
    fn put_chunk(&mut self, index: u64, chunk: Chunk) -> io::Result<()> {
        if !self.chunks.contains(index) {
            while self.chunks.len() >= MAX_CACHED_CLEARTEXT_CHUNKS {
                let Some((evicted_index, evicted)) = self.chunks.pop_lru() else { break };
                if evicted.dirty {
                    encrypt_and_write(&self.cryptor, &mut *self.rng, &self.file, &self.header, &self.stats, evicted_index, &evicted.data)?;
                }
            }
        }
        self.chunks.insert(index, chunk);
        Ok(())
    }
}

/// `ChunkSaver.save`
fn encrypt_and_write(cryptor: &Cryptor, rng: &mut dyn Rng, file: &File, header: &FileHeader, stats: &CryptoFsStats, index: u64, cleartext: &[u8]) -> io::Result<()> {
    stats.add_bytes_encrypted(cleartext.len() as u64);
    let ciphertext = cryptor.file_content_cryptor().encrypt_chunk(cleartext, index, header, rng);
    let position = index * cryptor.file_content_cryptor().ciphertext_chunk_size() as u64 + cryptor.file_header_cryptor().header_size() as u64;
    file.write_all_at(&ciphertext, position)
}
```

Note: `Rng` must be `Send`-capable as a trait object – `OsRng` and `DetRng` already are; if the compiler rejects `dyn Rng + Send`, do **not** introduce `Rng: Send` as a supertrait, but leave the box types as they are (both implementations are `Send`).

- [ ] **Step 3: Tests**

Run: `cargo test -p cryptomator-core fs::open_file`
Expected: PASS (5 Tests + 1 proptest)

- [ ] **Step 4: Gate + Commit** ("Add OpenCryptoFile with LRU chunk cache")

---

### Task 7: Registry of open files and handles

**Files:**
- Create: `crates/cryptomator-core/src/fs/open_files.rs`
- Modify: `crates/cryptomator-core/src/fs/mod.rs`

**Interfaces:**
- Consumes: Task 6.
- Produces: `RngFactory = Arc<dyn Fn() -> Box<dyn Rng + Send> + Send + Sync>`; `OpenCryptoFiles::{new(cryptor: Arc<Cryptor>, stats: Arc<CryptoFsStats>, events: EventSink, rng_factory: RngFactory), get(&Path) -> Option<Arc<Mutex<OpenCryptoFile>>>, open(&Path, OpenOptions) -> io::Result<FileHandle>, delete(&Path), prepare_move(src: &Path, dst: &Path) -> io::Result<TwoPhaseMove>, close_all() -> io::Result<()>, len()}`; `FileHandle::{read_at, read_exact_at, write_at, write_all_at, truncate, size, flush, sync(bool), set_last_modified, close(self) -> io::Result<()>}` (Drop closes silently); `TwoPhaseMove::commit(self)` (Drop = rollback).

- [ ] **Step 1: Failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rng::DetRng;
    use crate::crypto::stream::decrypt_all;
    use crate::fs::{discard_events, testutil};

    fn registry(cryptor: Arc<Cryptor>) -> OpenCryptoFiles {
        OpenCryptoFiles::new(cryptor, Arc::new(CryptoFsStats::default()), discard_events(), Arc::new(|| Box::new(DetRng::default())))
    }

    #[test]
    fn handles_share_one_open_file_and_close_on_last_drop() {
        let (dir, cryptor, _) = testutil::new_vault(220);
        let files = registry(cryptor.clone());
        let path = dir.path().join("f");
        let a = files.open(&path, OpenOptions::write_new()).unwrap();
        a.write_all_at(b"hello world", 0).unwrap();
        let b = files.open(&path, OpenOptions::read_only()).unwrap();
        let mut buf = [0u8; 5];
        b.read_exact_at(&mut buf, 6).unwrap();
        assert_eq!(&buf, b"world");
        assert_eq!(files.len(), 1);
        assert!(Arc::ptr_eq(&a.file, &b.file));
        assert!(files.open(&path, OpenOptions::write_new()).is_err(), "CREATE_NEW on an open file");
        drop(a);
        assert_eq!(files.len(), 1, "still open through b");
        assert!(b.write_at(b"x", 0).is_err(), "read-only handle");
        b.close().unwrap();
        assert_eq!(files.len(), 0);
        assert_eq!(decrypt_all(&cryptor, &std::fs::read(&path).unwrap()).unwrap(), b"hello world");
    }

    #[test]
    fn a_writable_handle_upgrades_a_read_only_open_file() {
        let (dir, cryptor, _) = testutil::new_vault(220);
        let files = registry(cryptor.clone());
        let path = dir.path().join("f");
        files.open(&path, OpenOptions::write_new()).unwrap().close().unwrap();
        let r = files.open(&path, OpenOptions::read_only()).unwrap();
        let w = files.open(&path, OpenOptions::read_write()).unwrap();
        w.write_all_at(b"data", 0).unwrap();
        assert_eq!(r.size(), 4);
        drop(w);
        drop(r);
        assert_eq!(decrypt_all(&cryptor, &std::fs::read(&path).unwrap()).unwrap(), b"data");
    }

    #[test]
    fn two_phase_move_and_delete_update_open_files() {
        let (dir, cryptor, _) = testutil::new_vault(220);
        let files = registry(cryptor);
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        let h = files.open(&src, OpenOptions::write_new()).unwrap();
        {
            let m = files.prepare_move(&src, &dst).unwrap();
            assert!(files.get(&dst).is_some(), "reserved during the move");
            drop(m); // rollback
            assert!(files.get(&dst).is_none());
        }
        let m = files.prepare_move(&src, &dst).unwrap();
        std::fs::rename(&src, &dst).unwrap();
        m.commit();
        assert!(files.get(&src).is_none());
        assert_eq!(super::super::lock(&files.get(&dst).unwrap()).path(), Some(dst.as_path()));
        // moving onto an open destination is refused
        let other = dir.path().join("other");
        let _o = files.open(&other, OpenOptions::write_new()).unwrap();
        assert_eq!(files.prepare_move(&dst, &other).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        files.delete(&dst);
        assert!(files.get(&dst).is_none());
        assert_eq!(super::super::lock(&h.file).path(), None);
        h.close().unwrap();
        files.close_all().unwrap();
        assert_eq!(files.len(), 0);
    }
}
```

- [ ] **Step 2: Implementation `fs/open_files.rs`**

```rust
//! `fh/OpenCryptoFiles`: one `OpenCryptoFile` per (normalised) ciphertext path, shared by all
//! handles; the last handle flushes and closes it. `TwoPhaseMove` keeps entries consistent while a
//! ciphertext file is renamed.
use super::events::EventSink;
use super::open_file::{OpenCryptoFile, OpenOptions};
use super::stats::CryptoFsStats;
use crate::crypto::rng::Rng;
use crate::Cryptor;
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

pub type RngFactory = Arc<dyn Fn() -> Box<dyn Rng + Send> + Send + Sync>;
type Registry = Arc<Mutex<HashMap<PathBuf, Arc<Mutex<OpenCryptoFile>>>>>;

pub struct OpenCryptoFiles {
    cryptor: Arc<Cryptor>,
    stats: Arc<CryptoFsStats>,
    events: EventSink,
    rng_factory: RngFactory,
    files: Registry,
}

impl std::fmt::Debug for OpenCryptoFiles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenCryptoFiles").field("open", &self.len()).finish_non_exhaustive()
    }
}

fn normalize(path: &Path) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}

impl OpenCryptoFiles {
    pub fn new(cryptor: Arc<Cryptor>, stats: Arc<CryptoFsStats>, events: EventSink, rng_factory: RngFactory) -> Self {
        Self { cryptor, stats, events, rng_factory, files: Arc::new(Mutex::new(HashMap::new())) }
    }

    pub fn len(&self) -> usize {
        super::lock(&self.files).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The open file for a ciphertext path, if any (without opening it).
    pub fn get(&self, ciphertext_path: &Path) -> Option<Arc<Mutex<OpenCryptoFile>>> {
        super::lock(&self.files).get(&normalize(ciphertext_path)).cloned()
    }

    /// Lock order everywhere: registry map first, then the file.
    pub fn open(&self, ciphertext_path: &Path, options: OpenOptions) -> io::Result<FileHandle> {
        let options = options.normalized();
        let key = normalize(ciphertext_path);
        let mut files = super::lock(&self.files);
        let file = match files.get(&key) {
            Some(existing) => {
                if options.create_new {
                    return Err(super::already_exists(key.display()));
                }
                let mut open = super::lock(existing);
                if options.write {
                    open.reopen_writable()?;
                }
                if options.truncate {
                    open.truncate(0)?;
                }
                open.retain();
                existing.clone()
            }
            None => {
                let open = OpenCryptoFile::open(self.cryptor.clone(), (self.rng_factory)(), self.stats.clone(), self.events.clone(), &key, options)?;
                let arc = Arc::new(Mutex::new(open));
                files.insert(key, arc.clone());
                arc
            }
        };
        Ok(FileHandle { file, files: self.files.clone(), writable: options.write, released: false })
    }

    /// `OpenCryptoFiles.delete`: forgets the mapping and marks the open file as deleted.
    pub fn delete(&self, ciphertext_path: &Path) {
        if let Some(file) = super::lock(&self.files).remove(&normalize(ciphertext_path)) {
            super::lock(&file).set_path(None);
        }
    }

    /// Reserves `dst` and, after the physical rename, `commit()` re-keys an open `src`.
    pub fn prepare_move(&self, src: &Path, dst: &Path) -> io::Result<TwoPhaseMove> {
        let (src, dst) = (normalize(src), normalize(dst));
        let mut files = super::lock(&self.files);
        if files.contains_key(&dst) {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, format!("{}: destination file is currently open", dst.display())));
        }
        let moved = files.get(&src).cloned();
        if let Some(file) = &moved {
            files.insert(dst.clone(), file.clone());
        }
        Ok(TwoPhaseMove { files: self.files.clone(), src, dst, moved, committed: false })
    }

    /// Flushes and closes every open file (even if handles are still around).
    pub fn close_all(&self) -> io::Result<()> {
        let files: Vec<Arc<Mutex<OpenCryptoFile>>> = super::lock(&self.files).drain().map(|(_, f)| f).collect();
        let mut first_error = None;
        for file in files {
            if let Err(e) = super::lock(&file).flush() {
                first_error.get_or_insert(e);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

/// A cleartext view on a shared `OpenCryptoFile` (`CleartextFileChannel`).
pub struct FileHandle {
    file: Arc<Mutex<OpenCryptoFile>>,
    files: Registry,
    writable: bool,
    released: bool,
}

impl std::fmt::Debug for FileHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileHandle").field("writable", &self.writable).finish_non_exhaustive()
    }
}

impl FileHandle {
    pub fn is_writable(&self) -> bool {
        self.writable
    }
    pub fn size(&self) -> u64 {
        super::lock(&self.file).size()
    }
    pub fn read_at(&self, buf: &mut [u8], position: u64) -> io::Result<usize> {
        super::lock(&self.file).read_at(buf, position)
    }
    pub fn read_exact_at(&self, buf: &mut [u8], position: u64) -> io::Result<()> {
        let mut done = 0;
        while done < buf.len() {
            match self.read_at(&mut buf[done..], position + done as u64)? {
                0 => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "read past end of file")),
                n => done += n,
            }
        }
        Ok(())
    }
    pub fn write_at(&self, data: &[u8], position: u64) -> io::Result<usize> {
        if !self.writable {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "handle not opened for writing"));
        }
        super::lock(&self.file).write_at(data, position)
    }
    pub fn write_all_at(&self, data: &[u8], position: u64) -> io::Result<()> {
        let mut done = 0;
        while done < data.len() {
            done += self.write_at(&data[done..], position + done as u64)?;
        }
        Ok(())
    }
    pub fn truncate(&self, size: u64) -> io::Result<()> {
        if !self.writable {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "handle not opened for writing"));
        }
        super::lock(&self.file).truncate(size)
    }
    pub fn flush(&self) -> io::Result<()> {
        super::lock(&self.file).flush()
    }
    pub fn sync(&self, metadata: bool) -> io::Result<()> {
        super::lock(&self.file).sync(metadata)
    }
    pub fn set_last_modified(&self, time: SystemTime) {
        super::lock(&self.file).set_last_modified(time)
    }

    /// Flushes; when this was the last handle the file leaves the registry and its mtime is restored.
    pub fn close(mut self) -> io::Result<()> {
        self.release()
    }

    fn release(&mut self) -> io::Result<()> {
        if self.released {
            return Ok(());
        }
        self.released = true;
        let mut files = super::lock(&self.files);
        let mut file = super::lock(&self.file);
        let result = file.flush();
        if file.release() == 0 {
            files.retain(|_, f| !Arc::ptr_eq(f, &self.file));
            let mtime = file.persist_last_modified();
            // a deleted file has no mtime to restore
            if let Err(e) = mtime {
                if e.kind() != io::ErrorKind::NotFound && result.is_ok() {
                    return Err(e);
                }
            }
        }
        result
    }
}

impl Drop for FileHandle {
    fn drop(&mut self) {
        let _ = self.release(); // errors are reported by an explicit close()
    }
}

pub struct TwoPhaseMove {
    files: Registry,
    src: PathBuf,
    dst: PathBuf,
    moved: Option<Arc<Mutex<OpenCryptoFile>>>,
    committed: bool,
}

impl std::fmt::Debug for TwoPhaseMove {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TwoPhaseMove").field("src", &self.src).field("dst", &self.dst).finish_non_exhaustive()
    }
}

impl TwoPhaseMove {
    pub fn commit(mut self) {
        let mut files = super::lock(&self.files);
        if let Some(file) = &self.moved {
            super::lock(file).set_path(Some(self.dst.clone()));
            files.remove(&self.src);
        }
        self.committed = true;
    }
}

impl Drop for TwoPhaseMove {
    fn drop(&mut self) {
        if !self.committed {
            if let Some(file) = &self.moved {
                let mut files = super::lock(&self.files);
                if files.get(&self.dst).is_some_and(|f| Arc::ptr_eq(f, file)) {
                    files.remove(&self.dst);
                }
            }
        }
    }
}
```

For test access to `FileHandle.file` (`Arc::ptr_eq`), make the field `pub(crate)`.

- [ ] **Step 3: Tests**

Run: `cargo test -p cryptomator-core fs::open_files`
Expected: PASS (3 tests)

- [ ] **Step 4: Gate + Commit** ("Add open file registry with shared handles and two-phase move")

---

### Task 8: Symlinks and attributes

**Files:**
- Create: `crates/cryptomator-core/src/fs/symlinks.rs`, `crates/cryptomator-core/src/fs/attrs.rs`
- Modify: `crates/cryptomator-core/src/fs/mod.rs`

**Interfaces:**
- Consumes: Task 4, 7.
- Produces: `Symlinks::{new(mapper: Arc<CryptoPathMapper>, open_files: Arc<OpenCryptoFiles>, read_only: bool), create_symbolic_link(&CleartextPath, target: &str) -> io::Result<()>, read_symbolic_link(&CleartextPath) -> io::Result<String>, resolve_recursively(&CleartextPath) -> io::Result<CleartextPath>}`; `FileAttributes { file_type: CiphertextFileType, size: u64, modified: Option<SystemTime>, accessed: Option<SystemTime>, created: Option<SystemTime>, mode: u32, uid: u32, gid: u32, nlink: u64 }` + `is_dir/is_file/is_symlink`; `attrs::attributes_of(ciphertext_path: &Path, file_type, cryptor: &Cryptor, open_file: Option<Arc<Mutex<OpenCryptoFile>>>, read_only: bool) -> io::Result<FileAttributes>`.

- [ ] **Step 1: Failing tests** (in `symlinks.rs`; `attrs.rs` is tested against fixtures via Task 9, here only one unit test)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rng::DetRng;
    use crate::fs::dir_id::DirIdLoader;
    use crate::fs::{discard_events, testutil, CryptoFsStats};

    fn symlinks(read_only: bool) -> (tempfile::TempDir, Symlinks) {
        let (dir, cryptor, config) = testutil::new_vault(220);
        let mapper = Arc::new(CryptoPathMapper::new(dir.path(), cryptor.clone(), Arc::new(DirIdLoader::new(discard_events())), config.shortening_threshold, discard_events()));
        let files = Arc::new(OpenCryptoFiles::new(cryptor, Arc::new(CryptoFsStats::default()), discard_events(), Arc::new(|| Box::new(DetRng::default()))));
        (dir, Symlinks::new(mapper, files, read_only))
    }

    #[test]
    fn create_read_and_resolve() {
        let (_dir, s) = symlinks(false);
        let link = CleartextPath::parse("/link");
        s.create_symbolic_link(&link, "target.txt").unwrap();
        assert_eq!(s.read_symbolic_link(&link).unwrap(), "target.txt");
        assert_eq!(s.mapper.ciphertext_file_type(&link).unwrap(), CiphertextFileType::Symlink);
        assert_eq!(s.create_symbolic_link(&link, "x").unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        // relative targets resolve against the link's parent; the target need not exist
        assert_eq!(s.resolve_recursively(&link).unwrap().to_string(), "/target.txt");
        s.create_symbolic_link(&CleartextPath::parse("/abs"), "/link").unwrap();
        assert_eq!(s.resolve_recursively(&CleartextPath::parse("/abs")).unwrap().to_string(), "/target.txt");
        // non-links resolve to themselves; missing paths too
        assert_eq!(s.resolve_recursively(&CleartextPath::parse("/nope")).unwrap().to_string(), "/nope");
        assert_eq!(s.read_symbolic_link(&CleartextPath::parse("/nope")).unwrap_err().kind(), io::ErrorKind::NotFound);
        let long = "x".repeat(200);
        s.create_symbolic_link(&CleartextPath::root().join(&long).unwrap(), "t").unwrap();
        assert_eq!(s.read_symbolic_link(&CleartextPath::root().join(&long).unwrap()).unwrap(), "t");
    }

    #[test]
    fn loops_and_limits() {
        let (_dir, s) = symlinks(false);
        s.create_symbolic_link(&CleartextPath::parse("/a"), "b").unwrap();
        s.create_symbolic_link(&CleartextPath::parse("/b"), "a").unwrap();
        assert!(s.resolve_recursively(&CleartextPath::parse("/a")).is_err());
        assert_eq!(s.create_symbolic_link(&CleartextPath::parse("/c"), &"y".repeat(32_768)).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        let (_dir, ro) = symlinks(true);
        assert_eq!(ro.create_symbolic_link(&CleartextPath::parse("/d"), "e").unwrap_err().kind(), io::ErrorKind::ReadOnlyFilesystem);
    }

    #[test]
    fn a_file_is_not_a_link() {
        let (_dir, s) = symlinks(false);
        let p = CleartextPath::parse("/f");
        let node = s.mapper.ciphertext_file_path(&p).unwrap();
        std::fs::write(node.raw_path(), b"not a node dir").unwrap();
        assert_eq!(s.read_symbolic_link(&p).unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }
}
```

- [ ] **Step 2: Implementation `fs/symlinks.rs`**

```rust
//! `Symlinks`: a symlink is a node directory holding `symlink.c9r`, an encrypted file whose
//! cleartext is the target string.
use super::ciphertext_path::CiphertextFileType;
use super::open_file::OpenOptions;
use super::open_files::OpenCryptoFiles;
use super::path::CleartextPath;
use super::path_mapper::CryptoPathMapper;
use crate::constants::MAX_SYMLINK_LENGTH;
use std::collections::HashSet;
use std::io;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug)]
pub struct Symlinks {
    pub(crate) mapper: Arc<CryptoPathMapper>,
    open_files: Arc<OpenCryptoFiles>,
    read_only: bool,
}

impl Symlinks {
    pub fn new(mapper: Arc<CryptoPathMapper>, open_files: Arc<OpenCryptoFiles>, read_only: bool) -> Self {
        Self { mapper, open_files, read_only }
    }

    pub fn create_symbolic_link(&self, cleartext: &CleartextPath, target: &str) -> io::Result<()> {
        if self.read_only {
            return Err(super::read_only_fs());
        }
        self.mapper.assert_non_existing(cleartext)?;
        if target.chars().count() > MAX_SYMLINK_LENGTH {
            return Err(super::invalid_input("path length limit exceeded."));
        }
        let ciphertext = self.mapper.ciphertext_file_path(cleartext)?;
        std::fs::create_dir(ciphertext.raw_path())?;
        let handle = self.open_files.open(&ciphertext.symlink_file_path(), OpenOptions::write_new())?;
        handle.write_all_at(target.as_bytes(), 0)?;
        handle.close()?;
        ciphertext.persist_long_file_name()
    }

    pub fn read_symbolic_link(&self, cleartext: &CleartextPath) -> io::Result<String> {
        let symlink_file = self.mapper.ciphertext_file_path(cleartext)?.symlink_file_path();
        assert_is_symlink(cleartext, &symlink_file)?;
        let handle = self.open_files.open(&symlink_file, OpenOptions::read_only())?;
        let size = handle.size();
        if size > MAX_SYMLINK_LENGTH as u64 {
            return Err(super::not_a_link(cleartext, "unreasonably large symlink file"));
        }
        let mut buf = vec![0u8; size as usize];
        handle.read_exact_at(&mut buf, 0)?;
        handle.close()?;
        String::from_utf8(buf).map_err(|_| super::invalid_data(format!("{cleartext}: symlink target is not UTF-8")))
    }

    /// Follows a chain of links to the final path (which need not exist). Relative targets are
    /// resolved against the link's parent directory (POSIX; cryptofs resolves them against the
    /// root, which its FUSE adapters never rely on).
    pub fn resolve_recursively(&self, cleartext: &CleartextPath) -> io::Result<CleartextPath> {
        let mut visited: HashSet<CleartextPath> = HashSet::new();
        let mut current = cleartext.clone();
        loop {
            let file_type = match self.mapper.ciphertext_file_type(&current) {
                Ok(t) => t,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(current), // cannot be a link
                Err(e) => return Err(e),
            };
            if file_type != CiphertextFileType::Symlink {
                return Ok(current);
            }
            if !visited.insert(current.clone()) {
                return Err(super::fs_loop(cleartext));
            }
            let target = self.read_symbolic_link(&current)?;
            let base = current.parent().unwrap_or_else(CleartextPath::root);
            current = base.join_path(&target);
        }
    }
}

/// `Symlinks.assertIsSymlink`: `NotFound` if the node directory is missing, "not a link" otherwise.
fn assert_is_symlink(cleartext: &CleartextPath, symlink_file: &Path) -> io::Result<()> {
    let parent = symlink_file.parent().ok_or_else(|| super::not_a_link(cleartext, "no node directory"))?;
    let parent_attr = std::fs::symlink_metadata(parent).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound { super::not_found(cleartext) } else { e }
    })?;
    if !parent_attr.is_dir() {
        return Err(super::not_a_link(cleartext, "file exists but is not a symlink"));
    }
    match std::fs::symlink_metadata(symlink_file) {
        Ok(attr) if attr.is_file() => Ok(()),
        _ => Err(super::not_a_link(cleartext, "file exists but is not a symlink")),
    }
}
```

`fs/attrs.rs`:

```rust
//! `attr/CryptoBasicFileAttributes` + `CryptoPosixFileAttributes`: ciphertext metadata with the
//! cleartext size; an open file overrides size and mtime.
use super::ciphertext_path::CiphertextFileType;
use super::open_file::OpenCryptoFile;
use crate::Cryptor;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileAttributes {
    pub file_type: CiphertextFileType,
    pub size: u64,
    pub modified: Option<SystemTime>,
    pub accessed: Option<SystemTime>,
    pub created: Option<SystemTime>,
    /// Unix permission bits of the ciphertext node (write bits cleared for read-only vaults).
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u64,
}

impl FileAttributes {
    pub fn is_dir(&self) -> bool {
        self.file_type == CiphertextFileType::Directory
    }
    pub fn is_file(&self) -> bool {
        self.file_type == CiphertextFileType::File
    }
    pub fn is_symlink(&self) -> bool {
        self.file_type == CiphertextFileType::Symlink
    }
}

/// `CryptoBasicFileAttributes.calculatePlaintextFileSize`: undefined sizes count as 0.
pub(crate) fn cleartext_size_of(cryptor: &Cryptor, ciphertext_size: u64) -> u64 {
    ciphertext_size
        .checked_sub(cryptor.file_header_cryptor().header_size() as u64)
        .and_then(|payload| cryptor.file_content_cryptor().cleartext_size(payload).ok())
        .unwrap_or(0)
}

pub(crate) fn attributes_of(ciphertext_path: &Path, file_type: CiphertextFileType, cryptor: &Cryptor, open_file: Option<Arc<Mutex<OpenCryptoFile>>>, read_only: bool) -> io::Result<FileAttributes> {
    let meta = std::fs::metadata(ciphertext_path)?;
    let open = open_file.map(|f| {
        let f = super::lock(&f);
        (f.size(), f.last_modified())
    });
    let size = match file_type {
        CiphertextFileType::Directory => meta.len(),
        CiphertextFileType::File | CiphertextFileType::Symlink => open.map(|(size, _)| size).unwrap_or_else(|| cleartext_size_of(cryptor, meta.len())),
    };
    let modified = match open {
        Some((_, Some(modified))) => Some(modified),
        _ => meta.modified().ok(),
    };
    let accessed = if open.is_some() { Some(SystemTime::now()) } else { meta.accessed().ok() };
    let mut mode = meta.mode() & 0o7777;
    if read_only {
        mode &= !0o222;
    }
    Ok(FileAttributes { file_type, size, modified, accessed, created: meta.created().ok(), mode, uid: meta.uid(), gid: meta.gid(), nlink: meta.nlink() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rng::DetRng;
    use crate::crypto::stream::encrypt_all;
    use crate::fs::testutil;

    #[test]
    fn file_size_is_the_cleartext_size_and_read_only_strips_write_bits() {
        let (dir, cryptor, _) = testutil::new_vault(220);
        let path = dir.path().join("f");
        std::fs::write(&path, encrypt_all(&cryptor, &mut DetRng::default(), &[1u8; 40_000]).unwrap()).unwrap();
        let attrs = attributes_of(&path, CiphertextFileType::File, &cryptor, None, false).unwrap();
        assert_eq!(attrs.size, 40_000);
        assert!(attrs.is_file());
        assert_ne!(attrs.mode & 0o200, 0);
        let ro = attributes_of(&path, CiphertextFileType::File, &cryptor, None, true).unwrap();
        assert_eq!(ro.mode & 0o222, 0);
        std::fs::write(&path, b"garbage").unwrap();
        assert_eq!(attributes_of(&path, CiphertextFileType::File, &cryptor, None, false).unwrap().size, 0);
        let d = attributes_of(dir.path(), CiphertextFileType::Directory, &cryptor, None, false).unwrap();
        assert!(d.is_dir());
    }
}
```

- [ ] **Step 3: Tests**

Run: `cargo test -p cryptomator-core fs::symlinks fs::attrs`
Expected: PASS (4 tests)

- [ ] **Step 4: Gate + Commit** ("Add symlink handling and file attributes")

---

### Task 9: `CryptoFs` facade (reading, creating directories and files) + fixture integration test

**Files:**
- Create: `crates/cryptomator-core/src/fs/crypto_fs.rs`, `crates/cryptomator-core/tests/crypto_fs_fixtures.rs`
- Modify: `crates/cryptomator-core/src/fs/mod.rs`, `crates/cryptomator-core/src/lib.rs`

**Interfaces:**
- Consumes: Tasks 1–8, `OpenedVault`, `VaultConfig`.
- Produces: `DEFAULT_MAX_CLEARTEXT_NAME_LENGTH = 10 * 1024`; `CryptoFsOptions { read_only: bool, max_cleartext_name_length: usize, events: EventSink }` (`Default`, manual `Debug`); `CryptoFs::{open(OpenedVault, CryptoFsOptions) -> Self, with_rng(OpenedVault, CryptoFsOptions, rng: Box<dyn Rng + Send>, rng_factory: RngFactory) -> Self, vault_path(), config(), is_read_only(), stats() -> &CryptoFsStats, mapper() -> &CryptoPathMapper, read_dir(&CleartextPath) -> io::Result<Vec<DirEntry>>, metadata(&CleartextPath) -> io::Result<FileAttributes>, symlink_metadata(&CleartextPath), ciphertext_path(&CleartextPath) -> io::Result<PathBuf>, open_file(&CleartextPath, OpenOptions) -> io::Result<FileHandle>, read_file(&CleartextPath) -> io::Result<Vec<u8>>, write_file(&CleartextPath, &[u8], overwrite: bool) -> io::Result<()>, copy_to_writer(&CleartextPath, &mut dyn Write) -> io::Result<u64>, write_from_reader(&CleartextPath, &mut dyn Read, overwrite: bool) -> io::Result<u64>, create_dir(&CleartextPath) -> io::Result<()>, create_dir_all(&CleartextPath) -> io::Result<()>, create_symlink(&CleartextPath, target: &str) -> io::Result<()>, read_link(&CleartextPath) -> io::Result<String>, close(self) -> io::Result<()>}`.

- [ ] **Step 1: Failing integration test `tests/crypto_fs_fixtures.rs`**

```rust
//! Every Java fixture, walked through the `CryptoFs` facade, equals its `expected.json`.
mod common;

use common::{expected_entries, open_fixture, ExpectedEntry, FIXTURE_NAMES};
use cryptomator_core::fs::{CleartextPath, CryptoFs, CryptoFsOptions};
use data_encoding::HEXLOWER;
use sha2::{Digest, Sha256};

fn walk(fs: &CryptoFs, dir: &CleartextPath, out: &mut Vec<ExpectedEntry>) {
    for entry in fs.read_dir(dir).unwrap() {
        let path = dir.join(&entry.cleartext_name).unwrap();
        let attrs = fs.symlink_metadata(&path).unwrap();
        if attrs.is_symlink() {
            out.push(ExpectedEntry { path: path.to_string(), kind: "symlink".into(), size: None, sha256: None, target: Some(fs.read_link(&path).unwrap()) });
        } else if attrs.is_dir() {
            out.push(ExpectedEntry { path: path.to_string(), kind: "dir".into(), size: None, sha256: None, target: None });
            walk(fs, &path, out);
        } else {
            let data = fs.read_file(&path).unwrap();
            assert_eq!(attrs.size, data.len() as u64, "{path}: metadata size");
            out.push(ExpectedEntry { path: path.to_string(), kind: "file".into(), size: Some(data.len() as u64), sha256: Some(HEXLOWER.encode(&Sha256::digest(&data))), target: None });
        }
    }
}

#[test]
fn every_fixture_reads_through_crypto_fs() {
    for name in FIXTURE_NAMES {
        let (dir, opened) = open_fixture(name);
        let fs = CryptoFs::open(opened, CryptoFsOptions { read_only: true, ..Default::default() });
        let mut actual = Vec::new();
        walk(&fs, &CleartextPath::root(), &mut actual);
        actual.sort();
        assert_eq!(actual, expected_entries(dir.path()), "{name}");
        assert!(fs.stats().snapshot().accesses > 0);
        fs.close().unwrap();
    }
}

#[test]
fn ciphertext_paths_and_streaming_reads() {
    let (dir, opened) = open_fixture("long_names");
    let fs = CryptoFs::open(opened, CryptoFsOptions::default());
    let long_dir = CleartextPath::parse(&format!("/{}", "d".repeat(200)));
    let content_dir = fs.ciphertext_path(&long_dir).unwrap();
    assert!(content_dir.starts_with(dir.path().join("d")) && content_dir.is_dir());
    let inner = long_dir.join("inner.txt").unwrap();
    assert!(fs.ciphertext_path(&inner).unwrap().ends_with("contents.c9r") || fs.ciphertext_path(&inner).unwrap().extension().is_some_and(|e| e == "c9r"));
    let mut out = Vec::new();
    assert_eq!(fs.copy_to_writer(&inner, &mut out).unwrap(), 16);
    assert_eq!(out, b"inside long dir\n");
    assert_eq!(fs.read_dir(&inner).unwrap_err().kind(), std::io::ErrorKind::NotADirectory);
    assert_eq!(fs.read_file(&CleartextPath::parse("/missing")).unwrap_err().kind(), std::io::ErrorKind::NotFound);
}
```

Unit tests in `crypto_fs.rs` (creation):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rng::DetRng;
    use crate::fs::events::EventCollector;
    use crate::fs::testutil;
    use crate::{open_vault_with_key, CipherCombo};

    pub(crate) fn test_fs(threshold: u32, read_only: bool) -> (tempfile::TempDir, CryptoFs) {
        let (dir, _, _) = testutil::new_vault(threshold);
        let opened = open_vault_with_key(dir.path(), testutil::masterkey()).unwrap();
        let options = CryptoFsOptions { read_only, ..Default::default() };
        let fs = CryptoFs::with_rng(opened, options, Box::new(DetRng::default()), Arc::new(|| Box::new(DetRng::default())));
        assert_eq!(fs.config().cipher_combo, CipherCombo::SivGcm);
        (dir, fs)
    }

    #[test]
    fn creates_directories_files_and_symlinks() {
        let (_dir, fs) = test_fs(220, false);
        let docs = CleartextPath::parse("/docs");
        fs.create_dir(&docs).unwrap();
        assert_eq!(fs.create_dir(&docs).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs.create_dir(&CleartextPath::parse("/a/b")).unwrap_err().kind(), io::ErrorKind::NotFound);
        fs.create_dir_all(&CleartextPath::parse("/a/b/c")).unwrap();
        fs.create_dir_all(&CleartextPath::parse("/a/b/c")).unwrap();
        let notes = docs.join("notes.md").unwrap();
        fs.write_file(&notes, b"# Notes\n", false).unwrap();
        assert_eq!(fs.write_file(&notes, b"x", false).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        fs.write_file(&notes, b"# Notes v2\n", true).unwrap();
        assert_eq!(fs.read_file(&notes).unwrap(), b"# Notes v2\n");
        assert_eq!(fs.metadata(&notes).unwrap().size, 11);
        fs.create_symlink(&CleartextPath::parse("/link"), "docs/notes.md").unwrap();
        assert_eq!(fs.read_link(&CleartextPath::parse("/link")).unwrap(), "docs/notes.md");
        assert_eq!(fs.metadata(&CleartextPath::parse("/link")).unwrap().size, 11, "follows the link");
        assert!(fs.symlink_metadata(&CleartextPath::parse("/link")).unwrap().is_symlink());
        assert_eq!(fs.read_file(&CleartextPath::parse("/link")).unwrap(), b"# Notes v2\n");
        let names: Vec<String> = fs.read_dir(&CleartextPath::root()).unwrap().into_iter().map(|e| e.cleartext_name).collect();
        assert_eq!(names, vec!["a", "docs", "link"]);
        assert_eq!(fs.create_dir_all(&notes.join("sub").unwrap()).unwrap_err().kind(), io::ErrorKind::NotADirectory);
        assert_eq!(fs.open_file(&docs, OpenOptions::read_only()).unwrap_err().kind(), io::ErrorKind::IsADirectory);
    }

    #[test]
    fn long_names_and_name_limits() {
        let (_dir, fs) = test_fs(220, false);
        let long = CleartextPath::root().join(&"n".repeat(200)).unwrap();
        fs.create_dir(&long).unwrap();
        let inner = long.join(&"m".repeat(200)).unwrap();
        fs.write_file(&inner, b"deep", false).unwrap();
        assert!(fs.ciphertext_path(&inner).unwrap().ends_with("contents.c9r"));
        assert_eq!(fs.read_file(&inner).unwrap(), b"deep");
        let (_dir, limited) = {
            let (dir, _, _) = testutil::new_vault(220);
            let opened = open_vault_with_key(dir.path(), testutil::masterkey()).unwrap();
            let options = CryptoFsOptions { max_cleartext_name_length: 5, ..Default::default() };
            (dir, CryptoFs::with_rng(opened, options, Box::new(DetRng::default()), Arc::new(|| Box::new(DetRng::default()))))
        };
        assert_eq!(limited.create_dir(&CleartextPath::parse("/toolong")).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert_eq!(limited.write_file(&CleartextPath::parse("/toolong"), b"", false).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        limited.write_file(&CleartextPath::parse("/ok"), b"", false).unwrap();
    }

    #[test]
    fn read_only_rejects_writes() {
        let (_dir, fs) = test_fs(220, true);
        assert_eq!(fs.create_dir(&CleartextPath::parse("/d")).unwrap_err().kind(), io::ErrorKind::ReadOnlyFilesystem);
        assert_eq!(fs.write_file(&CleartextPath::parse("/f"), b"", false).unwrap_err().kind(), io::ErrorKind::ReadOnlyFilesystem);
        assert!(fs.read_dir(&CleartextPath::root()).unwrap().is_empty());
    }

    #[test]
    fn streaming_write_and_read_over_many_chunks() {
        let (_dir, fs) = test_fs(220, false);
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let p = CleartextPath::parse("/big");
        assert_eq!(fs.write_from_reader(&p, &mut &data[..], false).unwrap(), 200_000);
        let mut out = Vec::new();
        assert_eq!(fs.copy_to_writer(&p, &mut out).unwrap(), 200_000);
        assert_eq!(out, data);
        let events = EventCollector::new();
        let _ = events; // events are exercised by dir_stream/dir_id tests
    }
}
```

- [ ] **Step 2: Implementation `fs/crypto_fs.rs` (part 1)**

```rust
//! `CryptoFileSystemImpl`: the cleartext view of a vault. Every method takes `&self`; the caches
//! and open files are protected by mutexes so the same instance can serve a FUSE session.
use super::attrs::{attributes_of, FileAttributes};
use super::ciphertext_path::{CiphertextFilePath, CiphertextFileType};
use super::dir_id::{write_dir_id_backup, DirIdLoader};
use super::dir_stream::{DirEntry, DirectoryLister};
use super::events::{discard_events, EventSink};
use super::open_file::OpenOptions;
use super::open_files::{FileHandle, OpenCryptoFiles, RngFactory};
use super::path::CleartextPath;
use super::path_mapper::CryptoPathMapper;
use super::stats::CryptoFsStats;
use super::symlinks::Symlinks;
use crate::crypto::rng::{OsRng, Rng};
use crate::vault::open::OpenedVault;
use crate::{Cryptor, VaultConfig};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// `CryptoFileSystemProperties.DEFAULT_MAX_CLEARTEXT_NAME_LENGTH`
pub const DEFAULT_MAX_CLEARTEXT_NAME_LENGTH: usize = 10 * 1024;

#[derive(Clone)]
pub struct CryptoFsOptions {
    pub read_only: bool,
    pub max_cleartext_name_length: usize,
    pub events: EventSink,
}

impl Default for CryptoFsOptions {
    fn default() -> Self {
        Self { read_only: false, max_cleartext_name_length: DEFAULT_MAX_CLEARTEXT_NAME_LENGTH, events: discard_events() }
    }
}

impl std::fmt::Debug for CryptoFsOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoFsOptions").field("read_only", &self.read_only).field("max_cleartext_name_length", &self.max_cleartext_name_length).finish_non_exhaustive()
    }
}

pub struct CryptoFs {
    vault_path: PathBuf,
    cryptor: Arc<Cryptor>,
    config: VaultConfig,
    dir_ids: Arc<DirIdLoader>,
    mapper: Arc<CryptoPathMapper>,
    open_files: Arc<OpenCryptoFiles>,
    symlinks: Symlinks,
    stats: Arc<CryptoFsStats>,
    options: CryptoFsOptions,
    /// RNG for `dirid.c9r` backups (file content uses the per-file RNG from `open_files`).
    rng: Mutex<Box<dyn Rng + Send>>,
}

impl std::fmt::Debug for CryptoFs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoFs").field("vault_path", &self.vault_path).field("options", &self.options).finish_non_exhaustive()
    }
}

impl CryptoFs {
    pub fn open(vault: OpenedVault, options: CryptoFsOptions) -> Self {
        Self::with_rng(vault, options, Box::new(OsRng), Arc::new(|| Box::new(OsRng)))
    }

    /// Like [`open`](Self::open) with explicit RNGs (deterministic tests). The masterkey inside
    /// `vault` is dropped (zeroised) here; only the derived `Cryptor` lives on.
    pub fn with_rng(vault: OpenedVault, options: CryptoFsOptions, rng: Box<dyn Rng + Send>, rng_factory: RngFactory) -> Self {
        let OpenedVault { path, config, cryptor, masterkey } = vault;
        drop(masterkey);
        let cryptor = Arc::new(cryptor);
        let stats = Arc::new(CryptoFsStats::default());
        let dir_ids = Arc::new(DirIdLoader::new(options.events.clone()));
        let mapper = Arc::new(CryptoPathMapper::new(&path, cryptor.clone(), dir_ids.clone(), config.shortening_threshold, options.events.clone()));
        let open_files = Arc::new(OpenCryptoFiles::new(cryptor.clone(), stats.clone(), options.events.clone(), rng_factory));
        let symlinks = Symlinks::new(mapper.clone(), open_files.clone(), options.read_only);
        Self { vault_path: path, cryptor, config, dir_ids, mapper, open_files, symlinks, stats, options, rng: Mutex::new(rng) }
    }

    pub fn vault_path(&self) -> &Path {
        &self.vault_path
    }
    pub fn config(&self) -> &VaultConfig {
        &self.config
    }
    pub fn is_read_only(&self) -> bool {
        self.options.read_only
    }
    pub fn stats(&self) -> &CryptoFsStats {
        &self.stats
    }
    pub fn mapper(&self) -> &CryptoPathMapper {
        &self.mapper
    }
    pub(crate) fn cryptor(&self) -> &Arc<Cryptor> {
        &self.cryptor
    }

    fn assert_writable(&self) -> io::Result<()> {
        if self.options.read_only { Err(super::read_only_fs()) } else { Ok(()) }
    }

    /// `assertCleartextNameLengthAllowed` (chars, like Java's `String.length()` for BMP names)
    fn assert_cleartext_name_length_allowed(&self, path: &CleartextPath) -> io::Result<()> {
        let len = path.file_name().map(|n| n.chars().count()).unwrap_or(0);
        if len > self.options.max_cleartext_name_length {
            return Err(super::name_too_long(path, self.options.max_cleartext_name_length));
        }
        Ok(())
    }

    fn lister(&self) -> DirectoryLister<'_> {
        DirectoryLister { mapper: &self.mapper, cryptor: &self.cryptor, events: &self.options.events, read_only: self.options.read_only }
    }

    /// Sorted cleartext listing; `NotADirectory` for files and symlinks.
    pub fn read_dir(&self, dir: &CleartextPath) -> io::Result<Vec<DirEntry>> {
        if self.mapper.ciphertext_file_type(dir)? != CiphertextFileType::Directory {
            return Err(super::not_a_directory(dir));
        }
        self.stats.increment_accesses();
        self.lister().list(dir)
    }

    /// Attributes following symlinks.
    pub fn metadata(&self, path: &CleartextPath) -> io::Result<FileAttributes> {
        self.attributes(path, true)
    }

    /// Attributes of the node itself (a symlink's size is the length of its target).
    pub fn symlink_metadata(&self, path: &CleartextPath) -> io::Result<FileAttributes> {
        self.attributes(path, false)
    }

    fn attributes(&self, path: &CleartextPath, follow_links: bool) -> io::Result<FileAttributes> {
        self.stats.increment_accesses();
        let mut path = path.clone();
        let mut file_type = self.mapper.ciphertext_file_type(&path)?;
        if file_type == CiphertextFileType::Symlink && follow_links {
            path = self.symlinks.resolve_recursively(&path)?;
            file_type = self.mapper.ciphertext_file_type(&path)?;
        }
        let ciphertext_path = self.ciphertext_path_for(&path, file_type)?;
        attributes_of(&ciphertext_path, file_type, &self.cryptor, self.open_files.get(&ciphertext_path), self.options.read_only)
    }

    fn ciphertext_path_for(&self, path: &CleartextPath, file_type: CiphertextFileType) -> io::Result<PathBuf> {
        Ok(match file_type {
            CiphertextFileType::Directory => self.mapper.ciphertext_dir(path)?.path,
            CiphertextFileType::Symlink => self.mapper.ciphertext_file_path(path)?.symlink_file_path(),
            CiphertextFileType::File => self.mapper.ciphertext_file_path(path)?.file_path(),
        })
    }

    /// `CryptoFileSystem.getCiphertextPath`: content dir for directories, `symlink.c9r` for links,
    /// the ciphertext file (or `contents.c9r`) for files.
    pub fn ciphertext_path(&self, path: &CleartextPath) -> io::Result<PathBuf> {
        let file_type = self.mapper.ciphertext_file_type(path)?;
        self.ciphertext_path_for(path, file_type)
    }

    /// `newFileChannel`: symlinks are followed; directories cannot be opened.
    pub fn open_file(&self, path: &CleartextPath, options: OpenOptions) -> io::Result<FileHandle> {
        let options = options.normalized();
        if options.write {
            self.assert_writable()?;
        }
        let file_type = match self.mapper.ciphertext_file_type(path) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound && (options.create || options.create_new) => CiphertextFileType::File,
            Err(e) => return Err(e),
        };
        match file_type {
            CiphertextFileType::Symlink => {
                let resolved = self.symlinks.resolve_recursively(path)?;
                self.open_regular_file(&resolved, options)
            }
            CiphertextFileType::File => self.open_regular_file(path, options),
            CiphertextFileType::Directory => Err(super::is_a_directory(path)),
        }
    }

    fn open_regular_file(&self, path: &CleartextPath, options: OpenOptions) -> io::Result<FileHandle> {
        if options.create || options.create_new {
            self.assert_cleartext_name_length_allowed(path)?;
        }
        let ciphertext = self.mapper.ciphertext_file_path(path)?;
        let file_path = ciphertext.file_path();
        if options.create_new && self.open_files.get(&file_path).is_some() {
            return Err(super::already_exists(path));
        }
        if ciphertext.is_shortened() && options.create_new {
            std::fs::create_dir(ciphertext.raw_path())?; // AlreadyExists if the node exists
        } else if ciphertext.is_shortened() && options.write {
            std::fs::create_dir_all(ciphertext.raw_path())?;
        }
        let handle = self.open_files.open(&file_path, options).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound { super::not_found(path) } else { e }
        })?;
        if options.write {
            ciphertext.persist_long_file_name()?;
            self.stats.increment_accesses_written();
        }
        if options.read {
            self.stats.increment_accesses_read();
        }
        self.stats.increment_accesses();
        Ok(handle)
    }

    pub fn read_file(&self, path: &CleartextPath) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        self.copy_to_writer(path, &mut out)?;
        Ok(out)
    }

    /// Streams the cleartext to `out` in chunk-sized pieces; returns the number of bytes copied.
    pub fn copy_to_writer(&self, path: &CleartextPath, out: &mut dyn Write) -> io::Result<u64> {
        let handle = self.open_file(path, OpenOptions::read_only())?;
        let mut buf = vec![0u8; self.cryptor.file_content_cryptor().cleartext_chunk_size() * 4];
        let mut position = 0u64;
        loop {
            let n = handle.read_at(&mut buf, position)?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n])?;
            position += n as u64;
        }
        handle.close()?;
        out.flush()?;
        Ok(position)
    }

    pub fn write_file(&self, path: &CleartextPath, data: &[u8], overwrite: bool) -> io::Result<()> {
        self.write_from_reader(path, &mut &data[..], overwrite).map(|_| ())
    }

    /// Encrypts everything read from `input` into a new (or, with `overwrite`, truncated) file.
    pub fn write_from_reader(&self, path: &CleartextPath, input: &mut dyn Read, overwrite: bool) -> io::Result<u64> {
        let options = if overwrite { OpenOptions::write_truncate() } else { OpenOptions::write_new() };
        let handle = self.open_file(path, options)?;
        let mut buf = vec![0u8; self.cryptor.file_content_cryptor().cleartext_chunk_size() * 4];
        let mut position = 0u64;
        loop {
            let n = match input.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            handle.write_all_at(&buf[..n], position)?;
            position += n as u64;
        }
        handle.close()?;
        Ok(position)
    }

    /// `createDirectory`: node dir + `dir.c9r`, then the content dir with its `dirid.c9r`.
    pub fn create_dir(&self, dir: &CleartextPath) -> io::Result<()> {
        self.assert_writable()?;
        self.assert_cleartext_name_length_allowed(dir)?;
        let Some(parent) = dir.parent() else {
            return Err(super::already_exists(dir));
        };
        let ciphertext_parent_dir = self.mapper.ciphertext_dir(&parent)?.path;
        if !ciphertext_parent_dir.is_dir() {
            return Err(super::not_found(&parent));
        }
        self.mapper.assert_non_existing(dir)?;
        let ciphertext_path = self.mapper.ciphertext_file_path(dir)?;
        let dir_file = ciphertext_path.dir_file_path();
        // the id for a not-yet-existing dir.c9r is a fresh UUID, cached so we write exactly that one
        let ciphertext_dir = self.mapper.ciphertext_dir(dir)?;
        std::fs::create_dir(ciphertext_path.raw_path()).map_err(|e| {
            if e.kind() == io::ErrorKind::AlreadyExists { super::already_exists(dir) } else { e }
        })?;
        let write_dir_file = || -> io::Result<()> {
            let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&dir_file)?;
            file.write_all(ciphertext_dir.dir_id.as_bytes())
        };
        let result = write_dir_file().and_then(|_| {
            std::fs::create_dir_all(&ciphertext_dir.path)?;
            write_dir_id_backup(&self.cryptor, &ciphertext_dir, &mut **super::lock(&self.rng))?;
            ciphertext_path.persist_long_file_name()
        });
        if let Err(e) = result {
            // make sure there is no orphan dir file
            let _ = std::fs::remove_dir_all(ciphertext_path.raw_path());
            self.mapper.invalidate_path_mapping(dir);
            self.dir_ids.delete(&dir_file);
            return Err(e);
        }
        Ok(())
    }

    /// `Files.createDirectories`: creates every missing ancestor; an existing non-directory is `NotADirectory`.
    pub fn create_dir_all(&self, dir: &CleartextPath) -> io::Result<()> {
        let mut current = CleartextPath::root();
        for element in dir.elements() {
            current = current.join(element).map_err(|e| super::invalid_input(e.to_string()))?;
            match self.mapper.ciphertext_file_type(&current) {
                Ok(CiphertextFileType::Directory) => {}
                Ok(_) => return Err(super::not_a_directory(&current)),
                Err(e) if e.kind() == io::ErrorKind::NotFound => self.create_dir(&current)?,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    pub fn create_symlink(&self, path: &CleartextPath, target: &str) -> io::Result<()> {
        self.assert_writable()?;
        self.assert_cleartext_name_length_allowed(path)?;
        self.symlinks.create_symbolic_link(path, target)
    }

    pub fn read_link(&self, path: &CleartextPath) -> io::Result<String> {
        self.symlinks.read_symbolic_link(path)
    }

    /// Flushes and closes every open file.
    pub fn close(self) -> io::Result<()> {
        self.open_files.close_all()
    }
}
```

(`&mut **super::lock(&self.rng)` yields `&mut dyn Rng` from `MutexGuard<Box<dyn Rng + Send>>`; if the borrow checker complains: `let mut rng = super::lock(&self.rng); write_dir_id_backup(&self.cryptor, &ciphertext_dir, rng.as_mut())`.)

`lib.rs`: `pub use fs::{CryptoFs, CryptoFsOptions, DirEntry, FileAttributes, FileHandle, OpenOptions};`

- [ ] **Step 3: Tests**

Run: `cargo test -p cryptomator-core fs::crypto_fs && cargo test -p cryptomator-core --test crypto_fs_fixtures`
Expected: PASS (4 unit tests, 2 integration tests; all 8 fixtures match `expected.json`)

- [ ] **Step 4: Gate + Commit** ("Add CryptoFs facade: listing, attributes, reads, creates")

---

### Task 10: `CryptoFs` – delete, move, copy, timestamps

**Files:**
- Modify: `crates/cryptomator-core/src/fs/crypto_fs.rs`

**Interfaces:**
- Produces: `CryptoFs::{delete(&CleartextPath) -> io::Result<()>` (directories must be empty), `delete_recursive(&CleartextPath)`, `rename(src, dst, replace_existing: bool) -> io::Result<()>`, `copy(src, dst, replace_existing: bool) -> io::Result<()>` (file: ciphertext copy; symlink: link copy; directory: not recursive, like `Files.copy`), `set_times(&CleartextPath, modified: Option<SystemTime>, accessed: Option<SystemTime>) -> io::Result<()>}`.

- [ ] **Step 1: Failing tests** (add to `mod tests` in `crypto_fs.rs`)

```rust
    #[test]
    fn delete_semantics_match_java() {
        let (_dir, fs) = test_fs(220, false);
        let d = CleartextPath::parse("/d");
        fs.create_dir(&d).unwrap();
        fs.write_file(&d.join("f").unwrap(), b"1", false).unwrap();
        fs.create_symlink(&d.join("l").unwrap(), "f").unwrap();
        assert_eq!(fs.delete(&CleartextPath::root()).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert_eq!(fs.delete(&d).unwrap_err().kind(), io::ErrorKind::DirectoryNotEmpty);
        fs.delete(&d.join("l").unwrap()).unwrap();
        fs.delete(&d.join("f").unwrap()).unwrap();
        assert_eq!(fs.delete(&d.join("f").unwrap()).unwrap_err().kind(), io::ErrorKind::NotFound);
        // stray non-ciphertext files inside the content dir do not block the delete
        std::fs::write(fs.mapper().ciphertext_dir(&d).unwrap().path.join(".DS_Store"), b"x").unwrap();
        let content_dir = fs.mapper().ciphertext_dir(&d).unwrap().path;
        fs.delete(&d).unwrap();
        assert!(!content_dir.exists());
        assert_eq!(fs.mapper().ciphertext_file_type(&d).unwrap_err().kind(), io::ErrorKind::NotFound);
        fs.create_dir_all(&CleartextPath::parse("/x/y/z")).unwrap();
        fs.write_file(&CleartextPath::parse("/x/y/z/f"), b"deep", false).unwrap();
        fs.delete_recursive(&CleartextPath::parse("/x")).unwrap();
        assert!(fs.read_dir(&CleartextPath::root()).unwrap().is_empty());
    }

    #[test]
    fn rename_files_symlinks_and_directories() {
        let (_dir, fs) = test_fs(220, false);
        fs.create_dir_all(&CleartextPath::parse("/a/sub")).unwrap();
        fs.write_file(&CleartextPath::parse("/a/sub/f"), b"content", false).unwrap();
        fs.create_symlink(&CleartextPath::parse("/a/l"), "sub/f").unwrap();
        fs.rename(&CleartextPath::parse("/a/sub/f"), &CleartextPath::parse("/a/g"), false).unwrap();
        assert_eq!(fs.read_file(&CleartextPath::parse("/a/g")).unwrap(), b"content");
        fs.write_file(&CleartextPath::parse("/a/h"), b"other", false).unwrap();
        assert_eq!(fs.rename(&CleartextPath::parse("/a/g"), &CleartextPath::parse("/a/h"), false).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        fs.rename(&CleartextPath::parse("/a/g"), &CleartextPath::parse("/a/h"), true).unwrap();
        assert_eq!(fs.read_file(&CleartextPath::parse("/a/h")).unwrap(), b"content");
        // long name target: contents.c9r inside .c9s; back to a short name removes name.c9s
        let long = CleartextPath::root().join(&"L".repeat(200)).unwrap();
        fs.rename(&CleartextPath::parse("/a/h"), &long, false).unwrap();
        assert!(fs.ciphertext_path(&long).unwrap().ends_with("contents.c9r"));
        fs.rename(&long, &CleartextPath::parse("/a/h"), false).unwrap();
        assert!(fs.ciphertext_path(&CleartextPath::parse("/a/h")).unwrap().extension().is_some_and(|e| e == "c9r"));
        fs.rename(&CleartextPath::parse("/a/l"), &CleartextPath::parse("/a/m"), false).unwrap();
        assert_eq!(fs.read_link(&CleartextPath::parse("/a/m")).unwrap(), "sub/f");
        // directory rename keeps the content dir (same dir id), moves the cached mapping
        let content = fs.mapper().ciphertext_dir(&CleartextPath::parse("/a")).unwrap();
        fs.rename(&CleartextPath::parse("/a"), &CleartextPath::parse("/b"), false).unwrap();
        assert_eq!(fs.mapper().ciphertext_dir(&CleartextPath::parse("/b")).unwrap(), content);
        assert_eq!(fs.read_file(&CleartextPath::parse("/b/h")).unwrap(), b"content");
        assert_eq!(fs.mapper().ciphertext_file_type(&CleartextPath::parse("/a")).unwrap_err().kind(), io::ErrorKind::NotFound);
        fs.create_dir(&CleartextPath::parse("/empty")).unwrap();
        assert_eq!(fs.rename(&CleartextPath::parse("/b"), &CleartextPath::parse("/empty"), false).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        fs.rename(&CleartextPath::parse("/b"), &CleartextPath::parse("/empty"), true).unwrap();
        assert_eq!(fs.read_file(&CleartextPath::parse("/empty/h")).unwrap(), b"content");
        fs.create_dir(&CleartextPath::parse("/full")).unwrap();
        fs.write_file(&CleartextPath::parse("/full/x"), b"", false).unwrap();
        assert_eq!(fs.rename(&CleartextPath::parse("/empty"), &CleartextPath::parse("/full"), true).unwrap_err().kind(), io::ErrorKind::DirectoryNotEmpty);
        assert!(fs.rename(&CleartextPath::root(), &CleartextPath::parse("/r"), false).is_err());
        fs.rename(&CleartextPath::parse("/empty"), &CleartextPath::parse("/empty"), false).unwrap();
        // an open file survives a rename
        let h = fs.open_file(&CleartextPath::parse("/empty/h"), OpenOptions::read_write()).unwrap();
        fs.rename(&CleartextPath::parse("/empty/h"), &CleartextPath::parse("/moved"), false).unwrap();
        h.write_all_at(b"X", 0).unwrap();
        h.close().unwrap();
        assert_eq!(fs.read_file(&CleartextPath::parse("/moved")).unwrap(), b"Xontent");
    }

    #[test]
    fn copy_and_set_times() {
        let (_dir, fs) = test_fs(220, false);
        fs.write_file(&CleartextPath::parse("/f"), b"data", false).unwrap();
        fs.copy(&CleartextPath::parse("/f"), &CleartextPath::parse("/g"), false).unwrap();
        assert_eq!(fs.read_file(&CleartextPath::parse("/g")).unwrap(), b"data");
        assert_eq!(fs.copy(&CleartextPath::parse("/f"), &CleartextPath::parse("/g"), false).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        fs.write_file(&CleartextPath::parse("/f"), b"new", true).unwrap();
        fs.copy(&CleartextPath::parse("/f"), &CleartextPath::parse("/g"), true).unwrap();
        assert_eq!(fs.read_file(&CleartextPath::parse("/g")).unwrap(), b"new");
        fs.create_symlink(&CleartextPath::parse("/l"), "f").unwrap();
        fs.copy(&CleartextPath::parse("/l"), &CleartextPath::parse("/l2"), false).unwrap();
        assert_eq!(fs.read_link(&CleartextPath::parse("/l2")).unwrap(), "f");
        fs.create_dir(&CleartextPath::parse("/d")).unwrap();
        fs.copy(&CleartextPath::parse("/d"), &CleartextPath::parse("/d2"), false).unwrap();
        assert!(fs.metadata(&CleartextPath::parse("/d2")).unwrap().is_dir());
        let t = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000);
        fs.set_times(&CleartextPath::parse("/g"), Some(t), None).unwrap();
        assert_eq!(fs.metadata(&CleartextPath::parse("/g")).unwrap().modified, Some(t));
        fs.set_times(&CleartextPath::parse("/d"), Some(t), Some(t)).unwrap();
        assert_eq!(fs.metadata(&CleartextPath::parse("/d")).unwrap().modified, Some(t));
    }
```

- [ ] **Step 2: Implementation (part 2 of `crypto_fs.rs`)**

```rust
use crate::constants::DIR_ID_BACKUP_FILE_NAME;
use std::collections::HashSet;
use std::time::SystemTime;

/// `DeletingFileVisitor` without the DOS/POSIX write-protection dance (unlink on Unix needs
/// directory permissions, not file permissions).
fn remove_recursively(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
        Ok(meta) if meta.is_dir() => std::fs::remove_dir_all(path),
        Ok(_) => std::fs::remove_file(path),
    }
}

fn remove_file_if_exists(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

fn is_not_empty_error(e: &io::Error) -> bool {
    // ENOTEMPTY, or EEXIST on some platforms
    matches!(e.kind(), io::ErrorKind::DirectoryNotEmpty | io::ErrorKind::AlreadyExists)
}

impl CryptoFs {
    /// `delete`: files and symlinks always, directories only when empty.
    pub fn delete(&self, path: &CleartextPath) -> io::Result<()> {
        self.assert_writable()?;
        if path.is_root() {
            return Err(super::invalid_input("The filesystem root cannot be deleted."));
        }
        let file_type = self.mapper.ciphertext_file_type(path)?;
        let ciphertext = self.mapper.ciphertext_file_path(path)?;
        match file_type {
            CiphertextFileType::Directory => self.delete_directory(path, &ciphertext),
            CiphertextFileType::File | CiphertextFileType::Symlink => {
                self.open_files.delete(&ciphertext.file_path());
                remove_recursively(ciphertext.raw_path())
            }
        }
    }

    /// Depth-first delete of a whole subtree (convenience for `fs rm -r`).
    pub fn delete_recursive(&self, path: &CleartextPath) -> io::Result<()> {
        if self.symlink_metadata(path)?.is_dir() {
            for entry in self.read_dir(path)? {
                self.delete_recursive(&path.join(&entry.cleartext_name).map_err(|e| super::invalid_input(e.to_string()))?)?;
            }
        }
        self.delete(path)
    }

    fn delete_directory(&self, path: &CleartextPath, ciphertext: &CiphertextFilePath) -> io::Result<()> {
        let ciphertext_dir = self.mapper.ciphertext_dir(path)?.path;
        let dir_file = ciphertext.dir_file_path();
        let result = self
            .delete_ciphertext_dir_including_non_ciphertext_files(&ciphertext_dir, path)
            .and_then(|_| remove_recursively(ciphertext.raw_path()));
        match result {
            Ok(()) => {
                self.mapper.invalidate_path_mapping(path);
                self.dir_ids.delete(&dir_file);
                Ok(())
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Err(super::not_found(path)),
            Err(e) if is_not_empty_error(&e) => Err(super::directory_not_empty(path)),
            Err(e) => Err(e),
        }
    }

    /// `CiphertextDirectoryDeleter`: a content dir that only holds non-ciphertext leftovers
    /// (`dirid.c9r`, `.DS_Store`, …) is emptied and removed; real content keeps it.
    fn delete_ciphertext_dir_including_non_ciphertext_files(&self, ciphertext_dir: &Path, cleartext_dir: &CleartextPath) -> io::Result<()> {
        match std::fs::remove_dir(ciphertext_dir) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) if is_not_empty_error(&e) => {
                let ciphertext_files: HashSet<PathBuf> = self.lister().list(cleartext_dir)?.into_iter().map(|n| n.ciphertext_path).collect();
                let mut deleted_some = false;
                for entry in std::fs::read_dir(ciphertext_dir)? {
                    let p = entry?.path();
                    if !ciphertext_files.contains(&p) {
                        deleted_some = true;
                        remove_recursively(&p)?;
                    }
                }
                if deleted_some { std::fs::remove_dir(ciphertext_dir) } else { Err(e) }
            }
            Err(e) => Err(e),
        }
    }

    /// `move`: renames the ciphertext node; directories keep their content dir.
    pub fn rename(&self, src: &CleartextPath, dst: &CleartextPath, replace_existing: bool) -> io::Result<()> {
        self.assert_writable()?;
        self.assert_cleartext_name_length_allowed(dst)?;
        if src.is_root() {
            return Err(super::invalid_input("Filesystem root cannot be moved."));
        }
        if dst.is_root() {
            return Err(super::already_exists(dst));
        }
        if src == dst {
            return Ok(());
        }
        let file_type = self.mapper.ciphertext_file_type(src)?;
        if !replace_existing {
            self.mapper.assert_non_existing(dst)?;
        }
        match file_type {
            CiphertextFileType::Symlink => self.move_symlink(src, dst),
            CiphertextFileType::File => self.move_file(src, dst, replace_existing),
            CiphertextFileType::Directory => self.move_directory(src, dst, replace_existing),
        }
    }

    fn move_symlink(&self, src: &CleartextPath, dst: &CleartextPath) -> io::Result<()> {
        let s = self.mapper.ciphertext_file_path(src)?;
        let d = self.mapper.ciphertext_file_path(dst)?;
        let two_phase = self.open_files.prepare_move(&s.symlink_file_path(), &d.symlink_file_path())?;
        remove_recursively(d.raw_path())?; // replace: an existing node was allowed by the caller
        std::fs::rename(s.raw_path(), d.raw_path())?;
        if d.is_shortened() { d.persist_long_file_name()?; } else { remove_file_if_exists(&d.inflated_name_path())?; }
        two_phase.commit();
        Ok(())
    }

    fn move_file(&self, src: &CleartextPath, dst: &CleartextPath, replace_existing: bool) -> io::Result<()> {
        let s = self.mapper.ciphertext_file_path(src)?;
        let d = self.mapper.ciphertext_file_path(dst)?;
        let two_phase = self.open_files.prepare_move(&s.file_path(), &d.file_path())?;
        if !replace_existing && std::fs::symlink_metadata(d.file_path()).is_ok() {
            return Err(super::already_exists(dst)); // std::fs::rename would replace silently
        }
        if d.is_shortened() {
            std::fs::create_dir_all(d.raw_path())?;
            d.persist_long_file_name()?;
        }
        std::fs::rename(s.file_path(), d.file_path())?;
        if s.is_shortened() {
            remove_recursively(s.raw_path())?;
        }
        two_phase.commit();
        Ok(())
    }

    fn move_directory(&self, src: &CleartextPath, dst: &CleartextPath, replace_existing: bool) -> io::Result<()> {
        let s = self.mapper.ciphertext_file_path(src)?;
        let d = self.mapper.ciphertext_file_path(dst)?;
        if replace_existing && std::fs::symlink_metadata(d.raw_path()).is_ok() {
            if self.mapper.ciphertext_file_type(dst)? != CiphertextFileType::Directory {
                remove_recursively(d.raw_path())?;
            } else {
                let target_content_dir = self.mapper.ciphertext_dir(dst)?.path;
                let mut target_exists = true;
                match std::fs::read_dir(&target_content_dir) {
                    Ok(entries) => {
                        if entries.filter_map(|e| e.ok()).any(|e| e.file_name() != DIR_ID_BACKUP_FILE_NAME) {
                            return Err(super::directory_not_empty(dst));
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::NotFound => target_exists = false,
                    Err(e) => return Err(e),
                }
                remove_recursively(d.raw_path())?;
                if target_exists {
                    remove_recursively(&target_content_dir)?;
                }
                self.mapper.invalidate_path_mapping(dst);
                self.dir_ids.delete(&d.dir_file_path());
            }
        }
        std::fs::rename(s.raw_path(), d.raw_path())?;
        if d.is_shortened() { d.persist_long_file_name()?; } else { remove_file_if_exists(&d.inflated_name_path())?; }
        self.dir_ids.move_id(&s.dir_file_path(), &d.dir_file_path());
        self.mapper.move_path_mapping(src, dst);
        Ok(())
    }

    /// `copy` (non-recursive for directories, like `Files.copy`): ciphertext files are copied as
    /// they are (same key, same header), symlinks copy their `symlink.c9r`.
    pub fn copy(&self, src: &CleartextPath, dst: &CleartextPath, replace_existing: bool) -> io::Result<()> {
        self.assert_writable()?;
        self.assert_cleartext_name_length_allowed(dst)?;
        if src == dst {
            return Ok(());
        }
        if dst.is_root() {
            return Err(super::invalid_input("The filesystem root cannot be replaced."));
        }
        let file_type = self.mapper.ciphertext_file_type(src)?;
        if !replace_existing {
            self.mapper.assert_non_existing(dst)?;
        }
        let s = self.mapper.ciphertext_file_path(src)?;
        let d = self.mapper.ciphertext_file_path(dst)?;
        match file_type {
            CiphertextFileType::File => {
                if d.is_shortened() {
                    std::fs::create_dir_all(d.raw_path())?;
                }
                std::fs::copy(s.file_path(), d.file_path())?;
                d.persist_long_file_name()
            }
            CiphertextFileType::Symlink => {
                remove_recursively(d.raw_path())?;
                std::fs::create_dir_all(d.raw_path())?;
                std::fs::copy(s.symlink_file_path(), d.symlink_file_path())?;
                d.persist_long_file_name()
            }
            CiphertextFileType::Directory => {
                if std::fs::symlink_metadata(d.raw_path()).is_err() {
                    self.create_dir(dst)
                } else if self.read_dir(dst)?.is_empty() {
                    Ok(()) // keep the existing empty directory
                } else {
                    Err(super::directory_not_empty(dst))
                }
            }
        }
    }

    /// `setTimes` (follows symlinks): updates an open file's mtime and the ciphertext node's times.
    pub fn set_times(&self, path: &CleartextPath, modified: Option<SystemTime>, accessed: Option<SystemTime>) -> io::Result<()> {
        self.assert_writable()?;
        let resolved = self.symlinks.resolve_recursively(path)?;
        let file_type = self.mapper.ciphertext_file_type(&resolved)?;
        let ciphertext_path = self.ciphertext_path_for(&resolved, file_type)?;
        if let (Some(modified), Some(open)) = (modified, self.open_files.get(&ciphertext_path)) {
            super::lock(&open).set_last_modified(modified);
        }
        let mut times = std::fs::FileTimes::new();
        if let Some(m) = modified { times = times.set_modified(m); }
        if let Some(a) = accessed { times = times.set_accessed(a); }
        std::fs::File::open(&ciphertext_path)?.set_times(times)
    }
}
```

- [ ] **Step 3: Tests**

Run: `cargo test -p cryptomator-core fs::crypto_fs && cargo test -p cryptomator-core --test crypto_fs_fixtures`
Expected: PASS (7 unit tests + 2 integration tests)

- [ ] **Step 4: Gate + Commit** ("Add delete, rename, copy and set_times to CryptoFs")

---

### Task 11: Name decryption and capability probe

**Files:**
- Create: `crates/cryptomator-core/src/fs/name_decryptor.rs`, `crates/cryptomator-core/src/fs/capabilities.rs`
- Modify: `crates/cryptomator-core/src/fs/mod.rs`, `crates/cryptomator-core/src/lib.rs`

**Interfaces:**
- Consumes: `dir_id::read_dir_id_backup`, `long_names::inflate`, `constants`.
- Produces: `fs::decrypt_filename(vault_path: &Path, cryptor: &Cryptor, ciphertext_node: &Path) -> crate::Result<String>`; `fs::determine_supported_cleartext_file_name_length(vault_path: &Path) -> io::Result<u32>`; `capabilities::determine_supported_ciphertext_file_name_length(vault_path) -> io::Result<u32>`.

- [ ] **Step 1: Failing tests**

`name_decryptor.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{DATA_DIR_NAME, DIR_ID_BACKUP_FILE_NAME};
    use crate::crypto::rng::DetRng;
    use crate::fs::{testutil, CleartextPath, CryptoFs, CryptoFsOptions};
    use crate::{open_vault_with_key, CoreError};

    fn fs() -> (tempfile::TempDir, CryptoFs) {
        let (dir, _, _) = testutil::new_vault(220);
        let opened = open_vault_with_key(dir.path(), testutil::masterkey()).unwrap();
        let fs = CryptoFs::with_rng(opened, CryptoFsOptions::default(), Box::new(DetRng::default()), Arc::new(|| Box::new(DetRng::default())));
        (dir, fs)
    }

    #[test]
    fn decrypts_plain_and_shortened_nodes_in_any_directory() {
        let (dir, fs) = fs();
        fs.create_dir(&CleartextPath::parse("/docs")).unwrap();
        fs.write_file(&CleartextPath::parse("/docs/notes.md"), b"", false).unwrap();
        let long = "x".repeat(200);
        fs.write_file(&CleartextPath::parse(&format!("/docs/{long}")), b"", false).unwrap();
        let docs_content = fs.mapper().ciphertext_dir(&CleartextPath::parse("/docs")).unwrap().path;
        let docs_node = fs.mapper().ciphertext_file_path(&CleartextPath::parse("/docs")).unwrap();
        assert_eq!(decrypt_filename(dir.path(), fs.cryptor(), docs_node.raw_path()).unwrap(), "docs");
        let notes = fs.mapper().ciphertext_file_path(&CleartextPath::parse("/docs/notes.md")).unwrap();
        assert_eq!(decrypt_filename(dir.path(), fs.cryptor(), notes.raw_path()).unwrap(), "notes.md");
        let long_node = fs.mapper().ciphertext_file_path(&CleartextPath::parse(&format!("/docs/{long}"))).unwrap();
        assert!(long_node.is_shortened());
        assert_eq!(decrypt_filename(dir.path(), fs.cryptor(), long_node.raw_path()).unwrap(), long);
        // relative node paths are resolved against the current directory, so pass absolute ones
        assert!(matches!(decrypt_filename(dir.path(), fs.cryptor(), Path::new("/elsewhere/x.c9r")), Err(CoreError::InvalidArgument(_))));
        assert!(matches!(decrypt_filename(dir.path(), fs.cryptor(), &docs_content), Err(CoreError::InvalidArgument(_))), "depth 3");
        assert!(matches!(decrypt_filename(dir.path(), fs.cryptor(), &docs_content.join("short.c9r")), Err(CoreError::InvalidArgument(_))));
        assert!(matches!(decrypt_filename(dir.path(), fs.cryptor(), &docs_content.join(format!("{}.txt", "a".repeat(30)))), Err(CoreError::InvalidArgument(_))));
        // a node from another vault (wrong key) fails authentication
        let (other_dir, other_fs) = fs();
        let _ = other_dir;
        let foreign = notes.raw_path().to_path_buf();
        assert!(matches!(decrypt_filename(dir.path(), other_fs.cryptor(), &foreign), Err(CoreError::AuthenticationFailed(_))));
        // missing dirid.c9r
        std::fs::remove_file(docs_content.join(DIR_ID_BACKUP_FILE_NAME)).unwrap();
        assert!(matches!(decrypt_filename(dir.path(), fs.cryptor(), notes.raw_path()), Err(CoreError::InvalidArgument(_))));
        let _ = DATA_DIR_NAME;
    }
}
```

(The `other_fs` test uses the same masterkey from `testutil` – use a **different key**: `Masterkey::from_raw([7u8; 64])` and `initialize` directly, so that the auth error is real; the implementer adapts the helper accordingly.)

`capabilities.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_filesystem_supports_the_maximum_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let cleartext = determine_supported_cleartext_file_name_length(dir.path()).unwrap();
        assert_eq!(cleartext, (220 - 4) / 4 * 3 - 16);
        assert!(!dir.path().join("c").exists(), "probe directory removed");
    }

    #[test]
    fn binary_search_finds_a_limit() {
        // a probe whose "file system" refuses names longer than 100 chars
        let mut probes = Vec::new();
        let found = search(28, 221, |n| {
            probes.push(n);
            n <= 100
        });
        assert_eq!(found, 100);
        assert!(probes.len() <= 9, "{probes:?}");
    }
}
```

- [ ] **Step 2: Implementation**

`fs/name_decryptor.rs`:

```rust
//! `FileNameDecryptor`: cleartext name of a ciphertext node (`…/d/XX/YYYY/<node>.c9r|.c9s`),
//! using the `dirid.c9r` of its content directory.
use super::dir_id::read_dir_id_backup;
use super::long_names::inflate;
use crate::constants::{CRYPTOMATOR_FILE_SUFFIX, DEFLATED_FILE_SUFFIX, DIR_ID_BACKUP_FILE_NAME, MIN_CIPHER_NAME_LENGTH};
use crate::error::{CoreError, Result};
use crate::Cryptor;
use std::path::Path;

pub fn decrypt_filename(vault_path: &Path, cryptor: &Cryptor, ciphertext_node: &Path) -> Result<String> {
    let absolute = std::path::absolute(ciphertext_node)?;
    validate_path(vault_path, &absolute)?;
    let parent = absolute.parent().ok_or_else(|| CoreError::InvalidArgument("node has no parent".into()))?;
    let dir_id = match read_dir_id_backup(cryptor, parent) {
        Ok(id) => id,
        Err(CoreError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(CoreError::InvalidArgument(format!("Directory does not have a {DIR_ID_BACKUP_FILE_NAME} file.")));
        }
        Err(e) => return Err(CoreError::AuthenticationFailed(format!("Decryption of dirId backup file failed: {e}"))),
    };
    let full_name = absolute.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let encrypted_name = if let Some(base) = full_name.strip_suffix(CRYPTOMATOR_FILE_SUFFIX) {
        base.to_string()
    } else {
        let c9r_name = inflate(&absolute)?;
        c9r_name.strip_suffix(CRYPTOMATOR_FILE_SUFFIX).unwrap_or(&c9r_name).to_string()
    };
    cryptor
        .file_name_cryptor()
        .decrypt_filename(&encrypted_name, &[dir_id.as_bytes()])
        .map_err(|e| CoreError::AuthenticationFailed(format!("Filename decryption failed: {e}")))
}

/// `FileNameDecryptor.validatePath`: inside the vault, at depth 4 (`d/XX/YYYY/node`), `.c9r`/`.c9s`, ≥ 28 chars.
fn validate_path(vault_path: &Path, absolute: &Path) -> Result<()> {
    let vault_abs = std::path::absolute(vault_path)?;
    let Ok(relative) = absolute.strip_prefix(&vault_abs) else {
        return Err(CoreError::InvalidArgument(format!("Node {} is not a part of vault {}", absolute.display(), vault_abs.display())));
    };
    if relative.components().count() != 4 {
        return Err(CoreError::InvalidArgument(format!("Node {} is not located at depth 4 from vault storage root", absolute.display())));
    }
    let name = absolute.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let has_extension = name.ends_with(CRYPTOMATOR_FILE_SUFFIX) || name.ends_with(DEFLATED_FILE_SUFFIX);
    if !has_extension || name.chars().count() < MIN_CIPHER_NAME_LENGTH {
        return Err(CoreError::InvalidArgument(format!(
            "Node {} does not end with {CRYPTOMATOR_FILE_SUFFIX} or {DEFLATED_FILE_SUFFIX} or filename is shorter than {MIN_CIPHER_NAME_LENGTH} characters.",
            absolute.display()
        )));
    }
    Ok(())
}
```

`fs/capabilities.rs`:

```rust
//! `FileSystemCapabilityChecker.determineSupportedCleartextFileNameLength`: probes the longest
//! `.c9r` name the storage accepts below `<vault>/c/` by binary search, then removes the probe dir.
use crate::constants::{MAX_ADDITIONAL_PATH_LENGTH, MAX_CIPHER_NAME_LENGTH, MIN_CIPHER_NAME_LENGTH};
use std::io;
use std::path::Path;

/// Cleartext characters that survive base64 + IV overhead for the supported ciphertext length.
pub fn determine_supported_cleartext_file_name_length(vault_path: &Path) -> io::Result<u32> {
    let max_ciphertext = determine_supported_ciphertext_file_name_length(vault_path)?;
    // math explained in cryptofs issue #60: subtract 4 for the extension, base64-decode, subtract 16 for the IV
    Ok((max_ciphertext - 4) / 4 * 3 - 16)
}

pub fn determine_supported_ciphertext_file_name_length(vault_path: &Path) -> io::Result<u32> {
    let sub_path_length = MAX_ADDITIONAL_PATH_LENGTH - 2; // subtract "c/"
    let check_dir = vault_path.join("c");
    let result = determine_in_dir(&check_dir, sub_path_length, MIN_CIPHER_NAME_LENGTH, MAX_CIPHER_NAME_LENGTH);
    let _ = std::fs::remove_dir_all(&check_dir);
    result
}

fn determine_in_dir(dir: &Path, sub_path_length: usize, min: usize, max: usize) -> io::Result<u32> {
    let filler_dir = dir.join("a".repeat(sub_path_length - 5)); // "a…a/nnn/" fills the sub path
    let result = (|| {
        std::fs::create_dir_all(filler_dir.join("nnn"))?;
        if !can_list_dir(&filler_dir) {
            return Err(io::Error::other("Unable to read dir"));
        }
        Ok(search(min, max + 1, |n| can_handle_file_name_length(&filler_dir, n)) as u32)
    })();
    let _ = std::fs::remove_dir_all(&filler_dir);
    result
}

/// Largest `n` in `[lower, upper)` for which `ok(n)` holds, assuming `ok` is monotonic and `ok(lower)`.
pub(crate) fn search(lower_incl: usize, upper_excl: usize, mut ok: impl FnMut(usize) -> bool) -> usize {
    let (mut lower, mut upper) = (lower_incl, upper_excl);
    loop {
        let mid = (lower + upper) / 2;
        if mid == lower {
            return mid;
        }
        if ok(mid) { lower = mid } else { upper = mid }
    }
}

fn can_handle_file_name_length(parent: &Path, name_length: usize) -> bool {
    let check_dir = parent.join(format!("{name_length:03}"));
    let check_file = check_dir.join("a".repeat(name_length));
    let result = std::fs::create_dir_all(&check_dir)
        .and_then(|_| match std::fs::File::create_new(&check_file) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
            Err(e) => Err(e),
        })
        .map(|_| can_list_dir(&check_dir))
        .unwrap_or(false);
    let _ = std::fs::remove_file(&check_file);
    let _ = std::fs::remove_dir_all(&check_dir);
    result
}

fn can_list_dir(dir: &Path) -> bool {
    std::fs::read_dir(dir).map(|mut entries| entries.next().map_or(true, |e| e.is_ok())).unwrap_or(false)
}
```

`lib.rs`: `pub use fs::{decrypt_filename, determine_supported_cleartext_file_name_length};`

- [ ] **Step 3: Tests**

Run: `cargo test -p cryptomator-core fs::name_decryptor fs::capabilities`
Expected: PASS (3 tests)

- [ ] **Step 4: Gate + Commit** ("Add ciphertext name decryption and file name length probing")

---

### Task 12: CLI `crypto fs ls|tree|cat|get|put|rm|mkdir|mv`

**Files:**
- Modify: `crates/crypto/src/cli.rs`, `crates/crypto/src/main.rs`, `crates/crypto/src/commands/mod.rs`, `crates/crypto/src/output.rs`, `crates/crypto/tests/cli.rs` (move Sandbox to `tests/common/mod.rs`)
- Create: `crates/crypto/src/commands/fs.rs`, `crates/crypto/tests/common/mod.rs`, `crates/crypto/tests/cli_fs.rs`

**Interfaces:**
- Consumes: `CryptoFs`, `CleartextPath`, `OpenOptions`, `PasswordArgs`/`read_passphrase`, `locked_vault_path`, `resolve_vault_index`.
- Produces: `commands::locked_vault(ctx, reference) -> Result<(VaultSettingsJson, PathBuf)>`; `commands::fs::open_fs(ctx, reference, &PasswordArgs, needs_write: bool) -> Result<CryptoFs>`; `output::format_timestamp(SystemTime) -> String` (`YYYY-MM-DD HH:MM:SS` UTC) and `output::epoch_seconds(SystemTime) -> u64`; test helpers `tests/common/mod.rs`: `Sandbox::{new, settings, path, crypto(&[&str]) -> Command, add_fixture(name) -> PathBuf}` (copies a fixture into the sandbox and registers it with `vault add`, returns the vault path).

- [ ] **Step 1: Grammar in `cli.rs`**

```rust
    /// Read and write vault contents without mounting
    Fs {
        #[command(subcommand)]
        command: FsCommand,
    },
```

and:

```rust
#[derive(Subcommand, Debug)]
pub enum FsCommand {
    /// List a directory
    Ls(FsLsArgs),
    /// List a directory tree recursively (one path per line; --json like the fixture manifests)
    Tree(FsTreeArgs),
    /// Print a file to standard output
    Cat(FsPathArgs),
    /// Copy a file out of the vault
    Get(FsGetArgs),
    /// Copy a file into the vault
    Put(FsPutArgs),
    /// Delete a file, symlink or (empty) directory
    Rm(FsRmArgs),
    /// Create a directory
    Mkdir(FsMkdirArgs),
    /// Move or rename a file, symlink or directory
    Mv(FsMvArgs),
}

#[derive(Args, Debug)]
pub struct FsLsArgs {
    /// Vault id, display name or path
    pub vault: String,
    /// Cleartext directory
    #[arg(default_value = "/")]
    pub path: String,
    /// Long listing: type, size, modification time, name
    #[arg(short = 'l', long)]
    pub long: bool,
    #[command(flatten)]
    pub password: PasswordArgs,
}

#[derive(Args, Debug)]
pub struct FsTreeArgs {
    pub vault: String,
    #[arg(default_value = "/")]
    pub path: String,
    /// Include the SHA-256 of every file (reads all content)
    #[arg(long)]
    pub hash: bool,
    #[command(flatten)]
    pub password: PasswordArgs,
}

#[derive(Args, Debug)]
pub struct FsPathArgs {
    pub vault: String,
    /// Cleartext path
    pub path: String,
    #[command(flatten)]
    pub password: PasswordArgs,
}

#[derive(Args, Debug)]
pub struct FsGetArgs {
    pub vault: String,
    /// Cleartext file
    pub path: String,
    /// Local destination file, or "-" for standard output
    pub local: PathBuf,
    /// Overwrite an existing local file
    #[arg(long)]
    pub force: bool,
    #[command(flatten)]
    pub password: PasswordArgs,
}

#[derive(Args, Debug)]
pub struct FsPutArgs {
    pub vault: String,
    /// Local source file, or "-" for standard input (not combinable with --password-stdin)
    pub local: PathBuf,
    /// Cleartext destination file (the full name, not a directory)
    pub path: String,
    /// Overwrite an existing vault file
    #[arg(long)]
    pub force: bool,
    #[command(flatten)]
    pub password: PasswordArgs,
}

#[derive(Args, Debug)]
pub struct FsRmArgs {
    pub vault: String,
    pub path: String,
    /// Delete directories with their contents
    #[arg(short = 'r', long)]
    pub recursive: bool,
    #[command(flatten)]
    pub password: PasswordArgs,
}

#[derive(Args, Debug)]
pub struct FsMkdirArgs {
    pub vault: String,
    pub path: String,
    /// Create missing parent directories; no error if the directory exists
    #[arg(short = 'p', long)]
    pub parents: bool,
    #[command(flatten)]
    pub password: PasswordArgs,
}

#[derive(Args, Debug)]
pub struct FsMvArgs {
    pub vault: String,
    pub source: String,
    /// Destination path (never "into" an existing directory)
    pub destination: String,
    /// Replace an existing destination (directories only if empty)
    #[arg(long)]
    pub force: bool,
    #[command(flatten)]
    pub password: PasswordArgs,
}
```

`main.rs`: `Command::Fs { command } => commands::fs::run(&ctx, command),`.

- [ ] **Step 2: Test helpers `crates/crypto/tests/common/mod.rs`**

Move `Sandbox` (struct, `new`, `settings`, `path`, `crypto`) unchanged from `tests/cli.rs` to here (`cli.rs` gets `mod common; use common::{Sandbox, PW};`), plus:

```rust
pub fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

pub fn copy_recursively(src: &Path, dst: &Path) {
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let target = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            std::fs::create_dir(&target).unwrap();
            copy_recursively(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

impl Sandbox {
    /// Copies a fixture vault into the sandbox and registers it under its name.
    pub fn add_fixture(&self, name: &str) -> PathBuf {
        let vault = self.path(name);
        std::fs::create_dir(&vault).unwrap();
        copy_recursively(&fixtures_root().join(name), &vault);
        self.crypto(&["vault", "add"]).arg(&vault).assert().success();
        vault
    }
}
```

- [ ] **Step 3: Failing tests `crates/crypto/tests/cli_fs.rs`**

```rust
mod common;

use assert_cmd::prelude::*;
use common::{fixtures_root, Sandbox};
use predicates::prelude::*;
use serde_json::Value;

fn json(out: &[u8]) -> Value {
    serde_json::from_slice(out).unwrap()
}

#[test]
fn fixture_trees_match_expected_json() {
    let sb = Sandbox::new();
    for name in ["siv_gcm_basic", "siv_ctrmac_basic", "long_names", "symlinks", "unicode", "nested", "sizes", "threshold_36"] {
        sb.add_fixture(name);
        let out = sb.crypto(&["--json", "fs", "tree", name, "--hash"]).assert().success().get_output().stdout.clone();
        let expected: Value = serde_json::from_slice(&std::fs::read(fixtures_root().join(name).join("expected.json")).unwrap()).unwrap();
        assert_eq!(json(&out), expected, "{name}");
    }
}

#[test]
fn ls_cat_and_get() {
    let sb = Sandbox::new();
    sb.add_fixture("siv_gcm_basic");
    sb.crypto(&["fs", "ls", "siv_gcm_basic"]).assert().success().stdout("docs/\nhello.txt\n");
    let out = sb.crypto(&["--json", "fs", "ls", "siv_gcm_basic", "-l"]).assert().success().get_output().stdout.clone();
    let entries = json(&out);
    assert_eq!(entries[0]["name"], "docs");
    assert_eq!(entries[0]["type"], "dir");
    assert_eq!(entries[1]["name"], "hello.txt");
    assert_eq!(entries[1]["size"], 20);
    assert!(entries[1]["modified"].is_u64());
    sb.crypto(&["fs", "ls", "siv_gcm_basic", "-l"]).assert().success().stdout(predicate::str::contains("f         20 ").and(predicate::str::contains("hello.txt")));
    sb.crypto(&["fs", "cat", "siv_gcm_basic", "/hello.txt"]).assert().success().stdout("Hello, Cryptomator!\n");
    sb.crypto(&["fs", "cat", "siv_gcm_basic", "docs/notes.md"]).assert().success().stdout("# Notes\n\nsome text\n");
    sb.crypto(&["fs", "cat", "siv_gcm_basic", "/docs"]).assert().code(1).stderr(predicate::str::contains("is a directory"));
    sb.crypto(&["fs", "cat", "siv_gcm_basic", "/nope"]).assert().code(1).stderr(predicate::str::contains("no such file"));
    let local = sb.path("out.txt");
    sb.crypto(&["fs", "get", "siv_gcm_basic", "/hello.txt"]).arg(&local).assert().success();
    assert_eq!(std::fs::read_to_string(&local).unwrap(), "Hello, Cryptomator!\n");
    sb.crypto(&["fs", "get", "siv_gcm_basic", "/hello.txt"]).arg(&local).assert().code(1).stderr(predicate::str::contains("already exists"));
    sb.crypto(&["fs", "get", "siv_gcm_basic", "/hello.txt", "--force"]).arg(&local).assert().success();
    sb.crypto(&["fs", "get", "siv_gcm_basic", "/hello.txt", "-"]).assert().success().stdout("Hello, Cryptomator!\n");
    // symlink listing shows the target; ls of the link itself follows it
    sb.add_fixture("symlinks");
    sb.crypto(&["fs", "ls", "symlinks", "-l"]).assert().success().stdout(predicate::str::contains("relative-link -> target.txt"));
    sb.crypto(&["fs", "cat", "symlinks", "/relative-link"]).assert().success().stdout("link target\n");
}

#[test]
fn put_mkdir_mv_rm_round_trip() {
    let sb = Sandbox::new();
    sb.crypto(&["vault", "create"]).arg(sb.path("v")).assert().success();
    sb.crypto(&["fs", "mkdir", "v", "/docs"]).assert().success();
    sb.crypto(&["fs", "mkdir", "v", "/docs"]).assert().code(1).stderr(predicate::str::contains("already exists"));
    sb.crypto(&["fs", "mkdir", "v", "/a/b/c"]).assert().code(1);
    sb.crypto(&["fs", "mkdir", "v", "-p", "/a/b/c"]).assert().success();
    let local = sb.path("in.txt");
    std::fs::write(&local, "put me\n").unwrap();
    sb.crypto(&["fs", "put", "v"]).arg(&local).arg("/docs/in.txt").assert().success();
    sb.crypto(&["fs", "put", "v"]).arg(&local).arg("/docs/in.txt").assert().code(1).stderr(predicate::str::contains("already exists"));
    sb.crypto(&["fs", "put", "v"]).arg(&local).arg("/docs").assert().code(1).stderr(predicate::str::contains("is a directory"));
    std::fs::write(&local, "replaced\n").unwrap();
    sb.crypto(&["fs", "put", "v", "--force"]).arg(&local).arg("/docs/in.txt").assert().success();
    sb.crypto(&["fs", "cat", "v", "/docs/in.txt"]).assert().success().stdout("replaced\n");
    sb.crypto(&["fs", "put", "v", "-", "/from-stdin"]).write_stdin("stdin data").assert().success();
    sb.crypto(&["fs", "cat", "v", "/from-stdin"]).assert().success().stdout("stdin data");
    sb.crypto(&["fs", "put", "v", "-", "/x", "--password-stdin"]).assert().code(2);
    let long = "n".repeat(200);
    sb.crypto(&["fs", "put", "v", "-"]).arg(format!("/docs/{long}")).write_stdin("long").assert().success();
    sb.crypto(&["fs", "mv", "v", "/docs/in.txt", "/a/b/c/moved.txt"]).assert().success();
    sb.crypto(&["fs", "mv", "v", "/from-stdin", "/a/b/c/moved.txt"]).assert().code(1).stderr(predicate::str::contains("already exists"));
    sb.crypto(&["fs", "mv", "v", "/from-stdin", "/a/b/c/moved.txt", "--force"]).assert().success();
    sb.crypto(&["fs", "cat", "v", "/a/b/c/moved.txt"]).assert().success().stdout("stdin data");
    sb.crypto(&["fs", "mv", "v", "/a", "/renamed"]).assert().success();
    let out = sb.crypto(&["--json", "fs", "tree", "v"]).assert().success().get_output().stdout.clone();
    let paths: Vec<String> = json(&out).as_array().unwrap().iter().map(|e| e["path"].as_str().unwrap().to_string()).collect();
    assert_eq!(paths, vec!["/WELCOME.rtf", "/docs", format!("/docs/{long}"), "/renamed", "/renamed/b", "/renamed/b/c", "/renamed/b/c/moved.txt"]);
    sb.crypto(&["fs", "tree", "v", "/renamed"]).assert().success().stdout("/renamed/b\n/renamed/b/c\n/renamed/b/c/moved.txt\n");
    sb.crypto(&["fs", "rm", "v", "/renamed"]).assert().code(1).stderr(predicate::str::contains("not empty"));
    sb.crypto(&["fs", "rm", "v", "-r", "/renamed"]).assert().success();
    sb.crypto(&["fs", "rm", "v", "/docs/".to_string().as_str()]).assert().code(1);
    sb.crypto(&["fs", "rm", "v", "-r", "/docs"]).assert().success();
    sb.crypto(&["fs", "rm", "v", "/WELCOME.rtf"]).assert().success();
    sb.crypto(&["--json", "fs", "ls", "v"]).assert().success().stdout("[]\n");
    // the vault is still valid for the core walker
    sb.crypto(&["fs", "rm", "v", "/"]).assert().code(1);
}

#[test]
fn read_only_setting_and_password_errors() {
    let sb = Sandbox::new();
    sb.crypto(&["vault", "create"]).arg(sb.path("v")).assert().success();
    sb.crypto(&["vault", "set", "v", "--read-only", "true"]).assert().success();
    sb.crypto(&["fs", "mkdir", "v", "/d"]).assert().code(5).stderr(predicate::str::contains("read-only"));
    sb.crypto(&["fs", "ls", "v"]).assert().success();
    sb.crypto(&["fs", "ls", "v"]).env("CRYPTO_PASSWORD", "wrong-password").assert().code(4);
    sb.crypto(&["fs", "ls", "nope"]).assert().code(3);
    // hub vault: rejected before any password is read
    let hub = sb.path("hub");
    std::fs::create_dir_all(hub.join("d")).unwrap();
    std::fs::write(hub.join("vault.cryptomator"), "eyJraWQiOiJodWIraHR0cHM6Ly9odWIuZXhhbXBsZS5jb20vYXBpL3ZhdWx0cy8xIiwiYWxnIjoiSFMyNTYiLCJ0eXAiOiJKV1QifQ.eyJqdGkiOiJ4IiwiZm9ybWF0Ijo4LCJjaXBoZXJDb21ibyI6IlNJVl9HQ00iLCJzaG9ydGVuaW5nVGhyZXNob2xkIjoyMjB9.AAAA").unwrap();
    std::fs::write(hub.join("masterkey.cryptomator"), "{}").unwrap();
    sb.crypto(&["vault", "add"]).arg(&hub).assert().success();
    sb.crypto(&["fs", "ls", "hub", "--password-stdin"]).write_stdin("").assert().code(9);
}
```

(Simplify `sb.crypto(&["fs","rm","v","/docs/".to_string().as_str()])` to `"/docs"` without `-r` → exit 1, because it is not empty.)

- [ ] **Step 4: Implementation `commands/mod.rs` (addition), `output.rs`, `commands/fs.rs`**

`commands/mod.rs` – build `locked_vault_path` on top of a shared helper:

```rust
/// Resolves a vault reference to its settings entry and path, requiring state LOCKED.
pub fn locked_vault(ctx: &Ctx, reference: &str) -> Result<(VaultSettingsJson, PathBuf)> {
    let settings = ctx.store.load()?;
    let index = resolve_vault_index(&settings, reference)?;
    let vault = settings.directories[index].clone();
    let path = vault.path_buf().ok_or_else(|| AppError::InvalidValue {
        key: "path".to_string(),
        message: format!("vault {} has no path", vault.id),
    })?;
    let state = determine_vault_state(&path)?;
    if state != VaultState::Locked {
        return Err(AppError::WrongState {
            expected: VaultState::Locked.as_str().to_string(),
            actual: state.as_str().to_string(),
        }
        .into());
    }
    Ok((vault, path))
}

pub fn locked_vault_path(ctx: &Ctx, reference: &str) -> Result<PathBuf> {
    locked_vault(ctx, reference).map(|(_, path)| path)
}
```

(Add `pub mod fs;` and `pub mod name;`.)

`output.rs` – time format without an extra crate (Howard Hinnant's `civil_from_days`):

```rust
use std::time::{SystemTime, UNIX_EPOCH};

pub fn epoch_seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// `YYYY-MM-DD HH:MM:SS` in UTC.
pub fn format_timestamp(time: SystemTime) -> String {
    let secs = epoch_seconds(time) as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (h, m, s) = (rem / 3600, rem % 3600 / 60, rem % 60);
    // days since 1970-01-01 → civil date (Howard Hinnant, "chrono-compatible low-level date algorithms")
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02}:{s:02}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn formats_known_instants() {
        assert_eq!(format_timestamp(UNIX_EPOCH), "1970-01-01 00:00:00");
        assert_eq!(format_timestamp(UNIX_EPOCH + Duration::from_secs(1_600_000_000)), "2020-09-13 12:26:40");
        assert_eq!(format_timestamp(UNIX_EPOCH + Duration::from_secs(951_782_400)), "2000-02-29 00:00:00");
    }
}
```

`commands/fs.rs`:

```rust
//! `crypto fs …`: mount-less access to vault contents.
use crate::cli::{FsCommand, FsGetArgs, FsLsArgs, FsMkdirArgs, FsMvArgs, FsPathArgs, FsPutArgs, FsRmArgs, FsTreeArgs};
use crate::commands::{locked_vault, Ctx};
use crate::exit;
use crate::output::{epoch_seconds, format_timestamp};
use anyhow::{Context, Result};
use cryptomator_app::{read_passphrase, AppError, PasswordArgs, SystemIo};
use cryptomator_core::fs::{CleartextPath, CryptoFs, CryptoFsOptions, EventSink, FileAttributes, DEFAULT_MAX_CLEARTEXT_NAME_LENGTH};
use cryptomator_core::{open_vault, read_vault_config, MasterkeyFileAccess};
use data_encoding::HEXLOWER;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::Arc;

/// Events are warnings on stderr (never on stdout, which carries data for `cat`/`get -`).
fn warn_sink() -> EventSink {
    Arc::new(|event| eprintln!("warning: {event}"))
}

/// Unlocks a registered LOCKED vault for mount-less access. Hub vaults are rejected before the
/// password is read; `usesReadOnlyMode` makes write commands fail with exit 5.
pub fn open_fs(ctx: &Ctx, reference: &str, password: &PasswordArgs, needs_write: bool) -> Result<CryptoFs> {
    let (vault, path) = locked_vault(ctx, reference)?;
    read_vault_config(&path)?.key_id()?.require_masterkey_file()?;
    if needs_write && vault.uses_read_only_mode {
        return Err(AppError::WrongState { expected: "writable vault".to_string(), actual: "usesReadOnlyMode=true (read-only)".to_string() }.into());
    }
    let passphrase = read_passphrase(password, "Password: ", &mut SystemIo)?;
    let opened = open_vault(&path, &MasterkeyFileAccess::new(Vec::new()), &passphrase)?;
    let max_cleartext_name_length = usize::try_from(vault.max_cleartext_filename_length).ok().filter(|n| *n > 0).unwrap_or(DEFAULT_MAX_CLEARTEXT_NAME_LENGTH);
    Ok(CryptoFs::open(opened, CryptoFsOptions { read_only: vault.uses_read_only_mode, max_cleartext_name_length, events: warn_sink() }))
}

pub fn run(ctx: &Ctx, command: FsCommand) -> Result<u8> {
    match command {
        FsCommand::Ls(args) => ls(ctx, args),
        FsCommand::Tree(args) => tree(ctx, args),
        FsCommand::Cat(args) => cat(ctx, args),
        FsCommand::Get(args) => get(ctx, args),
        FsCommand::Put(args) => put(ctx, args),
        FsCommand::Rm(args) => rm(ctx, args),
        FsCommand::Mkdir(args) => mkdir(ctx, args),
        FsCommand::Mv(args) => mv(ctx, args),
    }
}

fn entry_json(name: &str, path: &str, attrs: &FileAttributes, target: Option<&str>) -> Value {
    let mut value = json!({ "name": name, "path": path, "type": attrs.file_type.as_str() });
    if attrs.is_file() {
        value["size"] = json!(attrs.size);
    }
    value["modified"] = attrs.modified.map(|t| json!(epoch_seconds(t))).unwrap_or(Value::Null);
    if let Some(target) = target {
        value["target"] = json!(target);
    }
    value
}

fn ls(ctx: &Ctx, args: FsLsArgs) -> Result<u8> {
    let fs = open_fs(ctx, &args.vault, &args.password, false)?;
    let dir = CleartextPath::parse(&args.path);
    let mut rows = Vec::new();
    for entry in fs.read_dir(&dir).with_context(|| format!("cannot list {dir}"))? {
        let path = dir.join(&entry.cleartext_name).map_err(|e| anyhow::anyhow!(e))?;
        let attrs = fs.symlink_metadata(&path)?;
        let target = if attrs.is_symlink() { Some(fs.read_link(&path)?) } else { None };
        rows.push((entry.cleartext_name, path.to_string(), attrs, target));
    }
    let payload: Vec<Value> = rows.iter().map(|(name, path, attrs, target)| entry_json(name, path, attrs, target.as_deref())).collect();
    ctx.out.emit(Value::Array(payload), || {
        rows.iter()
            .map(|(name, _, attrs, target)| {
                if args.long {
                    let kind = match attrs.file_type.as_str() { "dir" => 'd', "symlink" => 'l', _ => 'f' };
                    let size = if attrs.is_file() { attrs.size.to_string() } else { "-".to_string() };
                    let modified = attrs.modified.map(format_timestamp).unwrap_or_else(|| "-".repeat(19));
                    let suffix = target.as_deref().map(|t| format!(" -> {t}")).unwrap_or_default();
                    format!("{kind} {size:>10} {modified}  {name}{suffix}")
                } else if attrs.is_dir() {
                    format!("{name}/")
                } else {
                    name.clone()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    })?;
    Ok(exit::OK)
}

/// Depth-first, sorted like the Java fixture generator (by cleartext path).
fn walk(fs: &CryptoFs, dir: &CleartextPath, hash: bool, out: &mut Vec<Value>) -> Result<()> {
    for entry in fs.read_dir(dir)? {
        let path = dir.join(&entry.cleartext_name).map_err(|e| anyhow::anyhow!(e))?;
        let attrs = fs.symlink_metadata(&path)?;
        let mut value = json!({ "path": path.to_string(), "type": attrs.file_type.as_str() });
        if attrs.is_symlink() {
            value["target"] = json!(fs.read_link(&path)?);
        } else if attrs.is_file() {
            value["size"] = json!(attrs.size);
            if hash {
                let mut hasher = Sha256::new();
                let size = fs.copy_to_writer(&path, &mut hasher)?;
                value["size"] = json!(size);
                value["sha256"] = json!(HEXLOWER.encode(&hasher.finalize()));
            }
        }
        out.push(value);
        if attrs.is_dir() {
            walk(fs, &path, hash, out)?;
        }
    }
    Ok(())
}

fn tree(ctx: &Ctx, args: FsTreeArgs) -> Result<u8> {
    let fs = open_fs(ctx, &args.vault, &args.password, false)?;
    let root = CleartextPath::parse(&args.path);
    let mut entries = Vec::new();
    walk(&fs, &root, args.hash, &mut entries)?;
    ctx.out.emit(Value::Array(entries.clone()), || {
        entries.iter().filter_map(|e| e["path"].as_str().map(str::to_string)).collect::<Vec<_>>().join("\n")
    })?;
    Ok(exit::OK)
}

fn cat(ctx: &Ctx, args: FsPathArgs) -> Result<u8> {
    let fs = open_fs(ctx, &args.vault, &args.password, false)?;
    let path = CleartextPath::parse(&args.path);
    let stdout = io::stdout();
    let mut lock = stdout.lock();
    fs.copy_to_writer(&path, &mut lock).with_context(|| format!("cannot read {path}"))?;
    Ok(exit::OK)
}

fn get(ctx: &Ctx, args: FsGetArgs) -> Result<u8> {
    let fs = open_fs(ctx, &args.vault, &args.password, false)?;
    let path = CleartextPath::parse(&args.path);
    if args.local == Path::new("-") {
        let stdout = io::stdout();
        let mut lock = stdout.lock();
        fs.copy_to_writer(&path, &mut lock)?;
        return Ok(exit::OK);
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .create_new(!args.force)
        .truncate(true)
        .open(&args.local)
        .with_context(|| format!("cannot create {}", args.local.display()))?;
    let bytes = fs.copy_to_writer(&path, &mut file).with_context(|| format!("cannot read {path}"))?;
    ctx.out.emit(json!({ "path": path.to_string(), "local": args.local, "bytes": bytes }), || format!("{path} -> {} ({bytes} bytes)", args.local.display()))?;
    Ok(exit::OK)
}

fn put(ctx: &Ctx, args: FsPutArgs) -> Result<u8> {
    let from_stdin = args.local == Path::new("-");
    if from_stdin && args.password.password_stdin {
        return Err(AppError::InvalidValue { key: "--password-stdin".to_string(), message: "standard input already carries the file content".to_string() }.into());
    }
    let fs = open_fs(ctx, &args.vault, &args.password, true)?;
    let path = CleartextPath::parse(&args.path);
    let bytes = if from_stdin {
        let stdin = io::stdin();
        let mut lock = stdin.lock();
        fs.write_from_reader(&path, &mut lock, args.force)
    } else {
        let mut file = std::fs::File::open(&args.local).with_context(|| format!("cannot open {}", args.local.display()))?;
        fs.write_from_reader(&path, &mut file, args.force)
    }
    .with_context(|| format!("cannot write {path}"))?;
    ctx.out.emit(json!({ "path": path.to_string(), "bytes": bytes }), || format!("{path} ({bytes} bytes)"))?;
    Ok(exit::OK)
}

fn rm(ctx: &Ctx, args: FsRmArgs) -> Result<u8> {
    let fs = open_fs(ctx, &args.vault, &args.password, true)?;
    let path = CleartextPath::parse(&args.path);
    if args.recursive { fs.delete_recursive(&path) } else { fs.delete(&path) }.with_context(|| format!("cannot delete {path}"))?;
    ctx.out.emit(json!({ "deleted": path.to_string() }), || format!("deleted {path}"))?;
    Ok(exit::OK)
}

fn mkdir(ctx: &Ctx, args: FsMkdirArgs) -> Result<u8> {
    let fs = open_fs(ctx, &args.vault, &args.password, true)?;
    let path = CleartextPath::parse(&args.path);
    if args.parents { fs.create_dir_all(&path) } else { fs.create_dir(&path) }.with_context(|| format!("cannot create {path}"))?;
    ctx.out.emit(json!({ "created": path.to_string() }), || format!("created {path}"))?;
    Ok(exit::OK)
}

fn mv(ctx: &Ctx, args: FsMvArgs) -> Result<u8> {
    let fs = open_fs(ctx, &args.vault, &args.password, true)?;
    let src = CleartextPath::parse(&args.source);
    let dst = CleartextPath::parse(&args.destination);
    fs.rename(&src, &dst, args.force).with_context(|| format!("cannot move {src} to {dst}"))?;
    ctx.out.emit(json!({ "from": src.to_string(), "to": dst.to_string() }), || format!("{src} -> {dst}"))?;
    Ok(exit::OK)
}

/// Unused imports guard: `Read`/`Write` are needed by the reader/writer trait objects above.
#[allow(dead_code)]
fn _traits(_: &dyn Read, _: &dyn Write) {}
```

(Leave out the `_traits` placeholder if `Read`/`Write` are already needed by the trait objects; otherwise remove the unused imports.) `crypto`'s `Cargo.toml` needs `sha2.workspace = true` and `data-encoding.workspace = true` as dependencies.

Error texts: anyhow contexts such as `cannot read /docs` + io error `…: is a directory` – the tests check the substrings `is a directory`, `no such file`, `already exists`, `not empty`, `read-only`.

- [ ] **Step 5: Tests**

Run: `cargo test -p crypto --test cli_fs && cargo test -p crypto --test cli`
Expected: PASS (4 new tests; the existing 20 still green, unchanged)

- [ ] **Step 6: Gate + Commit** ("Add crypto fs commands for mount-less vault access")

---

### Task 13: CLI `crypto name decrypt|locate`

**Files:**
- Modify: `crates/crypto/src/cli.rs`, `crates/crypto/src/main.rs`
- Create: `crates/crypto/src/commands/name.rs`, `crates/crypto/tests/cli_name.rs`

**Interfaces:**
- Consumes: `commands::fs::open_fs`, `cryptomator_core::fs::decrypt_filename`, `CryptoFs::{ciphertext_path, mapper}`.
- Produces: commands `name decrypt <VAULT> <CIPHERTEXT-PATH>...` and `name locate <VAULT> <CLEARTEXT-PATH> [--contents]`.

- [ ] **Step 1: Grammar**

```rust
    /// Translate between cleartext and ciphertext names
    Name {
        #[command(subcommand)]
        command: NameCommand,
    },

#[derive(Subcommand, Debug)]
pub enum NameCommand {
    /// Decrypt the names of ciphertext nodes (paths below <vault>/d/XX/YYYY/)
    Decrypt(NameDecryptArgs),
    /// Show the ciphertext node of a cleartext path
    Locate(NameLocateArgs),
}

#[derive(Args, Debug)]
pub struct NameDecryptArgs {
    pub vault: String,
    /// Ciphertext nodes (.c9r files, .c9r node directories or .c9s directories)
    #[arg(required = true)]
    pub paths: Vec<PathBuf>,
    #[command(flatten)]
    pub password: PasswordArgs,
}

#[derive(Args, Debug)]
pub struct NameLocateArgs {
    pub vault: String,
    /// Cleartext path
    pub path: String,
    /// Print the content directory of a directory, contents.c9r of a shortened file or symlink.c9r
    /// of a symlink instead of the node itself
    #[arg(long)]
    pub contents: bool,
    #[command(flatten)]
    pub password: PasswordArgs,
}
```

`main.rs`: `Command::Name { command } => commands::name::run(&ctx, command),`.

- [ ] **Step 2: Failing tests `crates/crypto/tests/cli_name.rs`**

```rust
mod common;

use assert_cmd::prelude::*;
use common::Sandbox;
use predicates::prelude::*;
use serde_json::Value;

#[test]
fn locate_and_decrypt_round_trip() {
    let sb = Sandbox::new();
    sb.add_fixture("long_names");
    let long_dir = format!("/{}", "d".repeat(200));
    let locate = |path: &str, contents: bool| -> String {
        let mut args = vec!["--json", "name", "locate", "long_names", path];
        if contents { args.push("--contents"); }
        let out = sb.crypto(&args).assert().success().get_output().stdout.clone();
        serde_json::from_slice::<Value>(&out).unwrap()["ciphertext"].as_str().unwrap().to_string()
    };
    let node = locate(&long_dir, false);
    assert!(node.ends_with(".c9s"), "{node}");
    let content_dir = locate(&long_dir, true);
    assert!(std::path::Path::new(&content_dir).join("dirid.c9r").is_file());
    let inner = locate(&format!("{long_dir}/inner.txt"), false);
    assert!(inner.ends_with(".c9r"), "{inner}");
    assert!(locate(&format!("{long_dir}/inner.txt"), true).ends_with("contents.c9r") || locate(&format!("{long_dir}/inner.txt"), true).ends_with(".c9r"));
    sb.crypto(&["name", "locate", "long_names", "/missing"]).assert().code(1).stderr(predicate::str::contains("no such file"));
    sb.crypto(&["name", "locate", "long_names", "/"]).assert().success().stdout(predicate::str::ends_with("\n"));
    // decrypt gives the names back
    sb.crypto(&["name", "decrypt", "long_names", &node, &inner]).assert().success()
        .stdout(predicate::str::contains(format!("\t{}\n", "d".repeat(200))).and(predicate::str::contains("\tinner.txt\n")));
    let out = sb.crypto(&["--json", "name", "decrypt", "long_names", &inner, "/not/in/vault/x.c9r"]).assert().code(1).get_output().stdout.clone();
    let entries: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(entries[0]["cleartext"], "inner.txt");
    assert!(entries[1]["error"].as_str().unwrap().contains("not a part of vault"));
    sb.crypto(&["name", "decrypt", "long_names"]).assert().code(2);
}
```

- [ ] **Step 3: Implementation `commands/name.rs`**

```rust
//! `crypto name decrypt|locate`
use crate::cli::{NameCommand, NameDecryptArgs, NameLocateArgs};
use crate::commands::fs::open_fs;
use crate::commands::Ctx;
use crate::exit;
use anyhow::Result;
use cryptomator_core::fs::{decrypt_filename, CleartextPath};
use serde_json::{json, Value};

pub fn run(ctx: &Ctx, command: NameCommand) -> Result<u8> {
    match command {
        NameCommand::Decrypt(args) => decrypt(ctx, args),
        NameCommand::Locate(args) => locate(ctx, args),
    }
}

/// All paths are processed; the exit code is 1 if any of them failed.
fn decrypt(ctx: &Ctx, args: NameDecryptArgs) -> Result<u8> {
    let fs = open_fs(ctx, &args.vault, &args.password, false)?;
    let mut failed = false;
    let rows: Vec<Value> = args
        .paths
        .iter()
        .map(|path| match decrypt_filename(fs.vault_path(), fs.cryptor_ref(), path) {
            Ok(name) => json!({ "ciphertext": path, "cleartext": name }),
            Err(e) => {
                failed = true;
                json!({ "ciphertext": path, "error": e.to_string() })
            }
        })
        .collect();
    ctx.out.emit(Value::Array(rows.clone()), || {
        rows.iter()
            .map(|row| match row.get("cleartext").and_then(Value::as_str) {
                Some(name) => format!("{}\t{name}", row["ciphertext"].as_str().unwrap_or_default()),
                None => format!("{}\terror: {}", row["ciphertext"].as_str().unwrap_or_default(), row["error"].as_str().unwrap_or_default()),
            })
            .collect::<Vec<_>>()
            .join("\n")
    })?;
    Ok(if failed { exit::GENERAL } else { exit::OK })
}

fn locate(ctx: &Ctx, args: NameLocateArgs) -> Result<u8> {
    let fs = open_fs(ctx, &args.vault, &args.password, false)?;
    let path = CleartextPath::parse(&args.path);
    let file_type = fs.mapper().ciphertext_file_type(&path)?;
    let ciphertext = if args.contents || path.is_root() {
        fs.ciphertext_path(&path)?
    } else {
        fs.mapper().ciphertext_file_path(&path)?.raw_path().to_path_buf()
    };
    ctx.out.emit(json!({ "cleartext": path.to_string(), "ciphertext": ciphertext, "type": file_type.as_str() }), || ciphertext.display().to_string())?;
    Ok(exit::OK)
}
```

For this, `CryptoFs` needs public access to the cryptor: add `pub fn cryptor_ref(&self) -> &Cryptor { &self.cryptor }` in `crypto_fs.rs` (the `pub(crate) cryptor()` from Task 9 can be switched over to it).

- [ ] **Step 4: Tests**

Run: `cargo test -p crypto --test cli_name`
Expected: PASS

- [ ] **Step 5: Gate + Commit** ("Add crypto name decrypt and locate")

---

### Task 14: Bidirectional Java interop test and documentation

**Files:**
- Modify: `crates/crypto/tests/java_interop.rs`, `README.md`, `CHANGELOG.md`, `docs/superpowers/specs/2026-09-04-crypto-cli-design.md`

- [ ] **Step 1: Add interop test** (in `java_interop.rs`, reuse the existing helpers `repo_root`, `verify_with_java`)

```rust
use cryptomator_core::fs::{CleartextPath, CryptoFs, CryptoFsOptions};
use cryptomator_core::{open_vault, MasterkeyFileAccess};

/// A tree written by `CryptoFs` (long names, unicode, sizes at chunk boundaries, symlinks, nesting)
/// is read by the real cryptofs; the Java manifest equals `crypto fs tree --json --hash`.
#[test]
#[ignore = "needs Java + Maven; run with --ignored"]
fn java_reads_a_tree_written_by_crypto_fs() {
    let dir = tempfile::tempdir().unwrap();
    let settings = dir.path().join("settings.json");
    let vault = dir.path().join("rust-tree");
    let crypto = |args: &[&str]| {
        let mut cmd = Command::cargo_bin("crypto").unwrap();
        cmd.env_remove("CRYPTO_SETTINGS_PATH").env_remove("CRYPTO_MIN_PW_LENGTH").env("CRYPTO_PASSWORD", "interop-passphrase").arg("--settings").arg(&settings).args(args);
        cmd
    };
    crypto(&["vault", "create", "--name", "tree"]).arg(&vault).assert().success();
    {
        let opened = open_vault(&vault, &MasterkeyFileAccess::new(Vec::new()), "interop-passphrase").unwrap();
        let fs = CryptoFs::open(opened, CryptoFsOptions::default());
        fs.delete(&CleartextPath::parse("/WELCOME.rtf")).unwrap();
        fs.create_dir_all(&CleartextPath::parse("/l1/l2/l3/l4/l5")).unwrap();
        fs.write_file(&CleartextPath::parse("/l1/l2/l3/l4/l5/deep.txt"), b"deep\n", false).unwrap();
        for size in [0usize, 1, 32_767, 32_768, 32_769, 65_536, 100_000] {
            let data: Vec<u8> = (0..size).map(|i| (i * 7) as u8).collect();
            fs.write_file(&CleartextPath::parse(&format!("/size-{size}.bin")), &data, false).unwrap();
        }
        fs.write_file(&CleartextPath::parse(&format!("/{}.txt", "c".repeat(200))), b"200 chars\n", false).unwrap();
        fs.create_dir(&CleartextPath::parse(&format!("/{}", "d".repeat(200)))).unwrap();
        fs.write_file(&CleartextPath::parse(&format!("/{}/inner.txt", "d".repeat(200))), b"inside long dir\n", false).unwrap();
        fs.write_file(&CleartextPath::parse("/Grüße 🚀.txt"), b"nfc\n", false).unwrap();
        fs.write_file(&CleartextPath::parse("/cafe\u{301}.txt"), b"nfd input, nfc name\n", false).unwrap();
        fs.create_dir(&CleartextPath::parse("/日本語")).unwrap();
        fs.write_file(&CleartextPath::parse("/日本語/ファイル.txt"), b"japanese\n", false).unwrap();
        fs.write_file(&CleartextPath::parse("/target.txt"), b"link target\n", false).unwrap();
        fs.create_symlink(&CleartextPath::parse("/relative-link"), "target.txt").unwrap();
        fs.create_symlink(&CleartextPath::parse("/absolute-link"), "/target.txt").unwrap();
        fs.create_symlink(&CleartextPath::parse("/dangling"), "does-not-exist").unwrap();
        // a rename and an overwrite exercise the mutation paths before Java looks
        fs.rename(&CleartextPath::parse("/size-1.bin"), &CleartextPath::parse("/l1/one.bin"), false).unwrap();
        fs.write_file(&CleartextPath::parse("/size-0.bin"), b"", true).unwrap();
        fs.close().unwrap();
    }
    let java = verify_with_java(&vault, "interop-passphrase");
    let out = crypto(&["--json", "fs", "tree", "tree", "--hash"]).assert().success().get_output().stdout.clone();
    let rust: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(rust, java, "Java manifest differs from crypto fs tree");
    assert_eq!(java.as_array().unwrap().len(), 22, "{java}");
    assert!(java.as_array().unwrap().iter().any(|e| e["path"] == "/caf\u{e9}.txt"), "NFC name");
}
```

Note on the comparison: Java sorts children per directory by `Path.toString()` (UTF-16 comparison); `fs tree` sorts by `cleartext_name` (UTF-8 byte comparison). For BMP characters both orderings are identical, for emoji (surrogate pairs) not necessarily – **`fs tree` therefore sorts per directory by UTF-16 code units** (`name.encode_utf16().collect::<Vec<u16>>()` as the sort key in `walk`, both in `commands/fs.rs` and – irrelevant for the test from Task 9 – not in `DirectoryLister`). If the comparison still fails on the ordering, sort both arrays by `path` before the `assert_eq!`.

- [ ] **Step 2: Documentation**

`README.md` – add rows to the "Commands" table for `fs ls|tree|cat|get|put|rm|mkdir|mv` and `name decrypt|locate` (one example each, e.g. `crypto fs put Secret ./report.pdf /2026/report.pdf`, `crypto fs tree Secret --json --hash`, `crypto name locate Secret /2026/report.pdf --contents`). New section "Mount-less access": the vault must be `LOCKED` (no running mount), password sources as above, `usesReadOnlyMode` is respected, `fs put -` excludes `--password-stdin`, cleartext names are NFC-normalized, when listing, sync conflict copies are renamed as in the desktop app (`name (1).ext`), `fs mv` never moves into a destination directory, `--force` replaces (directories only if empty), `fs rm` deletes directories only with `-r`.

`CHANGELOG.md` – `### M3 – File system and mount-less operations` under `## Unreleased`: `cryptomator_core::fs` (path mapper, listing with conflict resolution, long names, chunk cache, symlinks, attributes, events, statistics, name decryption, capability probe), CLI `fs *` and `name *`, bidirectional interop test, and the five deliberate deviations from the Global Constraints.

Spec – milestone table M3 ✅ (with a footnote as for M2: directory cache without expiry until M4); in the `cryptomator-core` table, add the sentence "relative targets are resolved against the parent directory of the link (POSIX semantics, deviation from cryptofs)" to `fs/symlinks.rs`.

- [ ] **Step 3: Gate + Commit**

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked && cargo test -p crypto --test java_interop --locked -- --ignored`
Expected: PASS (3 interop tests)

```bash
git add crates/crypto/tests/java_interop.rs README.md CHANGELOG.md docs/superpowers/specs/2026-09-04-crypto-cli-design.md
git commit -m "Verify crypto-written trees with cryptofs and document M3

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

## Self-check

- **Spec coverage M3:** `fs/dir_id.rs`, `fs/long_names.rs` (Tasks 2, 3); `fs/path_mapper.rs` with cache and prefix invalidation (4); `fs/dir_stream.rs` listing pipeline incl. conflicts, `.c9u`, BrokenDirectoryFilter (5); `fs/open_file.rs`/`fs/open_files.rs` chunk cache 5, dirty flags, read_at/write_at/truncate/flush, sparse zero fill, registry, two-phase move (6, 7); `fs/symlinks.rs`, `fs/attrs.rs`, `fs/events.rs`, `fs/stats.rs` (1, 8); `fs/crypto_fs.rs` facade with open/read_dir/metadata/create_dir/delete/rename/copy/symlink/read_link/set_times (9, 10); `fs/capabilities.rs`, `fs/name_decryptor.rs` (11); `crypto fs *` (12), `crypto name decrypt/locate` (13); milestone "bidirectional interop on all fixtures; proptests": all 8 fixtures via `CryptoFs` (9) and via `fs tree` (12), Rust-written tree in Java (14), proptest for chunk boundaries (6). Not in M3 (the spec assigns it to M4): cache expiry, `FileIsInUseEvent`/`.c9u` creation (Hub-only, excluded), `fs` access to mounted vaults.
- **Type consistency:** `CleartextPath::{parse, join, join_path, parent, file_name, is_root, starts_with, rebase}` (1) in 4, 5, 8, 9, 10, 12, 13; `EventSink`/`FilesystemEvent::{BrokenDirFile, BrokenFileNode, ConflictResolved, ConflictResolutionFailed, DecryptionFailed}` (1) in 3, 4, 5, 6; `CiphertextFilePath::{raw_path, file_path, dir_file_path, symlink_file_path, inflated_name_path, is_shortened, persist_long_file_name}` (2) in 4, 5, 8, 9, 10, 13; `DirIdLoader::{load, delete, move_id}` (3) in 4, 9, 10; `CryptoPathMapper::{ciphertext_file_type, ciphertext_file_path, ciphertext_dir, resolve_directory, resolve_directory_id, assert_non_existing, invalidate_path_mapping, move_path_mapping, shortening_threshold, root}` (4) in 5, 8, 9, 10, 13; `DirectoryLister{mapper, cryptor, events, read_only}.list` (5) in 9, 10; `OpenOptions::{read_only, read_write, write_new, write_truncate, normalized}`, `OpenCryptoFile::{size, read_at, write_at, truncate, flush, sync, path, set_path, reopen_writable, retain, release, last_modified, set_last_modified, persist_last_modified}` (6) in 7, 8; `OpenCryptoFiles::{open, get, delete, prepare_move, close_all}`, `FileHandle::{read_at, read_exact_at, write_at, write_all_at, truncate, size, flush, close}`, `RngFactory` (7) in 8, 9, 10; `attributes_of`, `FileAttributes::{is_dir, is_file, is_symlink, size, modified, file_type}` (8) in 9, 12; `Symlinks::{create_symbolic_link, read_symbolic_link, resolve_recursively}` (8) in 9, 10; `CryptoFs::{open, with_rng, read_dir, metadata, symlink_metadata, ciphertext_path, open_file, read_file, write_file, copy_to_writer, write_from_reader, create_dir, create_dir_all, create_symlink, read_link, close, mapper, cryptor_ref, vault_path, config, stats}` (9, 10, 13) in 11–14; `decrypt_filename(vault_path, cryptor, node)` (11) in 13; `open_fs`, `locked_vault` (12) in 13; `Sandbox::add_fixture` (12) in 13.
- **Placeholders:** none (the two flagged "placeholder warnings" in Tasks 3 and 12 explicitly instruct the implementer **not** to adopt the snippet in question).
- **Exit code mapping:** io errors of the fs layer → 1 (`GENERAL`, with context in the text), `WrongState` (LOCKED or read-only) → 5, `InvalidValue` (`put -` + `--password-stdin`) → 2, `InvalidPassphrase` → 4, `VaultNotFound` → 3, Hub → 9; `name decrypt` with partial errors → 1 after the complete output.

## Execution

`superpowers:subagent-driven-development` with Opus 5 subagents as in M1/M2; Task 14 requires Java + Maven (available locally). Order strictly 1 → 14 (each task builds on the interfaces of the previous one).
