//! `CryptoFileSystemImpl`: the cleartext view of a vault. Every method takes `&self`; the caches
//! and open files are protected by mutexes so the same instance can serve a FUSE session.
use super::attrs::{attributes_of, FileAttributes};
use super::ciphertext_path::CiphertextFileType;
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
        Self {
            read_only: false,
            max_cleartext_name_length: DEFAULT_MAX_CLEARTEXT_NAME_LENGTH,
            events: discard_events(),
        }
    }
}

impl std::fmt::Debug for CryptoFsOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoFsOptions")
            .field("read_only", &self.read_only)
            .field("max_cleartext_name_length", &self.max_cleartext_name_length)
            .finish_non_exhaustive()
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
        f.debug_struct("CryptoFs")
            .field("vault_path", &self.vault_path)
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

impl CryptoFs {
    pub fn open(vault: OpenedVault, options: CryptoFsOptions) -> Self {
        Self::with_rng(
            vault,
            options,
            Box::new(OsRng),
            Arc::new(|| Box::new(OsRng)),
        )
    }

    /// Like [`open`](Self::open) with explicit RNGs (deterministic tests). The masterkey inside
    /// `vault` is dropped (zeroised) here; only the derived `Cryptor` lives on.
    pub fn with_rng(
        vault: OpenedVault,
        options: CryptoFsOptions,
        rng: Box<dyn Rng + Send>,
        rng_factory: RngFactory,
    ) -> Self {
        let OpenedVault {
            path,
            config,
            cryptor,
            masterkey,
        } = vault;
        drop(masterkey);
        let cryptor = Arc::new(cryptor);
        let stats = Arc::new(CryptoFsStats::default());
        let dir_ids = Arc::new(DirIdLoader::new(options.events.clone()));
        let mapper = Arc::new(CryptoPathMapper::new(
            &path,
            cryptor.clone(),
            dir_ids.clone(),
            config.shortening_threshold,
            options.events.clone(),
        ));
        let open_files = Arc::new(OpenCryptoFiles::new(
            cryptor.clone(),
            stats.clone(),
            options.events.clone(),
            rng_factory,
        ));
        let symlinks = Symlinks::new(mapper.clone(), open_files.clone(), options.read_only);
        Self {
            vault_path: path,
            cryptor,
            config,
            dir_ids,
            mapper,
            open_files,
            symlinks,
            stats,
            options,
            rng: Mutex::new(rng),
        }
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
    // consumed by the mutating operations added in the next task
    #[allow(dead_code)]
    pub(crate) fn cryptor(&self) -> &Arc<Cryptor> {
        &self.cryptor
    }

    fn assert_writable(&self) -> io::Result<()> {
        if self.options.read_only {
            Err(super::read_only_fs())
        } else {
            Ok(())
        }
    }

    /// `assertCleartextNameLengthAllowed` (chars, like Java's `String.length()` for BMP names)
    fn assert_cleartext_name_length_allowed(&self, path: &CleartextPath) -> io::Result<()> {
        let len = path.file_name().map(|n| n.chars().count()).unwrap_or(0);
        if len > self.options.max_cleartext_name_length {
            return Err(super::name_too_long(
                path,
                self.options.max_cleartext_name_length,
            ));
        }
        Ok(())
    }

    fn lister(&self) -> DirectoryLister<'_> {
        DirectoryLister {
            mapper: &self.mapper,
            cryptor: &self.cryptor,
            events: &self.options.events,
            read_only: self.options.read_only,
        }
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
        attributes_of(
            &ciphertext_path,
            file_type,
            &self.cryptor,
            self.open_files.get(&ciphertext_path),
            self.options.read_only,
        )
    }

    fn ciphertext_path_for(
        &self,
        path: &CleartextPath,
        file_type: CiphertextFileType,
    ) -> io::Result<PathBuf> {
        Ok(match file_type {
            CiphertextFileType::Directory => self.mapper.ciphertext_dir(path)?.path,
            CiphertextFileType::Symlink => {
                self.mapper.ciphertext_file_path(path)?.symlink_file_path()
            }
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
            Err(e)
                if e.kind() == io::ErrorKind::NotFound
                    && (options.create || options.create_new) =>
            {
                CiphertextFileType::File
            }
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

    fn open_regular_file(
        &self,
        path: &CleartextPath,
        options: OpenOptions,
    ) -> io::Result<FileHandle> {
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
            if e.kind() == io::ErrorKind::NotFound {
                super::not_found(path)
            } else {
                e
            }
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
        self.write_from_reader(path, &mut &data[..], overwrite)
            .map(|_| ())
    }

    /// Encrypts everything read from `input` into a new (or, with `overwrite`, truncated) file.
    pub fn write_from_reader(
        &self,
        path: &CleartextPath,
        input: &mut dyn Read,
        overwrite: bool,
    ) -> io::Result<u64> {
        let options = if overwrite {
            OpenOptions::write_truncate()
        } else {
            OpenOptions::write_new()
        };
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
            if e.kind() == io::ErrorKind::AlreadyExists {
                super::already_exists(dir)
            } else {
                e
            }
        })?;
        let write_dir_file = || -> io::Result<()> {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&dir_file)?;
            file.write_all(ciphertext_dir.dir_id.as_bytes())
        };
        let result = write_dir_file().and_then(|_| {
            std::fs::create_dir_all(&ciphertext_dir.path)?;
            let mut rng = super::lock(&self.rng);
            write_dir_id_backup(&self.cryptor, &ciphertext_dir, rng.as_mut())?;
            drop(rng);
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
            current = current
                .join(element)
                .map_err(|e| super::invalid_input(e.to_string()))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rng::DetRng;
    use crate::fs::testutil;
    use crate::{open_vault_with_key, CipherCombo};

    pub(crate) fn test_fs(threshold: u32, read_only: bool) -> (tempfile::TempDir, CryptoFs) {
        let (dir, _, _) = testutil::new_vault(threshold);
        let opened = open_vault_with_key(dir.path(), testutil::masterkey()).unwrap();
        let options = CryptoFsOptions {
            read_only,
            ..Default::default()
        };
        let fs = CryptoFs::with_rng(
            opened,
            options,
            Box::new(DetRng::default()),
            Arc::new(|| Box::new(DetRng::default())),
        );
        assert_eq!(fs.config().cipher_combo, CipherCombo::SivGcm);
        (dir, fs)
    }

    #[test]
    fn creates_directories_files_and_symlinks() {
        let (_dir, fs) = test_fs(220, false);
        let docs = CleartextPath::parse("/docs");
        fs.create_dir(&docs).unwrap();
        assert_eq!(
            fs.create_dir(&docs).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(
            fs.create_dir(&CleartextPath::parse("/a/b"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        fs.create_dir_all(&CleartextPath::parse("/a/b/c")).unwrap();
        fs.create_dir_all(&CleartextPath::parse("/a/b/c")).unwrap();
        let notes = docs.join("notes.md").unwrap();
        fs.write_file(&notes, b"# Notes\n", false).unwrap();
        assert_eq!(
            fs.write_file(&notes, b"x", false).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        fs.write_file(&notes, b"# Notes v2\n", true).unwrap();
        assert_eq!(fs.read_file(&notes).unwrap(), b"# Notes v2\n");
        assert_eq!(fs.metadata(&notes).unwrap().size, 11);
        fs.create_symlink(&CleartextPath::parse("/link"), "docs/notes.md")
            .unwrap();
        assert_eq!(
            fs.read_link(&CleartextPath::parse("/link")).unwrap(),
            "docs/notes.md"
        );
        assert_eq!(
            fs.metadata(&CleartextPath::parse("/link")).unwrap().size,
            11,
            "follows the link"
        );
        assert!(fs
            .symlink_metadata(&CleartextPath::parse("/link"))
            .unwrap()
            .is_symlink());
        assert_eq!(
            fs.read_file(&CleartextPath::parse("/link")).unwrap(),
            b"# Notes v2\n"
        );
        let names: Vec<String> = fs
            .read_dir(&CleartextPath::root())
            .unwrap()
            .into_iter()
            .map(|e| e.cleartext_name)
            .collect();
        assert_eq!(names, vec!["a", "docs", "link"]);
        assert_eq!(
            fs.create_dir_all(&notes.join("sub").unwrap())
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotADirectory
        );
        assert_eq!(
            fs.open_file(&docs, OpenOptions::read_only())
                .unwrap_err()
                .kind(),
            io::ErrorKind::IsADirectory
        );
    }

    #[test]
    fn long_names_and_name_limits() {
        let (_dir, fs) = test_fs(220, false);
        let long = CleartextPath::root().join(&"n".repeat(200)).unwrap();
        fs.create_dir(&long).unwrap();
        let inner = long.join(&"m".repeat(200)).unwrap();
        fs.write_file(&inner, b"deep", false).unwrap();
        assert!(fs
            .ciphertext_path(&inner)
            .unwrap()
            .ends_with("contents.c9r"));
        assert_eq!(fs.read_file(&inner).unwrap(), b"deep");
        let (_dir, limited) = {
            let (dir, _, _) = testutil::new_vault(220);
            let opened = open_vault_with_key(dir.path(), testutil::masterkey()).unwrap();
            let options = CryptoFsOptions {
                max_cleartext_name_length: 5,
                ..Default::default()
            };
            (
                dir,
                CryptoFs::with_rng(
                    opened,
                    options,
                    Box::new(DetRng::default()),
                    Arc::new(|| Box::new(DetRng::default())),
                ),
            )
        };
        assert_eq!(
            limited
                .create_dir(&CleartextPath::parse("/toolong"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            limited
                .write_file(&CleartextPath::parse("/toolong"), b"", false)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        limited
            .write_file(&CleartextPath::parse("/ok"), b"", false)
            .unwrap();
    }

    #[test]
    fn read_only_rejects_writes() {
        let (_dir, fs) = test_fs(220, true);
        assert_eq!(
            fs.create_dir(&CleartextPath::parse("/d"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::ReadOnlyFilesystem
        );
        assert_eq!(
            fs.write_file(&CleartextPath::parse("/f"), b"", false)
                .unwrap_err()
                .kind(),
            io::ErrorKind::ReadOnlyFilesystem
        );
        assert!(fs.read_dir(&CleartextPath::root()).unwrap().is_empty());
    }

    #[test]
    fn streaming_write_and_read_over_many_chunks() {
        let (_dir, fs) = test_fs(220, false);
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let p = CleartextPath::parse("/big");
        assert_eq!(
            fs.write_from_reader(&p, &mut &data[..], false).unwrap(),
            200_000
        );
        let mut out = Vec::new();
        assert_eq!(fs.copy_to_writer(&p, &mut out).unwrap(), 200_000);
        assert_eq!(out, data);
    }
}
