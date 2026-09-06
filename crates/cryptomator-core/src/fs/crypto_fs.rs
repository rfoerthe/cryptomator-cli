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
use crate::constants::DIR_ID_BACKUP_FILE_NAME;
use crate::crypto::rng::{OsRng, Rng};
use crate::vault::open::OpenedVault;
use crate::{Cryptor, VaultConfig};
use std::collections::HashSet;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

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

// M4 puts this facade behind `fuser::Filesystem`, which requires both.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<CryptoFs>();
};

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
    /// The longest cleartext name this file system accepts; FUSE reports it as `statfs.namelen`.
    pub fn max_cleartext_name_length(&self) -> usize {
        self.options.max_cleartext_name_length
    }
    pub fn stats(&self) -> &CryptoFsStats {
        &self.stats
    }
    pub fn mapper(&self) -> &CryptoPathMapper {
        &self.mapper
    }
    pub fn cryptor_ref(&self) -> &Cryptor {
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
        match self.file_type_for_open(path, options)? {
            CiphertextFileType::Symlink => {
                let resolved = self.symlinks.resolve_recursively(path)?;
                self.open_link_target(&resolved, options)
            }
            CiphertextFileType::File => self.open_regular_file(path, options),
            CiphertextFileType::Directory => Err(super::is_a_directory(path)),
        }
    }

    /// The node a fully resolved symlink points at. `resolve_recursively` already followed every
    /// link (and detected loops), so this never resolves again and cannot recurse; a link that ends
    /// on a directory is rejected like the directory itself.
    fn open_link_target(
        &self,
        path: &CleartextPath,
        options: OpenOptions,
    ) -> io::Result<FileHandle> {
        match self.file_type_for_open(path, options)? {
            CiphertextFileType::Directory => Err(super::is_a_directory(path)),
            _ => self.open_regular_file(path, options),
        }
    }

    /// The ciphertext type of `path`; a missing node counts as a file when it is about to be created.
    fn file_type_for_open(
        &self,
        path: &CleartextPath,
        options: OpenOptions,
    ) -> io::Result<CiphertextFileType> {
        match self.mapper.ciphertext_file_type(path) {
            Ok(t) => Ok(t),
            Err(e)
                if e.kind() == io::ErrorKind::NotFound
                    && (options.create || options.create_new) =>
            {
                Ok(CiphertextFileType::File)
            }
            Err(e) => Err(e),
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

    /// Flushes and closes every open file, and reports the first error while doing so.
    ///
    /// The `Drop` below runs immediately afterwards and calls the same
    /// [`OpenCryptoFiles::close_all`], which is idempotent: this one already drained the registry
    /// (a failing flush included), so the second call finds it empty, flushes nothing and cannot
    /// turn a reported error into a second, silent one.
    pub fn close(self) -> io::Result<()> {
        self.flush_all()
    }

    /// [`CryptoFs::close`] without consuming the file system: flushes every open file and forgets
    /// it, while the `CryptoFs` itself stays usable.
    ///
    /// For a caller that cannot take ownership -- a shared `Arc<CryptoFs>` a mount session still
    /// holds on to -- and therefore cannot call [`CryptoFs::close`]: the buffered cleartext is
    /// what must not be lost, and this is what writes it out.
    ///
    /// # Errors
    /// The first error any of the flushes reports; the remaining files are still flushed.
    pub fn flush_all(&self) -> io::Result<()> {
        self.open_files.close_all()
    }
}

impl Drop for CryptoFs {
    /// The safety net under [`CryptoFs::close`]: a mount that ends by dropping its `Arc<CryptoFs>`
    /// -- a panicking FUSE worker, a daemon that never reaches its own teardown -- must not lose
    /// the cleartext its callers wrote and this file system still buffers.
    ///
    /// A `Drop` cannot return an error, so the first one is logged. After an explicit `close` this
    /// finds an empty registry and does nothing at all.
    fn drop(&mut self) {
        if let Err(err) = self.open_files.close_all() {
            log::warn!(
                "flushing the open files of {} failed: {err}",
                self.vault_path.display()
            );
        }
    }
}

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
    matches!(
        e.kind(),
        io::ErrorKind::DirectoryNotEmpty | io::ErrorKind::AlreadyExists
    )
}

impl CryptoFs {
    /// `delete`: files and symlinks always, directories only when empty.
    pub fn delete(&self, path: &CleartextPath) -> io::Result<()> {
        self.assert_writable()?;
        if path.is_root() {
            return Err(super::invalid_input(
                "The filesystem root cannot be deleted.",
            ));
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
                self.delete_recursive(
                    &path
                        .join(&entry.cleartext_name)
                        .map_err(|e| super::invalid_input(e.to_string()))?,
                )?;
            }
        }
        self.delete(path)
    }

    fn delete_directory(
        &self,
        path: &CleartextPath,
        ciphertext: &CiphertextFilePath,
    ) -> io::Result<()> {
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
    ///
    /// Deliberate deviation from Java's `CiphertextDirectoryDeleter`: that one sweeps `dirid.c9r`
    /// together with the other leftovers, so a delete that afterwards fails with
    /// `DirectoryNotEmpty` leaves a surviving directory without its dir id backup — and nothing
    /// rewrites it. Here the backup is never swept: it is removed last, once everything else is
    /// gone and the content dir is about to go with it. If real ciphertext nodes remain, the
    /// original `DirectoryNotEmpty` is returned with `dirid.c9r` untouched.
    fn delete_ciphertext_dir_including_non_ciphertext_files(
        &self,
        ciphertext_dir: &Path,
        cleartext_dir: &CleartextPath,
    ) -> io::Result<()> {
        match std::fs::remove_dir(ciphertext_dir) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) if is_not_empty_error(&e) => {
                let ciphertext_files: HashSet<PathBuf> = self
                    .lister()
                    .list(cleartext_dir)?
                    .into_iter()
                    .map(|n| n.ciphertext_path)
                    .collect();
                let mut dir_id_backup = None;
                let mut ciphertext_nodes_left = false;
                for entry in std::fs::read_dir(ciphertext_dir)? {
                    let entry = entry?;
                    let p = entry.path();
                    if ciphertext_files.contains(&p) {
                        ciphertext_nodes_left = true;
                    } else if entry.file_name() == DIR_ID_BACKUP_FILE_NAME {
                        dir_id_backup = Some(p);
                    } else {
                        remove_recursively(&p)?;
                    }
                }
                if ciphertext_nodes_left {
                    return Err(e);
                }
                if let Some(backup) = dir_id_backup {
                    remove_recursively(&backup)?;
                }
                std::fs::remove_dir(ciphertext_dir)
            }
            Err(e) => Err(e),
        }
    }

    /// `move`: renames the ciphertext node; directories keep their content dir.
    pub fn rename(
        &self,
        src: &CleartextPath,
        dst: &CleartextPath,
        replace_existing: bool,
    ) -> io::Result<()> {
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
            CiphertextFileType::Symlink => self.move_symlink(src, dst, replace_existing),
            CiphertextFileType::File => self.move_file(src, dst, replace_existing),
            CiphertextFileType::Directory => self.move_directory(src, dst, replace_existing),
        }
    }

    /// Removes an existing *directory* node at `dst` so that another node can take its place.
    /// Only an empty directory may be replaced; its `dirid.c9r` backup does not count as content.
    /// Besides the node dir this drops the content dir and the cached mappings, which would
    /// otherwise be orphaned (content dir) resp. stale (path mapping, dir id).
    fn replace_directory_node(
        &self,
        dst: &CleartextPath,
        d: &CiphertextFilePath,
    ) -> io::Result<()> {
        let target_content_dir = self.mapper.ciphertext_dir(dst)?.path;
        let mut target_exists = true;
        match std::fs::read_dir(&target_content_dir) {
            Ok(entries) => {
                for entry in entries {
                    if entry?.file_name() != DIR_ID_BACKUP_FILE_NAME {
                        return Err(super::directory_not_empty(dst));
                    }
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
        Ok(())
    }

    /// Clears the node currently at `dst` before a rename/copy puts a new one there. A directory
    /// node needs the extra cleanup above; anything else is simply removed.
    fn clear_existing_node(
        &self,
        dst: &CleartextPath,
        d: &CiphertextFilePath,
        replace_existing: bool,
    ) -> io::Result<()> {
        if std::fs::symlink_metadata(d.raw_path()).is_err() {
            return Ok(());
        }
        let is_directory = replace_existing
            && match self.mapper.ciphertext_file_type(dst) {
                Ok(t) => t == CiphertextFileType::Directory,
                Err(e) if e.kind() == io::ErrorKind::NotFound => false,
                Err(e) => return Err(e),
            };
        if is_directory {
            self.replace_directory_node(dst, d)
        } else {
            // replace: an existing node was allowed by the caller
            remove_recursively(d.raw_path())
        }
    }

    fn move_symlink(
        &self,
        src: &CleartextPath,
        dst: &CleartextPath,
        replace_existing: bool,
    ) -> io::Result<()> {
        let s = self.mapper.ciphertext_file_path(src)?;
        let d = self.mapper.ciphertext_file_path(dst)?;
        let two_phase = self
            .open_files
            .prepare_move(&s.symlink_file_path(), &d.symlink_file_path())?;
        self.clear_existing_node(dst, &d, replace_existing)?;
        std::fs::rename(s.raw_path(), d.raw_path())?;
        if d.is_shortened() {
            d.persist_long_file_name()?;
        } else {
            remove_file_if_exists(&d.inflated_name_path())?;
        }
        two_phase.commit();
        Ok(())
    }

    fn move_file(
        &self,
        src: &CleartextPath,
        dst: &CleartextPath,
        replace_existing: bool,
    ) -> io::Result<()> {
        let s = self.mapper.ciphertext_file_path(src)?;
        let d = self.mapper.ciphertext_file_path(dst)?;
        let two_phase = self
            .open_files
            .prepare_move(&s.file_path(), &d.file_path())?;
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

    fn move_directory(
        &self,
        src: &CleartextPath,
        dst: &CleartextPath,
        replace_existing: bool,
    ) -> io::Result<()> {
        let s = self.mapper.ciphertext_file_path(src)?;
        let d = self.mapper.ciphertext_file_path(dst)?;
        if replace_existing && std::fs::symlink_metadata(d.raw_path()).is_ok() {
            let dst_type = self.mapper.ciphertext_file_type(dst)?;
            if dst_type == CiphertextFileType::Directory {
                self.replace_directory_node(dst, &d)?;
            } else {
                // do not pull an open file out from under its handle (`prepare_move` guards the
                // same case for file/symlink renames)
                let open_path = match dst_type {
                    CiphertextFileType::Symlink => d.symlink_file_path(),
                    _ => d.file_path(),
                };
                if self.open_files.get(&open_path).is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!("{dst}: destination file is currently open"),
                    ));
                }
                remove_recursively(d.raw_path())?;
            }
        }
        std::fs::rename(s.raw_path(), d.raw_path())?;
        if d.is_shortened() {
            d.persist_long_file_name()?;
        } else {
            remove_file_if_exists(&d.inflated_name_path())?;
        }
        self.dir_ids.move_id(&s.dir_file_path(), &d.dir_file_path());
        self.mapper.move_path_mapping(src, dst);
        Ok(())
    }

    /// `copy` (non-recursive for directories, like `Files.copy`): ciphertext files are copied as
    /// they are (same key, same header), symlinks copy their `symlink.c9r`.
    pub fn copy(
        &self,
        src: &CleartextPath,
        dst: &CleartextPath,
        replace_existing: bool,
    ) -> io::Result<()> {
        self.assert_writable()?;
        self.assert_cleartext_name_length_allowed(dst)?;
        if src == dst {
            return Ok(());
        }
        if dst.is_root() {
            return Err(super::invalid_input(
                "The filesystem root cannot be replaced.",
            ));
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
                self.clear_existing_node(dst, &d, replace_existing)?;
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
    pub fn set_times(
        &self,
        path: &CleartextPath,
        modified: Option<SystemTime>,
        accessed: Option<SystemTime>,
    ) -> io::Result<()> {
        self.assert_writable()?;
        let resolved = self.symlinks.resolve_recursively(path)?;
        let file_type = self.mapper.ciphertext_file_type(&resolved)?;
        let ciphertext_path = self.ciphertext_path_for(&resolved, file_type)?;
        if let (Some(modified), Some(open)) = (modified, self.open_files.get(&ciphertext_path)) {
            super::lock(&open).set_last_modified(modified);
        }
        let mut times = std::fs::FileTimes::new();
        if let Some(m) = modified {
            times = times.set_modified(m);
        }
        if let Some(a) = accessed {
            times = times.set_accessed(a);
        }
        std::fs::File::open(&ciphertext_path)?.set_times(times)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::INFLATED_FILE_NAME;
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

    #[test]
    fn delete_semantics_match_java() {
        let (_dir, fs) = test_fs(220, false);
        let d = CleartextPath::parse("/d");
        fs.create_dir(&d).unwrap();
        fs.write_file(&d.join("f").unwrap(), b"1", false).unwrap();
        fs.create_symlink(&d.join("l").unwrap(), "f").unwrap();
        assert_eq!(
            fs.delete(&CleartextPath::root()).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            fs.delete(&d).unwrap_err().kind(),
            io::ErrorKind::DirectoryNotEmpty
        );
        // a failed delete leaves the surviving directory with its dir id backup
        let dir_id_backup = fs
            .mapper()
            .ciphertext_dir(&d)
            .unwrap()
            .path
            .join(DIR_ID_BACKUP_FILE_NAME);
        assert!(dir_id_backup.exists());
        fs.delete(&d.join("l").unwrap()).unwrap();
        fs.delete(&d.join("f").unwrap()).unwrap();
        assert_eq!(
            fs.delete(&d.join("f").unwrap()).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        // stray non-ciphertext files inside the content dir do not block the delete
        std::fs::write(
            fs.mapper()
                .ciphertext_dir(&d)
                .unwrap()
                .path
                .join(".DS_Store"),
            b"x",
        )
        .unwrap();
        let content_dir = fs.mapper().ciphertext_dir(&d).unwrap().path;
        // dirid.c9r + .DS_Store are the only leftovers now, so the directory is deletable
        assert!(dir_id_backup.exists());
        fs.delete(&d).unwrap();
        assert!(!content_dir.exists());
        assert_eq!(
            fs.mapper().ciphertext_file_type(&d).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        fs.create_dir_all(&CleartextPath::parse("/x/y/z")).unwrap();
        fs.write_file(&CleartextPath::parse("/x/y/z/f"), b"deep", false)
            .unwrap();
        fs.delete_recursive(&CleartextPath::parse("/x")).unwrap();
        assert!(fs.read_dir(&CleartextPath::root()).unwrap().is_empty());
    }

    #[test]
    fn rename_files_symlinks_and_directories() {
        let (_dir, fs) = test_fs(220, false);
        fs.create_dir_all(&CleartextPath::parse("/a/sub")).unwrap();
        fs.write_file(&CleartextPath::parse("/a/sub/f"), b"content", false)
            .unwrap();
        fs.create_symlink(&CleartextPath::parse("/a/l"), "sub/f")
            .unwrap();
        fs.rename(
            &CleartextPath::parse("/a/sub/f"),
            &CleartextPath::parse("/a/g"),
            false,
        )
        .unwrap();
        assert_eq!(
            fs.read_file(&CleartextPath::parse("/a/g")).unwrap(),
            b"content"
        );
        fs.write_file(&CleartextPath::parse("/a/h"), b"other", false)
            .unwrap();
        assert_eq!(
            fs.rename(
                &CleartextPath::parse("/a/g"),
                &CleartextPath::parse("/a/h"),
                false
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::AlreadyExists
        );
        fs.rename(
            &CleartextPath::parse("/a/g"),
            &CleartextPath::parse("/a/h"),
            true,
        )
        .unwrap();
        assert_eq!(
            fs.read_file(&CleartextPath::parse("/a/h")).unwrap(),
            b"content"
        );
        // long name target: contents.c9r inside .c9s; back to a short name removes name.c9s
        let long = CleartextPath::root().join(&"L".repeat(200)).unwrap();
        fs.rename(&CleartextPath::parse("/a/h"), &long, false)
            .unwrap();
        assert!(fs.ciphertext_path(&long).unwrap().ends_with("contents.c9r"));
        fs.rename(&long, &CleartextPath::parse("/a/h"), false)
            .unwrap();
        assert!(fs
            .ciphertext_path(&CleartextPath::parse("/a/h"))
            .unwrap()
            .extension()
            .is_some_and(|e| e == "c9r"));
        fs.rename(
            &CleartextPath::parse("/a/l"),
            &CleartextPath::parse("/a/m"),
            false,
        )
        .unwrap();
        assert_eq!(
            fs.read_link(&CleartextPath::parse("/a/m")).unwrap(),
            "sub/f"
        );
        // directory rename keeps the content dir (same dir id), moves the cached mapping
        let content = fs
            .mapper()
            .ciphertext_dir(&CleartextPath::parse("/a"))
            .unwrap();
        fs.rename(
            &CleartextPath::parse("/a"),
            &CleartextPath::parse("/b"),
            false,
        )
        .unwrap();
        assert_eq!(
            fs.mapper()
                .ciphertext_dir(&CleartextPath::parse("/b"))
                .unwrap(),
            content
        );
        assert_eq!(
            fs.read_file(&CleartextPath::parse("/b/h")).unwrap(),
            b"content"
        );
        assert_eq!(
            fs.mapper()
                .ciphertext_file_type(&CleartextPath::parse("/a"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        fs.create_dir(&CleartextPath::parse("/empty")).unwrap();
        assert_eq!(
            fs.rename(
                &CleartextPath::parse("/b"),
                &CleartextPath::parse("/empty"),
                false
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::AlreadyExists
        );
        fs.rename(
            &CleartextPath::parse("/b"),
            &CleartextPath::parse("/empty"),
            true,
        )
        .unwrap();
        assert_eq!(
            fs.read_file(&CleartextPath::parse("/empty/h")).unwrap(),
            b"content"
        );
        fs.create_dir(&CleartextPath::parse("/full")).unwrap();
        fs.write_file(&CleartextPath::parse("/full/x"), b"", false)
            .unwrap();
        assert_eq!(
            fs.rename(
                &CleartextPath::parse("/empty"),
                &CleartextPath::parse("/full"),
                true
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::DirectoryNotEmpty
        );
        assert!(fs
            .rename(&CleartextPath::root(), &CleartextPath::parse("/r"), false)
            .is_err());
        fs.rename(
            &CleartextPath::parse("/empty"),
            &CleartextPath::parse("/empty"),
            false,
        )
        .unwrap();
        // an open file survives a rename
        let h = fs
            .open_file(&CleartextPath::parse("/empty/h"), OpenOptions::read_write())
            .unwrap();
        fs.rename(
            &CleartextPath::parse("/empty/h"),
            &CleartextPath::parse("/moved"),
            false,
        )
        .unwrap();
        h.write_all_at(b"X", 0).unwrap();
        h.close().unwrap();
        assert_eq!(
            fs.read_file(&CleartextPath::parse("/moved")).unwrap(),
            b"Xontent"
        );
    }

    #[test]
    fn flush_all_writes_out_open_files_without_consuming_the_fs() {
        let (_dir, fs) = test_fs(220, false);
        let path = CleartextPath::parse("/buffered");
        let handle = fs.open_file(&path, OpenOptions::write_new()).unwrap();
        handle.write_all_at(b"payload", 0).unwrap();
        let ciphertext = fs.ciphertext_path(&path).unwrap();
        // Only the header is on disk so far; the chunk sits in the write buffer.
        let buffered = std::fs::metadata(&ciphertext).unwrap().len();

        fs.flush_all().unwrap();
        let flushed = std::fs::metadata(&ciphertext).unwrap().len();
        assert!(
            flushed > buffered,
            "flush_all wrote the dirty chunk out ({buffered} -> {flushed} bytes)"
        );
        // Unlike `close`, this leaves the file system usable.
        assert_eq!(fs.read_file(&path).unwrap(), b"payload");
        fs.close().unwrap();
    }

    #[test]
    fn dropping_the_file_system_flushes_open_files() {
        let (dir, fs) = test_fs(220, false);
        let path = CleartextPath::parse("/buffered");
        let handle = fs.open_file(&path, OpenOptions::write_new()).unwrap();
        handle.write_all_at(b"payload", 0).unwrap();
        let ciphertext = fs.ciphertext_path(&path).unwrap();
        // only the header is on disk so far; the chunk sits in the write buffer
        let buffered = std::fs::metadata(&ciphertext).unwrap().len();

        drop(fs); // no close(): the Drop is the only thing that can still write the chunk out

        assert!(
            std::fs::metadata(&ciphertext).unwrap().len() > buffered,
            "the Drop wrote the dirty chunk out"
        );

        // reopen the vault: what is on disk must be the complete file
        let fs2 = reopen(dir.path());
        assert_eq!(fs2.read_file(&path).unwrap(), b"payload");
        drop(handle);
    }

    #[test]
    fn close_and_the_following_drop_do_not_flush_twice() {
        // `close(self)` consumes the fs, so its own trailing Drop cannot be observed from here
        // (control never returns to a `fs` to query). `flush_all` does the same
        // `open_files.close_all()` without consuming `self`, so this drives that instead: one
        // explicit `flush_all`, then an explicit `drop` -- the same two calls `close` makes back
        // to back -- and checks that the second one writes nothing.
        let (dir, fs) = test_fs(220, false);
        let path = CleartextPath::parse("/buffered");
        let handle = fs.open_file(&path, OpenOptions::write_new()).unwrap();
        handle.write_all_at(b"payload", 0).unwrap();

        // an owned clone of the stats outlives `fs` itself, so the second flush stays observable
        // after the `drop(fs)` below.
        let stats = fs.stats.clone();

        fs.flush_all().unwrap();
        let after_first_flush = stats.snapshot();
        assert!(
            after_first_flush.bytes_encrypted > 0,
            "the first flush must have encrypted and written the dirty chunk"
        );

        // the Drop finds an empty registry (flush_all already drained it): a real second flush
        // would encrypt and write the same chunk again and move the counters a second time
        drop(fs);
        assert_eq!(
            stats.snapshot(),
            after_first_flush,
            "the Drop must not flush a second time"
        );

        let fs2 = reopen(dir.path());
        assert_eq!(fs2.read_file(&path).unwrap(), b"payload");
        drop(handle);
    }

    /// A second `CryptoFs` on the same vault directory, for reading back what a dropped one wrote.
    fn reopen(vault: &Path) -> CryptoFs {
        let opened = open_vault_with_key(vault, testutil::masterkey()).unwrap();
        CryptoFs::with_rng(
            opened,
            CryptoFsOptions::default(),
            Box::new(DetRng::default()),
            Arc::new(|| Box::new(DetRng::default())),
        )
    }

    #[test]
    fn copy_and_set_times() {
        let (_dir, fs) = test_fs(220, false);
        fs.write_file(&CleartextPath::parse("/f"), b"data", false)
            .unwrap();
        fs.copy(
            &CleartextPath::parse("/f"),
            &CleartextPath::parse("/g"),
            false,
        )
        .unwrap();
        assert_eq!(fs.read_file(&CleartextPath::parse("/g")).unwrap(), b"data");
        assert_eq!(
            fs.copy(
                &CleartextPath::parse("/f"),
                &CleartextPath::parse("/g"),
                false
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::AlreadyExists
        );
        fs.write_file(&CleartextPath::parse("/f"), b"new", true)
            .unwrap();
        fs.copy(
            &CleartextPath::parse("/f"),
            &CleartextPath::parse("/g"),
            true,
        )
        .unwrap();
        assert_eq!(fs.read_file(&CleartextPath::parse("/g")).unwrap(), b"new");
        fs.create_symlink(&CleartextPath::parse("/l"), "f").unwrap();
        fs.copy(
            &CleartextPath::parse("/l"),
            &CleartextPath::parse("/l2"),
            false,
        )
        .unwrap();
        assert_eq!(fs.read_link(&CleartextPath::parse("/l2")).unwrap(), "f");
        fs.create_dir(&CleartextPath::parse("/d")).unwrap();
        fs.copy(
            &CleartextPath::parse("/d"),
            &CleartextPath::parse("/d2"),
            false,
        )
        .unwrap();
        assert!(fs.metadata(&CleartextPath::parse("/d2")).unwrap().is_dir());
        let t = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000);
        fs.set_times(&CleartextPath::parse("/g"), Some(t), None)
            .unwrap();
        assert_eq!(
            fs.metadata(&CleartextPath::parse("/g")).unwrap().modified,
            Some(t)
        );
        fs.set_times(&CleartextPath::parse("/d"), Some(t), Some(t))
            .unwrap();
        assert_eq!(
            fs.metadata(&CleartextPath::parse("/d")).unwrap().modified,
            Some(t)
        );
    }

    #[test]
    fn replacing_a_directory_node_removes_its_content_dir() {
        let (_dir, fs) = test_fs(220, false);
        let d = CleartextPath::parse("/d");
        let l = CleartextPath::parse("/l");
        fs.create_dir(&d).unwrap();
        fs.create_symlink(&l, "target").unwrap();
        let content_dir = fs.mapper().ciphertext_dir(&d).unwrap().path;
        assert!(content_dir.exists());
        fs.rename(&l, &d, true).unwrap();
        assert!(!content_dir.exists()); // no orphaned content dir
        assert_eq!(
            fs.mapper().ciphertext_file_type(&d).unwrap(),
            CiphertextFileType::Symlink
        );
        assert_eq!(fs.read_link(&d).unwrap(), "target");
        // the cached mapping of the replaced directory is gone (a fresh lookup no longer
        // resolves to the removed content dir)
        assert_ne!(fs.mapper().ciphertext_dir(&d).unwrap().path, content_dir);

        // copying a symlink over an empty directory cleans up the same way
        let e = CleartextPath::parse("/e");
        fs.create_dir(&e).unwrap();
        let e_content_dir = fs.mapper().ciphertext_dir(&e).unwrap().path;
        fs.copy(&d, &e, true).unwrap();
        assert!(!e_content_dir.exists());
        assert_eq!(fs.read_link(&e).unwrap(), "target");

        // a non-empty directory is never replaced by a symlink, and nothing is deleted
        let full = CleartextPath::parse("/full");
        let x = CleartextPath::parse("/full/x");
        let l2 = CleartextPath::parse("/l2");
        fs.create_dir(&full).unwrap();
        fs.write_file(&x, b"keep", false).unwrap();
        fs.create_symlink(&l2, "target").unwrap();
        assert_eq!(
            fs.rename(&l2, &full, true).unwrap_err().kind(),
            io::ErrorKind::DirectoryNotEmpty
        );
        assert_eq!(
            fs.copy(&l2, &full, true).unwrap_err().kind(),
            io::ErrorKind::DirectoryNotEmpty
        );
        assert_eq!(fs.read_file(&x).unwrap(), b"keep");
        assert_eq!(fs.read_link(&l2).unwrap(), "target");
        assert_eq!(
            fs.mapper().ciphertext_file_type(&full).unwrap(),
            CiphertextFileType::Directory
        );
    }

    #[test]
    fn renaming_a_directory_onto_an_open_file_is_rejected() {
        let (_dir, fs) = test_fs(220, false);
        let d = CleartextPath::parse("/d");
        let f = CleartextPath::parse("/f");
        fs.create_dir(&d).unwrap();
        fs.write_file(&f, b"data", false).unwrap();
        let h = fs.open_file(&f, OpenOptions::read_write()).unwrap();
        assert_eq!(
            fs.rename(&d, &f, true).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs.read_file(&f).unwrap(), b"data");
        h.close().unwrap();
        fs.rename(&d, &f, true).unwrap();
        assert!(fs.metadata(&f).unwrap().is_dir());
    }

    /// A directory or symlink that moves from a shortened to a short name must leave the `.c9s`
    /// layout behind completely: the new node is a plain `.c9r` directory with `dir.c9r` or
    /// `symlink.c9r` and no `name.c9s`.
    #[test]
    fn moving_a_directory_to_a_short_name_drops_name_c9s() {
        let (_dir, fs) = test_fs(220, false);
        let long = CleartextPath::root().join(&"D".repeat(200)).unwrap();
        let short = CleartextPath::parse("/d");
        fs.create_dir(&long).unwrap();
        fs.write_file(&long.join("f").unwrap(), b"inside", false)
            .unwrap();
        let long_node = fs.mapper().ciphertext_file_path(&long).unwrap();
        assert!(long_node.is_shortened());
        assert!(long_node.inflated_name_path().is_file());

        fs.rename(&long, &short, false).unwrap();

        let node = fs.mapper().ciphertext_file_path(&short).unwrap();
        assert!(!node.is_shortened(), "{}", node.raw_path().display());
        assert!(
            node.raw_path().extension().is_some_and(|e| e == "c9r"),
            "{}",
            node.raw_path().display()
        );
        assert!(node.dir_file_path().is_file());
        assert!(!node.raw_path().join(INFLATED_FILE_NAME).exists());
        assert!(!long_node.raw_path().exists(), "old .c9s node removed");
        assert_eq!(fs.read_file(&short.join("f").unwrap()).unwrap(), b"inside");
    }

    #[test]
    fn moving_a_symlink_to_a_short_name_drops_name_c9s() {
        let (_dir, fs) = test_fs(220, false);
        let long = CleartextPath::root().join(&"S".repeat(200)).unwrap();
        let short = CleartextPath::parse("/l");
        fs.write_file(&CleartextPath::parse("/target"), b"t", false)
            .unwrap();
        fs.create_symlink(&long, "target").unwrap();
        let long_node = fs.mapper().ciphertext_file_path(&long).unwrap();
        assert!(long_node.is_shortened());
        assert!(long_node.inflated_name_path().is_file());

        fs.rename(&long, &short, false).unwrap();

        let node = fs.mapper().ciphertext_file_path(&short).unwrap();
        assert!(!node.is_shortened(), "{}", node.raw_path().display());
        assert!(node.symlink_file_path().is_file());
        assert!(!node.raw_path().join(INFLATED_FILE_NAME).exists());
        assert!(!long_node.raw_path().exists(), "old .c9s node removed");
        assert_eq!(fs.read_link(&short).unwrap(), "target");
    }

    #[test]
    fn opening_a_symlink_to_a_directory_is_a_directory() {
        let (_dir, fs) = test_fs(220, false);
        let d = CleartextPath::parse("/d");
        fs.create_dir(&d).unwrap();
        fs.create_symlink(&CleartextPath::parse("/link"), "d")
            .unwrap();
        // a link chain that ends on a directory counts too
        fs.create_symlink(&CleartextPath::parse("/link2"), "link")
            .unwrap();
        for path in ["/link", "/link2"] {
            let p = CleartextPath::parse(path);
            assert_eq!(
                fs.open_file(&p, OpenOptions::read_only())
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::IsADirectory,
                "{path}"
            );
            assert_eq!(
                fs.open_file(&p, OpenOptions::read_write())
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::IsADirectory,
                "{path}"
            );
            assert_eq!(
                fs.read_file(&p).unwrap_err().kind(),
                io::ErrorKind::IsADirectory,
                "{path}"
            );
        }
    }
}
