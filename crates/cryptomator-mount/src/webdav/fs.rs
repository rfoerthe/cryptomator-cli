//! `dav_server::fs::DavFileSystem` over a `CryptoFs`, modelled on Cryptomator's
//! `webdav-nio-adapter-servlet` (`DavResourceFactoryImpl`, `DavNode`, `DavFolder`, `DavFile`).
//!
//! Two things are worth knowing before reading on. First, every `CryptoFs` call blocks -- it
//! encrypts and touches the disk -- so each one runs on `tokio`'s blocking pool; the trait's
//! futures are just wrappers around a `spawn_blocking`. Second, symbolic links do not exist as
//! far as WebDAV is concerned: Java reads attributes with `NOFOLLOW_LINKS` and answers 404 for
//! anything that is neither a directory nor a regular file, and its directory listing skips those
//! nodes, so a vault's links stay invisible to a Finder that would otherwise follow them out of
//! the vault.
use bytes::Buf;
use cryptomator_core::fs::{
    CleartextPath, CryptoFs, FileAttributes, FileHandle, FilesystemLoop,
    OpenOptions as CoreOpenOptions,
};
use dav_server::davpath::DavPath;
use dav_server::fs::{
    DavDirEntry, DavFile, DavFileSystem, DavMetaData, FsError, FsFuture, FsResult, FsStream,
    OpenOptions, ReadDirMeta,
};
use std::io;
use std::sync::Arc;
use std::time::SystemTime;
use unicode_normalization::UnicodeNormalization;

/// The file system every WebDAV mount serves. Cloning is cheap and is what `dav-server` does for
/// each request (`DynClone`).
#[derive(Clone, Debug)]
pub struct CryptoDavFs {
    fs: Arc<CryptoFs>,
}

impl CryptoDavFs {
    /// Serves `fs`. Read-only-ness comes from the file system itself: a vault the daemon opened
    /// read-only answers every write with `EROFS`, which becomes `403 Forbidden` here.
    pub fn new(fs: Arc<CryptoFs>) -> Self {
        Self { fs }
    }

    /// The vault behind this adapter, for the server's health probe and the mount services.
    pub fn file_system(&self) -> &Arc<CryptoFs> {
        &self.fs
    }
}

/// Runs a blocking `CryptoFs` call on tokio's blocking pool.
///
/// A panicking or cancelled task becomes [`FsError::GeneralFailure`] (500) rather than a hung
/// request; the panic itself is logged, since it is a bug and not a client error.
pub(crate) async fn blocking<T, F>(f: F) -> FsResult<T>
where
    T: Send + 'static,
    F: FnOnce() -> FsResult<T> + Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(result) => result,
        Err(join) => {
            log::error!("a webdav worker did not finish: {join}");
            Err(FsError::GeneralFailure)
        }
    }
}

/// The cleartext path a request addresses, normalised to NFC.
///
/// `UnicodeResourcePathNormalizationFilter` does the same in Java: macOS asks in NFD, the vault
/// stores NFC. `CleartextPath::parse` normalises every component as well, so the `nfc()` here is
/// belt and braces -- it keeps the adapter correct even if the core ever stops doing it. A path
/// that is not UTF-8 cannot name anything in a vault, so it is "not found" rather than a server
/// error.
pub(crate) fn cleartext_path(path: &DavPath) -> FsResult<CleartextPath> {
    let raw = std::str::from_utf8(path.as_bytes()).map_err(|_| FsError::NotFound)?;
    let composed: String = raw.nfc().collect();
    Ok(CleartextPath::parse(&composed))
}

/// `std::io::Error` -> `FsError`, the WebDAV counterpart of the FUSE adapter's `errno_for`
/// (`crate::fuse::errno`, which the `webdav`-only build does not compile, so this is not a link).
///
/// The core reports most failures by [`io::ErrorKind`] and only a few carry an OS error code, so
/// both are consulted -- codes first, because they are the more specific answer. Anything
/// unrecognised is a 500 rather than a silently wrong success.
pub fn fs_error(err: &io::Error) -> FsError {
    if let Some(code) = err.raw_os_error() {
        match code {
            libc::ENOENT => return FsError::NotFound,
            libc::EEXIST | libc::ENOTEMPTY => return FsError::Exists,
            libc::EACCES | libc::EPERM | libc::EROFS | libc::EISDIR | libc::ENOTDIR => {
                return FsError::Forbidden
            }
            libc::ELOOP => return FsError::LoopDetected,
            libc::ENAMETOOLONG => return FsError::PathTooLong,
            libc::ENOSPC | libc::EDQUOT | libc::EMLINK => return FsError::InsufficientStorage,
            libc::EFBIG => return FsError::TooLarge,
            libc::EXDEV => return FsError::IsRemote,
            libc::ENOSYS => return FsError::NotImplemented,
            _ => {}
        }
    }
    match err.kind() {
        io::ErrorKind::NotFound => FsError::NotFound,
        // WebDAV has no "directory not empty": RFC 4918 answers a failed collection DELETE with
        // 409 Conflict, and `handle_delete` turns exactly [`FsError::Exists`] into that
        // (`dav-server-0.11.0/src/handle_delete.rs`, `dir_status`).
        io::ErrorKind::AlreadyExists | io::ErrorKind::DirectoryNotEmpty => FsError::Exists,
        io::ErrorKind::PermissionDenied
        | io::ErrorKind::ReadOnlyFilesystem
        | io::ErrorKind::NotADirectory
        | io::ErrorKind::IsADirectory
        // `CryptoFs` reports a name that is too long as `InvalidInput` as well; the adapter
        // catches that case before it gets here, so what is left is a genuinely malformed
        // request.
        | io::ErrorKind::InvalidInput => FsError::Forbidden,
        io::ErrorKind::StorageFull => FsError::InsufficientStorage,
        io::ErrorKind::Unsupported => FsError::NotImplemented,
        // `ErrorKind::FilesystemLoop` is still unstable, so the core reports a symlink loop as
        // `Other` carrying a [`FilesystemLoop`] payload -- never as `ELOOP`. The FUSE adapter
        // downcasts for exactly the same reason.
        io::ErrorKind::Other if is_filesystem_loop(err) => FsError::LoopDetected,
        _ => FsError::GeneralFailure,
    }
}

/// Whether `err` is the core's symlink-loop marker.
fn is_filesystem_loop(err: &io::Error) -> bool {
    err.get_ref()
        .and_then(|inner| inner.downcast_ref::<FilesystemLoop>())
        .is_some()
}

/// Attributes of one node. `dav-server` turns these into `getcontentlength`, `getlastmodified`,
/// `creationdate`, `resourcetype`, `getetag` and `displayname`.
#[derive(Clone, Debug)]
pub struct CryptoDavMeta {
    attrs: FileAttributes,
}

impl CryptoDavMeta {
    /// Wraps the core's attributes.
    pub fn new(attrs: FileAttributes) -> Self {
        Self { attrs }
    }
}

impl DavMetaData for CryptoDavMeta {
    fn len(&self) -> u64 {
        self.attrs.size
    }

    fn modified(&self) -> FsResult<SystemTime> {
        self.attrs.modified.ok_or(FsError::NotImplemented)
    }

    fn is_dir(&self) -> bool {
        self.attrs.is_dir()
    }

    fn is_file(&self) -> bool {
        self.attrs.is_file()
    }

    /// Never true here: a symbolic link never reaches a client, see the module docs.
    fn is_symlink(&self) -> bool {
        false
    }

    fn accessed(&self) -> FsResult<SystemTime> {
        self.attrs.accessed.ok_or(FsError::NotImplemented)
    }

    /// The birth time, where the host file system has one. ext4 exposes no `st_birthtime` through
    /// `std`, so on Linux this is a 501 and `creationdate` simply stays out of the response.
    fn created(&self) -> FsResult<SystemTime> {
        self.attrs.created.ok_or(FsError::NotImplemented)
    }

    /// A vault stores no ctime of its own, so the modification time stands in for it -- the same
    /// substitution the FUSE adapter makes.
    fn status_changed(&self) -> FsResult<SystemTime> {
        self.modified()
    }

    fn executable(&self) -> FsResult<bool> {
        Ok(self.attrs.mode & 0o111 != 0)
    }
}

/// One child in a `PROPFIND` listing. Its metadata is read while the directory is listed
/// (`ReadDirMeta` is only a hint, and reading it there costs one `stat` either way), so answering
/// `metadata()` needs no further I/O.
#[derive(Debug)]
pub struct CryptoDavEntry {
    name: Vec<u8>,
    meta: CryptoDavMeta,
}

impl CryptoDavEntry {
    /// A child called `name` with the attributes already read for it.
    pub fn new(name: Vec<u8>, meta: CryptoDavMeta) -> Self {
        Self { name, meta }
    }
}

impl DavDirEntry for CryptoDavEntry {
    fn name(&self) -> Vec<u8> {
        self.name.clone()
    }

    fn metadata(&self) -> FsFuture<'_, Box<dyn DavMetaData>> {
        let meta = self.meta.clone();
        Box::pin(async move { Ok(Box::new(meta) as Box<dyn DavMetaData>) })
    }

    fn is_dir(&self) -> FsFuture<'_, bool> {
        let is_dir = self.meta.is_dir();
        Box::pin(async move { Ok(is_dir) })
    }

    fn is_file(&self) -> FsFuture<'_, bool> {
        let is_file = self.meta.is_file();
        Box::pin(async move { Ok(is_file) })
    }

    fn is_symlink(&self) -> FsFuture<'_, bool> {
        Box::pin(async move { Ok(false) })
    }
}

/// Attributes of `path` as WebDAV sees them: links do not exist.
pub(crate) fn node_metadata(fs: &CryptoFs, path: &CleartextPath) -> FsResult<CryptoDavMeta> {
    let attrs = fs.symlink_metadata(path).map_err(|e| fs_error(&e))?;
    if attrs.is_symlink() {
        // Java: "Node not a file or directory" -> 404.
        return Err(FsError::NotFound);
    }
    Ok(CryptoDavMeta::new(attrs))
}

/// Refuses a name the vault's shortening scheme cannot store, before the core turns it into an
/// `InvalidInput` that is indistinguishable from other bad input.
///
/// Java answers `414 Request-URI Too Long` for `path too long` on PUT and MKCOL
/// (`DavFolder.addMemberFile`), which is what [`FsError::PathTooLong`] becomes
/// (`dav-server-0.11.0/src/errors.rs`: `PathTooLong => StatusCode::URI_TOO_LONG`).
fn assert_name_fits(fs: &CryptoFs, path: &CleartextPath) -> FsResult<()> {
    let Some(name) = path.file_name() else {
        return Ok(());
    };
    // Calls the vault's own policy (`CryptoFs::check_cleartext_name`) rather than
    // re-implementing it, so the two cannot silently drift apart; its only failure is
    // `InvalidInput`, which becomes the more specific 414 here.
    match fs.check_cleartext_name(name) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::InvalidInput => Err(FsError::PathTooLong),
        Err(e) => Err(fs_error(&e)),
    }
}

/// The largest gap [`CryptoDavFile::write_bytes`] will zero-fill before answering
/// [`FsError::TooLarge`] instead of writing it.
const MAX_SPARSE_GAP: u64 = 256 * 1024 * 1024;

/// One open file. `dav-server` drives it with `seek`, `read_bytes`, `write_bytes`/`write_buf` and
/// `flush`; the handle is shared with the blocking pool through an `Arc`.
///
/// The cursor lives here rather than in the core: [`FileHandle`] is a positional API, so every
/// read and write names its own offset and no lock is ever held across an `.await`.
///
/// Dropping a [`FileHandle`] runs its own `Drop` -- a flush of every dirty chunk, then the
/// registry-wide mutex `CryptoFs` serialises `open`/`rename`/`delete` on -- which is why the field
/// is an `Option`: [`CryptoDavFile`]'s own `Drop` takes it out and moves it onto the blocking pool
/// so a client that disconnects without a final `flush` neither loses what it wrote nor runs that
/// work on the async reactor. See that `Drop` impl for why the option matters.
#[derive(Debug)]
pub struct CryptoDavFile {
    fs: Arc<CryptoFs>,
    path: CleartextPath,
    handle: Option<Arc<FileHandle>>,
    position: u64,
}

impl CryptoDavFile {
    /// The handle, for any method that still has access to `self` -- i.e. everything before
    /// `Drop` takes it. `None` here would mean a method ran after `Drop`, which cannot happen
    /// through the trait; answering [`FsError::GeneralFailure`] rather than panicking keeps that
    /// true even if a future refactor gets it wrong.
    fn handle(&self) -> FsResult<Arc<FileHandle>> {
        self.handle.clone().ok_or(FsError::GeneralFailure)
    }
}

impl DavFile for CryptoDavFile {
    fn metadata(&mut self) -> FsFuture<'_, Box<dyn DavMetaData>> {
        let fs = Arc::clone(&self.fs);
        let path = self.path.clone();
        Box::pin(async move {
            let meta = blocking(move || node_metadata(&fs, &path)).await?;
            Ok(Box::new(meta) as Box<dyn DavMetaData>)
        })
    }

    fn write_buf(&mut self, mut buf: Box<dyn Buf + Send>) -> FsFuture<'_, ()> {
        let mut data = Vec::with_capacity(buf.remaining());
        while buf.has_remaining() {
            let chunk = buf.chunk();
            data.extend_from_slice(chunk);
            let len = chunk.len();
            buf.advance(len);
        }
        self.write_bytes(bytes::Bytes::from(data))
    }

    fn write_bytes(&mut self, buf: bytes::Bytes) -> FsFuture<'_, ()> {
        let handle = self.handle();
        let position = self.position;
        let len = buf.len() as u64;
        Box::pin(async move {
            let handle = handle?;
            // A position beyond EOF is not an error by itself: the core zero-fills the gap, which
            // is what a `Content-Range` PUT into a fresh file needs. But the gap's size is a
            // client-chosen `Content-Range`/`X-Update-Range` offset, and this server has no
            // authentication (see `webdav::mod`), so an unbounded gap would let any local process
            // make it encrypt and write terabytes of ciphertext from a handful of request bytes.
            // Java and the FUSE adapter both zero-fill without a limit -- a syscall or a local API
            // call already implies some trust in the caller -- but a WebDAV request does not carry
            // the same assumption, so this is a deliberate deviation from parity with them rather
            // than an oversight.
            blocking(move || {
                let size = handle.size();
                if position.saturating_sub(size) > MAX_SPARSE_GAP {
                    return Err(FsError::TooLarge);
                }
                handle
                    .write_all_at(&buf, position)
                    .map_err(|e| fs_error(&e))
            })
            .await?;
            self.position = self.position.saturating_add(len);
            Ok(())
        })
    }

    fn read_bytes(&mut self, count: usize) -> FsFuture<'_, bytes::Bytes> {
        let handle = self.handle();
        let position = self.position;
        Box::pin(async move {
            let handle = handle?;
            let data = blocking(move || {
                let mut buf = vec![0u8; count];
                let mut filled = 0;
                // `read_at` may stop at a chunk boundary; a short read that is not EOF would look
                // like a truncated body to the client.
                while filled < count {
                    match handle.read_at(&mut buf[filled..], position + filled as u64) {
                        Ok(0) => break,
                        Ok(n) => filled += n,
                        Err(e) => return Err(fs_error(&e)),
                    }
                }
                buf.truncate(filled);
                Ok(buf)
            })
            .await?;
            // `handle_gethead` streams a range with repeated `read_bytes` calls and no `seek` in
            // between, so the cursor has to advance here; at or past EOF it stays put and the
            // answer is an empty `Bytes`, never an error.
            self.position = self.position.saturating_add(data.len() as u64);
            Ok(bytes::Bytes::from(data))
        })
    }

    fn seek(&mut self, pos: io::SeekFrom) -> FsFuture<'_, u64> {
        let handle = self.handle();
        Box::pin(async move {
            let handle = handle?;
            // Only `End` needs to know how long the file is. `handle_put` (`Content-Range`) and
            // `handle_gethead` (`Range`) seek exclusively from `Start`, so asking for the size
            // unconditionally would put a blocking-pool round trip on every ranged GET and every
            // partial PUT for nothing.
            //
            // `i128` so that `size + offset` cannot wrap for any `u64`/`i64` pair.
            let target = match pos {
                io::SeekFrom::Start(offset) => i128::from(offset),
                io::SeekFrom::Current(offset) => i128::from(self.position) + i128::from(offset),
                io::SeekFrom::End(offset) => {
                    let size = blocking(move || Ok(handle.size())).await?;
                    i128::from(size) + i128::from(offset)
                }
            };
            // Seeking before the start is the caller's bug; `handle_put` turns the error into
            // `416 Range Not Satisfiable`.
            let target = u64::try_from(target).map_err(|_| FsError::GeneralFailure)?;
            self.position = target;
            Ok(target)
        })
    }

    fn flush(&mut self) -> FsFuture<'_, ()> {
        let handle = self.handle();
        Box::pin(async move {
            let handle = handle?;
            blocking(move || handle.flush().map_err(|e| fs_error(&e))).await
        })
    }
}

impl Drop for CryptoDavFile {
    /// Releasing the last `Arc<FileHandle>` flushes every dirty chunk and then takes the
    /// registry-wide mutex `CryptoFs` serialises `open`/`rename`/`delete` on ([`FileHandle`]'s own
    /// `Drop`, via `release()`). Doing that inline here -- e.g. because a client disconnected
    /// mid-PUT without a final `flush` -- would run disk I/O and lock contention on the async
    /// runtime's own thread, stalling every other request. Moving it onto `tokio`'s blocking pool
    /// keeps the reactor free; there is no pool to move it onto once the runtime has already shut
    /// down, so then the drop just runs inline, on whatever thread is dropping this value.
    fn drop(&mut self) {
        let Some(handle) = self.handle.take() else {
            return;
        };
        match tokio::runtime::Handle::try_current() {
            Ok(rt) => {
                rt.spawn_blocking(move || drop(handle));
            }
            Err(_) => drop(handle),
        }
    }
}

impl DavFileSystem for CryptoDavFs {
    /// Opens one file. `options.size` and `options.checksum` are hints this adapter ignores: the
    /// core neither preallocates nor verifies an `OC-Checksum`.
    fn open<'a>(
        &'a self,
        path: &'a DavPath,
        options: OpenOptions,
    ) -> FsFuture<'a, Box<dyn DavFile>> {
        let fs = Arc::clone(&self.fs);
        let parsed = cleartext_path(path);
        Box::pin(async move {
            let path = parsed?;
            let file = blocking(move || {
                if options.write
                    || options.append
                    || options.create
                    || options.create_new
                    || options.truncate
                {
                    assert_name_fits(&fs, &path)?;
                }
                // A symlink is invisible: opening one must not follow it out of the vault.
                if fs
                    .symlink_metadata(&path)
                    .is_ok_and(|attrs| attrs.is_symlink())
                {
                    return Err(FsError::NotFound);
                }
                let core_options = CoreOpenOptions {
                    read: options.read,
                    // The core has no append mode; an appending PUT is a writable handle whose
                    // cursor starts at the end (see `position` below).
                    write: options.write || options.append,
                    create: options.create,
                    create_new: options.create_new,
                    // Exactly what the caller asked for. `handle_put` sets `truncate` itself for a
                    // whole-body PUT and clears it again for a `Content-Range`/`X-Update-Range`
                    // one, so inferring it from `write` here would destroy a partial update.
                    truncate: options.truncate,
                };
                let handle = fs
                    .open_file(&path, core_options)
                    .map_err(|e| fs_error(&e))?;
                let position = if options.append { handle.size() } else { 0 };
                Ok(CryptoDavFile {
                    fs: Arc::clone(&fs),
                    path,
                    handle: Some(Arc::new(handle)),
                    position,
                })
            })
            .await?;
            Ok(Box::new(file) as Box<dyn DavFile>)
        })
    }

    fn create_dir<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        let fs = Arc::clone(&self.fs);
        let parsed = cleartext_path(path);
        Box::pin(async move {
            let dir = parsed?;
            blocking(move || {
                assert_name_fits(&fs, &dir)?;
                fs.create_dir(&dir).map_err(|e| fs_error(&e))
            })
            .await
        })
    }

    /// Removes **one empty** directory.
    ///
    /// `handle_delete` walks the collection itself and calls `remove_file`/`remove_dir` from the
    /// leaves upwards (`dav-server-0.11.0/src/handle_delete.rs`, `delete_items`), so deleting
    /// recursively here would pull the children out from under it and lose the per-resource
    /// statuses of the `207` response. A directory that still has content answers
    /// [`FsError::Exists`], which `dir_status` renders as `409 Conflict`.
    ///
    /// A collection whose only remaining child is a symlink can never be deleted this way: a
    /// vault's links are invisible to WebDAV (see the module docs), so `delete_items` never sees
    /// one to remove, and this then answers `Exists` forever. That follows from the two rulings
    /// above rather than from a defect here, but it is worth knowing before puzzling over a
    /// directory that a client insists is empty.
    fn remove_dir<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        let fs = Arc::clone(&self.fs);
        let parsed = cleartext_path(path);
        Box::pin(async move {
            let dir = parsed?;
            blocking(move || fs.delete(&dir).map_err(|e| fs_error(&e))).await
        })
    }

    fn remove_file<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        let fs = Arc::clone(&self.fs);
        let parsed = cleartext_path(path);
        Box::pin(async move {
            let file = parsed?;
            blocking(move || fs.delete(&file).map_err(|e| fs_error(&e))).await
        })
    }

    /// MOVE. `handle_copymove` has already enforced the `Overwrite` header (it deletes an existing
    /// destination itself when overwriting is allowed, and answers `412` when it is not), so the
    /// core is asked to replace unconditionally.
    fn rename<'a>(&'a self, from: &'a DavPath, to: &'a DavPath) -> FsFuture<'a, ()> {
        let fs = Arc::clone(&self.fs);
        let (src, dst) = (cleartext_path(from), cleartext_path(to));
        Box::pin(async move {
            let (src, dst) = (src?, dst?);
            blocking(move || {
                assert_name_fits(&fs, &dst)?;
                fs.rename(&src, &dst, true).map_err(|e| fs_error(&e))
            })
            .await
        })
    }

    /// COPY of a single resource; `handle_copymove` recurses into a collection itself. See
    /// [`DavFileSystem::rename`] for why `replace_existing` is always `true`.
    fn copy<'a>(&'a self, from: &'a DavPath, to: &'a DavPath) -> FsFuture<'a, ()> {
        let fs = Arc::clone(&self.fs);
        let (src, dst) = (cleartext_path(from), cleartext_path(to));
        Box::pin(async move {
            let (src, dst) = (src?, dst?);
            blocking(move || {
                assert_name_fits(&fs, &dst)?;
                fs.copy(&src, &dst, true).map_err(|e| fs_error(&e))
            })
            .await
        })
    }

    fn set_accessed<'a>(&'a self, path: &'a DavPath, tm: SystemTime) -> FsFuture<'a, ()> {
        let fs = Arc::clone(&self.fs);
        let parsed = cleartext_path(path);
        Box::pin(async move {
            let path = parsed?;
            blocking(move || {
                fs.set_times(&path, None, Some(tm))
                    .map_err(|e| fs_error(&e))
            })
            .await
        })
    }

    fn set_modified<'a>(&'a self, path: &'a DavPath, tm: SystemTime) -> FsFuture<'a, ()> {
        let fs = Arc::clone(&self.fs);
        let parsed = cleartext_path(path);
        Box::pin(async move {
            let path = parsed?;
            blocking(move || {
                fs.set_times(&path, Some(tm), None)
                    .map_err(|e| fs_error(&e))
            })
            .await
        })
    }

    fn metadata<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, Box<dyn DavMetaData>> {
        let fs = Arc::clone(&self.fs);
        let parsed = cleartext_path(path);
        Box::pin(async move {
            let path = parsed?;
            let meta = blocking(move || node_metadata(&fs, &path)).await?;
            Ok(Box::new(meta) as Box<dyn DavMetaData>)
        })
    }

    /// The same as [`DavFileSystem::metadata`]: links are invisible either way.
    fn symlink_metadata<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, Box<dyn DavMetaData>> {
        self.metadata(path)
    }

    /// The whole listing, stat'd and buffered in one blocking task.
    ///
    /// Every child is `stat`ed eagerly, which is what makes [`CryptoDavEntry::metadata`] free and
    /// what implements Java's "skip what you cannot stat" rule; `ReadDirMeta` is therefore ignored
    /// -- `ReadDirMeta::None` would buy nothing, because the metadata decides whether an entry is
    /// listed at all. The cost is that a directory with very many children is fully stat'ed before
    /// the first byte of the `PROPFIND` response goes out.
    fn read_dir<'a>(
        &'a self,
        path: &'a DavPath,
        _meta: ReadDirMeta,
    ) -> FsFuture<'a, FsStream<Box<dyn DavDirEntry>>> {
        let fs = Arc::clone(&self.fs);
        let parsed = cleartext_path(path);
        Box::pin(async move {
            let dir = parsed?;
            let entries = blocking(move || {
                let listing = fs.read_dir(&dir).map_err(|e| fs_error(&e))?;
                let mut out: Vec<Box<dyn DavDirEntry>> = Vec::with_capacity(listing.len());
                for entry in listing {
                    // Only the ciphertext name is ever logged: a file name is precisely what a
                    // vault encrypts, so a cleartext path must not reach a log line above `debug`.
                    let ciphertext = entry.extracted_ciphertext;
                    let child = match dir.join(&entry.cleartext_name) {
                        Ok(child) => child,
                        Err(err) => {
                            log::debug!(
                                "skipping {ciphertext}: its name is not a valid path: {err}"
                            );
                            continue;
                        }
                    };
                    // Java logs and skips a child whose attributes cannot be read, and skips
                    // anything that is not a file or a directory. Both end up here.
                    match node_metadata(&fs, &child) {
                        Ok(meta) => out.push(Box::new(CryptoDavEntry::new(
                            entry.cleartext_name.into_bytes(),
                            meta,
                        ))),
                        Err(FsError::NotFound) => {}
                        Err(err) => log::warn!("skipping {ciphertext} in the listing: {err}"),
                    }
                }
                Ok(out)
            })
            .await?;
            Ok(
                Box::pin(futures_util::stream::iter(entries.into_iter().map(Ok)))
                    as FsStream<Box<dyn DavDirEntry>>,
            )
        })
    }

    /// `quota-available-bytes` / `quota-used-bytes` from the file store the vault sits on.
    ///
    /// Suppressed on macOS 15.4 and newer, where reporting a quota makes the volume take 90
    /// seconds to mount (Cryptomator's `OSUtil.isMacOS15_4orNewer`). The check reads the Darwin
    /// release rather than shelling out to `sw_vers`: macOS 15.4 is Darwin 24.4.
    fn get_quota(&self) -> FsFuture<'_, (u64, Option<u64>)> {
        let fs = Arc::clone(&self.fs);
        Box::pin(async move {
            if suppresses_quota() {
                return Err(FsError::NotImplemented);
            }
            blocking(move || {
                let stat = nix::sys::statvfs::statvfs(fs.vault_path())
                    .map_err(|e| fs_error(&io::Error::from_raw_os_error(e as i32)))?;
                // `fsblkcnt_t` is 32 bits wide on macOS and 64 on Linux, so both counts are
                // widened before they are scaled.
                let frag = stat.fragment_size() as u64;
                let total = (stat.blocks() as u64).saturating_mul(frag);
                let available = (stat.blocks_available() as u64).saturating_mul(frag);
                Ok((total.saturating_sub(available), Some(total)))
            })
            .await
        })
    }
}

/// Whether this host is a macOS 15.4 or newer, where a reported quota delays the mount by 90 s.
fn suppresses_quota() -> bool {
    if !cfg!(target_os = "macos") {
        return false;
    }
    let Ok(uname) = nix::sys::utsname::uname() else {
        return false;
    };
    let release = uname.release().to_string_lossy().into_owned();
    let mut parts = release.split('.');
    let major: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let minor: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    // Darwin 24.4 == macOS 15.4.
    major > 24 || (major == 24 && minor >= 4)
}

#[cfg(all(test, feature = "webdav"))]
mod tests {
    use super::*;
    use crate::testing::{test_fs, test_fs_with};
    use dav_server::fs::ReadDirMeta;
    use futures_util::StreamExt;
    use std::time::Duration;

    /// Every test drives the futures on a current-thread runtime with a blocking pool, because
    /// `blocking()` uses `spawn_blocking`.
    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
    }

    /// `DavPath::new` only accepts printable ASCII, exactly like a URL path on the wire, so a
    /// non-ASCII name has to be percent-encoded here just as a client would send it.
    fn dav_path(path: &str) -> DavPath {
        DavPath::new(path).expect("a valid dav path")
    }

    /// Exactly what `handle_put` builds for a whole-body PUT (`handle_put.rs`: `write()` plus
    /// `create` and `truncate`).
    fn put_options() -> OpenOptions {
        OpenOptions {
            write: true,
            create: true,
            truncate: true,
            ..Default::default()
        }
    }

    #[test]
    fn metadata_reports_size_kind_and_times() {
        let (_dir, fs) = test_fs();
        fs.write_file(&CleartextPath::parse("/hello.txt"), b"hello dav", false)
            .expect("write");
        let dav = CryptoDavFs::new(Arc::clone(&fs));
        runtime().block_on(async {
            let root = dav.metadata(&dav_path("/")).await.expect("root metadata");
            assert!(root.is_dir());
            let meta = dav
                .metadata(&dav_path("/hello.txt"))
                .await
                .expect("file metadata");
            assert!(meta.is_file());
            assert_eq!(meta.len(), 9);
            meta.modified().expect("a modification time");
            meta.accessed().expect("an access time");
            assert_eq!(
                meta.status_changed().expect("a ctime"),
                meta.modified().expect("a modification time"),
                "a vault has no ctime of its own, so mtime stands in"
            );
            assert!(
                !meta.executable().expect("an executable bit"),
                "a freshly written file is not executable"
            );
            // `symlink_metadata` is the same answer, by design: links are invisible either way.
            let link_meta = dav
                .symlink_metadata(&dav_path("/hello.txt"))
                .await
                .expect("symlink_metadata");
            assert!(link_meta.is_file() && !link_meta.is_symlink());
            assert_eq!(link_meta.len(), meta.len());
            // A birth time only exists where the host file system stores one: macOS always does,
            // ext4 does not expose it through `std`, so there it is a 501.
            #[cfg(target_os = "macos")]
            meta.created().expect("a creation time");
            #[cfg(not(target_os = "macos"))]
            assert!(
                matches!(meta.created(), Ok(_) | Err(FsError::NotImplemented)),
                "a creation time or an honest 501"
            );
            meta.etag().expect("an etag is derived from size and mtime");
            let missing = dav.metadata(&dav_path("/nope")).await.expect_err("missing");
            assert_eq!(missing, FsError::NotFound);
        });
    }

    #[test]
    fn a_symlink_is_neither_listed_nor_addressable() {
        let (_dir, fs) = test_fs();
        fs.write_file(&CleartextPath::parse("/target.txt"), b"x", false)
            .expect("write");
        fs.create_symlink(&CleartextPath::parse("/link"), "target.txt")
            .expect("symlink");
        let dav = CryptoDavFs::new(Arc::clone(&fs));
        runtime().block_on(async {
            // Java's DavResourceFactoryImpl answers 404 for a node that is neither file nor dir.
            assert_eq!(
                dav.metadata(&dav_path("/link")).await.expect_err("hidden"),
                FsError::NotFound
            );
            // GET on a link must not follow it out of the vault either.
            let read = OpenOptions {
                read: true,
                ..Default::default()
            };
            assert_eq!(
                dav.open(&dav_path("/link"), read)
                    .await
                    .expect_err("a link cannot be opened"),
                FsError::NotFound
            );
            let mut names = Vec::new();
            let mut entries = dav
                .read_dir(&dav_path("/"), ReadDirMeta::Data)
                .await
                .expect("read_dir");
            while let Some(entry) = entries.next().await {
                names.push(entry.expect("entry").name());
            }
            assert_eq!(names, vec![b"target.txt".to_vec()], "the link is skipped");
        });
    }

    #[test]
    fn read_dir_reports_directories_and_files_with_metadata() {
        let (_dir, fs) = test_fs();
        fs.create_dir(&CleartextPath::parse("/sub")).expect("mkdir");
        fs.write_file(&CleartextPath::parse("/sub/a.txt"), b"abc", false)
            .expect("write");
        let dav = CryptoDavFs::new(Arc::clone(&fs));
        runtime().block_on(async {
            let mut entries = dav
                .read_dir(&dav_path("/"), ReadDirMeta::Data)
                .await
                .expect("read_dir");
            let entry = entries.next().await.expect("one entry").expect("entry");
            assert_eq!(entry.name(), b"sub".to_vec());
            assert!(entry.is_dir().await.expect("is_dir"));
            assert!(entries.next().await.is_none(), "only one child");
            let mut children = dav
                .read_dir(&dav_path("/sub"), ReadDirMeta::Data)
                .await
                .expect("read_dir");
            let child = children.next().await.expect("one child").expect("entry");
            assert_eq!(child.metadata().await.expect("metadata").len(), 3);
        });
    }

    #[test]
    fn a_request_path_is_normalised_to_nfc() {
        let (_dir, fs) = test_fs();
        // The vault stores NFC; a macOS client asks in NFD (percent-encoded on the wire).
        fs.write_file(&CleartextPath::parse("/caf\u{e9}.txt"), b"x", false)
            .expect("write");
        let dav = CryptoDavFs::new(Arc::clone(&fs));
        runtime().block_on(async {
            dav.metadata(&dav_path("/cafe%CC%81.txt"))
                .await
                .expect("the decomposed name resolves to the composed one");
        });
    }

    #[test]
    fn io_errors_become_the_matching_fs_errors() {
        use std::io::{Error, ErrorKind};
        assert_eq!(
            fs_error(&Error::from(ErrorKind::NotFound)),
            FsError::NotFound
        );
        assert_eq!(
            fs_error(&Error::from(ErrorKind::AlreadyExists)),
            FsError::Exists
        );
        assert_eq!(
            fs_error(&Error::from(ErrorKind::DirectoryNotEmpty)),
            FsError::Exists
        );
        assert_eq!(
            fs_error(&Error::from(ErrorKind::ReadOnlyFilesystem)),
            FsError::Forbidden
        );
        assert_eq!(
            fs_error(&Error::from(ErrorKind::PermissionDenied)),
            FsError::Forbidden
        );
        assert_eq!(
            fs_error(&Error::from(ErrorKind::StorageFull)),
            FsError::InsufficientStorage
        );
        assert_eq!(
            fs_error(&Error::from(ErrorKind::Other)),
            FsError::GeneralFailure
        );
        assert_eq!(
            fs_error(&Error::from_raw_os_error(libc::ELOOP)),
            FsError::LoopDetected
        );
        // The shape the core actually produces: `Other` with a `FilesystemLoop` payload, never a
        // raw `ELOOP` (`cryptomator_core::fs::fs_loop`).
        assert_eq!(
            fs_error(&io::Error::other(FilesystemLoop("/a".to_owned()))),
            FsError::LoopDetected
        );
    }

    #[test]
    fn quota_is_reported_unless_macos_suppresses_it() {
        let (_dir, fs) = test_fs();
        let dav = CryptoDavFs::new(Arc::clone(&fs));
        runtime().block_on(async {
            match dav.get_quota().await {
                Ok((used, Some(total))) => assert!(total >= used, "{used} of {total}"),
                Ok((_, None)) => panic!("a local file store always knows its size"),
                // macOS 15.4+ (Darwin 24.4+) mounts with a 90 s delay when quota is reported.
                Err(err) => assert_eq!(err, FsError::NotImplemented),
            }
        });
    }

    #[test]
    fn put_creates_truncates_and_reads_back() {
        let (_dir, fs) = test_fs();
        let dav = CryptoDavFs::new(Arc::clone(&fs));
        runtime().block_on(async {
            let options = put_options();
            let mut file = dav
                .open(&dav_path("/put.txt"), options.clone())
                .await
                .expect("open");
            file.write_bytes(bytes::Bytes::from_static(b"first"))
                .await
                .expect("write");
            file.flush().await.expect("flush");
            drop(file);
            assert_eq!(
                fs.read_file(&CleartextPath::parse("/put.txt"))
                    .expect("read"),
                b"first"
            );
            let first_etag = dav
                .metadata(&dav_path("/put.txt"))
                .await
                .expect("metadata")
                .etag()
                .expect("an etag");

            // A second PUT truncates.
            let mut file = dav
                .open(&dav_path("/put.txt"), options)
                .await
                .expect("reopen");
            file.write_bytes(bytes::Bytes::from_static(b"second body"))
                .await
                .expect("write");
            file.flush().await.expect("flush");
            drop(file);
            assert_eq!(
                fs.read_file(&CleartextPath::parse("/put.txt"))
                    .expect("read"),
                b"second body"
            );
            // The etag is `{len:x}-{mtime_us:x}`, so a different body must give a different one --
            // otherwise a cache would keep serving "first".
            let second_etag = dav
                .metadata(&dav_path("/put.txt"))
                .await
                .expect("metadata")
                .etag()
                .expect("an etag");
            assert_ne!(
                first_etag, second_etag,
                "the body changed, so the etag must"
            );

            // A *shorter* third PUT is what actually pins the truncation: without it the tail of
            // "second body" would survive past the new end.
            let mut file = dav
                .open(&dav_path("/put.txt"), put_options())
                .await
                .expect("reopen");
            file.write_bytes(bytes::Bytes::from_static(b"third"))
                .await
                .expect("write");
            file.flush().await.expect("flush");
            drop(file);
            assert_eq!(
                fs.read_file(&CleartextPath::parse("/put.txt"))
                    .expect("read"),
                b"third"
            );

            // And a PUT that does *not* ask for truncation must leave the rest of the body alone:
            // that is how `handle_put` opens a `Content-Range`/`X-Update-Range` request.
            let ranged = OpenOptions {
                write: true,
                create: true,
                ..Default::default()
            };
            let mut file = dav
                .open(&dav_path("/put.txt"), ranged)
                .await
                .expect("reopen");
            assert_eq!(file.seek(io::SeekFrom::Start(1)).await.expect("seek"), 1);
            file.write_bytes(bytes::Bytes::from_static(b"HI"))
                .await
                .expect("write");
            file.flush().await.expect("flush");
            drop(file);
            assert_eq!(
                fs.read_file(&CleartextPath::parse("/put.txt"))
                    .expect("read"),
                b"tHIrd",
                "a partial update keeps the bytes it did not write"
            );
        });
    }

    #[test]
    fn a_body_written_without_a_flush_is_not_lost() {
        let (_dir, fs) = test_fs();
        let dav = CryptoDavFs::new(Arc::clone(&fs));
        runtime().block_on(async {
            let mut file = dav
                .open(&dav_path("/nf.txt"), put_options())
                .await
                .expect("open");
            // `handle_put` streams the body as a sequence of `write_buf` calls with no `seek`
            // between them, so each one must continue where the last stopped.
            file.write_bytes(bytes::Bytes::from_static(b"un"))
                .await
                .expect("write");
            file.write_bytes(bytes::Bytes::from_static(b"flushed"))
                .await
                .expect("write");
            // A client that disconnects mid-PUT never reaches `flush`; `FileHandle::drop`
            // releases the last handle, which flushes.
            drop(file);
            assert_eq!(
                fs.read_file(&CleartextPath::parse("/nf.txt"))
                    .expect("read"),
                b"unflushed"
            );
        });
    }

    #[test]
    fn dropping_without_flush_still_persists_after_the_runtime_shuts_down() {
        let (_dir, fs) = test_fs();
        let dav = CryptoDavFs::new(Arc::clone(&fs));
        let rt = runtime();
        rt.block_on(async {
            let mut file = dav
                .open(&dav_path("/rt-drop.txt"), put_options())
                .await
                .expect("open");
            file.write_bytes(bytes::Bytes::from_static(b"deferred"))
                .await
                .expect("write");
            // No `flush()`: `CryptoDavFile::drop` must move the release onto `spawn_blocking`
            // itself, while a runtime is still current here, rather than run it inline.
            drop(file);
        });
        // The dropped file's release races the runtime shutdown below if it did not actually get
        // spawned onto the blocking pool before `block_on` returned; `shutdown_timeout` waits for
        // every outstanding blocking task, so this only passes if the spawn really happened.
        rt.shutdown_timeout(std::time::Duration::from_secs(5));
        assert_eq!(
            fs.read_file(&CleartextPath::parse("/rt-drop.txt"))
                .expect("read"),
            b"deferred",
            "the deferred release must have flushed before the runtime finished shutting down"
        );
    }

    #[test]
    fn a_seek_past_the_end_zero_fills_the_gap() {
        let (_dir, fs) = test_fs();
        let dav = CryptoDavFs::new(Arc::clone(&fs));
        runtime().block_on(async {
            let mut file = dav
                .open(&dav_path("/sparse.bin"), put_options())
                .await
                .expect("open");
            assert_eq!(file.seek(io::SeekFrom::Start(4)).await.expect("seek"), 4);
            file.write_bytes(bytes::Bytes::from_static(b"tail"))
                .await
                .expect("write");
            file.flush().await.expect("flush");
            assert_eq!(file.metadata().await.expect("metadata").len(), 8);
            drop(file);
            assert_eq!(
                fs.read_file(&CleartextPath::parse("/sparse.bin"))
                    .expect("read"),
                b"\0\0\0\0tail"
            );
        });
    }

    #[test]
    fn write_bytes_bounds_the_zero_fill_gap() {
        let (_dir, fs) = test_fs();
        let dav = CryptoDavFs::new(Arc::clone(&fs));
        runtime().block_on(async {
            let mut file = dav
                .open(&dav_path("/bounded.bin"), put_options())
                .await
                .expect("open");
            // The file is empty, so this is exactly `size + MAX_SPARSE_GAP + 1`: the write must
            // be rejected before it touches the file, not after encrypting the gap.
            let too_far = MAX_SPARSE_GAP + 1;
            assert_eq!(
                file.seek(io::SeekFrom::Start(too_far)).await.expect("seek"),
                too_far
            );
            assert_eq!(
                file.write_bytes(bytes::Bytes::from_static(b"x"))
                    .await
                    .expect_err("the gap is too large to zero-fill"),
                FsError::TooLarge
            );
            file.flush().await.expect("flush");
            drop(file);
            assert_eq!(
                fs.read_file(&CleartextPath::parse("/bounded.bin"))
                    .expect("read"),
                b"",
                "the rejected write must leave the file exactly as it was"
            );

            // A gap comfortably inside the limit still zero-fills, same as before.
            let mut file = dav
                .open(&dav_path("/bounded.bin"), put_options())
                .await
                .expect("reopen");
            assert_eq!(
                file.seek(io::SeekFrom::Start(1024)).await.expect("seek"),
                1024
            );
            file.write_bytes(bytes::Bytes::from_static(b"ok"))
                .await
                .expect("a gap well under the limit is still allowed");
            file.flush().await.expect("flush");
            drop(file);
            let body = fs
                .read_file(&CleartextPath::parse("/bounded.bin"))
                .expect("read");
            assert_eq!(body.len(), 1026);
            assert_eq!(&body[1024..], b"ok");
        });
    }

    #[test]
    fn a_ranged_read_seeks_and_returns_only_the_requested_bytes() {
        let (_dir, fs) = test_fs();
        fs.write_file(&CleartextPath::parse("/r.bin"), b"0123456789", false)
            .expect("write");
        let dav = CryptoDavFs::new(Arc::clone(&fs));
        runtime().block_on(async {
            let options = OpenOptions {
                read: true,
                ..Default::default()
            };
            let mut file = dav.open(&dav_path("/r.bin"), options).await.expect("open");
            assert_eq!(file.seek(io::SeekFrom::Start(3)).await.expect("seek"), 3);
            assert_eq!(&file.read_bytes(4).await.expect("read")[..], b"3456");
            assert_eq!(file.seek(io::SeekFrom::End(-2)).await.expect("seek"), 8);
            assert_eq!(&file.read_bytes(64).await.expect("read")[..], b"89");
            assert_eq!(
                file.read_bytes(64).await.expect("read at eof").len(),
                0,
                "reading past the end returns nothing, not an error"
            );
            assert_eq!(file.metadata().await.expect("metadata").len(), 10);
        });
    }

    /// `Start` and `Current` must not touch the file system: `handle_gethead` seeks once per
    /// ranged GET and `handle_put` once per `Content-Range` PUT, and a blocking-pool round trip
    /// for a number this function already has is pure latency.
    ///
    /// Proved by starving the pool: a runtime with a single blocking thread, that thread parked,
    /// and a `Start` seek that answers anyway -- while the `End` seek right after it, which does
    /// need the size, waits for the thread that never comes.
    #[test]
    fn seeking_from_the_start_needs_no_blocking_thread() {
        let (_dir, fs) = test_fs();
        fs.write_file(&CleartextPath::parse("/s.bin"), b"0123456789", false)
            .expect("write");
        let dav = CryptoDavFs::new(Arc::clone(&fs));
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .expect("runtime");
        let (release, parked) = std::sync::mpsc::channel::<()>();
        runtime.block_on(async {
            let options = OpenOptions {
                read: true,
                ..Default::default()
            };
            // The open still needs the pool, so it happens before the pool is taken away.
            let mut file = dav.open(&dav_path("/s.bin"), options).await.expect("open");
            tokio::task::spawn_blocking(move || {
                let _ = parked.recv();
            });
            // Let the parked task actually claim the one thread there is.
            tokio::time::sleep(Duration::from_millis(50)).await;

            let seeked =
                tokio::time::timeout(Duration::from_secs(5), file.seek(io::SeekFrom::Start(4)))
                    .await
                    .expect("a `Start` seek answers with no thread to run on")
                    .expect("seek");
            assert_eq!(seeked, 4);
            let seeked =
                tokio::time::timeout(Duration::from_secs(5), file.seek(io::SeekFrom::Current(2)))
                    .await
                    .expect("and so does `Current`")
                    .expect("seek");
            assert_eq!(seeked, 6);

            assert!(
                tokio::time::timeout(Duration::from_millis(300), file.seek(io::SeekFrom::End(-2)),)
                    .await
                    .is_err(),
                "`End` is the one variant that does read the size"
            );
            let _ = release.send(());
        });
    }

    #[test]
    fn create_new_refuses_an_existing_name() {
        let (_dir, fs) = test_fs();
        fs.write_file(&CleartextPath::parse("/taken.txt"), b"x", false)
            .expect("write");
        let dav = CryptoDavFs::new(Arc::clone(&fs));
        runtime().block_on(async {
            let options = OpenOptions {
                write: true,
                create_new: true,
                ..Default::default()
            };
            let err = dav
                .open(&dav_path("/taken.txt"), options)
                .await
                .expect_err("exists");
            assert_eq!(err, FsError::Exists);
        });
    }

    #[test]
    fn an_appending_open_starts_the_cursor_at_the_current_end() {
        let (_dir, fs) = test_fs();
        fs.write_file(&CleartextPath::parse("/append.txt"), b"existing-", false)
            .expect("write");
        let dav = CryptoDavFs::new(Arc::clone(&fs));
        runtime().block_on(async {
            // Exactly what `handle_put` builds for an `X-Update-Range: append` PATCH: the core
            // has no append mode of its own, so this is a writable handle whose cursor starts at
            // the end (see `position` in `DavFileSystem::open`).
            let options = OpenOptions {
                write: true,
                append: true,
                create: true,
                ..Default::default()
            };
            let mut file = dav
                .open(&dav_path("/append.txt"), options)
                .await
                .expect("open");
            file.write_bytes(bytes::Bytes::from_static(b"appended"))
                .await
                .expect("write");
            file.flush().await.expect("flush");
            drop(file);
        });
        assert_eq!(
            fs.read_file(&CleartextPath::parse("/append.txt"))
                .expect("read"),
            b"existing-appended",
            "the append must land after the existing body, not overwrite its start"
        );
    }

    #[test]
    fn create_dir_with_a_missing_parent_is_not_found() {
        let (_dir, fs) = test_fs();
        let dav = CryptoDavFs::new(Arc::clone(&fs));
        runtime().block_on(async {
            assert_eq!(
                dav.create_dir(&dav_path("/missing/child"))
                    .await
                    .expect_err("the parent does not exist"),
                FsError::NotFound
            );
        });
    }

    #[test]
    fn opening_a_directory_is_forbidden() {
        let (_dir, fs) = test_fs();
        fs.create_dir(&CleartextPath::parse("/dir")).expect("mkdir");
        let dav = CryptoDavFs::new(Arc::clone(&fs));
        runtime().block_on(async {
            let options = OpenOptions {
                read: true,
                ..Default::default()
            };
            assert_eq!(
                dav.open(&dav_path("/dir"), options)
                    .await
                    .expect_err("a directory cannot be opened as a file"),
                FsError::Forbidden
            );
        });
    }

    #[test]
    fn mkcol_delete_move_and_copy_go_through_the_vault() {
        let (_dir, fs) = test_fs();
        let dav = CryptoDavFs::new(Arc::clone(&fs));
        runtime().block_on(async {
            dav.create_dir(&dav_path("/coll")).await.expect("mkcol");
            assert!(fs
                .metadata(&CleartextPath::parse("/coll"))
                .expect("stat")
                .is_dir());
            assert_eq!(
                dav.create_dir(&dav_path("/coll")).await.expect_err("again"),
                FsError::Exists
            );

            fs.write_file(&CleartextPath::parse("/coll/a.txt"), b"body", false)
                .expect("write");
            dav.copy(&dav_path("/coll/a.txt"), &dav_path("/coll/b.txt"))
                .await
                .expect("copy");
            assert_eq!(
                fs.read_file(&CleartextPath::parse("/coll/b.txt"))
                    .expect("read"),
                b"body"
            );
            dav.rename(&dav_path("/coll/b.txt"), &dav_path("/c.txt"))
                .await
                .expect("move");
            assert!(fs
                .symlink_metadata(&CleartextPath::parse("/coll/b.txt"))
                .is_err());
            dav.remove_file(&dav_path("/c.txt")).await.expect("delete");
            assert_eq!(
                dav.remove_dir(&dav_path("/coll"))
                    .await
                    .expect_err("not empty"),
                FsError::Exists
            );
            dav.remove_file(&dav_path("/coll/a.txt"))
                .await
                .expect("delete");
            dav.remove_dir(&dav_path("/coll")).await.expect("rmdir");
        });
    }

    #[test]
    fn set_modified_updates_the_time_a_propfind_reports() {
        let (_dir, fs) = test_fs();
        fs.write_file(&CleartextPath::parse("/t.txt"), b"x", false)
            .expect("write");
        let dav = CryptoDavFs::new(Arc::clone(&fs));
        // Two distinct times, so that swapping the two calls cannot pass.
        let when = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000);
        let later = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_200_000_000);
        runtime().block_on(async {
            dav.set_modified(&dav_path("/t.txt"), when)
                .await
                .expect("set_modified");
            let meta = dav.metadata(&dav_path("/t.txt")).await.expect("metadata");
            assert_eq!(meta.modified().expect("mtime"), when);
            dav.set_accessed(&dav_path("/t.txt"), later)
                .await
                .expect("set_accessed");
            let meta = dav.metadata(&dav_path("/t.txt")).await.expect("metadata");
            assert_eq!(meta.accessed().expect("atime"), later);
            assert_eq!(
                meta.modified().expect("mtime"),
                when,
                "setting the access time must leave the modification time alone"
            );
        });
    }

    #[test]
    fn a_name_longer_than_the_vault_allows_is_414() {
        let (_dir, fs) = test_fs();
        fs.write_file(&CleartextPath::parse("/src.txt"), b"x", false)
            .expect("write");
        let dav = CryptoDavFs::new(Arc::clone(&fs));
        let long = "n".repeat(fs.max_cleartext_name_length() + 1);
        runtime().block_on(async {
            let err = dav
                .open(&dav_path(&format!("/{long}")), put_options())
                .await
                .expect_err("too long");
            assert_eq!(err, FsError::PathTooLong);
            assert_eq!(
                dav.create_dir(&dav_path(&format!("/{long}")))
                    .await
                    .expect_err("too long"),
                FsError::PathTooLong
            );
            // `rename`/`copy` run the same `assert_name_fits` on their destination.
            assert_eq!(
                dav.rename(&dav_path("/src.txt"), &dav_path(&format!("/{long}")))
                    .await
                    .expect_err("too long"),
                FsError::PathTooLong
            );
            assert_eq!(
                dav.copy(&dav_path("/src.txt"), &dav_path(&format!("/{long}")))
                    .await
                    .expect_err("too long"),
                FsError::PathTooLong
            );
        });
    }

    #[test]
    fn a_read_only_vault_forbids_every_write() {
        let (_dir, fs) = test_fs_with(cryptomator_core::fs::CryptoFsOptions {
            read_only: true,
            ..Default::default()
        });
        let dav = CryptoDavFs::new(fs);
        runtime().block_on(async {
            assert_eq!(
                dav.create_dir(&dav_path("/nope"))
                    .await
                    .expect_err("read-only"),
                FsError::Forbidden
            );
            assert_eq!(
                dav.open(&dav_path("/nope.txt"), put_options())
                    .await
                    .expect_err("read-only"),
                FsError::Forbidden
            );
        });
    }
}
