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
use cryptomator_core::fs::{CleartextPath, CryptoFs, FileAttributes};
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

/// `std::io::Error` -> `FsError`, the WebDAV counterpart of [`crate::fuse::errno_for`].
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
        _ => FsError::GeneralFailure,
    }
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

impl DavFileSystem for CryptoDavFs {
    // Task 3 replaces this with the real `CryptoDavFile`; the trait has no default body for
    // `open`, so the read side needs a stub to compile.
    fn open<'a>(
        &'a self,
        _path: &'a DavPath,
        _options: OpenOptions,
    ) -> FsFuture<'a, Box<dyn DavFile>> {
        Box::pin(async move { Err(FsError::NotImplemented) })
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
                    let Ok(child) = dir.join(&entry.cleartext_name) else {
                        continue;
                    };
                    // Java logs and skips a child whose attributes cannot be read, and skips
                    // anything that is not a file or a directory. Both end up here.
                    match node_metadata(&fs, &child) {
                        Ok(meta) => out.push(Box::new(CryptoDavEntry::new(
                            entry.cleartext_name.into_bytes(),
                            meta,
                        ))),
                        Err(FsError::NotFound) => {}
                        Err(err) => log::warn!("skipping {child} in the listing: {err}"),
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
    use crate::testing::test_fs;
    use dav_server::fs::ReadDirMeta;
    use futures_util::StreamExt;

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
            // A birth time only exists where the host file system stores one: macOS always does,
            // ext4 does not expose it through `std`, so there it is a 501.
            #[cfg(target_os = "macos")]
            meta.created().expect("a creation time");
            #[cfg(not(target_os = "macos"))]
            assert!(
                matches!(meta.created(), Ok(_) | Err(FsError::NotImplemented)),
                "a creation time or an honest 501"
            );
            assert!(
                meta.etag().is_some(),
                "an etag is derived from size and mtime"
            );
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
}
