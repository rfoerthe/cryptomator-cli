//! The FUSE operations over [`CryptoFs`], without any dependency on the fuser event loop.
//!
//! Everything the kernel asks for -- inode + name, or a file handle -- is translated here into
//! the path-based core API and back into the attribute/errno shapes FUSE expects. Keeping this
//! free of `fuser::Filesystem` and `fuser::Request` makes it testable without a mount: the
//! session in the next task only unpacks requests, calls one method here and packs the reply.
//!
//! Deliberate rulings, following Cryptomator's `fuse-nio-adapter`:
//! * `mode`, `uid` and `gid` cannot be stored in a vault, so `chmod`/`chown` are accepted and
//!   ignored; every node is reported as owned by the mount's `uid`/`gid`.
//! * `RENAME_EXCHANGE` has no atomic counterpart in the core and is rejected with `EINVAL`.
//! * A write on a read-only mount fails with `EROFS` before the core is even asked.
use super::errno::errno_for;
use super::handles::{DirHandles, DirListing, DirSnapshot, FileHandles, OpenFileEntry};
use super::inodes::{InodeTable, ROOT_INO};
use crate::flags::AdapterOptions;
use crate::transcoder::NameTranscoder;
use cryptomator_core::fs::{
    CiphertextFileType, CleartextPath, CryptoFs, FileAttributes, OpenOptions,
};
use fuser::{AccessFlags, Errno, FileType, OpenAccMode, OpenFlags, TimeOrNow};
use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

/// Block size reported in every `Attr` (`stat.st_blksize`), as libfuse's own examples do.
const BLOCK_SIZE: u32 = 4096;
/// `stat.st_blocks` counts 512-byte units, whatever `st_blksize` says.
const STAT_BLOCK: u64 = 512;
/// Smallest `statfs` block size we report; a filesystem below this confuses `df`.
const MIN_STATFS_BLOCK_SIZE: u32 = 512;
/// The `d_ino` reported for a listed entry the inode table does not know yet. `readdir` takes no
/// reference on the inodes it names, so allocating real ones would leak the table; this number is
/// only advisory (`ls -i`) and is never handed to a `lookup`.
///
/// The value is libfuse's `FUSE_UNKNOWN_INO`, which the kernel recognises in a plain `readdir`.
/// It must never appear in a **`readdirplus`** reply: there the inode is the one the kernel caches
/// for the name, and a placeholder would alias a real file. The adapter answers `READDIRPLUS` with
/// `ENOSYS` for exactly that reason.
const UNKNOWN_INO: u64 = 0xffff_ffff;
/// macOS resource-fork side car; swept with the `._*` files when `delete_apple_double` is set.
const DS_STORE: &str = ".DS_Store";
/// Permission bits reported for an open file whose own ones could not be read: the neutral mode
/// of a private temporary file, which is all a file without a name still is.
const PRIVATE_FILE_PERM: u16 = 0o600;

/// What the adapter needs to know beyond the vault itself.
#[derive(Debug, Clone)]
pub struct VaultOpsConfig {
    /// Normalisation between the FUSE peer's names and the vault's.
    pub transcoder: NameTranscoder,
    /// The mount options the adapter applies itself (uid/gid, timeouts).
    pub options: AdapterOptions,
    /// Whether the mount refuses every modification.
    pub read_only: bool,
    /// Sweep `._*` and `.DS_Store` out of a directory before removing it (macOS providers write
    /// them behind the user's back, like Java's `deleteAppleDoubleFiles`).
    pub delete_apple_double: bool,
    /// `statfs`' `namelen`: the longest cleartext name the vault accepts.
    pub max_name_length: u32,
}

/// The attributes of one node, in FUSE's shape (`fuser::FileAttr` without `rdev`/`flags`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attr {
    /// The inode the entry is reachable under.
    pub ino: u64,
    /// Cleartext size in bytes.
    pub size: u64,
    /// Size in 512-byte blocks.
    pub blocks: u64,
    /// Time of last access.
    pub atime: SystemTime,
    /// Time of last modification.
    pub mtime: SystemTime,
    /// Time of last status change (the vault stores none: same as `mtime`).
    pub ctime: SystemTime,
    /// Creation time (macOS).
    pub crtime: SystemTime,
    /// File, directory or symlink.
    pub kind: FileType,
    /// Permission bits.
    pub perm: u16,
    /// Hard links: 2 for the root, 1 for everything else (a vault has no hard links).
    pub nlink: u32,
    /// Owner, from the mount options.
    pub uid: u32,
    /// Group, from the mount options.
    pub gid: u32,
    /// Preferred I/O block size.
    pub blksize: u32,
}

/// The answer to `statfs`, taken from the file system holding the vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Statfs {
    /// Total data blocks, in units of `frsize`.
    pub blocks: u64,
    /// Free blocks.
    pub bfree: u64,
    /// Free blocks for unprivileged users.
    pub bavail: u64,
    /// Total inodes.
    pub files: u64,
    /// Free inodes.
    pub ffree: u64,
    /// Preferred transfer block size.
    pub bsize: u32,
    /// Longest name the file system accepts.
    pub namelen: u32,
    /// Fundamental block size.
    pub frsize: u32,
}

/// The result of `create`: the new node's attributes plus the handle it is already open under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Created {
    /// Attributes of the freshly created file.
    pub attr: Attr,
    /// The file handle the caller must release.
    pub fh: u64,
}

/// The FUSE operations of one mounted vault.
#[derive(Debug)]
pub struct VaultOps {
    fs: Arc<CryptoFs>,
    inodes: InodeTable,
    files: FileHandles,
    dirs: DirHandles,
    cfg: VaultOpsConfig,
    vault_path: PathBuf,
}

impl VaultOps {
    /// The operations over `fs`; the inode and handle tables start empty (the root aside).
    pub fn new(fs: Arc<CryptoFs>, cfg: VaultOpsConfig) -> Self {
        let vault_path = fs.vault_path().to_path_buf();
        Self {
            fs,
            inodes: InodeTable::new(),
            files: FileHandles::new(),
            dirs: DirHandles::new(),
            cfg,
            vault_path,
        }
    }

    /// The configuration this adapter runs with (the session needs the cache timeouts).
    pub fn config(&self) -> &VaultOpsConfig {
        &self.cfg
    }

    // --- helpers -------------------------------------------------------------------------

    /// Whether the mount rejects modifications -- either because it was mounted read-only or
    /// because the vault itself is.
    fn is_read_only(&self) -> bool {
        self.cfg.read_only || self.fs.is_read_only()
    }

    fn assert_writable(&self) -> Result<(), Errno> {
        if self.is_read_only() {
            Err(Errno::EROFS)
        } else {
            Ok(())
        }
    }

    /// The path of an inode the kernel still holds; a forgotten one is gone (`ENOENT`).
    fn path_of(&self, ino: u64) -> Result<CleartextPath, Errno> {
        self.inodes.path(ino).ok_or(Errno::ENOENT)
    }

    /// `parent` + a name from the FUSE peer, composed for the vault. A name that is not valid
    /// UTF-8 (or is `.`/`..`/contains a slash) has no vault representation: `EINVAL`.
    fn child_of(&self, parent: u64, name: &OsStr) -> Result<CleartextPath, Errno> {
        let parent = self.path_of(parent)?;
        let name = self
            .cfg
            .transcoder
            .fuse_to_vault(name)
            .ok_or(Errno::EINVAL)?;
        parent.join(&name).map_err(|_| Errno::EINVAL)
    }

    fn attr_of(&self, ino: u64, attrs: &FileAttributes) -> Attr {
        let mtime = attrs.modified.unwrap_or(SystemTime::UNIX_EPOCH);
        Attr {
            ino,
            size: attrs.size,
            blocks: attrs.size.div_ceil(STAT_BLOCK),
            atime: attrs.accessed.unwrap_or(mtime),
            mtime,
            ctime: mtime,
            crtime: attrs.created.unwrap_or(mtime),
            kind: kind_of(attrs.file_type),
            perm: (attrs.mode & 0o7777) as u16,
            nlink: if ino == ROOT_INO { 2 } else { 1 },
            uid: self.cfg.options.uid,
            gid: self.cfg.options.gid,
            blksize: BLOCK_SIZE,
        }
    }

    /// Attributes of a path that just appeared, together with the inode the kernel may now hold.
    fn attr_for_new_path(&self, path: &CleartextPath) -> Result<Attr, Errno> {
        let attrs = self.fs.symlink_metadata(path).map_err(|e| errno_for(&e))?;
        let ino = self.inodes.lookup(path);
        Ok(self.attr_of(ino, &attrs))
    }

    // --- metadata ------------------------------------------------------------------------

    /// Resolves a name in `parent` and counts the reference the kernel now holds on the inode.
    pub fn lookup(&self, parent: u64, name: &OsStr) -> Result<Attr, Errno> {
        let path = self.child_of(parent, name)?;
        self.attr_for_new_path(&path)
    }

    /// Drops `n` of the references `lookup` handed out.
    pub fn forget(&self, ino: u64, n: u64) {
        self.inodes.forget(ino, n);
    }

    /// Attributes of an inode; an open handle supplies the size the file has right now -- and, for
    /// a file that was unlinked while it is open, the attributes altogether.
    pub fn getattr(&self, ino: u64, fh: Option<u64>) -> Result<Attr, Errno> {
        let path = self.path_of(ino)?;
        let open = fh.and_then(|fh| self.files.get(fh));
        let attrs = match self.fs.symlink_metadata(&path) {
            Ok(attrs) => attrs,
            // `fstat` on a descriptor whose name is gone must keep working (POSIX): the inode
            // table hands the path out until the kernel forgets the inode, but nothing is behind
            // it any more, so only the handle can still describe the file.
            Err(e) => {
                return match open {
                    Some(entry) if is_not_found(&e) => Ok(self.attr_of_open_file(ino, &entry)),
                    _ => Err(errno_for(&e)),
                };
            }
        };
        let mut attr = self.attr_of(ino, &attrs);
        if let Some(entry) = open {
            attr.size = entry.handle.size();
            attr.blocks = attr.size.div_ceil(STAT_BLOCK);
        }
        Ok(attr)
    }

    /// Attributes synthesised for a file that lost its name while it was open. Everything the
    /// vault stored went with the directory entry, so the size and the permission bits come from
    /// the handle -- as do the times, if a `setattr` set any after the name was gone: a `futimens`
    /// followed by an `fstat` has to report what it just set, not the wall clock. `nlink` stays 1
    /// rather than the 0 a local `fstat` reports: spike C found FUSE-T sensitive to `nlink`, and a
    /// 0 buys nothing here.
    fn attr_of_open_file(&self, ino: u64, entry: &OpenFileEntry) -> Attr {
        let size = entry.handle.size();
        let now = SystemTime::now();
        let (atime, mtime) = entry.times().unwrap_or((now, now));
        Attr {
            ino,
            size,
            blocks: size.div_ceil(STAT_BLOCK),
            atime,
            mtime,
            // The vault stores neither of the two; `attr_of` reports `mtime` for both as well.
            ctime: mtime,
            crtime: mtime,
            kind: FileType::RegularFile,
            perm: entry.perm,
            nlink: 1,
            uid: self.cfg.options.uid,
            gid: self.cfg.options.gid,
            blksize: BLOCK_SIZE,
        }
    }

    /// Truncation and time stamps; `mode`, `uid` and `gid` are accepted and ignored (a vault has
    /// nowhere to store them).
    pub fn setattr(
        &self,
        ino: u64,
        fh: Option<u64>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
    ) -> Result<Attr, Errno> {
        let path = self.path_of(ino)?;
        if size.is_some() || atime.is_some() || mtime.is_some() {
            self.assert_writable()?;
        }
        if let Some(size) = size {
            self.truncate(&path, fh, size)?;
        }
        if atime.is_some() || mtime.is_some() {
            self.set_times(&path, fh, atime, mtime)?;
        }
        self.getattr(ino, fh)
    }

    /// `ftruncate` through the open handle if there is a writable one, `truncate` through a
    /// short-lived handle otherwise. A file that was unlinked while it is open has no path left to
    /// open, so there the handle is the only way -- and a read-only one is `EBADF`.
    fn truncate(&self, path: &CleartextPath, fh: Option<u64>, size: u64) -> Result<(), Errno> {
        let open = fh.and_then(|fh| self.files.get(fh));
        let unlinked = match self.fs.symlink_metadata(path) {
            Ok(attrs) if attrs.is_dir() => return Err(Errno::EISDIR),
            Ok(_) => false,
            Err(e) if open.is_some() && is_not_found(&e) => true,
            Err(e) => return Err(errno_for(&e)),
        };
        if let Some(entry) = open {
            if entry.writable {
                return entry.handle.truncate(size).map_err(handle_errno_for);
            }
            if unlinked {
                return Err(Errno::EBADF);
            }
        }
        let handle = self
            .fs
            .open_file(path, OpenOptions::read_write())
            .map_err(|e| errno_for(&e))?;
        let result = handle.truncate(size).map_err(handle_errno_for);
        let closed = handle.close().map_err(|e| errno_for(&e));
        result.and(closed)
    }

    /// `utimensat` through the path. A file that was unlinked while it is open has no path left,
    /// so its modification time is kept on the handle instead -- which is what `futimens` on an
    /// unlinked descriptor does. Both times are recorded on the handle as well, so the `fstat`
    /// that follows can report them ([`attr_of_open_file`](Self::attr_of_open_file)).
    fn set_times(
        &self,
        path: &CleartextPath,
        fh: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
    ) -> Result<(), Errno> {
        let Err(e) = self
            .fs
            .set_times(path, mtime.map(resolve_time), atime.map(resolve_time))
        else {
            return Ok(());
        };
        match fh.and_then(|fh| self.files.get(fh)) {
            Some(entry) if is_not_found(&e) => {
                let mtime = mtime.map(resolve_time);
                if let Some(mtime) = mtime {
                    entry.handle.set_last_modified(mtime);
                }
                entry.set_times(atime.map(resolve_time), mtime);
                Ok(())
            }
            _ => Err(errno_for(&e)),
        }
    }

    /// The target of a symlink, in the FUSE peer's normal form.
    pub fn readlink(&self, ino: u64) -> Result<Vec<u8>, Errno> {
        let path = self.path_of(ino)?;
        let target = self.fs.read_link(&path).map_err(|e| errno_for(&e))?;
        Ok(self.cfg.transcoder.vault_to_fuse(&target).into_vec())
    }

    // --- namespace -----------------------------------------------------------------------

    pub fn mkdir(&self, parent: u64, name: &OsStr) -> Result<Attr, Errno> {
        self.assert_writable()?;
        let path = self.child_of(parent, name)?;
        self.fs.create_dir(&path).map_err(|e| errno_for(&e))?;
        self.attr_for_new_path(&path)
    }

    /// Removes a file or symlink; a directory is `EISDIR` (that is `rmdir`'s job).
    pub fn unlink(&self, parent: u64, name: &OsStr) -> Result<(), Errno> {
        self.assert_writable()?;
        let path = self.child_of(parent, name)?;
        let attrs = self.fs.symlink_metadata(&path).map_err(|e| errno_for(&e))?;
        if attrs.is_dir() {
            return Err(Errno::EISDIR);
        }
        self.remove(&path)
    }

    /// Removes an empty directory; anything else is `ENOTDIR`.
    pub fn rmdir(&self, parent: u64, name: &OsStr) -> Result<(), Errno> {
        self.assert_writable()?;
        let path = self.child_of(parent, name)?;
        let attrs = self.fs.symlink_metadata(&path).map_err(|e| errno_for(&e))?;
        if !attrs.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        if self.cfg.delete_apple_double {
            self.sweep_apple_double_files(&path);
        }
        self.remove(&path)
    }

    fn remove(&self, path: &CleartextPath) -> Result<(), Errno> {
        self.fs.delete(path).map_err(|e| errno_for(&e))?;
        self.inodes.remove_path(path);
        Ok(())
    }

    /// `deleteAppleDoubleFiles`: macOS writes `._name` side cars and `.DS_Store` into directories
    /// the user believes to be empty, and then its own `rmdir` fails. Errors are ignored on
    /// purpose -- the `delete` that follows reports the directory as non-empty anyway.
    fn sweep_apple_double_files(&self, dir: &CleartextPath) {
        let Ok(entries) = self.fs.read_dir(dir) else {
            return;
        };
        for entry in entries {
            if !is_apple_double(&entry.cleartext_name) {
                continue;
            }
            let Ok(child) = dir.join(&entry.cleartext_name) else {
                continue;
            };
            if self.fs.delete(&child).is_ok() {
                self.inodes.remove_path(&child);
            }
        }
    }

    pub fn symlink(&self, parent: u64, link_name: &OsStr, target: &Path) -> Result<Attr, Errno> {
        self.assert_writable()?;
        let path = self.child_of(parent, link_name)?;
        let target = self
            .cfg
            .transcoder
            .fuse_to_vault(target.as_os_str())
            .ok_or(Errno::EINVAL)?;
        self.fs
            .create_symlink(&path, &target)
            .map_err(|e| errno_for(&e))?;
        self.attr_for_new_path(&path)
    }

    /// Renames, then re-keys the inode table so handles the kernel still holds keep resolving.
    /// `noreplace` is `RENAME_NOREPLACE`; `exchange` (`RENAME_EXCHANGE`) has no atomic
    /// counterpart in the core and is rejected.
    pub fn rename(
        &self,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        noreplace: bool,
        exchange: bool,
    ) -> Result<(), Errno> {
        if exchange {
            return Err(Errno::EINVAL);
        }
        self.assert_writable()?;
        let src = self.child_of(parent, name)?;
        let dst = self.child_of(newparent, newname)?;
        self.fs
            .rename(&src, &dst, !noreplace)
            .map_err(|e| errno_for(&e))?;
        self.inodes.rename(&src, &dst);
        Ok(())
    }

    // --- files ---------------------------------------------------------------------------

    /// Opens an existing node. `O_WRONLY` opens read-write in the core so `getattr(fh)` and a
    /// read-modify-write of a partial chunk keep working; the kernel already refuses reads on a
    /// write-only descriptor.
    pub fn open(&self, ino: u64, flags: OpenFlags) -> Result<u64, Errno> {
        let path = self.path_of(ino)?;
        let options = self.open_options(flags, false)?;
        let handle = self
            .fs
            .open_file(&path, options)
            .map_err(|e| errno_for(&e))?;
        let writable = handle.is_writable();
        let append = is_set(flags, libc::O_APPEND);
        let perm = self.perm_of(&path);
        Ok(self
            .files
            .insert(OpenFileEntry::new(handle, path, append, writable, perm)))
    }

    /// The permission bits of a node that was just opened, kept for the day its name is gone.
    /// A node that cannot be stat'ed (a race with a concurrent unlink) falls back to the neutral
    /// mode of a private temporary file, which is all an unnamed file can claim to be.
    fn perm_of(&self, path: &CleartextPath) -> u16 {
        self.fs
            .symlink_metadata(path)
            .map_or(PRIVATE_FILE_PERM, |attrs| (attrs.mode & 0o7777) as u16)
    }

    /// Creates and opens in one step. `O_EXCL` makes it exclusive (`EEXIST` if the name is
    /// taken); without it an existing file is opened (and truncated for `O_TRUNC`).
    pub fn create(&self, parent: u64, name: &OsStr, flags: OpenFlags) -> Result<Created, Errno> {
        let path = self.child_of(parent, name)?;
        let options = self.open_options(flags, true)?;
        let handle = self
            .fs
            .open_file(&path, options)
            .map_err(|e| errno_for(&e))?;
        let writable = handle.is_writable();
        let append = is_set(flags, libc::O_APPEND);
        // Stat before registering the handle: on failure the kernel never learns the `fh`, so an
        // entry in the table would be one nobody ever releases.
        let attr = match self.attr_for_new_path(&path) {
            Ok(attr) => attr,
            Err(e) => {
                let _ = handle.close();
                return Err(e);
            }
        };
        let fh = self.files.insert(OpenFileEntry::new(
            handle, path, append, writable, attr.perm,
        ));
        Ok(Created { attr, fh })
    }

    /// Translates the kernel's open flags; `create` adds `O_CREAT` regardless of what the peer
    /// sent, because that is what the `create` request means.
    fn open_options(&self, flags: OpenFlags, create: bool) -> Result<OpenOptions, Errno> {
        let write = create || flags.acc_mode() != OpenAccMode::O_RDONLY;
        if !write {
            return Ok(OpenOptions::read_only());
        }
        self.assert_writable()?;
        let exclusive = create && is_set(flags, libc::O_EXCL);
        Ok(OpenOptions {
            read: true,
            write: true,
            create: create && !exclusive,
            create_new: exclusive,
            truncate: is_set(flags, libc::O_TRUNC),
        })
    }

    /// Reads at most `size` bytes; a short result means end of file.
    pub fn read(&self, fh: u64, offset: u64, size: u32) -> Result<Vec<u8>, Errno> {
        let entry = self.files.get(fh).ok_or(Errno::EBADF)?;
        if !entry.handle.is_readable() {
            return Err(Errno::EBADF);
        }
        let available = entry.handle.size().saturating_sub(offset);
        let wanted = usize::try_from(u64::from(size).min(available)).unwrap_or(usize::MAX);
        let mut buf = vec![0u8; wanted];
        let mut done = 0;
        while done < buf.len() {
            let read = entry
                .handle
                .read_at(&mut buf[done..], offset + done as u64)
                .map_err(handle_errno_for)?;
            if read == 0 {
                break;
            }
            done += read;
        }
        buf.truncate(done);
        Ok(buf)
    }

    /// Writes `data`; an `O_APPEND` handle ignores `offset` and writes at the current end.
    pub fn write(&self, fh: u64, offset: u64, data: &[u8]) -> Result<u32, Errno> {
        let entry = self.files.get(fh).ok_or(Errno::EBADF)?;
        if !entry.writable {
            return Err(Errno::EBADF);
        }
        let position = if entry.append {
            entry.handle.size()
        } else {
            offset
        };
        entry
            .handle
            .write_all_at(data, position)
            .map_err(handle_errno_for)?;
        u32::try_from(data.len()).map_err(|_| Errno::EINVAL)
    }

    /// `flush` on every `close()` of a descriptor: the data reach the ciphertext file, but not
    /// necessarily the disk (that is `fsync`).
    pub fn flush(&self, fh: u64) -> Result<(), Errno> {
        let entry = self.files.get(fh).ok_or(Errno::EBADF)?;
        entry.handle.flush().map_err(|e| errno_for(&e))
    }

    /// The last reference on a descriptor: closes the core handle and reports its errors.
    pub fn release(&self, fh: u64) -> Result<(), Errno> {
        if self.files.get(fh).is_none() {
            return Err(Errno::EBADF);
        }
        match self.files.remove(fh) {
            // A concurrent request still holds the handle; dropping its `Arc` closes it.
            None => Ok(()),
            Some(entry) => entry.handle.close().map_err(|e| errno_for(&e)),
        }
    }

    pub fn fsync(&self, fh: u64, datasync: bool) -> Result<(), Errno> {
        let entry = self.files.get(fh).ok_or(Errno::EBADF)?;
        entry.handle.sync(!datasync).map_err(|e| errno_for(&e))
    }

    // --- directories ---------------------------------------------------------------------

    /// Snapshots the listing, so a directory that changes while it is read cannot make the
    /// kernel skip or repeat entries.
    pub fn opendir(&self, ino: u64) -> Result<u64, Errno> {
        let path = self.path_of(ino)?;
        let listing = self.fs.read_dir(&path).map_err(|e| errno_for(&e))?;
        let parent_ino = match path.parent() {
            Some(parent) => self.inodes.ino_of(&parent).unwrap_or(ROOT_INO),
            None => ROOT_INO,
        };
        let mut entries = Vec::with_capacity(listing.len() + 2);
        entries.push(DirListing {
            name: ".".into(),
            ino,
            kind: FileType::Directory,
        });
        entries.push(DirListing {
            name: "..".into(),
            ino: parent_ino,
            kind: FileType::Directory,
        });
        for entry in listing {
            let Ok(child) = path.join(&entry.cleartext_name) else {
                continue; // a name the vault holds but a path cannot express
            };
            let Ok(attrs) = self.fs.symlink_metadata(&child) else {
                continue; // vanished (or broken) between listing and stat
            };
            entries.push(DirListing {
                name: self.cfg.transcoder.vault_to_fuse(&entry.cleartext_name),
                ino: self.inodes.ino_of(&child).unwrap_or(UNKNOWN_INO),
                kind: kind_of(attrs.file_type),
            });
        }
        Ok(self.dirs.insert(DirSnapshot { entries }))
    }

    /// At most `limit` entries of the snapshot from index `offset` on, each with the offset to
    /// resume at.
    ///
    /// The limit is the caller's reply budget and is applied before the entries are cloned: a
    /// directory with a million names must cost one batch per request, not a million clones.
    pub fn readdir(
        &self,
        fh: u64,
        offset: u64,
        limit: usize,
    ) -> Result<Vec<(DirListing, u64)>, Errno> {
        let snapshot = self.dirs.get(fh).ok_or(Errno::EBADF)?;
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        Ok(snapshot
            .entries
            .iter()
            .enumerate()
            .skip(start)
            .take(limit)
            .map(|(index, entry)| (entry.clone(), index as u64 + 1))
            .collect())
    }

    pub fn releasedir(&self, fh: u64) -> Result<(), Errno> {
        if self.dirs.get(fh).is_none() {
            return Err(Errno::EBADF);
        }
        self.dirs.remove(fh);
        Ok(())
    }

    // --- volume --------------------------------------------------------------------------

    /// Numbers of the file system holding the vault; the ciphertext overhead is not subtracted,
    /// exactly as Cryptomator reports it.
    pub fn statfs(&self) -> Result<Statfs, Errno> {
        let stat =
            nix::sys::statvfs::statvfs(&self.vault_path).map_err(|e| Errno::from_i32(e as i32))?;
        let frsize = block_size(stat.fragment_size());
        let bsize = if stat.fragment_size() > 0 {
            frsize
        } else {
            block_size(stat.block_size())
        };
        Ok(Statfs {
            blocks: stat.blocks() as u64,
            bfree: stat.blocks_free() as u64,
            bavail: stat.blocks_available() as u64,
            files: stat.files() as u64,
            ffree: stat.files_free() as u64,
            bsize,
            namelen: self.cfg.max_name_length,
            frsize,
        })
    }

    /// Existence check plus the read-only ruling; the vault stores no permissions, so `R_OK` and
    /// `X_OK` are granted for every node the mount's owner can see.
    pub fn access(&self, ino: u64, mask: AccessFlags) -> Result<(), Errno> {
        let path = self.path_of(ino)?;
        self.fs.symlink_metadata(&path).map_err(|e| errno_for(&e))?;
        if mask.contains(AccessFlags::W_OK) && self.is_read_only() {
            return Err(Errno::EROFS);
        }
        Ok(())
    }

    /// Whether any file is still open -- an unmount would lose their buffered writes.
    pub fn is_in_use(&self) -> bool {
        !self.files.is_empty()
    }
}

fn kind_of(file_type: CiphertextFileType) -> FileType {
    match file_type {
        CiphertextFileType::Directory => FileType::Directory,
        CiphertextFileType::Symlink => FileType::Symlink,
        CiphertextFileType::File => FileType::RegularFile,
    }
}

fn resolve_time(time: TimeOrNow) -> SystemTime {
    match time {
        TimeOrNow::SpecificTime(time) => time,
        TimeOrNow::Now => SystemTime::now(),
    }
}

fn is_set(flags: OpenFlags, flag: i32) -> bool {
    flags.0 & flag != 0
}

/// Like [`errno_for`], but for the handle layer: it reports "not opened for reading/writing" as
/// `PermissionDenied`, which the kernel expects as `EBADF` (a wrong descriptor), not `EACCES`.
///
/// Only the core's own synthetic errors are re-classified. An error carrying an OS code came from
/// the operating system, where `EACCES` means exactly `EACCES`, and passes through [`errno_for`].
fn handle_errno_for(err: io::Error) -> Errno {
    if err.raw_os_error().is_none() && err.kind() == io::ErrorKind::PermissionDenied {
        Errno::EBADF
    } else {
        errno_for(&err)
    }
}

/// Whether `err` says "no such file or directory", however the core phrased it.
fn is_not_found(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::NotFound || err.raw_os_error() == Some(libc::ENOENT)
}

fn block_size(raw: impl TryInto<u32>) -> u32 {
    raw.try_into()
        .unwrap_or(MIN_STATFS_BLOCK_SIZE)
        .max(MIN_STATFS_BLOCK_SIZE)
}

fn is_apple_double(name: &str) -> bool {
    name.starts_with("._") || name == DS_STORE
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transcoder::FuseNormalization;
    use cryptomator_core::constants::DEFAULT_KEY_ID;
    use cryptomator_core::fs::CryptoFsOptions;
    use cryptomator_core::{
        initialize, open_vault_with_key, CipherCombo, DetRng, Masterkey, VaultConfig,
    };
    use std::ffi::OsString;
    use std::time::Duration;
    use tempfile::TempDir;

    const MAX_NAME_LENGTH: u32 = 10 * 1024;

    fn masterkey() -> Masterkey {
        Masterkey::from_raw([0x42; 64])
    }

    fn test_ops(read_only: bool) -> (TempDir, VaultOps) {
        test_ops_with(read_only, false)
    }

    fn test_ops_with(read_only: bool, delete_apple_double: bool) -> (TempDir, VaultOps) {
        let dir = tempfile::tempdir().expect("temp dir");
        let config: VaultConfig = initialize(
            dir.path(),
            &masterkey(),
            CipherCombo::SivGcm,
            220,
            DEFAULT_KEY_ID,
            &mut DetRng::default(),
        )
        .expect("initialize vault");
        assert_eq!(config.cipher_combo, CipherCombo::SivGcm);
        let opened = open_vault_with_key(dir.path(), masterkey()).expect("open vault");
        let fs = CryptoFs::open(
            opened,
            CryptoFsOptions {
                read_only,
                ..Default::default()
            },
        );
        let cfg = VaultOpsConfig {
            transcoder: NameTranscoder::new(FuseNormalization::Nfd),
            options: AdapterOptions::for_user(501, 20),
            read_only,
            delete_apple_double,
            max_name_length: MAX_NAME_LENGTH,
        };
        (dir, VaultOps::new(Arc::new(fs), cfg))
    }

    #[test]
    fn full_file_lifecycle_through_ops() {
        let (_dir, ops) = test_ops(false);
        let root = ops.getattr(1, None).expect("root attributes");
        assert_eq!(root.kind, FileType::Directory);
        assert_eq!((root.nlink, root.uid, root.gid), (2, 501, 20));
        let d = ops.mkdir(1, OsStr::new("docs")).expect("mkdir");
        let c = ops
            .create(
                d.ino,
                OsStr::new("a.txt"),
                OpenFlags(libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL),
            )
            .expect("create");
        assert_eq!(ops.write(c.fh, 0, b"hello").expect("write"), 5);
        assert_eq!(ops.write(c.fh, 5, b" world").expect("write"), 6);
        ops.flush(c.fh).expect("flush");
        ops.release(c.fh).expect("release");
        let a = ops.lookup(d.ino, OsStr::new("a.txt")).expect("lookup");
        assert_eq!(a.size, 11);
        let fh = ops.open(a.ino, OpenFlags(libc::O_RDONLY)).expect("open");
        assert_eq!(ops.read(fh, 6, 100).expect("read"), b"world");
        assert_eq!(ops.read(fh, 11, 10).expect("read at eof"), Vec::<u8>::new());
        assert_eq!(
            ops.write(fh, 0, b"x").unwrap_err(),
            Errno::EBADF,
            "read-only handle"
        );
        ops.release(fh).expect("release");
        let fh = ops
            .open(a.ino, OpenFlags(libc::O_WRONLY | libc::O_APPEND))
            .expect("open for append");
        ops.write(fh, 0, b"!").expect("append");
        ops.release(fh).expect("release");
        assert_eq!(ops.getattr(a.ino, None).expect("getattr").size, 12);
        let t = ops
            .setattr(a.ino, None, Some(5), None, None)
            .expect("truncate");
        assert_eq!(t.size, 5);
        let fh = ops
            .open(a.ino, OpenFlags(libc::O_RDWR | libc::O_TRUNC))
            .expect("open truncating");
        assert_eq!(ops.getattr(a.ino, Some(fh)).expect("getattr").size, 0);
        ops.release(fh).expect("release");
        // directory listing with . and ..
        let dh = ops.opendir(d.ino).expect("opendir");
        let names: Vec<String> = ops
            .readdir(dh, 0, usize::MAX)
            .expect("readdir")
            .into_iter()
            .map(|(e, _)| e.name.to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec![".", "..", "a.txt"]);
        // The limit bounds the batch, and the offset it hands back resumes right after it.
        let batch = ops.readdir(dh, 1, 1).expect("one entry from offset 1");
        assert_eq!(
            batch.len(),
            1,
            "the limit is applied, not the snapshot size"
        );
        assert_eq!(batch[0].0.name, OsString::from(".."));
        assert_eq!(batch[0].1, 2, "the next request resumes after this entry");
        assert!(ops
            .readdir(dh, 3, usize::MAX)
            .expect("readdir past the end")
            .is_empty());
        assert!(
            ops.readdir(dh, 0, 0)
                .expect("readdir with no budget")
                .is_empty(),
            "a zero limit asks for nothing"
        );
        ops.releasedir(dh).expect("releasedir");
        // rename keeps inode, unlink/rmdir
        ops.rename(
            d.ino,
            OsStr::new("a.txt"),
            1,
            OsStr::new("b.txt"),
            false,
            false,
        )
        .expect("rename");
        assert_eq!(
            ops.lookup(1, OsStr::new("b.txt")).expect("lookup").ino,
            a.ino
        );
        assert_eq!(
            ops.lookup(d.ino, OsStr::new("a.txt")).unwrap_err(),
            Errno::ENOENT
        );
        assert_eq!(
            ops.rename(1, OsStr::new("b.txt"), 1, OsStr::new("docs"), true, false)
                .unwrap_err(),
            Errno::EEXIST
        );
        assert_eq!(
            ops.rmdir(1, OsStr::new("b.txt")).unwrap_err(),
            Errno::ENOTDIR
        );
        assert_eq!(
            ops.unlink(1, OsStr::new("docs")).unwrap_err(),
            Errno::EISDIR
        );
        ops.unlink(1, OsStr::new("b.txt")).expect("unlink");
        ops.rmdir(1, OsStr::new("docs")).expect("rmdir");
        assert_eq!(
            ops.lookup(1, OsStr::new("docs")).unwrap_err(),
            Errno::ENOENT
        );
        assert!(!ops.is_in_use());
    }

    #[test]
    fn symlinks_transcoding_and_read_only() {
        let (_dir, ops) = test_ops(false);
        let l = ops
            .symlink(1, OsStr::new("link"), Path::new("docs/a.txt"))
            .expect("symlink");
        assert_eq!(l.kind, FileType::Symlink);
        assert_eq!(ops.readlink(l.ino).expect("readlink"), b"docs/a.txt");
        // NFD name from FUSE is stored NFC and served back NFD
        let f = ops
            .create(
                1,
                OsStr::new("cafe\u{301}.txt"),
                OpenFlags(libc::O_WRONLY | libc::O_CREAT),
            )
            .expect("create");
        ops.release(f.fh).expect("release");
        assert!(
            ops.lookup(1, OsStr::new("caf\u{e9}.txt")).is_ok(),
            "NFC lookup also works after transcoding"
        );
        let dh = ops.opendir(1).expect("opendir");
        let names: Vec<OsString> = ops
            .readdir(dh, 0, usize::MAX)
            .expect("readdir")
            .into_iter()
            .map(|(e, _)| e.name)
            .collect();
        assert!(names.contains(&OsString::from("cafe\u{301}.txt")));
        ops.releasedir(dh).expect("releasedir");
        let (_dir, ro) = test_ops(true);
        assert_eq!(ro.mkdir(1, OsStr::new("d")).unwrap_err(), Errno::EROFS);
        assert_eq!(ro.access(1, AccessFlags::W_OK).unwrap_err(), Errno::EROFS);
        assert!(ro.access(1, AccessFlags::R_OK).is_ok());
        let s = ro.statfs().expect("statfs");
        assert!(s.bsize > 0 && s.namelen == MAX_NAME_LENGTH);
    }

    #[test]
    fn unlinked_open_file_keeps_fstat_and_ftruncate_working() {
        let (_dir, ops) = test_ops(false);
        let c = ops
            .create(
                1,
                OsStr::new("doomed.txt"),
                OpenFlags(libc::O_RDWR | libc::O_CREAT | libc::O_EXCL),
            )
            .expect("create");
        assert_eq!(ops.write(c.fh, 0, b"hello").expect("write"), 5);
        ops.unlink(1, OsStr::new("doomed.txt")).expect("unlink");
        assert_eq!(
            ops.lookup(1, OsStr::new("doomed.txt")).unwrap_err(),
            Errno::ENOENT,
            "the name is gone"
        );
        // `fstat` through the handle still works, and reports what the handle holds.
        let attr = ops.getattr(c.attr.ino, Some(c.fh)).expect("fstat");
        assert_eq!((attr.size, attr.kind), (5, FileType::RegularFile));
        assert_eq!(attr.ino, c.attr.ino);
        assert_eq!(
            attr.perm, c.attr.perm,
            "the permission bits the file had when it was opened, not a hard-coded mode"
        );
        // ... while `stat` on the (forgotten) name does not.
        assert_eq!(ops.getattr(c.attr.ino, None).unwrap_err(), Errno::ENOENT);
        // `ftruncate` goes through the handle as well, and `futimens` is not only accepted: the
        // times it sets have to come back out of the handle, since nothing else holds them.
        let when = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let accessed = when + Duration::from_secs(60);
        let truncated = ops
            .setattr(
                c.attr.ino,
                Some(c.fh),
                Some(2),
                Some(TimeOrNow::SpecificTime(accessed)),
                Some(TimeOrNow::SpecificTime(when)),
            )
            .expect("ftruncate");
        assert_eq!(truncated.size, 2);
        assert_eq!(
            (truncated.mtime, truncated.atime),
            (when, accessed),
            "the reply echoes the times that were just set"
        );
        let after = ops.getattr(c.attr.ino, Some(c.fh)).expect("fstat");
        assert_eq!(
            (after.mtime, after.atime),
            (when, accessed),
            "and a later fstat still reports them"
        );
        assert_eq!(ops.read(c.fh, 0, 10).expect("read"), b"he");
        ops.release(c.fh).expect("release");
        assert!(!ops.is_in_use());
        // Without a handle there is nothing left to describe.
        assert_eq!(
            ops.setattr(c.attr.ino, None, Some(1), None, None)
                .unwrap_err(),
            Errno::ENOENT
        );
    }

    #[test]
    fn rmdir_sweeps_apple_double_files_when_configured() {
        for sweep in [false, true] {
            let (_dir, ops) = test_ops_with(false, sweep);
            let d = ops.mkdir(1, OsStr::new("d")).expect("mkdir");
            for name in ["._x", ".DS_Store"] {
                let c = ops
                    .create(
                        d.ino,
                        OsStr::new(name),
                        OpenFlags(libc::O_WRONLY | libc::O_CREAT),
                    )
                    .expect("create side car");
                ops.release(c.fh).expect("release");
            }
            let result = ops.rmdir(1, OsStr::new("d"));
            if sweep {
                result.expect("rmdir sweeps the side cars");
                assert_eq!(ops.lookup(1, OsStr::new("d")).unwrap_err(), Errno::ENOENT);
            } else {
                assert_eq!(result.unwrap_err(), Errno::ENOTEMPTY);
                assert!(ops.lookup(1, OsStr::new("d")).is_ok());
            }
        }
    }
}
