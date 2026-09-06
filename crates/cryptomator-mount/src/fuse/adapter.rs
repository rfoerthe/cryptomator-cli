//! The `fuser::Filesystem` implementation: the only place that knows about the fuser event loop.
//!
//! It is deliberately thin. Every method unpacks the request, calls exactly one [`VaultOps`]
//! method and packs the `Result<_, Errno>` into the matching reply -- there is no logic here that
//! could not be tested through [`VaultOps`] without a mount.
//!
//! Deliberate rulings, following Cryptomator's `fuse-nio-adapter`:
//! * `readdirplus` is answered with `ENOSYS`. The listing's inodes are the ones the kernel would
//!   then cache for the names, and a snapshot cannot supply them without leaking a lookup count
//!   per entry (see [`ops::UNKNOWN_INO`](super::ops)). Both libfuse and FUSE-T fall back to plain
//!   `readdir`.
//! * `mknod` is `ENOSYS` (a vault holds no devices, fifos or sockets) and `link` is `EPERM`
//!   (no hard links); `create` covers the regular files the kernel would otherwise `mknod`.
//! * Extended attributes are `ENOTSUP`: a vault has nowhere to store them, and macOS asks for
//!   them constantly.
//! * `chmod`/`chown` are accepted and ignored by [`VaultOps::setattr`], which then answers with
//!   the attributes the node actually has.
use super::ops::{Attr, VaultOps};
use fuser::{
    AccessFlags, BsdFileFlags, Errno, FileAttr, FileHandle, Filesystem, FopenFlags, Generation,
    INodeNo, KernelConfig, LockOwner, OpenFlags, RenameFlags, ReplyAttr, ReplyCreate, ReplyData,
    ReplyDirectory, ReplyDirectoryPlus, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite,
    ReplyXattr, Request, TimeOrNow,
};
use std::ffi::OsStr;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// How many entries one `READDIR` reply may ask [`VaultOps::readdir`] for.
///
/// It is the budget of one reply, not a truncation: the kernel resumes at the offset of the last
/// entry it took, so a directory of any size is served in batches of this many. The reply buffer
/// would stop the loop as well (`add` reports "full"), but only after the entries had been cloned
/// out of the snapshot -- which is why the bound is passed down rather than applied here.
const READDIR_BATCH: usize = 64;

/// `RENAME_NOREPLACE`, spelled out because `fuser::RenameFlags` only defines it on Linux while
/// FUSE-T sends the Linux bits on macOS as well.
const RENAME_NOREPLACE: u32 = 1;
/// `RENAME_EXCHANGE`, see [`RENAME_NOREPLACE`].
const RENAME_EXCHANGE: u32 = 2;

/// The fuser filesystem of one mounted vault.
#[derive(Debug)]
pub struct CryptoFuse {
    ops: Arc<VaultOps>,
}

impl CryptoFuse {
    /// The filesystem serving `ops`.
    pub fn new(ops: Arc<VaultOps>) -> Self {
        Self { ops }
    }

    /// How long the kernel may cache attributes (`-oattr_timeout=`).
    fn attr_ttl(&self) -> Duration {
        self.ops.config().options.attr_timeout
    }

    /// How long the kernel may cache a name → inode mapping (`-oentry_timeout=`).
    fn entry_ttl(&self) -> Duration {
        self.ops.config().options.entry_timeout
    }

    /// Answers a request that produces a directory entry.
    fn reply_entry(&self, reply: ReplyEntry, result: Result<Attr, Errno>) {
        match result {
            Ok(attr) => reply.entry_with_ttls(
                &self.attr_ttl(),
                &self.entry_ttl(),
                &file_attr(&attr),
                Generation(0),
            ),
            Err(e) => reply.error(e),
        }
    }

    /// Answers a request that produces attributes.
    fn reply_attr(&self, reply: ReplyAttr, result: Result<Attr, Errno>) {
        match result {
            Ok(attr) => reply.attr(&self.attr_ttl(), &file_attr(&attr)),
            Err(e) => reply.error(e),
        }
    }

    /// Answers a request that only has to succeed or fail.
    fn reply_empty(reply: ReplyEmpty, result: Result<(), Errno>) {
        match result {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    /// Answers an `open`/`opendir` that produced a file handle.
    fn reply_open(reply: ReplyOpen, result: Result<u64, Errno>) {
        match result {
            Ok(fh) => reply.opened(FileHandle(fh), FopenFlags::empty()),
            Err(e) => reply.error(e),
        }
    }
}

/// [`Attr`] in fuser's shape. A vault has no device nodes (`rdev`) and stores no BSD file flags,
/// so both are zero.
fn file_attr(attr: &Attr) -> FileAttr {
    FileAttr {
        ino: INodeNo(attr.ino),
        size: attr.size,
        blocks: attr.blocks,
        atime: attr.atime,
        mtime: attr.mtime,
        ctime: attr.ctime,
        crtime: attr.crtime,
        kind: attr.kind,
        perm: attr.perm,
        nlink: attr.nlink,
        uid: attr.uid,
        gid: attr.gid,
        rdev: 0,
        blksize: attr.blksize,
        flags: 0,
    }
}

impl Filesystem for CryptoFuse {
    /// The defaults fuser negotiates are what this adapter wants; nothing here needs a larger
    /// write size, passthrough or a coarser time granularity.
    fn init(&mut self, _req: &Request, _config: &mut KernelConfig) -> io::Result<()> {
        Ok(())
    }

    /// Nothing to tear down: the session owns the [`VaultOps`], and unlocking the vault is the
    /// mount's job, not the event loop's. FUSE-T does not send `DESTROY` at all (spike C).
    fn destroy(&mut self) {}

    // --- metadata ------------------------------------------------------------------------

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        self.reply_entry(reply, self.ops.lookup(parent.0, name));
    }

    fn forget(&self, _req: &Request, ino: INodeNo, nlookup: u64) {
        self.ops.forget(ino.0, nlookup);
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, fh: Option<FileHandle>, reply: ReplyAttr) {
        self.reply_attr(reply, self.ops.getattr(ino.0, fh.map(|fh| fh.0)));
    }

    /// `mode`, `uid`, `gid` and the BSD file flags have nowhere to live in a vault and are
    /// accepted as a no-op; the reply carries the attributes the node really has. `ctime`,
    /// `crtime`, `chgtime` and `bkuptime` are not settable either -- only `atime` and `mtime` are.
    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        let result = self
            .ops
            .setattr(ino.0, fh.map(|fh| fh.0), size, atime, mtime);
        self.reply_attr(reply, result);
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        match self.ops.readlink(ino.0) {
            Ok(target) => reply.data(&target),
            Err(e) => reply.error(e),
        }
    }

    // --- namespace -----------------------------------------------------------------------

    /// A vault stores regular files, directories and symlinks -- nothing `mknod` could create.
    /// The kernel calls `create` for regular files whenever the filesystem implements it.
    fn mknod(
        &self,
        _req: &Request,
        _parent: INodeNo,
        _name: &OsStr,
        _mode: u32,
        _umask: u32,
        _rdev: u32,
        reply: ReplyEntry,
    ) {
        reply.error(Errno::ENOSYS);
    }

    fn mkdir(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        self.reply_entry(reply, self.ops.mkdir(parent.0, name));
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        Self::reply_empty(reply, self.ops.unlink(parent.0, name));
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        Self::reply_empty(reply, self.ops.rmdir(parent.0, name));
    }

    fn symlink(
        &self,
        _req: &Request,
        parent: INodeNo,
        link_name: &OsStr,
        target: &Path,
        reply: ReplyEntry,
    ) {
        self.reply_entry(reply, self.ops.symlink(parent.0, link_name, target));
    }

    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        let bits = flags.bits();
        let result = self.ops.rename(
            parent.0,
            name,
            newparent.0,
            newname,
            bits & RENAME_NOREPLACE != 0,
            bits & RENAME_EXCHANGE != 0,
        );
        Self::reply_empty(reply, result);
    }

    /// A vault has no hard links; `EPERM` is what the kernel expects for a filesystem that cannot
    /// make them (and what fuser's own default replies).
    fn link(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _newparent: INodeNo,
        _newname: &OsStr,
        reply: ReplyEntry,
    ) {
        reply.error(Errno::EPERM);
    }

    // --- files ---------------------------------------------------------------------------

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        Self::reply_open(reply, self.ops.open(ino.0, flags));
    }

    /// `mode` and `umask` are dropped: the vault has no permission bits to apply them to.
    fn create(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        match self.ops.create(parent.0, name, OpenFlags(flags)) {
            Ok(created) => reply.created(
                // `created` carries a single TTL for both the entry and the attributes, so it has
                // to be the shorter of the two: caching either one longer than configured would
                // be wrong, caching it shorter never is.
                &self.attr_ttl().min(self.entry_ttl()),
                &file_attr(&created.attr),
                Generation(0),
                FileHandle(created.fh),
                FopenFlags::empty(),
            ),
            Err(e) => reply.error(e),
        }
    }

    fn read(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        match self.ops.read(fh.0, offset, size) {
            Ok(data) => reply.data(&data),
            Err(e) => reply.error(e),
        }
    }

    fn write(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: fuser::WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        match self.ops.write(fh.0, offset, data) {
            Ok(written) => reply.written(written),
            Err(e) => reply.error(e),
        }
    }

    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        Self::reply_empty(reply, self.ops.flush(fh.0));
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        Self::reply_empty(reply, self.ops.release(fh.0));
    }

    fn fsync(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        datasync: bool,
        reply: ReplyEmpty,
    ) {
        Self::reply_empty(reply, self.ops.fsync(fh.0, datasync));
    }

    // --- directories ---------------------------------------------------------------------

    fn opendir(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        Self::reply_open(reply, self.ops.opendir(ino.0));
    }

    fn readdir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        match self.ops.readdir(fh.0, offset, READDIR_BATCH) {
            Ok(entries) => {
                let offered = entries.len();
                let mut added = 0usize;
                for (entry, next_offset) in entries {
                    if reply.add(INodeNo(entry.ino), next_offset, entry.kind, &entry.name) {
                        break; // the reply buffer is full; the kernel asks again from `next_offset`
                    }
                    added += 1;
                }
                if readdir_batch_may_be_answered(offered, added) {
                    reply.ok();
                } else {
                    log::warn!(
                        "the readdir reply buffer does not hold even one entry; \
                         answering EINVAL rather than truncating the listing"
                    );
                    reply.error(Errno::EINVAL);
                }
            }
            Err(e) => reply.error(e),
        }
    }

    /// Not implemented on purpose, see the module documentation. The kernel and FUSE-T both fall
    /// back to [`readdir`](Self::readdir).
    fn readdirplus(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _offset: u64,
        reply: ReplyDirectoryPlus,
    ) {
        reply.error(Errno::ENOSYS);
    }

    fn releasedir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        reply: ReplyEmpty,
    ) {
        Self::reply_empty(reply, self.ops.releasedir(fh.0));
    }

    // --- volume --------------------------------------------------------------------------

    /// Mandatory rather than optional: FUSE-T asks for `statfs` before nearly every operation, and
    /// fuser's default answer of zero blocks looks like a full filesystem (spike C).
    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        match self.ops.statfs() {
            Ok(s) => reply.statfs(
                s.blocks, s.bfree, s.bavail, s.files, s.ffree, s.bsize, s.namelen, s.frsize,
            ),
            Err(e) => reply.error(e),
        }
    }

    fn access(&self, _req: &Request, ino: INodeNo, mask: AccessFlags, reply: ReplyEmpty) {
        Self::reply_empty(reply, self.ops.access(ino.0, mask));
    }

    // --- extended attributes -------------------------------------------------------------

    fn setxattr(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _name: &OsStr,
        _value: &[u8],
        _flags: i32,
        _position: u32,
        reply: ReplyEmpty,
    ) {
        reply.error(Errno::ENOTSUP);
    }

    fn getxattr(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _name: &OsStr,
        _size: u32,
        reply: ReplyXattr,
    ) {
        reply.error(Errno::ENOTSUP);
    }

    fn listxattr(&self, _req: &Request, _ino: INodeNo, _size: u32, reply: ReplyXattr) {
        reply.error(Errno::ENOTSUP);
    }

    fn removexattr(&self, _req: &Request, _ino: INodeNo, _name: &OsStr, reply: ReplyEmpty) {
        reply.error(Errno::ENOTSUP);
    }

    // --- macOS ---------------------------------------------------------------------------

    /// macFUSE renames the volume through this call. The name the Finder shows comes from the
    /// mount options (`-ovolname=`), so the request is accepted and dropped -- an error here makes
    /// the Finder report a failure the user cannot act on.
    #[cfg(target_os = "macos")]
    fn setvolname(&self, _req: &Request, _name: &OsStr, reply: ReplyEmpty) {
        reply.ok();
    }

    /// `exchangedata(2)`. The core has no atomic exchange, and [`VaultOps::rename`] rejects
    /// `RENAME_EXCHANGE` for the same reason; `EINVAL` makes the caller fall back to a copy.
    #[cfg(target_os = "macos")]
    fn exchange(
        &self,
        _req: &Request,
        _parent: INodeNo,
        _name: &OsStr,
        _newparent: INodeNo,
        _newname: &OsStr,
        _options: u64,
        reply: ReplyEmpty,
    ) {
        reply.error(Errno::EINVAL);
    }

    /// The vault stores a creation time but no backup time, so `bkuptime` is the epoch -- the
    /// "never backed up" value macOS itself uses.
    #[cfg(target_os = "macos")]
    fn getxtimes(&self, _req: &Request, ino: INodeNo, reply: fuser::ReplyXTimes) {
        match self.ops.getattr(ino.0, None) {
            Ok(attr) => reply.xtimes(SystemTime::UNIX_EPOCH, attr.crtime),
            Err(e) => reply.error(e),
        }
    }
}

/// Whether a `readdir` batch of `offered` entries, of which `added` fit into the reply, may be
/// answered with `ok()`.
///
/// `reply.add` reporting "full" is how a listing is normally split: the kernel asks again from the
/// offset of the first entry that did not fit. That only works while *something* fit. If the very
/// first entry of a non-empty batch is already too large for the reply buffer, `ok()` would send
/// an empty reply -- which the kernel reads as the end of the directory, silently truncating the
/// listing. There is no offset to resume from either, so the honest answer is an error.
fn readdir_batch_may_be_answered(offered: usize, added: usize) -> bool {
    offered == 0 || added > 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flags::AdapterOptions;
    use crate::fuse::ops::VaultOpsConfig;
    use crate::transcoder::{FuseNormalization, NameTranscoder};
    use cryptomator_core::constants::DEFAULT_KEY_ID;
    use cryptomator_core::fs::{CryptoFs, CryptoFsOptions};
    use cryptomator_core::{initialize, open_vault_with_key, CipherCombo, DetRng, Masterkey};
    use fuser::FileType;
    use std::time::UNIX_EPOCH;
    use tempfile::TempDir;

    /// `CryptoFuse` must satisfy the trait bound the session requires (`Send + Sync + 'static`).
    fn assert_filesystem<T: Filesystem>() {}

    #[test]
    fn crypto_fuse_is_a_filesystem() {
        assert_filesystem::<CryptoFuse>();
    }

    /// A `CryptoFuse` over an empty vault whose timeouts are the two given ones.
    fn test_fuse(attr: Duration, entry: Duration) -> (TempDir, CryptoFuse) {
        let dir = tempfile::tempdir().expect("temp dir");
        let key = Masterkey::from_raw([0x42; 64]);
        initialize(
            dir.path(),
            &key,
            CipherCombo::SivGcm,
            220,
            DEFAULT_KEY_ID,
            &mut DetRng::default(),
        )
        .expect("initialize vault");
        let opened =
            open_vault_with_key(dir.path(), Masterkey::from_raw([0x42; 64])).expect("open vault");
        let fs = CryptoFs::open(opened, CryptoFsOptions::default());
        let mut options = AdapterOptions::for_user(501, 20);
        options.attr_timeout = attr;
        options.entry_timeout = entry;
        let cfg = VaultOpsConfig {
            transcoder: NameTranscoder::new(FuseNormalization::Nfc),
            options,
            read_only: false,
            delete_apple_double: false,
            refuse_apple_double: false,
            max_name_length: 255,
        };
        let ops = Arc::new(VaultOps::new(Arc::new(fs), cfg));
        (dir, CryptoFuse::new(ops))
    }

    #[test]
    fn attributes_are_translated_one_to_one() {
        let attr = Attr {
            ino: 42,
            size: 11,
            blocks: 1,
            atime: UNIX_EPOCH + Duration::from_secs(1),
            mtime: UNIX_EPOCH + Duration::from_secs(2),
            ctime: UNIX_EPOCH + Duration::from_secs(3),
            crtime: UNIX_EPOCH + Duration::from_secs(4),
            kind: FileType::RegularFile,
            perm: 0o644,
            nlink: 1,
            uid: 501,
            gid: 20,
            blksize: 4096,
        };
        let out = file_attr(&attr);
        assert_eq!(out.ino, INodeNo(42));
        assert_eq!((out.size, out.blocks, out.blksize), (11, 1, 4096));
        assert_eq!(
            (out.atime, out.mtime, out.ctime, out.crtime),
            (attr.atime, attr.mtime, attr.ctime, attr.crtime)
        );
        assert_eq!(
            (out.kind, out.perm, out.nlink),
            (FileType::RegularFile, 0o644, 1)
        );
        assert_eq!((out.uid, out.gid), (501, 20));
        // A vault has no device nodes and no BSD file flags; spike C found a non-zero `flags`
        // corrupting the FUSE-T reply, so both must stay 0.
        assert_eq!((out.rdev, out.flags), (0, 0));
    }

    #[test]
    fn the_ttls_come_from_the_adapter_options() {
        let (_dir, fuse) = test_fuse(Duration::from_secs(5), Duration::from_secs(7));
        assert_eq!(fuse.attr_ttl(), Duration::from_secs(5));
        assert_eq!(fuse.entry_ttl(), Duration::from_secs(7));
        // `create` has room for one TTL only and must not over-cache either of them.
        assert_eq!(
            fuse.attr_ttl().min(fuse.entry_ttl()),
            Duration::from_secs(5)
        );
        let (_dir, fuse) = test_fuse(Duration::from_secs(9), Duration::from_secs(3));
        assert_eq!(
            fuse.attr_ttl().min(fuse.entry_ttl()),
            Duration::from_secs(3)
        );
    }

    #[test]
    fn rename_flag_bits_match_the_linux_values() {
        assert_eq!(RENAME_NOREPLACE, 1);
        assert_eq!(RENAME_EXCHANGE, 2);
        #[cfg(target_os = "linux")]
        {
            assert_eq!(RenameFlags::RENAME_NOREPLACE.bits(), RENAME_NOREPLACE);
            assert_eq!(RenameFlags::RENAME_EXCHANGE.bits(), RENAME_EXCHANGE);
        }
        // The bits survive decoding even where fuser does not name them (FUSE-T on macOS).
        let both = RenameFlags::from_bits_retain(RENAME_NOREPLACE | RENAME_EXCHANGE);
        assert_eq!(both.bits(), 3);
    }

    /// `ReplyDirectory` can only be built from a live channel sender, so the decision `readdir`
    /// makes about the batch it just filled is tested on its own.
    #[test]
    fn a_batch_whose_first_entry_does_not_fit_is_not_answered_with_ok() {
        // Nothing to list: an empty `ok()` is the correct end of the directory.
        assert!(readdir_batch_may_be_answered(0, 0));
        // The normal split: some entries fit, the kernel asks again from the next offset.
        assert!(readdir_batch_may_be_answered(64, 1));
        assert!(readdir_batch_may_be_answered(64, 63));
        assert!(readdir_batch_may_be_answered(64, 64));
        // The one that would silently truncate the listing.
        assert!(!readdir_batch_may_be_answered(1, 0));
        assert!(!readdir_batch_may_be_answered(64, 0));
    }
}
