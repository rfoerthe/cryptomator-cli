#![allow(refining_impl_trait)]

use std::io::IoSlice;
use std::os::unix::prelude::OsStrExt;
use std::path::Path;
use std::time::Duration;
#[cfg(target_os = "macos")]
use std::time::SystemTime;

use smallvec::SmallVec;
use zerocopy::Immutable;
use zerocopy::IntoBytes;

use crate::FileType;
use crate::KernelAbi;
use crate::PollEvents;
use crate::ll::Errno;
use crate::ll::FileHandle;
use crate::ll::Generation;
use crate::ll::INodeNo;
use crate::ll::Lock;
use crate::ll::RequestId;
use crate::ll::flags::fopen_flags::FopenFlags;
use crate::ll::fuse_abi as abi;
use crate::ll::ioslice_concat::IosliceConcat;
use crate::time::time_from_system_time;

const INLINE_DATA_THRESHOLD: usize = size_of::<u64>() * 4;
pub(crate) type ResponseBuf = SmallVec<[u8; INLINE_DATA_THRESHOLD]>;

pub(crate) trait Response {
    fn errno(&self) -> Option<Errno> {
        None
    }

    fn payload(&self) -> impl IosliceConcat;

    fn with_iovec<F: FnOnce(&[IoSlice<'_>]) -> T, T>(&self, unique: RequestId, f: F) -> T {
        let payload = self.payload();
        let payload_len = payload.sum_len();
        let header = abi::fuse_out_header {
            unique: unique.0,
            error: self.errno().map_or(0, |e| -e.0.get()),
            len: (size_of::<abi::fuse_out_header>() + payload_len)
                .try_into()
                .expect("Too much data"),
        };
        let v = ([IoSlice::new(header.as_bytes())], payload);
        IosliceConcat::with_ioslice(&v, f)
    }
}

pub(crate) struct ResponseSlice<'a>(pub(crate) &'a [u8]);

impl Response for ResponseSlice<'_> {
    fn payload(&self) -> Option<[IoSlice<'_>; 1]> {
        if self.0.is_empty() {
            None
        } else {
            Some([IoSlice::new(self.0)])
        }
    }
}

pub(crate) struct ResponseEmpty;

impl Response for ResponseEmpty {
    fn payload(&self) -> [IoSlice<'_>; 0] {
        []
    }
}

pub(crate) struct ResponseErrno(pub(crate) Errno);

impl Response for ResponseErrno {
    fn errno(&self) -> Option<Errno> {
        Some(self.0)
    }

    fn payload(&self) -> [IoSlice<'_>; 0] {
        []
    }
}

pub(crate) struct ResponseStruct<S: IntoBytes + Immutable>(pub(crate) S);

impl<S: IntoBytes + Immutable> Response for ResponseStruct<S> {
    fn payload(&self) -> [IoSlice<'_>; 1] {
        [IoSlice::new(self.0.as_bytes())]
    }
}

/// A reply body that embeds a `fuse_attr` and therefore has two possible wire layouts: the one
/// native to the target platform and the Linux one (see [`KernelAbi`]). On every target but macOS
/// the two are the same and only [`ResponseEntry::Native`] is ever built.
#[derive(Debug)]
pub(crate) enum ResponseEntry {
    Native(abi::fuse_entry_out),
    #[cfg(target_os = "macos")]
    Linux(abi::fuse_entry_out_linux),
}

impl Response for ResponseEntry {
    fn payload(&self) -> [IoSlice<'_>; 1] {
        match self {
            Self::Native(x) => [IoSlice::new(x.as_bytes())],
            #[cfg(target_os = "macos")]
            Self::Linux(x) => [IoSlice::new(x.as_bytes())],
        }
    }
}

impl ResponseEntry {
    pub(crate) fn new_entry(
        ino: INodeNo,
        generation: Generation,
        attr: &Attr,
        attr_ttl: Duration,
        entry_ttl: Duration,
        abi: KernelAbi,
    ) -> Self {
        let native = abi::fuse_entry_out {
            nodeid: ino.into(),
            generation: generation.0,
            entry_valid: entry_ttl.as_secs(),
            attr_valid: attr_ttl.as_secs(),
            entry_valid_nsec: entry_ttl.subsec_nanos(),
            attr_valid_nsec: attr_ttl.subsec_nanos(),
            attr: attr.attr,
        };
        #[cfg(target_os = "macos")]
        if abi == KernelAbi::Linux {
            return Self::Linux((&native).into());
        }
        #[cfg(not(target_os = "macos"))]
        let _ = abi;
        Self::Native(native)
    }
}

/// See [`ResponseEntry`].
#[derive(Debug)]
pub(crate) enum ResponseAttr {
    Native(abi::fuse_attr_out),
    #[cfg(target_os = "macos")]
    Linux(abi::fuse_attr_out_linux),
}

impl Response for ResponseAttr {
    fn payload(&self) -> [IoSlice<'_>; 1] {
        match self {
            Self::Native(x) => [IoSlice::new(x.as_bytes())],
            #[cfg(target_os = "macos")]
            Self::Linux(x) => [IoSlice::new(x.as_bytes())],
        }
    }
}

impl ResponseAttr {
    pub(crate) fn new_attr(ttl: &Duration, attr: &Attr, abi: KernelAbi) -> Self {
        let native = abi::fuse_attr_out {
            attr_valid: ttl.as_secs(),
            attr_valid_nsec: ttl.subsec_nanos(),
            dummy: 0,
            attr: attr.attr,
        };
        #[cfg(target_os = "macos")]
        if abi == KernelAbi::Linux {
            return Self::Linux((&native).into());
        }
        #[cfg(not(target_os = "macos"))]
        let _ = abi;
        Self::Native(native)
    }
}

/// See [`ResponseEntry`].
#[derive(Debug)]
pub(crate) enum ResponseCreate {
    Native(abi::fuse_create_out),
    #[cfg(target_os = "macos")]
    Linux(abi::fuse_create_out_linux),
}

impl Response for ResponseCreate {
    fn payload(&self) -> [IoSlice<'_>; 1] {
        match self {
            Self::Native(x) => [IoSlice::new(x.as_bytes())],
            #[cfg(target_os = "macos")]
            Self::Linux(x) => [IoSlice::new(x.as_bytes())],
        }
    }
}

impl ResponseCreate {
    pub(crate) fn new_create(
        ttl: &Duration,
        attr: &Attr,
        generation: Generation,
        fh: FileHandle,
        flags: FopenFlags,
        backing_id: u32,
        abi: KernelAbi,
    ) -> Self {
        let native = abi::fuse_create_out(
            abi::fuse_entry_out {
                nodeid: attr.attr.ino,
                generation: generation.into(),
                entry_valid: ttl.as_secs(),
                attr_valid: ttl.as_secs(),
                entry_valid_nsec: ttl.subsec_nanos(),
                attr_valid_nsec: ttl.subsec_nanos(),
                attr: attr.attr,
            },
            abi::fuse_open_out {
                fh: fh.into(),
                open_flags: flags.bits(),
                backing_id,
            },
        );
        #[cfg(target_os = "macos")]
        if abi == KernelAbi::Linux {
            return Self::Linux((&native).into());
        }
        #[cfg(not(target_os = "macos"))]
        let _ = abi;
        Self::Native(native)
    }
}

#[cfg(target_os = "macos")]
impl ResponseStruct<abi::fuse_getxtimes_out> {
    pub(crate) fn new_xtimes(bkuptime: SystemTime, crtime: SystemTime) -> Self {
        let (bkuptime_secs, bkuptime_nanos) = time_from_system_time(&bkuptime);
        let (crtime_secs, crtime_nanos) = time_from_system_time(&crtime);
        ResponseStruct(abi::fuse_getxtimes_out {
            bkuptime: bkuptime_secs as u64,
            crtime: crtime_secs as u64,
            bkuptimensec: bkuptime_nanos,
            crtimensec: crtime_nanos,
        })
    }
}

impl ResponseStruct<abi::fuse_open_out> {
    pub(crate) fn new_open(fh: FileHandle, flags: FopenFlags, backing_id: u32) -> Self {
        ResponseStruct(abi::fuse_open_out {
            fh: fh.into(),
            open_flags: flags.bits(),
            backing_id,
        })
    }
}

impl ResponseStruct<abi::fuse_lk_out> {
    pub(crate) fn new_lock(lock: &Lock) -> Self {
        ResponseStruct(abi::fuse_lk_out {
            lk: abi::fuse_file_lock {
                start: lock.range.0,
                end: lock.range.1,
                typ: lock.typ,
                pid: lock.pid,
            },
        })
    }
}

impl ResponseStruct<abi::fuse_bmap_out> {
    pub(crate) fn new_bmap(block: u64) -> Self {
        ResponseStruct(abi::fuse_bmap_out { block })
    }
}

impl ResponseStruct<abi::fuse_write_out> {
    pub(crate) fn new_write(written: u32) -> Self {
        ResponseStruct(abi::fuse_write_out {
            size: written,
            padding: 0,
        })
    }
}

impl ResponseStruct<abi::fuse_statfs_out> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_statfs(
        blocks: u64,
        bfree: u64,
        bavail: u64,
        files: u64,
        ffree: u64,
        bsize: u32,
        namelen: u32,
        frsize: u32,
    ) -> Self {
        ResponseStruct(abi::fuse_statfs_out {
            st: abi::fuse_kstatfs {
                blocks,
                bfree,
                bavail,
                files,
                ffree,
                bsize,
                namelen,
                frsize,
                padding: 0,
                spare: [0; 6],
            },
        })
    }
}

impl ResponseStruct<abi::fuse_poll_out> {
    pub(crate) fn new_poll(revents: PollEvents) -> Self {
        ResponseStruct(abi::fuse_poll_out {
            revents: revents.bits(),
            padding: 0,
        })
    }
}

impl ResponseStruct<abi::fuse_getxattr_out> {
    pub(crate) fn new_xattr_size(size: u32) -> Self {
        ResponseStruct(abi::fuse_getxattr_out { size, padding: 0 })
    }
}

impl ResponseStruct<abi::fuse_lseek_out> {
    pub(crate) fn new_lseek(offset: i64) -> Self {
        ResponseStruct(abi::fuse_lseek_out { offset })
    }
}

pub(crate) struct ResponseIoctl<'a> {
    out: abi::fuse_ioctl_out,
    iovs: &'a [IoSlice<'a>],
}

impl<'a> ResponseIoctl<'a> {
    // TODO: Are you allowed to send data while result != 0?
    pub(crate) fn new_ioctl(result: i32, iovs: &'a [IoSlice<'a>]) -> Self {
        let out = abi::fuse_ioctl_out {
            result,
            // these fields are only needed for unrestricted ioctls
            flags: 0,
            in_iovs: 1,
            out_iovs: iovs.len().try_into().expect("Too many ioctls"),
        };
        ResponseIoctl { out, iovs }
    }
}

impl Response for ResponseIoctl<'_> {
    fn payload(&self) -> ([IoSlice<'_>; 1], &'_ [IoSlice<'_>]) {
        ([IoSlice::new(self.out.as_bytes())], self.iovs)
    }
}

#[derive(Debug)]
pub(crate) struct ResponseData(ResponseBuf);

impl Response for ResponseData {
    fn payload(&self) -> Option<[IoSlice<'_>; 1]> {
        if self.0.is_empty() {
            None
        } else {
            Some([IoSlice::new(&self.0)])
        }
    }
}

impl ResponseData {
    // Constructors
    pub(crate) fn new_data<T: AsRef<[u8]> + Into<Vec<u8>>>(data: T) -> Self {
        Self(if data.as_ref().len() <= INLINE_DATA_THRESHOLD {
            ResponseBuf::from_slice(data.as_ref())
        } else {
            ResponseBuf::from_vec(data.into())
        })
    }

    pub(crate) fn new_directory(list: EntListBuf) -> Self {
        assert!(list.buf.len() <= list.max_size);
        Self(list.buf)
    }
}

// Some platforms like Linux x86_64 have mode_t = u32, and lint warns of a trivial_numeric_casts.
// But others like macOS x86_64 have mode_t = u16, requiring a typecast.  So, just silence lint.
#[allow(trivial_numeric_casts)]
#[allow(clippy::unnecessary_cast)]
/// Returns the mode for a given file kind and permission
pub(crate) fn mode_from_kind_and_perm(kind: FileType, perm: u16) -> u32 {
    (match kind {
        FileType::NamedPipe => libc::S_IFIFO,
        FileType::CharDevice => libc::S_IFCHR,
        FileType::BlockDevice => libc::S_IFBLK,
        FileType::Directory => libc::S_IFDIR,
        FileType::RegularFile => libc::S_IFREG,
        FileType::Symlink => libc::S_IFLNK,
        FileType::Socket => libc::S_IFSOCK,
    }) as u32
        | u32::from(perm)
}
/// Returns a `fuse_attr` from `FileAttr`
pub(crate) fn fuse_attr_from_attr(attr: &crate::FileAttr) -> abi::fuse_attr {
    let (atime_secs, atime_nanos) = time_from_system_time(&attr.atime);
    let (mtime_secs, mtime_nanos) = time_from_system_time(&attr.mtime);
    let (ctime_secs, ctime_nanos) = time_from_system_time(&attr.ctime);
    #[cfg(target_os = "macos")]
    let (crtime_secs, crtime_nanos) = time_from_system_time(&attr.crtime);

    abi::fuse_attr {
        ino: attr.ino.0,
        size: attr.size,
        blocks: attr.blocks,
        atime: atime_secs,
        mtime: mtime_secs,
        ctime: ctime_secs,
        #[cfg(target_os = "macos")]
        crtime: crtime_secs as u64,
        atimensec: atime_nanos,
        mtimensec: mtime_nanos,
        ctimensec: ctime_nanos,
        #[cfg(target_os = "macos")]
        crtimensec: crtime_nanos,
        mode: mode_from_kind_and_perm(attr.kind, attr.perm),
        nlink: attr.nlink,
        uid: attr.uid,
        gid: attr.gid,
        rdev: attr.rdev,
        #[cfg(target_os = "macos")]
        flags: attr.flags,
        blksize: attr.blksize,
        padding: 0,
    }
}

// TODO: Add methods for creating this without making a `FileAttr` first.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Attr {
    pub(crate) attr: abi::fuse_attr,
}
impl From<&crate::FileAttr> for Attr {
    fn from(attr: &crate::FileAttr) -> Self {
        Self {
            attr: fuse_attr_from_attr(attr),
        }
    }
}
impl From<crate::FileAttr> for Attr {
    fn from(attr: crate::FileAttr) -> Self {
        Self {
            attr: fuse_attr_from_attr(&attr),
        }
    }
}

#[derive(Debug)]
/// A generic data buffer
pub(crate) struct EntListBuf {
    max_size: usize,
    buf: ResponseBuf,
}
impl EntListBuf {
    pub(crate) fn new(max_size: usize) -> Self {
        Self {
            max_size,
            buf: ResponseBuf::new(),
        }
    }

    /// Add an entry to the directory reply buffer. Returns true if the buffer is full.
    /// A transparent offset value can be provided for each entry. The kernel uses these
    /// value to request the next entries in further readdir calls
    #[must_use]
    pub(crate) fn push(&mut self, ent: [&[u8]; 2]) -> bool {
        debug_assert!(self.buf.len() % size_of::<u64>() == 0);

        let entlen = ent[0].len() + ent[1].len();
        let entsize = entlen.next_multiple_of(size_of::<u64>()); // 64 bit align
        if self.buf.len() + entsize > self.max_size {
            return true;
        }
        self.buf.reserve(entsize);
        self.buf.extend_from_slice(ent[0]);
        self.buf.extend_from_slice(ent[1]);
        let padlen = entsize - entlen;
        self.buf.resize(self.buf.len() + padlen, 0);
        false
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord)]
pub(crate) struct DirEntOffset(pub(crate) u64);

#[derive(Debug)]
pub(crate) struct DirEntry<T: AsRef<Path>> {
    ino: INodeNo,
    offset: DirEntOffset,
    kind: FileType,
    name: T,
}

impl<T: AsRef<Path>> DirEntry<T> {
    pub(crate) fn new(ino: INodeNo, offset: DirEntOffset, kind: FileType, name: T) -> DirEntry<T> {
        DirEntry::<T> {
            ino,
            offset,
            kind,
            name,
        }
    }
}

/// Data buffer used to respond to [`Readdir`] requests.
#[derive(Debug)]
pub(crate) struct DirEntList(EntListBuf);
impl From<DirEntList> for ResponseData {
    fn from(l: DirEntList) -> Self {
        assert!(l.0.buf.len() <= l.0.max_size);
        ResponseData::new_directory(l.0)
    }
}

impl DirEntList {
    pub(crate) fn new(max_size: usize) -> Self {
        Self(EntListBuf::new(max_size))
    }
    /// Add an entry to the directory reply buffer. Returns true if the buffer is full.
    /// A transparent offset value can be provided for each entry. The kernel uses these
    /// value to request the next entries in further readdir calls
    #[must_use]
    pub(crate) fn push<T: AsRef<Path>>(&mut self, ent: &DirEntry<T>) -> bool {
        let name = ent.name.as_ref().as_os_str().as_bytes();
        let header = abi::fuse_dirent {
            ino: ent.ino.into(),
            off: ent.offset.0,
            namelen: name.len().try_into().expect("Name too long"),
            typ: mode_from_kind_and_perm(ent.kind, 0) >> 12,
        };
        self.0.push([header.as_bytes(), name])
    }
}

#[derive(Debug)]
pub(crate) struct DirEntryPlus<T: AsRef<Path>> {
    #[allow(unused)] // We use `attr.ino` instead
    ino: INodeNo,
    generation: Generation,
    offset: DirEntOffset,
    name: T,
    entry_valid: Duration,
    attr: Attr,
    attr_valid: Duration,
    /// Only consulted on macOS; elsewhere the native layout already is the Linux one.
    #[cfg_attr(not(target_os = "macos"), expect(dead_code))]
    abi: KernelAbi,
}

impl<T: AsRef<Path>> DirEntryPlus<T> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        ino: INodeNo,
        generation: Generation,
        offset: DirEntOffset,
        name: T,
        entry_valid: Duration,
        attr: Attr,
        attr_valid: Duration,
        abi: KernelAbi,
    ) -> Self {
        Self {
            ino,
            generation,
            offset,
            name,
            entry_valid,
            attr,
            attr_valid,
            abi,
        }
    }
}

/// Data buffer used to respond to [`ReaddirPlus`] requests.
#[derive(Debug)]
pub(crate) struct DirEntPlusList(EntListBuf);
impl From<DirEntPlusList> for ResponseData {
    fn from(l: DirEntPlusList) -> Self {
        assert!(l.0.buf.len() <= l.0.max_size);
        ResponseData::new_directory(l.0)
    }
}

impl DirEntPlusList {
    pub(crate) fn new(max_size: usize) -> Self {
        Self(EntListBuf::new(max_size))
    }
    /// Add an entry to the directory reply buffer. Returns true if the buffer is full.
    /// A transparent offset value can be provided for each entry. The kernel uses these
    /// value to request the next entries in further readdir calls
    #[must_use]
    pub(crate) fn push<T: AsRef<Path>>(&mut self, x: &DirEntryPlus<T>) -> bool {
        let name = x.name.as_ref().as_os_str().as_bytes();
        let header = abi::fuse_direntplus {
            entry_out: abi::fuse_entry_out {
                nodeid: x.attr.attr.ino,
                generation: x.generation.into(),
                entry_valid: x.entry_valid.as_secs(),
                attr_valid: x.attr_valid.as_secs(),
                entry_valid_nsec: x.entry_valid.subsec_nanos(),
                attr_valid_nsec: x.attr_valid.subsec_nanos(),
                attr: x.attr.attr,
            },
            dirent: abi::fuse_dirent {
                ino: x.attr.attr.ino,
                off: x.offset.0,
                namelen: name.len().try_into().expect("Name too long"),
                typ: x.attr.attr.mode >> 12,
            },
        };
        #[cfg(target_os = "macos")]
        if x.abi == KernelAbi::Linux {
            let header = abi::fuse_direntplus_linux::from(&header);
            return self.0.push([header.as_bytes(), name]);
        }
        self.0.push([header.as_bytes(), name])
    }
}

#[cfg(test)]
mod test {
    use std::num::NonZeroI32;
    use std::time::UNIX_EPOCH;

    use crate::ll::reply::*;
    use crate::ll::test::ioslice_to_vec;

    #[test]
    fn reply_empty() {
        let r = ResponseEmpty;
        assert_eq!(
            r.with_iovec(RequestId(0xdeadbeef), ioslice_to_vec),
            vec![
                0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00,
            ],
        );
    }

    #[test]
    fn reply_error() {
        let r = ResponseErrno(Errno(NonZeroI32::new(66).unwrap()));
        assert_eq!(
            r.with_iovec(RequestId(0xdeadbeef), ioslice_to_vec),
            vec![
                0x10, 0x00, 0x00, 0x00, 0xbe, 0xff, 0xff, 0xff, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00,
            ],
        );
    }

    #[test]
    fn reply_data() {
        let r = ResponseData::new_data([0xde, 0xad, 0xbe, 0xef].as_ref());
        assert_eq!(
            r.with_iovec(RequestId(0xdeadbeef), ioslice_to_vec),
            vec![
                0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00, 0xde, 0xad, 0xbe, 0xef,
            ],
        );
    }

    #[test]
    fn reply_entry() {
        let mut expected = if cfg!(target_os = "macos") {
            vec![
                0x98, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x65, 0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x65, 0x87,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x43, 0x00, 0x00, 0x21, 0x43, 0x00, 0x00,
                0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x12,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x78, 0x56, 0x00, 0x00, 0x78, 0x56, 0x00, 0x00, 0x78, 0x56, 0x00, 0x00, 0x78, 0x56,
                0x00, 0x00, 0xa4, 0x81, 0x00, 0x00, 0x55, 0x00, 0x00, 0x00, 0x66, 0x00, 0x00, 0x00,
                0x77, 0x00, 0x00, 0x00, 0x88, 0x00, 0x00, 0x00, 0x99, 0x00, 0x00, 0x00,
            ]
        } else {
            vec![
                0x88, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x65, 0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x65, 0x87,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x43, 0x00, 0x00, 0x21, 0x43, 0x00, 0x00,
                0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x12,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x56, 0x00, 0x00, 0x78, 0x56, 0x00, 0x00,
                0x78, 0x56, 0x00, 0x00, 0xa4, 0x81, 0x00, 0x00, 0x55, 0x00, 0x00, 0x00, 0x66, 0x00,
                0x00, 0x00, 0x77, 0x00, 0x00, 0x00, 0x88, 0x00, 0x00, 0x00,
            ]
        };

        expected.extend(vec![0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        expected[0] = (expected.len()) as u8;

        let time = UNIX_EPOCH + Duration::new(0x1234, 0x5678);
        let ttl = Duration::new(0x8765, 0x4321);
        let attr = crate::FileAttr {
            ino: INodeNo(0x11),
            size: 0x22,
            blocks: 0x33,
            atime: time,
            mtime: time,
            ctime: time,
            crtime: time,
            kind: FileType::RegularFile,
            perm: 0o644,
            nlink: 0x55,
            uid: 0x66,
            gid: 0x77,
            rdev: 0x88,
            flags: 0x99,
            blksize: 0xbb,
        };
        let r = ResponseEntry::new_entry(
            INodeNo(0x11),
            Generation(0xaa),
            &attr.into(),
            ttl,
            ttl,
            KernelAbi::Native,
        );
        assert_eq!(
            r.with_iovec(RequestId(0xdeadbeef), ioslice_to_vec),
            expected
        );
    }

    #[test]
    fn reply_attr() {
        let mut expected = if cfg!(target_os = "macos") {
            vec![
                0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00, 0x65, 0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x43, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x78, 0x56, 0x00, 0x00, 0x78, 0x56, 0x00, 0x00, 0x78, 0x56,
                0x00, 0x00, 0x78, 0x56, 0x00, 0x00, 0xa4, 0x81, 0x00, 0x00, 0x55, 0x00, 0x00, 0x00,
                0x66, 0x00, 0x00, 0x00, 0x77, 0x00, 0x00, 0x00, 0x88, 0x00, 0x00, 0x00, 0x99, 0x00,
                0x00, 0x00,
            ]
        } else {
            vec![
                0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00, 0x65, 0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x43, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x56, 0x00, 0x00,
                0x78, 0x56, 0x00, 0x00, 0x78, 0x56, 0x00, 0x00, 0xa4, 0x81, 0x00, 0x00, 0x55, 0x00,
                0x00, 0x00, 0x66, 0x00, 0x00, 0x00, 0x77, 0x00, 0x00, 0x00, 0x88, 0x00, 0x00, 0x00,
            ]
        };

        expected.extend_from_slice(&[0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        expected[0] = expected.len() as u8;

        let time = UNIX_EPOCH + Duration::new(0x1234, 0x5678);
        let ttl = Duration::new(0x8765, 0x4321);
        let attr = crate::FileAttr {
            ino: INodeNo(0x11),
            size: 0x22,
            blocks: 0x33,
            atime: time,
            mtime: time,
            ctime: time,
            crtime: time,
            kind: FileType::RegularFile,
            perm: 0o644,
            nlink: 0x55,
            uid: 0x66,
            gid: 0x77,
            rdev: 0x88,
            flags: 0x99,
            blksize: 0xbb,
        };
        let r = ResponseAttr::new_attr(&ttl, &attr.into(), KernelAbi::Native);
        assert_eq!(
            r.with_iovec(RequestId(0xdeadbeef), ioslice_to_vec),
            expected
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn reply_xtimes() {
        let expected = vec![
            0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
            0x00, 0x00, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x78, 0x56, 0x00, 0x00, 0x78, 0x56, 0x00, 0x00,
        ];
        let time = UNIX_EPOCH + Duration::new(0x1234, 0x5678);
        let r = ResponseStruct::new_xtimes(time, time);
        assert_eq!(
            r.with_iovec(RequestId(0xdeadbeef), ioslice_to_vec),
            expected
        );
    }

    #[test]
    fn reply_open() {
        let expected = vec![
            0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
            0x00, 0x00, 0x22, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let r = ResponseStruct::new_open(FileHandle(0x1122), FopenFlags::from_bits_retain(0x33), 0);
        assert_eq!(
            r.with_iovec(RequestId(0xdeadbeef), ioslice_to_vec),
            expected
        );
    }

    #[test]
    fn reply_write() {
        let expected = vec![
            0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
            0x00, 0x00, 0x22, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let r = ResponseStruct::new_write(0x1122);
        assert_eq!(
            r.with_iovec(RequestId(0xdeadbeef), ioslice_to_vec),
            expected
        );
    }

    #[test]
    fn reply_statfs() {
        let expected = vec![
            0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
            0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x66, 0x00, 0x00, 0x00, 0x77, 0x00, 0x00, 0x00, 0x88, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let r = ResponseStruct::new_statfs(0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88);
        assert_eq!(
            r.with_iovec(RequestId(0xdeadbeef), ioslice_to_vec),
            expected
        );
    }

    #[test]
    fn reply_create() {
        let mut expected = if cfg!(target_os = "macos") {
            vec![
                0xa8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x65, 0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x65, 0x87,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x43, 0x00, 0x00, 0x21, 0x43, 0x00, 0x00,
                0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x12,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x78, 0x56, 0x00, 0x00, 0x78, 0x56, 0x00, 0x00, 0x78, 0x56, 0x00, 0x00, 0x78, 0x56,
                0x00, 0x00, 0xa4, 0x81, 0x00, 0x00, 0x55, 0x00, 0x00, 0x00, 0x66, 0x00, 0x00, 0x00,
                0x77, 0x00, 0x00, 0x00, 0x88, 0x00, 0x00, 0x00, 0x99, 0x00, 0x00, 0x00, 0xbb, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xcc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]
        } else {
            vec![
                0x98, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x65, 0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x65, 0x87,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x43, 0x00, 0x00, 0x21, 0x43, 0x00, 0x00,
                0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x12,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x56, 0x00, 0x00, 0x78, 0x56, 0x00, 0x00,
                0x78, 0x56, 0x00, 0x00, 0xa4, 0x81, 0x00, 0x00, 0x55, 0x00, 0x00, 0x00, 0x66, 0x00,
                0x00, 0x00, 0x77, 0x00, 0x00, 0x00, 0x88, 0x00, 0x00, 0x00, 0xbb, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0xcc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]
        };

        let insert_at = expected.len() - 16;
        expected.splice(
            insert_at..insert_at,
            vec![0xdd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        );
        expected[0] = (expected.len()) as u8;

        let time = UNIX_EPOCH + Duration::new(0x1234, 0x5678);
        let ttl = Duration::new(0x8765, 0x4321);
        let attr = crate::FileAttr {
            ino: INodeNo(0x11),
            size: 0x22,
            blocks: 0x33,
            atime: time,
            mtime: time,
            ctime: time,
            crtime: time,
            kind: FileType::RegularFile,
            perm: 0o644,
            nlink: 0x55,
            uid: 0x66,
            gid: 0x77,
            rdev: 0x88,
            flags: 0x99,
            blksize: 0xdd,
        };
        let r = ResponseCreate::new_create(
            &ttl,
            &attr.into(),
            Generation(0xaa),
            FileHandle(0xbb),
            FopenFlags::from_bits_retain(0xcc),
            0,
            KernelAbi::Native,
        );
        assert_eq!(
            r.with_iovec(RequestId(0xdeadbeef), ioslice_to_vec),
            expected
        );
    }

    #[test]
    fn reply_lock() {
        let expected = vec![
            0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
            0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x33, 0x00, 0x00, 0x00, 0x44, 0x00, 0x00, 0x00,
        ];
        let r = ResponseStruct::new_lock(&Lock {
            range: (0x11, 0x22),
            typ: 0x33,
            pid: 0x44,
        });
        assert_eq!(
            r.with_iovec(RequestId(0xdeadbeef), ioslice_to_vec),
            expected
        );
    }

    #[test]
    fn reply_bmap() {
        let expected = vec![
            0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
            0x00, 0x00, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let r = ResponseStruct::new_bmap(0x1234);
        assert_eq!(
            r.with_iovec(RequestId(0xdeadbeef), ioslice_to_vec),
            expected
        );
    }

    #[test]
    fn reply_xattr_size() {
        let expected = vec![
            0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00,
            0x00, 0x00, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00,
        ];
        let r = ResponseStruct::new_xattr_size(0x12345678);
        assert_eq!(
            r.with_iovec(RequestId(0xdeadbeef), ioslice_to_vec),
            expected
        );
    }

    #[test]
    fn reply_xattr_data() {
        let expected = vec![
            0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00,
            0x00, 0x00, 0x11, 0x22, 0x33, 0x44,
        ];
        let r = ResponseData::new_data([0x11, 0x22, 0x33, 0x44].as_ref());
        assert_eq!(
            r.with_iovec(RequestId(0xdeadbeef), ioslice_to_vec),
            expected
        );
    }

    #[test]
    fn reply_directory() {
        let expected = vec![
            0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
            0x00, 0x00, 0xbb, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x68, 0x65,
            0x6c, 0x6c, 0x6f, 0x00, 0x00, 0x00, 0xdd, 0xcc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x08, 0x00,
            0x00, 0x00, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x2e, 0x72, 0x73,
        ];
        let mut buf = DirEntList::new(4096);
        assert!(!buf.push(&DirEntry::new(
            INodeNo(0xaabb),
            DirEntOffset(1),
            FileType::Directory,
            "hello"
        )));
        assert!(!buf.push(&DirEntry::new(
            INodeNo(0xccdd),
            DirEntOffset(2),
            FileType::RegularFile,
            "world.rs"
        )));
        let r: ResponseData = buf.into();
        assert_eq!(
            r.with_iovec(RequestId(0xdeadbeef), ioslice_to_vec),
            expected
        );
    }
}

/// Byte-layout tests for `KernelAbi::Linux` (vendored patch, see ../../README-VENDORED.md).
///
/// These only exist on macOS: everywhere else the native layout already *is* the Linux one, so
/// there is nothing to distinguish. The assertions pin the wire sizes and the field offsets that
/// FUSE-T decodes, which is the whole point of the switch.
#[cfg(all(test, target_os = "macos"))]
mod abi_test {
    use std::time::Duration;
    use std::time::UNIX_EPOCH;

    use crate::FileType;
    use crate::KernelAbi;
    use crate::ll::INodeNo;
    use crate::ll::reply::*;
    use crate::ll::test::ioslice_to_vec;

    const HEADER: usize = size_of::<abi::fuse_out_header>();
    /// `fuse_attr` as macFUSE declares it.
    const ATTR_NATIVE: usize = 104;
    /// `fuse_attr` as Linux declares it.
    const ATTR_LINUX: usize = 88;

    // Every field carries a distinct, non-zero value so that a twin which silently mixed two
    // fields up (or zeroed one) cannot pass by accident.
    const ATIME: (u64, u32) = (1_000_001, 111_000_111);
    const MTIME: (u64, u32) = (2_000_002, 222_000_222);
    const CTIME: (u64, u32) = (3_000_003, 333_000_333);
    const CRTIME: (u64, u32) = (4_000_004, 444_000_444);
    const RDEV: u32 = 0x0102_0304;
    /// Darwin `chflags(2)` bits. The Linux layout's `flags` field means `FUSE_ATTR_*` instead, so
    /// the twin must NOT carry this value over — it is expected to read back as 0.
    const DARWIN_FLAGS: u32 = 0xdead;

    fn at(t: (u64, u32)) -> std::time::SystemTime {
        UNIX_EPOCH + Duration::new(t.0, t.1)
    }

    fn attr() -> crate::FileAttr {
        crate::FileAttr {
            ino: INodeNo(1),
            size: 4242,
            blocks: 9,
            atime: at(ATIME),
            mtime: at(MTIME),
            ctime: at(CTIME),
            crtime: at(CRTIME),
            kind: FileType::Directory,
            perm: 0o755,
            nlink: 3,
            uid: 501,
            gid: 20,
            rdev: RDEV,
            flags: DARWIN_FLAGS,
            blksize: 512,
        }
    }

    fn bytes(r: &impl Response) -> Vec<u8> {
        r.with_iovec(RequestId(0xdeadbeef), ioslice_to_vec)
    }

    fn u32_at(buf: &[u8], off: usize) -> u32 {
        u32::from_ne_bytes(buf[off..off + 4].try_into().expect("4 bytes"))
    }

    fn u64_at(buf: &[u8], off: usize) -> u64 {
        u64::from_ne_bytes(buf[off..off + 8].try_into().expect("8 bytes"))
    }

    fn i64_at(buf: &[u8], off: usize) -> i64 {
        i64::from_ne_bytes(buf[off..off + 8].try_into().expect("8 bytes"))
    }

    /// Assert that `attr` (a `fuse_attr` starting at `buf[0]`) uses the Linux field order:
    /// ino 0, size 8, blocks 16, atime 24, mtime 32, ctime 40 (all i64/u64, no Darwin `crtime`),
    /// atimensec 48, mtimensec 52, ctimensec 56 (no Darwin `crtimensec`),
    /// mode 60, nlink 64, uid 68, gid 72, rdev 76, blksize 80, flags 84.
    fn assert_linux_attr_layout(attr: &[u8]) {
        assert_eq!(u64_at(attr, 0), 1, "ino");
        assert_eq!(u64_at(attr, 8), 4242, "size");
        assert_eq!(u64_at(attr, 16), 9, "blocks");
        assert_eq!(i64_at(attr, 24), ATIME.0 as i64, "atime");
        assert_eq!(i64_at(attr, 32), MTIME.0 as i64, "mtime");
        assert_eq!(i64_at(attr, 40), CTIME.0 as i64, "ctime");
        assert_eq!(u32_at(attr, 48), ATIME.1, "atimensec");
        assert_eq!(u32_at(attr, 52), MTIME.1, "mtimensec");
        assert_eq!(u32_at(attr, 56), CTIME.1, "ctimensec");
        assert_eq!(u32_at(attr, 60), 0o040755, "mode");
        assert_eq!(u32_at(attr, 64), 3, "nlink");
        assert_eq!(u32_at(attr, 68), 501, "uid");
        assert_eq!(u32_at(attr, 72), 20, "gid");
        assert_eq!(u32_at(attr, 76), RDEV, "rdev");
        assert_eq!(u32_at(attr, 80), 512, "blksize");
        // Darwin file flags are deliberately dropped: on Linux this field is `FUSE_ATTR_*`.
        assert_eq!(u32_at(attr, 84), 0, "flags");
        // Every offset above must actually lie inside the buffer; `crtime`/`crtimensec` have no
        // Linux offset at all, the struct ends after `flags`.
        assert!(attr.len() >= ATTR_LINUX, "fuse_attr too short");
    }

    /// The native (macFUSE) layout must be untouched by the patch: `crtime` at 48, `crtimensec`
    /// at 68 and the Darwin `flags` at 92 - i.e. exactly the fields FUSE-T cannot read.
    fn assert_native_attr_layout(attr: &[u8]) {
        assert_eq!(u64_at(attr, 48), CRTIME.0, "crtime");
        assert_eq!(u32_at(attr, 68), CRTIME.1, "crtimensec");
        assert_eq!(u32_at(attr, 72), 0o040755, "mode");
        assert_eq!(u32_at(attr, 88), RDEV, "rdev");
        assert_eq!(u32_at(attr, 92), DARWIN_FLAGS, "flags");
    }

    #[test]
    fn attr_out_switches_between_the_104_and_88_byte_layouts() {
        let ttl = Duration::from_secs(1);
        let native = bytes(&ResponseAttr::new_attr(
            &ttl,
            &(&attr()).into(),
            KernelAbi::Native,
        ));
        let linux = bytes(&ResponseAttr::new_attr(
            &ttl,
            &(&attr()).into(),
            KernelAbi::Linux,
        ));

        // fuse_attr_out = attr_valid(8) + attr_valid_nsec(4) + dummy(4) + fuse_attr
        assert_eq!(native.len(), HEADER + 16 + ATTR_NATIVE);
        assert_eq!(linux.len(), HEADER + 16 + ATTR_LINUX);
        assert_native_attr_layout(&native[HEADER + 16..]);
        assert_linux_attr_layout(&linux[HEADER + 16..]);
    }

    #[test]
    fn entry_out_switches_between_the_104_and_88_byte_layouts() {
        let ttl = Duration::from_secs(1);
        let mk = |abi| {
            bytes(&ResponseEntry::new_entry(
                INodeNo(1),
                Generation(0),
                &(&attr()).into(),
                ttl,
                ttl,
                abi,
            ))
        };
        let native = mk(KernelAbi::Native);
        let linux = mk(KernelAbi::Linux);

        // fuse_entry_out has 40 bytes ahead of the embedded fuse_attr.
        assert_eq!(native.len(), HEADER + 40 + ATTR_NATIVE);
        assert_eq!(linux.len(), HEADER + 40 + ATTR_LINUX);
        assert_native_attr_layout(&native[HEADER + 40..]);
        assert_linux_attr_layout(&linux[HEADER + 40..]);
    }

    #[test]
    fn create_reply_switches_between_the_104_and_88_byte_layouts() {
        let ttl = Duration::from_secs(1);
        let mk = |abi| {
            bytes(&ResponseCreate::new_create(
                &ttl,
                &(&attr()).into(),
                Generation(0),
                FileHandle(0xbb),
                FopenFlags::empty(),
                0,
                abi,
            ))
        };
        let native = mk(KernelAbi::Native);
        let linux = mk(KernelAbi::Linux);

        // fuse_create_out = fuse_entry_out + fuse_open_out(16)
        assert_eq!(native.len(), HEADER + 40 + ATTR_NATIVE + 16);
        assert_eq!(linux.len(), HEADER + 40 + ATTR_LINUX + 16);
        assert_native_attr_layout(&native[HEADER + 40..]);
        assert_linux_attr_layout(&linux[HEADER + 40..]);
    }

    #[test]
    fn readdirplus_entries_switch_between_the_104_and_88_byte_layouts() {
        let ttl = Duration::from_secs(1);
        let mk = |abi| {
            let mut list = DirEntPlusList::new(4096);
            let full = list.push(&DirEntryPlus::new(
                INodeNo(1),
                Generation(0),
                DirEntOffset(1),
                Path::new("a"),
                ttl,
                (&attr()).into(),
                ttl,
                abi,
            ));
            assert!(!full);
            let response: ResponseData = list.into();
            bytes(&response)
        };
        let native = mk(KernelAbi::Native);
        let linux = mk(KernelAbi::Linux);

        // fuse_direntplus = fuse_entry_out + fuse_dirent(24); the name "a" is padded to 8 bytes.
        assert_eq!(native.len(), HEADER + 40 + ATTR_NATIVE + 24 + 8);
        assert_eq!(linux.len(), HEADER + 40 + ATTR_LINUX + 24 + 8);
        assert_native_attr_layout(&native[HEADER + 40..]);
        assert_linux_attr_layout(&linux[HEADER + 40..]);
    }
}
