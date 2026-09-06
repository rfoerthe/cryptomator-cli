//! Mount services: FUSE (Linux libfuse3, macOS macFUSE/FUSE-T via dlopen) and WebDAV.
//!
//! The crate is organised like Cryptomator's mount integration: [`api`] holds the service /
//! builder / mount traits every provider implements, [`flags`] parses the user's mount flags,
//! [`transcoder`] normalises file names between the FUSE peer and the vault, and [`mounttab`]
//! answers whether a path is currently mounted. [`fuse`] (feature `fuse`) holds the FUSE adapter
//! and the platform back ends, [`webdav`] (feature `webdav`) holds the loopback WebDAV server and
//! its mounters, and [`registry`] lists the services the CLI can choose from.
#![warn(missing_debug_implementations)]

pub mod api;
pub mod flags;
#[cfg(feature = "fuse")]
pub mod fuse;
pub mod mounttab;
pub mod registry;
#[cfg(test)]
mod testing;
pub mod transcoder;
// The WebDAV back ends need no FFI at all, so the whole module is `forbid(unsafe_code)`: the
// crate's only `unsafe` lives under `fuse/`.
#[cfg(feature = "webdav")]
#[forbid(unsafe_code)]
pub mod webdav;

pub use api::{
    unsupported, Mount, MountBuilder, MountCapability, MountError, MountService, Mountpoint,
    ServiceInfo, UnmountError,
};
pub use flags::{current_uid_gid, parse_mount_flags, AdapterOptions, MountFlags};
#[cfg(feature = "fuse")]
pub use fuse::{
    errno_for, Attr, Created, CryptoFuse, DirHandles, DirListing, DirSnapshot, FileHandles,
    FuseMount, FuseSessionHandle, InodeTable, LinuxFuseMountBuilder, LinuxFuseMountProvider,
    OpenFileEntry, Statfs, Unmounter, VaultOps, VaultOpsConfig,
};
#[cfg(all(feature = "fuse", target_os = "macos"))]
pub use fuse::{
    FuseTMountBuilder, FuseTMountProvider, LibFuse, MacFuseMountBuilder, MacFuseMountProvider,
};
pub use mounttab::{is_mountpoint, mounted_paths};
pub use registry::{
    alias_for_class, all_services, conflicting_classes, service_by_class, service_infos, services,
    NullMountProvider, ENABLE_NULL_MOUNTER_ENV, FUSE_T_CLASS, LINUX_FUSE_CLASS, MAC_FUSE_CLASS,
    NULL_MOUNTER_CLASS, NULL_MOUNT_BUSY_ENV, NULL_MOUNT_MARKER,
};
pub use transcoder::{FuseNormalization, NameTranscoder};
