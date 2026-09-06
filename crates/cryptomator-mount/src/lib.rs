//! Mount services: FUSE (Linux libfuse3, macOS macFUSE/FUSE-T via dlopen) and WebDAV.
//!
//! The crate is organised like Cryptomator's mount integration: [`api`] holds the service /
//! builder / mount traits every provider implements, [`flags`] parses the user's mount flags,
//! [`transcoder`] normalises file names between the FUSE peer and the vault, and [`mounttab`]
//! answers whether a path is currently mounted.
#![warn(missing_debug_implementations)]

pub mod api;
pub mod flags;
pub mod mounttab;
pub mod transcoder;

pub use api::{
    unsupported, Mount, MountBuilder, MountCapability, MountError, MountService, Mountpoint,
    ServiceInfo, UnmountError,
};
pub use flags::{current_uid_gid, parse_mount_flags, AdapterOptions, MountFlags};
pub use mounttab::{is_mountpoint, mounted_paths};
pub use transcoder::{FuseNormalization, NameTranscoder};
