//! The FUSE adapter: it translates the kernel's inode/handle world into the path-based
//! [`cryptomator_core::fs`] API.
//!
//! [`errno`] maps `io::Error` to the errno the kernel expects, [`inodes`] keeps the inode ↔ path
//! table the protocol requires, and [`handles`] holds the open files and directory snapshots a
//! `fh` refers to. [`ops`] implements the operations themselves, free of the fuser event loop.
//! [`adapter`] is the thin `fuser::Filesystem` over them and [`session`] the handle on the running
//! event loop. [`mount`] holds the [`FuseMount`] they all hand back; the platform back ends are
//! [`linux`] (libfuse3), [`fuset`] and [`macfuse`] (both through [`macos_dl`]).
use std::sync::{Mutex, MutexGuard, PoisonError};

pub mod adapter;
pub mod errno;
#[cfg(target_os = "macos")]
pub mod fuset;
pub mod handles;
pub mod inodes;
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macfuse;
#[cfg(target_os = "macos")]
pub mod macos_dl;
pub mod mount;
pub mod ops;
pub mod session;

pub use adapter::CryptoFuse;
pub use errno::errno_for;
#[cfg(target_os = "macos")]
pub use fuset::{FuseTMountBuilder, FuseTMountProvider};
pub use handles::{DirHandles, DirListing, DirSnapshot, FileHandles, OpenFileEntry};
pub use inodes::InodeTable;
pub use linux::{LinuxFuseMountBuilder, LinuxFuseMountProvider};
#[cfg(target_os = "macos")]
pub use macfuse::{MacFuseMountBuilder, MacFuseMountProvider};
#[cfg(target_os = "macos")]
pub use macos_dl::LibFuse;
pub use mount::FuseMount;
pub use ops::{Attr, Created, Statfs, VaultOps, VaultOpsConfig};
pub use session::{FuseSessionHandle, Unmounter};

/// Locks without propagating poisoning (like `cryptomator_core::fs::lock`): the tables are plain
/// maps that stay consistent even if a panicking request thread interrupted a holder, and a FUSE
/// session must keep serving the other threads.
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
