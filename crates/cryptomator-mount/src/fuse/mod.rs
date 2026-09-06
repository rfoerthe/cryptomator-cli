//! The FUSE adapter: it translates the kernel's inode/handle world into the path-based
//! [`cryptomator_core::fs`] API.
//!
//! [`errno`] maps `io::Error` to the errno the kernel expects, [`inodes`] keeps the inode ↔ path
//! table the protocol requires, and [`handles`] holds the open files and directory snapshots a
//! `fh` refers to. [`ops`] implements the operations themselves, free of the fuser event loop.
//! The session and the platform back ends follow in later tasks.
use std::sync::{Mutex, MutexGuard, PoisonError};

pub mod errno;
pub mod handles;
pub mod inodes;
pub mod ops;

pub use errno::errno_for;
pub use handles::{DirHandles, DirListing, DirSnapshot, FileHandles, OpenFileEntry};
pub use inodes::InodeTable;
pub use ops::{Attr, Created, Statfs, VaultOps, VaultOpsConfig};

/// Locks without propagating poisoning (like `cryptomator_core::fs::lock`): the tables are plain
/// maps that stay consistent even if a panicking request thread interrupted a holder, and a FUSE
/// session must keep serving the other threads.
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
