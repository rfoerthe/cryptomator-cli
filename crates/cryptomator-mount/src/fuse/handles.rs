//! Open file and directory handles.
//!
//! A FUSE `fh` is an opaque number the adapter hands out on `open`/`opendir` and gets back with
//! every subsequent request, so both tables map `u64` → state and are shared across the request
//! threads. Numbers start at 1 and are never reused, which makes a stale `fh` an error instead of
//! a silent hit on someone else's file.
use super::lock;
use cryptomator_core::fs::{CleartextPath, FileHandle};
use std::collections::HashMap;
use std::ffi::OsString;
use std::sync::{Arc, Mutex};

/// An open file behind a FUSE file handle.
#[derive(Debug)]
pub struct OpenFileEntry {
    /// The core handle doing the actual I/O.
    pub handle: FileHandle,
    /// The path the file was opened under (only for diagnostics and events: after a rename the
    /// inode table is authoritative).
    pub path: CleartextPath,
    /// `O_APPEND`: writes go to the end of the file, whatever offset the kernel passes.
    pub append: bool,
    /// Whether the handle was opened for writing.
    pub writable: bool,
}

/// One entry of a directory snapshot, including the `.` and `..` entries FUSE expects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirListing {
    /// The name as the FUSE peer sees it (already transcoded).
    pub name: OsString,
    /// The inode reported for the entry.
    pub ino: u64,
    /// The entry's type.
    pub kind: fuser::FileType,
}

/// The result of one `opendir`: `readdir` serves from this snapshot, so a directory that changes
/// while it is being read cannot make the kernel skip or repeat entries.
#[derive(Debug)]
pub struct DirSnapshot {
    /// The entries in the order they are reported, starting with `.` and `..`.
    pub entries: Vec<DirListing>,
}

#[derive(Debug)]
struct Inner<T> {
    by_id: HashMap<u64, Arc<T>>,
    next: u64,
}

/// Shared, monotonically numbered table of handles.
#[derive(Debug)]
struct HandleTable<T> {
    inner: Mutex<Inner<T>>,
}

impl<T> HandleTable<T> {
    fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                by_id: HashMap::new(),
                next: 1,
            }),
        }
    }

    fn insert(&self, value: T) -> u64 {
        let mut inner = lock(&self.inner);
        let id = inner.next;
        inner.next = inner.next.saturating_add(1);
        inner.by_id.insert(id, Arc::new(value));
        id
    }

    fn get(&self, id: u64) -> Option<Arc<T>> {
        lock(&self.inner).by_id.get(&id).cloned()
    }

    /// Takes the handle out of the table. `None` if it was unknown -- or, in the race where a
    /// concurrent request still holds the `Arc`, once that request drops it: the value is gone
    /// from the table either way, only the caller does not get to unwrap it.
    fn remove(&self, id: u64) -> Option<T> {
        let value = lock(&self.inner).by_id.remove(&id)?;
        Arc::into_inner(value)
    }

    fn len(&self) -> usize {
        lock(&self.inner).by_id.len()
    }
}

macro_rules! handle_table {
    ($name:ident, $value:ty, $what:literal) => {
        #[doc = concat!("The ", $what, " a FUSE file handle refers to.")]
        #[derive(Debug)]
        pub struct $name {
            table: HandleTable<$value>,
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl $name {
            /// An empty table; the first handle it hands out is 1.
            pub fn new() -> Self {
                Self {
                    table: HandleTable::new(),
                }
            }

            /// Stores `value` and returns its handle number.
            pub fn insert(&self, value: $value) -> u64 {
                self.table.insert(value)
            }

            /// The entry behind a handle, or `None` if the handle is unknown (`EBADF`).
            pub fn get(&self, fh: u64) -> Option<Arc<$value>> {
                self.table.get(fh)
            }

            /// Removes the handle on release and returns its entry, so the caller can close it
            /// and report errors. See [`HandleTable::remove`] for the concurrent-access case.
            pub fn remove(&self, fh: u64) -> Option<$value> {
                self.table.remove(fh)
            }

            /// Number of open handles.
            #[allow(clippy::len_without_is_empty)]
            pub fn len(&self) -> usize {
                self.table.len()
            }

            /// Whether no handle is open.
            pub fn is_empty(&self) -> bool {
                self.table.len() == 0
            }
        }
    };
}

handle_table!(FileHandles, OpenFileEntry, "open files");
handle_table!(DirHandles, DirSnapshot, "directory snapshots");

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(name: &str) -> DirSnapshot {
        DirSnapshot {
            entries: vec![DirListing {
                name: OsString::from(name),
                ino: 1,
                kind: fuser::FileType::Directory,
            }],
        }
    }

    #[test]
    fn handles_are_monotonic_and_removable() {
        let dirs = DirHandles::new();
        assert!(dirs.is_empty());
        assert!(dirs.get(1).is_none(), "nothing is open yet");
        let first = dirs.insert(snapshot("a"));
        let second = dirs.insert(snapshot("b"));
        assert_eq!((first, second), (1, 2));
        assert_eq!(dirs.len(), 2);
        assert_eq!(
            dirs.get(first).unwrap().entries[0].name,
            OsString::from("a")
        );
        let removed = dirs.remove(first).expect("open handle");
        assert_eq!(removed.entries[0].name, OsString::from("a"));
        assert!(dirs.get(first).is_none());
        assert!(dirs.remove(first).is_none(), "released twice");
        let third = dirs.insert(snapshot("c"));
        assert_eq!(third, 3, "numbers are not reused");
        assert_eq!(dirs.len(), 2);
    }

    #[test]
    fn a_borrowed_handle_is_still_removed_from_the_table() {
        let dirs = DirHandles::default();
        let fh = dirs.insert(snapshot("a"));
        let borrowed = dirs.get(fh).expect("open handle");
        assert!(dirs.remove(fh).is_none(), "the Arc is still borrowed");
        assert!(dirs.get(fh).is_none());
        assert_eq!(borrowed.entries.len(), 1); // the borrower keeps working
    }

    #[test]
    fn file_handles_start_empty() {
        // `OpenFileEntry` needs a real vault, so the file table is exercised through the same
        // generic table above; here we only pin the empty-table behaviour.
        let files = FileHandles::new();
        assert!(files.is_empty());
        assert!(files.get(1).is_none());
        assert!(files.remove(1).is_none());
    }
}
