//! The inode ↔ path table.
//!
//! FUSE addresses files by inode number, the core file system by path, so the adapter keeps a
//! table of the inodes the kernel currently knows. Its lifetime rules follow the protocol: an
//! inode lives until as many `forget`s as `lookup`s have arrived (libfuse's `nlookup`), which is
//! why an unlinked file keeps working for handles that are still open.
use super::lock;
use cryptomator_core::fs::CleartextPath;
use std::collections::HashMap;
use std::sync::Mutex;

/// The root inode, fixed by the protocol.
pub const ROOT_INO: u64 = 1;

/// Lookup count of the root: it is never forgotten, and `u64::MAX / 2` leaves room for the
/// `forget(1, u64::MAX)` a misbehaving kernel might send without wrapping.
const ROOT_LOOKUPS: u64 = u64::MAX / 2;

#[derive(Debug)]
struct Entry {
    path: CleartextPath,
    /// The name this inode had is gone: it was unlinked, or another file was renamed over it.
    /// The inode itself lives on until the kernel forgets it, because open handles still refer to
    /// it -- but `path` no longer describes it. In the rename case something *else* sits there
    /// now, which is why [`InodeTable::path`] must not hand it out: a `getattr` would describe the
    /// wrong file and a `setattr(size)` without an `fh` would truncate it.
    unlinked: bool,
    lookups: u64,
}

#[derive(Debug)]
struct Inner {
    by_ino: HashMap<u64, Entry>,
    by_path: HashMap<CleartextPath, u64>,
    next: u64,
}

/// Maps inode numbers to cleartext paths and back. Shared across the FUSE request threads.
#[derive(Debug)]
pub struct InodeTable {
    inner: Mutex<Inner>,
}

impl Default for InodeTable {
    fn default() -> Self {
        Self::new()
    }
}

impl InodeTable {
    /// A table holding just the root (inode 1).
    pub fn new() -> Self {
        let root = CleartextPath::root();
        let mut by_ino = HashMap::new();
        by_ino.insert(
            ROOT_INO,
            Entry {
                path: root.clone(),
                unlinked: false,
                lookups: ROOT_LOOKUPS,
            },
        );
        let mut by_path = HashMap::new();
        by_path.insert(root, ROOT_INO);
        Self {
            inner: Mutex::new(Inner {
                by_ino,
                by_path,
                next: ROOT_INO + 1,
            }),
        }
    }

    /// The path of a known inode; `None` once it has been forgotten -- and `None` as well while
    /// it is [unlinked](Entry::unlinked), because then nothing (or something else) is behind that
    /// name. The callers treat `None` from an inode they still hold as "this file has no name any
    /// more" and answer from the open handle instead.
    pub fn path(&self, ino: u64) -> Option<CleartextPath> {
        lock(&self.inner)
            .by_ino
            .get(&ino)
            .filter(|entry| !entry.unlinked)
            .map(|entry| entry.path.clone())
    }

    /// The inode already mapped to `path`, without allocating one and without counting a lookup.
    ///
    /// `readdir` needs this: the kernel takes no reference on the inodes a listing names, so
    /// resolving them through [`lookup`](Self::lookup) would hand out inodes nobody ever forgets.
    pub fn ino_of(&self, path: &CleartextPath) -> Option<u64> {
        lock(&self.inner).by_path.get(path).copied()
    }

    /// The inode of `path`, allocating one if the path is not mapped yet, and counting the
    /// lookup the kernel now holds. A path that was [`remove_path`](Self::remove_path)d gets a
    /// fresh inode -- the old one stays reachable by number until it is forgotten.
    pub fn lookup(&self, path: &CleartextPath) -> u64 {
        let mut inner = lock(&self.inner);
        if let Some(&ino) = inner.by_path.get(path) {
            if let Some(entry) = inner.by_ino.get_mut(&ino) {
                entry.lookups = entry.lookups.saturating_add(1);
                return ino;
            }
            inner.by_path.remove(path); // stale mapping, should not happen
        }
        let ino = inner.next;
        inner.next = inner.next.saturating_add(1);
        inner.by_ino.insert(
            ino,
            Entry {
                path: path.clone(),
                unlinked: false,
                lookups: 1,
            },
        );
        inner.by_path.insert(path.clone(), ino);
        ino
    }

    /// Drops `n` lookups; the inode is released once they reach zero. The root is never released.
    pub fn forget(&self, ino: u64, n: u64) {
        if ino == ROOT_INO {
            return;
        }
        let mut inner = lock(&self.inner);
        let Some(entry) = inner.by_ino.get_mut(&ino) else {
            return;
        };
        entry.lookups = entry.lookups.saturating_sub(n);
        if entry.lookups > 0 {
            return;
        }
        let path = entry.path.clone();
        inner.by_ino.remove(&ino);
        if inner.by_path.get(&path) == Some(&ino) {
            inner.by_path.remove(&path);
        }
    }

    /// Re-keys `from` and everything below it after a rename, so inodes the kernel still holds
    /// keep resolving to the right file. An inode that already sat at `to` is marked
    /// [unlinked](Entry::unlinked), exactly like one whose name an `unlink` took away: it keeps
    /// its number for the handles that still hold it, but it is reachable neither by path nor
    /// through [`path`](Self::path) -- the file that took the name is a different one.
    pub fn rename(&self, from: &CleartextPath, to: &CleartextPath) {
        let mut inner = lock(&self.inner);
        let affected: Vec<(CleartextPath, u64)> = inner
            .by_path
            .iter()
            .filter(|(path, _)| path.starts_with(from))
            .map(|(path, &ino)| (path.clone(), ino))
            .collect();
        for (old, ino) in affected {
            let Some(new) = old.rebase(from, to) else {
                continue;
            };
            inner.by_path.remove(&old);
            if let Some(entry) = inner.by_ino.get_mut(&ino) {
                entry.path = new.clone();
            }
            // `insert` hands back the inode that sat at the destination, if any: that one has
            // just lost its name to the file being renamed.
            if let Some(victim) = inner.by_path.insert(new, ino) {
                if victim != ino {
                    if let Some(entry) = inner.by_ino.get_mut(&victim) {
                        entry.unlinked = true;
                    }
                }
            }
        }
    }

    /// After `unlink`/`rmdir`: the path no longer resolves to an inode, but the inode itself
    /// survives until it is forgotten, so open handles keep working (as in libfuse). The entry is
    /// marked [unlinked](Entry::unlinked), so nothing resolves it back to the name it lost.
    pub fn remove_path(&self, path: &CleartextPath) {
        let mut inner = lock(&self.inner);
        let Some(ino) = inner.by_path.remove(path) else {
            return;
        };
        if let Some(entry) = inner.by_ino.get_mut(&ino) {
            entry.unlinked = true;
        }
    }

    /// Number of inodes the kernel may still refer to (at least the root).
    #[allow(clippy::len_without_is_empty)] // the table always holds the root
    pub fn len(&self) -> usize {
        lock(&self.inner).by_ino.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_forget_rename_and_remove() {
        let t = InodeTable::new();
        assert_eq!(t.path(1).unwrap(), CleartextPath::root());
        let a = t.lookup(&CleartextPath::parse("/a"));
        let ab = t.lookup(&CleartextPath::parse("/a/b"));
        assert_eq!(t.lookup(&CleartextPath::parse("/a")), a, "stable");
        assert!(a >= 2 && ab > a);
        t.rename(&CleartextPath::parse("/a"), &CleartextPath::parse("/x"));
        assert_eq!(t.path(ab).unwrap().to_string(), "/x/b");
        assert_eq!(t.lookup(&CleartextPath::parse("/x")), a);
        t.remove_path(&CleartextPath::parse("/x/b"));
        assert!(
            t.path(ab).is_none(),
            "the name is gone, so the inode no longer resolves to it"
        );
        assert_eq!(t.len(), 3, "the ino itself survives until forget");
        assert_ne!(
            t.lookup(&CleartextPath::parse("/x/b")),
            ab,
            "a re-created path gets a fresh ino"
        );
        t.forget(a, 1);
        assert!(t.path(a).is_some(), "two lookups, one forget");
        t.forget(a, 1);
        assert!(
            t.path(a).is_some(),
            "the lookup of /x after the rename counts as well"
        );
        t.forget(a, 1);
        assert!(t.path(a).is_none());
        t.forget(1, u64::MAX);
        assert!(t.path(1).is_some(), "root is never forgotten");
    }

    #[test]
    fn forgetting_the_last_lookup_frees_the_inode_and_its_path() {
        let t = InodeTable::default();
        assert_eq!(t.len(), 1);
        let p = CleartextPath::parse("/f");
        let f = t.lookup(&p);
        assert_eq!(t.len(), 2);
        t.forget(f, 3); // more forgets than lookups: still just gone
        assert_eq!(t.len(), 1);
        assert!(t.path(f).is_none());
        assert_ne!(t.lookup(&p), f, "the path is unmapped as well");
        t.forget(u64::MAX, 1); // an unknown inode is ignored
    }

    #[test]
    fn renaming_over_an_existing_inode_unlinks_it() {
        let t = InodeTable::new();
        let src = t.lookup(&CleartextPath::parse("/src"));
        let child = t.lookup(&CleartextPath::parse("/src/deep/child"));
        let dst = t.lookup(&CleartextPath::parse("/dst"));
        let len_before = t.len();
        t.rename(&CleartextPath::parse("/src"), &CleartextPath::parse("/dst"));
        assert_eq!(t.lookup(&CleartextPath::parse("/dst")), src);
        assert_eq!(
            t.path(src).unwrap().to_string(),
            "/dst",
            "the renamed inode carries the destination path"
        );
        assert_eq!(t.path(child).unwrap().to_string(), "/dst/deep/child");
        // The victim keeps its number for the handles the kernel still holds, but it must not
        // resolve to `/dst` any more -- that name belongs to the file that replaced it, and a
        // `getattr`/`setattr(size)` on the victim would otherwise describe or truncate *that* one.
        assert!(
            t.path(dst).is_none(),
            "the overwritten inode lost its name to the rename"
        );
        assert_eq!(t.len(), len_before, "but it is still allocated");
        // The stale inode is not moved along by a second rename either.
        t.rename(&CleartextPath::parse("/dst"), &CleartextPath::parse("/end"));
        assert_eq!(t.path(src).unwrap().to_string(), "/end");
        assert!(t.path(dst).is_none());
        // And it is freed the moment the kernel forgets it, like any other inode.
        t.forget(dst, 1);
        assert_eq!(t.len(), len_before - 1);
    }

    /// The same rule from the other side: `unlink` takes the name away, the inode stays until the
    /// kernel forgets it, and a file re-created under that name is a different inode.
    #[test]
    fn removing_a_path_unlinks_its_inode_without_freeing_it() {
        let t = InodeTable::new();
        let path = CleartextPath::parse("/f");
        let f = t.lookup(&path);
        t.remove_path(&path);
        assert!(t.path(f).is_none(), "the name is gone");
        assert_eq!(t.len(), 2, "the inode is not");
        let fresh = t.lookup(&path);
        assert_ne!(fresh, f);
        assert_eq!(t.path(fresh).unwrap().to_string(), "/f");
        assert!(t.path(f).is_none(), "the old inode stays nameless");
        t.forget(f, 1);
        assert_eq!(t.len(), 2, "forgetting the old one leaves the fresh one");
        t.remove_path(&CleartextPath::parse("/never-mapped"));
    }

    #[test]
    fn renaming_an_unknown_path_changes_nothing() {
        let t = InodeTable::new();
        let a = t.lookup(&CleartextPath::parse("/a"));
        t.rename(&CleartextPath::parse("/b"), &CleartextPath::parse("/c"));
        assert_eq!(t.path(a).unwrap().to_string(), "/a");
        assert_eq!(t.len(), 2);
    }
}
