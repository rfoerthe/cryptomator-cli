//! `CryptoPathMapper` + `CiphertextDirCache`: cleartext path ↔ ciphertext node / content directory.
use super::ciphertext_path::{CiphertextDirectory, CiphertextFilePath, CiphertextFileType};
use super::dir_id::DirIdLoader;
use super::events::{EventSink, FilesystemEvent};
use super::long_names::deflate;
use super::path::CleartextPath;
use crate::constants::{CRYPTOMATOR_FILE_SUFFIX, DATA_DIR_NAME, ROOT_DIR_ID};
use crate::Cryptor;
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub struct CryptoPathMapper {
    data_root: PathBuf,
    cryptor: Arc<Cryptor>,
    pub(crate) dir_ids: Arc<DirIdLoader>,
    shortening_threshold: usize,
    events: EventSink,
    /// `CiphertextDirCache`: mapping plus the time it was loaded, expiring after
    /// [`DIR_CACHE_TTL`](super::DIR_CACHE_TTL).
    dir_cache: Mutex<HashMap<CleartextPath, CachedDir>>,
    clock: super::Clock,
    root: CiphertextDirectory,
}

/// One `dir_cache` entry: cryptofs caches with `expireAfterWrite`, so the load time is what
/// decides, not the last access.
#[derive(Clone)]
struct CachedDir {
    dir: CiphertextDirectory,
    loaded: Instant,
}

impl std::fmt::Debug for CryptoPathMapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoPathMapper")
            .field("data_root", &self.data_root)
            .finish_non_exhaustive()
    }
}

impl CryptoPathMapper {
    pub fn new(
        vault_path: &Path,
        cryptor: Arc<Cryptor>,
        dir_ids: Arc<DirIdLoader>,
        shortening_threshold: u32,
        events: EventSink,
    ) -> Self {
        let data_root = vault_path.join(DATA_DIR_NAME);
        let root = Self::directory_for_id(&data_root, &cryptor, ROOT_DIR_ID);
        Self {
            data_root,
            cryptor,
            dir_ids,
            shortening_threshold: shortening_threshold as usize,
            events,
            dir_cache: Mutex::new(HashMap::new()),
            clock: super::Clock::default(),
            root,
        }
    }

    fn directory_for_id(data_root: &Path, cryptor: &Cryptor, dir_id: &str) -> CiphertextDirectory {
        let hash = cryptor.file_name_cryptor().hash_directory_id(dir_id);
        CiphertextDirectory {
            dir_id: dir_id.to_string(),
            path: data_root.join(&hash[..2]).join(&hash[2..]),
        }
    }

    pub fn root(&self) -> &CiphertextDirectory {
        &self.root
    }

    pub fn shortening_threshold(&self) -> usize {
        self.shortening_threshold
    }

    /// `<base64url(SIV(name, dirId))>.c9r`
    pub fn ciphertext_file_name(&self, dir_id: &str, cleartext_name: &str) -> String {
        format!(
            "{}{CRYPTOMATOR_FILE_SUFFIX}",
            self.cryptor
                .file_name_cryptor()
                .encrypt_filename(cleartext_name, &[dir_id.as_bytes()])
        )
    }

    /// `AlreadyExists` if any node (file, dir, symlink, broken) exists for the path.
    pub fn assert_non_existing(&self, cleartext: &CleartextPath) -> io::Result<()> {
        let ciphertext = self.ciphertext_file_path(cleartext)?;
        match std::fs::symlink_metadata(ciphertext.raw_path()) {
            Ok(_) => Err(super::already_exists(cleartext)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// `NotFound` if the node does not exist; `InvalidData` (+ `BrokenFileNode` event) for a node
    /// directory without `dir.c9r`, `symlink.c9r` or (shortened) `contents.c9r`.
    pub fn ciphertext_file_type(
        &self,
        cleartext: &CleartextPath,
    ) -> io::Result<CiphertextFileType> {
        if cleartext.is_root() {
            return Ok(CiphertextFileType::Directory);
        }
        let ciphertext = self.ciphertext_file_path(cleartext)?;
        let attr = std::fs::symlink_metadata(ciphertext.raw_path()).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                super::not_found(cleartext)
            } else {
                e
            }
        })?;
        if !attr.is_dir() {
            // assume "file" if not a directory (even if it isn't a "regular" file, see cryptofs issue #81)
            return Ok(CiphertextFileType::File);
        }
        let exists = |p: PathBuf| std::fs::symlink_metadata(p).is_ok();
        if exists(ciphertext.dir_file_path()) {
            Ok(CiphertextFileType::Directory)
        } else if exists(ciphertext.symlink_file_path()) {
            Ok(CiphertextFileType::Symlink)
        } else if ciphertext.is_shortened() && exists(ciphertext.file_path()) {
            Ok(CiphertextFileType::File)
        } else {
            (self.events)(FilesystemEvent::BrokenFileNode {
                cleartext_path: cleartext.to_string(),
                ciphertext_path: ciphertext.raw_path().to_path_buf(),
            });
            Err(super::invalid_data(format!(
                "{cleartext}: ciphertext directory {} has no clear type (missing dir.c9r, symlink.c9r or contents.c9r)",
                ciphertext.raw_path().display()
            )))
        }
    }

    pub fn ciphertext_file_path(
        &self,
        cleartext: &CleartextPath,
    ) -> io::Result<CiphertextFilePath> {
        let (Some(parent), Some(name)) = (cleartext.parent(), cleartext.file_name()) else {
            return Err(super::invalid_input(format!(
                "Invalid file path (must have a parent): {cleartext}"
            )));
        };
        let parent_dir = self.ciphertext_dir(&parent)?;
        Ok(self.ciphertext_file_path_in(&parent_dir.path, &parent_dir.dir_id, name))
    }

    pub fn ciphertext_file_path_in(
        &self,
        parent_ciphertext_dir: &Path,
        parent_dir_id: &str,
        cleartext_name: &str,
    ) -> CiphertextFilePath {
        let ciphertext_name = self.ciphertext_file_name(parent_dir_id, cleartext_name);
        let c9r_path = parent_ciphertext_dir.join(&ciphertext_name);
        if ciphertext_name.len() > self.shortening_threshold {
            let deflated = deflate(&c9r_path);
            CiphertextFilePath::new(deflated.c9s_path.clone(), Some(deflated))
        } else {
            CiphertextFilePath::new(c9r_path, None)
        }
    }

    /// Removes the mapping of `cleartext` and everything below it.
    pub fn invalidate_path_mapping(&self, cleartext: &CleartextPath) {
        super::lock(&self.dir_cache).retain(|key, _| !key.starts_with(cleartext));
    }

    /// Re-keys every mapping below `src` to live below `dst`. The moved entries keep their load
    /// time, so a rename cannot extend an entry's life beyond the 20 seconds it started with.
    pub fn move_path_mapping(&self, src: &CleartextPath, dst: &CleartextPath) {
        let mut cache = super::lock(&self.dir_cache);
        let moved: Vec<(CleartextPath, CachedDir)> = cache
            .iter()
            .filter(|(key, _)| key.starts_with(src))
            .filter_map(|(key, dir)| key.rebase(src, dst).map(|k| (k, dir.clone())))
            .collect();
        cache.retain(|key, _| !key.starts_with(src));
        cache.extend(moved);
    }

    /// The content directory of a cleartext directory (root without I/O; others via `dir.c9r`).
    pub fn ciphertext_dir(&self, cleartext: &CleartextPath) -> io::Result<CiphertextDirectory> {
        if cleartext.is_root() {
            return Ok(self.root.clone());
        }
        let now = self.clock.now();
        if let Some(entry) = super::lock(&self.dir_cache).get(cleartext) {
            if super::is_fresh(entry.loaded, now) {
                return Ok(entry.dir.clone());
            }
        }
        // not holding the lock: the lookup recurses into the parent directory
        let dir_file = self.ciphertext_file_path(cleartext)?.dir_file_path();
        let dir = self.resolve_directory(&dir_file)?;
        let now = self.clock.now();
        let mut cache = super::lock(&self.dir_cache);
        // Nothing else bounds the map, so a miss (which just did I/O anyway) drops what expired.
        // cryptofs additionally caps the cache at 5000 entries; expiry alone bounds ours to the
        // directories touched within the last 20 seconds.
        cache.retain(|_, entry| super::is_fresh(entry.loaded, now));
        // Overwrites a concurrently inserted entry instead of cryptofs' `putIfAbsent`: both were
        // read from the same `dir.c9r`, and this one is the younger of the two.
        cache.insert(
            cleartext.clone(),
            CachedDir {
                dir: dir.clone(),
                loaded: now,
            },
        );
        Ok(dir)
    }

    pub fn resolve_directory(&self, dir_file: &Path) -> io::Result<CiphertextDirectory> {
        let dir_id = self.dir_ids.load(dir_file)?;
        Ok(self.resolve_directory_id(&dir_id))
    }

    pub fn resolve_directory_id(&self, dir_id: &str) -> CiphertextDirectory {
        Self::directory_for_id(&self.data_root, &self.cryptor, dir_id)
    }

    /// Ages every cached mapping by `d` (the directory ids have their own clock).
    #[cfg(test)]
    pub(crate) fn advance(&self, d: std::time::Duration) {
        self.clock.advance(d);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::ROOT_DIR_ID;
    use crate::fs::{
        discard_events, testutil::new_vault, CiphertextFileType, CleartextPath, DIR_CACHE_TTL,
    };
    use std::time::Duration;

    fn mapper(threshold: u32) -> (tempfile::TempDir, CryptoPathMapper) {
        let (dir, cryptor, config) = new_vault(threshold);
        let loader = Arc::new(DirIdLoader::new(discard_events()));
        let mapper = CryptoPathMapper::new(
            dir.path(),
            cryptor,
            loader,
            config.shortening_threshold,
            discard_events(),
        );
        (dir, mapper)
    }

    #[test]
    fn root_maps_to_the_hashed_empty_dir_id() {
        let (dir, mapper) = mapper(220);
        let root = mapper.ciphertext_dir(&CleartextPath::root()).unwrap();
        assert_eq!(root.dir_id, ROOT_DIR_ID);
        assert!(root.path.starts_with(dir.path().join("d")));
        assert!(root.path.is_dir());
        assert_eq!(
            mapper.ciphertext_file_type(&CleartextPath::root()).unwrap(),
            CiphertextFileType::Directory
        );
        assert!(mapper.ciphertext_file_path(&CleartextPath::root()).is_err());
    }

    #[test]
    fn file_paths_are_encrypted_per_parent_dir_id_and_shortened_above_threshold() {
        let (_dir, mapper) = mapper(220);
        let short = mapper
            .ciphertext_file_path(&CleartextPath::parse("/a.txt"))
            .unwrap();
        assert!(!short.is_shortened());
        assert_eq!(short.raw_path().parent().unwrap(), mapper.root().path);
        assert!(short.raw_path().to_string_lossy().ends_with(".c9r"));
        let long = mapper
            .ciphertext_file_path(&CleartextPath::parse(&format!("/{}", "x".repeat(200))))
            .unwrap();
        assert!(long.is_shortened());
        assert!(long.raw_path().to_string_lossy().ends_with(".c9s"));
        // same name, other parent dir id → other ciphertext name
        let a = mapper.ciphertext_file_path_in(&mapper.root().path, "id-1", "a.txt");
        let b = mapper.ciphertext_file_path_in(&mapper.root().path, "id-2", "a.txt");
        assert_ne!(a, b);
        // BASE64URL(16 byte SIV tag + 5 byte name) = 28 characters, plus ".c9r"
        assert_eq!(mapper.ciphertext_file_name("id-1", "a.txt").len(), 28 + 4);
    }

    #[test]
    fn missing_nodes_and_types() {
        let (_dir, mapper) = mapper(220);
        let p = CleartextPath::parse("/missing");
        assert_eq!(
            mapper.ciphertext_file_type(&p).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert!(mapper.assert_non_existing(&p).is_ok());
        // a regular ciphertext file is a FILE, a node dir with dir.c9r a DIRECTORY, with symlink.c9r a SYMLINK
        let file = mapper
            .ciphertext_file_path(&CleartextPath::parse("/f"))
            .unwrap();
        std::fs::write(file.raw_path(), b"x").unwrap();
        assert_eq!(
            mapper
                .ciphertext_file_type(&CleartextPath::parse("/f"))
                .unwrap(),
            CiphertextFileType::File
        );
        assert_eq!(
            mapper
                .assert_non_existing(&CleartextPath::parse("/f"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        let dir = mapper
            .ciphertext_file_path(&CleartextPath::parse("/d"))
            .unwrap();
        std::fs::create_dir(dir.raw_path()).unwrap();
        std::fs::write(dir.dir_file_path(), "2f3a8f2e-0b8a-4e6f-9c5d-1a2b3c4d5e6f").unwrap();
        assert_eq!(
            mapper
                .ciphertext_file_type(&CleartextPath::parse("/d"))
                .unwrap(),
            CiphertextFileType::Directory
        );
        let link = mapper
            .ciphertext_file_path(&CleartextPath::parse("/l"))
            .unwrap();
        std::fs::create_dir(link.raw_path()).unwrap();
        std::fs::write(link.symlink_file_path(), b"x").unwrap();
        assert_eq!(
            mapper
                .ciphertext_file_type(&CleartextPath::parse("/l"))
                .unwrap(),
            CiphertextFileType::Symlink
        );
        // empty node dir: broken
        let broken = mapper
            .ciphertext_file_path(&CleartextPath::parse("/b"))
            .unwrap();
        std::fs::create_dir(broken.raw_path()).unwrap();
        assert_eq!(
            mapper
                .ciphertext_file_type(&CleartextPath::parse("/b"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn dir_cache_invalidation_and_move() {
        let (_dir, mapper) = mapper(220);
        let d = CleartextPath::parse("/d");
        let node = mapper.ciphertext_file_path(&d).unwrap();
        std::fs::create_dir(node.raw_path()).unwrap();
        std::fs::write(node.dir_file_path(), "id-one").unwrap();
        let resolved = mapper.ciphertext_dir(&d).unwrap();
        assert_eq!(resolved.dir_id, "id-one");
        assert_eq!(
            resolved,
            mapper.resolve_directory(&node.dir_file_path()).unwrap()
        );
        // cached: changing dir.c9r on disk is invisible until invalidated
        std::fs::write(node.dir_file_path(), "id-two").unwrap();
        assert_eq!(mapper.ciphertext_dir(&d).unwrap().dir_id, "id-one");
        mapper.move_path_mapping(&d, &CleartextPath::parse("/e"));
        assert_eq!(
            mapper
                .ciphertext_dir(&CleartextPath::parse("/e"))
                .unwrap()
                .dir_id,
            "id-one"
        );
        mapper.invalidate_path_mapping(&d);
        // the dir id loader also caches; drop its entry to see the new id
        mapper.dir_ids.delete(&node.dir_file_path());
        assert_eq!(mapper.ciphertext_dir(&d).unwrap().dir_id, "id-two");
    }

    #[test]
    fn dir_cache_entries_expire_after_the_ttl() {
        let (_dir, mapper) = mapper(220);
        let d = CleartextPath::parse("/d");
        let node = mapper.ciphertext_file_path(&d).unwrap();
        std::fs::create_dir(node.raw_path()).unwrap();
        std::fs::write(node.dir_file_path(), "id-one").unwrap();
        assert_eq!(mapper.ciphertext_dir(&d).unwrap().dir_id, "id-one");
        // somebody else (a sync client) rewrites dir.c9r
        std::fs::write(node.dir_file_path(), "id-two").unwrap();

        // within the expiry: still the cached mapping (half the TTL, so the wall clock the test
        // itself spends cannot push it over)
        let half = DIR_CACHE_TTL / 2;
        mapper.advance(half);
        mapper.dir_ids.advance(half);
        assert_eq!(mapper.ciphertext_dir(&d).unwrap().dir_id, "id-one");

        // past it: both caches re-read the file
        mapper.advance(DIR_CACHE_TTL);
        mapper.dir_ids.advance(DIR_CACHE_TTL);
        assert_eq!(mapper.ciphertext_dir(&d).unwrap().dir_id, "id-two");
        // and the fresh entry is cached again
        std::fs::write(node.dir_file_path(), "id-three").unwrap();
        assert_eq!(mapper.ciphertext_dir(&d).unwrap().dir_id, "id-two");
    }

    #[test]
    fn a_miss_drops_the_entries_that_expired() {
        let (_dir, mapper) = mapper(220);
        for name in ["/a", "/b"] {
            let node = mapper
                .ciphertext_file_path(&CleartextPath::parse(name))
                .unwrap();
            std::fs::create_dir(node.raw_path()).unwrap();
            std::fs::write(node.dir_file_path(), format!("id{name}")).unwrap();
            mapper.ciphertext_dir(&CleartextPath::parse(name)).unwrap();
        }
        assert_eq!(super::super::lock(&mapper.dir_cache).len(), 2);
        mapper.advance(DIR_CACHE_TTL + Duration::from_secs(1));
        // the next miss is what prunes: nothing else bounds the map
        mapper.ciphertext_dir(&CleartextPath::parse("/a")).unwrap();
        assert_eq!(super::super::lock(&mapper.dir_cache).len(), 1);
    }
}
