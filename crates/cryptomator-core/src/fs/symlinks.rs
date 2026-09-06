//! `Symlinks`: a symlink is a node directory holding `symlink.c9r`, an encrypted file whose
//! cleartext is the target string.
use super::ciphertext_path::CiphertextFileType;
use super::open_file::OpenOptions;
use super::open_files::OpenCryptoFiles;
use super::path::CleartextPath;
use super::path_mapper::CryptoPathMapper;
use crate::constants::MAX_SYMLINK_LENGTH;
use std::collections::HashSet;
use std::io;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug)]
pub struct Symlinks {
    pub(crate) mapper: Arc<CryptoPathMapper>,
    open_files: Arc<OpenCryptoFiles>,
    read_only: bool,
}

impl Symlinks {
    pub fn new(
        mapper: Arc<CryptoPathMapper>,
        open_files: Arc<OpenCryptoFiles>,
        read_only: bool,
    ) -> Self {
        Self {
            mapper,
            open_files,
            read_only,
        }
    }

    pub fn create_symbolic_link(&self, cleartext: &CleartextPath, target: &str) -> io::Result<()> {
        if self.read_only {
            return Err(super::read_only_fs());
        }
        self.mapper.assert_non_existing(cleartext)?;
        if target.chars().count() > MAX_SYMLINK_LENGTH {
            return Err(super::invalid_input("path length limit exceeded."));
        }
        let ciphertext = self.mapper.ciphertext_file_path(cleartext)?;
        std::fs::create_dir(ciphertext.raw_path())?;
        let handle = self
            .open_files
            .open(&ciphertext.symlink_file_path(), OpenOptions::write_new())?;
        handle.write_all_at(target.as_bytes(), 0)?;
        handle.close()?;
        ciphertext.persist_long_file_name()
    }

    pub fn read_symbolic_link(&self, cleartext: &CleartextPath) -> io::Result<String> {
        let symlink_file = self
            .mapper
            .ciphertext_file_path(cleartext)?
            .symlink_file_path();
        assert_is_symlink(cleartext, &symlink_file)?;
        let handle = self
            .open_files
            .open(&symlink_file, OpenOptions::read_only())?;
        let size = handle.size();
        if size > MAX_SYMLINK_LENGTH as u64 {
            return Err(super::not_a_link(
                cleartext,
                "unreasonably large symlink file",
            ));
        }
        let mut buf = vec![0u8; size as usize];
        handle.read_exact_at(&mut buf, 0)?;
        handle.close()?;
        String::from_utf8(buf)
            .map_err(|_| super::invalid_data(format!("{cleartext}: symlink target is not UTF-8")))
    }

    /// Follows a chain of links to the final path (which need not exist). Relative targets are
    /// resolved against the link's parent directory (POSIX; cryptofs resolves them against the
    /// root, which its FUSE adapters never rely on).
    pub fn resolve_recursively(&self, cleartext: &CleartextPath) -> io::Result<CleartextPath> {
        let mut visited: HashSet<CleartextPath> = HashSet::new();
        let mut current = cleartext.clone();
        loop {
            let file_type = match self.mapper.ciphertext_file_type(&current) {
                Ok(t) => t,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(current), // cannot be a link
                Err(e) => return Err(e),
            };
            if file_type != CiphertextFileType::Symlink {
                return Ok(current);
            }
            if !visited.insert(current.clone()) {
                return Err(super::fs_loop(cleartext));
            }
            let target = self.read_symbolic_link(&current)?;
            let base = current.parent().unwrap_or_else(CleartextPath::root);
            current = base.join_path(&target);
        }
    }
}

/// `Symlinks.assertIsSymlink`: `NotFound` if the node directory is missing, "not a link" otherwise.
fn assert_is_symlink(cleartext: &CleartextPath, symlink_file: &Path) -> io::Result<()> {
    let parent = symlink_file
        .parent()
        .ok_or_else(|| super::not_a_link(cleartext, "no node directory"))?;
    let parent_attr = std::fs::symlink_metadata(parent).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            super::not_found(cleartext)
        } else {
            e
        }
    })?;
    if !parent_attr.is_dir() {
        return Err(super::not_a_link(
            cleartext,
            "file exists but is not a symlink",
        ));
    }
    match std::fs::symlink_metadata(symlink_file) {
        Ok(attr) if attr.is_file() => Ok(()),
        _ => Err(super::not_a_link(
            cleartext,
            "file exists but is not a symlink",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rng::DetRng;
    use crate::fs::dir_id::DirIdLoader;
    use crate::fs::{discard_events, testutil, CryptoFsStats};

    fn symlinks(read_only: bool) -> (tempfile::TempDir, Symlinks) {
        let (dir, cryptor, config) = testutil::new_vault(220);
        let mapper = Arc::new(CryptoPathMapper::new(
            dir.path(),
            cryptor.clone(),
            Arc::new(DirIdLoader::new(discard_events())),
            config.shortening_threshold,
            discard_events(),
        ));
        let files = Arc::new(OpenCryptoFiles::new(
            cryptor,
            Arc::new(CryptoFsStats::default()),
            discard_events(),
            Arc::new(|| Box::new(DetRng::default())),
        ));
        (dir, Symlinks::new(mapper, files, read_only))
    }

    #[test]
    fn create_read_and_resolve() {
        let (_dir, s) = symlinks(false);
        let link = CleartextPath::parse("/link");
        s.create_symbolic_link(&link, "target.txt").unwrap();
        assert_eq!(s.read_symbolic_link(&link).unwrap(), "target.txt");
        assert_eq!(
            s.mapper.ciphertext_file_type(&link).unwrap(),
            CiphertextFileType::Symlink
        );
        assert_eq!(
            s.create_symbolic_link(&link, "x").unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        // relative targets resolve against the link's parent; the target need not exist
        assert_eq!(
            s.resolve_recursively(&link).unwrap().to_string(),
            "/target.txt"
        );
        s.create_symbolic_link(&CleartextPath::parse("/abs"), "/link")
            .unwrap();
        assert_eq!(
            s.resolve_recursively(&CleartextPath::parse("/abs"))
                .unwrap()
                .to_string(),
            "/target.txt"
        );
        // non-links resolve to themselves; missing paths too
        assert_eq!(
            s.resolve_recursively(&CleartextPath::parse("/nope"))
                .unwrap()
                .to_string(),
            "/nope"
        );
        assert_eq!(
            s.read_symbolic_link(&CleartextPath::parse("/nope"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        let long = "x".repeat(200);
        s.create_symbolic_link(&CleartextPath::root().join(&long).unwrap(), "t")
            .unwrap();
        assert_eq!(
            s.read_symbolic_link(&CleartextPath::root().join(&long).unwrap())
                .unwrap(),
            "t"
        );
    }

    #[test]
    fn loops_and_limits() {
        let (_dir, s) = symlinks(false);
        s.create_symbolic_link(&CleartextPath::parse("/a"), "b")
            .unwrap();
        s.create_symbolic_link(&CleartextPath::parse("/b"), "a")
            .unwrap();
        let loop_err = s
            .resolve_recursively(&CleartextPath::parse("/a"))
            .unwrap_err();
        assert_eq!(loop_err.kind(), io::ErrorKind::Other);
        assert!(
            loop_err
                .get_ref()
                .and_then(|e| e.downcast_ref::<crate::fs::FilesystemLoop>())
                .is_some(),
            "a loop is recognisable by its payload: {loop_err}"
        );
        assert_eq!(
            s.create_symbolic_link(&CleartextPath::parse("/c"), &"y".repeat(32_768))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        let (_dir, ro) = symlinks(true);
        assert_eq!(
            ro.create_symbolic_link(&CleartextPath::parse("/d"), "e")
                .unwrap_err()
                .kind(),
            io::ErrorKind::ReadOnlyFilesystem
        );
    }

    #[test]
    fn a_file_is_not_a_link() {
        let (_dir, s) = symlinks(false);
        let p = CleartextPath::parse("/f");
        let node = s.mapper.ciphertext_file_path(&p).unwrap();
        std::fs::write(node.raw_path(), b"not a node dir").unwrap();
        assert_eq!(
            s.read_symbolic_link(&p).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
