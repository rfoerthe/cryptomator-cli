//! `CiphertextFilePath`, `CiphertextDirectory`, `CiphertextFileType`.
use super::long_names::DeflatedFileName;
use crate::constants::{CONTENTS_FILE_NAME, DIR_FILE_NAME, INFLATED_FILE_NAME, SYMLINK_FILE_NAME};
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CiphertextFileType {
    File,
    Directory,
    Symlink,
}

impl CiphertextFileType {
    /// Matches the `type` field of the fixture manifests.
    pub fn as_str(&self) -> &'static str {
        match self {
            CiphertextFileType::File => "file",
            CiphertextFileType::Directory => "dir",
            CiphertextFileType::Symlink => "symlink",
        }
    }
}

/// A directory id together with its content directory `d/XX/YYYY…`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiphertextDirectory {
    pub dir_id: String,
    pub path: PathBuf,
}

/// The ciphertext node of a cleartext path: a `.c9r` file or directory, or a `.c9s` directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiphertextFilePath {
    path: PathBuf,
    deflated: Option<DeflatedFileName>,
}

impl CiphertextFilePath {
    pub fn new(path: PathBuf, deflated: Option<DeflatedFileName>) -> Self {
        Self { path, deflated }
    }
    pub fn raw_path(&self) -> &Path {
        &self.path
    }
    pub fn is_shortened(&self) -> bool {
        self.deflated.is_some()
    }
    /// The regular-file ciphertext: the node itself, or `contents.c9r` inside a `.c9s` directory.
    pub fn file_path(&self) -> PathBuf {
        if self.is_shortened() {
            self.path.join(CONTENTS_FILE_NAME)
        } else {
            self.path.clone()
        }
    }
    pub fn dir_file_path(&self) -> PathBuf {
        self.path.join(DIR_FILE_NAME)
    }
    pub fn symlink_file_path(&self) -> PathBuf {
        self.path.join(SYMLINK_FILE_NAME)
    }
    pub fn inflated_name_path(&self) -> PathBuf {
        self.path.join(INFLATED_FILE_NAME)
    }
    pub fn persist_long_file_name(&self) -> io::Result<()> {
        match &self.deflated {
            Some(deflated) => deflated.persist(),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::long_names::deflate;

    #[test]
    fn shortened_paths_point_into_the_c9s_directory() {
        let plain = CiphertextFilePath::new(PathBuf::from("/v/d/AB/CD/x.c9r"), None);
        assert_eq!(plain.file_path(), PathBuf::from("/v/d/AB/CD/x.c9r"));
        assert_eq!(
            plain.dir_file_path(),
            PathBuf::from("/v/d/AB/CD/x.c9r/dir.c9r")
        );
        let deflated = deflate(Path::new("/v/d/AB/CD/long.c9r"));
        let short = CiphertextFilePath::new(deflated.c9s_path.clone(), Some(deflated.clone()));
        assert!(short.is_shortened());
        assert_eq!(short.file_path(), deflated.c9s_path.join("contents.c9r"));
        assert_eq!(
            short.symlink_file_path(),
            deflated.c9s_path.join("symlink.c9r")
        );
        assert_eq!(
            short.inflated_name_path(),
            deflated.c9s_path.join("name.c9s")
        );
        assert_eq!(CiphertextFileType::Directory.as_str(), "dir");
    }
}
