//! `attr/CryptoBasicFileAttributes` + `CryptoPosixFileAttributes`: ciphertext metadata with the
//! cleartext size; an open file overrides size and mtime.
use super::ciphertext_path::CiphertextFileType;
use super::open_file::OpenCryptoFile;
use crate::Cryptor;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileAttributes {
    pub file_type: CiphertextFileType,
    pub size: u64,
    pub modified: Option<SystemTime>,
    pub accessed: Option<SystemTime>,
    pub created: Option<SystemTime>,
    /// Unix permission bits of the ciphertext node (write bits cleared for read-only vaults).
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u64,
}

impl FileAttributes {
    pub fn is_dir(&self) -> bool {
        self.file_type == CiphertextFileType::Directory
    }
    pub fn is_file(&self) -> bool {
        self.file_type == CiphertextFileType::File
    }
    pub fn is_symlink(&self) -> bool {
        self.file_type == CiphertextFileType::Symlink
    }
}

/// `CryptoBasicFileAttributes.calculatePlaintextFileSize`: undefined sizes count as 0.
// Consumed by `CryptoFs` (added in a later task); until then only the tests below call it.
#[allow(dead_code)]
pub(crate) fn cleartext_size_of(cryptor: &Cryptor, ciphertext_size: u64) -> u64 {
    ciphertext_size
        .checked_sub(cryptor.file_header_cryptor().header_size() as u64)
        .and_then(|payload| cryptor.file_content_cryptor().cleartext_size(payload).ok())
        .unwrap_or(0)
}

#[allow(dead_code)]
pub(crate) fn attributes_of(
    ciphertext_path: &Path,
    file_type: CiphertextFileType,
    cryptor: &Cryptor,
    open_file: Option<Arc<Mutex<OpenCryptoFile>>>,
    read_only: bool,
) -> io::Result<FileAttributes> {
    let meta = std::fs::metadata(ciphertext_path)?;
    let open = open_file.map(|f| {
        let f = super::lock(&f);
        (f.size(), f.last_modified())
    });
    let size = match file_type {
        CiphertextFileType::Directory => meta.len(),
        CiphertextFileType::File | CiphertextFileType::Symlink => open
            .map(|(size, _)| size)
            .unwrap_or_else(|| cleartext_size_of(cryptor, meta.len())),
    };
    let modified = match open {
        Some((_, Some(modified))) => Some(modified),
        _ => meta.modified().ok(),
    };
    let accessed = if open.is_some() {
        Some(SystemTime::now())
    } else {
        meta.accessed().ok()
    };
    let mut mode = meta.mode() & 0o7777;
    if read_only {
        mode &= !0o222;
    }
    Ok(FileAttributes {
        file_type,
        size,
        modified,
        accessed,
        created: meta.created().ok(),
        mode,
        uid: meta.uid(),
        gid: meta.gid(),
        nlink: meta.nlink(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rng::DetRng;
    use crate::crypto::stream::encrypt_all;
    use crate::fs::testutil;

    #[test]
    fn file_size_is_the_cleartext_size_and_read_only_strips_write_bits() {
        let (dir, cryptor, _) = testutil::new_vault(220);
        let path = dir.path().join("f");
        std::fs::write(
            &path,
            encrypt_all(&cryptor, &mut DetRng::default(), &[1u8; 40_000]).unwrap(),
        )
        .unwrap();
        let attrs = attributes_of(&path, CiphertextFileType::File, &cryptor, None, false).unwrap();
        assert_eq!(attrs.size, 40_000);
        assert!(attrs.is_file());
        assert_ne!(attrs.mode & 0o200, 0);
        let ro = attributes_of(&path, CiphertextFileType::File, &cryptor, None, true).unwrap();
        assert_eq!(ro.mode & 0o222, 0);
        std::fs::write(&path, b"garbage").unwrap();
        assert_eq!(
            attributes_of(&path, CiphertextFileType::File, &cryptor, None, false)
                .unwrap()
                .size,
            0
        );
        let d = attributes_of(
            dir.path(),
            CiphertextFileType::Directory,
            &cryptor,
            None,
            false,
        )
        .unwrap();
        assert!(d.is_dir());
    }
}
