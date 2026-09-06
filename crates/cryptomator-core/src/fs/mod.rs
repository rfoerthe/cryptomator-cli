//! Cleartext file system layer, ported from cryptofs 2.10.0 (`CryptoFileSystemImpl` and friends).
//! Errors are `std::io::Error` so a FUSE adapter can map them to errnos.
pub mod attrs;
pub mod capabilities;
pub mod ciphertext_path;
pub mod crypto_fs;
pub mod dir_id;
pub mod dir_stream;
pub mod events;
pub mod long_names;
pub mod name_decryptor;
pub mod open_file;
pub mod open_files;
pub mod path;
pub mod path_mapper;
pub mod stats;
pub mod symlinks;

// Re-exports of items that later tasks create; activated by the task that adds them.
pub use attrs::FileAttributes;
pub use capabilities::determine_supported_cleartext_file_name_length;
pub use ciphertext_path::{CiphertextDirectory, CiphertextFilePath, CiphertextFileType};
pub use crypto_fs::{CryptoFs, CryptoFsOptions, DEFAULT_MAX_CLEARTEXT_NAME_LENGTH};
pub use dir_id::DirIdLoader;
pub use dir_stream::DirEntry;
pub use events::{discard_events, EventCollector, EventSink, FilesystemEvent};
pub use name_decryptor::decrypt_filename;
pub use open_file::{OpenCryptoFile, OpenOptions};
pub use open_files::{FileHandle, OpenCryptoFiles, RngFactory, TwoPhaseMove};
pub use path::{child_display, CleartextPath};
pub use path_mapper::CryptoPathMapper;
pub use stats::{CryptoFsStats, StatsSnapshot};
pub use symlinks::Symlinks;

use std::fmt::Display;
use std::io;
use std::sync::{Mutex, MutexGuard, PoisonError};

/// Payload of the `io::Error` a symlink loop produces (`ErrorKind::Other`, because
/// `ErrorKind::FilesystemLoop` is unstable): downcast the error's inner value to it to recognise
/// the loop, e.g. `err.get_ref().and_then(|e| e.downcast_ref::<FilesystemLoop>())`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesystemLoop(pub String);

impl Display for FilesystemLoop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: too many levels of symbolic links", self.0)
    }
}

impl std::error::Error for FilesystemLoop {}

/// Locks without propagating poisoning: the protected data are caches and counters that stay
/// consistent even if a panic interrupted a holder.
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

mod io_errors {
    use super::*;

    pub(crate) fn not_found(path: impl Display) -> io::Error {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("{path}: no such file or directory"),
        )
    }
    pub(crate) fn already_exists(path: impl Display) -> io::Error {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{path}: already exists"),
        )
    }
    pub(crate) fn not_a_directory(path: impl Display) -> io::Error {
        io::Error::new(
            io::ErrorKind::NotADirectory,
            format!("{path}: not a directory"),
        )
    }
    pub(crate) fn is_a_directory(path: impl Display) -> io::Error {
        io::Error::new(
            io::ErrorKind::IsADirectory,
            format!("{path}: is a directory"),
        )
    }
    pub(crate) fn directory_not_empty(path: impl Display) -> io::Error {
        io::Error::new(
            io::ErrorKind::DirectoryNotEmpty,
            format!("{path}: directory not empty"),
        )
    }
    pub(crate) fn invalid_input(message: impl Into<String>) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, message.into())
    }
    pub(crate) fn invalid_data(message: impl Into<String>) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message.into())
    }
    pub(crate) fn read_only_fs() -> io::Error {
        io::Error::new(
            io::ErrorKind::ReadOnlyFilesystem,
            "vault is opened read-only",
        )
    }
    pub(crate) fn name_too_long(path: impl Display, max: usize) -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{path}: file name longer than {max} characters"),
        )
    }
    pub(crate) fn not_a_link(path: impl Display, detail: &str) -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{path}: not a symbolic link ({detail})"),
        )
    }
    /// `ErrorKind::FilesystemLoop` is still unstable, so this uses `Other` and carries the
    /// [`FilesystemLoop`] marker as the payload so a FUSE adapter can still answer `ELOOP`.
    pub(crate) fn fs_loop(path: impl Display) -> io::Error {
        io::Error::other(FilesystemLoop(path.to_string()))
    }
}

pub(crate) use io_errors::{
    already_exists, directory_not_empty, fs_loop, invalid_data, invalid_input, is_a_directory,
    name_too_long, not_a_directory, not_a_link, not_found, read_only_fs,
};

#[cfg(test)]
#[allow(dead_code)]
pub(crate) mod testutil {
    use crate::constants::DEFAULT_KEY_ID;
    use crate::crypto::rng::DetRng;
    use crate::{initialize, CipherCombo, Cryptor, Masterkey, VaultConfig};
    use std::sync::Arc;

    pub fn masterkey() -> Masterkey {
        let mut raw = [0u8; 64];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = i as u8;
        }
        Masterkey::from_raw(raw)
    }

    /// Initialises an empty format-8 vault (no scrypt: the raw masterkey is used directly).
    pub fn new_vault(threshold: u32) -> (tempfile::TempDir, Arc<Cryptor>, VaultConfig) {
        let dir = tempfile::tempdir().unwrap();
        let key = masterkey();
        let config = initialize(
            dir.path(),
            &key,
            CipherCombo::SivGcm,
            threshold,
            DEFAULT_KEY_ID,
            &mut DetRng::default(),
        )
        .unwrap();
        (
            dir,
            Arc::new(Cryptor::new(CipherCombo::SivGcm, &key)),
            config,
        )
    }
}
