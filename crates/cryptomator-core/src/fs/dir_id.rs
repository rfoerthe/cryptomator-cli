//! `DirectoryIdLoader`/`DirectoryIdProvider` (dir.c9r → directory id, cached) and `DirectoryIdBackup`
//! (`dirid.c9r`: the directory id encrypted like file content, inside its own content directory).
use super::ciphertext_path::CiphertextDirectory;
use super::events::{EventSink, FilesystemEvent};
use crate::constants::{DIR_ID_BACKUP_FILE_NAME, MAX_DIR_ID_LENGTH};
use crate::crypto::rng::Rng;
use crate::crypto::stream::{decrypt_all, encrypt_all};
use crate::error::{CoreError, Result};
use crate::Cryptor;
use data_encoding::BASE32;
use std::collections::HashMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// `DirectoryIdLoader.MAX_DIR_ID_LENGTH` (the loader tolerates more than the 36 chars of a UUID).
pub const MAX_DIR_FILE_LENGTH: u64 = 1000;

pub struct DirIdLoader {
    events: EventSink,
    cache: Mutex<HashMap<PathBuf, String>>,
}

impl std::fmt::Debug for DirIdLoader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirIdLoader")
            .field("cached", &super::lock(&self.cache).len())
            .finish()
    }
}

impl DirIdLoader {
    pub fn new(events: EventSink) -> Self {
        Self {
            events,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Reads `dir.c9r`. A missing file yields a fresh random UUID (which is cached, so a later
    /// `create_dir` writes exactly that id); empty or oversized files are broken.
    pub fn load(&self, dir_file: &Path) -> io::Result<String> {
        if let Some(id) = super::lock(&self.cache).get(dir_file) {
            return Ok(id.clone());
        }
        let id = self.load_uncached(dir_file)?;
        super::lock(&self.cache).insert(dir_file.to_path_buf(), id.clone());
        Ok(id)
    }

    fn load_uncached(&self, dir_file: &Path) -> io::Result<String> {
        let size = match std::fs::metadata(dir_file) {
            Ok(meta) => meta.len(),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Ok(uuid::Uuid::new_v4().to_string())
            }
            Err(e) => return Err(e),
        };
        if size == 0 {
            (self.events)(FilesystemEvent::BrokenDirFile {
                ciphertext_path: dir_file.to_path_buf(),
            });
            return Err(super::invalid_data(format!(
                "Invalid, empty directory file: {}",
                dir_file.display()
            )));
        }
        if size > MAX_DIR_FILE_LENGTH {
            (self.events)(FilesystemEvent::BrokenDirFile {
                ciphertext_path: dir_file.to_path_buf(),
            });
            return Err(super::invalid_data(format!(
                "Unexpectedly large directory file: {}",
                dir_file.display()
            )));
        }
        Ok(String::from_utf8_lossy(&std::fs::read(dir_file)?).into_owned())
    }

    pub fn delete(&self, dir_file: &Path) {
        super::lock(&self.cache).remove(dir_file);
    }

    /// `DirectoryIdProvider.move`: transfers a cached id to the new dir file path.
    pub fn move_id(&self, src: &Path, dst: &Path) {
        let mut cache = super::lock(&self.cache);
        if let Some(id) = cache.remove(src) {
            cache.insert(dst.to_path_buf(), id);
        }
    }
}

/// `CiphertextPathValidations.isCiphertextContentDir`: `<2 chars>/<30 chars>` that decode as BASE32.
pub fn is_ciphertext_content_dir(path: &Path) -> bool {
    let (Some(parent), Some(name)) = (path.parent().and_then(Path::file_name), path.file_name())
    else {
        return false;
    };
    let joined = format!("{}{}", parent.to_string_lossy(), name.to_string_lossy());
    joined.len() == 32 && BASE32.decode(joined.as_bytes()).is_ok()
}

/// `DirectoryIdBackup.write`: `dirid.c9r` (CREATE_NEW) with the id as encrypted file content.
pub fn write_dir_id_backup(
    cryptor: &Cryptor,
    dir: &CiphertextDirectory,
    rng: &mut dyn Rng,
) -> io::Result<()> {
    let ciphertext = encrypt_all(cryptor, rng, dir.dir_id.as_bytes())?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dir.path.join(DIR_ID_BACKUP_FILE_NAME))?;
    file.write_all(&ciphertext)
}

/// `DirectoryIdBackup.read`: decrypts `dirid.c9r` of a content directory (at most 36 chars).
pub fn read_dir_id_backup(cryptor: &Cryptor, content_dir: &Path) -> Result<String> {
    if !is_ciphertext_content_dir(content_dir) {
        return Err(CoreError::InvalidArgument(format!(
            "Directory {} is not a ciphertext content dir",
            content_dir.display()
        )));
    }
    let bytes = std::fs::read(content_dir.join(DIR_ID_BACKUP_FILE_NAME))?;
    let cleartext = decrypt_all(cryptor, &bytes).map_err(|e| match e.kind() {
        io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof => {
            CoreError::AuthenticationFailed(e.to_string())
        }
        _ => CoreError::Io(e),
    })?;
    if cleartext.len() > MAX_DIR_ID_LENGTH {
        return Err(CoreError::InvalidArgument(format!(
            "Read directory id exceeds the maximum length of {MAX_DIR_ID_LENGTH} characters"
        )));
    }
    String::from_utf8(cleartext)
        .map_err(|_| CoreError::AuthenticationFailed("directory id is not UTF-8".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{DATA_DIR_NAME, ROOT_DIR_ID};
    use crate::crypto::rng::DetRng;
    use crate::fs::events::EventCollector;
    use crate::fs::testutil::new_vault;
    use crate::fs::FilesystemEvent;

    #[test]
    fn load_reads_cached_deletes_and_moves() {
        let dir = tempfile::tempdir().unwrap();
        let events = EventCollector::new();
        let loader = DirIdLoader::new(events.sink());
        let dir_file = dir.path().join("dir.c9r");
        std::fs::write(&dir_file, "2f3a8f2e-0b8a-4e6f-9c5d-1a2b3c4d5e6f").unwrap();
        assert_eq!(
            loader.load(&dir_file).unwrap(),
            "2f3a8f2e-0b8a-4e6f-9c5d-1a2b3c4d5e6f"
        );
        // cached: a changed file is not re-read until delete()
        std::fs::write(&dir_file, "changed").unwrap();
        assert_eq!(
            loader.load(&dir_file).unwrap(),
            "2f3a8f2e-0b8a-4e6f-9c5d-1a2b3c4d5e6f"
        );
        let moved = dir.path().join("moved.c9r");
        loader.move_id(&dir_file, &moved);
        assert_eq!(
            loader.load(&moved).unwrap(),
            "2f3a8f2e-0b8a-4e6f-9c5d-1a2b3c4d5e6f"
        );
        loader.delete(&dir_file);
        assert_eq!(loader.load(&dir_file).unwrap(), "changed");
        assert!(events.take().is_empty());
    }

    #[test]
    fn missing_dir_file_yields_a_random_uuid_that_is_cached() {
        let dir = tempfile::tempdir().unwrap();
        let loader = DirIdLoader::new(crate::fs::discard_events());
        let missing = dir.path().join("dir.c9r");
        let id = loader.load(&missing).unwrap();
        assert_eq!(id.len(), 36);
        assert!(uuid::Uuid::parse_str(&id).is_ok());
        assert_eq!(loader.load(&missing).unwrap(), id);
    }

    #[test]
    fn empty_and_oversized_dir_files_are_broken() {
        let dir = tempfile::tempdir().unwrap();
        let events = EventCollector::new();
        let loader = DirIdLoader::new(events.sink());
        let empty = dir.path().join("empty.c9r");
        std::fs::write(&empty, b"").unwrap();
        let huge = dir.path().join("huge.c9r");
        std::fs::write(&huge, vec![b'a'; 1001]).unwrap();
        assert_eq!(
            loader.load(&empty).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        assert_eq!(
            loader.load(&huge).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        assert_eq!(events.kinds(), vec!["BROKEN_DIR_FILE", "BROKEN_DIR_FILE"]);
        assert!(
            matches!(&events.take()[0], FilesystemEvent::BrokenDirFile { ciphertext_path } if ciphertext_path == &empty)
        );
    }

    #[test]
    fn dir_id_backup_round_trip_and_validation() {
        let (vault, cryptor, _) = new_vault(220);
        let hash = cryptor.file_name_cryptor().hash_directory_id(ROOT_DIR_ID);
        let root = vault
            .path()
            .join(DATA_DIR_NAME)
            .join(&hash[..2])
            .join(&hash[2..]);
        assert!(is_ciphertext_content_dir(&root));
        assert!(!is_ciphertext_content_dir(vault.path()));
        // initialize() already wrote the root backup
        assert_eq!(read_dir_id_backup(&cryptor, &root).unwrap(), ROOT_DIR_ID);
        let child = CiphertextDirectory {
            dir_id: "2f3a8f2e-0b8a-4e6f-9c5d-1a2b3c4d5e6f".into(),
            path: vault
                .path()
                .join(DATA_DIR_NAME)
                .join("AA")
                .join("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"),
        };
        std::fs::create_dir_all(&child.path).unwrap();
        write_dir_id_backup(&cryptor, &child, &mut DetRng::default()).unwrap();
        assert_eq!(
            read_dir_id_backup(&cryptor, &child.path).unwrap(),
            child.dir_id
        );
        // CREATE_NEW: a second write fails
        assert!(write_dir_id_backup(&cryptor, &child, &mut DetRng::default()).is_err());
        // tampered backup is an authentication failure, not an io error
        let backup = child.path.join(DIR_ID_BACKUP_FILE_NAME);
        let mut bytes = std::fs::read(&backup).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        std::fs::write(&backup, bytes).unwrap();
        assert!(matches!(
            read_dir_id_backup(&cryptor, &child.path),
            Err(crate::CoreError::AuthenticationFailed(_))
        ));
    }
}
