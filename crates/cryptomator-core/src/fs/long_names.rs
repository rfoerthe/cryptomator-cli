//! `LongFileNameProvider`: names longer than the shortening threshold are stored as
//! `BASE64URL(SHA1(name)).c9s/` directories holding the full name in `name.c9s`.
use crate::constants::{DEFLATED_FILE_SUFFIX, INFLATED_FILE_NAME};
use data_encoding::BASE64URL;
use sha1::{Digest, Sha1};
use std::io;
use std::path::{Path, PathBuf};

/// "no sane person gives a file a 10kb long name."
pub const MAX_FILENAME_BUFFER_SIZE: u64 = 10 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeflatedFileName {
    pub c9s_path: PathBuf,
    pub long_name: String,
}

impl DeflatedFileName {
    /// Creates the `.c9s` directory (if needed) and (re)writes `name.c9s`.
    pub fn persist(&self) -> io::Result<()> {
        std::fs::create_dir_all(&self.c9s_path)?;
        std::fs::write(
            self.c9s_path.join(INFLATED_FILE_NAME),
            self.long_name.as_bytes(),
        )
    }
}

pub fn is_deflated(name: &str) -> bool {
    name.ends_with(DEFLATED_FILE_SUFFIX)
}

/// The deflated *name* of a long file name: `BASE64URL(SHA1(longName)).c9s`.
///
/// The arithmetic of [`deflate`] on a bare name, so that the `shortened` health check
/// ([`crate::health::shortened::deflate_name`]) can compute the expected `.c9s` directory name of a
/// `name.c9s` content without building a path first — and without a second BASE64/SHA-1 site.
pub(crate) fn deflate_str(long_name: &str) -> String {
    format!(
        "{}{DEFLATED_FILE_SUFFIX}",
        BASE64URL.encode(&Sha1::digest(long_name.as_bytes()))
    )
}

/// `LongFileNameProvider.deflate`: `<parent>/<BASE64URL(SHA1(longName))>.c9s`.
pub fn deflate(c9r_path: &Path) -> DeflatedFileName {
    let long_name = c9r_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let short_name = deflate_str(&long_name);
    DeflatedFileName {
        c9s_path: c9r_path.with_file_name(short_name),
        long_name,
    }
}

/// `LongFileNameProvider.inflate`: reads `<c9s>/name.c9s` (at most 10 KiB, UTF-8).
pub fn inflate(c9s_path: &Path) -> io::Result<String> {
    let long_name_file = c9s_path.join(INFLATED_FILE_NAME);
    if std::fs::metadata(&long_name_file)?.len() > MAX_FILENAME_BUFFER_SIZE {
        return Err(super::invalid_data(format!(
            "Unexpectedly large file: {}",
            long_name_file.display()
        )));
    }
    String::from_utf8(std::fs::read(&long_name_file)?)
        .map_err(|_| super::invalid_data(format!("{}: not valid UTF-8", long_name_file.display())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{
        CRYPTOMATOR_FILE_SUFFIX, DATA_DIR_NAME, INFLATED_FILE_NAME, ROOT_DIR_ID,
    };
    use crate::{CipherCombo, Cryptor, Masterkey};
    use data_encoding::HEXLOWER;
    use std::path::PathBuf;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name)
    }

    fn fixture_cryptor(vault: &Path) -> Cryptor {
        let meta: serde_json::Value =
            serde_json::from_slice(&std::fs::read(vault.join("fixture.json")).unwrap()).unwrap();
        let raw = HEXLOWER
            .decode(meta["masterkeyHex"].as_str().unwrap().as_bytes())
            .unwrap();
        let mut key = [0u8; 64];
        key.copy_from_slice(&raw);
        Cryptor::new(CipherCombo::SivGcm, &Masterkey::from_raw(key))
    }

    #[test]
    fn deflate_matches_the_c9s_directory_java_created() {
        let vault = fixture("long_names");
        let cryptor = fixture_cryptor(&vault);
        let hash = cryptor.file_name_cryptor().hash_directory_id(ROOT_DIR_ID);
        let root = vault.join(DATA_DIR_NAME).join(&hash[..2]).join(&hash[2..]);
        let long_name = format!("{}.txt", "c".repeat(200));
        let c9r_name = format!(
            "{}{CRYPTOMATOR_FILE_SUFFIX}",
            cryptor
                .file_name_cryptor()
                .encrypt_filename(&long_name, &[ROOT_DIR_ID.as_bytes()])
        );
        assert!(c9r_name.len() > 220);
        let deflated = deflate(&root.join(&c9r_name));
        assert!(is_deflated(
            deflated.c9s_path.file_name().unwrap().to_str().unwrap()
        ));
        assert!(
            deflated.c9s_path.is_dir(),
            "{}",
            deflated.c9s_path.display()
        );
        assert_eq!(deflated.long_name, c9r_name);
        assert_eq!(inflate(&deflated.c9s_path).unwrap(), c9r_name);
    }

    #[test]
    fn persist_and_inflate_round_trip_and_size_cap() {
        let dir = tempfile::tempdir().unwrap();
        let deflated = deflate(&dir.path().join(format!("{}.c9r", "A".repeat(300))));
        deflated.persist().unwrap();
        assert_eq!(inflate(&deflated.c9s_path).unwrap(), deflated.long_name);
        // persisting twice truncates (Java: TRUNCATE_EXISTING)
        deflated.persist().unwrap();
        std::fs::write(
            deflated.c9s_path.join(INFLATED_FILE_NAME),
            vec![b'x'; 10 * 1024 + 1],
        )
        .unwrap();
        assert_eq!(
            inflate(&deflated.c9s_path).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        assert_eq!(
            inflate(&dir.path().join("missing.c9s")).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
    }
}
