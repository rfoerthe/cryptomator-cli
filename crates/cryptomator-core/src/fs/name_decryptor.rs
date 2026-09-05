//! `FileNameDecryptor`: cleartext name of a ciphertext node (`…/d/XX/YYYY/<node>.c9r|.c9s`),
//! using the `dirid.c9r` of its content directory.
use super::dir_id::read_dir_id_backup;
use super::long_names::inflate;
use crate::constants::{
    CRYPTOMATOR_FILE_SUFFIX, DEFLATED_FILE_SUFFIX, DIR_ID_BACKUP_FILE_NAME, MIN_CIPHER_NAME_LENGTH,
};
use crate::error::{CoreError, Result};
use crate::Cryptor;
use std::path::Path;

pub fn decrypt_filename(
    vault_path: &Path,
    cryptor: &Cryptor,
    ciphertext_node: &Path,
) -> Result<String> {
    let absolute = std::path::absolute(ciphertext_node)?;
    validate_path(vault_path, &absolute)?;
    let parent = absolute
        .parent()
        .ok_or_else(|| CoreError::InvalidArgument("node has no parent".into()))?;
    let dir_id = match read_dir_id_backup(cryptor, parent) {
        Ok(id) => id,
        Err(CoreError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(CoreError::InvalidArgument(format!(
                "Directory does not have a {DIR_ID_BACKUP_FILE_NAME} file."
            )));
        }
        Err(e) => {
            return Err(CoreError::AuthenticationFailed(format!(
                "Decryption of dirId backup file failed: {e}"
            )))
        }
    };
    let full_name = absolute
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let encrypted_name = if let Some(base) = full_name.strip_suffix(CRYPTOMATOR_FILE_SUFFIX) {
        base.to_string()
    } else {
        let c9r_name = inflate(&absolute)?;
        c9r_name
            .strip_suffix(CRYPTOMATOR_FILE_SUFFIX)
            .unwrap_or(&c9r_name)
            .to_string()
    };
    cryptor
        .file_name_cryptor()
        .decrypt_filename(&encrypted_name, &[dir_id.as_bytes()])
        .map_err(|e| CoreError::AuthenticationFailed(format!("Filename decryption failed: {e}")))
}

/// `FileNameDecryptor.validatePath`: inside the vault, at depth 4 (`d/XX/YYYY/node`), `.c9r`/`.c9s`, ≥ 28 chars.
fn validate_path(vault_path: &Path, absolute: &Path) -> Result<()> {
    let vault_abs = std::path::absolute(vault_path)?;
    let Ok(relative) = absolute.strip_prefix(&vault_abs) else {
        return Err(CoreError::InvalidArgument(format!(
            "Node {} is not a part of vault {}",
            absolute.display(),
            vault_abs.display()
        )));
    };
    if relative.components().count() != 4 {
        return Err(CoreError::InvalidArgument(format!(
            "Node {} is not located at depth 4 from vault storage root",
            absolute.display()
        )));
    }
    let name = absolute
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let has_extension =
        name.ends_with(CRYPTOMATOR_FILE_SUFFIX) || name.ends_with(DEFLATED_FILE_SUFFIX);
    if !has_extension || name.chars().count() < MIN_CIPHER_NAME_LENGTH {
        return Err(CoreError::InvalidArgument(format!(
            "Node {} does not end with {CRYPTOMATOR_FILE_SUFFIX} or {DEFLATED_FILE_SUFFIX} or filename is shorter than {MIN_CIPHER_NAME_LENGTH} characters.",
            absolute.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{DEFAULT_KEY_ID, DIR_ID_BACKUP_FILE_NAME};
    use crate::crypto::rng::DetRng;
    use crate::fs::{testutil, CleartextPath, CryptoFs, CryptoFsOptions};
    use crate::{initialize, open_vault_with_key, CipherCombo, CoreError, Masterkey};
    use std::sync::Arc;

    fn crypto_fs(dir: &tempfile::TempDir, key: Masterkey) -> CryptoFs {
        let opened = open_vault_with_key(dir.path(), key).unwrap();
        CryptoFs::with_rng(
            opened,
            CryptoFsOptions::default(),
            Box::new(DetRng::default()),
            Arc::new(|| Box::new(DetRng::default())),
        )
    }

    fn fs() -> (tempfile::TempDir, CryptoFs) {
        let (dir, _, _) = testutil::new_vault(220);
        let fs = crypto_fs(&dir, testutil::masterkey());
        (dir, fs)
    }

    /// A second vault with a genuinely different masterkey, so its cryptor fails authentication.
    fn foreign_fs() -> (tempfile::TempDir, CryptoFs) {
        let dir = tempfile::tempdir().unwrap();
        initialize(
            dir.path(),
            &Masterkey::from_raw([7u8; 64]),
            CipherCombo::SivGcm,
            220,
            DEFAULT_KEY_ID,
            &mut DetRng::default(),
        )
        .unwrap();
        let fs = crypto_fs(&dir, Masterkey::from_raw([7u8; 64]));
        (dir, fs)
    }

    #[test]
    fn decrypts_plain_and_shortened_nodes_in_any_directory() {
        let (dir, fs) = fs();
        fs.create_dir(&CleartextPath::parse("/docs")).unwrap();
        fs.write_file(&CleartextPath::parse("/docs/notes.md"), b"", false)
            .unwrap();
        let long = "x".repeat(200);
        fs.write_file(&CleartextPath::parse(&format!("/docs/{long}")), b"", false)
            .unwrap();
        let docs_content = fs
            .mapper()
            .ciphertext_dir(&CleartextPath::parse("/docs"))
            .unwrap()
            .path;
        let docs_node = fs
            .mapper()
            .ciphertext_file_path(&CleartextPath::parse("/docs"))
            .unwrap();
        assert_eq!(
            decrypt_filename(dir.path(), fs.cryptor_ref(), docs_node.raw_path()).unwrap(),
            "docs"
        );
        let notes = fs
            .mapper()
            .ciphertext_file_path(&CleartextPath::parse("/docs/notes.md"))
            .unwrap();
        assert_eq!(
            decrypt_filename(dir.path(), fs.cryptor_ref(), notes.raw_path()).unwrap(),
            "notes.md"
        );
        let long_node = fs
            .mapper()
            .ciphertext_file_path(&CleartextPath::parse(&format!("/docs/{long}")))
            .unwrap();
        assert!(long_node.is_shortened());
        assert_eq!(
            decrypt_filename(dir.path(), fs.cryptor_ref(), long_node.raw_path()).unwrap(),
            long
        );
        // relative node paths are resolved against the current directory, so pass absolute ones
        assert!(matches!(
            decrypt_filename(dir.path(), fs.cryptor_ref(), Path::new("/elsewhere/x.c9r")),
            Err(CoreError::InvalidArgument(_))
        ));
        assert!(
            matches!(
                decrypt_filename(dir.path(), fs.cryptor_ref(), &docs_content),
                Err(CoreError::InvalidArgument(_))
            ),
            "depth 3"
        );
        assert!(matches!(
            decrypt_filename(
                dir.path(),
                fs.cryptor_ref(),
                &docs_content.join("short.c9r")
            ),
            Err(CoreError::InvalidArgument(_))
        ));
        assert!(matches!(
            decrypt_filename(
                dir.path(),
                fs.cryptor_ref(),
                &docs_content.join(format!("{}.txt", "a".repeat(30)))
            ),
            Err(CoreError::InvalidArgument(_))
        ));
        // a node from another vault (wrong key) fails authentication
        let (other_dir, other_fs) = foreign_fs();
        let _ = other_dir;
        let foreign = notes.raw_path().to_path_buf();
        assert!(matches!(
            decrypt_filename(dir.path(), other_fs.cryptor_ref(), &foreign),
            Err(CoreError::AuthenticationFailed(_))
        ));
        // missing dirid.c9r
        std::fs::remove_file(docs_content.join(DIR_ID_BACKUP_FILE_NAME)).unwrap();
        assert!(matches!(
            decrypt_filename(dir.path(), fs.cryptor_ref(), notes.raw_path()),
            Err(CoreError::InvalidArgument(_))
        ));
    }
}
