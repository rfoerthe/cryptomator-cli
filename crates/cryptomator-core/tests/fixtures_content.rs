//! Walks every Java-generated fixture vault end to end: decrypt names, directory ids, file contents
//! and symlink targets, then compare the whole cleartext tree against the fixture's `expected.json`.
//! Slow in debug builds (~40 s) because every fixture unlocks its masterkey with scrypt N=2^15.
use cryptomator_core::constants::{
    CONTENTS_FILE_NAME, CRYPTOMATOR_FILE_SUFFIX, DATA_DIR_NAME, DEFLATED_FILE_SUFFIX,
    DIR_FILE_NAME, DIR_ID_BACKUP_FILE_NAME, INFLATED_FILE_NAME, MASTERKEY_FILENAME, ROOT_DIR_ID,
    SYMLINK_FILE_NAME, VAULTCONFIG_FILENAME, VAULT_VERSION,
};
use cryptomator_core::{
    decrypt_all, CipherCombo, Cryptor, MasterkeyFileAccess, UnverifiedVaultConfig,
};
use data_encoding::HEXLOWER;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// The clean format-8 fixtures. Deliberately damaged (`kind` = `broken`) and pre-format-8
/// (`kind` = `legacy`) fixtures do not decrypt to a full cleartext tree and stay out of this list.
const FIXTURE_NAMES: [&str; 8] = [
    "long_names",
    "nested",
    "siv_ctrmac_basic",
    "siv_gcm_basic",
    "sizes",
    "symlinks",
    "threshold_36",
    "unicode",
];

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureMeta {
    cipher_combo: String,
    passphrase: String,
    /// `clean` (the default for manifests written before the field existed), `broken` or `legacy`.
    #[serde(default)]
    kind: Option<String>,
}

/// A fixture is clean unless its manifest marks it as damaged or as an older vault format.
fn is_clean(vault: &Path) -> bool {
    let meta: FixtureMeta =
        serde_json::from_slice(&std::fs::read(vault.join("fixture.json")).unwrap()).unwrap();
    !matches!(meta.kind.as_deref(), Some("broken") | Some("legacy"))
}

/// One cleartext node. `size`/`sha256` are set for files, `target` for symlinks, matching `expected.json`.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize)]
struct Entry {
    path: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    size: Option<u64>,
    #[serde(default)]
    sha256: Option<String>,
    #[serde(default)]
    target: Option<String>,
}

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

fn decrypt_file(cryptor: &Cryptor, path: &Path) -> Vec<u8> {
    decrypt_all(cryptor, &std::fs::read(path).unwrap())
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// Walks the content directory of `dir_id` and appends every cleartext node below `prefix`.
fn walk(vault: &Path, cryptor: &Cryptor, dir_id: &str, prefix: &str, out: &mut Vec<Entry>) {
    let hash = cryptor.file_name_cryptor().hash_directory_id(dir_id);
    let content_dir = vault.join(DATA_DIR_NAME).join(&hash[..2]).join(&hash[2..]);
    assert!(content_dir.is_dir(), "{} missing", content_dir.display());
    assert_eq!(
        decrypt_file(cryptor, &content_dir.join(DIR_ID_BACKUP_FILE_NAME)),
        dir_id.as_bytes(),
        "{}: dirid.c9r does not hold its own directory id",
        content_dir.display()
    );

    let mut children: Vec<PathBuf> = std::fs::read_dir(&content_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.file_name().unwrap() != DIR_ID_BACKUP_FILE_NAME)
        .collect();
    children.sort();

    for node in children {
        let stored_name = node.file_name().unwrap().to_str().unwrap().to_owned();
        // Shortened names keep the full `<base64>.c9r` name in `name.c9s` inside the `.c9s` directory.
        let full_name = if stored_name.ends_with(DEFLATED_FILE_SUFFIX) {
            assert!(node.is_dir(), "{stored_name} (.c9s) must be a directory");
            String::from_utf8(std::fs::read(node.join(INFLATED_FILE_NAME)).unwrap()).unwrap()
        } else {
            stored_name.clone()
        };
        let base64 = full_name
            .strip_suffix(CRYPTOMATOR_FILE_SUFFIX)
            .unwrap_or_else(|| panic!("{full_name} does not end in .c9r"));
        let name = cryptor
            .file_name_cryptor()
            .decrypt_filename(base64, &[dir_id.as_bytes()])
            .unwrap_or_else(|e| panic!("{}: {e}", node.display()));
        let path = format!("{prefix}/{name}");

        if node.is_file() {
            // Unshortened regular file: the node itself is the ciphertext.
            assert!(!stored_name.ends_with(DEFLATED_FILE_SUFFIX));
            out.push(file_entry(path, decrypt_file(cryptor, &node)));
        } else if node.join(DIR_FILE_NAME).is_file() {
            let child_dir_id = String::from_utf8(std::fs::read(node.join(DIR_FILE_NAME)).unwrap())
                .expect("dir.c9r holds the child directory id as plain UTF-8");
            out.push(Entry {
                path: path.clone(),
                kind: "dir".into(),
                size: None,
                sha256: None,
                target: None,
            });
            walk(vault, cryptor, &child_dir_id, &path, out);
        } else if node.join(SYMLINK_FILE_NAME).is_file() {
            let target = decrypt_file(cryptor, &node.join(SYMLINK_FILE_NAME));
            out.push(Entry {
                path,
                kind: "symlink".into(),
                size: None,
                sha256: None,
                target: Some(String::from_utf8(target).unwrap()),
            });
        } else if node.join(CONTENTS_FILE_NAME).is_file() {
            assert!(
                stored_name.ends_with(DEFLATED_FILE_SUFFIX),
                "{stored_name}: contents.c9r only occurs inside shortened .c9s directories"
            );
            out.push(file_entry(
                path,
                decrypt_file(cryptor, &node.join(CONTENTS_FILE_NAME)),
            ));
        } else {
            panic!(
                "{}: neither file, dir.c9r, symlink.c9r nor contents.c9r",
                node.display()
            );
        }
    }
}

fn file_entry(path: String, cleartext: Vec<u8>) -> Entry {
    Entry {
        path,
        kind: "file".into(),
        size: Some(cleartext.len() as u64),
        sha256: Some(HEXLOWER.encode(&Sha256::digest(&cleartext))),
        target: None,
    }
}

#[test]
fn every_fixture_decrypts_to_its_expected_tree() {
    let root = fixtures_root();
    let mut found: Vec<String> = std::fs::read_dir(&root)
        .expect("tests/fixtures exists (run tools/fixture-gen)")
        .map(|e| e.unwrap().file_name().to_str().unwrap().to_owned())
        .filter(|n| root.join(n).join("fixture.json").exists())
        .filter(|n| is_clean(&root.join(n)))
        .collect();
    found.sort();
    assert_eq!(found, FIXTURE_NAMES, "unexpected set of clean fixtures");

    for name in FIXTURE_NAMES {
        let vault = root.join(name);
        let meta: FixtureMeta =
            serde_json::from_slice(&std::fs::read(vault.join("fixture.json")).unwrap()).unwrap();
        let masterkey = MasterkeyFileAccess::new(Vec::new())
            .load(&vault.join(MASTERKEY_FILENAME), &meta.passphrase)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let token = std::fs::read_to_string(vault.join(VAULTCONFIG_FILENAME)).unwrap();
        let config = UnverifiedVaultConfig::decode(token.trim())
            .unwrap()
            .verify(masterkey.raw(), VAULT_VERSION)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(
            config.cipher_combo,
            meta.cipher_combo.parse::<CipherCombo>().unwrap(),
            "{name}"
        );

        let cryptor = Cryptor::new(config.cipher_combo, &masterkey);
        let mut actual = Vec::new();
        walk(&vault, &cryptor, ROOT_DIR_ID, "", &mut actual);
        actual.sort();

        let mut expected: Vec<Entry> =
            serde_json::from_slice(&std::fs::read(vault.join("expected.json")).unwrap()).unwrap();
        expected.sort();
        assert_eq!(actual, expected, "{name}: decrypted tree differs");
    }
}
