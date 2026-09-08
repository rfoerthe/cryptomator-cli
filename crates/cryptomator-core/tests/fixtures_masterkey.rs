//! Loads every Java-generated fixture: masterkey file + vault config must verify with our implementation.
use cryptomator_core::constants::{MASTERKEY_FILENAME, VAULTCONFIG_FILENAME, VAULT_VERSION};
use cryptomator_core::{
    CipherCombo, FileNameCryptor, KeyId, MasterkeyFileAccess, UnverifiedVaultConfig,
};
use data_encoding::HEXLOWER;
use std::path::PathBuf;

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureMeta {
    name: String,
    cipher_combo: String,
    shortening_threshold: u32,
    passphrase: String,
    masterkey_hex: String,
}

/// Only the `kind` of a manifest, so this filter also parses the manifests of `legacy` fixtures,
/// which carry neither `masterkeyHex` nor a format-8 vault config.
#[derive(serde::Deserialize)]
struct FixtureKind {
    #[serde(default)]
    kind: Option<String>,
}

/// A fixture is clean unless its manifest marks it as damaged or as an older vault format.
fn is_clean(vault: &std::path::Path) -> bool {
    let kind: FixtureKind =
        serde_json::from_slice(&std::fs::read(vault.join("fixture.json")).unwrap()).unwrap();
    !matches!(kind.kind.as_deref(), Some("broken") | Some("legacy"))
}

fn fixture_dirs() -> Vec<PathBuf> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(&root)
        .expect("tests/fixtures exists (run tools/fixture-gen)")
        .map(|e| e.unwrap().path())
        .filter(|p| p.join("fixture.json").exists())
        .filter(|p| is_clean(p))
        .collect();
    dirs.sort();
    assert!(
        dirs.len() >= 8,
        "expected at least 8 fixtures, found {}",
        dirs.len()
    );
    dirs
}

#[test]
fn every_fixture_unlocks_and_verifies() {
    for dir in fixture_dirs() {
        let meta: FixtureMeta =
            serde_json::from_slice(&std::fs::read(dir.join("fixture.json")).unwrap()).unwrap();
        let access = MasterkeyFileAccess::new(Vec::new());
        let masterkey = access
            .load(&dir.join(MASTERKEY_FILENAME), &meta.passphrase)
            .unwrap_or_else(|e| panic!("{}: {e}", meta.name));
        assert_eq!(
            HEXLOWER.encode(masterkey.raw()),
            meta.masterkey_hex,
            "{}",
            meta.name
        );

        let token = std::fs::read_to_string(dir.join(VAULTCONFIG_FILENAME)).unwrap();
        let unverified = UnverifiedVaultConfig::decode(token.trim()).unwrap();
        assert_eq!(
            unverified.key_id().unwrap(),
            KeyId::MasterkeyFile {
                file_name: MASTERKEY_FILENAME.into()
            }
        );
        let config = unverified
            .verify(masterkey.raw(), VAULT_VERSION)
            .unwrap_or_else(|e| panic!("{}: {e}", meta.name));
        assert_eq!(
            config.cipher_combo,
            meta.cipher_combo.parse::<CipherCombo>().unwrap(),
            "{}",
            meta.name
        );
        assert_eq!(
            config.shortening_threshold, meta.shortening_threshold,
            "{}",
            meta.name
        );

        let wrong = access.load(&dir.join(MASTERKEY_FILENAME), "wrong password");
        assert!(
            matches!(wrong, Err(cryptomator_core::CoreError::InvalidPassphrase)),
            "{}",
            meta.name
        );
    }
}

#[test]
fn root_directory_of_every_fixture_exists_under_hashed_name() {
    for dir in fixture_dirs() {
        let meta: FixtureMeta =
            serde_json::from_slice(&std::fs::read(dir.join("fixture.json")).unwrap()).unwrap();
        let masterkey = MasterkeyFileAccess::new(Vec::new())
            .load(&dir.join(MASTERKEY_FILENAME), &meta.passphrase)
            .unwrap();
        let hash = FileNameCryptor::new(&masterkey).hash_directory_id("");
        let root = dir.join("d").join(&hash[..2]).join(&hash[2..]);
        assert!(
            root.is_dir(),
            "{}: root content dir {} missing",
            meta.name,
            root.display()
        );
        assert!(
            root.join("dirid.c9r").is_file(),
            "{}: dirid.c9r missing",
            meta.name
        );
    }
}
