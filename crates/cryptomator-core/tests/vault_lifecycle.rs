//! create → open → change password → open again, exercising the public API only.
use cryptomator_core::{
    change_password, create_vault, open_vault, CoreError, CreateVaultOptions, MasterkeyFileAccess,
    OsRng,
};
use std::fs;

const OLD: &str = "old-passphrase-1";
const NEW: &str = "new-passphrase-2";

#[test]
fn full_password_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v");
    let access = MasterkeyFileAccess::new(Vec::new());
    let created = create_vault(
        &vault,
        OLD,
        &CreateVaultOptions::default(),
        &access,
        &mut OsRng,
    )
    .unwrap();
    let old_file = fs::read(vault.join("masterkey.cryptomator")).unwrap();

    let backup = change_password(&vault, &access, OLD, NEW, &mut OsRng).unwrap();
    assert!(backup
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("masterkey.cryptomator."));
    assert!(backup.to_string_lossy().ends_with(".bkup"));
    assert_eq!(
        fs::read(&backup).unwrap(),
        old_file,
        "backup holds the previous masterkey file"
    );
    assert_ne!(
        fs::read(vault.join("masterkey.cryptomator")).unwrap(),
        old_file
    );
    assert!(!vault.join("masterkey.cryptomator.tmp").exists());

    let opened = open_vault(&vault, &access, NEW).unwrap();
    assert_eq!(
        opened.masterkey.raw(),
        created.raw(),
        "the masterkey itself is unchanged"
    );
    assert!(matches!(
        open_vault(&vault, &access, OLD),
        Err(CoreError::InvalidPassphrase)
    ));
}

#[test]
fn wrong_old_password_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v");
    let access = MasterkeyFileAccess::new(Vec::new());
    create_vault(
        &vault,
        OLD,
        &CreateVaultOptions::default(),
        &access,
        &mut OsRng,
    )
    .unwrap();
    let before = fs::read(vault.join("masterkey.cryptomator")).unwrap();
    assert!(matches!(
        change_password(&vault, &access, "wrong", NEW, &mut OsRng),
        Err(CoreError::InvalidPassphrase)
    ));
    assert_eq!(
        fs::read(vault.join("masterkey.cryptomator")).unwrap(),
        before
    );
    assert_eq!(
        fs::read_dir(&vault)
            .unwrap()
            .filter(|e| e
                .as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".bkup"))
            .count(),
        0
    );
}
