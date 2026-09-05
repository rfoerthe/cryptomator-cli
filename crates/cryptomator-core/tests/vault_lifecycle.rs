//! create → open → change password → open again, exercising the public API only.
use cryptomator_core::recovery::{create_recovery_key, reset_password, WordEncoder};
use cryptomator_core::{
    change_password, create_vault, open_vault, read_vault_config, CoreError, CreateVaultOptions,
    MasterkeyFileAccess, OsRng, VAULT_VERSION,
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

/// `reset_password` must use the file named by the config's `kid`, not `masterkey.cryptomator`.
#[test]
fn reset_password_honours_a_non_default_masterkey_file_name() {
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
    let recovery_key = create_recovery_key(&WordEncoder::new(), created.raw());

    // Point the (properly signed) config at `other.cryptomator` and move the file there.
    let config = read_vault_config(&vault)
        .unwrap()
        .verify(created.raw(), VAULT_VERSION)
        .unwrap();
    fs::write(
        vault.join("vault.cryptomator"),
        config.to_token("masterkeyfile:other.cryptomator", created.raw()),
    )
    .unwrap();
    fs::rename(
        vault.join("masterkey.cryptomator"),
        vault.join("other.cryptomator"),
    )
    .unwrap();
    let before = fs::read(vault.join("other.cryptomator")).unwrap();

    reset_password(
        &WordEncoder::new(),
        &access,
        &vault,
        &recovery_key,
        NEW,
        &mut OsRng,
    )
    .unwrap();

    assert!(
        !vault.join("masterkey.cryptomator").exists(),
        "the default name must not be resurrected"
    );
    assert_ne!(fs::read(vault.join("other.cryptomator")).unwrap(), before);
    let backups: Vec<_> = fs::read_dir(&vault)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".bkup"))
        .collect();
    assert_eq!(backups.len(), 1);
    assert!(
        backups[0].starts_with("other.cryptomator."),
        "backup sits beside the renamed file, got {}",
        backups[0]
    );
    assert_eq!(fs::read(vault.join(&backups[0])).unwrap(), before);

    let opened = open_vault(&vault, &access, NEW).unwrap();
    assert_eq!(opened.masterkey.raw(), created.raw());
}
