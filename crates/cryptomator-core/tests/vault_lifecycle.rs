//! create → open → change password → open again, exercising the public API only.
mod common;

use cryptomator_core::recovery::{create_recovery_key, reset_password, restore, WordEncoder};
use cryptomator_core::{
    change_password, create_vault, open_vault, read_vault_config, BackupStatus, CipherCombo,
    CoreError, CreateVaultOptions, MasterkeyFileAccess, OsRng, VAULT_VERSION,
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

    let outcome = change_password(&vault, &access, OLD, NEW, &mut OsRng).unwrap();
    assert_eq!(outcome.status, BackupStatus::Created);
    let backup = outcome.path;
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

// ---------------------------------------------------------------------------------------------
// `recovery::restore`: rebuilding masterkey.cryptomator, vault.cryptomator or both.
// ---------------------------------------------------------------------------------------------

/// Removes the `.bkup` copies whose prefix is `prefix`, so a deleted key file stays deleted
/// (`determine_vault_state` and the tests below would otherwise see a restored one).
fn remove_backups(vault: &std::path::Path, prefix: &str) {
    for entry in fs::read_dir(vault).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(prefix) && name.ends_with(".bkup") {
            fs::remove_file(entry.path()).unwrap();
        }
    }
}

fn delete_key_file(vault: &std::path::Path, name: &str) {
    fs::remove_file(vault.join(name)).unwrap();
    remove_backups(vault, name);
}

fn recovery_key_of(vault: &std::path::Path) -> zeroize::Zeroizing<String> {
    let opened = open_vault(
        vault,
        &MasterkeyFileAccess::new(Vec::new()),
        common::PASSPHRASE,
    )
    .unwrap();
    create_recovery_key(&WordEncoder::new(), opened.masterkey.raw())
}

#[test]
fn detect_cipher_combo_recognises_both_schemes() {
    for (name, expected) in [
        ("siv_gcm_basic", CipherCombo::SivGcm),
        ("siv_ctrmac_basic", CipherCombo::SivCtrMac),
    ] {
        let (_tmp, opened) = common::open_fixture(name);
        let detected = restore::detect_cipher_combo(&opened.path, &opened.masterkey).unwrap();
        assert_eq!(detected, expected, "{name}");
    }
}

#[test]
fn restoring_the_config_reproduces_an_equivalent_vault_config() {
    let (_tmp, vault) = common::fixture_copy_at("siv_gcm_basic");
    let before = read_vault_config(&vault).unwrap();
    let before_id = before.key_id().unwrap().to_string();
    delete_key_file(&vault, "vault.cryptomator");

    let config = restore::restore_config(
        &MasterkeyFileAccess::new(Vec::new()),
        &vault,
        common::PASSPHRASE,
        restore::ConfigOptions::default(),
        &mut OsRng,
    )
    .unwrap();
    assert_eq!(
        config.cipher_combo,
        CipherCombo::SivGcm,
        "detected, not guessed"
    );
    assert_eq!(config.shortening_threshold, 220);

    // The vault opens and reads again; only the jti is new, the key id is the one from before.
    let opened = open_vault(
        &vault,
        &MasterkeyFileAccess::new(Vec::new()),
        common::PASSPHRASE,
    )
    .unwrap();
    assert_eq!(
        read_vault_config(&vault)
            .unwrap()
            .key_id()
            .unwrap()
            .to_string(),
        before_id
    );
    let fs = cryptomator_core::fs::CryptoFs::open(opened, Default::default());
    assert!(fs
        .metadata(&cryptomator_core::fs::CleartextPath::parse("/hello.txt"))
        .is_ok());
}

#[test]
fn restoring_the_config_keeps_a_backup_of_the_old_one() {
    let (_tmp, vault) = common::fixture_copy_at("siv_ctrmac_basic");
    remove_backups(&vault, "vault.cryptomator");
    let old = fs::read(vault.join("vault.cryptomator")).unwrap();
    let config = restore::restore_config(
        &MasterkeyFileAccess::new(Vec::new()),
        &vault,
        common::PASSPHRASE,
        restore::ConfigOptions::default(),
        &mut OsRng,
    )
    .unwrap();
    assert_eq!(config.cipher_combo, CipherCombo::SivCtrMac);
    let backup = vault.join(cryptomator_core::backup_file_name(
        "vault.cryptomator",
        &old,
    ));
    assert_eq!(
        fs::read(&backup).unwrap(),
        old,
        "the replaced config survives"
    );
    assert_ne!(fs::read(vault.join("vault.cryptomator")).unwrap(), old);
}

#[test]
fn the_shortening_threshold_of_a_restored_config_is_the_one_that_was_asked_for() {
    let (_tmp, vault) = common::fixture_copy_at("siv_gcm_basic");
    delete_key_file(&vault, "vault.cryptomator");
    let config = restore::restore_config(
        &MasterkeyFileAccess::new(Vec::new()),
        &vault,
        common::PASSPHRASE,
        restore::ConfigOptions {
            cipher_combo: Some(CipherCombo::SivGcm),
            shortening_threshold: 100,
        },
        &mut OsRng,
    )
    .unwrap();
    assert_eq!(config.shortening_threshold, 100);
    assert_eq!(
        read_vault_config(&vault)
            .unwrap()
            .alleged_shortening_threshold(),
        Some(100)
    );
}

#[test]
fn restoring_the_masterkey_from_a_recovery_key_sets_a_new_password() {
    let (_tmp, vault) = common::fixture_copy_at("siv_gcm_basic");
    let recovery_key = recovery_key_of(&vault);
    let before = open_vault(
        &vault,
        &MasterkeyFileAccess::new(Vec::new()),
        common::PASSPHRASE,
    )
    .unwrap()
    .masterkey
    .raw()
    .to_owned();
    delete_key_file(&vault, "masterkey.cryptomator");

    restore::restore_masterkey(
        &WordEncoder::new(),
        &MasterkeyFileAccess::new(Vec::new()),
        &vault,
        &recovery_key,
        "brand-new-pass",
        &mut OsRng,
    )
    .unwrap();

    let reopened = open_vault(
        &vault,
        &MasterkeyFileAccess::new(Vec::new()),
        "brand-new-pass",
    )
    .unwrap();
    assert_eq!(reopened.masterkey.raw(), &before);
    assert!(matches!(
        open_vault(
            &vault,
            &MasterkeyFileAccess::new(Vec::new()),
            common::PASSPHRASE
        ),
        Err(CoreError::InvalidPassphrase)
    ));
}

#[test]
fn restoring_everything_rebuilds_both_files() {
    let (_tmp, vault) = common::fixture_copy_at("siv_ctrmac_basic");
    let recovery_key = recovery_key_of(&vault);
    for name in ["masterkey.cryptomator", "vault.cryptomator"] {
        delete_key_file(&vault, name);
    }

    let config = restore::restore_all(
        &WordEncoder::new(),
        &MasterkeyFileAccess::new(Vec::new()),
        &vault,
        &recovery_key,
        "brand-new-pass",
        restore::ConfigOptions::default(),
        &mut OsRng,
    )
    .unwrap();
    assert_eq!(
        config.cipher_combo,
        CipherCombo::SivCtrMac,
        "the combo was detected, not guessed"
    );
    let reopened = open_vault(
        &vault,
        &MasterkeyFileAccess::new(Vec::new()),
        "brand-new-pass",
    )
    .unwrap();
    let fs = cryptomator_core::fs::CryptoFs::open(reopened, Default::default());
    assert!(fs
        .metadata(&cryptomator_core::fs::CleartextPath::parse("/hello.txt"))
        .is_ok());
}

#[test]
fn an_empty_vault_cannot_have_its_combo_detected() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v");
    fs::create_dir_all(vault.join("d")).unwrap();
    let key = cryptomator_core::Masterkey::generate(&mut OsRng);
    assert!(matches!(
        restore::detect_cipher_combo(&vault, &key),
        Err(CoreError::CipherComboUndetectable(_))
    ));
    // restore_all reports that as its own error instead of quietly guessing SIV_GCM.
    let encoder = WordEncoder::new();
    let recovery_key = create_recovery_key(&encoder, key.raw());
    let err = restore::restore_all(
        &encoder,
        &MasterkeyFileAccess::new(Vec::new()),
        &vault,
        &recovery_key,
        "pw",
        restore::ConfigOptions::default(),
        &mut OsRng,
    )
    .unwrap_err();
    assert!(err.to_string().contains("cipher combo"), "{err}");
    assert!(
        !vault.join("vault.cryptomator").exists() && !vault.join("masterkey.cryptomator").exists(),
        "nothing was written"
    );
    // With the combo named, the same call succeeds.
    restore::restore_all(
        &encoder,
        &MasterkeyFileAccess::new(Vec::new()),
        &vault,
        &recovery_key,
        "pw",
        restore::ConfigOptions {
            cipher_combo: Some(CipherCombo::SivGcm),
            shortening_threshold: 220,
        },
        &mut OsRng,
    )
    .unwrap();
    assert!(vault.join("vault.cryptomator").exists());
    assert!(vault.join("masterkey.cryptomator").exists());
}

#[test]
fn a_failed_restore_leaves_the_vault_untouched() {
    let (_tmp, vault) = common::fixture_copy_at("siv_gcm_basic");
    let before = fs::read(vault.join("vault.cryptomator")).unwrap();
    let masterkey_before = fs::read(vault.join("masterkey.cryptomator")).unwrap();
    // A recovery key with a broken checksum never reaches the writing part.
    let err = restore::restore_all(
        &WordEncoder::new(),
        &MasterkeyFileAccess::new(Vec::new()),
        &vault,
        "not even words",
        "pw",
        restore::ConfigOptions::default(),
        &mut OsRng,
    )
    .unwrap_err();
    assert!(matches!(err, CoreError::InvalidRecoveryKey(_)), "{err}");
    assert_eq!(fs::read(vault.join("vault.cryptomator")).unwrap(), before);
    assert_eq!(
        fs::read(vault.join("masterkey.cryptomator")).unwrap(),
        masterkey_before
    );
}

#[test]
fn a_wrong_password_does_not_replace_the_vault_config() {
    let (_tmp, vault) = common::fixture_copy_at("siv_gcm_basic");
    let before = fs::read(vault.join("vault.cryptomator")).unwrap();
    assert!(matches!(
        restore::restore_config(
            &MasterkeyFileAccess::new(Vec::new()),
            &vault,
            "not-the-password",
            restore::ConfigOptions::default(),
            &mut OsRng,
        ),
        Err(CoreError::InvalidPassphrase)
    ));
    assert_eq!(fs::read(vault.join("vault.cryptomator")).unwrap(), before);
}
