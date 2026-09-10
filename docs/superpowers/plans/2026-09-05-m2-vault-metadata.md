# M2: Vault metadata – settings.json, vault management, password and recovery – Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `crypto` can create, register, list, describe and configure vaults, change passwords and show/use recovery keys – schema-compatible with the `settings.json` of the Cryptomator desktop app; vaults created by `crypto` can be opened by the real Java library (cryptofs 2.10.0).

**Architecture:** `cryptomator-core` gains the module `vault/` (state detection with backup restore, readme generator, vault initialization, opening with verification and backups, password change). `cryptomator-app` gains `settings/` (serde model with `flatten` for unknown fields, legacy migration, store with atomic writes, vault reference resolution, ID/name rules), `password.rs` (password sources, NFC, minimum length) and `mounters.rs` (aliases ↔ Java class names). The `crypto` binary gains the commands `vault create/add/remove/list/info/set`, `config get/set`, `password change`, `recovery-key show/reset-password` with `--json` output and fixed exit codes. The Java fixture generator gains a `verify` mode that opens Rust-created vaults with cryptofs.

**Tech Stack:** Rust stable ≥ 1.85; existing crates from M1; new: `rpassword` 7.5, `unicode-normalization` 0.1, `serde`/`serde_json` (preserve_order) in `cryptomator-app`, `data-encoding`, `zeroize`, `thiserror`; tests with `tempfile`, `assert_cmd`, `predicates`. Java 21+/Maven for the interop test.

**Spec:** `docs/superpowers/specs/2026-09-04-crypto-cli-design.md` (sections `cryptomator-app`, `cryptomator-core` → `vault/*`, command grammar, exit codes, milestone M2)

## Global Constraints

- Working directory `/Users/rfoerthe/work/cryptomator-cli`, branch `feature/m2-vault-metadata` (from `main@1071afa`).
- License AGPL-3.0-only; `#![forbid(unsafe_code)]` in core and app; no `unwrap()` on input data in library code (tests may).
- `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo test --workspace --locked` clean before every commit; commit message ends with `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.
- settings.json: paths macOS `~/Library/Application Support/Cryptomator/settings.json`; Linux `~/.config/Cryptomator/settings.json`, then `~/.Cryptomator/settings.json`; override `CRYPTO_SETTINGS_PATH` (several paths separated by `:`) and `--settings PATH`. Saving always goes to the first path, atomically (`settings.json.tmp` → rename). Unknown fields are preserved when writing back. Java defaults: `port` 42427, `useKeychain` true, `keychainProvider` macOS `org.cryptomator.macos.keychain.MacSystemKeychainAccess` / Linux `org.cryptomator.linux.keychain.GnomeKeyringKeychainAccess`, vault: `revealAfterMount` true, `autoLockIdleSeconds` 1800, `actionAfterUnlock` `ASK`, `maxCleartextFilenameLength` -1, `mountFlags` `""`, `port` 42427. Legacy fields `preferredVolumeImpl`, `winDriveLetter`, `useCustomMountPath`/`usesIndividualMountPath`, `customMountPath`/`individualMountPath` are read and migrated, never written.
- Deviation from Java (deliberate): an unparsable settings.json is NOT silently replaced by defaults but leads to an error (exit 1) – the desktop app would overwrite it on the next save.
- Vault ID = base64url of 9 random bytes (12 characters); `mountName` normalization like `VaultSettings.normalizeDisplayName`.
- Create a vault like `CreateNewVaultPasswordController.createVault`: create the directory (must be new), `masterkey.cryptomator` (version 999, N=32768), `vault.cryptomator` (`kid` `masterkeyfile:masterkey.cryptomator`, SIV_GCM, threshold 36..220, default 220), root content dir + `dirid.c9r`, `WELCOME.rtf` inside the vault, `IMPORTANT.rtf` next to it. Readme texts exactly from `strings.properties` (English), RTF escaping like `ReadmeGenerator`.
- Passphrases are NFC-normalized (like `SecurePasswordField`); new passwords at least 8 characters (`CRYPTO_MIN_PW_LENGTH` overrides); order of sources `--password-stdin` (one line) → `--password-file` (≤ 5000 bytes, one trailing newline stripped) → `--password-env VAR` → `CRYPTO_PASSWORD` → TTY prompt (only if stdin is a terminal).
- Exit codes: 0 ok, 1 general, 2 usage, 3 vault not found/ambiguous, 4 password/recovery key invalid, 5 wrong vault state, 9 hub vault, 12 not a vault directory.
- Passwords, recovery keys and masterkeys never appear in error messages or logs; `Zeroizing` for all secret strings.
- Hub vaults (`kid` starts with `hub+`) are shown with type `hub` by `vault info` and rejected by all other operations with exit 9.

---

## File structure

```
crates/cryptomator-core/src/error.rs            + NotAVaultReason, NotAVaultDirectory, ContentRootMissing, NeedsMigration
crates/cryptomator-core/src/vault/mod.rs
crates/cryptomator-core/src/vault/state.rs      DirStructure, VaultState, determine_vault_state, assert_is_vault_directory, restore_if_backup_present
crates/cryptomator-core/src/vault/readme.rs     RTF readmes (port of ReadmeGenerator)
crates/cryptomator-core/src/vault/open.rs       read_vault_config, open_vault, root_content_dir, OpenedVault
crates/cryptomator-core/src/vault/init.rs       initialize, write_root_file, create_vault, CreateVaultOptions
crates/cryptomator-core/src/vault/password.rs   change_password
crates/cryptomator-core/tests/vault_lifecycle.rs create → open → change password → open (integration test)
crates/cryptomator-app/Cargo.toml               + serde, serde_json, data-encoding, zeroize, thiserror, rpassword, unicode-normalization, tempfile(dev)
crates/cryptomator-app/src/lib.rs
crates/cryptomator-app/src/error.rs             AppError
crates/cryptomator-app/src/settings/mod.rs
crates/cryptomator-app/src/settings/model.rs    SettingsJson, VaultSettingsJson, WhenUnlocked, defaults, legacy migration
crates/cryptomator-app/src/settings/ids.rs      generate_id, normalize_display_name
crates/cryptomator-app/src/settings/vault_ref.rs resolve_vault
crates/cryptomator-app/src/settings/store.rs    SettingsStore (paths, load, save, update)
crates/cryptomator-app/src/password.rs          PasswordArgs, read_passphrase, read_new_passphrase
crates/cryptomator-app/src/mounters.rs          alias ↔ Java class name
crates/crypto/src/cli.rs                        grammar (extended)
crates/crypto/src/exit.rs                       exit codes + error mapping
crates/crypto/src/output.rs                     human/json
crates/crypto/src/commands/{mod,vault,config,password,recovery}.rs
crates/crypto/tests/cli.rs                      assert_cmd tests (extended)
crates/crypto/tests/java_interop.rs             #[ignore] test: open a Rust vault with cryptofs
tools/fixture-gen/…/Gen.java                    + verify mode; pom.xml parameterized
.github/workflows/ci.yml                        + job interop-java
README.md, CHANGELOG.md, spec                   updated
```

---

### Task 1: Vault state detection with backup restore (`vault/state.rs`)

**Files:**
- Modify: `crates/cryptomator-core/src/error.rs`, `crates/cryptomator-core/src/lib.rs`
- Create: `crates/cryptomator-core/src/vault/mod.rs`, `crates/cryptomator-core/src/vault/state.rs`

**Interfaces:**
- Consumes: `constants::{DATA_DIR_NAME, VAULTCONFIG_FILENAME, MASTERKEY_FILENAME, BACKUP_SUFFIX, VAULT_VERSION}`, `MasterkeyFileAccess::read_alleged_vault_version`, `UnverifiedVaultConfig::{decode, alleged_vault_version}`.
- Produces: `CoreError::NotAVaultDirectory { path: PathBuf, reason: NotAVaultReason }`, `CoreError::ContentRootMissing(PathBuf)`, `CoreError::NeedsMigration(PathBuf)`; `NotAVaultReason::{MissingDataDir, DataNotADirectory, MissingVaultConfig, VaultConfigAccessDenied, UnsupportedStructure}` with `as_str()` (Java names); `DirStructure::{Vault, MaybeLegacy, Unrelated}`; `check_dir_structure(&Path) -> Result<DirStructure>`; `assert_is_vault_directory(&Path) -> Result<()>`; `restore_if_backup_present(vault_path: &Path, file_prefix: &str) -> Option<PathBuf>`; `VaultState::{Missing, VaultConfigMissing, AllMissing, NeedsMigration, Locked}` with `as_str()` (`MISSING`, `VAULT_CONFIG_MISSING`, `ALL_MISSING`, `NEEDS_MIGRATION`, `LOCKED`); `determine_vault_state(&Path) -> Result<VaultState>`; `determine_vault_version(&Path) -> Result<u32>`; `needs_migration(&Path) -> Result<bool>`.

- [ ] **Step 1: Write failing tests**

```rust
// at the end of crates/cryptomator-core/src/vault/state.rs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::NotAVaultReason;
    use std::fs;

    const MASTERKEY_V7: &str = r#"{"version":7,"scryptSalt":"AAAAAAAAAAA=","scryptCostParam":2,"scryptBlockSize":1,"primaryMasterKey":"AA==","hmacMasterKey":"AA==","versionMac":"AA=="}"#;
    const MASTERKEY_V999: &str = r#"{"version":999,"scryptSalt":"AAAAAAAAAAA=","scryptCostParam":2,"scryptBlockSize":1,"primaryMasterKey":"AA==","hmacMasterKey":"AA==","versionMac":"AA=="}"#;
    const CONFIG_TOKEN: &str = "eyJraWQiOiJtYXN0ZXJrZXlmaWxlOm1hc3RlcmtleS5jcnlwdG9tYXRvciIsImFsZyI6IkhTMjU2IiwidHlwIjoiSldUIn0.eyJqdGkiOiI1YmMwMzg0Yi0xNGFjLTRmZGMtYWVkMC02MmU3YmMwOGZkNWEiLCJmb3JtYXQiOjgsImNpcGhlckNvbWJvIjoiU0lWX0dDTSIsInNob3J0ZW5pbmdUaHJlc2hvbGQiOjIyMH0.0DdfRRefLZici0eI0jDe6lS4sU7H8ZGp9eTqESy29Cg";

    fn fixture(name: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures").join(name)
    }

    #[test]
    fn fixture_vault_is_locked() {
        assert_eq!(check_dir_structure(&fixture("siv_gcm_basic")).unwrap(), DirStructure::Vault);
        assert_eq!(determine_vault_state(&fixture("siv_gcm_basic")).unwrap(), VaultState::Locked);
        assert!(assert_is_vault_directory(&fixture("siv_gcm_basic")).is_ok());
    }

    #[test]
    fn nonexistent_path_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(determine_vault_state(&dir.path().join("nope")).unwrap(), VaultState::Missing);
    }

    #[test]
    fn empty_directory_is_unrelated_and_missing() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(check_dir_structure(dir.path()).unwrap(), DirStructure::Unrelated);
        assert_eq!(determine_vault_state(dir.path()).unwrap(), VaultState::Missing);
        let err = assert_is_vault_directory(dir.path()).unwrap_err();
        assert!(matches!(err, CoreError::NotAVaultDirectory { reason: NotAVaultReason::MissingDataDir, .. }));
    }

    #[test]
    fn file_instead_of_directory_is_not_a_directory_error() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file");
        fs::write(&file, b"x").unwrap();
        let err = check_dir_structure(&file).unwrap_err();
        assert!(matches!(err, CoreError::Io(ref e) if e.kind() == std::io::ErrorKind::NotADirectory));
    }

    #[test]
    fn data_dir_but_no_config_reports_reason() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("d")).unwrap();
        let err = assert_is_vault_directory(dir.path()).unwrap_err();
        assert!(matches!(err, CoreError::NotAVaultDirectory { reason: NotAVaultReason::MissingVaultConfig, .. }));
        fs::remove_dir(dir.path().join("d")).unwrap();
        fs::write(dir.path().join("d"), b"not a dir").unwrap();
        let err = assert_is_vault_directory(dir.path()).unwrap_err();
        assert!(matches!(err, CoreError::NotAVaultDirectory { reason: NotAVaultReason::DataNotADirectory, .. }));
    }

    #[test]
    fn legacy_masterkey_without_config_needs_migration() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("d")).unwrap();
        fs::write(dir.path().join("masterkey.cryptomator"), MASTERKEY_V7).unwrap();
        assert_eq!(check_dir_structure(dir.path()).unwrap(), DirStructure::MaybeLegacy);
        assert_eq!(determine_vault_version(dir.path()).unwrap(), 7);
        assert!(needs_migration(dir.path()).unwrap());
        assert_eq!(determine_vault_state(dir.path()).unwrap(), VaultState::NeedsMigration);
    }

    #[test]
    fn format8_masterkey_without_config_is_vault_config_missing() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("d")).unwrap();
        fs::write(dir.path().join("masterkey.cryptomator"), MASTERKEY_V999).unwrap();
        assert_eq!(determine_vault_state(dir.path()).unwrap(), VaultState::VaultConfigMissing);
    }

    #[test]
    fn data_dir_without_any_key_file_is_all_missing() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("d")).unwrap();
        assert_eq!(determine_vault_state(dir.path()).unwrap(), VaultState::AllMissing);
    }

    #[test]
    fn newest_backup_is_restored_and_vault_becomes_locked() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("d")).unwrap();
        fs::write(dir.path().join("masterkey.cryptomator"), MASTERKEY_V999).unwrap();
        fs::write(dir.path().join("vault.cryptomator.OLDOLD01.bkup"), "old").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        fs::write(dir.path().join("vault.cryptomator.NEWNEW02.bkup"), CONFIG_TOKEN).unwrap();
        let restored = restore_if_backup_present(dir.path(), "vault.cryptomator").unwrap();
        assert!(restored.ends_with("vault.cryptomator.NEWNEW02.bkup"));
        assert_eq!(fs::read_to_string(dir.path().join("vault.cryptomator")).unwrap(), CONFIG_TOKEN);
        fs::remove_file(dir.path().join("vault.cryptomator")).unwrap();
        assert_eq!(determine_vault_state(dir.path()).unwrap(), VaultState::Locked);
        assert!(dir.path().join("vault.cryptomator").exists(), "determine_vault_state restores the config backup");
    }

    #[test]
    fn restore_without_backups_is_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(restore_if_backup_present(dir.path(), "vault.cryptomator").is_none());
        assert!(restore_if_backup_present(&dir.path().join("missing"), "vault.cryptomator").is_none());
    }

    #[test]
    fn state_names_match_java() {
        assert_eq!(VaultState::Locked.as_str(), "LOCKED");
        assert_eq!(VaultState::VaultConfigMissing.as_str(), "VAULT_CONFIG_MISSING");
        assert_eq!(NotAVaultReason::UnsupportedStructure.as_str(), "UNSUPPORTED_STRUCTURE");
    }
}
```

- [ ] **Step 2: Run tests, confirm failure**

Run: `cargo test -p cryptomator-core -- vault::state`
Expected: FAIL (module missing)

- [ ] **Step 3: Implement**

Add to `crates/cryptomator-core/src/error.rs` (before `Io`):

```rust
    #[error("not a vault directory: {path} ({reason})")]
    NotAVaultDirectory { path: std::path::PathBuf, reason: NotAVaultReason },
    #[error("vault content root is missing: {0}")]
    ContentRootMissing(std::path::PathBuf),
    #[error("vault needs migration to format 8: {0}")]
    NeedsMigration(std::path::PathBuf),
```

and after the enum:

```rust
/// Why a directory is not usable as a vault (`common/vaults/NotAVaultDirectoryException.Reason`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotAVaultReason {
    MissingDataDir,
    DataNotADirectory,
    MissingVaultConfig,
    VaultConfigAccessDenied,
    UnsupportedStructure,
}

impl NotAVaultReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            NotAVaultReason::MissingDataDir => "MISSING_DATA_DIR",
            NotAVaultReason::DataNotADirectory => "DATA_NOT_A_DIRECTORY",
            NotAVaultReason::MissingVaultConfig => "MISSING_VAULT_CONFIG",
            NotAVaultReason::VaultConfigAccessDenied => "VAULT_CONFIG_ACCESS_DENIED",
            NotAVaultReason::UnsupportedStructure => "UNSUPPORTED_STRUCTURE",
        }
    }
}

impl std::fmt::Display for NotAVaultReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
```

```rust
// crates/cryptomator-core/src/vault/mod.rs
//! Vault lifecycle: state detection, creation, opening, password change.
pub mod state;
```

```rust
// crates/cryptomator-core/src/vault/state.rs
//! Vault directory structure and state detection, ported from cryptofs `DirStructure.java`,
//! the desktop app's `VaultListManager.java` (`determineVaultState`, `assertIsVaultDirectory`)
//! and `BackupRestorer.java`.
use crate::constants::{BACKUP_SUFFIX, DATA_DIR_NAME, MASTERKEY_FILENAME, VAULTCONFIG_FILENAME, VAULT_VERSION};
use crate::error::{CoreError, NotAVaultReason, Result};
use crate::masterkey_file::MasterkeyFileAccess;
use crate::vault_config::UnverifiedVaultConfig;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirStructure {
    /// `d/` exists and `vault.cryptomator` is readable.
    Vault,
    /// `d/` exists, no readable `vault.cryptomator`, but a readable `masterkey.cryptomator` (format ≤ 7 or config lost).
    MaybeLegacy,
    Unrelated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultState {
    Missing,
    VaultConfigMissing,
    AllMissing,
    NeedsMigration,
    Locked,
}

impl VaultState {
    pub fn as_str(&self) -> &'static str {
        match self {
            VaultState::Missing => "MISSING",
            VaultState::VaultConfigMissing => "VAULT_CONFIG_MISSING",
            VaultState::AllMissing => "ALL_MISSING",
            VaultState::NeedsMigration => "NEEDS_MIGRATION",
            VaultState::Locked => "LOCKED",
        }
    }
}

impl std::fmt::Display for VaultState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

fn is_readable(path: &Path) -> bool {
    std::fs::File::open(path).is_ok()
}

/// `DirStructure.checkDirStructure`: the path must be a directory (else `NotADirectory` I/O error).
pub fn check_dir_structure(path_to_vault: &Path) -> Result<DirStructure> {
    let metadata = std::fs::metadata(path_to_vault)?;
    if !metadata.is_dir() {
        return Err(CoreError::Io(std::io::Error::new(
            std::io::ErrorKind::NotADirectory,
            path_to_vault.display().to_string(),
        )));
    }
    if path_to_vault.join(DATA_DIR_NAME).is_dir() {
        if is_readable(&path_to_vault.join(VAULTCONFIG_FILENAME)) {
            return Ok(DirStructure::Vault);
        }
        if is_readable(&path_to_vault.join(MASTERKEY_FILENAME)) {
            return Ok(DirStructure::MaybeLegacy);
        }
    }
    Ok(DirStructure::Unrelated)
}

/// `VaultListManager.assertIsVaultDirectory`: Ok for `Vault` and `MaybeLegacy`, otherwise the most specific reason.
pub fn assert_is_vault_directory(path_to_vault: &Path) -> Result<()> {
    if check_dir_structure(path_to_vault)? != DirStructure::Unrelated {
        return Ok(());
    }
    let fail = |reason| Err(CoreError::NotAVaultDirectory { path: path_to_vault.to_path_buf(), reason });
    let data_dir = path_to_vault.join(DATA_DIR_NAME);
    if !data_dir.exists() {
        return fail(NotAVaultReason::MissingDataDir);
    }
    if !data_dir.is_dir() {
        return fail(NotAVaultReason::DataNotADirectory);
    }
    match std::fs::File::open(path_to_vault.join(VAULTCONFIG_FILENAME)) {
        Ok(_) => fail(NotAVaultReason::UnsupportedStructure),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => fail(NotAVaultReason::MissingVaultConfig),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => fail(NotAVaultReason::VaultConfigAccessDenied),
        Err(_) => fail(NotAVaultReason::UnsupportedStructure),
    }
}

/// `BackupRestorer.restoreIfBackupPresent`: copies the newest `<prefix>*.bkup` over `<vault>/<prefix>`.
/// Best effort like Java: any I/O problem yields `None`.
pub fn restore_if_backup_present(vault_path: &Path, file_prefix: &str) -> Option<PathBuf> {
    let entries = std::fs::read_dir(vault_path).ok()?;
    let newest = entries
        .flatten()
        .filter(|e| {
            let name = e.file_name();
            let name = name.to_string_lossy();
            name.starts_with(file_prefix) && name.ends_with(BACKUP_SUFFIX)
        })
        .filter_map(|e| e.metadata().ok().and_then(|m| m.modified().ok()).map(|t| (t, e.path())))
        .max_by_key(|(time, _)| *time)
        .map(|(_, path)| path)?;
    std::fs::copy(&newest, vault_path.join(file_prefix)).ok()?;
    Some(newest)
}

/// `Migrators.determineVaultVersion`: the `format` claim if a config exists, else the masterkey file's `version`.
pub fn determine_vault_version(path_to_vault: &Path) -> Result<u32> {
    let config_path = path_to_vault.join(VAULTCONFIG_FILENAME);
    if config_path.exists() {
        let token = std::fs::read_to_string(&config_path)?;
        UnverifiedVaultConfig::decode(token.trim())?
            .alleged_vault_version()
            .ok_or_else(|| CoreError::VaultConfigLoad("vault config has no format claim".into()))
    } else {
        let bytes = std::fs::read(path_to_vault.join(MASTERKEY_FILENAME))?;
        MasterkeyFileAccess::read_alleged_vault_version(&bytes)
    }
}

pub fn needs_migration(path_to_vault: &Path) -> Result<bool> {
    Ok(determine_vault_version(path_to_vault)? < VAULT_VERSION)
}

fn check_structure(path_to_vault: &Path) -> Result<VaultState> {
    Ok(match check_dir_structure(path_to_vault)? {
        DirStructure::Vault => VaultState::Locked,
        DirStructure::Unrelated => VaultState::Missing,
        DirStructure::MaybeLegacy => {
            if needs_migration(path_to_vault)? {
                VaultState::NeedsMigration
            } else {
                VaultState::Missing
            }
        }
    })
}

/// `VaultListManager.determineVaultState`, including the `.bkup` auto-restore of missing key files.
pub fn determine_vault_state(path_to_vault: &Path) -> Result<VaultState> {
    if !path_to_vault.exists() {
        return Ok(VaultState::Missing);
    }
    let structure = check_structure(path_to_vault)?;
    if matches!(structure, VaultState::Locked | VaultState::NeedsMigration) {
        return Ok(structure);
    }
    let config_path = path_to_vault.join(VAULTCONFIG_FILENAME);
    let masterkey_path = path_to_vault.join(MASTERKEY_FILENAME);
    if !config_path.exists() {
        restore_if_backup_present(path_to_vault, VAULTCONFIG_FILENAME);
    }
    if !masterkey_path.exists() {
        restore_if_backup_present(path_to_vault, MASTERKEY_FILENAME);
    }
    let has_config = config_path.exists();
    if !has_config && !masterkey_path.exists() {
        return Ok(VaultState::AllMissing);
    }
    if !has_config {
        return Ok(VaultState::VaultConfigMissing);
    }
    check_structure(path_to_vault)
}
```

In `lib.rs`: `pub mod vault;` and `pub use error::NotAVaultReason;` as well as `pub use vault::state::{assert_is_vault_directory, check_dir_structure, determine_vault_state, determine_vault_version, needs_migration, restore_if_backup_present, DirStructure, VaultState};`.

Note: `data_dir_without_any_key_file_is_all_missing` expects `ALL_MISSING`, even though an empty `d/` without files yields `UNRELATED → MISSING` in Java and the backup check only kicks in afterwards – exactly that order is what `determine_vault_state` implements (structure `Missing`, then restore, then `AllMissing`). Java behaves identically.

- [ ] **Step 4: Run tests**

Run: `cargo test -p cryptomator-core -- vault::state`
Expected: PASS (11 tests)

- [ ] **Step 5: Commit**

```bash
git add crates/cryptomator-core
git commit -m "Add vault directory structure and state detection with backup restore

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 2: RTF readme generator (`vault/readme.rs`)

**Files:**
- Create: `crates/cryptomator-core/src/vault/readme.rs`
- Modify: `crates/cryptomator-core/src/vault/mod.rs`

**Interfaces:**
- Produces: `STORAGE_LOCATION_README_FILE_NAME = "IMPORTANT.rtf"`, `ACCESS_LOCATION_README_FILE_NAME = "WELCOME.rtf"`, `storage_location_readme_rtf() -> String`, `access_location_readme_rtf() -> String`, `create_document(paragraphs: &[String]) -> String`, `escape_non_ascii(&str) -> String` (alle Ausgaben reines ASCII).

- [ ] **Step 1: Write failing tests**

```rust
// at the end of crates/cryptomator-core/src/vault/readme.rs
#[cfg(test)]
mod tests {
    use super::*;

    // ReadmeGenerator.appendEscaped iterates UTF-16 code units: <128 verbatim, <=0xFF as \'XX, <0xFFFF as \u<decimal>, 0xFFFF dropped.
    #[test]
    fn escapes_like_java() {
        assert_eq!(escape_non_ascii("abc"), "abc");
        assert_eq!(escape_non_ascii("é"), "\\'E9");
        assert_eq!(escape_non_ascii("⚠️"), "\\u9888\\u65039");
        assert_eq!(escape_non_ascii("🔐️"), "\\u55357\\u56592\\u65039");
        assert_eq!(escape_non_ascii("•"), "\\u8226");
        assert_eq!(escape_non_ascii("\u{ffff}"), "");
    }

    #[test]
    fn document_has_header_paragraphs_and_footer() {
        let doc = create_document(&["a".to_string(), "".to_string(), "é".to_string()]);
        assert_eq!(doc, "{\\rtf1\\fbidis\\ansi\\uc0\\fs32\n{\\sa80 a}\\par \n{\\sa80 }\\par \n{\\sa80 \\'E9}\\par \n}");
    }

    #[test]
    fn storage_readme_matches_desktop_app() {
        let doc = storage_location_readme_rtf();
        assert!(doc.is_ascii());
        assert!(doc.starts_with("{\\rtf1\\fbidis\\ansi\\uc0\\fs32\n{\\sa80 \\fs40\\qc \\u9888\\u65039  VAULT FILES  \\u9888\\u65039}\\par \n{\\sa80 This is your vault's storage location.}\\par \n{\\sa80 }\\par \n{\\sa80 \\b DO NOT}\\par \n{\\sa80     \\u8226  alter any files within this directory or}\\par \n"));
        assert!(doc.contains("{\\sa80     3.  Open the access location by clicking the \"Reveal\" button.}\\par \n"));
        assert!(doc.ends_with("{\\sa80 If you need help, visit the documentation: {\\field{\\*\\fldinst HYPERLINK \"http://docs.cryptomator.org/\"}{\\fldrslt http://docs.cryptomator.org}}}\\par \n}"));
        assert_eq!(doc.matches("\\par \n").count(), 13);
    }

    #[test]
    fn access_readme_matches_desktop_app() {
        let doc = access_location_readme_rtf();
        assert!(doc.is_ascii());
        assert!(doc.starts_with("{\\rtf1\\fbidis\\ansi\\uc0\\fs32\n{\\sa80 \\fs40\\qc \\u55357\\u56592\\u65039  ENCRYPTED VOLUME  \\u55357\\u56592\\u65039}\\par \n{\\sa80 This is your vault's access location.}\\par \n"));
        assert!(doc.ends_with("{\\sa80 Feel free to remove this file.}\\par \n}"));
        assert_eq!(doc.matches("\\par \n").count(), 6);
        assert_eq!(STORAGE_LOCATION_README_FILE_NAME, "IMPORTANT.rtf");
        assert_eq!(ACCESS_LOCATION_README_FILE_NAME, "WELCOME.rtf");
    }
}
```

- [ ] **Step 2: Run tests, confirm failure**

Run: `cargo test -p cryptomator-core -- vault::readme`
Expected: FAIL (module missing)

- [ ] **Step 3: Implement**

```rust
// crates/cryptomator-core/src/vault/readme.rs
//! RTF readme files written on vault creation (`ui/addvaultwizard/ReadmeGenerator.java`,
//! texts from `i18n/strings.properties` keys `addvault.new.readme.*`).
pub const STORAGE_LOCATION_README_FILE_NAME: &str = "IMPORTANT.rtf";
pub const ACCESS_LOCATION_README_FILE_NAME: &str = "WELCOME.rtf";

const RTF_HEADER: &str = "{\\rtf1\\fbidis\\ansi\\uc0\\fs32\n";
const RTF_FOOTER: &str = "}";
const HELP_URL: &str = "{\\field{\\*\\fldinst HYPERLINK \"http://docs.cryptomator.org/\"}{\\fldrslt http://docs.cryptomator.org}}";

fn heading(text: &str) -> String {
    format!("\\fs40\\qc {text}")
}

fn bold(text: &str) -> String {
    format!("\\b {text}")
}

fn indented(text: &str) -> String {
    format!("    {text}")
}

/// `IMPORTANT.rtf`, written next to the vault (storage location).
pub fn storage_location_readme_rtf() -> String {
    create_document(&[
        heading("⚠️  VAULT FILES  ⚠️"),
        "This is your vault's storage location.".to_string(),
        String::new(),
        bold("DO NOT"),
        indented("•  alter any files within this directory or"),
        indented("•  paste any files for encryption into this directory."),
        String::new(),
        "If you want to encrypt files and view the content of the vault, do the following:".to_string(),
        indented("1.  Add this vault to Cryptomator."),
        indented("2.  Unlock the vault in Cryptomator."),
        indented("3.  Open the access location by clicking the \"Reveal\" button."),
        String::new(),
        format!("If you need help, visit the documentation: {HELP_URL}"),
    ])
}

/// `WELCOME.rtf`, written inside the vault (access location).
pub fn access_location_readme_rtf() -> String {
    create_document(&[
        heading("🔐️  ENCRYPTED VOLUME  🔐️"),
        "This is your vault's access location.".to_string(),
        String::new(),
        "Any files added to this volume will be encrypted by Cryptomator. You can work on it like on any other drive/folder. This is only a decrypted view of its content, your files stay encrypted on your hard drive all the time.".to_string(),
        String::new(),
        "Feel free to remove this file.".to_string(),
    ])
}

pub fn create_document(paragraphs: &[String]) -> String {
    let mut out = String::from(RTF_HEADER);
    for paragraph in paragraphs {
        out.push_str("{\\sa80 ");
        out.push_str(&escape_non_ascii(paragraph));
        out.push_str("}\\par \n");
    }
    out.push_str(RTF_FOOTER);
    out
}

/// Java iterates `String.chars()` (UTF-16 code units); surrogate halves are escaped individually.
pub fn escape_non_ascii(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for unit in input.encode_utf16() {
        match unit {
            u if u < 128 => out.push(u as u8 as char),
            u if u <= 0xFF => out.push_str(&format!("\\'{u:02X}")),
            u if u < 0xFFFF => out.push_str(&format!("\\u{u}")),
            _ => {}
        }
    }
    out
}
```

`vault/mod.rs`: add `pub mod readme;`.

- [ ] **Step 4: Run tests**

Run: `cargo test -p cryptomator-core -- vault::readme`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add crates/cryptomator-core
git commit -m "Add RTF readme generator for new vaults

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 3: Open a vault with verification and backups (`vault/open.rs`)

**Files:**
- Create: `crates/cryptomator-core/src/vault/open.rs`
- Modify: `crates/cryptomator-core/src/vault/mod.rs`, `crates/cryptomator-core/src/lib.rs`

**Interfaces:**
- Consumes: `UnverifiedVaultConfig::{decode, key_id, verify}`, `KeyId::require_masterkey_file`, `MasterkeyFileAccess::load`, `Cryptor::new`, `FileNameCryptor::hash_directory_id`, `attempt_backup`, `constants::{ROOT_DIR_ID, DATA_DIR_NAME, VAULTCONFIG_FILENAME, VAULT_VERSION}`.
- Produces: `OpenedVault { pub path: PathBuf, pub config: VaultConfig, pub masterkey: Masterkey, pub cryptor: Cryptor }` (Debug redigiert); `read_vault_config(vault_path: &Path) -> Result<UnverifiedVaultConfig>`; `root_content_dir(vault_path: &Path, cryptor: &Cryptor) -> PathBuf`; `open_vault(vault_path: &Path, access: &MasterkeyFileAccess, passphrase: &str) -> Result<OpenedVault>`; `open_vault_with_key(vault_path: &Path, masterkey: Masterkey) -> Result<OpenedVault>`.

- [ ] **Step 1: Write failing tests**

```rust
// at the end of crates/cryptomator-core/src/vault/open.rs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::MASTERKEY_FILENAME;
    use std::fs;
    use std::path::PathBuf;

    const PASSPHRASE: &str = "test-password-123";

    /// Copies a committed fixture into a temp dir (opening writes .bkup files; fixtures must stay pristine).
    fn copy_fixture(name: &str) -> tempfile::TempDir {
        let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures").join(name);
        let dir = tempfile::tempdir().unwrap();
        copy_recursively(&src, dir.path());
        dir
    }

    fn copy_recursively(src: &Path, dst: &Path) {
        for entry in fs::read_dir(src).unwrap() {
            let entry = entry.unwrap();
            let target = dst.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                fs::create_dir(&target).unwrap();
                copy_recursively(&entry.path(), &target);
            } else {
                fs::copy(entry.path(), &target).unwrap();
            }
        }
    }

    fn backups(dir: &Path, prefix: &str) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(prefix) && n.ends_with(".bkup"))
            .collect();
        names.sort();
        names
    }

    #[test]
    fn opens_fixture_and_writes_both_backups() {
        for name in ["siv_gcm_basic", "siv_ctrmac_basic"] {
            let dir = copy_fixture(name);
            let access = MasterkeyFileAccess::new(Vec::new());
            let opened = open_vault(dir.path(), &access, PASSPHRASE).unwrap();
            assert_eq!(opened.path, dir.path());
            assert_eq!(opened.config.vault_version, 8);
            assert_eq!(opened.cryptor.cipher_combo(), opened.config.cipher_combo);
            assert!(root_content_dir(dir.path(), &opened.cryptor).is_dir());
            assert_eq!(backups(dir.path(), "vault.cryptomator").len(), 1, "{name}: config backup");
            assert_eq!(backups(dir.path(), MASTERKEY_FILENAME).len(), 1, "{name}: masterkey backup");
            // opening again does not create a second backup of unchanged files
            open_vault(dir.path(), &access, PASSPHRASE).unwrap();
            assert_eq!(backups(dir.path(), "vault.cryptomator").len(), 1);
        }
    }

    #[test]
    fn wrong_passphrase_is_invalid_passphrase_and_writes_no_backup() {
        let dir = copy_fixture("siv_gcm_basic");
        let access = MasterkeyFileAccess::new(Vec::new());
        assert!(matches!(open_vault(dir.path(), &access, "nope"), Err(CoreError::InvalidPassphrase)));
        assert!(backups(dir.path(), "vault.cryptomator").is_empty());
    }

    #[test]
    fn hub_vault_is_rejected_before_asking_for_a_key() {
        let dir = copy_fixture("siv_gcm_basic");
        let token = crate::VaultConfig { id: "x".into(), vault_version: 8, cipher_combo: crate::CipherCombo::SivGcm, shortening_threshold: 220 }
            .to_token("hub+https://hub.example.com/api/vaults/1", &[0u8; 64]);
        fs::write(dir.path().join(VAULTCONFIG_FILENAME), token).unwrap();
        let access = MasterkeyFileAccess::new(Vec::new());
        assert!(matches!(open_vault(dir.path(), &access, PASSPHRASE), Err(CoreError::HubVaultUnsupported(_))));
    }

    #[test]
    fn missing_content_root_is_reported() {
        let dir = copy_fixture("siv_gcm_basic");
        fs::remove_dir_all(dir.path().join("d")).unwrap();
        let access = MasterkeyFileAccess::new(Vec::new());
        assert!(matches!(open_vault(dir.path(), &access, PASSPHRASE), Err(CoreError::ContentRootMissing(_))));
    }

    #[test]
    fn open_with_key_verifies_signature() {
        let dir = copy_fixture("siv_gcm_basic");
        let access = MasterkeyFileAccess::new(Vec::new());
        let key = access.load(&dir.path().join(MASTERKEY_FILENAME), PASSPHRASE).unwrap();
        assert!(open_vault_with_key(dir.path(), key).is_ok());
        assert!(matches!(open_vault_with_key(dir.path(), Masterkey::from_raw([1u8; 64])), Err(CoreError::VaultKeyInvalid)));
    }

    #[test]
    fn read_vault_config_reports_missing_file_as_io() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(read_vault_config(dir.path()), Err(CoreError::Io(_))));
    }
}
```

- [ ] **Step 2: Run tests, confirm failure**

Run: `cargo test -p cryptomator-core -- vault::open`
Expected: FAIL (module missing)

- [ ] **Step 3: Implement**

```rust
// crates/cryptomator-core/src/vault/open.rs
//! Opening a vault: read + verify `vault.cryptomator`, load the masterkey, write the best-effort
//! backups Java writes on every unlock, and check the content root (`CryptoFileSystems.create`,
//! `MasterkeyFileLoadingStrategy.loadKey`).
use crate::backup::attempt_backup;
use crate::constants::{DATA_DIR_NAME, ROOT_DIR_ID, VAULTCONFIG_FILENAME, VAULT_VERSION};
use crate::crypto::cryptor::Cryptor;
use crate::crypto::masterkey::Masterkey;
use crate::error::{CoreError, Result};
use crate::masterkey_file::MasterkeyFileAccess;
use crate::vault_config::{UnverifiedVaultConfig, VaultConfig};
use std::path::{Path, PathBuf};

pub struct OpenedVault {
    pub path: PathBuf,
    pub config: VaultConfig,
    pub masterkey: Masterkey,
    pub cryptor: Cryptor,
}

impl std::fmt::Debug for OpenedVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenedVault").field("path", &self.path).field("config", &self.config).finish_non_exhaustive()
    }
}

pub fn read_vault_config(vault_path: &Path) -> Result<UnverifiedVaultConfig> {
    let token = std::fs::read_to_string(vault_path.join(VAULTCONFIG_FILENAME))?;
    UnverifiedVaultConfig::decode(token.trim())
}

/// `<vault>/d/<hash[..2]>/<hash[2..]>` for the root directory id `""`.
pub fn root_content_dir(vault_path: &Path, cryptor: &Cryptor) -> PathBuf {
    let hash = cryptor.file_name_cryptor().hash_directory_id(ROOT_DIR_ID);
    vault_path.join(DATA_DIR_NAME).join(&hash[..2]).join(&hash[2..])
}

/// Password-based unlock. Rejects Hub vaults before touching any key material.
pub fn open_vault(vault_path: &Path, access: &MasterkeyFileAccess, passphrase: &str) -> Result<OpenedVault> {
    let unverified = read_vault_config(vault_path)?;
    let masterkey_file_name = unverified.key_id()?.require_masterkey_file()?.to_string();
    let masterkey_path = vault_path.join(&masterkey_file_name);
    let masterkey = access.load(&masterkey_path, passphrase)?;
    // Java backs the masterkey file up after every successful load (best effort, read-only vaults tolerated).
    let _ = attempt_backup(&masterkey_path);
    open_with_key(vault_path, unverified, masterkey)
}

/// Unlock with an already known masterkey (recovery key flows, tests).
pub fn open_vault_with_key(vault_path: &Path, masterkey: Masterkey) -> Result<OpenedVault> {
    let unverified = read_vault_config(vault_path)?;
    open_with_key(vault_path, unverified, masterkey)
}

fn open_with_key(vault_path: &Path, unverified: UnverifiedVaultConfig, masterkey: Masterkey) -> Result<OpenedVault> {
    let config = unverified.verify(masterkey.raw(), VAULT_VERSION)?;
    let _ = attempt_backup(&vault_path.join(VAULTCONFIG_FILENAME));
    let cryptor = Cryptor::new(config.cipher_combo, &masterkey);
    let root = root_content_dir(vault_path, &cryptor);
    if !root.exists() {
        return Err(CoreError::ContentRootMissing(root));
    }
    Ok(OpenedVault { path: vault_path.to_path_buf(), config, masterkey, cryptor })
}
```

`vault/mod.rs`: `pub mod open;`. `lib.rs`: `pub use vault::open::{open_vault, open_vault_with_key, read_vault_config, root_content_dir, OpenedVault};`.

- [ ] **Step 4: Run tests**

Run: `cargo test -p cryptomator-core -- vault::open`
Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add crates/cryptomator-core
git commit -m "Add vault opening with config verification, backups and root check

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 4: Create a vault (`vault/init.rs`)

**Files:**
- Create: `crates/cryptomator-core/src/vault/init.rs`
- Modify: `crates/cryptomator-core/src/vault/mod.rs`, `crates/cryptomator-core/src/lib.rs`

**Interfaces:**
- Consumes: `VaultConfig::{create_new, to_token}`, `Cryptor`, `encrypt_all`, `decrypt_all`, `root_content_dir`, `open_vault`, `MasterkeyFileAccess::persist`, `Masterkey::generate`, `readme::*`, `constants::{DEFAULT_KEY_ID, DIR_ID_BACKUP_FILE_NAME, CRYPTOMATOR_FILE_SUFFIX, MASTERKEY_FILENAME, VAULTCONFIG_FILENAME, ROOT_DIR_ID}`, `masterkey_file::DEFAULT_MASTERKEY_FILE_VERSION`.
- Produces: `MIN_SHORTENING_THRESHOLD = 36`, `MAX_SHORTENING_THRESHOLD = 220`, `DEFAULT_SHORTENING_THRESHOLD = 220`; `CreateVaultOptions { cipher_combo: CipherCombo, shortening_threshold: u32, write_readme_files: bool }` (Default: SivGcm/220/true); `initialize(vault_path: &Path, masterkey: &Masterkey, cipher_combo: CipherCombo, shortening_threshold: u32, key_id: &str, rng: &mut dyn Rng) -> Result<VaultConfig>`; `write_root_file(vault_path: &Path, cryptor: &Cryptor, cleartext_name: &str, content: &[u8], shortening_threshold: u32, rng: &mut dyn Rng) -> Result<PathBuf>`; `create_vault(vault_path: &Path, passphrase: &str, options: &CreateVaultOptions, access: &MasterkeyFileAccess, rng: &mut dyn Rng) -> Result<Masterkey>`.

- [ ] **Step 1: Write failing tests**

```rust
// at the end of crates/cryptomator-core/src/vault/init.rs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rng::OsRng;
    use crate::crypto::stream::decrypt_all;
    use crate::vault::open::open_vault;
    use crate::vault::readme::{access_location_readme_rtf, storage_location_readme_rtf, ACCESS_LOCATION_README_FILE_NAME, STORAGE_LOCATION_README_FILE_NAME};
    use std::fs;

    const PASSPHRASE: &str = "correct horse battery";

    #[test]
    fn creates_a_vault_that_opens_and_contains_the_readme() {
        for combo in [CipherCombo::SivGcm, CipherCombo::SivCtrMac] {
            let dir = tempfile::tempdir().unwrap();
            let vault = dir.path().join("vault");
            let access = MasterkeyFileAccess::new(Vec::new());
            let options = CreateVaultOptions { cipher_combo: combo, shortening_threshold: 100, write_readme_files: true };
            let masterkey = create_vault(&vault, PASSPHRASE, &options, &access, &mut OsRng).unwrap();

            let opened = open_vault(&vault, &access, PASSPHRASE).unwrap();
            assert_eq!(opened.masterkey.raw(), masterkey.raw());
            assert_eq!(opened.config.cipher_combo, combo);
            assert_eq!(opened.config.shortening_threshold, 100);

            let root = root_content_dir(&vault, &opened.cryptor);
            let dirid = decrypt_all(&opened.cryptor, &fs::read(root.join(DIR_ID_BACKUP_FILE_NAME)).unwrap()).unwrap();
            assert_eq!(dirid, b"");

            let mut entries: Vec<String> = fs::read_dir(&root).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
            entries.sort();
            assert_eq!(entries.len(), 2, "{combo}: dirid.c9r + WELCOME.rtf, got {entries:?}");
            let readme_entry = entries.iter().find(|n| *n != DIR_ID_BACKUP_FILE_NAME).unwrap();
            let base64 = readme_entry.strip_suffix(CRYPTOMATOR_FILE_SUFFIX).unwrap();
            assert_eq!(opened.cryptor.file_name_cryptor().decrypt_filename(base64, &[ROOT_DIR_ID.as_bytes()]).unwrap(), ACCESS_LOCATION_README_FILE_NAME);
            let content = decrypt_all(&opened.cryptor, &fs::read(root.join(readme_entry)).unwrap()).unwrap();
            assert_eq!(String::from_utf8(content.to_vec()).unwrap(), access_location_readme_rtf());

            assert_eq!(fs::read_to_string(vault.join(STORAGE_LOCATION_README_FILE_NAME)).unwrap(), storage_location_readme_rtf());
            assert!(vault.join(MASTERKEY_FILENAME).is_file());
            assert!(vault.join(VAULTCONFIG_FILENAME).is_file());
        }
    }

    #[test]
    fn without_readmes_the_root_only_holds_the_dirid_backup() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault");
        let options = CreateVaultOptions { write_readme_files: false, ..CreateVaultOptions::default() };
        create_vault(&vault, PASSPHRASE, &options, &MasterkeyFileAccess::new(Vec::new()), &mut OsRng).unwrap();
        let opened = open_vault(&vault, &MasterkeyFileAccess::new(Vec::new()), PASSPHRASE).unwrap();
        let root = root_content_dir(&vault, &opened.cryptor);
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        assert!(!vault.join(STORAGE_LOCATION_README_FILE_NAME).exists());
    }

    #[test]
    fn existing_directory_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let err = create_vault(dir.path(), PASSPHRASE, &CreateVaultOptions::default(), &MasterkeyFileAccess::new(Vec::new()), &mut OsRng).unwrap_err();
        assert!(matches!(err, CoreError::Io(ref e) if e.kind() == std::io::ErrorKind::AlreadyExists));
    }

    #[test]
    fn threshold_out_of_range_is_rejected_before_writing() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault");
        for threshold in [35, 221] {
            let options = CreateVaultOptions { shortening_threshold: threshold, ..CreateVaultOptions::default() };
            let err = create_vault(&vault, PASSPHRASE, &options, &MasterkeyFileAccess::new(Vec::new()), &mut OsRng).unwrap_err();
            assert!(matches!(err, CoreError::InvalidArgument(_)), "{threshold}");
            assert!(!vault.exists(), "{threshold}: nothing may be created");
        }
    }

    #[test]
    fn write_root_file_rejects_names_longer_than_the_threshold() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault");
        let options = CreateVaultOptions { shortening_threshold: 36, write_readme_files: false, ..CreateVaultOptions::default() };
        let masterkey = create_vault(&vault, PASSPHRASE, &options, &MasterkeyFileAccess::new(Vec::new()), &mut OsRng).unwrap();
        let cryptor = Cryptor::new(CipherCombo::SivGcm, &masterkey);
        let err = write_root_file(&vault, &cryptor, "a-name-that-is-long-enough.txt", b"x", 36, &mut OsRng).unwrap_err();
        assert!(matches!(err, CoreError::InvalidArgument(_)));
    }
}
```

- [ ] **Step 2: Run tests, confirm failure**

Run: `cargo test -p cryptomator-core -- vault::init`
Expected: FAIL (module missing)

- [ ] **Step 3: Implement**

```rust
// crates/cryptomator-core/src/vault/init.rs
//! Vault creation: `CryptoFileSystemProvider.initialize` + the desktop app's
//! `CreateNewVaultPasswordController.createVault` (masterkey file, config, root dir, readme files).
use crate::constants::{CRYPTOMATOR_FILE_SUFFIX, DEFAULT_KEY_ID, DIR_ID_BACKUP_FILE_NAME, MASTERKEY_FILENAME, ROOT_DIR_ID, VAULTCONFIG_FILENAME};
use crate::crypto::cryptor::{CipherCombo, Cryptor};
use crate::crypto::masterkey::Masterkey;
use crate::crypto::rng::Rng;
use crate::crypto::stream::encrypt_all;
use crate::error::{CoreError, Result};
use crate::masterkey_file::{MasterkeyFileAccess, DEFAULT_MASTERKEY_FILE_VERSION};
use crate::vault::open::root_content_dir;
use crate::vault::readme::{access_location_readme_rtf, storage_location_readme_rtf, ACCESS_LOCATION_README_FILE_NAME, STORAGE_LOCATION_README_FILE_NAME};
use crate::vault_config::VaultConfig;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const MIN_SHORTENING_THRESHOLD: u32 = 36;
pub const MAX_SHORTENING_THRESHOLD: u32 = 220;
pub const DEFAULT_SHORTENING_THRESHOLD: u32 = 220;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateVaultOptions {
    pub cipher_combo: CipherCombo,
    pub shortening_threshold: u32,
    pub write_readme_files: bool,
}

impl Default for CreateVaultOptions {
    fn default() -> Self {
        Self { cipher_combo: CipherCombo::SivGcm, shortening_threshold: DEFAULT_SHORTENING_THRESHOLD, write_readme_files: true }
    }
}

fn validate_threshold(shortening_threshold: u32) -> Result<()> {
    if !(MIN_SHORTENING_THRESHOLD..=MAX_SHORTENING_THRESHOLD).contains(&shortening_threshold) {
        return Err(CoreError::InvalidArgument(format!(
            "shortening threshold must be between {MIN_SHORTENING_THRESHOLD} and {MAX_SHORTENING_THRESHOLD}, got {shortening_threshold}"
        )));
    }
    Ok(())
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// `CryptoFileSystemProvider.initialize`: writes `vault.cryptomator`, creates the root content dir and its `dirid.c9r`.
pub fn initialize(vault_path: &Path, masterkey: &Masterkey, cipher_combo: CipherCombo, shortening_threshold: u32, key_id: &str, rng: &mut dyn Rng) -> Result<VaultConfig> {
    if !vault_path.is_dir() {
        return Err(CoreError::Io(std::io::Error::new(std::io::ErrorKind::NotADirectory, vault_path.display().to_string())));
    }
    validate_threshold(shortening_threshold)?;
    let config = VaultConfig::create_new(cipher_combo, shortening_threshold);
    let token = config.to_token(key_id, masterkey.raw());
    write_new_file(&vault_path.join(VAULTCONFIG_FILENAME), token.as_bytes())?;
    let cryptor = Cryptor::new(cipher_combo, masterkey);
    let root = root_content_dir(vault_path, &cryptor);
    std::fs::create_dir_all(&root)?;
    let dir_id_backup = encrypt_all(&cryptor, rng, ROOT_DIR_ID.as_bytes())?;
    write_new_file(&root.join(DIR_ID_BACKUP_FILE_NAME), &dir_id_backup)?;
    Ok(config)
}

/// Writes one regular file into the vault's root directory (no `.c9s` shortening support; M3 adds the full fs layer).
pub fn write_root_file(vault_path: &Path, cryptor: &Cryptor, cleartext_name: &str, content: &[u8], shortening_threshold: u32, rng: &mut dyn Rng) -> Result<PathBuf> {
    let ciphertext_name = format!("{}{CRYPTOMATOR_FILE_SUFFIX}", cryptor.file_name_cryptor().encrypt_filename(cleartext_name, &[ROOT_DIR_ID.as_bytes()]));
    if ciphertext_name.len() > shortening_threshold as usize {
        return Err(CoreError::InvalidArgument(format!("ciphertext name of {cleartext_name:?} exceeds the shortening threshold {shortening_threshold}")));
    }
    let path = root_content_dir(vault_path, cryptor).join(ciphertext_name);
    let ciphertext = encrypt_all(cryptor, rng, content)?;
    write_new_file(&path, &ciphertext)?;
    Ok(path)
}

/// `CreateNewVaultPasswordController.createVault`: directory (must not exist) → masterkey file → config + root → readmes.
pub fn create_vault(vault_path: &Path, passphrase: &str, options: &CreateVaultOptions, access: &MasterkeyFileAccess, rng: &mut dyn Rng) -> Result<Masterkey> {
    validate_threshold(options.shortening_threshold)?;
    std::fs::create_dir(vault_path)?;
    let masterkey = Masterkey::generate(rng);
    access.persist(&masterkey, &vault_path.join(MASTERKEY_FILENAME), passphrase, DEFAULT_MASTERKEY_FILE_VERSION, rng)?;
    let config = initialize(vault_path, &masterkey, options.cipher_combo, options.shortening_threshold, DEFAULT_KEY_ID, rng)?;
    if options.write_readme_files {
        let cryptor = Cryptor::new(options.cipher_combo, &masterkey);
        write_root_file(vault_path, &cryptor, ACCESS_LOCATION_README_FILE_NAME, access_location_readme_rtf().as_bytes(), config.shortening_threshold, rng)?;
        write_new_file(&vault_path.join(STORAGE_LOCATION_README_FILE_NAME), storage_location_readme_rtf().as_bytes())?;
    }
    Ok(masterkey)
}
```

`vault/mod.rs`: `pub mod init;`. `lib.rs`: `pub use vault::init::{create_vault, initialize, write_root_file, CreateVaultOptions, DEFAULT_SHORTENING_THRESHOLD, MAX_SHORTENING_THRESHOLD, MIN_SHORTENING_THRESHOLD};` and `pub use vault::readme::{access_location_readme_rtf, storage_location_readme_rtf, ACCESS_LOCATION_README_FILE_NAME, STORAGE_LOCATION_README_FILE_NAME};`.

- [ ] **Step 4: Run tests**

Run: `cargo test -p cryptomator-core -- vault::init`
Expected: PASS (5 tests; the scrypt calls with N=32768 cost ~0.2 s each)

- [ ] **Step 5: Commit**

```bash
git add crates/cryptomator-core
git commit -m "Add vault creation with config, root directory and readme files

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 5: Change password (`vault/password.rs`) and lifecycle integration test

**Files:**
- Create: `crates/cryptomator-core/src/vault/password.rs`, `crates/cryptomator-core/tests/vault_lifecycle.rs`
- Modify: `crates/cryptomator-core/src/vault/mod.rs`, `crates/cryptomator-core/src/lib.rs`

**Interfaces:**
- Consumes: `MasterkeyFileAccess::change_passphrase`, `attempt_backup`, `BackupOutcome`, `read_vault_config`, `KeyId::require_masterkey_file`.
- Produces: `change_password(vault_path: &Path, access: &MasterkeyFileAccess, old_passphrase: &str, new_passphrase: &str, rng: &mut dyn Rng) -> Result<PathBuf>` (returns the path of the backup file; hub vaults → `HubVaultUnsupported`; wrong old password → `InvalidPassphrase`, nothing written).

- [ ] **Step 1: Write failing tests**

```rust
// crates/cryptomator-core/tests/vault_lifecycle.rs
//! create → open → change password → open again, exercising the public API only.
use cryptomator_core::{change_password, create_vault, open_vault, CoreError, CreateVaultOptions, MasterkeyFileAccess, OsRng};
use std::fs;

const OLD: &str = "old-passphrase-1";
const NEW: &str = "new-passphrase-2";

#[test]
fn full_password_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v");
    let access = MasterkeyFileAccess::new(Vec::new());
    let created = create_vault(&vault, OLD, &CreateVaultOptions::default(), &access, &mut OsRng).unwrap();
    let old_file = fs::read(vault.join("masterkey.cryptomator")).unwrap();

    let backup = change_password(&vault, &access, OLD, NEW, &mut OsRng).unwrap();
    assert!(backup.file_name().unwrap().to_string_lossy().starts_with("masterkey.cryptomator."));
    assert!(backup.to_string_lossy().ends_with(".bkup"));
    assert_eq!(fs::read(&backup).unwrap(), old_file, "backup holds the previous masterkey file");
    assert_ne!(fs::read(vault.join("masterkey.cryptomator")).unwrap(), old_file);
    assert!(!vault.join("masterkey.cryptomator.tmp").exists());

    let opened = open_vault(&vault, &access, NEW).unwrap();
    assert_eq!(opened.masterkey.raw(), created.raw(), "the masterkey itself is unchanged");
    assert!(matches!(open_vault(&vault, &access, OLD), Err(CoreError::InvalidPassphrase)));
}

#[test]
fn wrong_old_password_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v");
    let access = MasterkeyFileAccess::new(Vec::new());
    create_vault(&vault, OLD, &CreateVaultOptions::default(), &access, &mut OsRng).unwrap();
    let before = fs::read(vault.join("masterkey.cryptomator")).unwrap();
    assert!(matches!(change_password(&vault, &access, "wrong", NEW, &mut OsRng), Err(CoreError::InvalidPassphrase)));
    assert_eq!(fs::read(vault.join("masterkey.cryptomator")).unwrap(), before);
    assert_eq!(fs::read_dir(&vault).unwrap().filter(|e| e.as_ref().unwrap().file_name().to_string_lossy().ends_with(".bkup")).count(), 0);
}
```

- [ ] **Step 2: Run test, confirm failure**

Run: `cargo test -p cryptomator-core --test vault_lifecycle`
Expected: FAIL (`change_password` missing)

- [ ] **Step 3: Implement**

```rust
// crates/cryptomator-core/src/vault/password.rs
//! Password change (`ui/changepassword/ChangePasswordController.finish`). Unlike Java, which moves the
//! old file away before writing the new one, this keeps the original until the replacement is renamed
//! into place: backup copy → new file as `.tmp` → atomic rename.
use crate::backup::attempt_backup;
use crate::crypto::rng::Rng;
use crate::error::Result;
use crate::masterkey_file::MasterkeyFileAccess;
use crate::vault::open::read_vault_config;
use std::io::Write;
use std::path::{Path, PathBuf};

pub fn change_password(vault_path: &Path, access: &MasterkeyFileAccess, old_passphrase: &str, new_passphrase: &str, rng: &mut dyn Rng) -> Result<PathBuf> {
    let file_name = read_vault_config(vault_path)?.key_id()?.require_masterkey_file()?.to_string();
    let masterkey_path = vault_path.join(&file_name);
    let old_bytes = std::fs::read(&masterkey_path)?;
    let new_bytes = access.change_passphrase(&old_bytes, old_passphrase, new_passphrase, rng)?;
    let backup = attempt_backup(&masterkey_path)?;
    let tmp_path = vault_path.join(format!("{file_name}.tmp"));
    {
        let mut tmp = std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp_path)?;
        tmp.write_all(&new_bytes)?;
        tmp.sync_all()?;
    }
    std::fs::rename(&tmp_path, &masterkey_path)?;
    Ok(backup.path)
}
```

`vault/mod.rs`: `pub mod password;`. `lib.rs`: `pub use vault::password::change_password;`.

- [ ] **Step 4: Run tests**

Run: `cargo test -p cryptomator-core --test vault_lifecycle`
Expected: PASS (2 tests)

- [ ] **Step 5: Full run and commit**

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked`
Expected: PASS

```bash
git add crates/cryptomator-core
git commit -m "Add vault password change and lifecycle integration test

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 6: settings.json model (`cryptomator-app`: `error.rs`, `settings/model.rs`)

**Files:**
- Modify: `crates/cryptomator-app/Cargo.toml`, `crates/cryptomator-app/src/lib.rs`, `Cargo.toml` (Workspace-Dependencies `rpassword`, `unicode-normalization`)
- Create: `crates/cryptomator-app/src/error.rs`, `crates/cryptomator-app/src/settings/mod.rs`, `crates/cryptomator-app/src/settings/model.rs`

**Interfaces:**
- Consumes: `cryptomator_core::CoreError`.
- Produces: `AppError` (variants see code); `WhenUnlocked::{Ignore, Reveal, Ask}` (`as_str`, `parse`, serde `IGNORE|REVEAL|ASK`, unknown → `Ask`); `VaultSettingsJson` (fields as in Java, `extra: serde_json::Map`), `VaultSettingsJson::new(id: String, path: &Path) -> Self`, `migrate_legacy(&mut self)`; `SettingsJson` (fields `directories`, `written_by_version`, `use_keychain`, `keychain_provider`, `mount_service`, `port`, `debug_mode`, `extra`), `SettingsJson::parse(&[u8]) -> Result<Self, serde_json::Error>` (incl. migration), `to_json_pretty(&self) -> String`, `migrate_legacy(&mut self)`, `Default`; constants `DEFAULT_PORT = 42427`, `DEFAULT_AUTOLOCK_IDLE_SECONDS = 1800`, `DEFAULT_MAX_CLEARTEXT_FILENAME_LENGTH = -1`, `default_keychain_provider() -> String`.

- [ ] **Step 1: Add dependencies**

Add to the workspace `Cargo.toml` under `[workspace.dependencies]`:

```toml
rpassword = "7.5"
unicode-normalization = "0.1"
```

Replace `crates/cryptomator-app/Cargo.toml` with:

```toml
[package]
name = "cryptomator-app"
description = "Settings, keychain, daemon and vault registry for the crypto CLI"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true

[dependencies]
cryptomator-core = { path = "../cryptomator-core" }
clap.workspace = true
data-encoding.workspace = true
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
zeroize.workspace = true
rpassword.workspace = true
unicode-normalization.workspace = true

[target.'cfg(target_os = "macos")'.dependencies]
security-framework = "3.7"

[dev-dependencies]
tempfile.workspace = true
```

- [ ] **Step 2: Write failing tests**

```rust
// at the end of crates/cryptomator-app/src/settings/model.rs
#[cfg(test)]
mod tests {
    use super::*;

    // SettingsJsonTest.testDeserialize from the desktop app
    const JAVA_TEST_JSON: &str = r#"{
        "directories": [
            {"id": "1", "path": "/vault1", "mountName": "vault1", "winDriveLetter": "X", "shouldBeIgnored": true},
            {"id": "2", "path": "/vault2", "mountName": "vault2", "winDriveLetter": "Y", "mountFlags":"--foo --bar"}
        ],
        "autoCloseVaults" : true,
        "checkForUpdatesEnabled": true,
        "port": 8080,
        "language": "de-DE",
        "numTrayNotifications": 42,
        "trustedHosts": null
    }"#;

    // Shape of a settings.json written by Cryptomator 1.19.3 (values redacted)
    const DESKTOP_JSON: &str = r#"{
  "directories" : [ {
    "id" : "OefwgtaX5vsy",
    "path" : "/Users/me/Vaults/Test",
    "displayName" : "Test",
    "unlockAfterStartup" : false,
    "revealAfterMount" : true,
    "usesReadOnlyMode" : false,
    "mountFlags" : "",
    "maxCleartextFilenameLength" : 2147483647,
    "actionAfterUnlock" : "REVEAL",
    "autoLockWhenIdle" : false,
    "autoLockIdleSeconds" : 1800,
    "lastKnownKeyLoader" : "masterkeyfile",
    "port" : 42427
  } ],
  "writtenByVersion" : "1.19.3-dmg-6495",
  "autoCloseVaults" : false,
  "debugMode" : false,
  "theme" : "LIGHT",
  "keychainProvider" : "org.cryptomator.macos.keychain.MacSystemKeychainAccess",
  "numTrayNotifications" : 3,
  "port" : 42427,
  "showTrayIcon" : true,
  "compactMode" : false,
  "startHidden" : false,
  "uiOrientation" : "LEFT_TO_RIGHT",
  "useKeychain" : true,
  "windowHeight" : 702,
  "windowWidth" : 1061,
  "windowXPosition" : 202,
  "windowYPosition" : 62,
  "checkForUpdatesEnabled" : true,
  "lastReminderForUpdateCheck" : "2026-09-04T19:34:53Z",
  "lastSuccessfulUpdateCheck" : "2026-09-04T20:10:12Z",
  "useQuickAccess" : true,
  "previouslyUsedVaultDirectory" : "file:///Users/me/pCloud%20Drive/",
  "trustedHosts" : [ ]
}"#;

    #[test]
    fn deserializes_like_java_test() {
        let s = SettingsJson::parse(JAVA_TEST_JSON.as_bytes()).unwrap();
        assert_eq!(s.directories.len(), 2);
        assert_eq!(s.directories[0].path.as_deref(), Some("/vault1"));
        assert_eq!(s.directories[1].path.as_deref(), Some("/vault2"));
        assert_eq!(s.directories[1].mount_flags, "--foo --bar");
        assert_eq!(s.port, 8080);
        assert_eq!(s.extra.get("autoCloseVaults"), Some(&serde_json::Value::Bool(true)));
        assert_eq!(s.extra.get("language"), Some(&serde_json::Value::String("de-DE".into())));
        assert_eq!(s.extra.get("numTrayNotifications"), Some(&serde_json::json!(42)));
        assert_eq!(s.extra.get("trustedHosts"), Some(&serde_json::Value::Null));
        assert_eq!(s.directories[0].extra.get("shouldBeIgnored"), Some(&serde_json::Value::Bool(true)));
        // legacy winDriveLetter migrates to a mount point and is never written back
        assert_eq!(s.directories[0].mount_point.as_deref(), Some("X:\\"));
        let out = s.to_json_pretty();
        assert!(!out.contains("winDriveLetter"));
        assert!(out.contains("\"shouldBeIgnored\": true"), "unknown vault keys survive: {out}");
        assert!(out.contains("\"language\": \"de-DE\""));
    }

    #[test]
    fn malformed_input_is_an_error() {
        for input in ["", "<html>", "{invalidjson}", "[]"] {
            assert!(SettingsJson::parse(input.as_bytes()).is_err(), "{input:?}");
        }
    }

    #[test]
    fn null_directories_become_empty() {
        let s = SettingsJson::parse(br#"{"directories": null}"#).unwrap();
        assert!(s.directories.is_empty());
    }

    #[test]
    fn defaults_match_java() {
        let s = SettingsJson::default();
        assert_eq!(s.port, DEFAULT_PORT);
        assert!(s.use_keychain);
        assert_eq!(s.keychain_provider, default_keychain_provider());
        assert!(s.mount_service.is_none());
        let v = VaultSettingsJson::new("abc".into(), std::path::Path::new("/tmp/v"));
        assert_eq!(v.path.as_deref(), Some("/tmp/v"));
        assert_eq!(v.display_name.as_deref(), Some("v"));
        assert!(v.reveal_after_mount);
        assert!(!v.unlock_after_startup);
        assert_eq!(v.auto_lock_idle_seconds, DEFAULT_AUTOLOCK_IDLE_SECONDS);
        assert_eq!(v.max_cleartext_filename_length, DEFAULT_MAX_CLEARTEXT_FILENAME_LENGTH);
        assert_eq!(v.action_after_unlock, WhenUnlocked::Ask);
        assert_eq!(v.port, DEFAULT_PORT);
        assert_eq!(v.mount_flags, "");
        let out = SettingsJson { directories: vec![v], ..SettingsJson::default() }.to_json_pretty();
        for needle in ["\"useKeychain\": true", "\"actionAfterUnlock\": \"ASK\"", "\"revealAfterMount\": true", "\"port\": 42427", "\"maxCleartextFilenameLength\": -1"] {
            assert!(out.contains(needle), "{needle} missing in {out}");
        }
        assert!(!out.contains("\"mountPoint\""), "None fields are omitted like Jackson NON_NULL");
    }

    #[test]
    fn desktop_file_round_trips_and_keeps_unknown_fields() {
        let s = SettingsJson::parse(DESKTOP_JSON.as_bytes()).unwrap();
        assert_eq!(s.written_by_version.as_deref(), Some("1.19.3-dmg-6495"));
        assert_eq!(s.directories[0].max_cleartext_filename_length, 2147483647);
        assert_eq!(s.directories[0].action_after_unlock, WhenUnlocked::Reveal);
        let out = s.to_json_pretty();
        let again = SettingsJson::parse(out.as_bytes()).unwrap();
        assert_eq!(again, s);
        for needle in ["\"theme\": \"LIGHT\"", "\"windowHeight\": 702", "\"previouslyUsedVaultDirectory\": \"file:///Users/me/pCloud%20Drive/\"", "\"trustedHosts\": []", "\"lastKnownKeyLoader\": \"masterkeyfile\""] {
            assert!(out.contains(needle), "{needle} missing in {out}");
        }
    }

    #[test]
    fn preferred_volume_impl_migrates_to_mount_service() {
        let s = SettingsJson::parse(br#"{"preferredVolumeImpl": "FUSE"}"#).unwrap();
        let expected = if cfg!(target_os = "macos") { "org.cryptomator.frontend.fuse.mount.MacFuseMountProvider" } else { "org.cryptomator.frontend.fuse.mount.LinuxFuseMountProvider" };
        assert_eq!(s.mount_service.as_deref(), Some(expected));
        assert!(!s.to_json_pretty().contains("preferredVolumeImpl"));
        let s = SettingsJson::parse(br#"{"preferredVolumeImpl": "WEBDAV", "mountService": "keep.Me"}"#).unwrap();
        assert_eq!(s.mount_service.as_deref(), Some("keep.Me"), "explicit mountService wins");
        let s = SettingsJson::parse(br#"{"preferredVolumeImpl": "Dokany"}"#).unwrap();
        assert_eq!(s.mount_service.as_deref(), Some("org.cryptomator.frontend.dokany.mount.DokanyMountProvider"));
    }

    #[test]
    fn legacy_custom_mount_path_and_aliases_migrate() {
        let s = SettingsJson::parse(br#"{"directories":[{"id":"a","useCustomMountPath":true,"customMountPath":"/mnt/a"},{"id":"b","usesIndividualMountPath":true,"individualMountPath":"/mnt/b"},{"id":"c","useCustomMountPath":false,"customMountPath":"/ignored","winDriveLetter":"Z"}]}"#).unwrap();
        assert_eq!(s.directories[0].mount_point.as_deref(), Some("/mnt/a"));
        assert_eq!(s.directories[1].mount_point.as_deref(), Some("/mnt/b"));
        assert_eq!(s.directories[2].mount_point.as_deref(), Some("Z:\\"));
        let out = s.to_json_pretty();
        for legacy in ["useCustomMountPath", "customMountPath", "usesIndividualMountPath", "individualMountPath", "winDriveLetter"] {
            assert!(!out.contains(legacy), "{legacy} must not be written");
        }
    }

    #[test]
    fn unknown_action_after_unlock_falls_back_to_ask() {
        let s = SettingsJson::parse(br#"{"directories":[{"id":"a","actionAfterUnlock":"DANCE"}]}"#).unwrap();
        assert_eq!(s.directories[0].action_after_unlock, WhenUnlocked::Ask);
        assert_eq!(WhenUnlocked::parse("REVEAL"), Some(WhenUnlocked::Reveal));
        assert_eq!(WhenUnlocked::Ignore.as_str(), "IGNORE");
    }

    #[test]
    fn null_keychain_provider_falls_back_to_default() {
        let s = SettingsJson::parse(br#"{"keychainProvider": null}"#).unwrap();
        assert_eq!(s.keychain_provider, default_keychain_provider());
    }
}
```

- [ ] **Step 3: Run tests, confirm failure**

Run: `cargo test -p cryptomator-app`
Expected: FAIL (modules missing)

- [ ] **Step 4: Implement**

```rust
// crates/cryptomator-app/src/error.rs
//! Errors of the application layer.
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error(transparent)]
    Core(#[from] cryptomator_core::CoreError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("settings file {path} is not valid JSON: {source}")]
    SettingsCorrupt {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("no vault matches {0:?} (by id, display name or path)")]
    VaultNotFound(String),
    #[error("{0:?} matches several vaults: {}", .1.join(", "))]
    AmbiguousVault(String, Vec<String>),
    #[error("vault at {0} is already registered")]
    VaultAlreadyAdded(PathBuf),
    #[error("no password source: use --password-stdin, --password-file, --password-env or CRYPTO_PASSWORD, or run interactively")]
    NoPasswordSource,
    #[error("password must be at least {0} characters long")]
    PasswordTooShort(usize),
    #[error("passwords do not match")]
    PasswordMismatch,
    #[error("vault is {actual}, expected {expected}")]
    WrongState { expected: String, actual: String },
    #[error("invalid value for {key}: {message}")]
    InvalidValue { key: String, message: String },
    #[error("no home directory (set HOME or CRYPTO_SETTINGS_PATH)")]
    NoHomeDirectory,
}

pub type Result<T> = std::result::Result<T, AppError>;
```

```rust
// crates/cryptomator-app/src/settings/mod.rs
//! Desktop-compatible `settings.json`.
pub mod model;

pub use model::{default_keychain_provider, SettingsJson, VaultSettingsJson, WhenUnlocked, DEFAULT_AUTOLOCK_IDLE_SECONDS, DEFAULT_MAX_CLEARTEXT_FILENAME_LENGTH, DEFAULT_PORT};
```

```rust
// crates/cryptomator-app/src/settings/model.rs
//! On-disk schema of the desktop app's `settings.json` (`common/settings/SettingsJson.java`,
//! `VaultSettingsJson.java`). Only the fields the CLI uses are typed; everything else is kept
//! verbatim in `extra` so the desktop app's GUI settings survive a round trip. Legacy fields
//! (`preferredVolumeImpl`, `winDriveLetter`, `useCustomMountPath`, `customMountPath`) are read,
//! migrated like `Settings.migrateLegacySettings` / `VaultSettings.migrateLegacySettings` and never written.
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use std::path::Path;

pub const DEFAULT_PORT: u16 = 42427;
pub const DEFAULT_AUTOLOCK_IDLE_SECONDS: u32 = 30 * 60;
pub const DEFAULT_MAX_CLEARTEXT_FILENAME_LENGTH: i32 = -1;

/// `Settings.DEFAULT_KEYCHAIN_PROVIDER` for macOS and Linux.
pub fn default_keychain_provider() -> String {
    if cfg!(target_os = "macos") {
        "org.cryptomator.macos.keychain.MacSystemKeychainAccess".to_string()
    } else {
        "org.cryptomator.linux.keychain.GnomeKeyringKeychainAccess".to_string()
    }
}

fn d_true() -> bool {
    true
}

fn d_port() -> u16 {
    DEFAULT_PORT
}

fn d_idle() -> u32 {
    DEFAULT_AUTOLOCK_IDLE_SECONDS
}

fn d_max_name() -> i32 {
    DEFAULT_MAX_CLEARTEXT_FILENAME_LENGTH
}

/// Jackson `@JsonSetter(nulls = Nulls.AS_EMPTY)`.
fn null_as_empty<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> std::result::Result<Vec<T>, D::Error> {
    Ok(Option::<Vec<T>>::deserialize(d)?.unwrap_or_default())
}

fn null_as_default_provider<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<String, D::Error> {
    Ok(Option::<String>::deserialize(d)?.unwrap_or_else(default_keychain_provider))
}

/// `common/settings/WhenUnlocked.java`; unknown values fall back to `ASK` (`@JsonEnumDefaultValue`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub enum WhenUnlocked {
    #[serde(rename = "IGNORE")]
    Ignore,
    #[serde(rename = "REVEAL")]
    Reveal,
    #[default]
    #[serde(rename = "ASK")]
    Ask,
}

impl WhenUnlocked {
    pub fn as_str(&self) -> &'static str {
        match self {
            WhenUnlocked::Ignore => "IGNORE",
            WhenUnlocked::Reveal => "REVEAL",
            WhenUnlocked::Ask => "ASK",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "IGNORE" => Some(WhenUnlocked::Ignore),
            "REVEAL" => Some(WhenUnlocked::Reveal),
            "ASK" => Some(WhenUnlocked::Ask),
            _ => None,
        }
    }
}

impl<'de> Deserialize<'de> for WhenUnlocked {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let value = Option::<String>::deserialize(d)?;
        Ok(value.as_deref().and_then(WhenUnlocked::parse).unwrap_or_default())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultSettingsJson {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default)]
    pub unlock_after_startup: bool,
    #[serde(default = "d_true")]
    pub reveal_after_mount: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mount_point: Option<String>,
    #[serde(default)]
    pub uses_read_only_mode: bool,
    #[serde(default)]
    pub mount_flags: String,
    #[serde(default = "d_max_name")]
    pub max_cleartext_filename_length: i32,
    #[serde(default)]
    pub action_after_unlock: WhenUnlocked,
    #[serde(default)]
    pub auto_lock_when_idle: bool,
    #[serde(default = "d_idle")]
    pub auto_lock_idle_seconds: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mount_service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_known_key_loader: Option<String>,
    #[serde(default = "d_port")]
    pub port: u16,
    /// Legacy (< 1.7.0), read-only.
    #[serde(default, skip_serializing)]
    pub win_drive_letter: Option<String>,
    #[serde(default, skip_serializing, alias = "usesIndividualMountPath")]
    pub use_custom_mount_path: bool,
    #[serde(default, skip_serializing, alias = "individualMountPath")]
    pub custom_mount_path: Option<String>,
    /// Every other key, preserved verbatim.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl VaultSettingsJson {
    /// `VaultListManager.newVaultSettings`: display name = last path component (or "Vault").
    pub fn new(id: String, path: &Path) -> Self {
        let display_name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "Vault".to_string());
        Self {
            id,
            path: Some(path.to_string_lossy().into_owned()),
            display_name: Some(display_name),
            unlock_after_startup: false,
            reveal_after_mount: true,
            mount_point: None,
            uses_read_only_mode: false,
            mount_flags: String::new(),
            max_cleartext_filename_length: DEFAULT_MAX_CLEARTEXT_FILENAME_LENGTH,
            action_after_unlock: WhenUnlocked::Ask,
            auto_lock_when_idle: false,
            auto_lock_idle_seconds: DEFAULT_AUTOLOCK_IDLE_SECONDS,
            mount_service: None,
            last_known_key_loader: None,
            port: DEFAULT_PORT,
            win_drive_letter: None,
            use_custom_mount_path: false,
            custom_mount_path: None,
            extra: Map::new(),
        }
    }

    /// `VaultSettings.migrateLegacySettings`.
    pub fn migrate_legacy(&mut self) {
        if self.use_custom_mount_path && self.custom_mount_path.as_deref().is_some_and(|p| !p.is_empty()) {
            self.mount_point = self.custom_mount_path.clone();
        } else if let Some(letter) = self.win_drive_letter.as_deref().filter(|l| !l.is_empty()) {
            self.mount_point = Some(format!("{letter}:\\"));
        }
        self.win_drive_letter = None;
        self.use_custom_mount_path = false;
        self.custom_mount_path = None;
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsJson {
    #[serde(default, deserialize_with = "null_as_empty")]
    pub directories: Vec<VaultSettingsJson>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub written_by_version: Option<String>,
    #[serde(default = "d_true")]
    pub use_keychain: bool,
    #[serde(default = "default_keychain_provider", deserialize_with = "null_as_default_provider")]
    pub keychain_provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mount_service: Option<String>,
    #[serde(default = "d_port")]
    pub port: u16,
    #[serde(default)]
    pub debug_mode: bool,
    /// Legacy (< 1.7.0), read-only.
    #[serde(default, skip_serializing)]
    pub preferred_volume_impl: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for SettingsJson {
    fn default() -> Self {
        Self {
            directories: Vec::new(),
            written_by_version: None,
            use_keychain: true,
            keychain_provider: default_keychain_provider(),
            mount_service: None,
            port: DEFAULT_PORT,
            debug_mode: false,
            preferred_volume_impl: None,
            extra: Map::new(),
        }
    }
}

impl SettingsJson {
    pub fn parse(bytes: &[u8]) -> std::result::Result<Self, serde_json::Error> {
        let mut settings: Self = serde_json::from_slice(bytes)?;
        settings.migrate_legacy();
        Ok(settings)
    }

    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).expect("settings serialize")
    }

    /// `Settings.migrateLegacySettings` (macOS/Linux branches) plus per-vault migration.
    pub fn migrate_legacy(&mut self) {
        if self.mount_service.is_none() {
            if let Some(legacy) = self.preferred_volume_impl.as_deref() {
                self.mount_service = Some(
                    match legacy {
                        "Dokany" => "org.cryptomator.frontend.dokany.mount.DokanyMountProvider",
                        "FUSE" if cfg!(target_os = "macos") => "org.cryptomator.frontend.fuse.mount.MacFuseMountProvider",
                        "FUSE" => "org.cryptomator.frontend.fuse.mount.LinuxFuseMountProvider",
                        _ if cfg!(target_os = "macos") => "org.cryptomator.frontend.webdav.mount.MacAppleScriptMounter",
                        _ => "org.cryptomator.frontend.webdav.mount.LinuxGioMounter",
                    }
                    .to_string(),
                );
            }
        }
        self.preferred_volume_impl = None;
        for vault in &mut self.directories {
            vault.migrate_legacy();
        }
    }
}
```

```rust
// crates/cryptomator-app/src/lib.rs
//! Application layer: settings.json, keychain, daemon protocol, vault registry.
#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod error;
pub mod settings;

pub use error::{AppError, Result};
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p cryptomator-app`
Expected: PASS (9 tests). If `"[]"` in `malformed_input_is_an_error` does NOT fail (serde does not accept an array for a struct – it must fail), leave the test unchanged and check the implementation.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock crates/cryptomator-app
git commit -m "Add desktop-compatible settings.json model with legacy migration

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 7: Vault IDs, display names and reference resolution (`settings/ids.rs`, `settings/vault_ref.rs`)

**Files:**
- Create: `crates/cryptomator-app/src/settings/ids.rs`, `crates/cryptomator-app/src/settings/vault_ref.rs`
- Modify: `crates/cryptomator-app/src/settings/mod.rs`

**Interfaces:**
- Consumes: `cryptomator_core::Rng`, `SettingsJson`, `VaultSettingsJson`, `AppError`.
- Produces: `generate_id(rng: &mut dyn Rng) -> String` (12 Zeichen base64url); `normalize_display_name(&str) -> String`; `impl VaultSettingsJson { pub fn mount_name(&self) -> String; pub fn path_buf(&self) -> Option<PathBuf> }`; `resolve_vault_index(settings: &SettingsJson, reference: &str) -> Result<usize>`; `resolve_vault<'a>(settings: &'a SettingsJson, reference: &str) -> Result<&'a VaultSettingsJson>`; `normalize_vault_path(path: &Path) -> PathBuf` (absolut + kanonisch, falls existent).

- [ ] **Step 1: Write failing tests**

```rust
// at the end of crates/cryptomator-app/src/settings/ids.rs
#[cfg(test)]
mod tests {
    use super::*;
    use cryptomator_core::OsRng;

    #[test]
    fn ids_are_12_base64url_chars() {
        let id = generate_id(&mut OsRng);
        assert_eq!(id.len(), 12);
        assert!(id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'), "{id}");
        assert_ne!(id, generate_id(&mut OsRng));
    }

    // VaultSettingsTest.testNormalize
    #[test]
    fn normalizes_like_java() {
        assert_eq!(normalize_display_name("a\u{000F}a"), "a_a");
        assert_eq!(normalize_display_name(": \\"), "_ _");
        assert_eq!(normalize_display_name("汉语"), "汉语");
        assert_eq!(normalize_display_name(".."), "_");
        assert_eq!(normalize_display_name("a\ta"), "a a");
        assert_eq!(normalize_display_name("\t\n\r"), "_");
        assert_eq!(normalize_display_name("a  \u{00A0} b"), "a b", "unicode whitespace collapses to one space");
        assert_eq!(normalize_display_name("x<>:\"/\\|?*y"), "x_y");
        assert_eq!(normalize_display_name(""), "_");
        assert_eq!(normalize_display_name("."), "_");
    }

    #[test]
    fn mount_name_uses_display_name_or_path() {
        let mut v = VaultSettingsJson::new("id".into(), std::path::Path::new("/tmp/My: Vault"));
        assert_eq!(v.mount_name(), "My_ Vault");
        v.display_name = Some("".into());
        assert_eq!(v.mount_name(), "My_ Vault", "empty display name falls back to the path");
        v.display_name = None;
        v.path = None;
        assert_eq!(v.mount_name(), "Vault");
    }
}
```

```rust
// at the end of crates/cryptomator-app/src/settings/vault_ref.rs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::SettingsJson;

    fn settings(dir: &Path) -> SettingsJson {
        let mut s = SettingsJson::default();
        let mut a = VaultSettingsJson::new("AAAAAAAAAAAA".into(), &dir.join("Alpha"));
        a.display_name = Some("Alpha".into());
        let mut b = VaultSettingsJson::new("BBBBBBBBBBBB".into(), &dir.join("Beta"));
        b.display_name = Some("beta".into());
        let mut c = VaultSettingsJson::new("CCCCCCCCCCCC".into(), &dir.join("Gamma"));
        c.display_name = Some("Beta".into());
        s.directories = vec![a, b, c];
        s
    }

    #[test]
    fn resolves_by_id_name_and_path() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("Alpha")).unwrap();
        let s = settings(dir.path());
        assert_eq!(resolve_vault_index(&s, "AAAAAAAAAAAA").unwrap(), 0);
        assert_eq!(resolve_vault(&s, "Alpha").unwrap().id, "AAAAAAAAAAAA");
        assert_eq!(resolve_vault(&s, "alpha").unwrap().id, "AAAAAAAAAAAA", "case-insensitive when unique");
        assert_eq!(resolve_vault(&s, dir.path().join("Alpha").to_str().unwrap()).unwrap().id, "AAAAAAAAAAAA");
        assert_eq!(resolve_vault(&s, dir.path().join("Alpha/./").to_str().unwrap()).unwrap().id, "AAAAAAAAAAAA", "path is normalized");
        assert_eq!(resolve_vault(&s, dir.path().join("Gamma").to_str().unwrap()).unwrap().id, "CCCCCCCCCCCC", "non-existent paths still match textually");
    }

    #[test]
    fn exact_name_beats_case_insensitive_and_ambiguity_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let s = settings(dir.path());
        assert_eq!(resolve_vault(&s, "beta").unwrap().id, "BBBBBBBBBBBB");
        assert_eq!(resolve_vault(&s, "Beta").unwrap().id, "CCCCCCCCCCCC");
        match resolve_vault(&s, "BETA") {
            Err(AppError::AmbiguousVault(reference, ids)) => {
                assert_eq!(reference, "BETA");
                assert_eq!(ids, vec!["BBBBBBBBBBBB".to_string(), "CCCCCCCCCCCC".to_string()]);
            }
            other => panic!("expected ambiguity, got {other:?}"),
        }
    }

    #[test]
    fn unknown_reference_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let s = settings(dir.path());
        assert!(matches!(resolve_vault(&s, "nope"), Err(AppError::VaultNotFound(r)) if r == "nope"));
        assert!(matches!(resolve_vault(&s, "/definitely/not/there"), Err(AppError::VaultNotFound(_))));
    }
}
```

- [ ] **Step 2: Run tests, confirm failure**

Run: `cargo test -p cryptomator-app -- settings::ids settings::vault_ref`
Expected: FAIL (modules missing)

- [ ] **Step 3: Implement**

```rust
// crates/cryptomator-app/src/settings/ids.rs
//! Vault ids (`VaultSettings.generateId`) and display-name normalisation (`VaultSettings.normalizeDisplayName`).
use crate::settings::VaultSettingsJson;
use cryptomator_core::Rng;
use data_encoding::BASE64URL;
use std::path::PathBuf;

/// 9 random bytes → 12 base64url characters (no padding needed).
pub fn generate_id(rng: &mut dyn Rng) -> String {
    let mut bytes = [0u8; 9];
    rng.fill(&mut bytes);
    BASE64URL.encode(&bytes)
}

/// Guava `CharMatcher.collapseFrom`: every run of matching chars becomes one `replacement`.
fn collapse(input: &str, matches: impl Fn(char) -> bool, replacement: char) -> String {
    let mut out = String::with_capacity(input.len());
    let mut in_run = false;
    for c in input.chars() {
        if matches(c) {
            if !in_run {
                out.push(replacement);
                in_run = true;
            }
        } else {
            out.push(c);
            in_run = false;
        }
    }
    out
}

/// `Character.isISOControl`
fn is_iso_control(c: char) -> bool {
    matches!(c as u32, 0x00..=0x1F | 0x7F..=0x9F)
}

pub fn normalize_display_name(original: &str) -> String {
    if original.trim().is_empty() || original == "." || original == ".." {
        return "_".to_string();
    }
    let without_fancy_whitespace = collapse(original, char::is_whitespace, ' ');
    collapse(&without_fancy_whitespace, |c| "<>:\"/\\|?*".contains(c) || is_iso_control(c), '_')
}

impl VaultSettingsJson {
    /// `VaultSettings.mountName`: normalised display name, falling back to the path's file name, then "Vault".
    pub fn mount_name(&self) -> String {
        let name = match self.display_name.as_deref() {
            Some(name) if !name.is_empty() => name.to_string(),
            _ => self
                .path_buf()
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
                .unwrap_or_else(|| "Vault".to_string()),
        };
        normalize_display_name(&name)
    }

    pub fn path_buf(&self) -> Option<PathBuf> {
        self.path.as_deref().map(PathBuf::from)
    }
}
```

```rust
// crates/cryptomator-app/src/settings/vault_ref.rs
//! Resolving a user-supplied vault reference (id, display name or path) against the settings.
use crate::error::{AppError, Result};
use crate::settings::{SettingsJson, VaultSettingsJson};
use std::path::{Path, PathBuf};

/// Absolute, `.`/`..`-free path; canonicalised (symlinks resolved) when it exists.
pub fn normalize_vault_path(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().map(|cwd| cwd.join(path)).unwrap_or_else(|_| path.to_path_buf())
    };
    if let Ok(canonical) = absolute.canonicalize() {
        return canonical;
    }
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

pub fn resolve_vault_index(settings: &SettingsJson, reference: &str) -> Result<usize> {
    let vaults = &settings.directories;
    if let Some(i) = vaults.iter().position(|v| v.id == reference) {
        return Ok(i);
    }
    let exact: Vec<usize> = vaults.iter().enumerate().filter(|(_, v)| v.display_name.as_deref() == Some(reference)).map(|(i, _)| i).collect();
    match exact.as_slice() {
        [i] => return Ok(*i),
        [_, ..] => return Err(AppError::AmbiguousVault(reference.to_string(), exact.iter().map(|i| vaults[*i].id.clone()).collect())),
        [] => {}
    }
    let lowered = reference.to_lowercase();
    let insensitive: Vec<usize> = vaults
        .iter()
        .enumerate()
        .filter(|(_, v)| v.display_name.as_deref().is_some_and(|n| n.to_lowercase() == lowered))
        .map(|(i, _)| i)
        .collect();
    match insensitive.as_slice() {
        [i] => return Ok(*i),
        [_, ..] => return Err(AppError::AmbiguousVault(reference.to_string(), insensitive.iter().map(|i| vaults[*i].id.clone()).collect())),
        [] => {}
    }
    let wanted = normalize_vault_path(Path::new(reference));
    if let Some(i) = vaults.iter().position(|v| v.path_buf().is_some_and(|p| normalize_vault_path(&p) == wanted)) {
        return Ok(i);
    }
    Err(AppError::VaultNotFound(reference.to_string()))
}

pub fn resolve_vault<'a>(settings: &'a SettingsJson, reference: &str) -> Result<&'a VaultSettingsJson> {
    let index = resolve_vault_index(settings, reference)?;
    Ok(&settings.directories[index])
}
```

Extend `settings/mod.rs`: `pub mod ids; pub mod vault_ref;` and `pub use ids::{generate_id, normalize_display_name}; pub use vault_ref::{normalize_vault_path, resolve_vault, resolve_vault_index};`.

- [ ] **Step 4: Run tests**

Run: `cargo test -p cryptomator-app -- settings::ids settings::vault_ref`
Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add crates/cryptomator-app
git commit -m "Add vault id generation, display-name normalisation and vault reference resolution

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 8: Settings store – paths, loading, atomic saving (`settings/store.rs`)

**Files:**
- Create: `crates/cryptomator-app/src/settings/store.rs`
- Modify: `crates/cryptomator-app/src/settings/mod.rs`

**Interfaces:**
- Consumes: `SettingsJson::{parse, to_json_pretty}`, `AppError`.
- Produces: `SETTINGS_PATH_ENV = "CRYPTO_SETTINGS_PATH"`; `default_settings_candidates(home: &Path) -> Vec<PathBuf>`; `candidates_from_env_value(&str) -> Vec<PathBuf>`; `SettingsStore::with_paths(Vec<PathBuf>) -> Result<Self>`, `SettingsStore::from_env_or_default() -> Result<Self>`, `SettingsStore::at(path: PathBuf) -> Self`, `preferred_path(&self) -> &Path`, `candidates(&self) -> &[PathBuf]`, `load(&self) -> Result<SettingsJson>`, `save(&self, &mut SettingsJson) -> Result<()>`, `update<T>(&self, f: impl FnOnce(&mut SettingsJson) -> Result<T>) -> Result<T>`.

- [ ] **Step 1: Write failing tests**

```rust
// at the end of crates/cryptomator-app/src/settings/store.rs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::VaultSettingsJson;

    #[test]
    fn default_candidates_per_os() {
        let home = Path::new("/home/u");
        let candidates = default_settings_candidates(home);
        if cfg!(target_os = "macos") {
            assert_eq!(candidates, vec![PathBuf::from("/home/u/Library/Application Support/Cryptomator/settings.json")]);
        } else {
            assert_eq!(candidates, vec![PathBuf::from("/home/u/.config/Cryptomator/settings.json"), PathBuf::from("/home/u/.Cryptomator/settings.json")]);
        }
        assert_eq!(candidates_from_env_value("/a/s.json::/b/s.json:"), vec![PathBuf::from("/a/s.json"), PathBuf::from("/b/s.json")]);
        assert!(SettingsStore::with_paths(Vec::new()).is_err());
    }

    #[test]
    fn missing_file_loads_defaults_and_save_creates_directories() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deep/er/settings.json");
        let store = SettingsStore::at(path.clone());
        let mut settings = store.load().unwrap();
        assert_eq!(settings, SettingsJson::default());
        settings.directories.push(VaultSettingsJson::new("AAAAAAAAAAAA".into(), Path::new("/v")));
        store.save(&mut settings).unwrap();
        assert!(path.is_file());
        assert!(!dir.path().join("deep/er/settings.json.tmp").exists());
        assert_eq!(settings.written_by_version.as_deref(), Some(concat!("crypto-", env!("CARGO_PKG_VERSION"))));
        let loaded = store.load().unwrap();
        assert_eq!(loaded, settings);
    }

    #[test]
    fn existing_written_by_version_is_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, br#"{"writtenByVersion":"1.19.3-dmg-6495","theme":"DARK"}"#).unwrap();
        let store = SettingsStore::at(path.clone());
        let mut settings = store.load().unwrap();
        settings.port = 5000;
        store.save(&mut settings).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"writtenByVersion\": \"1.19.3-dmg-6495\""));
        assert!(text.contains("\"theme\": \"DARK\""));
        assert!(text.contains("\"port\": 5000"));
    }

    #[test]
    fn falls_back_to_second_candidate_but_saves_to_first() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first/settings.json");
        let second = dir.path().join("second/settings.json");
        std::fs::create_dir_all(second.parent().unwrap()).unwrap();
        std::fs::write(&second, br#"{"port": 4711}"#).unwrap();
        let store = SettingsStore::with_paths(vec![first.clone(), second.clone()]).unwrap();
        let mut settings = store.load().unwrap();
        assert_eq!(settings.port, 4711);
        store.save(&mut settings).unwrap();
        assert!(first.is_file());
        assert_eq!(std::fs::read_to_string(&second).unwrap(), r#"{"port": 4711}"#, "second candidate untouched");
    }

    #[test]
    fn corrupt_file_is_an_error_not_silently_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, b"{ not json").unwrap();
        let store = SettingsStore::at(path.clone());
        assert!(matches!(store.load(), Err(AppError::SettingsCorrupt { .. })));
        assert!(store.update(|s| { s.port = 1; Ok(()) }).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"{ not json");
    }

    #[test]
    fn update_loads_applies_and_saves() {
        let dir = tempfile::tempdir().unwrap();
        let store = SettingsStore::at(dir.path().join("settings.json"));
        let id = store.update(|s| { s.directories.push(VaultSettingsJson::new("BBBBBBBBBBBB".into(), Path::new("/b"))); Ok(s.directories[0].id.clone()) }).unwrap();
        assert_eq!(id, "BBBBBBBBBBBB");
        assert_eq!(store.load().unwrap().directories.len(), 1);
    }
}
```

- [ ] **Step 2: Run tests, confirm failure**

Run: `cargo test -p cryptomator-app -- settings::store`
Expected: FAIL (module missing)

- [ ] **Step 3: Implement**

```rust
// crates/cryptomator-app/src/settings/store.rs
//! Locating, loading and atomically saving `settings.json` (`common/settings/SettingsProvider.java`
//! plus the per-OS `-Dcryptomator.settingsPath` values from the desktop packaging scripts).
use crate::error::{AppError, Result};
use crate::settings::SettingsJson;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const SETTINGS_PATH_ENV: &str = "CRYPTO_SETTINGS_PATH";
const WRITTEN_BY_VERSION: &str = concat!("crypto-", env!("CARGO_PKG_VERSION"));

/// macOS: `~/Library/Application Support/Cryptomator/settings.json`;
/// Linux: `~/.config/Cryptomator/settings.json`, then `~/.Cryptomator/settings.json`.
pub fn default_settings_candidates(home: &Path) -> Vec<PathBuf> {
    if cfg!(target_os = "macos") {
        vec![home.join("Library/Application Support/Cryptomator/settings.json")]
    } else {
        vec![home.join(".config/Cryptomator/settings.json"), home.join(".Cryptomator/settings.json")]
    }
}

/// `CRYPTO_SETTINGS_PATH` is a `:`-separated list like Java's `cryptomator.settingsPath`; empty entries are ignored.
pub fn candidates_from_env_value(value: &str) -> Vec<PathBuf> {
    value.split(':').filter(|p| !p.is_empty()).map(PathBuf::from).collect()
}

#[derive(Debug, Clone)]
pub struct SettingsStore {
    candidates: Vec<PathBuf>,
}

impl SettingsStore {
    pub fn with_paths(candidates: Vec<PathBuf>) -> Result<Self> {
        if candidates.is_empty() {
            return Err(AppError::InvalidValue { key: SETTINGS_PATH_ENV.to_string(), message: "at least one settings path is required".to_string() });
        }
        Ok(Self { candidates })
    }

    pub fn at(path: PathBuf) -> Self {
        Self { candidates: vec![path] }
    }

    pub fn from_env_or_default() -> Result<Self> {
        if let Some(value) = std::env::var_os(SETTINGS_PATH_ENV) {
            return Self::with_paths(candidates_from_env_value(&value.to_string_lossy()));
        }
        let home = std::env::var_os("HOME").map(PathBuf::from).ok_or(AppError::NoHomeDirectory)?;
        Self::with_paths(default_settings_candidates(&home))
    }

    /// The first candidate: always the save target (`SettingsProvider.scheduleSave`).
    pub fn preferred_path(&self) -> &Path {
        &self.candidates[0]
    }

    pub fn candidates(&self) -> &[PathBuf] {
        &self.candidates
    }

    /// First candidate that exists wins. Unlike Java, a corrupt file is an error rather than a silent reset.
    pub fn load(&self) -> Result<SettingsJson> {
        for path in &self.candidates {
            match std::fs::read(path) {
                Ok(bytes) => return SettingsJson::parse(&bytes).map_err(|source| AppError::SettingsCorrupt { path: path.clone(), source }),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(AppError::Io(e)),
            }
        }
        Ok(SettingsJson::default())
    }

    /// Writes `settings.json.tmp` and renames it over the preferred path (`SettingsProvider.save`).
    pub fn save(&self, settings: &mut SettingsJson) -> Result<()> {
        let path = self.preferred_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if settings.written_by_version.is_none() {
            settings.written_by_version = Some(WRITTEN_BY_VERSION.to_string());
        }
        let file_name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "settings.json".to_string());
        let tmp_path = path.with_file_name(format!("{file_name}.tmp"));
        {
            let mut tmp = std::fs::File::create(&tmp_path)?;
            tmp.write_all(settings.to_json_pretty().as_bytes())?;
            tmp.sync_all()?;
        }
        std::fs::rename(&tmp_path, path)?;
        Ok(())
    }

    pub fn update<T>(&self, f: impl FnOnce(&mut SettingsJson) -> Result<T>) -> Result<T> {
        let mut settings = self.load()?;
        let result = f(&mut settings)?;
        self.save(&mut settings)?;
        Ok(result)
    }
}
```

Extend `settings/mod.rs`: `pub mod store;` and `pub use store::{candidates_from_env_value, default_settings_candidates, SettingsStore, SETTINGS_PATH_ENV};`.

- [ ] **Step 4: Run tests**

Run: `cargo test -p cryptomator-app -- settings::store`
Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add crates/cryptomator-app
git commit -m "Add settings store with desktop paths and atomic saves

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 9: Password sources (`password.rs`) and mounter aliases (`mounters.rs`)

**Files:**
- Create: `crates/cryptomator-app/src/password.rs`, `crates/cryptomator-app/src/mounters.rs`
- Modify: `crates/cryptomator-app/src/lib.rs`

**Interfaces:**
- Consumes: `AppError`.
- Produces: `PasswordArgs` (clap `Args`: `--password-stdin`, `--password-file FILE`, `--password-env VAR`, mutually exclusive, group `password-source`); `NewPasswordArgs` (clap `Args`: `--new-password-stdin`, `--new-password-file FILE`, `--new-password-env VAR`, group `new-password-source`) with `impl From<&NewPasswordArgs> for PasswordArgs`; `trait PasswordIo { fn read_stdin_line(&mut self) -> io::Result<Option<String>>; fn env(&self, name: &str) -> Option<String>; fn prompt(&mut self, prompt: &str) -> io::Result<Option<String>>; }`; `SystemIo` (stdin, `std::env`, `rpassword` only when on a terminal); `normalize_passphrase(&str) -> Zeroizing<String>` (NFC); `read_passphrase(args: &PasswordArgs, prompt: &str, io: &mut dyn PasswordIo) -> Result<Zeroizing<String>>`; `read_new_passphrase(args: &PasswordArgs, prompt: &str, min_len: usize, io: &mut dyn PasswordIo) -> Result<Zeroizing<String>>`; `min_password_length() -> usize`; constants `PASSWORD_ENV = "CRYPTO_PASSWORD"`, `MIN_PW_LENGTH_ENV = "CRYPTO_MIN_PW_LENGTH"`, `DEFAULT_MIN_PW_LENGTH = 8`, `MAX_PASSWORD_FILE_BYTES = 5000`. `mounters::{MOUNTER_ALIASES, resolve_mounter(input: &str) -> Result<String>, alias_for(class_name: &str) -> Option<&'static str>}`.

- [ ] **Step 1: Write failing tests**

```rust
// at the end of crates/cryptomator-app/src/password.rs
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, VecDeque};

    #[derive(Default)]
    struct FakeIo {
        stdin: VecDeque<String>,
        env: HashMap<String, String>,
        prompts: Option<VecDeque<String>>,
        prompted: Vec<String>,
    }

    impl PasswordIo for FakeIo {
        fn read_stdin_line(&mut self) -> std::io::Result<Option<String>> {
            Ok(self.stdin.pop_front())
        }
        fn env(&self, name: &str) -> Option<String> {
            self.env.get(name).cloned()
        }
        fn prompt(&mut self, prompt: &str) -> std::io::Result<Option<String>> {
            self.prompted.push(prompt.to_string());
            Ok(self.prompts.as_mut().and_then(|p| p.pop_front()))
        }
    }

    fn args(stdin: bool, file: Option<&Path>, env: Option<&str>) -> PasswordArgs {
        PasswordArgs { password_stdin: stdin, password_file: file.map(Path::to_path_buf), password_env: env.map(str::to_string) }
    }

    #[test]
    fn stdin_source_reads_one_line_without_line_ending() {
        let mut io = FakeIo { stdin: VecDeque::from(["first\r\n".to_string(), "second\n".to_string()]), ..Default::default() };
        assert_eq!(*read_passphrase(&args(true, None, None), "p", &mut io).unwrap(), "first");
        assert_eq!(*read_passphrase(&args(true, None, None), "p", &mut io).unwrap(), "second");
        assert!(matches!(read_passphrase(&args(true, None, None), "p", &mut io), Err(AppError::NoPasswordSource)));
        assert!(io.prompted.is_empty());
    }

    #[test]
    fn file_source_strips_one_trailing_newline_and_normalizes_nfc() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("pw");
        std::fs::write(&file, "cafe\u{0301}\n\n").unwrap();
        let mut io = FakeIo::default();
        let pw = read_passphrase(&args(false, Some(&file), None), "p", &mut io).unwrap();
        assert_eq!(*pw, "caf\u{00E9}\n", "only one newline stripped, NFD composed to NFC");
        std::fs::write(&file, vec![b'a'; MAX_PASSWORD_FILE_BYTES as usize + 1]).unwrap();
        assert!(matches!(read_passphrase(&args(false, Some(&file), None), "p", &mut io), Err(AppError::InvalidValue { .. })));
    }

    #[test]
    fn env_sources_and_precedence() {
        let mut io = FakeIo { env: HashMap::from([("MY_PW".to_string(), "from-var".to_string()), (PASSWORD_ENV.to_string(), "from-default".to_string())]), stdin: VecDeque::from(["from-stdin".to_string()]), ..Default::default() };
        assert_eq!(*read_passphrase(&args(false, None, Some("MY_PW")), "p", &mut io).unwrap(), "from-var");
        assert_eq!(*read_passphrase(&args(false, None, None), "p", &mut io).unwrap(), "from-default");
        assert_eq!(*read_passphrase(&args(true, None, None), "p", &mut io).unwrap(), "from-stdin");
        assert!(matches!(read_passphrase(&args(false, None, Some("MISSING")), "p", &mut io), Err(AppError::InvalidValue { .. })));
    }

    #[test]
    fn interactive_prompt_is_the_last_resort() {
        let mut io = FakeIo { prompts: Some(VecDeque::from(["typed".to_string()])), ..Default::default() };
        assert_eq!(*read_passphrase(&args(false, None, None), "Password: ", &mut io).unwrap(), "typed");
        assert_eq!(io.prompted, vec!["Password: ".to_string()]);
        let mut no_tty = FakeIo::default();
        assert!(matches!(read_passphrase(&args(false, None, None), "p", &mut no_tty), Err(AppError::NoPasswordSource)));
    }

    #[test]
    fn new_passphrase_enforces_length_and_confirmation() {
        let mut io = FakeIo { env: HashMap::from([(PASSWORD_ENV.to_string(), "short".to_string())]), ..Default::default() };
        assert!(matches!(read_new_passphrase(&args(false, None, None), "p", 8, &mut io), Err(AppError::PasswordTooShort(8))));
        let mut io = FakeIo { prompts: Some(VecDeque::from(["long-enough-1".to_string(), "long-enough-1".to_string()])), ..Default::default() };
        assert_eq!(*read_new_passphrase(&args(false, None, None), "New password: ", 8, &mut io).unwrap(), "long-enough-1");
        assert_eq!(io.prompted.len(), 2);
        let mut io = FakeIo { prompts: Some(VecDeque::from(["long-enough-1".to_string(), "different-123".to_string()])), ..Default::default() };
        assert!(matches!(read_new_passphrase(&args(false, None, None), "p", 8, &mut io), Err(AppError::PasswordMismatch)));
    }

    #[test]
    fn new_password_args_convert() {
        let new = NewPasswordArgs { new_password_stdin: true, new_password_file: None, new_password_env: Some("X".into()) };
        let converted = PasswordArgs::from(&new);
        assert!(converted.password_stdin);
        assert_eq!(converted.password_env.as_deref(), Some("X"));
    }
}
```

```rust
// at the end of crates/cryptomator-app/src/mounters.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases_map_to_java_class_names_and_back() {
        assert_eq!(resolve_mounter("fuse-t").unwrap(), "org.cryptomator.frontend.fuse.mount.FuseTMountProvider");
        assert_eq!(resolve_mounter("MacFUSE").unwrap(), "org.cryptomator.frontend.fuse.mount.MacFuseMountProvider");
        assert_eq!(resolve_mounter("fuse").unwrap(), "org.cryptomator.frontend.fuse.mount.LinuxFuseMountProvider");
        assert_eq!(resolve_mounter("webdav").unwrap(), "org.cryptomator.frontend.webdav.mount.FallbackMounter");
        assert_eq!(resolve_mounter("org.example.Custom").unwrap(), "org.example.Custom", "class names pass through");
        assert!(matches!(resolve_mounter("bogus"), Err(AppError::InvalidValue { .. })));
        assert_eq!(alias_for("org.cryptomator.frontend.fuse.mount.FuseTMountProvider"), Some("fuse-t"));
        assert_eq!(alias_for("org.example.Custom"), None);
    }
}
```

- [ ] **Step 2: Run tests, confirm failure**

Run: `cargo test -p cryptomator-app -- password mounters`
Expected: FAIL (modules missing)

- [ ] **Step 3: Implement**

```rust
// crates/cryptomator-app/src/password.rs
//! Passphrase sources for the CLI. Order: --password-stdin (one line) → --password-file → --password-env VAR
//! → $CRYPTO_PASSWORD → interactive prompt (only when stdin is a terminal). Passphrases are NFC-normalised
//! like the desktop app's `SecurePasswordField`.
use crate::error::{AppError, Result};
use clap::Args;
use std::io::{BufRead, IsTerminal, Read};
use std::path::{Path, PathBuf};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

pub const PASSWORD_ENV: &str = "CRYPTO_PASSWORD";
pub const MIN_PW_LENGTH_ENV: &str = "CRYPTO_MIN_PW_LENGTH";
pub const DEFAULT_MIN_PW_LENGTH: usize = 8;
pub const MAX_PASSWORD_FILE_BYTES: u64 = 5000;

#[derive(Args, Debug, Clone, Default)]
pub struct PasswordArgs {
    /// Read the password from the next line of standard input
    #[arg(long, group = "password-source")]
    pub password_stdin: bool,
    /// Read the password from a file (at most 5000 bytes; one trailing newline is removed)
    #[arg(long, value_name = "FILE", group = "password-source")]
    pub password_file: Option<PathBuf>,
    /// Read the password from the named environment variable (default: CRYPTO_PASSWORD)
    #[arg(long, value_name = "VAR", group = "password-source")]
    pub password_env: Option<String>,
}

#[derive(Args, Debug, Clone, Default)]
pub struct NewPasswordArgs {
    /// Read the new password from the next line of standard input
    #[arg(long, group = "new-password-source")]
    pub new_password_stdin: bool,
    /// Read the new password from a file
    #[arg(long, value_name = "FILE", group = "new-password-source")]
    pub new_password_file: Option<PathBuf>,
    /// Read the new password from the named environment variable
    #[arg(long, value_name = "VAR", group = "new-password-source")]
    pub new_password_env: Option<String>,
}

impl From<&NewPasswordArgs> for PasswordArgs {
    fn from(args: &NewPasswordArgs) -> Self {
        Self { password_stdin: args.new_password_stdin, password_file: args.new_password_file.clone(), password_env: args.new_password_env.clone() }
    }
}

/// Abstraction over stdin, environment and terminal prompting so the resolution logic is testable.
pub trait PasswordIo {
    /// One line of stdin including its line ending; `None` at EOF.
    fn read_stdin_line(&mut self) -> std::io::Result<Option<String>>;
    fn env(&self, name: &str) -> Option<String>;
    /// `None` when not interactive.
    fn prompt(&mut self, prompt: &str) -> std::io::Result<Option<String>>;
}

#[derive(Debug, Default)]
pub struct SystemIo;

impl PasswordIo for SystemIo {
    fn read_stdin_line(&mut self) -> std::io::Result<Option<String>> {
        let mut line = String::new();
        let read = std::io::stdin().lock().read_line(&mut line)?;
        Ok((read > 0).then_some(line))
    }

    fn env(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }

    fn prompt(&mut self, prompt: &str) -> std::io::Result<Option<String>> {
        if !std::io::stdin().is_terminal() {
            return Ok(None);
        }
        rpassword::prompt_password(prompt).map(Some)
    }
}

pub fn normalize_passphrase(raw: &str) -> Zeroizing<String> {
    Zeroizing::new(raw.nfc().collect())
}

fn strip_line_ending(mut line: String) -> String {
    if line.ends_with('\n') {
        line.pop();
        if line.ends_with('\r') {
            line.pop();
        }
    }
    line
}

fn read_password_file(path: &Path) -> Result<Zeroizing<String>> {
    let file = std::fs::File::open(path)?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_PASSWORD_FILE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_PASSWORD_FILE_BYTES {
        return Err(AppError::InvalidValue { key: "--password-file".to_string(), message: format!("file is larger than {MAX_PASSWORD_FILE_BYTES} bytes") });
    }
    let text = String::from_utf8(bytes.to_vec()).map_err(|_| AppError::InvalidValue { key: "--password-file".to_string(), message: "file is not valid UTF-8".to_string() })?;
    Ok(Zeroizing::new(strip_line_ending(text)))
}

fn read_raw(args: &PasswordArgs, prompt: &str, io: &mut dyn PasswordIo) -> Result<Zeroizing<String>> {
    if args.password_stdin {
        return io.read_stdin_line()?.map(|line| Zeroizing::new(strip_line_ending(line))).ok_or(AppError::NoPasswordSource);
    }
    if let Some(file) = &args.password_file {
        return read_password_file(file);
    }
    if let Some(var) = &args.password_env {
        return io.env(var).map(Zeroizing::new).ok_or_else(|| AppError::InvalidValue { key: "--password-env".to_string(), message: format!("environment variable {var} is not set") });
    }
    if let Some(value) = io.env(PASSWORD_ENV) {
        return Ok(Zeroizing::new(value));
    }
    io.prompt(prompt)?.map(Zeroizing::new).ok_or(AppError::NoPasswordSource)
}

pub fn read_passphrase(args: &PasswordArgs, prompt: &str, io: &mut dyn PasswordIo) -> Result<Zeroizing<String>> {
    let raw = read_raw(args, prompt, io)?;
    Ok(normalize_passphrase(&raw))
}

/// For new passwords: interactive input is asked twice and compared; every source enforces `min_len` characters.
pub fn read_new_passphrase(args: &PasswordArgs, prompt: &str, min_len: usize, io: &mut dyn PasswordIo) -> Result<Zeroizing<String>> {
    let interactive = !args.password_stdin && args.password_file.is_none() && args.password_env.is_none() && io.env(PASSWORD_ENV).is_none();
    let passphrase = read_passphrase(args, prompt, io)?;
    if passphrase.chars().count() < min_len {
        return Err(AppError::PasswordTooShort(min_len));
    }
    if interactive {
        let confirmation = io.prompt("Confirm password: ")?.map(|c| normalize_passphrase(&c)).ok_or(AppError::NoPasswordSource)?;
        if *confirmation != *passphrase {
            return Err(AppError::PasswordMismatch);
        }
    }
    Ok(passphrase)
}

/// `cryptomator.minPwLength` (default 8), overridable with `CRYPTO_MIN_PW_LENGTH`.
pub fn min_password_length() -> usize {
    std::env::var(MIN_PW_LENGTH_ENV).ok().and_then(|v| v.parse().ok()).unwrap_or(DEFAULT_MIN_PW_LENGTH)
}
```

```rust
// crates/cryptomator-app/src/mounters.rs
//! Short CLI aliases for the Java mount-service class names stored in settings.json.
use crate::error::{AppError, Result};

pub const MOUNTER_ALIASES: &[(&str, &str)] = &[
    ("fuse-t", "org.cryptomator.frontend.fuse.mount.FuseTMountProvider"),
    ("macfuse", "org.cryptomator.frontend.fuse.mount.MacFuseMountProvider"),
    ("fuse", "org.cryptomator.frontend.fuse.mount.LinuxFuseMountProvider"),
    ("webdav", "org.cryptomator.frontend.webdav.mount.FallbackMounter"),
];

/// Alias (case-insensitive) or a fully qualified Java class name (must contain a dot).
pub fn resolve_mounter(input: &str) -> Result<String> {
    let lowered = input.to_lowercase();
    if let Some((_, class)) = MOUNTER_ALIASES.iter().find(|(alias, _)| *alias == lowered) {
        return Ok((*class).to_string());
    }
    if input.contains('.') {
        return Ok(input.to_string());
    }
    Err(AppError::InvalidValue {
        key: "mounter".to_string(),
        message: format!("unknown mounter {input:?}; use one of {} or a Java class name", MOUNTER_ALIASES.iter().map(|(a, _)| *a).collect::<Vec<_>>().join(", ")),
    })
}

pub fn alias_for(class_name: &str) -> Option<&'static str> {
    MOUNTER_ALIASES.iter().find(|(_, class)| *class == class_name).map(|(alias, _)| *alias)
}
```

Extend `lib.rs`: `pub mod mounters; pub mod password;` and `pub use password::{min_password_length, normalize_passphrase, read_new_passphrase, read_passphrase, NewPasswordArgs, PasswordArgs, PasswordIo, SystemIo};` as well as `pub use mounters::{alias_for, resolve_mounter};`.

- [ ] **Step 4: Run tests**

Run: `cargo test -p cryptomator-app -- password mounters`
Expected: PASS (7 tests)

- [ ] **Step 5: Full run and commit**

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked`
Expected: PASS

```bash
git add Cargo.lock crates/cryptomator-app
git commit -m "Add password source resolution and mounter aliases

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 10: CLI scaffolding and `vault create/add/remove/list/info`

**Files:**
- Modify: `crates/crypto/Cargo.toml`, `crates/crypto/src/cli.rs`, `crates/crypto/src/main.rs`, `crates/crypto/tests/cli.rs`
- Create: `crates/crypto/src/exit.rs`, `crates/crypto/src/output.rs`, `crates/crypto/src/commands/mod.rs`, `crates/crypto/src/commands/vault.rs`

**Interfaces:**
- Consumes: `cryptomator_app::{SettingsStore, SettingsJson, VaultSettingsJson, generate_id, normalize_vault_path, resolve_vault_index, read_new_passphrase, min_password_length, PasswordArgs, SystemIo, AppError}`, `cryptomator_core::{create_vault, CreateVaultOptions, CipherCombo, MasterkeyFileAccess, OsRng, assert_is_vault_directory, determine_vault_state, read_vault_config, KeyId, recovery::{create_recovery_key, WordEncoder}}`.
- Produces: `exit::{OK, GENERAL, USAGE, VAULT_NOT_FOUND, INVALID_PASSPHRASE, WRONG_STATE, HUB_VAULT, NOT_A_VAULT, code_for(&anyhow::Error) -> u8}`; `Output { json: bool }` with `emit(&self, value: serde_json::Value, human: impl FnOnce() -> String) -> anyhow::Result<()>`; `commands::Ctx { store: SettingsStore, out: Output }`; `commands::vault::{create, add, remove, list, info, vault_json(&VaultSettingsJson) -> serde_json::Value, key_loader_scheme(&Path) -> Option<String>}`; `cli::{Cli, Command, VaultCommand, CreateArgs, AddArgs}` (recovery-key validate stays).

- [ ] **Step 1: Dependencies**

Extend `crates/crypto/Cargo.toml` `[dependencies]`: `serde_json.workspace = true`. Extend `[dev-dependencies]`: `tempfile.workspace = true`, `serde_json.workspace = true`.

- [ ] **Step 2: Write failing tests**

`crates/crypto/tests/cli.rs` – the existing tests stay; append the following:

```rust
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const PW: &str = "test-password-123";

struct Sandbox {
    dir: TempDir,
}

impl Sandbox {
    fn new() -> Self {
        Self { dir: tempfile::tempdir().unwrap() }
    }
    fn settings(&self) -> PathBuf {
        self.dir.path().join("settings.json")
    }
    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
    /// `crypto --settings <sandbox> <args>` with CRYPTO_PASSWORD set and no inherited password variables.
    fn crypto(&self, args: &[&str]) -> Command {
        let mut cmd = Command::cargo_bin("crypto").unwrap();
        cmd.env_remove("CRYPTO_SETTINGS_PATH").env_remove("CRYPTO_MIN_PW_LENGTH").env("CRYPTO_PASSWORD", PW);
        cmd.arg("--settings").arg(self.settings());
        cmd.args(args);
        cmd
    }
    fn settings_json(&self) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(self.settings()).unwrap()).unwrap()
    }
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures").join(name)
}

#[test]
fn vault_create_registers_and_writes_vault_files() {
    let sb = Sandbox::new();
    let vault = sb.path("MyVault");
    sb.crypto(&["vault", "create", vault.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Created vault"));
    assert!(vault.join("vault.cryptomator").is_file());
    assert!(vault.join("masterkey.cryptomator").is_file());
    assert!(vault.join("IMPORTANT.rtf").is_file());
    assert!(vault.join("d").is_dir());
    let json = sb.settings_json();
    let dirs = json["directories"].as_array().unwrap();
    assert_eq!(dirs.len(), 1);
    assert_eq!(dirs[0]["id"].as_str().unwrap().len(), 12);
    assert_eq!(dirs[0]["displayName"], "MyVault");
    assert_eq!(dirs[0]["path"], vault.canonicalize().unwrap().to_str().unwrap());
    assert_eq!(dirs[0]["lastKnownKeyLoader"], "masterkeyfile");
    assert_eq!(json["useKeychain"], true, "new files carry the Java defaults");
}

#[test]
fn vault_create_json_output_and_recovery_key() {
    let sb = Sandbox::new();
    let vault = sb.path("v");
    let out = sb.crypto(&["--json", "vault", "create", "--name", "Nice Name", "--shortening-threshold", "100", "--show-recovery-key", vault.to_str().unwrap()])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(json["displayName"], "Nice Name");
    assert_eq!(json["cipherCombo"], "SIV_GCM");
    assert_eq!(json["shorteningThreshold"], 100);
    assert_eq!(json["recoveryKey"].as_str().unwrap().split(' ').count(), 44);
    assert_eq!(json["id"].as_str().unwrap().len(), 12);
}

#[test]
fn vault_create_rejects_existing_dir_short_password_and_missing_source() {
    let sb = Sandbox::new();
    sb.crypto(&["vault", "create", sb.dir.path().to_str().unwrap()]).assert().code(1);
    sb.crypto(&["vault", "create", sb.path("x").to_str().unwrap()]).env("CRYPTO_PASSWORD", "short").assert().code(4);
    sb.crypto(&["vault", "create", sb.path("y").to_str().unwrap()]).env_remove("CRYPTO_PASSWORD").assert().code(2);
    assert!(!sb.path("x").exists() && !sb.path("y").exists());
}

#[test]
fn vault_add_list_info_remove() {
    let sb = Sandbox::new();
    let fixture_path = fixture("siv_gcm_basic");
    let out = sb.crypto(&["--json", "vault", "add", "--name", "Basic", fixture_path.to_str().unwrap()]).assert().success().get_output().stdout.clone();
    let id = serde_json::from_slice::<serde_json::Value>(&out).unwrap()["id"].as_str().unwrap().to_string();
    sb.crypto(&["vault", "add", fixture_path.to_str().unwrap()]).assert().code(5).stderr(predicate::str::contains("already registered"));
    sb.crypto(&["vault", "add", sb.dir.path().to_str().unwrap()]).assert().code(12);

    sb.crypto(&["vault", "list"]).assert().success().stdout(predicate::str::contains(&id).and(predicate::str::contains("LOCKED")).and(predicate::str::contains("Basic")));
    let out = sb.crypto(&["--json", "vault", "list"]).assert().success().get_output().stdout.clone();
    let list: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert_eq!(list[0]["state"], "LOCKED");

    let out = sb.crypto(&["--json", "vault", "info", "Basic"]).assert().success().get_output().stdout.clone();
    let info: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(info["id"], id);
    assert_eq!(info["cipherCombo"], "SIV_GCM");
    assert_eq!(info["shorteningThreshold"], 220);
    assert_eq!(info["format"], 8);
    assert_eq!(info["keyType"], "masterkeyfile");
    assert_eq!(info["keyId"], "masterkeyfile:masterkey.cryptomator");
    assert_eq!(info["port"], 42427);
    sb.crypto(&["vault", "info", "basic"]).assert().success();
    sb.crypto(&["vault", "info", "nope"]).assert().code(3);

    sb.crypto(&["vault", "remove", &id]).assert().success();
    assert!(sb.settings_json()["directories"].as_array().unwrap().is_empty());
    assert!(fixture_path.join("vault.cryptomator").is_file(), "remove never deletes vault files");
}

#[test]
fn vault_info_detects_hub_vaults() {
    let sb = Sandbox::new();
    let vault = sb.path("hub");
    std::fs::create_dir_all(vault.join("d")).unwrap();
    // header {"kid":"hub+https://hub.example.com/api/vaults/1","alg":"HS256","typ":"JWT"}, unsigned-looking payload; info never verifies
    std::fs::write(vault.join("vault.cryptomator"), "eyJraWQiOiJodWIraHR0cHM6Ly9odWIuZXhhbXBsZS5jb20vYXBpL3ZhdWx0cy8xIiwiYWxnIjoiSFMyNTYiLCJ0eXAiOiJKV1QifQ.eyJqdGkiOiJ4IiwiZm9ybWF0Ijo4LCJjaXBoZXJDb21ibyI6IlNJVl9HQ00iLCJzaG9ydGVuaW5nVGhyZXNob2xkIjoyMjB9.AAAA").unwrap();
    sb.crypto(&["vault", "add", vault.to_str().unwrap()]).assert().success();
    let out = sb.crypto(&["--json", "vault", "info", "hub"]).assert().success().get_output().stdout.clone();
    let info: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(info["keyType"], "hub");
    assert_eq!(sb.settings_json()["directories"][0]["lastKnownKeyLoader"], "hub+https");
}
```

- [ ] **Step 3: Run tests, confirm failure**

Run: `cargo test -p crypto`
Expected: FAIL (subcommand `vault` unknown)

- [ ] **Step 4: Implement**

```rust
// crates/crypto/src/exit.rs
//! Exit codes from the design spec and the mapping from error types.
use cryptomator_app::AppError;
use cryptomator_core::CoreError;

pub const OK: u8 = 0;
pub const GENERAL: u8 = 1;
pub const USAGE: u8 = 2;
pub const VAULT_NOT_FOUND: u8 = 3;
pub const INVALID_PASSPHRASE: u8 = 4;
pub const WRONG_STATE: u8 = 5;
pub const HUB_VAULT: u8 = 9;
pub const NOT_A_VAULT: u8 = 12;

fn core_code(err: &CoreError) -> u8 {
    match err {
        CoreError::InvalidPassphrase | CoreError::InvalidRecoveryKey(_) | CoreError::VaultKeyInvalid | CoreError::AuthenticationFailed(_) => INVALID_PASSPHRASE,
        CoreError::HubVaultUnsupported(_) => HUB_VAULT,
        CoreError::NotAVaultDirectory { .. } => NOT_A_VAULT,
        CoreError::NeedsMigration(_) | CoreError::ContentRootMissing(_) | CoreError::VaultVersionMismatch { .. } => WRONG_STATE,
        CoreError::InvalidArgument(_) => USAGE,
        _ => GENERAL,
    }
}

pub fn code_for(err: &anyhow::Error) -> u8 {
    if let Some(app) = err.downcast_ref::<AppError>() {
        return match app {
            AppError::Core(core) => core_code(core),
            AppError::VaultNotFound(_) | AppError::AmbiguousVault(..) => VAULT_NOT_FOUND,
            AppError::PasswordTooShort(_) | AppError::PasswordMismatch => INVALID_PASSPHRASE,
            AppError::WrongState { .. } | AppError::VaultAlreadyAdded(_) => WRONG_STATE,
            AppError::NoPasswordSource | AppError::InvalidValue { .. } => USAGE,
            AppError::Io(_) | AppError::SettingsCorrupt { .. } | AppError::NoHomeDirectory => GENERAL,
        };
    }
    if let Some(core) = err.downcast_ref::<CoreError>() {
        return core_code(core);
    }
    GENERAL
}
```

```rust
// crates/crypto/src/output.rs
//! Human vs. `--json` output.
#[derive(Debug, Clone, Copy)]
pub struct Output {
    pub json: bool,
}

impl Output {
    pub fn emit(&self, value: serde_json::Value, human: impl FnOnce() -> String) -> anyhow::Result<()> {
        if self.json {
            println!("{}", serde_json::to_string_pretty(&value)?);
        } else {
            let text = human();
            if !text.is_empty() {
                println!("{text}");
            }
        }
        Ok(())
    }
}
```

```rust
// crates/crypto/src/commands/mod.rs
//! Command implementations; each returns the process exit code.
pub mod vault;

use crate::output::Output;
use cryptomator_app::SettingsStore;

#[derive(Debug)]
pub struct Ctx {
    pub store: SettingsStore,
    pub out: Output,
}
```

```rust
// crates/crypto/src/commands/vault.rs
//! `crypto vault create|add|remove|list|info`
use crate::cli::{AddArgs, CreateArgs};
use crate::commands::Ctx;
use crate::exit;
use anyhow::Result;
use cryptomator_app::{generate_id, min_password_length, normalize_vault_path, read_new_passphrase, resolve_vault_index, AppError, SystemIo, VaultSettingsJson};
use cryptomator_core::recovery::{create_recovery_key, WordEncoder};
use cryptomator_core::{assert_is_vault_directory, create_vault, determine_vault_state, read_vault_config, CipherCombo, CreateVaultOptions, KeyId, MasterkeyFileAccess, OsRng};
use serde_json::{json, Value};
use std::path::Path;

/// `VaultListManager.initializeLastKnownKeyLoaderIfPossible`: the scheme of the config's key id.
pub fn key_loader_scheme(vault_path: &Path) -> Option<String> {
    let key_id = read_vault_config(vault_path).ok()?.key_id().ok()?;
    Some(match key_id {
        KeyId::MasterkeyFile { .. } => "masterkeyfile".to_string(),
        KeyId::Hub { uri } | KeyId::Other(uri) => uri.split(':').next().unwrap_or_default().to_string(),
    })
}

fn state_of(vault: &VaultSettingsJson) -> String {
    match vault.path_buf().map(|p| determine_vault_state(&p)) {
        Some(Ok(state)) => state.as_str().to_string(),
        _ => "ERROR".to_string(),
    }
}

pub fn vault_json(vault: &VaultSettingsJson) -> Value {
    let mut value = json!({
        "id": vault.id,
        "displayName": vault.display_name,
        "path": vault.path,
        "state": state_of(vault),
        "mountPoint": vault.mount_point,
        "usesReadOnlyMode": vault.uses_read_only_mode,
        "mountFlags": vault.mount_flags,
        "mountService": vault.mount_service,
        "port": vault.port,
        "autoLockWhenIdle": vault.auto_lock_when_idle,
        "autoLockIdleSeconds": vault.auto_lock_idle_seconds,
        "maxCleartextFilenameLength": vault.max_cleartext_filename_length,
        "actionAfterUnlock": vault.action_after_unlock.as_str(),
        "lastKnownKeyLoader": vault.last_known_key_loader,
    });
    if let Some(config) = vault.path_buf().and_then(|p| read_vault_config(&p).ok()) {
        let key_type = match config.key_id() {
            Ok(KeyId::MasterkeyFile { .. }) => "masterkeyfile",
            Ok(KeyId::Hub { .. }) => "hub",
            _ => "other",
        };
        value["format"] = json!(config.alleged_vault_version());
        value["shorteningThreshold"] = json!(config.alleged_shortening_threshold());
        value["cipherCombo"] = json!(config.alleged_cipher_combo());
        value["keyId"] = json!(config.key_id().map(|k| k.to_string()).ok());
        value["keyType"] = json!(key_type);
    }
    value
}

fn human_info(value: &Value) -> String {
    let order = ["id", "displayName", "path", "state", "keyType", "keyId", "format", "cipherCombo", "shorteningThreshold", "mountPoint", "mountService", "mountFlags", "usesReadOnlyMode", "port", "autoLockWhenIdle", "autoLockIdleSeconds", "maxCleartextFilenameLength", "actionAfterUnlock", "lastKnownKeyLoader"];
    order
        .iter()
        .filter_map(|key| value.get(*key).map(|v| (key, v)))
        .map(|(key, v)| match v {
            Value::String(s) => format!("{key}: {s}"),
            Value::Null => format!("{key}: -"),
            other => format!("{key}: {other}"),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn register(ctx: &Ctx, path: &Path, name: Option<String>) -> Result<VaultSettingsJson> {
    let path = normalize_vault_path(path);
    let scheme = key_loader_scheme(&path);
    let registered = ctx.store.update(|settings| {
        if settings.directories.iter().any(|v| v.path_buf().is_some_and(|p| normalize_vault_path(&p) == path)) {
            return Err(AppError::VaultAlreadyAdded(path.clone()));
        }
        let mut vault = VaultSettingsJson::new(generate_id(&mut OsRng), &path);
        if let Some(name) = name {
            vault.display_name = Some(name);
        }
        vault.last_known_key_loader = scheme.clone();
        settings.directories.push(vault.clone());
        Ok(vault)
    })?;
    Ok(registered)
}

pub fn create(ctx: &Ctx, args: CreateArgs) -> Result<u8> {
    let cipher_combo: CipherCombo = args.cipher_combo.parse()?;
    let path = normalize_vault_path(&args.path);
    let passphrase = read_new_passphrase(&args.password, "Password for the new vault: ", min_password_length(), &mut SystemIo)?;
    let options = CreateVaultOptions { cipher_combo, shortening_threshold: args.shortening_threshold, write_readme_files: true };
    let masterkey = create_vault(&path, &passphrase, &options, &MasterkeyFileAccess::new(Vec::new()), &mut OsRng)?;
    let recovery_key = args.show_recovery_key.then(|| create_recovery_key(&WordEncoder::new(), masterkey.raw()));
    let registered = if args.no_register { None } else { Some(register(ctx, &path, args.name.clone())?) };
    let display_name = registered.as_ref().and_then(|v| v.display_name.clone()).or(args.name.clone());
    let value = json!({
        "id": registered.as_ref().map(|v| v.id.clone()),
        "path": path,
        "displayName": display_name,
        "cipherCombo": cipher_combo.as_str(),
        "shorteningThreshold": args.shortening_threshold,
        "recoveryKey": recovery_key.as_deref().map(|k| k.to_string()),
    });
    ctx.out.emit(value, || {
        let mut lines = vec![format!("Created vault at {}", path.display())];
        if let Some(v) = &registered {
            lines.push(format!("Registered as {} ({})", v.id, v.display_name.clone().unwrap_or_default()));
        }
        if let Some(key) = &recovery_key {
            lines.push(format!("Recovery key: {}", key.as_str()));
        }
        lines.join("\n")
    })?;
    Ok(exit::OK)
}

pub fn add(ctx: &Ctx, args: AddArgs) -> Result<u8> {
    let path = normalize_vault_path(&args.path);
    assert_is_vault_directory(&path)?;
    let vault = register(ctx, &path, args.name)?;
    ctx.out.emit(vault_json(&vault), || format!("Registered {} as {} ({})", path.display(), vault.id, vault.display_name.clone().unwrap_or_default()))?;
    Ok(exit::OK)
}

pub fn remove(ctx: &Ctx, reference: &str) -> Result<u8> {
    let removed = ctx.store.update(|settings| {
        let index = resolve_vault_index(settings, reference)?;
        Ok(settings.directories.remove(index))
    })?;
    ctx.out.emit(json!({ "id": removed.id, "path": removed.path }), || format!("Removed {} from the vault list (files kept)", removed.id))?;
    Ok(exit::OK)
}

pub fn list(ctx: &Ctx) -> Result<u8> {
    let settings = ctx.store.load()?;
    let rows: Vec<Value> = settings.directories.iter().map(vault_json).collect();
    ctx.out.emit(Value::Array(rows.clone()), || {
        if rows.is_empty() {
            return "No vaults registered. Use `crypto vault create` or `crypto vault add`.".to_string();
        }
        let mut lines = vec![format!("{:<12}  {:<20}  {:<20}  PATH", "ID", "STATE", "NAME")];
        for row in &rows {
            let s = |key: &str| row[key].as_str().unwrap_or("-").to_string();
            lines.push(format!("{:<12}  {:<20}  {:<20}  {}", s("id"), s("state"), s("displayName"), s("path")));
        }
        lines.join("\n")
    })?;
    Ok(exit::OK)
}

pub fn info(ctx: &Ctx, reference: &str) -> Result<u8> {
    let settings = ctx.store.load()?;
    let index = resolve_vault_index(&settings, reference)?;
    let value = vault_json(&settings.directories[index]);
    ctx.out.emit(value.clone(), || human_info(&value))?;
    Ok(exit::OK)
}
```

`vault_json` uses `UnverifiedVaultConfig::alleged_cipher_combo()`, which does not exist yet: add it to `crates/cryptomator-core/src/vault_config.rs` (next to `alleged_shortening_threshold`):

```rust
    pub fn alleged_cipher_combo(&self) -> Option<String> {
        self.claims.get(CLAIM_CIPHER_COMBO).and_then(Value::as_str).map(str::to_string)
    }
```

```rust
// crates/crypto/src/cli.rs
//! Command grammar of `crypto`.
use clap::{Args, Parser, Subcommand};
use cryptomator_app::PasswordArgs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "crypto", version, about = "Cryptomator vaults from the command line", arg_required_else_help = true)]
pub struct Cli {
    /// Path to settings.json (default: the Cryptomator desktop app's file, or $CRYPTO_SETTINGS_PATH)
    #[arg(long, global = true, value_name = "PATH")]
    pub settings: Option<PathBuf>,
    /// Machine-readable JSON output
    #[arg(long, global = true)]
    pub json: bool,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Create, register and inspect vaults
    Vault {
        #[command(subcommand)]
        command: VaultCommand,
    },
    /// Show, validate or use recovery keys
    #[command(name = "recovery-key")]
    RecoveryKey {
        #[command(subcommand)]
        command: RecoveryKeyCommand,
    },
}

#[derive(Subcommand, Debug)]
pub enum VaultCommand {
    /// Create a new vault directory and register it
    Create(CreateArgs),
    /// Register an existing vault directory
    Add(AddArgs),
    /// Unregister a vault (its files are kept)
    Remove {
        /// Vault id, display name or path
        vault: String,
    },
    /// List registered vaults with their state
    List,
    /// Show settings and configuration of a vault
    Info {
        /// Vault id, display name or path
        vault: String,
    },
}

#[derive(Args, Debug)]
pub struct CreateArgs {
    /// Directory to create (must not exist yet)
    pub path: PathBuf,
    /// Display name (default: directory name)
    #[arg(long)]
    pub name: Option<String>,
    /// Ciphertext file name length above which names are shortened (36-220)
    #[arg(long, default_value_t = 220, value_parser = clap::value_parser!(u32).range(36..=220))]
    pub shortening_threshold: u32,
    #[arg(long, hide = true, default_value = "SIV_GCM")]
    pub cipher_combo: String,
    /// Print the recovery key after creation
    #[arg(long)]
    pub show_recovery_key: bool,
    /// Do not add the vault to settings.json
    #[arg(long)]
    pub no_register: bool,
    #[command(flatten)]
    pub password: PasswordArgs,
}

#[derive(Args, Debug)]
pub struct AddArgs {
    /// Existing vault directory (contains vault.cryptomator)
    pub path: PathBuf,
    /// Display name (default: directory name)
    #[arg(long)]
    pub name: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum RecoveryKeyCommand {
    /// Check whether a recovery key is well-formed (dictionary words, length, checksum)
    Validate(ValidateArgs),
}

#[derive(Args, Debug)]
pub struct ValidateArgs {
    /// Read the recovery key from standard input
    #[arg(long, required = true)]
    pub recovery_key_stdin: bool,
}
```

```rust
// crates/crypto/src/main.rs
//! `crypto` – Cryptomator command line interface.
mod cli;
mod commands;
mod exit;
mod output;

use clap::Parser;
use cli::{Cli, Command, RecoveryKeyCommand, VaultCommand};
use commands::Ctx;
use cryptomator_app::SettingsStore;
use cryptomator_core::recovery::{validate_recovery_key, WordEncoder};
use output::Output;
use std::io::Read;
use std::process::ExitCode;
use zeroize::Zeroizing;

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            let _ = err.print();
            return match err.kind() {
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion => ExitCode::from(exit::OK),
                _ => ExitCode::from(exit::USAGE),
            };
        }
    };
    match run(cli) {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(exit::code_for(&err))
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<u8> {
    let store = match cli.settings {
        Some(path) => SettingsStore::at(path),
        None => SettingsStore::from_env_or_default()?,
    };
    let ctx = Ctx { store, out: Output { json: cli.json } };
    match cli.command {
        Command::Vault { command } => match command {
            VaultCommand::Create(args) => commands::vault::create(&ctx, args),
            VaultCommand::Add(args) => commands::vault::add(&ctx, args),
            VaultCommand::Remove { vault } => commands::vault::remove(&ctx, &vault),
            VaultCommand::List => commands::vault::list(&ctx),
            VaultCommand::Info { vault } => commands::vault::info(&ctx, &vault),
        },
        Command::RecoveryKey { command: RecoveryKeyCommand::Validate(args) } => {
            debug_assert!(args.recovery_key_stdin);
            let mut input = Zeroizing::new(String::new());
            std::io::stdin().read_to_string(&mut input)?;
            let recovery_key: &str = input.trim();
            if validate_recovery_key(&WordEncoder::new(), recovery_key) {
                println!("valid");
                Ok(exit::OK)
            } else {
                println!("invalid");
                Ok(exit::INVALID_PASSPHRASE)
            }
        }
    }
}
```

Note on `vault_info_detects_hub_vaults`: the embedded token has the header `{"kid":"hub+https://hub.example.com/api/vaults/1","alg":"HS256","typ":"JWT"}`; `vault add` only checks the directory structure, `info` reads the config unverified – so any signature will do.

- [ ] **Step 5: Run tests**

Run: `cargo test -p crypto`
Expected: PASS (10 tests: 5 existing + 5 new). The `vault_create_*` tests take ~0.5 s each because of scrypt.

- [ ] **Step 6: Gate and commit**

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked`
Expected: PASS

```bash
git add Cargo.lock crates/crypto crates/cryptomator-core/src/vault_config.rs
git commit -m "Add crypto vault create/add/remove/list/info commands

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 11: `vault set` and `config get/set`

**Files:**
- Modify: `crates/crypto/src/cli.rs`, `crates/crypto/src/main.rs`, `crates/crypto/src/commands/mod.rs`, `crates/crypto/tests/cli.rs`
- Create: `crates/crypto/src/commands/config.rs`; `commands/vault.rs` gains `set`

**Interfaces:**
- Consumes: `resolve_mounter`, `alias_for`, `WhenUnlocked::parse`, `resolve_vault_index`, `SettingsStore::update`, `vault_json`.
- Produces: `cli::SetArgs`, `cli::ConfigCommand::{Get { key: Option<String> }, Set { key: String, value: String }}`; `commands::vault::set(&Ctx, SetArgs) -> Result<u8>`; `commands::config::{get, set}`; configuration keys `mountService`, `port`, `useKeychain`, `keychainProvider`, `debugMode`.

- [ ] **Step 1: Write failing tests**

```rust
// append to crates/crypto/tests/cli.rs
#[test]
fn vault_set_updates_settings() {
    let sb = Sandbox::new();
    sb.crypto(&["vault", "add", "--name", "B", fixture("siv_gcm_basic").to_str().unwrap()]).assert().success();
    sb.crypto(&["vault", "set", "B", "--name", "Renamed", "--mount-point", "/tmp/mnt-b", "--read-only", "true", "--mount-flags", "-o foo", "--mounter", "webdav", "--port", "8080", "--auto-lock-idle", "300", "--max-filename-length", "146", "--action-after-unlock", "REVEAL"])
        .assert()
        .success();
    let v = sb.settings_json()["directories"][0].clone();
    assert_eq!(v["displayName"], "Renamed");
    assert_eq!(v["mountPoint"], "/tmp/mnt-b");
    assert_eq!(v["usesReadOnlyMode"], true);
    assert_eq!(v["mountFlags"], "-o foo");
    assert_eq!(v["mountService"], "org.cryptomator.frontend.webdav.mount.FallbackMounter");
    assert_eq!(v["port"], 8080);
    assert_eq!(v["autoLockWhenIdle"], true);
    assert_eq!(v["autoLockIdleSeconds"], 300);
    assert_eq!(v["maxCleartextFilenameLength"], 146);
    assert_eq!(v["actionAfterUnlock"], "REVEAL");

    sb.crypto(&["vault", "set", "Renamed", "--no-mount-point", "--default-mount-flags", "--mounter", "default", "--no-auto-lock", "--max-filename-length", "auto", "--read-only", "false"]).assert().success();
    let v = sb.settings_json()["directories"][0].clone();
    assert!(v.get("mountPoint").is_none());
    assert_eq!(v["mountFlags"], "");
    assert!(v.get("mountService").is_none());
    assert_eq!(v["autoLockWhenIdle"], false);
    assert_eq!(v["maxCleartextFilenameLength"], -1);
    assert_eq!(v["usesReadOnlyMode"], false);

    sb.crypto(&["vault", "set", "Renamed", "--mounter", "bogus"]).assert().code(2);
    sb.crypto(&["vault", "set", "Renamed", "--action-after-unlock", "DANCE"]).assert().code(2);
    sb.crypto(&["vault", "set", "missing", "--name", "x"]).assert().code(3);
}

#[test]
fn config_get_and_set() {
    let sb = Sandbox::new();
    let out = sb.crypto(&["--json", "config", "get"]).assert().success().get_output().stdout.clone();
    let cfg: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(cfg["port"], 42427);
    assert_eq!(cfg["useKeychain"], true);
    assert!(cfg["mountService"].is_null());

    sb.crypto(&["config", "set", "mountService", "fuse-t"]).assert().success();
    sb.crypto(&["config", "set", "port", "42428"]).assert().success();
    sb.crypto(&["config", "set", "useKeychain", "false"]).assert().success();
    sb.crypto(&["config", "set", "debugMode", "true"]).assert().success();
    sb.crypto(&["config", "set", "keychainProvider", "org.example.Keychain"]).assert().success();
    sb.crypto(&["config", "get", "mountService"]).assert().success().stdout(predicate::str::contains("org.cryptomator.frontend.fuse.mount.FuseTMountProvider"));
    let json = sb.settings_json();
    assert_eq!(json["port"], 42428);
    assert_eq!(json["useKeychain"], false);
    assert_eq!(json["debugMode"], true);
    assert_eq!(json["keychainProvider"], "org.example.Keychain");

    sb.crypto(&["config", "set", "mountService", "default"]).assert().success();
    assert!(sb.settings_json().get("mountService").is_none());
    sb.crypto(&["config", "set", "port", "70000"]).assert().code(2);
    sb.crypto(&["config", "set", "theme", "DARK"]).assert().code(2);
    sb.crypto(&["config", "get", "theme"]).assert().code(2);
}
```

- [ ] **Step 2: Run tests, confirm failure**

Run: `cargo test -p crypto -- vault_set config_get`
Expected: FAIL (subcommands missing)

- [ ] **Step 3: Implement**

In `cli.rs`: extend `VaultCommand` with `/// Change per-vault settings\n Set(SetArgs)`, `Command` with `/// Global settings (settings.json)\n Config { #[command(subcommand)] command: ConfigCommand }`, and add:

```rust
#[derive(Args, Debug)]
pub struct SetArgs {
    /// Vault id, display name or path
    pub vault: String,
    /// New display name
    #[arg(long)]
    pub name: Option<String>,
    /// Mount point directory (absolute path)
    #[arg(long, value_name = "PATH", conflicts_with = "no_mount_point")]
    pub mount_point: Option<PathBuf>,
    /// Let the mounter choose the mount point
    #[arg(long)]
    pub no_mount_point: bool,
    /// Mount read-only (true|false)
    #[arg(long, value_name = "BOOL", value_parser = clap::value_parser!(bool))]
    pub read_only: Option<bool>,
    /// Custom mount flags, e.g. "-ovolname=Secret"
    #[arg(long, value_name = "FLAGS", conflicts_with = "default_mount_flags")]
    pub mount_flags: Option<String>,
    /// Use the mounter's default flags
    #[arg(long)]
    pub default_mount_flags: bool,
    /// Mounter alias (fuse-t, macfuse, fuse, webdav), Java class name, or "default"
    #[arg(long, value_name = "MOUNTER")]
    pub mounter: Option<String>,
    /// TCP port for loopback mounters (WebDAV)
    #[arg(long)]
    pub port: Option<u16>,
    /// Lock automatically after this many idle seconds
    #[arg(long, value_name = "SECONDS", conflicts_with = "no_auto_lock")]
    pub auto_lock_idle: Option<u32>,
    /// Disable idle auto-lock
    #[arg(long)]
    pub no_auto_lock: bool,
    /// Maximum cleartext file name length, or "auto" to probe on unlock
    #[arg(long, value_name = "N|auto")]
    pub max_filename_length: Option<String>,
    /// What to do after unlock: IGNORE, REVEAL or ASK
    #[arg(long, value_name = "ACTION")]
    pub action_after_unlock: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum ConfigCommand {
    /// Print one or all global settings
    Get {
        /// mountService | port | useKeychain | keychainProvider | debugMode
        key: Option<String>,
    },
    /// Change a global setting
    Set {
        key: String,
        value: String,
    },
}
```

Add to `commands/vault.rs`:

```rust
use crate::cli::SetArgs;
use cryptomator_app::{resolve_mounter, WhenUnlocked};

fn invalid(key: &str, message: impl Into<String>) -> AppError {
    AppError::InvalidValue { key: key.to_string(), message: message.into() }
}

pub fn set(ctx: &Ctx, args: SetArgs) -> Result<u8> {
    let mounter = match args.mounter.as_deref() {
        None => None,
        Some("default") | Some("") => Some(None),
        Some(other) => Some(Some(resolve_mounter(other)?)),
    };
    let action = match args.action_after_unlock.as_deref() {
        None => None,
        Some(value) => Some(WhenUnlocked::parse(value).ok_or_else(|| invalid("--action-after-unlock", "expected IGNORE, REVEAL or ASK"))?),
    };
    let max_name_length = match args.max_filename_length.as_deref() {
        None => None,
        Some("auto") => Some(-1),
        Some(value) => Some(value.parse::<i32>().ok().filter(|n| *n > 0).ok_or_else(|| invalid("--max-filename-length", "expected a positive number or \"auto\""))?),
    };
    let updated = ctx.store.update(|settings| {
        let index = resolve_vault_index(settings, &args.vault)?;
        let vault = &mut settings.directories[index];
        if let Some(name) = &args.name {
            vault.display_name = Some(name.clone());
        }
        if let Some(mount_point) = &args.mount_point {
            vault.mount_point = Some(mount_point.to_string_lossy().into_owned());
        }
        if args.no_mount_point {
            vault.mount_point = None;
        }
        if let Some(read_only) = args.read_only {
            vault.uses_read_only_mode = read_only;
        }
        if let Some(flags) = &args.mount_flags {
            vault.mount_flags = flags.clone();
        }
        if args.default_mount_flags {
            vault.mount_flags = String::new();
        }
        if let Some(mounter) = &mounter {
            vault.mount_service = mounter.clone();
        }
        if let Some(port) = args.port {
            vault.port = port;
        }
        if let Some(seconds) = args.auto_lock_idle {
            vault.auto_lock_when_idle = true;
            vault.auto_lock_idle_seconds = seconds;
        }
        if args.no_auto_lock {
            vault.auto_lock_when_idle = false;
        }
        if let Some(n) = max_name_length {
            vault.max_cleartext_filename_length = n;
        }
        if let Some(action) = action {
            vault.action_after_unlock = action;
        }
        Ok(vault.clone())
    })?;
    let value = vault_json(&updated);
    ctx.out.emit(value.clone(), || human_info(&value))?;
    Ok(exit::OK)
}
```

```rust
// crates/crypto/src/commands/config.rs
//! `crypto config get|set` for the global settings the CLI understands.
use crate::commands::Ctx;
use crate::exit;
use anyhow::Result;
use cryptomator_app::{resolve_mounter, AppError, SettingsJson};
use serde_json::{json, Value};

pub const KEYS: &[&str] = &["mountService", "port", "useKeychain", "keychainProvider", "debugMode"];

fn unknown_key(key: &str) -> AppError {
    AppError::InvalidValue { key: key.to_string(), message: format!("unknown setting; known: {}", KEYS.join(", ")) }
}

fn parse_bool(key: &str, value: &str) -> Result<bool, AppError> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(AppError::InvalidValue { key: key.to_string(), message: "expected true or false".to_string() }),
    }
}

pub fn config_json(settings: &SettingsJson) -> Value {
    json!({
        "mountService": settings.mount_service,
        "port": settings.port,
        "useKeychain": settings.use_keychain,
        "keychainProvider": settings.keychain_provider,
        "debugMode": settings.debug_mode,
    })
}

pub fn get(ctx: &Ctx, key: Option<&str>) -> Result<u8> {
    let settings = ctx.store.load()?;
    let all = config_json(&settings);
    match key {
        None => ctx.out.emit(all.clone(), || KEYS.iter().map(|k| format!("{k}={}", render(&all[*k]))).collect::<Vec<_>>().join("\n"))?,
        Some(key) => {
            if !KEYS.contains(&key) {
                return Err(unknown_key(key).into());
            }
            let value = all[key].clone();
            ctx.out.emit(json!({ key: value }), || render(&value))?;
        }
    }
    Ok(exit::OK)
}

fn render(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

pub fn set(ctx: &Ctx, key: &str, value: &str) -> Result<u8> {
    let updated = ctx.store.update(|settings| {
        match key {
            "mountService" => settings.mount_service = if value.is_empty() || value == "default" { None } else { Some(resolve_mounter(value)?) },
            "port" => settings.port = value.parse().map_err(|_| AppError::InvalidValue { key: key.to_string(), message: "expected a port number 0-65535".to_string() })?,
            "useKeychain" => settings.use_keychain = parse_bool(key, value)?,
            "keychainProvider" => settings.keychain_provider = value.to_string(),
            "debugMode" => settings.debug_mode = parse_bool(key, value)?,
            _ => return Err(unknown_key(key)),
        }
        Ok(config_json(settings))
    })?;
    ctx.out.emit(json!({ key: updated[key] }), || format!("{key}={}", render(&updated[key])))?;
    Ok(exit::OK)
}
```

`commands/mod.rs`: `pub mod config;`. In `main.rs` `run`: `VaultCommand::Set(args) => commands::vault::set(&ctx, args)` and

```rust
        Command::Config { command } => match command {
            ConfigCommand::Get { key } => commands::config::get(&ctx, key.as_deref()),
            ConfigCommand::Set { key, value } => commands::config::set(&ctx, &key, &value),
        },
```

(add `use cli::ConfigCommand;`.)

- [ ] **Step 4: Run tests**

Run: `cargo test -p crypto`
Expected: PASS (12 tests)

- [ ] **Step 5: Gate and commit**

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked`
Expected: PASS

```bash
git add crates/crypto
git commit -m "Add crypto vault set and config get/set commands

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 12: `password change`, `recovery-key show`, `recovery-key reset-password`

**Files:**
- Modify: `crates/crypto/src/cli.rs`, `crates/crypto/src/main.rs`, `crates/crypto/src/commands/mod.rs`, `crates/crypto/tests/cli.rs`
- Create: `crates/crypto/src/commands/password.rs`, `crates/crypto/src/commands/recovery.rs`

**Interfaces:**
- Consumes: `change_password`, `open_vault`, `read_vault_config`, `determine_vault_state`, `VaultState`, `recovery::{create_recovery_key, decode_recovery_key, reset_password, WordEncoder}`, `Masterkey::from_raw`, `read_passphrase`, `read_new_passphrase`, `NewPasswordArgs`, `PasswordArgs`, `SystemIo`.
- Produces: `cli::PasswordCommand::Change(ChangePasswordArgs)`, `cli::RecoveryKeyCommand::{Show(ShowArgs), ResetPassword(ResetPasswordArgs), Validate(ValidateArgs)}`; `commands::password::change`, `commands::recovery::{show, reset_password}`; helper function `commands::locked_vault_path(&Ctx, reference: &str) -> Result<PathBuf>` (resolves it, requires state `LOCKED`, otherwise `WrongState`).

- [ ] **Step 1: Write failing tests**

```rust
// append to crates/crypto/tests/cli.rs
#[test]
fn password_change_and_recovery_key_flows() {
    let sb = Sandbox::new();
    let vault = sb.path("pw");
    sb.crypto(&["vault", "create", vault.to_str().unwrap()]).assert().success();

    // change password: old from CRYPTO_PASSWORD, new from --new-password-env
    sb.crypto(&["password", "change", "pw", "--new-password-env", "NEWPW"]).env("NEWPW", "brand-new-passphrase").assert().success().stdout(predicate::str::contains("Password changed"));
    assert_eq!(std::fs::read_dir(&vault).unwrap().filter(|e| e.as_ref().unwrap().file_name().to_string_lossy().ends_with(".bkup")).count(), 1);
    sb.crypto(&["recovery-key", "show", "pw"]).assert().code(4).stderr(predicate::str::contains("invalid passphrase"));
    let out = sb.crypto(&["--json", "recovery-key", "show", "pw"]).env("CRYPTO_PASSWORD", "brand-new-passphrase").assert().success().get_output().stdout.clone();
    let recovery_key = serde_json::from_slice::<serde_json::Value>(&out).unwrap()["recoveryKey"].as_str().unwrap().to_string();
    assert_eq!(recovery_key.split(' ').count(), 44);
    sb.crypto(&["password", "change", "pw", "--new-password-env", "NEWPW"]).env("NEWPW", "short").env("CRYPTO_PASSWORD", "brand-new-passphrase").assert().code(4);

    // reset via recovery key from stdin, new password from --new-password-env
    sb.crypto(&["recovery-key", "reset-password", "pw", "--recovery-key-stdin", "--new-password-env", "NP"])
        .env("NP", "reset-passphrase-1")
        .write_stdin(format!("{recovery_key}\n"))
        .assert()
        .success();
    sb.crypto(&["recovery-key", "show", "pw"]).env("CRYPTO_PASSWORD", "reset-passphrase-1").assert().success().stdout(predicate::str::contains(&recovery_key));

    // a recovery key of another vault is rejected before anything is written
    let other = sb.path("other");
    let out = sb.crypto(&["--json", "vault", "create", "--show-recovery-key", other.to_str().unwrap()]).assert().success().get_output().stdout.clone();
    let foreign_key = serde_json::from_slice::<serde_json::Value>(&out).unwrap()["recoveryKey"].as_str().unwrap().to_string();
    let before = std::fs::read(vault.join("masterkey.cryptomator")).unwrap();
    sb.crypto(&["recovery-key", "reset-password", "pw", "--recovery-key-stdin", "--new-password-env", "NP"])
        .env("NP", "reset-passphrase-2")
        .write_stdin(format!("{foreign_key}\n"))
        .assert()
        .code(4);
    assert_eq!(std::fs::read(vault.join("masterkey.cryptomator")).unwrap(), before);
    sb.crypto(&["recovery-key", "reset-password", "pw", "--recovery-key-stdin", "--new-password-env", "NP"]).env("NP", "reset-passphrase-2").write_stdin("pathway lift\n").assert().code(4);
}

#[test]
fn password_and_recovery_commands_refuse_hub_and_missing_vaults() {
    let sb = Sandbox::new();
    let hub = sb.path("hub");
    std::fs::create_dir_all(hub.join("d")).unwrap();
    std::fs::write(hub.join("vault.cryptomator"), "eyJraWQiOiJodWIraHR0cHM6Ly9odWIuZXhhbXBsZS5jb20vYXBpL3ZhdWx0cy8xIiwiYWxnIjoiSFMyNTYiLCJ0eXAiOiJKV1QifQ.eyJqdGkiOiJ4IiwiZm9ybWF0Ijo4LCJjaXBoZXJDb21ibyI6IlNJVl9HQ00iLCJzaG9ydGVuaW5nVGhyZXNob2xkIjoyMjB9.AAAA").unwrap();
    sb.crypto(&["vault", "add", hub.to_str().unwrap()]).assert().success();
    sb.crypto(&["recovery-key", "show", "hub"]).assert().code(9);
    sb.crypto(&["password", "change", "hub", "--new-password-env", "X"]).env("X", "whatever-long").assert().code(9);
    std::fs::remove_dir_all(&hub).unwrap();
    sb.crypto(&["recovery-key", "show", "hub"]).assert().code(5).stderr(predicate::str::contains("MISSING"));
}
```

- [ ] **Step 2: Run tests, confirm failure**

Run: `cargo test -p crypto -- password_change password_and_recovery`
Expected: FAIL (subcommands missing)

- [ ] **Step 3: Implement**

`cli.rs`: extend `Command` with `/// Change or forget vault passwords\n Password { #[command(subcommand)] command: PasswordCommand }`; extend `RecoveryKeyCommand`; new structs:

```rust
#[derive(Subcommand, Debug)]
pub enum PasswordCommand {
    /// Change the password of a vault (writes a .bkup of the old masterkey file)
    Change(ChangePasswordArgs),
}

#[derive(Args, Debug)]
pub struct ChangePasswordArgs {
    /// Vault id, display name or path
    pub vault: String,
    #[command(flatten)]
    pub password: PasswordArgs,
    #[command(flatten)]
    pub new_password: NewPasswordArgs,
}

#[derive(Subcommand, Debug)]
pub enum RecoveryKeyCommand {
    /// Print the recovery key of a vault (requires the password)
    Show(ShowArgs),
    /// Set a new password using the recovery key
    #[command(name = "reset-password")]
    ResetPassword(ResetPasswordArgs),
    /// Check whether a recovery key is well-formed (dictionary words, length, checksum)
    Validate(ValidateArgs),
}

#[derive(Args, Debug)]
pub struct ShowArgs {
    /// Vault id, display name or path
    pub vault: String,
    #[command(flatten)]
    pub password: PasswordArgs,
}

#[derive(Args, Debug)]
pub struct ResetPasswordArgs {
    /// Vault id, display name or path
    pub vault: String,
    /// Read the recovery key from the next line of standard input
    #[arg(long, group = "recovery-key-source", required = true)]
    pub recovery_key_stdin: bool,
    /// Read the recovery key from a file
    #[arg(long, value_name = "FILE", group = "recovery-key-source")]
    pub recovery_key_file: Option<PathBuf>,
    #[command(flatten)]
    pub new_password: NewPasswordArgs,
}
```

(`use cryptomator_app::{NewPasswordArgs, PasswordArgs};`). Note: `required = true` on `recovery_key_stdin` together with the group means "exactly one source"; clap reports an error for `--recovery-key-file` without `--recovery-key-stdin`. Mark the group as required instead: `#[command(group = clap::ArgGroup::new("recovery-key-source").required(true))]` on `ResetPasswordArgs` and on both fields only `group = "recovery-key-source"` (no `required`).

```rust
// crates/crypto/src/commands/mod.rs
pub mod config;
pub mod password;
pub mod recovery;
pub mod vault;

use crate::output::Output;
use anyhow::Result;
use cryptomator_app::{resolve_vault_index, AppError, SettingsStore};
use cryptomator_core::{determine_vault_state, VaultState};
use std::path::PathBuf;

#[derive(Debug)]
pub struct Ctx {
    pub store: SettingsStore,
    pub out: Output,
}

/// Resolves a vault reference and requires the vault to be in state LOCKED (config + masterkey present).
pub fn locked_vault_path(ctx: &Ctx, reference: &str) -> Result<PathBuf> {
    let settings = ctx.store.load()?;
    let index = resolve_vault_index(&settings, reference)?;
    let path = settings.directories[index].path_buf().ok_or_else(|| AppError::InvalidValue { key: "path".to_string(), message: format!("vault {} has no path", settings.directories[index].id) })?;
    let state = determine_vault_state(&path)?;
    if state != VaultState::Locked {
        return Err(AppError::WrongState { expected: VaultState::Locked.as_str().to_string(), actual: state.as_str().to_string() }.into());
    }
    Ok(path)
}
```

```rust
// crates/crypto/src/commands/password.rs
//! `crypto password change`
use crate::cli::ChangePasswordArgs;
use crate::commands::{locked_vault_path, Ctx};
use crate::exit;
use anyhow::Result;
use cryptomator_app::{min_password_length, read_new_passphrase, read_passphrase, PasswordArgs, SystemIo};
use cryptomator_core::{change_password, read_vault_config, MasterkeyFileAccess, OsRng};
use serde_json::json;

pub fn change(ctx: &Ctx, args: ChangePasswordArgs) -> Result<u8> {
    let path = locked_vault_path(ctx, &args.vault)?;
    read_vault_config(&path)?.key_id()?.require_masterkey_file()?;
    let mut io = SystemIo;
    let old = read_passphrase(&args.password, "Current password: ", &mut io)?;
    let new = read_new_passphrase(&PasswordArgs::from(&args.new_password), "New password: ", min_password_length(), &mut io)?;
    let backup = change_password(&path, &MasterkeyFileAccess::new(Vec::new()), &old, &new, &mut OsRng)?;
    ctx.out.emit(json!({ "path": path, "backup": backup }), || format!("Password changed. Previous masterkey file kept as {}", backup.display()))?;
    Ok(exit::OK)
}
```

```rust
// crates/crypto/src/commands/recovery.rs
//! `crypto recovery-key show|reset-password`
use crate::cli::{ResetPasswordArgs, ShowArgs};
use crate::commands::{locked_vault_path, Ctx};
use crate::exit;
use anyhow::Result;
use cryptomator_app::{min_password_length, read_new_passphrase, read_passphrase, AppError, PasswordArgs, PasswordIo, SystemIo};
use cryptomator_core::recovery::{create_recovery_key, decode_recovery_key, reset_password, WordEncoder};
use cryptomator_core::{open_vault, read_vault_config, Masterkey, MasterkeyFileAccess, OsRng, VAULT_VERSION};
use serde_json::json;
use zeroize::Zeroizing;

pub fn show(ctx: &Ctx, args: ShowArgs) -> Result<u8> {
    let path = locked_vault_path(ctx, &args.vault)?;
    let passphrase = read_passphrase(&args.password, "Password: ", &mut SystemIo)?;
    let opened = open_vault(&path, &MasterkeyFileAccess::new(Vec::new()), &passphrase)?;
    let key = create_recovery_key(&WordEncoder::new(), opened.masterkey.raw());
    ctx.out.emit(json!({ "recoveryKey": key.as_str() }), || key.to_string())?;
    Ok(exit::OK)
}

fn read_recovery_key(args: &ResetPasswordArgs, io: &mut dyn PasswordIo) -> Result<Zeroizing<String>> {
    let raw = if let Some(file) = &args.recovery_key_file {
        Zeroizing::new(std::fs::read_to_string(file)?)
    } else {
        io.read_stdin_line()?.map(Zeroizing::new).ok_or(AppError::NoPasswordSource)?
    };
    Ok(Zeroizing::new(raw.split_whitespace().collect::<Vec<_>>().join(" ")))
}

pub fn reset_password_cmd(ctx: &Ctx, args: ResetPasswordArgs) -> Result<u8> {
    let path = locked_vault_path(ctx, &args.vault)?;
    let unverified = read_vault_config(&path)?;
    unverified.key_id()?.require_masterkey_file()?;
    let mut io = SystemIo;
    let recovery_key = read_recovery_key(&args, &mut io)?;
    let encoder = WordEncoder::new();
    // Prove the key belongs to this vault before touching the masterkey file.
    let raw = decode_recovery_key(&encoder, &recovery_key)?;
    unverified.verify(&raw, VAULT_VERSION)?;
    drop(Masterkey::from_raw(*raw));
    let new = read_new_passphrase(&PasswordArgs::from(&args.new_password), "New password: ", min_password_length(), &mut io)?;
    reset_password(&encoder, &MasterkeyFileAccess::new(Vec::new()), &path, &recovery_key, &new, &mut OsRng)?;
    ctx.out.emit(json!({ "path": path }), || "Password reset. A backup of the previous masterkey file was kept next to it.".to_string())?;
    Ok(exit::OK)
}
```

Re-export `VAULT_VERSION` in `cryptomator-core/src/lib.rs` (`pub use constants::VAULT_VERSION;`) if not already done. Extend `main.rs` `run`:

```rust
        Command::Password { command: PasswordCommand::Change(args) } => commands::password::change(&ctx, args),
        Command::RecoveryKey { command } => match command {
            RecoveryKeyCommand::Show(args) => commands::recovery::show(&ctx, args),
            RecoveryKeyCommand::ResetPassword(args) => commands::recovery::reset_password_cmd(&ctx, args),
            RecoveryKeyCommand::Validate(args) => { /* existing code */ }
        },
```

The error message "invalid passphrase" comes from `CoreError::InvalidPassphrase` (Display); `error: {err:#}` prints it to stderr.

- [ ] **Step 4: Run tests**

Run: `cargo test -p crypto`
Expected: PASS (14 tests)

- [ ] **Step 5: Gate and commit**

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked`
Expected: PASS

```bash
git add crates/crypto crates/cryptomator-core/src/lib.rs
git commit -m "Add password change and recovery-key show/reset-password commands

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 13: Java verification of Rust-created vaults, CI job and documentation

**Files:**
- Modify: `tools/fixture-gen/src/main/java/org/cryptomator/cli/fixtures/Gen.java`, `tools/fixture-gen/pom.xml`, `tools/fixture-gen/README.md`, `.github/workflows/ci.yml`, `README.md`, `CHANGELOG.md`, `docs/superpowers/specs/2026-09-04-crypto-cli-design.md`
- Create: `crates/crypto/tests/java_interop.rs`

**Interfaces:**
- Produces: `Gen verify <vaultDir> <passphrase>` (opens the vault with cryptofs 2.10.0, prints the manifest JSON of the cleartext tree to stdout, exit 0; exit 3 on error); POM properties `fixture.cmd` (default `gen`), `fixture.arg1` (default fixture directory), `fixture.arg2` (default empty); Rust test `java_interop` (`#[ignore]`, runs with `--ignored`), CI job `interop-java`.

- [ ] **Step 1: Java `verify` mode**

`Gen.main` ersetzen:

```java
    public static void main(String[] args) throws Exception {
        List<String> argv = java.util.Arrays.stream(args).filter(a -> !a.isEmpty()).toList();
        if (argv.size() == 2 && argv.get(0).equals("gen")) {
            Path out = Path.of(argv.get(1));
            Files.createDirectories(out);
            for (Spec spec : specs()) {
                generate(out.resolve(spec.name()), spec);
                System.out.println("generated " + spec.name());
            }
        } else if (argv.size() == 3 && argv.get(0).equals("verify")) {
            System.exit(verify(Path.of(argv.get(1)), argv.get(2)));
        } else {
            System.err.println("usage: Gen gen <outputDir> | Gen verify <vaultDir> <passphrase>");
            System.exit(2);
        }
    }

    /** Opens a vault written by another implementation with the real cryptofs and prints its cleartext tree as JSON. */
    static int verify(Path vault, String passphrase) {
        try {
            var access = new MasterkeyFileAccess(new byte[0], new SecureRandom());
            try (Masterkey masterkey = access.load(vault.resolve("masterkey.cryptomator"), passphrase)) {
                CryptoFileSystemProperties props = CryptoFileSystemProperties.cryptoFileSystemProperties()
                        .withKeyLoader(uri -> masterkey.copy())
                        .build();
                List<Map<String, Object>> entries = new ArrayList<>();
                try (CryptoFileSystem fs = CryptoFileSystemProvider.newFileSystem(vault, props)) {
                    walk(fs.getPath("/"), entries);
                    for (Map<String, Object> entry : entries) {
                        if ("file".equals(entry.get("type"))) {
                            Files.readAllBytes(fs.getPath((String) entry.get("path"))); // authenticate every chunk
                        }
                    }
                }
                var gson = new GsonBuilder().disableHtmlEscaping().create();
                System.out.println(gson.toJson(entries));
                return 0;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return 3;
        }
    }
```

`walk`/`sha256` stay unchanged (they already read files completely; the additional `readAllBytes` is deliberately redundant and documents the intent).

`pom.xml`: add to `<properties>`

```xml
    <fixture.cmd>gen</fixture.cmd>
    <fixture.arg1>${project.basedir}/../../tests/fixtures</fixture.arg1>
    <fixture.arg2></fixture.arg2>
```

and change the `<arguments>` of the exec plugin to

```xml
            <argument>${exec.mainClass}</argument>
            <argument>${fixture.cmd}</argument>
            <argument>${fixture.arg1}</argument>
            <argument>${fixture.arg2}</argument>
```

(the previous property `fixtures.out` goes away; adjust the README: `mvn -q -f tools/fixture-gen/pom.xml compile exec:exec` still generates the fixtures; `mvn -q -f tools/fixture-gen/pom.xml compile exec:exec -Dfixture.cmd=verify -Dfixture.arg1=/path/to/vault -Dfixture.arg2=<passphrase>` verifies a vault).

Run: `mvn -q -f tools/fixture-gen/pom.xml compile exec:exec -Dfixture.cmd=verify -Dfixture.arg1=$(pwd)/tests/fixtures/siv_gcm_basic -Dfixture.arg2=test-password-123`
Expected: JSON array with `/docs`, `/docs/notes.md`, `/hello.txt`; exit 0. With a wrong password: stacktrace, exit 3.

- [ ] **Step 2: Rust interop test**

```rust
// crates/crypto/tests/java_interop.rs
//! Vaults created by `crypto` must open with the real cryptofs. Needs Java 21+ and Maven; run with
//! `cargo test -p crypto --test java_interop -- --ignored` (CI job `interop-java`).
use assert_cmd::Command;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

fn verify_with_java(vault: &Path, passphrase: &str) -> serde_json::Value {
    let output = std::process::Command::new("mvn")
        .current_dir(repo_root())
        .args(["-q", "-f", "tools/fixture-gen/pom.xml", "compile", "exec:exec", "-Dfixture.cmd=verify"])
        .arg(format!("-Dfixture.arg1={}", vault.display()))
        .arg(format!("-Dfixture.arg2={passphrase}"))
        .output()
        .expect("mvn is installed");
    assert!(output.status.success(), "java verify failed:\n{}\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let json_line = stdout.lines().find(|l| l.starts_with('[')).expect("manifest JSON on stdout");
    serde_json::from_str(json_line).unwrap()
}

#[test]
#[ignore = "needs Java + Maven; run with --ignored"]
fn java_opens_vaults_created_by_crypto() {
    for combo in ["SIV_GCM", "SIV_CTRMAC"] {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("rust-vault");
        Command::cargo_bin("crypto")
            .unwrap()
            .env("CRYPTO_PASSWORD", "interop-passphrase")
            .arg("--settings")
            .arg(dir.path().join("settings.json"))
            .args(["vault", "create", "--cipher-combo", combo, "--shortening-threshold", "220"])
            .arg(&vault)
            .assert()
            .success();
        let manifest = verify_with_java(&vault, "interop-passphrase");
        let entries = manifest.as_array().unwrap();
        assert_eq!(entries.len(), 1, "{combo}: only WELCOME.rtf, got {manifest}");
        assert_eq!(entries[0]["path"], "/WELCOME.rtf");
        assert_eq!(entries[0]["type"], "file");
        assert!(entries[0]["size"].as_u64().unwrap() > 100);
    }
}
```

Run: `cargo test -p crypto --test java_interop -- --ignored`
Expected: PASS (1 test, ~30 s incl. Maven)

- [ ] **Step 3: CI job**

Append to `.github/workflows/ci.yml` (same indentation as `test`):

```yaml
  interop-java:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - uses: actions/setup-java@v4
        with:
          distribution: temurin
          java-version: "21"
          cache: maven
      - run: cargo test -p crypto --test java_interop --locked -- --ignored
```

- [ ] **Step 4: Documentation**

`README.md` – extend the "Commands" section with the M2 commands (one line each with an example: `vault create`, `vault add`, `vault list`, `vault info`, `vault set`, `vault remove`, `config get|set`, `password change`, `recovery-key show|reset-password|validate`), section "Password sources" (order from the Global Constraints) and "Settings file" (paths, `--settings`, `CRYPTO_SETTINGS_PATH`, note: settings.json is shared with the desktop app; close the app before `vault add/remove`).

`CHANGELOG.md` – section `## M2 – vault metadata` with the commands and the deliberate deviation (corrupt settings.json → error instead of reset).

Spec – mark M2 as done in the "Phases and milestones" table and add the sentence "An unparsable settings.json leads to an error (deviation from Java, which silently replaces it)" under `cryptomator-app` → `settings/store.rs`.

- [ ] **Step 5: Gate and commit**

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked && cargo test -p crypto --test java_interop --locked -- --ignored`
Expected: PASS

```bash
git add tools/fixture-gen crates/crypto/tests/java_interop.rs .github/workflows/ci.yml README.md CHANGELOG.md docs/superpowers/specs/2026-09-04-crypto-cli-design.md
git commit -m "Verify crypto-created vaults with cryptofs and document M2 commands

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

## Self-check

- **Spec coverage M2:** settings model/store (6, 8), vault refs + IDs (7), state detection + bkup restore (1), `vault create/add/remove/list/info` (10), `vault set` + `config` (11), `password change` (5, 12), `recovery-key show/reset-password` (12), readme generation (2, 4), milestone "Java verify accepts Rust vaults, both combos" (13), settings roundtrip (6, 8). "Desktop app opens CLI vault" is a manual step (see verification in the final report).
- **Type consistency:** `read_vault_config` (3) returns `UnverifiedVaultConfig` with `key_id()`, `alleged_*()`, `verify()` (M1); `KeyId::require_masterkey_file()` (M1) in 3, 5, 12; `VaultSettingsJson::{new, path_buf, mount_name}` (6, 7) in 10, 11; `resolve_vault_index` (7) in 10–12; `SettingsStore::{at, from_env_or_default, load, update}` (8) in 10–12; `PasswordArgs`/`NewPasswordArgs`/`read_passphrase`/`read_new_passphrase`/`SystemIo`/`PasswordIo` (9) in 10, 12; `create_vault`/`CreateVaultOptions` (4) in 10, 13; `change_password` (5) in 12; `reset_password(encoder, access, path, key, new, rng)` (M1, fix wave) in 12; `alleged_cipher_combo()` is added to `vault_config.rs` in 10; `VAULT_VERSION` re-export in 12.
- **Placeholders:** none.
- **Exit code mapping:** `NoPasswordSource` → 2 (usage), `PasswordTooShort/Mismatch` → 4, `VaultAlreadyAdded` → 5, `NotAVaultDirectory` → 12, `HubVaultUnsupported` → 9, `WrongState` → 5, `VaultNotFound/Ambiguous` → 3; the tests in 10–12 check exactly these codes.

## Execution

`superpowers:subagent-driven-development` with Opus 5 subagents as in M1; task 13 needs Java + Maven (available locally).
