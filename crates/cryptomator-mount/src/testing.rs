//! Helpers shared by the crate's unit tests.
use cryptomator_core::constants::DEFAULT_KEY_ID;
use cryptomator_core::fs::{CryptoFs, CryptoFsOptions};
use cryptomator_core::{initialize, open_vault_with_key, CipherCombo, DetRng, Masterkey};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

/// Serialises the tests that change the process environment (the library and null-mounter
/// overrides): `std::env` is global, and the unit tests share one process.
pub(crate) static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Locks [`ENV_LOCK`], ignoring poisoning -- a test that panicked while holding it left the
/// environment in whatever state it was, which the next test sets up again anyway.
pub(crate) fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// An empty vault in a temporary directory, opened. The directory must outlive the file system.
pub(crate) fn test_fs() -> (TempDir, Arc<CryptoFs>) {
    test_fs_with(CryptoFsOptions::default())
}

/// An empty vault in a temporary directory, opened with `options` -- e.g. `read_only: true`.
pub(crate) fn test_fs_with(options: CryptoFsOptions) -> (TempDir, Arc<CryptoFs>) {
    let dir = tempfile::tempdir().expect("temp dir");
    let key = Masterkey::from_raw([0x42; 64]);
    initialize(
        dir.path(),
        &key,
        CipherCombo::SivGcm,
        220,
        DEFAULT_KEY_ID,
        &mut DetRng::default(),
    )
    .expect("initialize vault");
    let opened = open_vault_with_key(dir.path(), key).expect("open vault");
    (dir, Arc::new(CryptoFs::open(opened, options)))
}
