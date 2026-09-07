//! Real OS mounts of a WebDAV vault. Ignored twice over: `cargo test` skips them, and even
//! `--ignored` only mounts when `CRYPTO_E2E_WEBDAV=1` says this machine may be mounted on.
//!
//! ```text
//! CRYPTO_E2E_WEBDAV=1 cargo test -p cryptomator-mount --test webdav_e2e -- --ignored --nocapture
//! ```
//!
//! Every test unmounts in a `Drop` guard, so a failed assertion never leaves a volume -- or a
//! server -- behind.
#![cfg(feature = "webdav")]

use cryptomator_core::constants::DEFAULT_KEY_ID;
use cryptomator_core::fs::{CleartextPath, CryptoFs, CryptoFsOptions};
use cryptomator_core::{initialize, open_vault_with_key, CipherCombo, DetRng, Masterkey};
use cryptomator_mount::api::{Mount, MountService, Mountpoint};
#[cfg(target_os = "linux")]
use cryptomator_mount::webdav::os_mount::LinuxGioMounter;
#[cfg(target_os = "macos")]
use cryptomator_mount::webdav::os_mount::MacAppleScriptMounter;
use std::sync::Arc;
use tempfile::TempDir;

/// Set to `1` to allow the tests in this file to mount a real volume.
const ENABLED_ENV: &str = "CRYPTO_E2E_WEBDAV";

/// Whether this machine may be mounted on.
fn enabled() -> bool {
    std::env::var(ENABLED_ENV).is_ok_and(|value| value == "1")
}

/// An empty vault in a temporary directory, opened. The directory must outlive the file system.
fn test_fs() -> (TempDir, Arc<CryptoFs>) {
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
    (
        dir,
        Arc::new(CryptoFs::open(opened, CryptoFsOptions::default())),
    )
}

/// Unmounts whatever is still mounted when the test ends, panic or not.
struct Guard(Option<Box<dyn Mount>>);

impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(mut mount) = self.0.take() {
            let _ = mount.unmount();
            let _ = mount.close();
        }
    }
}

#[test]
#[ignore = "mounts a real volume; set CRYPTO_E2E_WEBDAV=1"]
#[cfg(target_os = "macos")]
fn applescript_mounts_a_volume_that_the_finder_can_read() {
    if !enabled() {
        eprintln!("skipped: {ENABLED_ENV} is not 1");
        return;
    }
    let service = MacAppleScriptMounter;
    assert!(service.is_supported(), "osascript must be there");
    let (_dir, fs) = test_fs();
    fs.write_file(&CleartextPath::parse("/e2e.txt"), b"through webdav", false)
        .expect("write");
    let mut builder = service.for_file_system(Arc::clone(&fs));
    builder.set_loopback_port(0).expect("LOOPBACK_PORT");
    builder.set_volume_id("e2evault").expect("VOLUME_ID");
    builder.set_volume_name("CryptoE2E").expect("VOLUME_NAME");
    let mut guard = Guard(Some(builder.mount().expect("osascript mount")));
    let Mountpoint::Path(path) = guard.0.as_ref().expect("still mounted").mountpoint() else {
        panic!("the AppleScript mounter reports a path")
    };
    eprintln!("service: mounted at {}", path.display());
    assert_eq!(
        std::fs::read(path.join("e2e.txt")).expect("read through the volume"),
        b"through webdav"
    );
    // And back the other way: what the volume writes is in the vault afterwards.
    std::fs::write(path.join("back.txt"), b"written through the volume").expect("write");
    let mut mount = guard.0.take().expect("still mounted");
    mount.unmount().expect("diskutil umount");
    mount.close().expect("close");
    assert!(
        !cryptomator_mount::mounttab::is_mountpoint(&path),
        "the volume is gone"
    );
    assert_eq!(
        fs.read_file(&CleartextPath::parse("/back.txt"))
            .expect("the vault has it"),
        b"written through the volume"
    );
}

#[test]
#[ignore = "mounts a real volume; set CRYPTO_E2E_WEBDAV=1"]
#[cfg(target_os = "linux")]
fn gio_mounts_a_volume_under_gvfs() {
    if !enabled() {
        eprintln!("skipped: {ENABLED_ENV} is not 1");
        return;
    }
    let service = LinuxGioMounter;
    if !service.is_supported() {
        eprintln!("skipped: no gvfs session on this machine");
        return;
    }
    let (_dir, fs) = test_fs();
    fs.write_file(&CleartextPath::parse("/e2e.txt"), b"through webdav", false)
        .expect("write");
    let mut builder = service.for_file_system(Arc::clone(&fs));
    builder.set_loopback_port(0).expect("LOOPBACK_PORT");
    builder.set_volume_id("e2evault").expect("VOLUME_ID");
    let mut guard = Guard(Some(builder.mount().expect("gio mount")));
    let Mountpoint::Path(path) = guard.0.as_ref().expect("still mounted").mountpoint() else {
        panic!("gio reports the gvfs path")
    };
    eprintln!("service: mounted at {}", path.display());
    assert_eq!(
        std::fs::read(path.join("e2e.txt")).expect("read through the volume"),
        b"through webdav"
    );
    let mut mount = guard.0.take().expect("still mounted");
    mount.unmount().expect("gio mount -u");
    mount.close().expect("close");
}
