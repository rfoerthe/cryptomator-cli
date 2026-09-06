//! The end-to-end proof that a vault mounted through a real FUSE back end behaves like a file
//! system: everything below goes through `std::fs` on the mount point, i.e. through the operating
//! system, the back end's transport and the adapter, and is checked again in the vault afterwards.
//!
//! The test mounts for real, so it is `#[ignore]`d twice over: `cargo test` skips it, and even
//! `--ignored` only runs it when `CRYPTO_E2E_MOUNT=1` says the machine may be mounted on.
//!
//! ```text
//! CRYPTO_E2E_MOUNT=1 cargo test -p cryptomator-mount --test mount_e2e -- --ignored --nocapture
//! ```
//!
//! Every exit path unmounts: the happy one gracefully, [`Mounted::drop`] forcibly, and as a last
//! resort with `umount -f` on the path itself. A stranded mount point would outlive the test
//! process and need a shell to clean up.
#![cfg(feature = "fuse")]

use cryptomator_core::constants::DEFAULT_KEY_ID;
use cryptomator_core::fs::{CleartextPath, CryptoFs, CryptoFsOptions};
use cryptomator_core::{initialize, open_vault_with_key, CipherCombo, DetRng, Masterkey};
use cryptomator_mount::api::{Mount, MountCapability, MountService};
use cryptomator_mount::mounttab::is_mountpoint;
use cryptomator_mount::registry::{self, NULL_MOUNTER_CLASS};
use std::error::Error;
use std::fs;
use std::io::Write;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Set to `1` to allow the tests in this file to mount a real file system.
const E2E_ENV: &str = "CRYPTO_E2E_MOUNT";

/// How long every access to the mount point together may take. A FUSE mount that stops answering
/// would otherwise hang the test run; this turns it into a failure with the mount taken down.
const WORK_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the volume may take to appear in the mount table after `mount()` returned.
const MOUNT_TIMEOUT: Duration = Duration::from_secs(20);

/// The size of the file that is written through the mount: several FUSE write requests and more
/// than three 32 KiB cleartext chunks, so chunk boundaries are crossed in both directions.
const PATTERN_LEN: usize = 100_000;

/// What is appended to it afterwards.
const APPENDED: &[u8] = b"appended through the mount\n";

/// A name macOS hands FUSE decomposed; the vault has to store it composed.
const NFD_NAME: &str = "cafe\u{301}.txt";
/// The same name, composed -- what [`CryptoFs::read_dir`] must report.
const NFC_NAME: &str = "caf\u{e9}.txt";

// --- test harness ---------------------------------------------------------------------------

/// Whether this machine may be mounted on.
fn e2e_enabled() -> bool {
    std::env::var(E2E_ENV).is_ok_and(|value| value == "1")
}

/// A fresh vault in a temporary directory, and the directory it lives in.
fn new_vault() -> Result<(tempfile::TempDir, PathBuf), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("vault");
    fs::create_dir(&path)?;
    initialize(
        &path,
        &Masterkey::from_raw([0x17; 64]),
        CipherCombo::SivGcm,
        220,
        DEFAULT_KEY_ID,
        &mut DetRng::default(),
    )?;
    Ok((dir, path))
}

/// Opens `vault` again -- once for each mount, and once more to inspect the result.
fn open(vault: &Path) -> Result<Arc<CryptoFs>, Box<dyn Error>> {
    let opened = open_vault_with_key(vault, Masterkey::from_raw([0x17; 64]))?;
    Ok(Arc::new(CryptoFs::open(opened, CryptoFsOptions::default())))
}

/// Closes a file system the test itself opened; the last reference has to be this one.
fn close(fs: Arc<CryptoFs>) -> Result<(), Box<dyn Error>> {
    Arc::into_inner(fs)
        .ok_or("the file system is still referenced elsewhere")?
        .close()?;
    Ok(())
}

/// A live mount that takes itself down, whatever happens to the test around it.
struct Mounted {
    mount: Option<Box<dyn Mount>>,
    mountpoint: PathBuf,
    /// Kept so the mount point outlives the mount.
    _dir: tempfile::TempDir,
}

impl Mounted {
    /// Mounts `fs` through `service` on a fresh temporary directory.
    fn new(
        service: &dyn MountService,
        fs: Arc<CryptoFs>,
        volume_name: &str,
        read_only: bool,
    ) -> Result<Self, Box<dyn Error>> {
        let dir = tempfile::tempdir()?;
        let mountpoint = dir.path().to_path_buf();
        let mut builder = service.for_file_system(fs);
        builder.set_mountpoint(&mountpoint)?;
        builder.set_mount_flags(&service.default_mount_flags())?;
        builder.set_volume_name(volume_name)?;
        if read_only {
            builder.set_read_only(true)?;
        }
        let mount = builder.mount()?;
        let mounted = Self {
            mount: Some(mount),
            mountpoint,
            _dir: dir,
        };
        // From here on a failure goes through `Drop`, which unmounts.
        wait_until_mounted(&mounted.mountpoint)?;
        Ok(mounted)
    }

    fn path(&self) -> &Path {
        &self.mountpoint
    }

    /// The graceful way out: unmount, wait for the session, and prove the volume is gone.
    ///
    /// Both steps are timed and reported: `unmount` and `close` are where a mount that has stopped
    /// answering shows up (as `Busy` after their own timeouts), and how long they took says which
    /// of the two it was.
    fn finish(mut self) -> Result<(), Box<dyn Error>> {
        let Some(mut mount) = self.mount.take() else {
            return Err("the mount was already released".into());
        };
        let started = Instant::now();
        let unmounted = mount.unmount();
        eprintln!(
            "  unmount() took {:.2?} -> {unmounted:?}",
            started.elapsed()
        );
        unmounted?;
        let started = Instant::now();
        let closed = mount.close();
        eprintln!("  close() took {:.2?} -> {closed:?}", started.elapsed());
        closed?;
        if is_mountpoint(&self.mountpoint) {
            return Err(format!(
                "{} is still mounted after close()",
                self.mountpoint.display()
            )
            .into());
        }
        Ok(())
    }
}

impl Drop for Mounted {
    fn drop(&mut self) {
        if let Some(mut mount) = self.mount.take() {
            // A failed test leaves files open or a thread stuck in a syscall; only a forced
            // unmount is guaranteed to get the volume out of the namespace.
            let forced = mount.unmount_forced();
            let closed = mount.close();
            eprintln!("cleanup: forced unmount {forced:?}, close {closed:?}");
        }
        if is_mountpoint(&self.mountpoint) {
            let out = std::process::Command::new("umount")
                .arg("-f")
                .arg("--")
                .arg(&self.mountpoint)
                .output();
            eprintln!(
                "cleanup: {} was still mounted, umount -f said {out:?}",
                self.mountpoint.display()
            );
        }
    }
}

/// Waits until the volume shows up in the mount table.
///
/// `fuse_mount_compat25` hands back the socket as soon as FUSE-T's server is listening; the NFS
/// mount it then drives is registered a moment later. A test that unmounted straight away would
/// race that: `umount` would report "not currently mounted", the session would keep running, and
/// the volume would appear afterwards -- with nothing left to take it down.
fn wait_until_mounted(path: &Path) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + MOUNT_TIMEOUT;
    while Instant::now() < deadline {
        if is_mountpoint(path) {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err(format!(
        "{} did not appear in the mount table within {} s",
        path.display(),
        MOUNT_TIMEOUT.as_secs()
    )
    .into())
}

/// Runs `work` on a helper thread and gives up after [`WORK_TIMEOUT`].
///
/// The caller unmounts either way: a thread still stuck in a syscall on the mount point is
/// released by the unmount, and is deliberately not joined -- joining it is exactly the hang this
/// timeout exists to avoid.
fn with_timeout<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    let (tx, rx) = mpsc::channel();
    thread::Builder::new()
        .name("crypto-mount-e2e".to_owned())
        .spawn(move || {
            let _ = tx.send(work());
        })
        .map_err(|err| format!("could not spawn the worker thread: {err}"))?;
    match rx.recv_timeout(WORK_TIMEOUT) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(format!(
            "the mount stopped answering: no result within {} s",
            WORK_TIMEOUT.as_secs()
        )),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err("the worker thread panicked; see the panic message above".to_owned())
        }
    }
}

/// The `mount(8)` lines for this mount point (and any other FUSE volume), for the record in the
/// report. The mount point is matched by its canonical path: on macOS a temporary directory lives
/// under `/var/folders/...`, which `mount` prints as `/private/var/folders/...`.
fn print_mount_table(what: &str, mountpoint: &Path) {
    let canonical = std::fs::canonicalize(mountpoint).unwrap_or_else(|_| mountpoint.to_path_buf());
    let needle = canonical.to_string_lossy().into_owned();
    match std::process::Command::new("/sbin/mount").output() {
        Ok(out) => {
            let table = String::from_utf8_lossy(&out.stdout);
            let mut printed = false;
            for line in table
                .lines()
                .filter(|l| l.contains(&needle) || l.to_lowercase().contains("fuse"))
            {
                println!("{what}: {line}");
                printed = true;
            }
            if !printed {
                println!("{what}: no line for {needle} in the mount table");
            }
        }
        Err(err) => println!("{what}: could not run mount: {err}"),
    }
}

/// The `pattern.bin` payload: never the same byte twice in a row, and not compressible into a
/// pattern a buggy read could reproduce by accident.
fn pattern() -> Vec<u8> {
    (0..PATTERN_LEN)
        .map(|i| ((i * 31 + i / 251) % 251) as u8)
        .collect()
}

/// The facts the worker collected on the mount point; asserted on the test's own thread so a
/// failure does not take the unmount with it.
#[derive(Debug)]
struct Observed {
    pattern_len: u64,
    appended_len: u64,
    link_target: String,
    docs_names: Vec<String>,
    root_names: Vec<String>,
    root_is_dir: bool,
}

/// Everything the test does through `std::fs` on the mount point.
fn exercise(mp: PathBuf) -> Result<Observed, String> {
    let e = |what: &str, err: std::io::Error| format!("{what}: {err} ({err:?})");
    // Unbuffered and timed, so a slow or stuck step is visible in the test output.
    let started = Instant::now();
    let step = |what: &str| eprintln!("  step: {what} (+{:.2?})", started.elapsed());

    step("create_dir docs");
    let docs = mp.join("docs");
    fs::create_dir(&docs).map_err(|err| e("create_dir docs", err))?;

    step("write pattern.bin");
    let data = pattern();
    let file = docs.join("pattern.bin");
    fs::write(&file, &data).map_err(|err| e("write pattern.bin", err))?;
    step("read pattern.bin");
    let read_back = fs::read(&file).map_err(|err| e("read pattern.bin", err))?;
    if read_back != data {
        return Err(format!(
            "pattern.bin differs: {} bytes back, first difference at {:?}",
            read_back.len(),
            read_back.iter().zip(&data).position(|(a, b)| a != b)
        ));
    }
    let pattern_len = fs::metadata(&file)
        .map_err(|err| e("metadata pattern.bin", err))?
        .len();

    step("append");
    {
        let mut handle = fs::OpenOptions::new()
            .append(true)
            .open(&file)
            .map_err(|err| e("open pattern.bin for append", err))?;
        handle
            .write_all(APPENDED)
            .map_err(|err| e("append to pattern.bin", err))?;
        handle.flush().map_err(|err| e("flush pattern.bin", err))?;
    }
    step("read after append");
    let appended = fs::read(&file).map_err(|err| e("read appended pattern.bin", err))?;
    let mut expected = data.clone();
    expected.extend_from_slice(APPENDED);
    if appended != expected {
        return Err(format!(
            "the appended file differs: {} bytes, expected {}",
            appended.len(),
            expected.len()
        ));
    }
    let appended_len = fs::metadata(&file)
        .map_err(|err| e("metadata appended pattern.bin", err))?
        .len();

    step("rename");
    let renamed = docs.join("renamed.bin");
    fs::rename(&file, &renamed).map_err(|err| e("rename pattern.bin", err))?;

    step("symlink + read_link");
    let link = docs.join("link");
    symlink("renamed.bin", &link).map_err(|err| e("symlink docs/link", err))?;
    let link_target = fs::read_link(&link)
        .map_err(|err| e("read_link docs/link", err))?
        .to_string_lossy()
        .into_owned();

    // Written decomposed, as macOS hands names to FUSE; the vault has to store it composed.
    step("write the NFD name");
    fs::write(docs.join(NFD_NAME), b"nfd in, nfc in the vault\n")
        .map_err(|err| e("write the NFD name", err))?;

    // A file that is created and removed again, and a directory likewise: `unlink` and `rmdir`
    // have to work through the mount, and neither may leave anything in the vault.
    step("unlink + rmdir");
    let doomed = docs.join("doomed.txt");
    fs::write(&doomed, b"gone in a moment\n").map_err(|err| e("write doomed.txt", err))?;
    fs::remove_file(&doomed).map_err(|err| e("remove_file doomed.txt", err))?;
    let empty = docs.join("empty-dir");
    fs::create_dir(&empty).map_err(|err| e("create_dir empty-dir", err))?;
    fs::remove_dir(&empty).map_err(|err| e("remove_dir empty-dir", err))?;

    step("listings");
    let mut docs_names = names(&docs).map_err(|err| e("read_dir docs", err))?;
    docs_names.sort();
    let mut root_names = names(&mp).map_err(|err| e("read_dir the mount point", err))?;
    root_names.sort();

    // The root has to answer `stat` -- the operating system asks for it (and, on FUSE-T, for
    // `statfs`) before nearly every other operation.
    step("stat the root");
    let root_is_dir = fs::metadata(&mp)
        .map_err(|err| e("metadata of the mount point", err))?
        .is_dir();

    Ok(Observed {
        pattern_len,
        appended_len,
        link_target,
        docs_names,
        root_names,
        root_is_dir,
    })
}

fn names(dir: &Path) -> std::io::Result<Vec<String>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir)? {
        out.push(entry?.file_name().to_string_lossy().into_owned());
    }
    Ok(out)
}

/// The names in `dir` inside the vault, sorted.
fn vault_names(fs: &CryptoFs, dir: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let mut out: Vec<String> = fs
        .read_dir(&CleartextPath::parse(dir))?
        .into_iter()
        .map(|entry| entry.cleartext_name)
        .collect();
    out.sort();
    Ok(out)
}

/// AppleDouble side cars and the other metadata files macOS scatters over a volume. None of them
/// may end up encrypted in the vault.
fn is_macos_metadata(name: &str) -> bool {
    name.starts_with("._") || name == ".DS_Store" || name.starts_with(".Spotlight")
}

// --- the tests ------------------------------------------------------------------------------

/// The first supported service that actually mounts something, or `None`.
fn fuse_service() -> Option<Box<dyn MountService>> {
    registry::services()
        .into_iter()
        .find(|service| service.java_class_name() != NULL_MOUNTER_CLASS)
}

#[test]
#[ignore = "mounts a real FUSE filesystem; run with CRYPTO_E2E_MOUNT=1"]
fn a_vault_mounted_through_fuse_behaves_like_a_file_system() -> Result<(), Box<dyn Error>> {
    if !e2e_enabled() {
        println!("skipped: {E2E_ENV} is not set to 1");
        return Ok(());
    }
    let Some(service) = fuse_service() else {
        println!("skipped: no FUSE service supported");
        return Ok(());
    };
    println!(
        "service: {} ({}), flags {}",
        service.display_name(),
        service.java_class_name(),
        service.default_mount_flags()
    );

    let (_vault_dir, vault) = new_vault()?;
    let observed = {
        let mounted = Mounted::new(service.as_ref(), open(&vault)?, "e2e", false)?;
        println!("mounted at {}", mounted.path().display());
        assert!(
            is_mountpoint(mounted.path()),
            "{} is not in the mount table",
            mounted.path().display()
        );
        print_mount_table("mount", mounted.path());

        let observed = with_timeout({
            let mp = mounted.path().to_path_buf();
            move || exercise(mp)
        });
        // Say what happened before unmounting: if the unmount itself fails, the reason the work
        // failed is the more interesting half and would otherwise be swallowed by `?`.
        println!("worker: {observed:?}");
        // Unmount before asserting: an assertion failure must not strand the volume.
        mounted.finish()?;
        observed?
    };
    println!("observed: {observed:#?}");

    assert_eq!(observed.pattern_len, PATTERN_LEN as u64);
    assert_eq!(
        observed.appended_len,
        (PATTERN_LEN + APPENDED.len()) as u64,
        "the appended size the mount reports"
    );
    assert_eq!(observed.link_target, "renamed.bin");
    assert!(observed.root_is_dir, "the mount point is a directory");
    assert!(
        observed.root_names.contains(&"docs".to_owned()),
        "the root listing: {:?}",
        observed.root_names
    );
    assert!(
        !observed.docs_names.iter().any(|n| n == "." || n == ".."),
        "read_dir must not report the dot entries: {:?}",
        observed.docs_names
    );
    for gone in ["doomed.txt", "empty-dir", "pattern.bin"] {
        assert!(
            !observed.docs_names.iter().any(|n| n == gone),
            "{gone} is still listed: {:?}",
            observed.docs_names
        );
    }
    for present in ["renamed.bin", "link"] {
        assert!(
            observed.docs_names.iter().any(|n| n == present),
            "{present} is missing: {:?}",
            observed.docs_names
        );
    }

    // --- and now the vault, read without any FUSE in the way ---------------------------------
    let fs = open(&vault)?;
    let root = vault_names(&fs, "/")?;
    let docs = vault_names(&fs, "/docs")?;
    println!("vault root: {root:?}\nvault /docs: {docs:?}");

    assert_eq!(root, vec!["docs".to_owned()], "the vault's root");
    assert!(
        fs.metadata(&CleartextPath::parse("/docs"))?.is_dir(),
        "/docs is a directory in the vault"
    );

    // The decomposed name arrived composed: this is the transcoder's whole reason to exist.
    assert!(
        docs.iter().any(|n| n == NFC_NAME),
        "the vault has to hold the composed name {NFC_NAME:?}, listing: {docs:?}"
    );
    assert!(
        !docs.iter().any(|n| n == NFD_NAME),
        "the decomposed name must not reach the vault: {docs:?}"
    );

    let stored = fs.read_file(&CleartextPath::parse("/docs/renamed.bin"))?;
    let mut expected = pattern();
    expected.extend_from_slice(APPENDED);
    assert_eq!(stored.len(), expected.len(), "the stored size");
    assert!(
        stored == expected,
        "the stored bytes differ from what was written"
    );
    assert_eq!(
        fs.metadata(&CleartextPath::parse("/docs/renamed.bin"))?
            .size,
        expected.len() as u64
    );
    assert_eq!(
        fs.read_link(&CleartextPath::parse("/docs/link"))?,
        "renamed.bin",
        "the symlink target"
    );
    assert_eq!(
        fs.read_file(&CleartextPath::parse(&format!("/docs/{NFC_NAME}")))?,
        b"nfd in, nfc in the vault\n"
    );

    // macOS asks for `._*`, `.DS_Store` and friends on every directory it looks at. The adapter
    // answers ENOENT; none of them may have been created in the vault.
    let stray: Vec<&String> = root
        .iter()
        .chain(docs.iter())
        .filter(|name| is_macos_metadata(name))
        .collect();
    assert!(
        stray.is_empty(),
        "macOS metadata files ended up in the vault: {stray:?}"
    );

    close(fs)?;
    assert!(
        registry::services()
            .iter()
            .any(|s| s.java_class_name() == service.java_class_name()),
        "the service is still supported after the test"
    );
    Ok(())
}

/// A read-only mount of a vault that already has content: reading works, writing does not.
#[test]
#[ignore = "mounts a real FUSE filesystem; run with CRYPTO_E2E_MOUNT=1"]
fn a_read_only_mount_refuses_writes() -> Result<(), Box<dyn Error>> {
    if !e2e_enabled() {
        println!("skipped: {E2E_ENV} is not set to 1");
        return Ok(());
    }
    let Some(service) = fuse_service() else {
        println!("skipped: no FUSE service supported");
        return Ok(());
    };
    if !service.has_capability(MountCapability::ReadOnly) {
        println!(
            "skipped: {} has no READ_ONLY capability",
            service.display_name()
        );
        return Ok(());
    }

    let (_vault_dir, vault) = new_vault()?;
    {
        let fs = open(&vault)?;
        fs.write_file(&CleartextPath::parse("/readable.txt"), b"read me\n", false)?;
        close(fs)?;
    }

    let outcome = {
        let mounted = Mounted::new(service.as_ref(), open(&vault)?, "e2e-ro", true)?;
        println!("read-only mount at {}", mounted.path().display());
        print_mount_table("mount (ro)", mounted.path());
        let outcome = with_timeout({
            let mp = mounted.path().to_path_buf();
            move || {
                let content = fs::read(mp.join("readable.txt"))
                    .map_err(|err| format!("reading through a read-only mount: {err}"))?;
                let write = fs::write(mp.join("nope.txt"), b"denied\n");
                let mkdir = fs::create_dir(mp.join("nope-dir"));
                Ok((
                    content,
                    write.err().map(|err| (err.raw_os_error(), err.to_string())),
                    mkdir.err().map(|err| (err.raw_os_error(), err.to_string())),
                ))
            }
        });
        mounted.finish()?;
        outcome?
    };
    let (content, write_err, mkdir_err) = outcome;
    println!("read-only mount: write {write_err:?}, mkdir {mkdir_err:?}");

    assert_eq!(content, b"read me\n", "reading must still work");
    let (write_errno, _) = write_err.ok_or("writing to a read-only mount must fail")?;
    let (mkdir_errno, _) = mkdir_err.ok_or("mkdir on a read-only mount must fail")?;
    for errno in [write_errno, mkdir_errno] {
        assert!(
            matches!(
                errno,
                Some(libc::EROFS) | Some(libc::EACCES) | Some(libc::EPERM)
            ),
            "expected EROFS/EACCES/EPERM, got {errno:?}"
        );
    }

    // Nothing may have reached the vault.
    let fs = open(&vault)?;
    assert_eq!(vault_names(&fs, "/")?, vec!["readable.txt".to_owned()]);
    close(fs)?;
    Ok(())
}

/// A guard against the harness itself: without the environment variable neither test mounts.
#[test]
fn the_e2e_tests_are_opt_in() {
    if std::env::var_os(E2E_ENV).is_none() {
        assert!(!e2e_enabled());
    }
    assert!(is_macos_metadata("._pattern.bin"));
    assert!(is_macos_metadata(".DS_Store"));
    assert!(!is_macos_metadata("renamed.bin"));
    assert_eq!(pattern().len(), PATTERN_LEN);
}
