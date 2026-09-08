//! Vaults created by `crypto` must open with the real cryptofs. Needs Java 21+ and Maven; run with
//! `cargo test -p crypto --test java_interop -- --ignored` (CI job `interop-java`).
use assert_cmd::Command;
use cryptomator_core::fs::{CleartextPath, CryptoFs, CryptoFsOptions, OpenOptions};
use cryptomator_core::{open_vault, MasterkeyFileAccess};
use cryptomator_mount::api::{Mount, MountBuilder, MountError, MountService};
use cryptomator_mount::mounttab::is_mountpoint;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn run_java_verify(vault: &Path, passphrase: &str) -> std::process::Output {
    std::process::Command::new("mvn")
        .current_dir(repo_root())
        .args([
            "-q",
            "-f",
            "tools/fixture-gen/pom.xml",
            "compile",
            "exec:exec",
            "-Dfixture.cmd=verify",
        ])
        .arg(format!("-Dfixture.arg1={}", vault.display()))
        .arg(format!("-Dfixture.arg2={passphrase}"))
        .output()
        .expect("mvn is installed")
}

/// The counterpart of [`verify_with_java`]: the passphrase must be rejected. `Gen.verify` answers
/// with exit code 3, which exec-maven-plugin reports verbatim ("Exit value: 3") while failing the
/// build. The passphrase itself never appears in an assertion message.
fn assert_java_rejects(vault: &Path, passphrase: &str) {
    let output = run_java_verify(vault, passphrase);
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !output.status.success(),
        "java verify accepted a passphrase it should have rejected"
    );
    assert!(
        combined.contains("Exit value: 3"),
        "expected Gen.verify to exit 3, maven said:\n{combined}"
    );
    assert!(
        !combined.lines().any(|l| l.starts_with("[{")),
        "a manifest was printed although the passphrase should have been rejected"
    );
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

fn verify_with_java(vault: &Path, passphrase: &str) -> serde_json::Value {
    let output = run_java_verify(vault, passphrase);
    assert!(
        output.status.success(),
        "java verify failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let json_line = stdout
        .lines()
        // Not `starts_with('[')`: Maven prints `[WARNING] ...` on stdout, and picking such a line
        // up would fail as a JSON parse panic instead of a legible assertion.
        .find(|l| l.starts_with("[{") || l.trim() == "[]")
        .expect("manifest JSON on stdout");
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
            .env_remove("CRYPTO_MIN_PW_LENGTH")
            .env_remove("CRYPTO_SETTINGS_PATH")
            .arg("--settings")
            .arg(dir.path().join("settings.json"))
            .args([
                "vault",
                "create",
                "--cipher-combo",
                combo,
                "--shortening-threshold",
                "220",
            ])
            .arg(&vault)
            .assert()
            .success();
        let manifest = verify_with_java(&vault, "interop-passphrase");
        let entries = manifest.as_array().unwrap();
        assert_eq!(
            entries.len(),
            1,
            "{combo}: only WELCOME.rtf, got {manifest}"
        );
        assert_eq!(entries[0]["path"], "/WELCOME.rtf");
        assert_eq!(entries[0]["type"], "file");
        assert!(entries[0]["size"].as_u64().unwrap() > 100);
    }
}

/// `crypto password change` on a Java-generated fixture: cryptofs must still open the vault with
/// the new passphrase and see exactly the fixture's files, and the old passphrase must stop working.
/// The fixtures themselves are read-only, so everything happens on a copy in a temporary directory.
#[test]
#[ignore = "needs Java + Maven; run with --ignored"]
fn java_opens_fixtures_after_a_password_change_by_crypto() {
    const OLD_PW: &str = "test-password-123";
    const NEW_PW: &str = "changed-by-crypto-1";
    for name in ["siv_gcm_basic", "siv_ctrmac_basic"] {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join(name);
        let fixture = repo_root().join("tests/fixtures").join(name);
        copy_dir(&fixture, &vault);
        let expected: serde_json::Value =
            serde_json::from_slice(&std::fs::read(fixture.join("expected.json")).unwrap()).unwrap();
        let settings = dir.path().join("settings.json");

        let crypto = || {
            let mut cmd = Command::cargo_bin("crypto").unwrap();
            cmd.env_remove("CRYPTO_PASSWORD")
                .env_remove("CRYPTO_MIN_PW_LENGTH")
                .env_remove("CRYPTO_SETTINGS_PATH");
            cmd.arg("--settings").arg(&settings);
            cmd
        };
        crypto()
            .args(["vault", "add", "--name", name])
            .arg(&vault)
            .assert()
            .success();
        // Passphrases only through the environment, never on the command line.
        crypto()
            .env("OLD_PW", OLD_PW)
            .env("NEW_PW", NEW_PW)
            .args([
                "password",
                "change",
                name,
                "--password-env",
                "OLD_PW",
                "--new-password-env",
                "NEW_PW",
            ])
            .assert()
            .success();

        let manifest = verify_with_java(&vault, NEW_PW);
        assert_eq!(
            manifest, expected,
            "{name}: cryptofs sees a different tree than expected.json after the password change"
        );
        assert_java_rejects(&vault, OLD_PW);
    }
}

/// A vault `crypto migrate` lifted to format 8 must be a vault cryptofs 2.10.0 reads — the 6 → 7
/// name migration (BASE32 → base64url, `.lng` → `.c9s`) is the one step of the chain that rewrites
/// the ciphertext, so this is where a mistake would hide. All three legacy formats run here,
/// because each enters the chain at a different step: 7 → 8 alone, 6 → 7 → 8, and 5 → 6 → 7 → 8
/// with the NFD passphrase that only the 5 → 6 step normalises. The fixtures are read-only, so
/// every migration runs on a copy, and the migrated vault opens with the **NFC** passphrase.
///
/// Only the committed fixtures and cryptofs 2.10.0 are needed here; the legacy cryptofs releases
/// that *wrote* the fixtures are a regeneration concern (`tools/fixture-gen/legacy-v*`).
#[test]
#[ignore = "needs Java + Maven; run with --ignored"]
fn java_reads_vaults_migrated_from_legacy_formats() {
    for (name, starts_at) in [
        ("legacy_v7", cryptomator_core::VaultVersion::V7),
        ("legacy_v6", cryptomator_core::VaultVersion::V6),
        ("legacy_v5", cryptomator_core::VaultVersion::V5),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join(name);
        let fixture = repo_root().join("tests/fixtures").join(name);
        copy_dir(&fixture, &vault);
        let meta: serde_json::Value =
            serde_json::from_slice(&std::fs::read(fixture.join("fixture.json")).unwrap()).unwrap();
        let passphrase = meta["passphrase"].as_str().unwrap().to_owned();
        let nfc = meta["passphraseNfc"]
            .as_str()
            .unwrap_or(&passphrase)
            .to_owned();

        assert_eq!(
            cryptomator_core::migration::detect_version(&vault).expect("the fixture's format"),
            starts_at,
            "{name} does not start where its manifest says it does"
        );
        let reached = cryptomator_core::migration::migrate(
            &vault,
            &passphrase,
            cryptomator_core::MigrationOptions {
                full_scan_allowed: true,
                dry_run: false,
            },
            &mut |_| {},
        )
        .unwrap_or_else(|err| panic!("the chain to format 8 for {name}: {err}"));
        assert_eq!(reached, cryptomator_core::VaultVersion::V8);
        assert!(
            !vault.join("m").exists(),
            "{name}: the metadata directory is gone"
        );

        let manifest = verify_with_java(&vault, &nfc);
        assert_eq!(
            manifest, meta["expected"],
            "{name}: cryptofs sees a different tree than the fixture manifest after the migration"
        );
    }
}

/// A vault whose `masterkey.cryptomator` **and** `vault.cryptomator` were rebuilt by
/// `crypto recovery-key restore --all` must still be a vault cryptofs 2.10.0 opens: the restored
/// config is a freshly signed JWT (new `jti`) and the restored masterkey file a freshly wrapped
/// key, so a mistake in either -- a wrong cipher combo detected, a wrong `kid`, a threshold the
/// files do not match -- shows up here and nowhere else. The fixture is read-only, so the restore
/// runs on a copy.
#[test]
#[ignore = "needs Java + Maven; run with --ignored"]
fn java_reads_a_vault_restored_by_crypto() {
    const OLD_PW: &str = "test-password-123";
    const NEW_PW: &str = "restored-by-crypto-1";
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("siv_gcm_basic");
    let fixture = repo_root().join("tests/fixtures/siv_gcm_basic");
    copy_dir(&fixture, &vault);
    let expected: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixture.join("expected.json")).unwrap()).unwrap();
    let settings = dir.path().join("settings.json");
    let crypto = || {
        let mut cmd = Command::cargo_bin("crypto").unwrap();
        cmd.env_remove("CRYPTO_PASSWORD")
            .env_remove("CRYPTO_MIN_PW_LENGTH")
            .env_remove("CRYPTO_SETTINGS_PATH");
        cmd.arg("--settings").arg(&settings);
        cmd
    };
    crypto()
        .args(["vault", "add", "--name", "siv_gcm_basic"])
        .arg(&vault)
        .assert()
        .success();
    let key = crypto()
        .env("PW", OLD_PW)
        .args([
            "recovery-key",
            "show",
            "siv_gcm_basic",
            "--password-env",
            "PW",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let key = String::from_utf8(key).unwrap();

    // Both key files (and every backup that would resurrect them) go away first, so the restore
    // has to rebuild them from the recovery key alone -- including the cipher combo, which is read
    // out of the ciphertext.
    for name in ["masterkey.cryptomator", "vault.cryptomator"] {
        std::fs::remove_file(vault.join(name)).unwrap();
    }
    for entry in std::fs::read_dir(&vault).unwrap().flatten() {
        if entry.file_name().to_string_lossy().ends_with(".bkup") {
            std::fs::remove_file(entry.path()).unwrap();
        }
    }
    crypto()
        .env("NP", NEW_PW)
        .args([
            "recovery-key",
            "restore",
            "siv_gcm_basic",
            "--all",
            "--recovery-key-stdin",
            "--new-password-env",
            "NP",
        ])
        .write_stdin(key)
        .assert()
        .success();

    let manifest = verify_with_java(&vault, NEW_PW);
    assert_eq!(
        manifest, expected,
        "cryptofs sees a different tree than expected.json after the restore"
    );
    assert_java_rejects(&vault, OLD_PW);
}

/// A tree written by `CryptoFs` (long names, unicode, sizes at chunk boundaries, symlinks, nesting)
/// is read by the real cryptofs; the Java manifest equals `crypto fs tree --json --hash`.
#[test]
#[ignore = "needs Java + Maven; run with --ignored"]
fn java_reads_a_tree_written_by_crypto_fs() {
    let dir = tempfile::tempdir().unwrap();
    let settings = dir.path().join("settings.json");
    let vault = dir.path().join("rust-tree");
    let crypto = |args: &[&str]| {
        let mut cmd = Command::cargo_bin("crypto").unwrap();
        cmd.env_remove("CRYPTO_SETTINGS_PATH")
            .env_remove("CRYPTO_MIN_PW_LENGTH")
            .env("CRYPTO_PASSWORD", "interop-passphrase")
            .arg("--settings")
            .arg(&settings)
            .args(args);
        cmd
    };
    crypto(&["vault", "create", "--name", "tree"])
        .arg(&vault)
        .assert()
        .success();
    {
        let opened = open_vault(
            &vault,
            &MasterkeyFileAccess::new(Vec::new()),
            "interop-passphrase",
        )
        .unwrap();
        let fs = CryptoFs::open(opened, CryptoFsOptions::default());
        fs.delete(&CleartextPath::parse("/WELCOME.rtf")).unwrap();
        fs.create_dir_all(&CleartextPath::parse("/l1/l2/l3/l4/l5"))
            .unwrap();
        fs.write_file(
            &CleartextPath::parse("/l1/l2/l3/l4/l5/deep.txt"),
            b"deep\n",
            false,
        )
        .unwrap();
        for size in [0usize, 1, 32_767, 32_768, 32_769, 65_536, 100_000] {
            let data: Vec<u8> = (0..size).map(|i| (i * 7) as u8).collect();
            fs.write_file(
                &CleartextPath::parse(&format!("/size-{size}.bin")),
                &data,
                false,
            )
            .unwrap();
        }
        fs.write_file(
            &CleartextPath::parse(&format!("/{}.txt", "c".repeat(200))),
            b"200 chars\n",
            false,
        )
        .unwrap();
        fs.create_dir(&CleartextPath::parse(&format!("/{}", "d".repeat(200))))
            .unwrap();
        fs.write_file(
            &CleartextPath::parse(&format!("/{}/inner.txt", "d".repeat(200))),
            b"inside long dir\n",
            false,
        )
        .unwrap();
        fs.write_file(&CleartextPath::parse("/Grüße 🚀.txt"), b"nfc\n", false)
            .unwrap();
        fs.write_file(
            &CleartextPath::parse("/cafe\u{301}.txt"),
            b"nfd input, nfc name\n",
            false,
        )
        .unwrap();
        fs.create_dir(&CleartextPath::parse("/日本語")).unwrap();
        fs.write_file(
            &CleartextPath::parse("/日本語/ファイル.txt"),
            b"japanese\n",
            false,
        )
        .unwrap();
        fs.write_file(
            &CleartextPath::parse("/target.txt"),
            b"link target\n",
            false,
        )
        .unwrap();
        fs.create_symlink(&CleartextPath::parse("/relative-link"), "target.txt")
            .unwrap();
        fs.create_symlink(&CleartextPath::parse("/absolute-link"), "/target.txt")
            .unwrap();
        fs.create_symlink(&CleartextPath::parse("/dangling"), "does-not-exist")
            .unwrap();
        // a rename and an overwrite exercise the mutation paths before Java looks
        fs.rename(
            &CleartextPath::parse("/size-1.bin"),
            &CleartextPath::parse("/l1/one.bin"),
            false,
        )
        .unwrap();
        fs.write_file(&CleartextPath::parse("/size-0.bin"), b"", true)
            .unwrap();
        // renaming *to* a shortened name: the node becomes a `.c9s` directory with `name.c9s`
        fs.write_file(&CleartextPath::parse("/rename-me.bin"), b"renamed\n", false)
            .unwrap();
        fs.rename(
            &CleartextPath::parse("/rename-me.bin"),
            &CleartextPath::parse(&format!("/{}.bin", "r".repeat(200))),
            false,
        )
        .unwrap();
        // renaming *from* a shortened name must leave no `name.c9s` behind (directory and symlink)
        fs.create_dir(&CleartextPath::parse(&format!("/{}", "e".repeat(200))))
            .unwrap();
        fs.write_file(
            &CleartextPath::parse(&format!("/{}/kept.txt", "e".repeat(200))),
            b"survives the rename\n",
            false,
        )
        .unwrap();
        fs.rename(
            &CleartextPath::parse(&format!("/{}", "e".repeat(200))),
            &CleartextPath::parse("/was-long-dir"),
            false,
        )
        .unwrap();
        fs.create_symlink(
            &CleartextPath::parse(&format!("/{}", "k".repeat(200))),
            "target.txt",
        )
        .unwrap();
        fs.rename(
            &CleartextPath::parse(&format!("/{}", "k".repeat(200))),
            &CleartextPath::parse("/was-long-link"),
            false,
        )
        .unwrap();
        // a symlink that keeps its 200-char name
        fs.create_symlink(
            &CleartextPath::parse(&format!("/{}", "m".repeat(200))),
            "target.txt",
        )
        .unwrap();
        // truncating a multi-chunk file to a size that is neither zero nor a chunk boundary
        {
            let handle = fs
                .open_file(
                    &CleartextPath::parse("/size-100000.bin"),
                    OpenOptions::read_write(),
                )
                .unwrap();
            handle.truncate(40_000).unwrap();
            handle.close().unwrap();
        }
        fs.copy(
            &CleartextPath::parse("/target.txt"),
            &CleartextPath::parse("/copy-of-target.txt"),
            false,
        )
        .unwrap();
        fs.close().unwrap();
    }
    let java = verify_with_java(&vault, "interop-passphrase");
    let out = crypto(&["--json", "fs", "tree", "tree", "--hash"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let rust: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(rust, java, "Java manifest differs from crypto fs tree");
    assert_eq!(java.as_array().unwrap().len(), 30, "{java}");
    let entry = |path: &str| {
        java.as_array()
            .unwrap()
            .iter()
            .find(|e| e["path"] == path)
            .unwrap_or_else(|| panic!("{path} missing from {java}"))
            .clone()
    };
    assert_eq!(entry("/size-100000.bin")["size"], 40_000, "truncated size");
    assert_eq!(entry("/was-long-dir")["type"], "dir");
    assert_eq!(entry("/was-long-dir/kept.txt")["size"], 20);
    assert_eq!(entry("/was-long-link")["type"], "symlink");
    assert_eq!(
        entry("/copy-of-target.txt")["sha256"],
        entry("/target.txt")["sha256"]
    );
    entry(&format!("/{}.bin", "r".repeat(200)));
    entry(&format!("/{}", "m".repeat(200)));
    assert!(
        java.as_array()
            .unwrap()
            .iter()
            .any(|e| e["path"] == "/caf\u{e9}.txt"),
        "NFC name"
    );
}

// --- the mount cross-check -------------------------------------------------------------------
//
// Everything below writes its tree through a real FUSE mount instead of through `CryptoFs`, so
// the whole stack -- kernel/NFS client, the back end, the FUSE adapter, the core -- is between the
// test and the ciphertext. The real cryptofs then has to read exactly the same tree.

/// Set to `1` to allow this file to mount a real file system.
const E2E_ENV: &str = "CRYPTO_E2E_MOUNT";
/// How long the writing through the mount may take before the mount is taken down and the test
/// fails, rather than hanging the suite.
const MOUNT_WORK_TIMEOUT: Duration = Duration::from_secs(60);
/// How long the volume may take to appear in the mount table after `mount()` returned; FUSE-T
/// mounts its NFS share a moment after handing back the session socket.
const MOUNT_APPEARS_TIMEOUT: Duration = Duration::from_secs(20);

/// A live mount that takes itself down whatever happens to the test around it.
struct TestMount {
    mount: Option<Box<dyn Mount>>,
    mountpoint: PathBuf,
    _dir: tempfile::TempDir,
}

impl TestMount {
    fn new(service: &dyn MountService, fs: Arc<CryptoFs>) -> Result<Self, String> {
        let dir = tempfile::tempdir().map_err(|err| format!("temp dir: {err}"))?;
        let mountpoint = dir.path().to_path_buf();
        let mut builder = service.for_file_system(fs);
        let configure = |builder: &mut Box<dyn MountBuilder>| -> Result<(), MountError> {
            builder.set_mountpoint(&mountpoint)?;
            builder.set_mount_flags(&service.default_mount_flags())?;
            builder.set_volume_name("java-interop")
        };
        configure(&mut builder).map_err(|err| format!("configuring the mount: {err}"))?;
        let mount = builder.mount().map_err(|err| format!("mounting: {err}"))?;
        let mounted = Self {
            mount: Some(mount),
            mountpoint,
            _dir: dir,
        };
        // From here on every failure goes through `Drop`, which unmounts.
        let deadline = Instant::now() + MOUNT_APPEARS_TIMEOUT;
        while !is_mountpoint(&mounted.mountpoint) {
            if Instant::now() >= deadline {
                return Err(format!(
                    "{} did not appear in the mount table",
                    mounted.mountpoint.display()
                ));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Ok(mounted)
    }

    fn finish(mut self) -> Result<(), String> {
        let mut mount = self.mount.take().ok_or("already released")?;
        mount.unmount().map_err(|err| format!("unmount: {err}"))?;
        mount.close().map_err(|err| format!("close: {err}"))?;
        if is_mountpoint(&self.mountpoint) {
            return Err(format!("{} is still mounted", self.mountpoint.display()));
        }
        Ok(())
    }
}

impl Drop for TestMount {
    fn drop(&mut self) {
        if let Some(mut mount) = self.mount.take() {
            let _ = mount.unmount_forced();
            let _ = mount.close();
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

/// Writes the tree the cross-check is about, on the mount point.
fn write_tree_through_the_mount(mp: &Path) -> Result<(), String> {
    let e = |what: &str, err: std::io::Error| format!("{what}: {err}");
    let long = "n".repeat(200);

    std::fs::create_dir(mp.join("dir")).map_err(|err| e("create_dir dir", err))?;
    std::fs::create_dir_all(mp.join("dir/deeper/still")).map_err(|err| e("create_dir_all", err))?;
    std::fs::write(mp.join("dir/small.txt"), b"written through the mount\n")
        .map_err(|err| e("write small.txt", err))?;
    std::fs::write(mp.join("dir/deeper/still/deep.txt"), b"deep\n")
        .map_err(|err| e("write deep.txt", err))?;
    // Larger than one 32 KiB cleartext chunk, so the ciphertext spans several of them.
    let big: Vec<u8> = (0..100_000)
        .map(|i| ((i * 31 + i / 251) % 251) as u8)
        .collect();
    std::fs::write(mp.join("dir/big.bin"), &big).map_err(|err| e("write big.bin", err))?;
    // A name long enough to be stored shortened (`.c9s`), written through the mount.
    std::fs::write(mp.join(format!("dir/{long}.txt")), b"200 chars\n")
        .map_err(|err| e("write the long name", err))?;
    std::os::unix::fs::symlink("small.txt", mp.join("dir/link"))
        .map_err(|err| e("symlink dir/link", err))?;
    // Unicode, decomposed as macOS hands it to FUSE; the vault stores it composed.
    std::fs::write(
        mp.join("dir/cafe\u{301}.txt"),
        b"nfd in, nfc in the vault\n",
    )
    .map_err(|err| e("write the NFD name", err))?;
    Ok(())
}

/// The tree of the previous test, but written through a mounted vault: the real cryptofs must read
/// it, and its manifest must equal `crypto fs tree --json --hash`.
#[test]
#[ignore = "needs Java + Maven and mounts a real FUSE filesystem; run with CRYPTO_E2E_MOUNT=1"]
fn java_reads_files_written_through_the_mount() {
    if std::env::var(E2E_ENV).as_deref() != Ok("1") {
        println!("skipped: {E2E_ENV} is not set to 1");
        return;
    }
    let Some(service) = cryptomator_mount::registry::services()
        .into_iter()
        .find(|service| {
            service.java_class_name() != cryptomator_mount::registry::NULL_MOUNTER_CLASS
        })
    else {
        println!("skipped: no FUSE service supported");
        return;
    };
    println!("service: {}", service.display_name());

    let dir = tempfile::tempdir().unwrap();
    let settings = dir.path().join("settings.json");
    let vault = dir.path().join("mounted-vault");
    let crypto = |args: &[&str]| {
        let mut cmd = Command::cargo_bin("crypto").unwrap();
        cmd.env_remove("CRYPTO_SETTINGS_PATH")
            .env_remove("CRYPTO_MIN_PW_LENGTH")
            .env("CRYPTO_PASSWORD", "interop-passphrase")
            .arg("--settings")
            .arg(&settings)
            .args(args);
        cmd
    };
    // A masterkey file is needed, so the vault is created by the CLI rather than by `initialize`.
    crypto(&["vault", "create", "--name", "mounted"])
        .arg(&vault)
        .assert()
        .success();

    {
        let opened = open_vault(
            &vault,
            &MasterkeyFileAccess::new(Vec::new()),
            "interop-passphrase",
        )
        .unwrap();
        let fs = Arc::new(CryptoFs::open(opened, CryptoFsOptions::default()));
        let mounted = TestMount::new(service.as_ref(), fs).expect("mount the vault");
        println!("mounted at {}", mounted.mountpoint.display());
        for line in String::from_utf8_lossy(
            &std::process::Command::new("/sbin/mount")
                .output()
                .expect("mount(8)")
                .stdout,
        )
        .lines()
        .filter(|line| line.to_lowercase().contains("fuse"))
        {
            println!("mount: {line}");
        }

        // On a helper thread with a deadline: a mount that stops answering must fail the test,
        // not hang the suite. The mount is taken down either way.
        let (tx, rx) = std::sync::mpsc::channel();
        let mp = mounted.mountpoint.clone();
        std::thread::spawn(move || {
            let _ = tx.send(write_tree_through_the_mount(&mp));
        });
        let written = match rx.recv_timeout(MOUNT_WORK_TIMEOUT) {
            Ok(result) => result,
            Err(err) => Err(format!("writing through the mount did not finish: {err}")),
        };
        println!("wrote the tree: {written:?}");
        mounted.finish().expect("unmount");
        written.expect("the tree was written through the mount");
    }

    let java = verify_with_java(&vault, "interop-passphrase");
    let out = crypto(&["--json", "fs", "tree", "mounted", "--hash"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let rust: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(
        rust, java,
        "Java manifest differs from crypto fs tree for a vault written through the mount"
    );

    let entries = java.as_array().unwrap();
    println!("java manifest: {} entries", entries.len());
    // `WELCOME.rtf` from `vault create`, plus the nine nodes written through the mount.
    assert_eq!(entries.len(), 10, "{java}");
    let entry = |path: &str| {
        entries
            .iter()
            .find(|e| e["path"] == path)
            .unwrap_or_else(|| panic!("{path} missing from {java}"))
            .clone()
    };
    assert_eq!(entry("/dir")["type"], "dir");
    assert_eq!(
        entry("/dir/big.bin")["size"],
        100_000,
        "the multi-chunk file"
    );
    assert_eq!(entry("/dir/deeper/still/deep.txt")["size"], 5);
    assert_eq!(entry("/dir/link")["type"], "symlink");
    entry(&format!("/dir/{}.txt", "n".repeat(200)));
    // The decomposed name macOS handed FUSE has to be composed in the vault.
    entry("/dir/caf\u{e9}.txt");
    assert!(
        !entries
            .iter()
            .any(|e| e["path"].as_str().is_some_and(|p| p.contains("/._"))),
        "AppleDouble side cars reached the vault: {java}"
    );
}
