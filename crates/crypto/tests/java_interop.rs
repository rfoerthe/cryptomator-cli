//! Vaults created by `crypto` must open with the real cryptofs. Needs Java 21+ and Maven; run with
//! `cargo test -p crypto --test java_interop -- --ignored` (CI job `interop-java`).
use assert_cmd::Command;
use std::path::{Path, PathBuf};

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
