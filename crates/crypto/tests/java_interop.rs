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

fn verify_with_java(vault: &Path, passphrase: &str) -> serde_json::Value {
    let output = std::process::Command::new("mvn")
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
        .expect("mvn is installed");
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
