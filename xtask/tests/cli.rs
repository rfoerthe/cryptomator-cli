//! The built `xtask` binary, driven the way a release drives it.
//!
//! The unit tests in `man.rs` and `completions.rs` call the generators directly, so they cannot
//! see which grammar `main` hands them. These tests run the real binary: if `main` ever passed
//! `crypto::cli::Cli::command()` instead of `crypto::commands::completions::public_command()`,
//! the hidden `__daemon` would appear in a shipped page or completion script and only this file
//! would notice.
use std::path::{Path, PathBuf};
use std::process::Command;

fn xtask() -> Command {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
}

/// The files in `dir`, sorted, as names.
fn file_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn read_all(dir: &Path) -> Vec<(PathBuf, String)> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let path = e.unwrap().path();
            let body = std::fs::read_to_string(&path).unwrap();
            (path, body)
        })
        .collect()
}

#[test]
fn the_binary_writes_manpages_for_the_public_grammar_only() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("man");
    let run = xtask().args(["man", "--out"]).arg(&out).output().unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let names = file_names(&out);
    for expected in [
        "crypto.1",
        "crypto-vault.1",
        // The nested pages the SUBCOMMANDS cross-references point at.
        "crypto-vault-create.1",
        "crypto-recovery-key-restore.1",
    ] {
        assert!(names.contains(&expected.to_string()), "{names:?}");
    }
    assert!(
        !names.iter().any(|n| n.contains("__daemon")),
        "a page for the hidden command: {names:?}"
    );
    for (path, body) in read_all(&out) {
        assert!(!body.contains("__daemon"), "hidden command in {path:?}");
    }
    // Every path is printed, and the count goes to stderr.
    let stdout = String::from_utf8_lossy(&run.stdout);
    assert_eq!(stdout.lines().count(), names.len());
    assert!(
        String::from_utf8_lossy(&run.stderr).contains("manpages"),
        "no summary line"
    );
}

#[test]
fn the_binary_writes_completion_scripts_for_the_public_grammar_only() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("completions");
    let run = xtask()
        .args(["completions", "--out"])
        .arg(&out)
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(
        file_names(&out),
        vec![
            "_crypto",
            "_crypto.ps1",
            "crypto.bash",
            "crypto.elv",
            "crypto.fish"
        ]
    );
    for (path, body) in read_all(&out) {
        assert!(!body.contains("__daemon"), "hidden command in {path:?}");
        assert!(
            body.contains("vault"),
            "visible command missing in {path:?}"
        );
    }
}

/// An `--out` nobody can write to has to fail with the path in the message, not with a panic and
/// not silently: `release.yml` reads the exit code, a human reads the message.
#[cfg(unix)]
#[test]
fn an_unwritable_out_directory_fails_with_the_path_in_the_message() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let parent = dir.path().join("read-only");
    std::fs::create_dir(&parent).unwrap();
    let out = parent.join("man");
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o555)).unwrap();
    // root writes into a mode 555 directory, and then there is nothing to assert.
    let euid_is_root = std::fs::write(parent.join("probe"), b"x").is_ok();

    let run = xtask().args(["man", "--out"]).arg(&out).output().unwrap();
    // Before any assertion, so the temporary directory can be removed either way.
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();
    if euid_is_root {
        eprintln!("skipped: this user writes into a read-only directory");
        return;
    }

    assert!(!run.status.success(), "an unwritable --out succeeded");
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(
        stderr.contains(&out.display().to_string()),
        "the message does not name the path: {stderr}"
    );
    assert!(
        !stderr.contains("panicked"),
        "a panic rather than an error: {stderr}"
    );
}

/// `lipo -create` refuses two inputs of one architecture, and `xtask` has to pass that refusal on
/// rather than write a thin binary and call it universal. This is the only part of `xtask lipo`
/// that can run on a machine without both macOS toolchains.
#[test]
fn combining_two_binaries_of_one_architecture_fails_with_lipos_message() {
    if !Path::new("/usr/bin/lipo").exists() {
        eprintln!("skipped: no /usr/bin/lipo on this machine");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("crypto");
    let me = env!("CARGO_BIN_EXE_xtask");
    let run = xtask()
        .args(["lipo", "--arm64", me, "--x86-64", me, "--out"])
        .arg(&out)
        .output()
        .unwrap();
    assert!(!run.status.success(), "two thin inputs were accepted");
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(
        stderr.contains("lipo"),
        "lipo's own message did not reach stderr: {stderr}"
    );
    assert!(!out.exists(), "a binary was written anyway");
}
