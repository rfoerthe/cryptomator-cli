//! `xtask dist`, run as the binary and unpacked again.
//!
//! The tests never build a release binary -- that takes minutes because of `lto = "fat"`. They
//! pass `--no-build --bin <a binary that is already here>`, which is also what `release.yml` does
//! with a downloaded artefact, and then look at what came out of `tar`.
//!
//! The target triple is deliberately not a real one: `dist` writes into the repository's own
//! `target/dist`, and a test must not overwrite the archive a developer just built for the host.
//! It also carries this process's pid, because `target/dist` is shared with every *other* `cargo
//! test` running in the same checkout: with a fixed name, a second run's `dist` would
//! `remove_dir_all` the staging directory this one is in the middle of packing, and `tar` failed
//! with "Couldn't visit directory". The mutex below only orders the two tests inside one binary.
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The triple these tests pack for: unique per process, see the module comment.
fn target() -> String {
    format!("xtask-test-{}", std::process::id())
}

/// `target/dist/SHA256SUMS` is one file both tests rewrite; cargo runs them in threads.
static DIST: Mutex<()> = Mutex::new(());

/// Removes what a run left in the shared `target/dist`: the staging directory and the archive.
/// The `SHA256SUMS` line stays -- rewriting the file others append to is the race this avoids.
fn clean_up(dist_dir: &Path, target: &str) {
    let _ = std::fs::remove_dir_all(dist_dir.join(format!("crypto-{VERSION}-{target}")));
    let _ = std::fs::remove_file(dist_dir.join(format!("crypto-{VERSION}-{target}.tar.gz")));
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

/// A binary to pack. The real `crypto` when a debug build is lying around (the usual case during
/// `cargo test --workspace`), otherwise `xtask` itself -- the test only needs a file that is
/// executable and answers `--version`.
fn payload() -> PathBuf {
    let debug = root().join("target").join("debug").join("crypto");
    if debug.is_file() {
        debug
    } else {
        PathBuf::from(env!("CARGO_BIN_EXE_xtask"))
    }
}

/// Runs `xtask dist` for the test triple and returns its stdout.
fn run_dist(target: &str) -> String {
    let run = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["dist", "--target", target, "--no-build", "--bin"])
        .arg(payload())
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "dist failed: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    String::from_utf8_lossy(&run.stdout).into_owned()
}

/// Every path below `dir`, directories included, relative to `dir`'s parent.
fn walk(dir: &Path, base: &Path, into: &mut BTreeSet<String>) {
    into.insert(
        dir.strip_prefix(base)
            .unwrap()
            .to_string_lossy()
            .into_owned(),
    );
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            walk(&path, base, into);
        } else {
            into.insert(
                path.strip_prefix(base)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
            );
        }
    }
}

fn members(archive: &Path) -> BTreeSet<String> {
    let listing = Command::new("tar")
        .arg("-tzf")
        .arg(archive)
        .output()
        .unwrap();
    assert!(listing.status.success(), "tar -tzf failed");
    String::from_utf8_lossy(&listing.stdout)
        .lines()
        .map(|l| l.trim_end_matches('/').to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

#[test]
fn the_archive_holds_the_binary_the_docs_the_pages_and_the_scripts() {
    let _guard = DIST.lock().unwrap_or_else(|e| e.into_inner());
    let target = target();
    let stdout = run_dist(&target);
    let archive = PathBuf::from(stdout.lines().next().unwrap());
    assert_eq!(
        archive.file_name().unwrap().to_string_lossy(),
        format!("crypto-{VERSION}-{target}.tar.gz")
    );
    assert!(archive.is_file(), "{archive:?} was not written");

    let dist_dir = archive.parent().unwrap().to_path_buf();
    let stage = dist_dir.join(format!("crypto-{VERSION}-{target}"));
    let mut staged = BTreeSet::new();
    walk(&stage, &dist_dir, &mut staged);
    // The exact member set: what was staged, nothing else. In particular no `._`-prefixed
    // AppleDouble members, which Apple's `tar` adds for extended attributes unless told not to.
    assert_eq!(members(&archive), staged);

    let prefix = format!("crypto-{VERSION}-{target}");
    for expected in [
        "crypto",
        "README.md",
        "LICENSE",
        "CHANGELOG.md",
        "man/crypto.1",
        "man/crypto-vault.1",
        "man/crypto-vault-create.1",
        "completions/crypto.bash",
        "completions/_crypto",
        "completions/crypto.fish",
        "completions/crypto.elv",
        "completions/_crypto.ps1",
    ] {
        assert!(
            staged.contains(&format!("{prefix}/{expected}")),
            "{expected} is not in the archive: {staged:?}"
        );
    }
    assert!(
        !staged.iter().any(|m| m.contains("__daemon")),
        "the hidden command is packaged: {staged:?}"
    );

    // Unpacked somewhere else, the binary is still executable.
    let unpack = tempfile::tempdir().unwrap();
    let untar = Command::new("tar")
        .arg("-xzf")
        .arg(&archive)
        .arg("-C")
        .arg(unpack.path())
        .status()
        .unwrap();
    assert!(untar.success(), "tar -xzf failed");
    let binary = unpack.path().join(&prefix).join("crypto");
    let version = Command::new(&binary).arg("--version").output().unwrap();
    assert!(
        version.status.success(),
        "{binary:?} --version failed: {}",
        String::from_utf8_lossy(&version.stderr)
    );
    assert!(
        String::from_utf8_lossy(&version.stdout).contains(VERSION),
        "--version does not name the version: {}",
        String::from_utf8_lossy(&version.stdout)
    );
    clean_up(&dist_dir, &target);
}

#[test]
fn the_checksum_file_lists_each_archive_exactly_once() {
    let _guard = DIST.lock().unwrap_or_else(|e| e.into_inner());
    let target = target();
    run_dist(&target);
    // A second run for the same target must replace its line, not add another one: two lines for
    // one file make `sha256sum --check` verify it twice and hide which hash is current.
    let stdout = run_dist(&target);
    let mut lines = stdout.lines();
    let archive = PathBuf::from(lines.next().unwrap());
    let printed = lines.next().unwrap();
    let name = archive.file_name().unwrap().to_string_lossy().into_owned();

    let dist_dir = archive.parent().unwrap().to_path_buf();
    let sums = dist_dir.join("SHA256SUMS");
    let body = std::fs::read_to_string(&sums).unwrap();
    let ours: Vec<&str> = body
        .lines()
        .filter(|l| l.ends_with(&format!("  {name}")))
        .collect();
    assert_eq!(ours.len(), 1, "{name} appears {} times", ours.len());
    assert_eq!(ours[0], printed, "the file and stdout disagree");

    // `sha256sum`'s format: 64 lowercase hex digits, two spaces, the bare file name.
    let (hex, rest) = printed.split_at(64);
    assert!(
        hex.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "not lowercase hex: {hex}"
    );
    assert_eq!(rest, format!("  {name}"));
    assert!(body.ends_with('\n'), "the last line has no newline");
    clean_up(&dist_dir, &target);
}
