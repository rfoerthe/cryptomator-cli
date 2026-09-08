//! Puts the commit and the target triple into the binary, for `crypto --version`.
//!
//! Deliberately dependency-free: it shells out to `git` and falls back to `unknown`. A build from
//! a source tarball has no `.git` and must still succeed -- and can still name its commit by
//! setting `$CRYPTO_GIT_SHA`, which wins over the git call.
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CRYPTO_GIT_SHA");

    let sha = std::env::var("CRYPTO_GIT_SHA")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(git_sha)
        .unwrap_or_else(|| "unknown".to_string());
    // `TARGET` is set by cargo for every build script; the fallback only matters if that ever
    // stops being true.
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());

    println!("cargo:rustc-env=CRYPTO_BUILD_SHA={sha}");
    println!("cargo:rustc-env=CRYPTO_BUILD_TARGET={target}");

    // Rebuild when HEAD moves, so the sha in the binary is not the one from three commits ago.
    for path in git_head_paths() {
        println!("cargo:rerun-if-changed={}", path.display());
    }
}

/// `git rev-parse --short HEAD` in the manifest directory. `None` when git is missing, the
/// directory is not a repository, or the call fails for any other reason -- never a panic: a
/// build script that dies takes the whole build with it.
fn git_sha() -> Option<String> {
    let sha = git(&["rev-parse", "--short", "HEAD"])?;
    (!sha.is_empty()).then_some(sha)
}

/// The files whose change means "HEAD moved": `HEAD` itself, which a checkout rewrites, and the
/// branch ref it points at, which a commit rewrites. Both are asked for by
/// `git rev-parse --git-path`, so this is right in a linked worktree too -- there `.git` is a
/// *file* naming `<main>/.git/worktrees/<name>/`, and that file never changes, while the real
/// `HEAD` lives in the directory it names. Paths that do not exist (a packed ref, an unborn
/// branch, a detached HEAD) are dropped: cargo treats a missing `rerun-if-changed` path as
/// permanently dirty and would rebuild the crate on every single invocation.
fn git_head_paths() -> Vec<PathBuf> {
    let mut refs = vec!["HEAD".to_string()];
    if let Some(branch) = git(&["symbolic-ref", "--quiet", "HEAD"]) {
        refs.push(branch);
    }
    refs.iter()
        .filter_map(|r| git(&["rev-parse", "--git-path", r]))
        .map(PathBuf::from)
        .filter(|path| path.exists())
        .collect()
}

/// Runs `git` in the manifest directory and returns its trimmed standard output, or `None` if
/// git is absent, this is no repository, or the command failed.
fn git(args: &[&str]) -> Option<String> {
    let dir = std::env::var("CARGO_MANIFEST_DIR").ok()?;
    let out = Command::new("git")
        .args(args)
        .current_dir(&dir)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8(out.stdout).ok()?.trim().to_string())
}
