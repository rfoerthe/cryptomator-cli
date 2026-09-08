//! `cargo xtask dist`: build one target and pack everything a user needs into one tarball.
//!
//! Layout inside the archive -- one directory, so `tar xzf` never scatters files into the
//! current one:
//!
//! ```text
//! crypto-0.1.0-aarch64-apple-darwin/
//!   crypto
//!   README.md  LICENSE  CHANGELOG.md
//!   man/crypto.1  man/crypto-vault.1  man/crypto-vault-create.1  ...
//!   completions/crypto.bash  completions/_crypto  ...
//! ```
//!
//! The archive is built with the system `tar` rather than a Rust crate: `tar -czf` is present on
//! every machine this runs on (and in every CI image), and a packer crate would be a new
//! dependency for one call.
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;

/// The version the archives are named after: the workspace version, which `xtask` shares.
pub(crate) const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The file names the archive carries, in one place so a test can pin them.
pub(crate) struct Layout {
    pub binary: &'static str,
    pub docs: [&'static str; 3],
    pub man_subdir: &'static str,
    pub completions_subdir: &'static str,
}

pub(crate) fn staging_layout() -> Layout {
    Layout {
        binary: "crypto",
        docs: ["README.md", "LICENSE", "CHANGELOG.md"],
        man_subdir: "man",
        completions_subdir: "completions",
    }
}

/// The one directory the archive contains, and the archive's own name minus `.tar.gz`.
pub(crate) fn staging_dir_name(version: &str, target: &str) -> String {
    format!("crypto-{version}-{target}")
}

pub(crate) fn archive_name(version: &str, target: &str) -> String {
    format!("{}.tar.gz", staging_dir_name(version, target))
}

/// One `sha256sum`-format line for `path`: lowercase hex, two spaces, the bare file name.
pub(crate) fn sha256_line(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    let digest = Sha256::digest(&bytes);
    let hex = data_encoding::HEXLOWER.encode(&digest);
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .with_context(|| format!("not a file name: {}", path.display()))?;
    Ok(format!("{hex}  {name}"))
}

/// `SHA256SUMS` with `line` in it exactly once: a second line for the same file would make
/// `sha256sum --check` verify one archive twice and hide which of the two hashes is the current
/// one. Every other line is kept, in order, because one file holds every target's checksum.
pub(crate) fn merge_sums(existing: &str, line: &str) -> String {
    let name = line.split_once("  ").map_or(line, |(_, name)| name);
    let mut merged: String = existing
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter(|l| l.split_once("  ").is_none_or(|(_, n)| n != name))
        .map(|l| format!("{l}\n"))
        .collect();
    merged.push_str(line);
    merged.push('\n');
    merged
}

/// Whether `dist` compiles anything. An explicit `--bin` is a binary the caller already has --
/// a downloaded CI artefact, or the output of `xtask lipo` -- so it implies `--no-build`; a
/// release build would take minutes and then be ignored.
pub(crate) fn needs_build(no_build: bool, bin: Option<&Path>) -> bool {
    !no_build && bin.is_none()
}

/// Builds `target` (unless the binary is given or `no_build` is set), stages everything into
/// `target/dist/<name>/`, packs it and puts its checksum into `target/dist/SHA256SUMS`. Returns
/// the archive path.
pub(crate) fn dist(
    root: &Path,
    target: &str,
    no_build: bool,
    bin: Option<&Path>,
) -> Result<PathBuf> {
    if needs_build(no_build, bin) {
        build(root, target)?;
    }
    let dist_dir = root.join("target").join("dist");
    let stage = dist_dir.join(staging_dir_name(VERSION, target));
    // A stale staging directory from a previous run would smuggle old files into the archive.
    if stage.exists() {
        std::fs::remove_dir_all(&stage)
            .with_context(|| format!("cannot clear {}", stage.display()))?;
    }
    let layout = staging_layout();
    std::fs::create_dir_all(&stage)
        .with_context(|| format!("cannot create {}", stage.display()))?;

    let built = root
        .join("target")
        .join(target)
        .join("release")
        .join(layout.binary);
    let binary = bin.unwrap_or(&built);
    if !binary.is_file() {
        bail!(
            "{} does not exist; run without --no-build, or point --bin at a binary",
            binary.display()
        );
    }
    copy_preserving_mode(binary, &stage.join(layout.binary))?;
    for doc in layout.docs {
        copy_preserving_mode(&root.join(doc), &stage.join(doc))?;
    }
    // The grammar without `__daemon`, the same one `xtask man` and `crypto completions` use: what
    // a tarball ships and what a user generates by hand must not differ.
    let cmd = crypto::commands::completions::public_command();
    crate::man::render_all(&cmd, &stage.join(layout.man_subdir))?;
    crate::completions::generate_all(&stage.join(layout.completions_subdir))?;

    let archive = dist_dir.join(archive_name(VERSION, target));
    // `-C dist` so the archive holds `crypto-0.1.0-<target>/…` and not `target/dist/…`.
    let status = Command::new("tar")
        .arg("-czf")
        .arg(&archive)
        .arg("-C")
        .arg(&dist_dir)
        .arg(staging_dir_name(VERSION, target))
        // Apple's `tar` otherwise stores extended attributes as `._`-prefixed members, which a
        // Linux user would unpack as junk files next to the binary.
        .env("COPYFILE_DISABLE", "1")
        .status()
        .context("cannot run tar")?;
    if !status.success() {
        bail!("tar failed with {status}");
    }

    let line = sha256_line(&archive)?;
    let sums = dist_dir.join("SHA256SUMS");
    let existing = std::fs::read_to_string(&sums).unwrap_or_default();
    std::fs::write(&sums, merge_sums(&existing, &line))
        .with_context(|| format!("cannot write {}", sums.display()))?;
    println!("{}", archive.display());
    println!("{line}");
    Ok(archive)
}

/// `cargo build --release --locked -p crypto --target <target>` (Ruling 11), with the deployment
/// target the spec fixes for macOS.
fn build(root: &Path, target: &str) -> Result<()> {
    let mut command = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    command.current_dir(root).args([
        "build",
        "--release",
        "--locked",
        "-p",
        "crypto",
        "--target",
        target,
    ]);
    if target.ends_with("-apple-darwin") {
        // Spec, "Build & Packaging": the binary must run on macOS 12 and later.
        command.env("MACOSX_DEPLOYMENT_TARGET", "12.0");
    }
    let status = command.status().context("cannot run cargo")?;
    if !status.success() {
        bail!("cargo build failed with {status}");
    }
    Ok(())
}

/// `std::fs::copy` keeps the permission bits, which is what the executable bit rides on.
fn copy_preserving_mode(from: &Path, to: &Path) -> Result<()> {
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
    }
    std::fs::copy(from, to)
        .with_context(|| format!("cannot copy {} to {}", from.display(), to.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_archive_is_named_after_version_and_target() {
        assert_eq!(
            archive_name("0.1.0", "aarch64-apple-darwin"),
            "crypto-0.1.0-aarch64-apple-darwin.tar.gz"
        );
        assert_eq!(
            archive_name("0.1.0", "x86_64-unknown-linux-gnu"),
            "crypto-0.1.0-x86_64-unknown-linux-gnu.tar.gz"
        );
    }

    #[test]
    fn the_staging_directory_drops_the_tar_gz_suffix() {
        assert_eq!(
            staging_dir_name("0.1.0", "aarch64-apple-darwin"),
            "crypto-0.1.0-aarch64-apple-darwin"
        );
    }

    /// `sha256sum`'s own format: hex, two spaces, file name. Anything else and
    /// `sha256sum --check SHA256SUMS` refuses the file.
    #[test]
    fn a_checksum_line_matches_what_sha256sum_writes() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("crypto-0.1.0-test.tar.gz");
        std::fs::write(&file, b"hello\n").unwrap();
        let line = sha256_line(&file).unwrap();
        assert_eq!(
            line,
            "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03  \
             crypto-0.1.0-test.tar.gz"
        );
    }

    /// Everything the archive carries has to be listed in one place, so a forgotten file is a
    /// failing test rather than a user's missing manpage.
    #[test]
    fn the_layout_names_the_binary_the_docs_the_pages_and_the_scripts() {
        let layout = staging_layout();
        assert_eq!(layout.docs, ["README.md", "LICENSE", "CHANGELOG.md"]);
        assert_eq!(layout.man_subdir, "man");
        assert_eq!(layout.completions_subdir, "completions");
        assert_eq!(layout.binary, "crypto");
    }

    /// Re-running `dist` for one target replaces that target's line and leaves the others alone:
    /// `SHA256SUMS` collects every target of a release.
    #[test]
    fn a_second_run_replaces_its_own_line_and_keeps_the_others() {
        let linux = "1111111111111111111111111111111111111111111111111111111111111111  \
                     crypto-0.1.0-x86_64-unknown-linux-gnu.tar.gz";
        let mac_old = "2222222222222222222222222222222222222222222222222222222222222222  \
                       crypto-0.1.0-aarch64-apple-darwin.tar.gz";
        let mac_new = "3333333333333333333333333333333333333333333333333333333333333333  \
                       crypto-0.1.0-aarch64-apple-darwin.tar.gz";
        let first = merge_sums("", linux);
        assert_eq!(first, format!("{linux}\n"));
        let second = merge_sums(&first, mac_old);
        assert_eq!(second, format!("{linux}\n{mac_old}\n"));
        let third = merge_sums(&second, mac_new);
        assert_eq!(third, format!("{linux}\n{mac_new}\n"));
        // Idempotent: the same line twice leaves the file as it was.
        assert_eq!(merge_sums(&third, mac_new), third);
    }

    /// A binary handed in is a binary the caller already has -- from CI, or from `xtask lipo`.
    #[test]
    fn a_given_binary_is_never_rebuilt() {
        assert!(needs_build(false, None));
        assert!(!needs_build(true, None));
        assert!(!needs_build(false, Some(Path::new("/tmp/crypto"))));
        assert!(!needs_build(true, Some(Path::new("/tmp/crypto"))));
    }
}
