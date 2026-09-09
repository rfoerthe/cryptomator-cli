//! `cargo xtask lipo`: the two macOS builds into one Universal Mach-O.
//!
//! `lipo` ships with the Xcode command line tools; there is no Rust crate for this and no reason
//! to write a Mach-O fat-header packer.
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

/// The triple the Universal archive is named after. Not a real target triple -- no compiler ever
/// sees it -- but the name Homebrew and `release.yml` download.
pub(crate) const UNIVERSAL_TARGET: &str = "universal-apple-darwin";

/// The absolute path, not `lipo` on the `PATH`: a pyenv shim of that name shadows Xcode's tool on
/// this machine (pre-flight finding), and the shim would fail with an unrelated message.
const LIPO: &str = "/usr/bin/lipo";

/// The archive `dist` writes for the combined binary.
pub(crate) fn universal_name(version: &str) -> String {
    crate::dist::archive_name(version, UNIVERSAL_TARGET)
}

/// Where the combined binary goes unless `--out` says otherwise.
///
/// Deliberately without the version: `target/dist/crypto-<version>-universal-apple-darwin` is the
/// name of `dist`'s staging *directory*, which `dist` deletes before it stages into it.
pub(crate) fn default_output(root: &Path) -> PathBuf {
    root.join("target")
        .join("dist")
        .join(format!("crypto-{UNIVERSAL_TARGET}"))
}

/// `/usr/bin/lipo -create <arm64> <x86_64> -output <out>`.
pub(crate) fn lipo_command(arm64: &Path, x86_64: &Path, out: &Path) -> Command {
    let mut command = Command::new(LIPO);
    command
        .arg("-create")
        .arg(arm64)
        .arg(x86_64)
        .arg("-output")
        .arg(out);
    command
}

/// Combines the two binaries and verifies the result really is fat, because `lipo -create` on two
/// copies of the same architecture succeeds and produces a thin file.
pub(crate) fn lipo(arm64: &Path, x86_64: &Path, out: &Path) -> Result<()> {
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
    }
    // `status()` and not `output()`: lipo's own diagnostics belong on our stderr, where the CI log
    // shows them.
    let status = lipo_command(arm64, x86_64, out)
        .status()
        .with_context(|| format!("cannot run {LIPO}"))?;
    if !status.success() {
        bail!("lipo failed with {status}");
    }
    let info = Command::new(LIPO)
        .arg("-info")
        .arg(out)
        .output()
        .with_context(|| format!("cannot run {LIPO} -info"))?;
    let text = String::from_utf8_lossy(&info.stdout).into_owned();
    if !(text.contains("arm64") && text.contains("x86_64")) {
        bail!("the combined binary is not universal: {}", text.trim());
    }
    println!("{}", text.trim());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_universal_archive_has_its_own_triple() {
        assert_eq!(
            universal_name("0.1.0"),
            "crypto-0.1.0-universal-apple-darwin.tar.gz"
        );
    }

    /// The default output must not collide with `dist`'s staging directory for the same target --
    /// `dist` removes that directory, and it would take the binary with it.
    #[test]
    fn the_default_output_is_not_the_staging_directory() {
        let out = default_output(Path::new("/repo"));
        assert_eq!(
            out,
            Path::new("/repo/target/dist/crypto-universal-apple-darwin")
        );
        assert_ne!(
            out.file_name().unwrap().to_string_lossy(),
            crate::dist::staging_dir_name(crate::dist::VERSION, UNIVERSAL_TARGET)
        );
    }

    /// The argument vector, built rather than interpolated into a shell: a path with a space in it
    /// must not become two arguments. The program is the absolute path, so a shim of the same name
    /// earlier on the `PATH` cannot take the call.
    #[test]
    fn the_lipo_call_is_an_argument_vector() {
        let command = lipo_command(
            Path::new("/tmp/a arm/crypto"),
            Path::new("/tmp/b intel/crypto"),
            Path::new("/tmp/out/crypto"),
        );
        assert_eq!(command.get_program(), "/usr/bin/lipo");
        let args: Vec<String> = command
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            vec![
                "-create",
                "/tmp/a arm/crypto",
                "/tmp/b intel/crypto",
                "-output",
                "/tmp/out/crypto",
            ]
        );
    }
}
