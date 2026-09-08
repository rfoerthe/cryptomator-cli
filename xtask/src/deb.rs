//! `cargo xtask deb`: the Debian package, via cargo-deb.
//!
//! The manpages and completion scripts do not exist in a fresh checkout (Ruling 3), so this task
//! generates them into the paths `[package.metadata.deb].assets` names before handing over to
//! `cargo deb`. Running `cargo deb` directly works too -- as long as `cargo xtask man` and
//! `cargo xtask completions` ran first.
//!
//! The binary is built here, the way `xtask dist` builds it (`--release --locked --target …`), and
//! `cargo deb` is then told `--no-build`: letting cargo-deb build again would produce a second,
//! differently configured binary in the same tree.
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

/// The manifest carrying `[package.metadata.deb]`, relative to the workspace root. cargo-deb
/// resolves every asset path against *its* directory, so this is also the base of the `../../`
/// paths in that section.
pub(crate) const MANIFEST: &str = "crates/crypto/Cargo.toml";

/// Where `xtask man` and `xtask completions` have to write for the asset paths to resolve.
pub(crate) fn man_dir(root: &Path) -> PathBuf {
    root.join("target").join("man")
}

pub(crate) fn completions_dir(root: &Path) -> PathBuf {
    root.join("target").join("completions")
}

/// `cargo` -- the one running this xtask, if cargo said which.
fn cargo() -> Command {
    Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
}

/// `cargo deb --manifest-path <manifest> --target <triple> --no-build --no-strip --output <dir>`.
///
/// `--no-strip` because the binary is packaged exactly as it was built and as the tarballs ship
/// it; stripping here would put a different `crypto` in the `.deb` than in the archive with the
/// same version.
pub(crate) fn deb_command(manifest: &Path, target: &str, out_dir: &Path) -> Command {
    let mut command = cargo();
    command
        .arg("deb")
        .arg("--manifest-path")
        .arg(manifest)
        .args(["--target", target])
        .arg("--no-build")
        .arg("--no-strip")
        .arg("--output")
        .arg(out_dir);
    command
}

/// Whether `cargo deb` can be run at all. `cargo` itself always exists, so a missing cargo-deb
/// surfaces as an unknown subcommand rather than as a failure to spawn -- and the message cargo
/// prints for that does not say how to fix it.
fn ensure_cargo_deb() -> Result<()> {
    let out = cargo()
        .args(["deb", "--version"])
        .output()
        .context("cannot run cargo")?;
    if !out.status.success() {
        bail!("`cargo deb` is not available; install it with `cargo install cargo-deb --locked`");
    }
    Ok(())
}

/// Builds the binary (unless `no_build`), generates the assets the manifest points at, then builds
/// the package into `target/dist/`.
pub(crate) fn deb(root: &Path, target: &str, no_build: bool) -> Result<()> {
    // Before a five-minute release build, not after it.
    ensure_cargo_deb()?;
    if !no_build {
        crate::dist::build(root, target)?;
    }

    let man_dir = man_dir(root);
    // A page left over from an older grammar would be swept into the package by the `*.1` glob,
    // and `man crypto-vault-gone` would then document a command that no longer exists.
    if man_dir.exists() {
        std::fs::remove_dir_all(&man_dir)
            .with_context(|| format!("cannot clear {}", man_dir.display()))?;
    }
    // The grammar without `__daemon`, the same one the tarballs carry.
    let cmd = crypto::commands::completions::public_command();
    crate::man::render_all(&cmd, &man_dir)?;
    crate::completions::generate_all(&completions_dir(root))?;

    let pages = man_asset_paths(&man_dir)?;
    if pages.is_empty() {
        bail!(
            "no manpages in {}; the package's `target/man/*.1` asset would match nothing",
            man_dir.display()
        );
    }
    eprintln!("{} manpages in {}", pages.len(), man_dir.display());

    let out_dir = root.join("target").join("dist");
    std::fs::create_dir_all(&out_dir)
        .with_context(|| format!("cannot create {}", out_dir.display()))?;
    let status = deb_command(&root.join(MANIFEST), target, &out_dir)
        .current_dir(root)
        .status()
        .context("cannot run cargo")?;
    if !status.success() {
        bail!("cargo deb failed with {status}");
    }
    Ok(())
}

/// The manpages `cargo xtask man` produced, sorted -- the files the `target/man/*.1` asset entry
/// expands to, for the check above and for a caller that wants to list them.
pub(crate) fn man_asset_paths(man_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut pages: Vec<PathBuf> = std::fs::read_dir(man_dir)
        .with_context(|| format!("cannot list {}", man_dir.display()))?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|e| e == "1"))
        .collect();
    pages.sort();
    Ok(pages)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::sync::Mutex;
    use toml_edit::DocumentMut;

    /// `target/man` and `target/completions` are the repository's own directories, shared by
    /// every test that generates into them: two tests rendering there at once would list a
    /// half-written directory.
    static GENERATED: Mutex<()> = Mutex::new(());

    fn root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask has a parent directory")
            .to_path_buf()
    }

    /// The parsed `[package.metadata.deb]` table of the real manifest -- what cargo-deb reads.
    fn deb_metadata() -> toml_edit::Item {
        let path = root().join(MANIFEST);
        let text = std::fs::read_to_string(&path).expect("the crypto manifest is readable");
        let doc: DocumentMut = text.parse().expect("the crypto manifest is valid TOML");
        doc["package"]["metadata"]["deb"].clone()
    }

    fn string_at(item: &toml_edit::Item, key: &str) -> String {
        item.get(key)
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("[package.metadata.deb] has no string `{key}`"))
            .to_string()
    }

    /// `[source, destination, mode]`, as cargo-deb parses them.
    fn assets(metadata: &toml_edit::Item) -> Vec<(String, String, String)> {
        metadata["assets"]
            .as_array()
            .expect("`assets` is an array")
            .iter()
            .map(|entry| {
                let row: Vec<String> = entry
                    .as_array()
                    .expect("every asset is an array")
                    .iter()
                    .map(|v| v.as_str().expect("asset fields are strings").to_string())
                    .collect();
                assert_eq!(row.len(), 3, "an asset needs source, destination and mode");
                (row[0].clone(), row[1].clone(), row[2].clone())
            })
            .collect()
    }

    /// What one asset source expands to on disk, relative to the manifest's own directory --
    /// cargo-deb's `path_in_cargo_crate`, plus its `*` glob.
    fn expand(package_dir: &Path, source: &str) -> Vec<PathBuf> {
        let full = package_dir.join(source);
        let Some(name) = full.file_name().and_then(|n| n.to_str()) else {
            return Vec::new();
        };
        if !name.contains('*') {
            return if full.is_file() {
                vec![full]
            } else {
                Vec::new()
            };
        }
        let (prefix, suffix) = name.split_once('*').expect("the name has a `*`");
        let dir = full.parent().expect("a glob has a parent directory");
        let mut matches: Vec<PathBuf> = std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(prefix) && n.ends_with(suffix))
            })
            .collect();
        matches.sort();
        matches
    }

    /// The argument vector: `--manifest-path` (cargo-deb resolves the asset paths against its
    /// directory), the target, `--no-build` (the binary is the one `xtask`/`dist` built with
    /// `--locked`), `--no-strip` (the same bytes the tarball ships) and the shared output
    /// directory.
    #[test]
    fn the_deb_call_is_an_argument_vector_over_a_prebuilt_binary() {
        let command = deb_command(
            Path::new("/w/crates/crypto/Cargo.toml"),
            "x86_64-unknown-linux-gnu",
            Path::new("/w/target/dist"),
        );
        let args: Vec<String> = command
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            vec![
                "deb",
                "--manifest-path",
                "/w/crates/crypto/Cargo.toml",
                "--target",
                "x86_64-unknown-linux-gnu",
                "--no-build",
                "--no-strip",
                "--output",
                "/w/target/dist",
            ]
        );
    }

    /// Every asset source has to resolve to a file that exists, or `cargo deb` stops with
    /// "No files match" and the release job fails after everything else has already run.
    ///
    /// This generates the pages and the scripts exactly where `xtask deb` does and then resolves
    /// the manifest's own paths against `crates/crypto/`, which is the directory cargo-deb joins
    /// them to. A `../../` dropped from one entry fails here rather than in CI.
    #[test]
    fn every_asset_source_resolves_to_a_file_that_exists() {
        let _generated = GENERATED
            .lock()
            .expect("the generation lock is not poisoned");
        let root = root();
        let package_dir = root.join(MANIFEST);
        let package_dir = package_dir.parent().expect("the manifest has a directory");
        let cmd = crypto::commands::completions::public_command();
        crate::man::render_all(&cmd, &man_dir(&root)).expect("manpages render");
        crate::completions::generate_all(&completions_dir(&root)).expect("scripts generate");

        let metadata = deb_metadata();
        let mut built = 0;
        for (source, destination, mode) in assets(&metadata) {
            if source.starts_with("target/release/") {
                // cargo-deb's placeholder for the build-products directory; it is rewritten to
                // `target/<triple>/release/` and so cannot be checked against the checkout.
                assert_eq!(source, "target/release/crypto");
                assert_eq!(destination, "usr/bin/crypto");
                assert_eq!(mode, "755");
                built += 1;
                continue;
            }
            let matched = expand(package_dir, &source);
            assert!(
                !matched.is_empty(),
                "the asset `{source}` matches no file below {}",
                package_dir.display()
            );
        }
        assert_eq!(built, 1, "exactly one asset is the built binary");
    }

    /// Every page `cargo xtask man` writes must end up in the package, otherwise it ships a
    /// `crypto.1` and silently drops `crypto-vault-create.1`. The wildcard is what covers a new
    /// subcommand automatically -- this checks that it really expands to all of them.
    #[test]
    fn the_manpage_asset_covers_every_generated_page() {
        let _generated = GENERATED
            .lock()
            .expect("the generation lock is not poisoned");
        let root = root();
        let package_dir = root.join(MANIFEST);
        let package_dir = package_dir.parent().expect("the manifest has a directory");
        let cmd = crypto::commands::completions::public_command();
        let rendered = crate::man::render_all(&cmd, &man_dir(&root)).expect("manpages render");
        let listed = man_asset_paths(&man_dir(&root)).expect("the pages are listable");

        let metadata = deb_metadata();
        let man_asset = assets(&metadata)
            .into_iter()
            .find(|(_, destination, _)| destination == "usr/share/man/man1/")
            .expect("an asset installs into usr/share/man/man1/");
        // By file name: the glob resolves through `crates/crypto/../../`, `render_all` returns
        // the same files spelled from the root, and both name the identical directory.
        let names = |paths: &[PathBuf]| -> BTreeSet<String> {
            paths
                .iter()
                .filter(|p| p.extension().is_some_and(|e| e == "1"))
                .filter_map(|p| p.file_name().and_then(|n| n.to_str()).map(str::to_string))
                .collect()
        };
        let matched = names(&expand(package_dir, &man_asset.0));
        let expected = names(&rendered);
        assert!(expected.len() > 20, "the grammar has more than 20 pages");
        assert_eq!(
            matched, expected,
            "the `{}` asset does not cover every rendered page",
            man_asset.0
        );
        assert_eq!(
            names(&listed),
            expected,
            "man_asset_paths and the asset glob disagree"
        );
        assert_eq!(man_asset.2, "644");
    }

    /// The runtime facts the spec fixes for the package, read as cargo-deb reads them: `fuse3` is
    /// a run-time call (`fusermount3`) that no linker records, and the keyring tools are optional.
    #[test]
    fn the_package_declares_fuse3_and_recommends_the_keyring_tools() {
        let metadata = deb_metadata();
        assert_eq!(string_at(&metadata, "depends"), "$auto, fuse3");
        assert_eq!(
            string_at(&metadata, "recommends"),
            "gnome-keyring, libsecret-tools"
        );
        assert_eq!(string_at(&metadata, "section"), "utils");
        assert_eq!(string_at(&metadata, "priority"), "optional");
        assert_eq!(
            string_at(&metadata, "maintainer"),
            "cryptomator-cli maintainers <cryptomator-cli@users.noreply.github.com>"
        );
        assert!(string_at(&metadata, "extended-description").contains("Cryptomator"));
    }

    /// `license-file` is resolved against the manifest's directory like any asset, so the same
    /// `../../` applies -- and a wrong path fails the package build, not the metadata parse.
    #[test]
    fn the_licence_file_resolves_from_the_package_directory() {
        let root = root();
        let package_dir = root.join(MANIFEST);
        let package_dir = package_dir.parent().expect("the manifest has a directory");
        let metadata = deb_metadata();
        let entry = metadata["license-file"]
            .as_array()
            .expect("`license-file` is an array");
        let path = entry
            .get(0)
            .and_then(|v| v.as_str())
            .expect("the first element is the path");
        assert_eq!(
            entry.get(1).and_then(|v| v.as_str()),
            Some("0"),
            "no lines are skipped"
        );
        assert!(
            package_dir.join(path).is_file(),
            "the licence file `{path}` does not exist below {}",
            package_dir.display()
        );
    }
}
