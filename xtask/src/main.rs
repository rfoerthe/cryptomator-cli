//! `cargo xtask <task>` -- the repository's own build tooling.
//!
//! Everything here writes into `target/` and nothing here talks to the network or to GitHub:
//! uploading is `release.yml`'s job, triggered by a tag a human pushed. Neither the manpages nor
//! the completion scripts are committed; both are rendered from the live `crypto` grammar, so
//! neither can drift from what the binary actually accepts.
#![forbid(unsafe_code)]
mod completions;
mod dist;
mod lipo;
mod man;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(
    name = "xtask",
    version,
    about = "Development-time tasks for cryptomator-cli"
)]
struct Xtask {
    #[command(subcommand)]
    task: Task,
}

#[derive(Subcommand, Debug)]
enum Task {
    /// Render one roff manpage per visible command
    Man {
        /// Where to write the pages (default: target/man)
        #[arg(long, value_name = "DIR")]
        out: Option<PathBuf>,
    },
    /// Write the five shell completion scripts as files
    Completions {
        /// Where to write the scripts (default: target/completions)
        #[arg(long, value_name = "DIR")]
        out: Option<PathBuf>,
    },
    /// Build one target and pack binary, docs, manpages and completions into a tarball
    Dist {
        /// Target triple (default: the host's)
        #[arg(long, value_name = "TRIPLE")]
        target: Option<String>,
        /// Use the binary that is already in target/<triple>/release
        #[arg(long)]
        no_build: bool,
        /// Pack this binary instead (a CI artefact, or `xtask lipo`'s output); implies --no-build
        #[arg(long, value_name = "FILE")]
        bin: Option<PathBuf>,
    },
    /// Combine an arm64 and an x86_64 macOS binary into a Universal one, then pack it
    Lipo {
        /// The aarch64-apple-darwin binary
        #[arg(long, value_name = "FILE")]
        arm64: PathBuf,
        /// The x86_64-apple-darwin binary
        #[arg(long = "x86-64", value_name = "FILE")]
        x86_64: PathBuf,
        /// Where the combined binary goes (default: target/dist/crypto-universal-apple-darwin)
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
    },
}

/// The workspace root: `xtask/..`, resolved from this crate's manifest directory rather than from
/// the current directory, so `cargo xtask` works from anywhere in the tree.
fn workspace_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .map_or(manifest.clone(), Path::to_path_buf)
}

/// The host triple, read from `rustc -vV` -- the same value cargo would use for a build without
/// `--target`.
fn host_triple() -> Result<String> {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let out = std::process::Command::new(&rustc)
        .arg("-vV")
        .output()
        .with_context(|| format!("cannot run {rustc} -vV"))?;
    let text = String::from_utf8_lossy(&out.stdout);
    match text.lines().find_map(|line| line.strip_prefix("host: ")) {
        Some(triple) => Ok(triple.trim().to_string()),
        None => bail!("{rustc} -vV does not report a host triple; pass --target"),
    }
}

/// What `man` and `completions` print: every path on stdout, a count on stderr.
fn report(written: &[PathBuf], dir: &Path, what: &str) {
    for path in written {
        println!("{}", path.display());
    }
    eprintln!("{} {what} in {}", written.len(), dir.display());
}

fn main() -> Result<()> {
    let xtask = Xtask::parse();
    let root = workspace_root();
    match xtask.task {
        Task::Man { out } => {
            let dir = out.unwrap_or_else(|| root.join("target/man"));
            // The grammar without `__daemon`: clap_mangen renders hidden commands like any other.
            let cmd = crypto::commands::completions::public_command();
            report(&man::render_all(&cmd, &dir)?, &dir, "manpages");
        }
        Task::Completions { out } => {
            let dir = out.unwrap_or_else(|| root.join("target/completions"));
            report(
                &completions::generate_all(&dir)?,
                &dir,
                "completion scripts",
            );
        }
        Task::Dist {
            target,
            no_build,
            bin,
        } => {
            let triple = match target {
                Some(triple) => triple,
                None => host_triple()?,
            };
            dist::dist(&root, &triple, no_build, bin.as_deref())?;
        }
        Task::Lipo { arm64, x86_64, out } => {
            let binary = out.unwrap_or_else(|| lipo::default_output(&root));
            lipo::lipo(&arm64, &x86_64, &binary)?;
            // The universal binary is not where a `--target` build would put it, so `dist` gets
            // told about it rather than guessing.
            let archive = dist::dist(&root, lipo::UNIVERSAL_TARGET, true, Some(&binary))?;
            // The name `release.yml` and the Homebrew formula spell out by hand. If `dist` ever
            // names the archive differently, the release would upload a file nobody downloads.
            let expected = lipo::universal_name(dist::VERSION);
            if archive.file_name().and_then(|n| n.to_str()) != Some(expected.as_str()) {
                bail!(
                    "packed {} but the release expects {expected}",
                    archive.display()
                );
            }
        }
    }
    Ok(())
}
