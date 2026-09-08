//! `cargo xtask <task>` -- the repository's own build tooling.
//!
//! Everything here writes into `target/` and nothing here talks to the network or to GitHub:
//! uploading is `release.yml`'s job, triggered by a tag a human pushed. Neither the manpages nor
//! the completion scripts are committed; both are rendered from the live `crypto` grammar, so
//! neither can drift from what the binary actually accepts.
#![forbid(unsafe_code)]
mod completions;
mod man;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(name = "xtask", about = "Development-time tasks for cryptomator-cli")]
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
}

/// The workspace root: `xtask/..`, resolved from this crate's manifest directory rather than from
/// the current directory, so `cargo xtask` works from anywhere in the tree.
fn workspace_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .map_or(manifest.clone(), Path::to_path_buf)
}

fn main() -> Result<()> {
    let xtask = Xtask::parse();
    let root = workspace_root();
    let (written, dir, what) = match xtask.task {
        Task::Man { out } => {
            let dir = out.unwrap_or_else(|| root.join("target/man"));
            // The grammar without `__daemon`: clap_mangen renders hidden commands like any other.
            let cmd = crypto::commands::completions::public_command();
            (man::render_all(&cmd, &dir)?, dir, "manpages")
        }
        Task::Completions { out } => {
            let dir = out.unwrap_or_else(|| root.join("target/completions"));
            (completions::generate_all(&dir)?, dir, "completion scripts")
        }
    };
    for path in &written {
        println!("{}", path.display());
    }
    eprintln!("{} {what} in {}", written.len(), dir.display());
    Ok(())
}
