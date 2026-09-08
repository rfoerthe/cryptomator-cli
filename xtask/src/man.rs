//! `cargo xtask man`: one roff page per visible command, rendered from the live clap grammar.
//!
//! Not committed (Ruling 3): a checked-in manpage is wrong from the first grammar commit onwards
//! and nobody notices. `target/man/` is the output, and the release workflow ships what it finds
//! there.
use std::io;
use std::path::{Path, PathBuf};

/// The page name for a command path: `[] -> crypto.1`, `["vault"] -> crypto-vault.1`.
///
/// git's convention, so `man crypto-vault` works and `man 1 crypto` stays the overview. The path
/// is a slice rather than an `Option` because the convention is the same at any depth, even though
/// [`render_all`] gives its own page to the root and the top level only.
fn man_file_name(path: &[&str]) -> String {
    let mut name = String::from("crypto");
    for segment in path {
        name.push('-');
        name.push_str(segment);
    }
    name.push_str(".1");
    name
}

/// Renders `cmd` and each of its visible subcommands into `out`, returning what it wrote.
///
/// `cmd` is expected to be [`crypto::commands::completions::public_command`] — the grammar without
/// the hidden `__daemon`. Hidden commands are skipped here as well, because `clap_mangen` renders
/// them like any other and a page for `__daemon` would document a command nobody may run.
///
/// Nesting stops at the top level: `crypto recovery-key restore` is documented in the SUBCOMMANDS
/// section of `crypto-recovery-key.1`, which is where a reader of that page looks for it.
pub(crate) fn render_all(cmd: &clap::Command, out: &Path) -> io::Result<Vec<PathBuf>> {
    std::fs::create_dir_all(out)
        .map_err(|e| context(e, &format!("cannot create {}", out.display())))?;
    let mut written = vec![render_one(cmd, &[], out)?];
    for sub in cmd.get_subcommands() {
        // `help` is clap's own subcommand, added by `build()`; its page would only say what
        // `crypto --help` already prints.
        if sub.is_hide_set() || sub.get_name() == "help" {
            continue;
        }
        written.push(render_one(sub, &[sub.get_name()], out)?);
    }
    Ok(written)
}

/// Renders the page for one command, reached by `path` from the root, into `out`.
fn render_one(cmd: &clap::Command, path: &[&str], out: &Path) -> io::Result<PathBuf> {
    let file_name = man_file_name(path);
    let page_name = file_name.trim_end_matches(".1").to_string();
    // `clap_mangen` takes the command's own name for the synopsis, and a subcommand's name is the
    // bare word (`vault`). Renaming the clone gives `crypto-vault` there, and the explicit title
    // gives `CRYPTO-VAULT(1)` in the header -- `.TH` titles are all caps by convention, and
    // clap_mangen leaves the name's case alone.
    let titled = cmd.clone().name(page_name.clone());
    let mut buf: Vec<u8> = Vec::new();
    clap_mangen::Man::new(titled)
        .title(page_name.to_uppercase())
        .render(&mut buf)
        .map_err(|e| context(e, &format!("cannot render {file_name}")))?;
    let target = out.join(&file_name);
    std::fs::write(&target, &buf)
        .map_err(|e| context(e, &format!("cannot write {}", target.display())))?;
    Ok(target)
}

/// Puts the path back into an `io::Error`, which otherwise says only "No such file or directory".
fn context(err: io::Error, what: &str) -> io::Error {
    io::Error::new(err.kind(), format!("{what}: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{Arg, Command};

    /// A command tree with the shape that matters here: a nested subcommand and a hidden one.
    fn sample() -> Command {
        Command::new("crypto")
            .version("0.1.0")
            .subcommand(
                Command::new("vault").about("vaults").subcommand(
                    Command::new("create")
                        .about("create one")
                        .arg(Arg::new("path")),
                ),
            )
            .subcommand(Command::new("__daemon").hide(true))
    }

    fn file_names(paths: &[PathBuf]) -> Vec<String> {
        let mut names: Vec<String> = paths
            .iter()
            .filter_map(|p| p.file_name())
            .map(|n| n.to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// git's convention: the page for `crypto vault create` is `crypto-vault-create.1`, so
    /// `man crypto-vault-create` works and `man 1 crypto` stays the overview.
    #[test]
    fn a_page_is_named_after_its_command_path() {
        assert_eq!(man_file_name(&[]), "crypto.1");
        assert_eq!(man_file_name(&["vault"]), "crypto-vault.1");
        assert_eq!(man_file_name(&["vault", "create"]), "crypto-vault-create.1");
        assert_eq!(
            man_file_name(&["recovery-key", "restore"]),
            "crypto-recovery-key-restore.1"
        );
    }

    /// The overview plus one page per visible top-level command -- and none for a hidden one: a
    /// page for `__daemon` would document a command users must never run.
    #[test]
    fn it_renders_one_page_per_visible_top_level_command_and_skips_hidden_ones() {
        let dir = tempfile::tempdir().unwrap();
        let written = render_all(&sample(), dir.path()).unwrap();
        assert_eq!(file_names(&written), vec!["crypto-vault.1", "crypto.1"]);
        for path in &written {
            let page = std::fs::read_to_string(path).unwrap();
            assert!(page.starts_with(".ie"), "not roff: {path:?}");
        }
        assert!(!dir.path().join("crypto-__daemon.1").exists());
        // The nested command is documented inside its parent's page, not in one of its own.
        assert!(!dir.path().join("crypto-vault-create.1").exists());
        let vault = std::fs::read_to_string(dir.path().join("crypto-vault.1")).unwrap();
        assert!(vault.contains("create"), "nested command missing: {vault}");
    }

    /// clap's auto-generated `help` subcommand appears once the command is built; it gets no page.
    #[test]
    fn the_generated_help_subcommand_gets_no_page() {
        let dir = tempfile::tempdir().unwrap();
        let mut built = sample();
        built.build();
        assert!(
            built.get_subcommands().any(|c| c.get_name() == "help"),
            "clap no longer adds a `help` subcommand -- the filter can go"
        );
        let written = render_all(&built, dir.path()).unwrap();
        assert_eq!(file_names(&written), vec!["crypto-vault.1", "crypto.1"]);
    }

    /// The header is what `man` shows in the top and bottom margins, and it is all caps there.
    #[test]
    fn every_page_header_names_its_own_command_in_caps() {
        let dir = tempfile::tempdir().unwrap();
        render_all(&sample(), dir.path()).unwrap();
        let overview = std::fs::read_to_string(dir.path().join("crypto.1")).unwrap();
        assert!(overview.contains(".TH CRYPTO 1"), "{overview}");
        let vault = std::fs::read_to_string(dir.path().join("crypto-vault.1")).unwrap();
        // The `.TH` arguments are not roff-escaped, unlike the body text below them.
        assert!(vault.contains(".TH CRYPTO-VAULT 1"), "{vault}");
        // The synopsis of a subcommand page names the hyphenated command, not the bare word.
        assert!(vault.contains("crypto\\-vault"), "{vault}");
    }

    /// The overview page has to carry the version, because that is what a bug report quotes.
    #[test]
    fn the_overview_page_carries_the_version() {
        let dir = tempfile::tempdir().unwrap();
        render_all(&Command::new("crypto").version("9.9.9-test"), dir.path()).unwrap();
        let page = std::fs::read_to_string(dir.path().join("crypto.1")).unwrap();
        assert!(page.contains("9.9.9\\-test"), "version missing: {page}");
    }

    /// The output directory is the caller's choice and does not have to exist yet.
    #[test]
    fn it_writes_into_the_directory_it_is_given_and_creates_it() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("nested/man");
        let written = render_all(&sample(), &out).unwrap();
        assert!(written.iter().all(|p| p.starts_with(&out)), "{written:?}");
        assert!(out.join("crypto.1").is_file());
    }

    /// Running the task twice overwrites the pages instead of appending to them or adding new
    /// ones -- `cargo xtask man` is something one runs repeatedly during a release.
    #[test]
    fn rendering_twice_leaves_the_same_files() {
        let dir = tempfile::tempdir().unwrap();
        let first = render_all(&sample(), dir.path()).unwrap();
        let first_page = std::fs::read_to_string(dir.path().join("crypto.1")).unwrap();
        let second = render_all(&sample(), dir.path()).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("crypto.1")).unwrap(),
            first_page
        );
        let on_disk: Vec<String> = {
            let mut names: Vec<String> = std::fs::read_dir(dir.path())
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        };
        assert_eq!(on_disk, file_names(&second));
    }

    /// The real grammar, not a fixture: every visible command a user can type has a page, the
    /// overview carries the sections `man` renders, and `__daemon` is nowhere.
    #[test]
    fn the_real_grammar_gets_a_page_per_visible_command() {
        let dir = tempfile::tempdir().unwrap();
        let public = crypto::commands::completions::public_command();
        let expected: Vec<String> = std::iter::once("crypto.1".to_string())
            .chain(
                public
                    .get_subcommands()
                    .map(|c| format!("crypto-{}.1", c.get_name())),
            )
            .collect();
        let written = render_all(&public, dir.path()).unwrap();
        let mut expected_sorted = expected.clone();
        expected_sorted.sort();
        assert_eq!(file_names(&written), expected_sorted);
        assert!(
            expected.contains(&"crypto-vault.1".to_string()),
            "{expected:?}"
        );
        assert!(
            expected.contains(&"crypto-recovery-key.1".to_string()),
            "{expected:?}"
        );

        let overview = std::fs::read_to_string(dir.path().join("crypto.1")).unwrap();
        assert!(overview.contains(".TH CRYPTO 1"), "no title");
        assert!(overview.contains(".SH NAME"), "no NAME section");
        assert!(overview.contains(".SH SYNOPSIS"), "no SYNOPSIS section");
        for sub in public.get_subcommands() {
            let name = sub.get_name().replace('-', "\\-");
            assert!(overview.contains(&name), "{name} missing from the overview");
        }
        for path in &written {
            let page = std::fs::read_to_string(path).unwrap();
            assert!(!page.contains("__daemon"), "hidden command in {path:?}");
        }
    }
}
