//! `cargo xtask completions`: the five completion scripts as files, for the packages.
//!
//! Same generator and same command as `crypto completions <shell>` (Ruling 4) -- both go through
//! `crypto::commands::completions::public_command()`, so what a user installs by hand and what a
//! `.deb` ships cannot differ, and neither of them offers the hidden `__daemon`. The file names
//! are the ones each shell looks for, so a package can drop them straight into the shell's
//! completion directory.
use clap_complete::Shell;
use std::io;
use std::path::{Path, PathBuf};

/// The five shells and the file name each one expects.
const SHELLS: &[(Shell, &str)] = &[
    (Shell::Bash, "crypto.bash"),
    (Shell::Zsh, "_crypto"),
    (Shell::Fish, "crypto.fish"),
    (Shell::Elvish, "crypto.elv"),
    (Shell::PowerShell, "_crypto.ps1"),
];

/// Writes all five scripts into `out`, returning the paths in the order of [`SHELLS`].
pub(crate) fn generate_all(out: &Path) -> io::Result<Vec<PathBuf>> {
    std::fs::create_dir_all(out)
        .map_err(|e| io::Error::new(e.kind(), format!("cannot create {}: {e}", out.display())))?;
    let mut written = Vec::with_capacity(SHELLS.len());
    for (shell, file_name) in SHELLS {
        let mut command = crypto::commands::completions::public_command();
        // `generate` needs the name separately -- it does not take it from the command -- and it
        // must be the one a user types, not the crate name.
        let name = command.get_name().to_string();
        // Into a buffer first: `generate` takes a `&mut dyn Write` whose errors it swallows, so a
        // failed write to a file would go unnoticed. A completion script is a few dozen kilobytes.
        let mut buf: Vec<u8> = Vec::new();
        clap_complete::generate(*shell, &mut command, name, &mut buf);
        let target = out.join(file_name);
        std::fs::write(&target, &buf).map_err(|e| {
            io::Error::new(e.kind(), format!("cannot write {}: {e}", target.display()))
        })?;
        written.push(target);
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The marker each shell's own script carries, keyed by file name.
    const MARKERS: &[(&str, &str)] = &[
        ("crypto.bash", "complete -F _crypto"),
        ("_crypto", "#compdef crypto"),
        ("crypto.fish", "complete -c crypto"),
        ("crypto.elv", "edit:completion:arg-completer[crypto]"),
        ("_crypto.ps1", "Register-ArgumentCompleter"),
    ];

    /// All five files appear, each with its shell's marker -- a generator wired to the wrong shell
    /// would still produce five non-empty files.
    #[test]
    fn it_writes_one_script_per_shell() {
        let dir = tempfile::tempdir().unwrap();
        let written = generate_all(dir.path()).unwrap();
        assert_eq!(written.len(), 5);
        for (file_name, marker) in MARKERS {
            let body = std::fs::read_to_string(dir.path().join(file_name)).unwrap();
            assert!(
                body.contains(marker),
                "{file_name} does not look like its shell's script"
            );
        }
    }

    /// The whole reason this goes through `public_command()`: a packaged script that offers
    /// `__daemon` invites a user to run the command `crypto unlock` re-execs into.
    #[test]
    fn no_packaged_script_offers_the_hidden_daemon_command() {
        let dir = tempfile::tempdir().unwrap();
        for path in generate_all(dir.path()).unwrap() {
            let body = std::fs::read_to_string(&path).unwrap();
            assert!(!body.contains("__daemon"), "hidden command in {path:?}");
            assert!(
                body.contains("vault"),
                "visible command missing in {path:?}"
            );
        }
    }

    /// The output directory is the caller's choice and does not have to exist yet.
    #[test]
    fn it_writes_into_the_directory_it_is_given_and_creates_it() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("nested/completions");
        let written = generate_all(&out).unwrap();
        assert!(written.iter().all(|p| p.starts_with(&out)), "{written:?}");
        assert!(out.join("_crypto").is_file());
    }

    /// Running the task twice overwrites the scripts instead of appending to them.
    #[test]
    fn generating_twice_leaves_the_same_files() {
        let dir = tempfile::tempdir().unwrap();
        let first = generate_all(dir.path()).unwrap();
        let first_body = std::fs::read_to_string(dir.path().join("crypto.bash")).unwrap();
        let second = generate_all(dir.path()).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("crypto.bash")).unwrap(),
            first_body
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), SHELLS.len());
    }
}
