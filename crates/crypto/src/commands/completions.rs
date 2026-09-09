//! `crypto completions <shell>`: the completion script for one shell on standard output.
//!
//! This is the same generator `cargo xtask completions` runs for the packages (Ruling 4), on the
//! same `Cli::command()`, so what a user installs by hand and what a `.deb` ships cannot differ.
use crate::cli::Cli;
use crate::exit;
use anyhow::Result;
use clap::CommandFactory;
use clap_complete::Shell;
use std::io::Write;

/// Writes the script for `shell` to `out`. The writer is a parameter so a test can render into a
/// buffer; the command passes the locked `std::io::stdout()`.
///
/// The script is rendered into memory first and handed to `out` in one `write_all`, because
/// `clap_complete::generate` `.unwrap()`s every write it makes: given stdout directly, the ~88 kB
/// zsh script overruns the pipe buffer of `crypto completions zsh | head -1` and the generator
/// panics (exit 101) somewhere the CLI's own error handling never sees. A `Vec<u8>` cannot fail,
/// so the only fallible write is the one below -- and its [`std::io::ErrorKind::BrokenPipe`] travels up
/// through `?` to [`exit::failure_report`], which ends the command the way every other one already
/// ends on a closed pipe: quietly, with code 0.
pub fn completions(out: &mut dyn Write, shell: Shell) -> Result<u8> {
    let mut command = public_command();
    // `generate` needs the name separately -- it does not take it from the command -- and it must
    // be the one a user types, not the crate name.
    let name = command.get_name().to_string();
    let mut script: Vec<u8> = Vec::new();
    clap_complete::generate(shell, &mut command, name, &mut script);
    out.write_all(&script)?;
    out.flush()?;
    Ok(exit::OK)
}

/// [`Cli::command()`] with the hidden subcommands left out.
///
/// The script generators walk `get_subcommands()` and, unlike the help renderer, do not skip a
/// command marked `hide = true` -- clap_complete 4.6.9 filters hidden *possible values* only. So
/// `__daemon`, which exists for `crypto unlock` to re-exec itself and is not a command anyone
/// should be offered, would otherwise be advertised in every user's shell.
///
/// clap has no API to drop a subcommand once it is attached, hence the rebuild: a fresh root that
/// takes over the arguments (globals included, they propagate again at build time) and the visible
/// subcommands. Only the root is filtered; `the_grammar_hides_nothing_below_the_root` below fails
/// if a hidden command is ever nested deeper, where this would not catch it.
///
/// Public because `xtask` renders both the packaged completion scripts and the manpages from it:
/// `clap_mangen` walks hidden subcommands too, so this is the one command a generator may see.
pub fn public_command() -> clap::Command {
    let base = Cli::command();
    let mut command = clap::Command::new(base.get_name().to_string());
    if let Some(about) = base.get_about() {
        command = command.about(about.clone());
    }
    if let Some(version) = base.get_version() {
        command = command.version(version.to_string());
    }
    command.args(base.get_arguments().cloned()).subcommands(
        base.get_subcommands()
            .filter(|sub| !sub.is_hide_set())
            .cloned(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rebuilt command keeps everything a completion script needs: the program name, the
    /// global options and every visible subcommand -- and only `__daemon` goes missing.
    #[test]
    fn the_public_command_is_the_grammar_minus_the_hidden_commands() {
        let public = public_command();
        assert_eq!(public.get_name(), Cli::command().get_name());
        let visible: Vec<&str> = public.get_subcommands().map(|c| c.get_name()).collect();
        assert!(visible.contains(&"vault"), "subcommands lost: {visible:?}");
        assert!(!visible.contains(&"__daemon"), "hidden command kept");
        let longs: Vec<String> = public
            .get_arguments()
            .filter_map(|a| a.get_long().map(str::to_string))
            .collect();
        for global in ["settings", "state-dir", "json", "no-keychain"] {
            assert!(longs.contains(&global.to_string()), "global lost: {global}");
        }
    }

    /// [`public_command`] drops hidden commands at the root only, which is enough exactly as long
    /// as the grammar hides nothing deeper. If this fails, that filter has to become recursive --
    /// otherwise the newly hidden command is advertised in every generated script.
    #[test]
    fn the_grammar_hides_nothing_below_the_root() {
        fn assert_visible(cmd: &clap::Command, path: &str) {
            for sub in cmd.get_subcommands() {
                let path = format!("{path} {}", sub.get_name());
                assert!(!sub.is_hide_set(), "hidden below the root:{path}");
                assert_visible(sub, &path);
            }
        }
        for sub in Cli::command().get_subcommands() {
            assert_visible(sub, sub.get_name());
        }
    }

    /// A writer whose reader has gone away: every write is [`std::io::ErrorKind::BrokenPipe`].
    struct ClosedPipe;

    impl Write for ClosedPipe {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "Broken pipe (os error 32)",
            ))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// `crypto completions zsh | head -1`: the reader closes the pipe long before the ~88 kB
    /// script is out. That must arrive as an error the CLI classifies -- [`exit::failure_report`]
    /// turns it into a silent exit 0 -- and never as a panic out of the generator, which is what
    /// happened while `generate` wrote to stdout itself.
    #[test]
    fn a_closed_pipe_is_reported_rather_than_panicked_over() {
        let err = completions(&mut ClosedPipe, Shell::Zsh)
            .expect_err("a closed pipe has to fail the command");
        assert_eq!(
            exit::failure_report(&err),
            None,
            "not recognised as a closed pipe: {err:#}"
        );
    }

    /// The renderer writes to whatever it is given, and the script carries the program name.
    #[test]
    fn it_renders_into_the_writer_it_is_handed() {
        let mut buf: Vec<u8> = Vec::new();
        assert_eq!(completions(&mut buf, Shell::Zsh).unwrap(), exit::OK);
        let script = String::from_utf8(buf).unwrap();
        assert!(
            script.starts_with("#compdef crypto"),
            "unexpected start: {:?}",
            &script[..40]
        );
    }
}
