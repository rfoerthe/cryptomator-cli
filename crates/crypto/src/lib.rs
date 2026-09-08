//! `crypto` – Cryptomator command line interface.
//!
//! The binary in `main.rs` is a thin shell around this library. The library exists for one reason
//! beyond tidiness: `xtask` builds `cli::Cli::command()` to render manpages and completion scripts
//! at development time, and it cannot do that against a bin-only package.
pub mod cli;
pub mod commands;
pub mod exit;
pub mod output;

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    /// clap's own consistency check: duplicate long options, a positional after a variadic one, a
    /// `value_parser` that cannot produce the declared type. It panics with the offending
    /// argument's name, so a grammar mistake surfaces here instead of at the user's first run.
    #[test]
    fn the_grammar_is_internally_consistent() {
        crate::cli::Cli::command().debug_assert();
    }

    /// The name is what `clap_complete` and `clap_mangen` put into every generated file, and what
    /// a user types. It must not drift with the crate or binary name.
    #[test]
    fn the_command_is_called_crypto() {
        assert_eq!(crate::cli::Cli::command().get_name(), "crypto");
    }
}
