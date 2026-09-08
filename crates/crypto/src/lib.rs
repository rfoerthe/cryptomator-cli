//! `crypto` – Cryptomator command line interface.
//!
//! The binary in `main.rs` is a thin shell around this library. The library exists for one reason
//! beyond tidiness: `xtask` builds `cli::Cli::command()` to render manpages and completion scripts
//! at development time, and it cannot do that against a bin-only package.
pub mod cli;
pub mod commands;
pub mod exit;
pub mod output;

/// What `crypto --version` prints after the program name: `0.1.0 (a01958d, aarch64-apple-darwin)`.
///
/// `concat!` + `env!` rather than a `format!` at run time, so this is one static string in the
/// binary and no allocation. The two build-time variables come from `build.rs`; `CRYPTO_BUILD_SHA`
/// is `unknown` when there was no git repository to ask.
pub const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (",
    env!("CRYPTO_BUILD_SHA"),
    ", ",
    env!("CRYPTO_BUILD_TARGET"),
    ")"
);

/// The commit this binary was built from, abbreviated, or `unknown` outside a git repository.
/// Separate from [`VERSION`] so a packaging step (`xtask`) can name a file after it.
pub const GIT_SHA: &str = env!("CRYPTO_BUILD_SHA");

/// The target triple this binary was built for, e.g. `aarch64-apple-darwin`.
pub const TARGET: &str = env!("CRYPTO_BUILD_TARGET");

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
