//! `crypto` – Cryptomator command line interface.
use clap::Parser;
use std::process::ExitCode;

/// Exit codes as defined in the design spec.
pub mod exit {
    pub const OK: u8 = 0;
    pub const GENERAL: u8 = 1;
    pub const USAGE: u8 = 2;
    pub const INVALID_PASSPHRASE: u8 = 4;
}

#[derive(Parser, Debug)]
#[command(
    name = "crypto",
    version,
    about = "Cryptomator vaults from the command line",
    arg_required_else_help = true
)]
struct Cli {}

fn main() -> ExitCode {
    match Cli::try_parse() {
        Ok(_cli) => ExitCode::from(exit::OK),
        Err(err) => {
            // clap's own --help/--version output goes to stdout with exit 0; usage errors to stderr with exit 2.
            let _ = err.print();
            match err.kind() {
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion => {
                    ExitCode::from(exit::OK)
                }
                _ => ExitCode::from(exit::USAGE),
            }
        }
    }
}
