//! `crypto` – Cryptomator command line interface.
mod cli;

use clap::Parser;
use cli::{Cli, Command, RecoveryKeyCommand};
use cryptomator_core::recovery::{validate_recovery_key, WordEncoder};
use std::io::Read;
use std::process::ExitCode;

/// Exit codes as defined in the design spec.
pub mod exit {
    pub const OK: u8 = 0;
    pub const GENERAL: u8 = 1;
    pub const USAGE: u8 = 2;
    pub const INVALID_PASSPHRASE: u8 = 4;
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            // clap's own --help/--version output goes to stdout with exit 0; usage errors to stderr with exit 2.
            let _ = err.print();
            return match err.kind() {
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion => {
                    ExitCode::from(exit::OK)
                }
                _ => ExitCode::from(exit::USAGE),
            };
        }
    };
    match run(cli) {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(exit::GENERAL)
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<u8> {
    match cli.command {
        Command::RecoveryKey {
            command: RecoveryKeyCommand::Validate(args),
        } => {
            debug_assert!(args.recovery_key_stdin);
            let mut input = String::new();
            std::io::stdin().read_to_string(&mut input)?;
            let encoder = WordEncoder::new();
            if validate_recovery_key(&encoder, input.trim()) {
                println!("valid");
                Ok(exit::OK)
            } else {
                println!("invalid");
                Ok(exit::INVALID_PASSPHRASE)
            }
        }
    }
}
