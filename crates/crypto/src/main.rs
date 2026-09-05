//! `crypto` – Cryptomator command line interface.
mod cli;
mod commands;
mod exit;
mod output;

use clap::Parser;
use cli::{Cli, Command, ConfigCommand, PasswordCommand, RecoveryKeyCommand, VaultCommand};
use commands::Ctx;
use cryptomator_app::settings::SettingsStore;
use cryptomator_core::recovery::{validate_recovery_key, WordEncoder};
use output::Output;
use std::io::Read;
use std::process::ExitCode;
use zeroize::Zeroizing;

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
            ExitCode::from(exit::code_for(&err))
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<u8> {
    let store = match cli.settings {
        Some(path) => SettingsStore::at(path),
        None => SettingsStore::from_env_or_default()?,
    };
    let ctx = Ctx {
        store,
        out: Output { json: cli.json },
    };
    match cli.command {
        Command::Vault { command } => match command {
            VaultCommand::Create(args) => commands::vault::create(&ctx, args),
            VaultCommand::Add(args) => commands::vault::add(&ctx, args),
            VaultCommand::Remove { vault } => commands::vault::remove(&ctx, &vault),
            VaultCommand::List => commands::vault::list(&ctx),
            VaultCommand::Info { vault } => commands::vault::info(&ctx, &vault),
            VaultCommand::Set(args) => commands::vault::set(&ctx, args),
        },
        Command::Password {
            command: PasswordCommand::Change(args),
        } => commands::password::change(&ctx, args),
        Command::RecoveryKey { command } => match command {
            RecoveryKeyCommand::Show(args) => commands::recovery::show(&ctx, args),
            RecoveryKeyCommand::ResetPassword(args) => {
                commands::recovery::reset_password_cmd(&ctx, args)
            }
            RecoveryKeyCommand::Validate(args) => {
                debug_assert!(args.recovery_key_stdin);
                // The recovery key is key material: keep it in a buffer that is wiped on drop and
                // never copy it into an owned String (`trim` borrows).
                let mut input = Zeroizing::new(String::new());
                std::io::stdin().read_to_string(&mut input)?;
                let recovery_key: &str = input.trim();
                let valid = validate_recovery_key(&WordEncoder::new(), recovery_key);
                ctx.out.emit(serde_json::json!({ "valid": valid }), || {
                    if valid { "valid" } else { "invalid" }.to_string()
                })?;
                Ok(if valid {
                    exit::OK
                } else {
                    exit::INVALID_PASSPHRASE
                })
            }
        },
        Command::Config { command } => match command {
            ConfigCommand::Get { key } => commands::config::get(&ctx, key.as_deref()),
            ConfigCommand::Set { key, value } => commands::config::set(&ctx, &key, &value),
        },
    }
}
