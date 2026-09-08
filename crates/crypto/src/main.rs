//! `crypto` – Cryptomator command line interface.
mod cli;
mod commands;
mod exit;
mod output;

use anyhow::Context;
use clap::Parser;
use cli::{
    Cli, Command, ConfigCommand, KeychainCommand, PasswordCommand, RecoveryKeyCommand, VaultCommand,
};
use commands::Ctx;
use cryptomator_app::settings::SettingsStore;
use cryptomator_app::StateDir;
use cryptomator_core::recovery::{validate_recovery_key, WordEncoder};
use output::Output;
use std::io::Read;
use std::path::PathBuf;
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
        // `None`: the reader closed the pipe (`crypto vault list | head -3`). Nothing is printed
        // and the exit code stays 0 -- that reader got what it asked for.
        Err(err) => match exit::failure_report(&err) {
            None => ExitCode::from(exit::OK),
            Some(code) => {
                eprintln!("error: {err:#}");
                ExitCode::from(code)
            }
        },
    }
}

fn run(cli: Cli) -> anyhow::Result<u8> {
    // Before anything can log: the library warns through `log` (a keychain provider that had to
    // be skipped, a self-test entry that could not be removed), and without a logger installed
    // every one of those lines is dropped. `warn` is the CLI's level -- the console is for what
    // the user has to know, not for a trace. `unlock --foreground` later swaps the daemon's log
    // file in behind this same logger (`daemon::logging`), which is why it is installed here
    // rather than fought over there.
    cryptomator_app::daemon::init_stderr_logger(log::LevelFilter::Warn);
    // Absolutized once, here, rather than wherever each value is later used: a detached daemon
    // runs with its cwd at `/` (see `commands::unlock::spawn_daemon`), so a relative `--settings`
    // or `--state-dir` would resolve to the wrong place in the child even though it was correct
    // when the user typed it against the shell's own cwd.
    let settings_arg = cli.settings.map(absolutize).transpose()?;
    let store = match settings_arg.clone() {
        Some(path) => SettingsStore::at(path),
        None => SettingsStore::from_env_or_default()?,
    };
    let state_dir = match cli.state_dir.map(absolutize).transpose()? {
        Some(path) => StateDir::at(path),
        None => StateDir::from_env_or_default()?,
    };
    let ctx = Ctx::new(
        store,
        Output { json: cli.json },
        state_dir,
        settings_arg,
        cli.no_keychain,
    );
    // Before the command runs, not after it wrote: the `flock` only serialises `crypto` against
    // `crypto`, and the user should know about the remaining gap while there is still time to
    // quit the app. stderr, so `--json` output stays machine-readable.
    if writes_settings(&cli.command) && ctx.store.desktop_app_running() {
        eprintln!(
            "warning: the Cryptomator desktop app is running; changes to settings.json may be \
             overwritten by it"
        );
    }
    match cli.command {
        Command::Vault { command } => match command {
            VaultCommand::Create(args) => commands::vault::create(&ctx, args),
            VaultCommand::Add(args) => commands::vault::add(&ctx, args),
            VaultCommand::Remove {
                vault,
                forget_password,
            } => commands::vault::remove(&ctx, &vault, forget_password),
            VaultCommand::List => commands::vault::list(&ctx),
            VaultCommand::Info { vault } => commands::vault::info(&ctx, &vault),
            VaultCommand::Set(args) => commands::vault::set(&ctx, args),
        },
        Command::Password { command } => match command {
            PasswordCommand::Change(args) => commands::password::change(&ctx, args),
            PasswordCommand::Store(args) => commands::password::store(&ctx, args),
            PasswordCommand::Forget { vault } => commands::password::forget(&ctx, &vault),
        },
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
        Command::Fs { command } => commands::fs::run(&ctx, command),
        Command::Name { command } => commands::name::run(&ctx, command),
        Command::Unlock(args) => commands::unlock::unlock(&ctx, args),
        Command::Lock(args) => commands::lock::lock(&ctx, args),
        Command::Status(args) => commands::status::status(&ctx, args),
        Command::Stats(args) => commands::stats::stats(&ctx, args),
        Command::Events(args) => commands::events::events(&ctx, args),
        Command::Mounters(args) => commands::mounters::mounters(&ctx, args),
        Command::Health(args) => commands::health::run(&ctx, args),
        Command::Migrate(args) => commands::migrate::run(&ctx, args),
        Command::Keychain { command } => match command {
            KeychainCommand::Test => commands::keychain::test(&ctx),
        },
        Command::Daemon(args) => commands::daemon::run(&ctx, args),
    }
}

/// Whether `command` writes `settings.json`, and therefore whether a running desktop app can lose
/// its changes to it (or the other way round).
///
/// Read-only commands stay silent: nothing they do can be lost, and a warning on every
/// `crypto status` would train the user to ignore it. `password change` and `recovery-key` are
/// silent too -- they rewrite the masterkey file inside the vault, which the desktop app does not
/// hold a competing copy of.
fn writes_settings(command: &Command) -> bool {
    match command {
        // `list` and `info` only read; everything else in `vault` rewrites the vault list.
        Command::Vault { command } => {
            !matches!(command, VaultCommand::List | VaultCommand::Info { .. })
        }
        // `set` on a `cli.json` key writes only that file, but the warning is about the desktop
        // app's settings as a whole and the key is not worth a second, quieter rule.
        Command::Config { command } => matches!(command, ConfigCommand::Set { .. }),
        // `unlock` persists the probed cleartext file name length of the vault it opens.
        Command::Unlock(_) => true,
        Command::Password { .. }
        | Command::RecoveryKey { .. }
        | Command::Fs { .. }
        | Command::Name { .. }
        | Command::Lock(_)
        | Command::Status(_)
        | Command::Stats(_)
        | Command::Events(_)
        | Command::Mounters(_)
        // `health` reads the vault; even `--fix` (Task 9) never touches settings.json.
        | Command::Health(_)
        // `migrate` rewrites the vault directory, never the vault list: the entry that names it
        // keeps its id, its path and its display name across every format.
        | Command::Migrate(_)
        // `keychain test` writes into the keychain, never into settings.json.
        | Command::Keychain { .. }
        | Command::Daemon(_) => false,
    }
}

/// Resolves `path` against the current directory if it is relative; a path that is already
/// absolute is returned unchanged. Unlike [`std::fs::canonicalize`], this does not require `path`
/// to exist and does not resolve symlinks -- exactly what a CLI argument that may name a file not
/// yet created (`--settings`) or a directory a detached child will create (`--state-dir`) needs.
fn absolutize(path: PathBuf) -> anyhow::Result<PathBuf> {
    std::path::absolute(&path).with_context(|| format!("cannot resolve path {}", path.display()))
}
