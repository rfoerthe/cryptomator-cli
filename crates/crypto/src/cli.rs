//! Command grammar of `crypto`.
use clap::{Args, Parser, Subcommand};
use cryptomator_app::PasswordArgs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "crypto",
    version,
    about = "Cryptomator vaults from the command line",
    arg_required_else_help = true
)]
pub struct Cli {
    /// Path to settings.json (default: the Cryptomator desktop app's file, or $CRYPTO_SETTINGS_PATH)
    #[arg(long, global = true, value_name = "PATH")]
    pub settings: Option<PathBuf>,
    /// Machine-readable JSON output
    #[arg(long, global = true)]
    pub json: bool,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Create, register and inspect vaults
    Vault {
        #[command(subcommand)]
        command: VaultCommand,
    },
    /// Show, validate or use recovery keys
    #[command(name = "recovery-key")]
    RecoveryKey {
        #[command(subcommand)]
        command: RecoveryKeyCommand,
    },
}

#[derive(Subcommand, Debug)]
pub enum VaultCommand {
    /// Create a new vault directory and register it
    Create(CreateArgs),
    /// Register an existing vault directory
    Add(AddArgs),
    /// Unregister a vault (its files are kept)
    Remove {
        /// Vault id, display name or path
        vault: String,
    },
    /// List registered vaults with their state
    List,
    /// Show settings and configuration of a vault
    Info {
        /// Vault id, display name or path
        vault: String,
    },
}

#[derive(Args, Debug)]
pub struct CreateArgs {
    /// Directory to create (must not exist yet)
    pub path: PathBuf,
    /// Display name (default: directory name)
    #[arg(long)]
    pub name: Option<String>,
    /// Ciphertext file name length above which names are shortened (36-220)
    #[arg(long, default_value_t = 220, value_parser = clap::value_parser!(u32).range(36..=220))]
    pub shortening_threshold: u32,
    #[arg(long, hide = true, default_value = "SIV_GCM")]
    pub cipher_combo: String,
    /// Print the recovery key after creation
    #[arg(long)]
    pub show_recovery_key: bool,
    /// Do not add the vault to settings.json
    #[arg(long)]
    pub no_register: bool,
    #[command(flatten)]
    pub password: PasswordArgs,
}

#[derive(Args, Debug)]
pub struct AddArgs {
    /// Existing vault directory (contains vault.cryptomator)
    pub path: PathBuf,
    /// Display name (default: directory name)
    #[arg(long)]
    pub name: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum RecoveryKeyCommand {
    /// Check whether a recovery key is well-formed (dictionary words, length, checksum)
    Validate(ValidateArgs),
}

#[derive(Args, Debug)]
pub struct ValidateArgs {
    /// Read the recovery key from standard input
    #[arg(long, required = true)]
    pub recovery_key_stdin: bool,
}
