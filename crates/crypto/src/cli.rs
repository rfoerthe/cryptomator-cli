//! Command grammar of `crypto`. Only the subcommands implemented so far are declared here.
use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "crypto",
    version,
    about = "Cryptomator vaults from the command line",
    arg_required_else_help = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Show, validate or use recovery keys
    #[command(name = "recovery-key")]
    RecoveryKey {
        #[command(subcommand)]
        command: RecoveryKeyCommand,
    },
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
