//! Command grammar of `crypto`.
use clap::{Args, Parser, Subcommand};
use cryptomator_app::{NewPasswordArgs, PasswordArgs};
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
    /// Change or forget vault passwords
    Password {
        #[command(subcommand)]
        command: PasswordCommand,
    },
    /// Show, validate or use recovery keys
    #[command(name = "recovery-key")]
    RecoveryKey {
        #[command(subcommand)]
        command: RecoveryKeyCommand,
    },
    /// Global settings (settings.json)
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Read and write vault contents without mounting
    Fs {
        #[command(subcommand)]
        command: FsCommand,
    },
    /// Translate between cleartext and ciphertext names
    Name {
        #[command(subcommand)]
        command: NameCommand,
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
        // Vault ids are base64url and may start with `-`; clap would otherwise read one as a flag.
        #[arg(allow_hyphen_values = true)]
        vault: String,
    },
    /// List registered vaults with their state
    List,
    /// Show settings and configuration of a vault
    Info {
        /// Vault id, display name or path
        // Vault ids are base64url and may start with `-`; clap would otherwise read one as a flag.
        #[arg(allow_hyphen_values = true)]
        vault: String,
    },
    /// Change per-vault settings
    Set(SetArgs),
}

#[derive(Args, Debug)]
pub struct SetArgs {
    /// Vault id, display name or path
    // Vault ids are base64url and may start with `-`; clap would otherwise read one as a flag.
    #[arg(allow_hyphen_values = true)]
    pub vault: String,
    /// New display name
    #[arg(long)]
    pub name: Option<String>,
    /// Mount point directory (absolute path)
    #[arg(long, value_name = "PATH", conflicts_with = "no_mount_point")]
    pub mount_point: Option<PathBuf>,
    /// Let the mounter choose the mount point
    #[arg(long)]
    pub no_mount_point: bool,
    /// Mount read-only (true|false)
    #[arg(long, value_name = "BOOL", value_parser = clap::value_parser!(bool))]
    pub read_only: Option<bool>,
    /// Custom mount flags, e.g. --mount-flags="-ovolname=Secret"
    // Mount flags start with a dash; without `allow_hyphen_values` clap would read them as options.
    // `require_equals` keeps that from swallowing the *next* flag when the value is left out.
    #[arg(
        long,
        value_name = "FLAGS",
        allow_hyphen_values = true,
        require_equals = true,
        conflicts_with = "default_mount_flags"
    )]
    pub mount_flags: Option<String>,
    /// Use the mounter's default flags
    #[arg(long)]
    pub default_mount_flags: bool,
    /// Mounter alias (fuse-t, macfuse, fuse, webdav), Java class name, or "default"
    #[arg(long, value_name = "MOUNTER")]
    pub mounter: Option<String>,
    /// TCP port for loopback mounters (WebDAV)
    #[arg(long)]
    pub port: Option<u16>,
    /// Lock automatically after this many idle seconds
    #[arg(long, value_name = "SECONDS", conflicts_with = "no_auto_lock")]
    pub auto_lock_idle: Option<u32>,
    /// Disable idle auto-lock
    #[arg(long)]
    pub no_auto_lock: bool,
    /// Maximum cleartext file name length, or "auto" to probe on unlock
    #[arg(long, value_name = "N|auto")]
    pub max_filename_length: Option<String>,
    /// What to do after unlock: IGNORE, REVEAL or ASK
    #[arg(long, value_name = "ACTION")]
    pub action_after_unlock: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum ConfigCommand {
    /// Print one or all global settings
    Get {
        /// mountService | port | useKeychain | keychainProvider | debugMode
        key: Option<String>,
    },
    /// Change a global setting
    Set { key: String, value: String },
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
pub enum PasswordCommand {
    /// Change the password of a vault (writes a .bkup of the old masterkey file)
    Change(ChangePasswordArgs),
}

#[derive(Args, Debug)]
pub struct ChangePasswordArgs {
    /// Vault id, display name or path
    // Vault ids are base64url and may start with `-`; clap would otherwise read one as a flag.
    #[arg(allow_hyphen_values = true)]
    pub vault: String,
    #[command(flatten)]
    pub password: PasswordArgs,
    #[command(flatten)]
    pub new_password: NewPasswordArgs,
}

#[derive(Subcommand, Debug)]
pub enum RecoveryKeyCommand {
    /// Print the recovery key of a vault (requires the password)
    Show(ShowArgs),
    /// Set a new password using the recovery key
    #[command(name = "reset-password")]
    ResetPassword(ResetPasswordArgs),
    /// Check whether a recovery key is well-formed (dictionary words, length, checksum)
    Validate(ValidateArgs),
}

#[derive(Args, Debug)]
pub struct ShowArgs {
    /// Vault id, display name or path
    // Vault ids are base64url and may start with `-`; clap would otherwise read one as a flag.
    #[arg(allow_hyphen_values = true)]
    pub vault: String,
    #[command(flatten)]
    pub password: PasswordArgs,
}

// The group carries `required(true)`, not the flag: putting it on `recovery_key_stdin` would make
// clap demand that flag even when `--recovery-key-file` is given.
#[derive(Args, Debug)]
#[command(group = clap::ArgGroup::new("recovery-key-source").required(true))]
pub struct ResetPasswordArgs {
    /// Vault id, display name or path
    // Vault ids are base64url and may start with `-`; clap would otherwise read one as a flag.
    #[arg(allow_hyphen_values = true)]
    pub vault: String,
    /// Read the recovery key from the next line of standard input
    #[arg(long, group = "recovery-key-source")]
    pub recovery_key_stdin: bool,
    /// Read the recovery key from a file
    #[arg(long, value_name = "FILE", group = "recovery-key-source")]
    pub recovery_key_file: Option<PathBuf>,
    #[command(flatten)]
    pub new_password: NewPasswordArgs,
}

#[derive(Args, Debug)]
pub struct ValidateArgs {
    /// Read the recovery key from standard input
    #[arg(long, required = true)]
    pub recovery_key_stdin: bool,
}

#[derive(Subcommand, Debug)]
pub enum FsCommand {
    /// List a directory
    Ls(FsLsArgs),
    /// List a directory tree recursively (one path per line; --json like the fixture manifests)
    Tree(FsTreeArgs),
    /// Print a file to standard output
    Cat(FsPathArgs),
    /// Copy a file out of the vault
    Get(FsGetArgs),
    /// Copy a file into the vault
    Put(FsPutArgs),
    /// Delete a file, symlink or (empty) directory
    Rm(FsRmArgs),
    /// Create a directory
    Mkdir(FsMkdirArgs),
    /// Move or rename a file, symlink or directory
    Mv(FsMvArgs),
}

#[derive(Args, Debug)]
pub struct FsLsArgs {
    /// Vault id, display name or path
    // Vault ids are base64url and may start with `-`; clap would otherwise read one as a flag.
    #[arg(allow_hyphen_values = true)]
    pub vault: String,
    /// Cleartext directory
    #[arg(default_value = "/")]
    pub path: String,
    /// Long listing: type, size, modification time, name
    #[arg(short = 'l', long)]
    pub long: bool,
    #[command(flatten)]
    pub password: PasswordArgs,
}

#[derive(Args, Debug)]
pub struct FsTreeArgs {
    /// Vault id, display name or path
    // Vault ids are base64url and may start with `-`; clap would otherwise read one as a flag.
    #[arg(allow_hyphen_values = true)]
    pub vault: String,
    /// Cleartext directory to start from
    #[arg(default_value = "/")]
    pub path: String,
    /// Include the SHA-256 of every file (reads all content)
    #[arg(long)]
    pub hash: bool,
    #[command(flatten)]
    pub password: PasswordArgs,
}

#[derive(Args, Debug)]
pub struct FsPathArgs {
    /// Vault id, display name or path
    // Vault ids are base64url and may start with `-`; clap would otherwise read one as a flag.
    #[arg(allow_hyphen_values = true)]
    pub vault: String,
    /// Cleartext path
    pub path: String,
    #[command(flatten)]
    pub password: PasswordArgs,
}

#[derive(Args, Debug)]
pub struct FsGetArgs {
    /// Vault id, display name or path
    // Vault ids are base64url and may start with `-`; clap would otherwise read one as a flag.
    #[arg(allow_hyphen_values = true)]
    pub vault: String,
    /// Cleartext file
    pub path: String,
    /// Local destination file, or "-" for standard output
    pub local: PathBuf,
    /// Overwrite an existing local file
    #[arg(long)]
    pub force: bool,
    #[command(flatten)]
    pub password: PasswordArgs,
}

#[derive(Args, Debug)]
pub struct FsPutArgs {
    /// Vault id, display name or path
    // Vault ids are base64url and may start with `-`; clap would otherwise read one as a flag.
    #[arg(allow_hyphen_values = true)]
    pub vault: String,
    /// Local source file, or "-" for standard input (not combinable with --password-stdin)
    pub local: PathBuf,
    /// Cleartext destination file (the full name, not a directory)
    pub path: String,
    /// Overwrite an existing vault file
    #[arg(long)]
    pub force: bool,
    #[command(flatten)]
    pub password: PasswordArgs,
}

#[derive(Args, Debug)]
pub struct FsRmArgs {
    /// Vault id, display name or path
    // Vault ids are base64url and may start with `-`; clap would otherwise read one as a flag.
    #[arg(allow_hyphen_values = true)]
    pub vault: String,
    /// Cleartext path
    pub path: String,
    /// Delete directories with their contents
    #[arg(short = 'r', long)]
    pub recursive: bool,
    #[command(flatten)]
    pub password: PasswordArgs,
}

#[derive(Args, Debug)]
pub struct FsMkdirArgs {
    /// Vault id, display name or path
    // Vault ids are base64url and may start with `-`; clap would otherwise read one as a flag.
    #[arg(allow_hyphen_values = true)]
    pub vault: String,
    /// Cleartext directory
    pub path: String,
    /// Create missing parent directories; no error if the directory exists
    #[arg(short = 'p', long)]
    pub parents: bool,
    #[command(flatten)]
    pub password: PasswordArgs,
}

#[derive(Args, Debug)]
pub struct FsMvArgs {
    /// Vault id, display name or path
    // Vault ids are base64url and may start with `-`; clap would otherwise read one as a flag.
    #[arg(allow_hyphen_values = true)]
    pub vault: String,
    /// Cleartext source path
    pub source: String,
    /// Destination path (never "into" an existing directory)
    pub destination: String,
    /// Replace an existing destination (directories only if empty)
    #[arg(long)]
    pub force: bool,
    #[command(flatten)]
    pub password: PasswordArgs,
}

#[derive(Subcommand, Debug)]
pub enum NameCommand {
    /// Decrypt the names of ciphertext nodes (paths below <vault>/d/XX/YYYY/)
    Decrypt(NameDecryptArgs),
    /// Show the ciphertext node of a cleartext path
    Locate(NameLocateArgs),
}

#[derive(Args, Debug)]
pub struct NameDecryptArgs {
    /// Vault id, display name or path
    // Vault ids are base64url and may start with `-`; clap would otherwise read one as a flag.
    #[arg(allow_hyphen_values = true)]
    pub vault: String,
    /// Ciphertext nodes (.c9r files, .c9r node directories or .c9s directories)
    #[arg(required = true)]
    pub paths: Vec<PathBuf>,
    #[command(flatten)]
    pub password: PasswordArgs,
}

#[derive(Args, Debug)]
pub struct NameLocateArgs {
    /// Vault id, display name or path
    // Vault ids are base64url and may start with `-`; clap would otherwise read one as a flag.
    #[arg(allow_hyphen_values = true)]
    pub vault: String,
    /// Cleartext path
    pub path: String,
    /// Print the content directory of a directory, contents.c9r of a shortened file or symlink.c9r
    /// of a symlink instead of the node itself
    #[arg(long)]
    pub contents: bool,
    #[command(flatten)]
    pub password: PasswordArgs,
}
