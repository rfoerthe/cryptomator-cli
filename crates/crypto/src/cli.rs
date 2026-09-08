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
    /// Directory holding the socket, pid and run info of every unlocked vault (default:
    /// $CRYPTO_STATE_DIR, else a platform default)
    // No `env` attribute here: clap's own env handling turns an empty value into a hard error
    // ("a value is required"), while `StateDir::from_env_or_default` (main.rs) deliberately reads
    // the variable itself and treats an empty value as unset.
    #[arg(long, global = true, value_name = "PATH")]
    pub state_dir: Option<PathBuf>,
    /// Machine-readable JSON output
    #[arg(long, global = true)]
    pub json: bool,
    /// Never touch the keychain, whatever settings.json says
    #[arg(long, global = true)]
    pub no_keychain: bool,
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
    /// Global settings (settings.json) and CLI settings (cli.json)
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
    /// Unlock and mount a vault in a background daemon
    Unlock(UnlockArgs),
    /// Unmount and lock vaults
    Lock(LockArgs),
    /// Show what is registered, what is unlocked and where
    Status(StatusArgs),
    /// Throughput and cache counters of an unlocked vault
    Stats(StatsArgs),
    /// The event log of an unlocked vault
    Events(EventsArgs),
    /// The mount services this build knows
    Mounters(MountersArgs),
    /// Check a vault for structural damage and optionally repair it
    Health(HealthArgs),
    /// Inspect and self-test the keychain
    Keychain {
        #[command(subcommand)]
        command: KeychainCommand,
    },
    /// The vault daemon itself; started by `crypto unlock`, never by hand.
    #[command(name = "__daemon", hide = true)]
    Daemon(DaemonArgs),
}

#[derive(Subcommand, Debug)]
pub enum KeychainCommand {
    /// Report the provider and do a store/load/delete round trip with a throwaway key
    Test,
}

#[derive(Args, Debug)]
pub struct UnlockArgs {
    /// Vault id, display name or path
    // Vault ids are base64url and may start with `-`; clap would otherwise read one as a flag.
    #[arg(allow_hyphen_values = true)]
    pub vault: String,
    /// Mounter alias (fuse-t, macfuse, fuse, webdav, webdav-applescript, webdav-gio, null) or Java class name
    #[arg(long, value_name = "MOUNTER")]
    pub mounter: Option<String>,
    /// Where to mount (default: the vault's mountPoint, else <mountPointsDir>/<name>)
    #[arg(long, value_name = "PATH")]
    pub mount_point: Option<PathBuf>,
    /// Extra mount flag, e.g. --mount-option=-oallow_other (repeatable)
    // Mount options start with a dash; without `allow_hyphen_values` clap would read them as
    // options, and `require_equals` keeps a missing value from swallowing the next flag.
    #[arg(
        long,
        value_name = "OPTION",
        allow_hyphen_values = true,
        require_equals = true
    )]
    pub mount_option: Vec<String>,
    /// TCP port for loopback mounters (WebDAV); 0 picks any free port
    #[arg(long, value_name = "PORT")]
    pub port: Option<u16>,
    /// Mount read-only, whatever the vault's usesReadOnlyMode says
    #[arg(long)]
    pub read_only: bool,
    /// Volume name shown by the operating system
    #[arg(long, value_name = "NAME")]
    pub volume_name: Option<String>,
    /// Serve the vault in this process instead of a detached daemon (Ctrl-C locks it)
    #[arg(long)]
    pub foreground: bool,
    /// Open the mount point in the file manager afterwards
    #[arg(long)]
    pub reveal: bool,
    /// Save the password in the keychain once the vault is mounted
    // `--password-keychain` took the password *from* the keychain, so there would be nothing to
    // store that is not stored already: clap refuses that combination as a usage error (exit 2).
    #[arg(
        long,
        group = "store-password-choice",
        conflicts_with = "password_keychain"
    )]
    pub store_password: bool,
    /// Do not save the password (the default; spell it out to be explicit in a script)
    // A no-op today, on purpose: without `--store-password` nothing is ever stored implicitly. It
    // is in the same group so a script can write the default down and keep its meaning if the
    // default ever changes.
    #[arg(long, group = "store-password-choice")]
    pub no_store_password: bool,
    #[command(flatten)]
    pub password: PasswordArgs,
}

// The group carries `required(true)`: one of the two ways of naming what to lock has to be given,
// and `--all` excludes an explicit list.
#[derive(Args, Debug)]
#[command(group = clap::ArgGroup::new("lock-targets").required(true).multiple(false))]
pub struct LockArgs {
    /// Vault ids, display names or paths
    // No `allow_hyphen_values` here, unlike the single-vault commands: on a repeated positional it
    // swallows every following flag, so `crypto lock v --force` would look for a vault called
    // "--force". A vault id starting with `-` is reachable as `crypto lock -- -id`.
    #[arg(group = "lock-targets")]
    pub vaults: Vec<String>,
    /// Lock every unlocked vault
    #[arg(long, group = "lock-targets")]
    pub all: bool,
    /// Unmount even while the volume is in use
    #[arg(long)]
    pub force: bool,
}

/// Only `--report` and `--no-report` exclude each other; `--fix-severity` without `--fix` is
/// harmless and stays a no-op, the way `--interval` without `--follow` does.
#[derive(Args, Debug)]
pub struct HealthArgs {
    /// Vault id, display name or path
    // Vault ids are base64url and may start with `-`; clap would otherwise read one as a flag.
    #[arg(allow_hyphen_values = true)]
    pub vault: String,
    /// Which checks to run, comma separated: dirid, type, shortened (default: all)
    #[arg(long, value_name = "LIST", value_delimiter = ',')]
    pub check: Vec<String>,
    /// Apply the fixes of the findings that have one
    #[arg(long)]
    pub fix: bool,
    /// Lowest severity that --fix repairs (INFO is accepted here, unlike --fail-on)
    #[arg(long, value_name = "INFO|WARN|CRITICAL", default_value = "WARN")]
    pub fix_severity: String,
    /// Where to write the text report; it replaces an existing file of that name
    /// (default: ./healthReport_<vault>_<stamp>.log, which never replaces one)
    #[arg(long, value_name = "FILE", conflicts_with = "no_report")]
    pub report: Option<PathBuf>,
    /// Write no report file
    #[arg(long)]
    pub no_report: bool,
    /// Lowest severity that makes the command exit 11
    #[arg(long, value_name = "WARN|CRITICAL", default_value = "CRITICAL")]
    pub fail_on: String,
    #[command(flatten)]
    pub password: PasswordArgs,
}

#[derive(Args, Debug)]
pub struct StatusArgs {
    /// Vault id, display name or path; without one, every registered vault
    // Vault ids are base64url and may start with `-`; clap would otherwise read one as a flag.
    #[arg(allow_hyphen_values = true)]
    pub vault: Option<String>,
}

#[derive(Args, Debug)]
pub struct StatsArgs {
    /// Vault id, display name or path
    // Vault ids are base64url and may start with `-`; clap would otherwise read one as a flag.
    #[arg(allow_hyphen_values = true)]
    pub vault: String,
    /// Keep printing one sample per interval until Ctrl-C
    #[arg(long)]
    pub follow: bool,
    /// Seconds between samples with --follow
    #[arg(long, value_name = "SECS", default_value_t = 1, value_parser = clap::value_parser!(u64).range(1..))]
    pub interval: u64,
}

#[derive(Args, Debug)]
pub struct EventsArgs {
    /// Vault id, display name or path
    // Vault ids are base64url and may start with `-`; clap would otherwise read one as a flag.
    #[arg(allow_hyphen_values = true)]
    pub vault: String,
    /// Keep printing events as they happen until Ctrl-C
    #[arg(long)]
    pub follow: bool,
    /// Only events after this sequence number (the `seq` of the last one you saw)
    #[arg(long, value_name = "SEQ", default_value_t = 0)]
    pub since: u64,
}

#[derive(Args, Debug)]
pub struct MountersArgs {
    /// Include the services that do not work on this machine
    #[arg(long)]
    pub all: bool,
}

#[derive(Args, Debug)]
pub struct DaemonArgs {
    /// The vault to serve, by its id in settings.json
    #[arg(long, value_name = "ID", allow_hyphen_values = true)]
    pub vault_id: String,
    /// The control socket to bind. Informational: the state directory and the vault id decide,
    /// and `crypto unlock` passes the path it expects so a mismatch shows up in the log.
    #[arg(long, value_name = "PATH")]
    pub socket: Option<PathBuf>,
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
        /// Also remove the vault's password from the keychain
        #[arg(long)]
        forget_password: bool,
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
    /// Mounter alias (fuse-t, macfuse, fuse, null, webdav, webdav-applescript, webdav-gio), Java class name, or "default"
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
    /// Print one or all settings
    Get {
        /// settings.json: mountService | port | useKeychain | keychainProvider (alias: macos,
        /// touchid, secret-service, gnome-keyring, kde, kwallet) | debugMode; cli.json:
        /// mountPointsDir | defaultMounter | logLevel | forceUnmountOnSignalAfterSecs | webdavBind
        key: Option<String>,
    },
    /// Change a setting (keychainProvider takes the aliases macos, touchid, secret-service,
    /// gnome-keyring, kde, kwallet or a Java class name)
    // Values may start with a dash (a negative number is refused later, with a reason).
    Set {
        key: String,
        #[arg(allow_hyphen_values = true)]
        value: String,
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
    /// Save the new password in the keychain
    #[arg(long)]
    pub store_password: bool,
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
    /// Verify a password and save it in the keychain
    Store(StorePasswordArgs),
    /// Remove a vault's password from the keychain
    Forget {
        /// Vault id, display name or path
        // Vault ids are base64url and may start with `-`; clap would otherwise read one as a flag.
        #[arg(allow_hyphen_values = true)]
        vault: String,
    },
}

#[derive(Args, Debug)]
pub struct StorePasswordArgs {
    /// Vault id, display name or path
    // Vault ids are base64url and may start with `-`; clap would otherwise read one as a flag.
    #[arg(allow_hyphen_values = true)]
    pub vault: String,
    #[command(flatten)]
    pub password: PasswordArgs,
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
