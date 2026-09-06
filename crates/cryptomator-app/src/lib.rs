//! Application layer: settings.json, keychain, daemon protocol, vault registry.
#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod cli_config;
pub mod daemon;
pub mod error;
pub mod mounters;
pub mod mounting;
pub mod password;
pub mod platform;
pub mod registry;
pub mod settings;
pub mod state_dir;

pub use cli_config::{default_mount_points_dir, CliConfig};
pub use daemon::{
    format_timestamp, run_daemon, DaemonClient, DaemonConfig, ErrorBody, EventRecord, EventsResult,
    Hello, LineStatus, Request, Response, StatsResult, StatusResult, StreamItem, MAX_LINE_LEN,
    PROTOCOL_VERSION,
};
pub use error::{AppError, Result};
pub use mounters::{alias_for, resolve_mounter};
pub use mounting::{
    choose_service, conflicts_with, mount, MountHandle, MountOverrides, MountRequest,
};
pub use password::{
    min_password_length, normalize_passphrase, read_new_passphrase,
    read_new_passphrase_no_env_fallback, read_passphrase, read_secret_file, NewPasswordArgs,
    PasswordArgs, PasswordIo, SystemIo,
};
pub use platform::Platform;
pub use registry::{RuntimeState, VaultInfo, VaultRegistry};
pub use state_dir::{
    check_root, default_state_dir, process_alive, RunInfo, StateDir, VaultStateFiles, STATE_DIR_ENV,
};
