//! Application layer: settings.json, keychain, daemon protocol, vault registry.
#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod error;
pub mod mounters;
pub mod password;
pub mod settings;

pub use error::{AppError, Result};
pub use mounters::{alias_for, resolve_mounter};
pub use password::{
    min_password_length, normalize_passphrase, read_new_passphrase,
    read_new_passphrase_no_env_fallback, read_passphrase, read_secret_file, NewPasswordArgs,
    PasswordArgs, PasswordIo, SystemIo,
};
