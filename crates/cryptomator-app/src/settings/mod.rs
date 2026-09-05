//! Desktop-compatible `settings.json`.
pub mod model;

pub use model::{
    default_keychain_provider, SettingsJson, VaultSettingsJson, WhenUnlocked,
    DEFAULT_AUTOLOCK_IDLE_SECONDS, DEFAULT_MAX_CLEARTEXT_FILENAME_LENGTH, DEFAULT_PORT,
};
