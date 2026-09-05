//! Desktop-compatible `settings.json`.
pub mod ids;
pub mod model;
pub mod vault_ref;

pub use ids::{generate_id, normalize_display_name};
pub use model::{
    default_keychain_provider, SettingsJson, VaultSettingsJson, WhenUnlocked,
    DEFAULT_AUTOLOCK_IDLE_SECONDS, DEFAULT_MAX_CLEARTEXT_FILENAME_LENGTH, DEFAULT_PORT,
};
pub use vault_ref::{normalize_vault_path, resolve_vault, resolve_vault_index};
