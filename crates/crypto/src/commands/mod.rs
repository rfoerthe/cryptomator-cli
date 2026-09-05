//! Command implementations; each returns the process exit code.
pub mod config;
pub mod vault;

use crate::output::Output;
use cryptomator_app::settings::SettingsStore;

#[derive(Debug)]
pub struct Ctx {
    pub store: SettingsStore,
    pub out: Output,
}
