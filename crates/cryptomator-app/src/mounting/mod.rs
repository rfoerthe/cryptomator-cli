//! Turning a vault's settings into a mount: the CLI's port of Cryptomator's `Mounter`.
pub mod mounter;

pub use mounter::{
    choose_service, conflicts_with, mount, MountHandle, MountOverrides, MountRequest,
    FILE_SYSTEM_NAME, FORCED_UNMOUNT_UNSUPPORTED,
};
