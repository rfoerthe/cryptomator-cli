//! Recovery key handling (desktop app `ui/recoverykey/{WordEncoder,RecoveryKeyFactory}.java`).
pub mod key;
pub mod restore;
pub mod words;

pub use key::{
    create_recovery_key, decode_recovery_key, reset_password, validate_recovery_key,
    RECOVERY_KEY_WORDS,
};
pub use words::{WordEncoder, WORD_COUNT};
