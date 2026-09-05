//! Cryptomator vault format 8, ported from cryptolib 2.2.2 and cryptofs 2.10.0.
#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod constants;
pub mod crypto;
pub mod error;
pub mod masterkey_file;

pub use crypto::masterkey::Masterkey;
pub use crypto::rng::{DetRng, OsRng, Rng};
pub use error::{CoreError, Result};
pub use masterkey_file::{MasterkeyFile, MasterkeyFileAccess};
