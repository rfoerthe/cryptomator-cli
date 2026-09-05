//! Cryptomator vault format 8, ported from cryptolib 2.2.2 and cryptofs 2.10.0.
#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod backup;
pub mod constants;
pub mod crypto;
pub mod error;
pub mod masterkey_file;
pub mod vault_config;

pub use crypto::cryptor::{CipherCombo, ContentCryptor, Cryptor, HeaderCryptor};
pub use crypto::header::FileHeader;
pub use crypto::masterkey::Masterkey;
pub use crypto::rng::{DetRng, OsRng, Rng};
pub use crypto::stream::{decrypt_all, encrypt_all, DecryptingReader, EncryptingWriter};
pub use error::{CoreError, Result};
pub use masterkey_file::{MasterkeyFile, MasterkeyFileAccess};
pub use vault_config::{JwtAlgorithm, KeyId, UnverifiedVaultConfig, VaultConfig};
