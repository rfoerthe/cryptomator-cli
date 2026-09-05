//! Cryptographic primitives of vault format 8.
pub mod cryptor;
// The scheme-specific implementations are reachable only through the `Cryptor` /
// `HeaderCryptor` / `ContentCryptor` facade in `cryptor`, whose nonce-length guard is the
// only thing standing between a caller and a cross-scheme panic.
pub(crate) mod ctrmac;
pub(crate) mod gcm;
pub mod header;
pub mod kdf;
pub mod keywrap;
pub mod masterkey;
pub mod rng;
pub mod siv;
pub mod stream;
