//! 512-bit vault masterkey (`api/Masterkey.java`): encryption key || MAC key.
use crate::crypto::rng::Rng;
use crate::error::{CoreError, Result};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const SUBKEY_LEN: usize = 32;
pub const MASTERKEY_LEN: usize = 64;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Masterkey {
    raw: [u8; MASTERKEY_LEN],
}

impl Masterkey {
    pub fn from_raw(raw: [u8; MASTERKEY_LEN]) -> Self {
        Self { raw }
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let raw: [u8; MASTERKEY_LEN] = bytes.try_into().map_err(|_| {
            CoreError::InvalidArgument(format!(
                "masterkey must be {MASTERKEY_LEN} bytes, got {}",
                bytes.len()
            ))
        })?;
        Ok(Self { raw })
    }

    pub fn from_parts(enc_key: &[u8; SUBKEY_LEN], mac_key: &[u8; SUBKEY_LEN]) -> Self {
        let mut raw = [0u8; MASTERKEY_LEN];
        raw[..SUBKEY_LEN].copy_from_slice(enc_key);
        raw[SUBKEY_LEN..].copy_from_slice(mac_key);
        Self { raw }
    }

    pub fn generate(rng: &mut dyn Rng) -> Self {
        let mut raw = [0u8; MASTERKEY_LEN];
        rng.fill(&mut raw);
        Self { raw }
    }

    pub fn enc_key(&self) -> &[u8; SUBKEY_LEN] {
        self.raw[..SUBKEY_LEN]
            .try_into()
            .expect("slice has fixed length")
    }

    pub fn mac_key(&self) -> &[u8; SUBKEY_LEN] {
        self.raw[SUBKEY_LEN..]
            .try_into()
            .expect("slice has fixed length")
    }

    pub fn raw(&self) -> &[u8; MASTERKEY_LEN] {
        &self.raw
    }
}

impl std::fmt::Debug for Masterkey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Masterkey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rng::DetRng;

    fn sequential_key() -> [u8; 64] {
        let mut raw = [0u8; 64];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = i as u8;
        }
        raw
    }

    #[test]
    fn enc_and_mac_key_are_first_and_second_half() {
        let key = Masterkey::from_raw(sequential_key());
        assert_eq!(key.enc_key()[0], 0x00);
        assert_eq!(key.enc_key()[31], 0x1f);
        assert_eq!(key.mac_key()[0], 0x20);
        assert_eq!(key.mac_key()[31], 0x3f);
        assert_eq!(key.raw(), &sequential_key());
    }

    #[test]
    fn from_slice_rejects_wrong_length() {
        assert!(matches!(
            Masterkey::from_slice(&[0u8; 63]),
            Err(CoreError::InvalidArgument(_))
        ));
        assert!(Masterkey::from_slice(&[0u8; 64]).is_ok());
    }

    #[test]
    fn generate_uses_rng() {
        let key = Masterkey::generate(&mut DetRng::default());
        assert_eq!(key.raw()[0], 0xa0);
        assert_eq!(key.raw()[63], 0xdf);
    }

    #[test]
    fn debug_output_is_redacted() {
        let key = Masterkey::from_raw(sequential_key());
        assert_eq!(format!("{key:?}"), "Masterkey(<redacted>)");
    }
}
