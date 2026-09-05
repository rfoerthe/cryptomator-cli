//! Cleartext file header (`v1/FileHeaderImpl.java`, `v2/FileHeaderImpl.java`): nonce + payload(reserved i64, content key).
use crate::error::{CoreError, Result};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const CONTENT_KEY_LEN: usize = 32;
pub const RESERVED_LEN: usize = 8;
pub const PAYLOAD_LEN: usize = RESERVED_LEN + CONTENT_KEY_LEN;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct FileHeader {
    nonce: Vec<u8>,
    reserved: i64,
    content_key: [u8; CONTENT_KEY_LEN],
}

impl std::fmt::Debug for FileHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileHeader")
            .field("nonce_len", &self.nonce.len())
            .field("reserved", &self.reserved)
            .finish_non_exhaustive()
    }
}

impl FileHeader {
    pub fn new(nonce: Vec<u8>, reserved: i64, content_key: [u8; CONTENT_KEY_LEN]) -> Self {
        Self {
            nonce,
            reserved,
            content_key,
        }
    }

    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    pub fn reserved(&self) -> i64 {
        self.reserved
    }

    pub fn content_key(&self) -> &[u8; CONTENT_KEY_LEN] {
        &self.content_key
    }

    /// `BE-int64(reserved) || contentKey`
    pub fn encode_payload(&self) -> Zeroizing<[u8; PAYLOAD_LEN]> {
        let mut out = Zeroizing::new([0u8; PAYLOAD_LEN]);
        out[..RESERVED_LEN].copy_from_slice(&self.reserved.to_be_bytes());
        out[RESERVED_LEN..].copy_from_slice(&self.content_key);
        out
    }

    pub fn decode_payload(nonce: Vec<u8>, payload: &[u8]) -> Result<Self> {
        if payload.len() != PAYLOAD_LEN {
            return Err(CoreError::InvalidArgument(format!(
                "invalid payload buffer length {}",
                payload.len()
            )));
        }
        let reserved = i64::from_be_bytes(payload[..RESERVED_LEN].try_into().expect("8 bytes"));
        let mut content_key = [0u8; CONTENT_KEY_LEN];
        content_key.copy_from_slice(&payload[RESERVED_LEN..]);
        Ok(Self {
            nonce,
            reserved,
            content_key,
        })
    }
}
