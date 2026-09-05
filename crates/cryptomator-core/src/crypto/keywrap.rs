//! AES key wrap (RFC 3394) as used by `common/AesKeyWrap.java` (JCE "AESWrap").
use crate::error::{CoreError, Result};
use aes_kw::cipher::KeyInit;
use aes_kw::KwAes256;
use zeroize::Zeroizing;

pub const WRAPPED_LEN: usize = 40;

pub fn wrap_key(kek: &[u8; 32], key: &[u8; 32]) -> [u8; WRAPPED_LEN] {
    let kw = KwAes256::new_from_slice(kek).expect("32-byte KEK");
    let mut out = [0u8; WRAPPED_LEN];
    kw.wrap_key(key, &mut out)
        .expect("output buffer sized for 32-byte key");
    out
}

pub fn unwrap_key(kek: &[u8; 32], wrapped: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    if wrapped.len() != WRAPPED_LEN {
        return Err(CoreError::AuthenticationFailed(format!(
            "wrapped key must be {WRAPPED_LEN} bytes, got {}",
            wrapped.len()
        )));
    }
    let kw = KwAes256::new_from_slice(kek).expect("32-byte KEK");
    let mut out = Zeroizing::new([0u8; 32]);
    kw.unwrap_key(wrapped, out.as_mut())
        .map_err(|_| CoreError::AuthenticationFailed("key unwrap integrity check failed".into()))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_encoding::HEXUPPER;

    // RFC 3394 §4.6: wrap 256 bits of key data with a 256-bit KEK.
    const KEK: &str = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
    const KEY: &str = "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F";
    const WRAPPED: &str =
        "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21";

    fn arr32(hex: &str) -> [u8; 32] {
        HEXUPPER.decode(hex.as_bytes()).unwrap().try_into().unwrap()
    }

    #[test]
    fn wraps_like_rfc3394() {
        let wrapped = wrap_key(&arr32(KEK), &arr32(KEY));
        assert_eq!(HEXUPPER.encode(&wrapped), WRAPPED);
    }

    #[test]
    fn unwraps_like_rfc3394() {
        let wrapped = HEXUPPER.decode(WRAPPED.as_bytes()).unwrap();
        let key = unwrap_key(&arr32(KEK), &wrapped).unwrap();
        assert_eq!(*key, arr32(KEY));
    }

    #[test]
    fn unwrap_with_wrong_kek_fails_authentication() {
        let wrapped = HEXUPPER.decode(WRAPPED.as_bytes()).unwrap();
        let mut kek = arr32(KEK);
        kek[0] ^= 1;
        assert!(matches!(
            unwrap_key(&kek, &wrapped),
            Err(CoreError::AuthenticationFailed(_))
        ));
    }

    #[test]
    fn unwrap_rejects_wrong_length() {
        assert!(matches!(
            unwrap_key(&arr32(KEK), &[0u8; 39]),
            Err(CoreError::AuthenticationFailed(_))
        ));
    }
}
