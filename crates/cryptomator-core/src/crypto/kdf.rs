//! scrypt key derivation for the masterkey file (`common/Scrypt.java`, `MasterkeyFileAccess.scrypt`).
//! p is fixed to 1 and the derived key is always 32 bytes, exactly like cryptolib.
use crate::error::{CoreError, Result};
use zeroize::Zeroizing;

pub const KEK_LEN: usize = 32;

pub fn scrypt_kek(
    passphrase: &str,
    salt: &[u8],
    pepper: &[u8],
    cost_param: u32,
    block_size: u32,
) -> Result<Zeroizing<[u8; KEK_LEN]>> {
    if cost_param < 2 || !cost_param.is_power_of_two() {
        return Err(CoreError::InvalidArgument(
            "scrypt N must be a power of 2 greater than 1".into(),
        ));
    }
    let log_n = cost_param.trailing_zeros() as u8;
    let params = scrypt::Params::new(log_n, block_size, 1)
        .map_err(|e| CoreError::InvalidArgument(format!("invalid scrypt parameters: {e}")))?;
    let mut salt_and_pepper = Zeroizing::new(Vec::with_capacity(salt.len() + pepper.len()));
    salt_and_pepper.extend_from_slice(salt);
    salt_and_pepper.extend_from_slice(pepper);
    let mut kek = Zeroizing::new([0u8; KEK_LEN]);
    scrypt::scrypt(
        passphrase.as_bytes(),
        &salt_and_pepper,
        &params,
        kek.as_mut(),
    )
    .map_err(|e| CoreError::InvalidArgument(format!("scrypt failed: {e}")))?;
    Ok(kek)
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_encoding::HEXLOWER;

    #[test]
    fn rfc7914_vector_1_first_32_bytes() {
        // RFC 7914 §12, scrypt("", "", N=16, r=1, p=1, dkLen=64) – dkLen 32 is the prefix.
        let kek = scrypt_kek("", b"", b"", 16, 1).unwrap();
        assert_eq!(
            HEXLOWER.encode(&*kek),
            "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442"
        );
    }

    #[test]
    fn pepper_is_appended_to_salt() {
        let with_pepper = scrypt_kek("pw", b"sa", b"lt", 16, 1).unwrap();
        let joined = scrypt_kek("pw", b"salt", b"", 16, 1).unwrap();
        assert_eq!(*with_pepper, *joined);
    }

    #[test]
    fn rejects_cost_param_that_is_not_a_power_of_two() {
        assert!(matches!(
            scrypt_kek("pw", b"salt", b"", 1000, 8),
            Err(CoreError::InvalidArgument(_))
        ));
        assert!(matches!(
            scrypt_kek("pw", b"salt", b"", 1, 8),
            Err(CoreError::InvalidArgument(_))
        ));
    }
}
