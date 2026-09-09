//! scrypt key derivation for the masterkey file (`common/Scrypt.java`, `MasterkeyFileAccess.scrypt`).
//! p is fixed to 1 and the derived key is always 32 bytes, exactly like cryptolib.
use crate::error::{CoreError, Result};
use zeroize::Zeroizing;

pub const KEK_LEN: usize = 32;

/// The largest `scryptCostParam` (`N`) a masterkey file may ask for.
///
/// cryptolib has no limit at all -- `MasterkeyFileAccess.unlock` hands the value straight to
/// `Scrypt.scrypt` -- and a `masterkey.cryptomator` is a file someone else can hand you. 2^20 is
/// 32 times the library's own default and, at the default block size, a one-gigabyte allocation:
/// far beyond anything a Cryptomator release has ever written, and still not a machine killer.
pub const MAX_SCRYPT_COST_PARAM: u32 = 1 << 20;
/// The largest `scryptBlockSize` (`r`). Every Cryptomator vault uses 8.
pub const MAX_SCRYPT_BLOCK_SIZE: u32 = 64;
/// The memory ceiling for one derivation. scrypt's working set is `128 * N * r` bytes, so the two
/// limits above are not enough on their own: N = 2^20 with r = 64 is 8 GiB with both values inside
/// their individual bounds.
pub const MAX_SCRYPT_MEMORY_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Checks `cost_param` (`N`) and `block_size` (`r`) against the three limits above.
///
/// Split out of [`scrypt_kek`] so a masterkey file can be refused when it is *read*
/// ([`crate::masterkey_file::MasterkeyFile::validate`]) — before a passphrase is asked for and
/// before scrypt allocates anything. The error is [`CoreError::InvalidMasterkeyFile`] (exit 1)
/// rather than an invalid *argument*: every value that reaches here came out of a file. Its text
/// names the two values and the limits, none of which is secret.
pub fn check_scrypt_params(cost_param: u32, block_size: u32) -> Result<()> {
    // u128, so the product cannot overflow whatever the file asks for -- independent of the order
    // in which the conditions below happen to be evaluated.
    let memory = 128u128 * u128::from(cost_param) * u128::from(block_size);
    let within_limits = (2..=MAX_SCRYPT_COST_PARAM).contains(&cost_param)
        && cost_param.is_power_of_two()
        && (1..=MAX_SCRYPT_BLOCK_SIZE).contains(&block_size)
        && memory <= u128::from(MAX_SCRYPT_MEMORY_BYTES);
    if within_limits {
        return Ok(());
    }
    Err(CoreError::InvalidMasterkeyFile(format!(
        "scrypt parameters out of range: N={cost_param}, r={block_size} \
         (limits: N ≤ 2^{} power of two, r ≤ {MAX_SCRYPT_BLOCK_SIZE}, memory ≤ {} GiB)",
        MAX_SCRYPT_COST_PARAM.trailing_zeros(),
        MAX_SCRYPT_MEMORY_BYTES / (1024 * 1024 * 1024),
    )))
}

pub fn scrypt_kek(
    passphrase: &str,
    salt: &[u8],
    pepper: &[u8],
    cost_param: u32,
    block_size: u32,
) -> Result<Zeroizing<[u8; KEK_LEN]>> {
    // Also here, not only in `MasterkeyFile::validate`: `unlock` is public and the migration path
    // reaches it with a file this process never validated.
    check_scrypt_params(cost_param, block_size)?;
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
            Err(CoreError::InvalidMasterkeyFile(_))
        ));
        assert!(matches!(
            scrypt_kek("pw", b"salt", b"", 1, 8),
            Err(CoreError::InvalidMasterkeyFile(_))
        ));
        assert!(
            check_scrypt_params(3, 8).is_err(),
            "N = 3 is not a power of 2"
        );
        assert!(
            check_scrypt_params(0, 8).is_err(),
            "N = 0 is not a cost parameter"
        );
    }

    /// A hostile masterkey file can ask for any cost parameter it likes. 2^24 with r = 8 is a
    /// 16 GiB allocation before a passphrase has even been typed; the derivation must refuse it
    /// instead of trying.
    #[test]
    fn an_absurd_cost_parameter_is_rejected_rather_than_attempted() {
        let err = scrypt_kek("pw", b"salt", b"", 1 << 24, 8).unwrap_err();
        let text = err.to_string();
        assert!(
            matches!(err, CoreError::InvalidMasterkeyFile(_)),
            "wrong error type: {err:?}"
        );
        assert!(
            text.contains("16777216"),
            "the message does not name the value: {text}"
        );
    }

    /// The cost parameter's own boundary: 2^20 is in, the next power of two is out.
    #[test]
    fn the_cost_parameter_limit_is_inclusive() {
        assert!(
            check_scrypt_params(MAX_SCRYPT_COST_PARAM, 8).is_ok(),
            "N = 2^20 with r = 8 is 1 GiB: slow, but legal"
        );
        assert!(
            check_scrypt_params(1 << 21, 8).is_err(),
            "2^21 is over the limit"
        );
    }

    /// The block size multiplies the memory just as the cost parameter does, so it has a limit of
    /// its own.
    #[test]
    fn the_block_size_limit_is_inclusive() {
        assert!(check_scrypt_params(1024, MAX_SCRYPT_BLOCK_SIZE).is_ok());
        assert!(
            check_scrypt_params(1024, 65).is_err(),
            "r = 65 is over the limit"
        );
        assert!(
            check_scrypt_params(1024, 0).is_err(),
            "r = 0 is not a block size"
        );
    }

    /// The product has a limit too, because N = 2^20 with r = 64 is 8 GiB even though both values
    /// are individually inside their bounds. The boundary is exactly 2 GiB, and the arithmetic
    /// that decides it is done in u128, so no file can overflow it.
    #[test]
    fn the_memory_limit_is_exactly_two_gibibytes() {
        assert_eq!(
            128u64 * u64::from(MAX_SCRYPT_COST_PARAM) * 16,
            MAX_SCRYPT_MEMORY_BYTES,
            "N = 2^20 with r = 16 is the boundary case"
        );
        assert!(check_scrypt_params(MAX_SCRYPT_COST_PARAM, 16).is_ok());
        assert!(
            check_scrypt_params(MAX_SCRYPT_COST_PARAM, 17).is_err(),
            "one block over 2 GiB is out"
        );
        let err = check_scrypt_params(MAX_SCRYPT_COST_PARAM, MAX_SCRYPT_BLOCK_SIZE).unwrap_err();
        assert!(
            err.to_string().contains("memory"),
            "the product limit does not mention memory: {err}"
        );
    }

    /// The values real vaults use stay well inside the limits -- by a factor of 64 in memory. A
    /// limit that rejected a Cryptomator vault would be worse than no limit.
    #[test]
    fn every_value_a_cryptomator_release_writes_is_accepted() {
        // The library default (N = 2^15, r = 8 -> 32 MiB), the fixtures' N, `legacy_v5`'s N, the
        // Java reference file's N and the smallest legal pair the unit tests use.
        for (cost_param, block_size) in [
            (1 << 15, 8),
            (32768, 8),
            (16384, 8),
            (1024, 8),
            (16, 1),
            (2, 1),
        ] {
            check_scrypt_params(cost_param, block_size)
                .unwrap_or_else(|e| panic!("N={cost_param}, r={block_size} refused: {e}"));
        }
    }
}
