//! Recovery key = 64-byte masterkey + 2 low-order bytes (little-endian) of CRC32 → 66 bytes → 44 words.
use crate::backup::backup_file_name;
use crate::constants::MASTERKEY_FILENAME;
use crate::crypto::masterkey::Masterkey;
use crate::crypto::rng::Rng;
use crate::error::{CoreError, Result};
use crate::masterkey_file::{MasterkeyFileAccess, DEFAULT_MASTERKEY_FILE_VERSION};
use crate::recovery::words::WordEncoder;
use std::path::Path;
use zeroize::Zeroizing;

pub const RECOVERY_KEY_WORDS: usize = 44;
const PADDED_LEN: usize = 66;

fn crc_suffix(raw_key: &[u8; 64]) -> [u8; 2] {
    // Guava's HashCode.asBytes() is little-endian; Java copies its first two bytes.
    let crc = crc32fast::hash(raw_key).to_le_bytes();
    [crc[0], crc[1]]
}

pub fn create_recovery_key(encoder: &WordEncoder, raw_key: &[u8; 64]) -> String {
    let mut padded = Zeroizing::new([0u8; PADDED_LEN]);
    padded[..64].copy_from_slice(raw_key);
    padded[64..].copy_from_slice(&crc_suffix(raw_key));
    encoder
        .encode_padded(&*padded)
        .expect("66 is a multiple of 3")
}

pub fn decode_recovery_key(
    encoder: &WordEncoder,
    recovery_key: &str,
) -> Result<Zeroizing<[u8; 64]>> {
    let padded = Zeroizing::new(encoder.decode(recovery_key)?);
    if padded.len() != PADDED_LEN {
        return Err(CoreError::InvalidRecoveryKey(
            "Recovery key doesn't consist of 66 bytes.".into(),
        ));
    }
    let mut raw = Zeroizing::new([0u8; 64]);
    raw.copy_from_slice(&padded[..64]);
    if padded[64..] != crc_suffix(&raw) {
        return Err(CoreError::InvalidRecoveryKey(
            "Recovery key has invalid CRC.".into(),
        ));
    }
    Ok(raw)
}

pub fn validate_recovery_key(encoder: &WordEncoder, recovery_key: &str) -> bool {
    decode_recovery_key(encoder, recovery_key).is_ok()
}

/// `RecoveryKeyFactory.newMasterkeyFileWithPassphrase`: back up an existing masterkey file, then write a new one.
pub fn reset_password(
    encoder: &WordEncoder,
    vault_path: &Path,
    recovery_key: &str,
    new_passphrase: &str,
    rng: &mut dyn Rng,
) -> Result<()> {
    let raw = decode_recovery_key(encoder, recovery_key)?;
    let masterkey = Masterkey::from_raw(*raw);
    let masterkey_path = vault_path.join(MASTERKEY_FILENAME);
    if masterkey_path.exists() {
        let old_bytes = std::fs::read(&masterkey_path)?;
        let backup_path = vault_path.join(backup_file_name(MASTERKEY_FILENAME, &old_bytes));
        std::fs::rename(&masterkey_path, &backup_path)?;
    }
    MasterkeyFileAccess::new(Vec::new()).persist(
        &masterkey,
        &masterkey_path,
        new_passphrase,
        DEFAULT_MASTERKEY_FILE_VERSION,
        rng,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rng::DetRng;
    use crate::masterkey_file::MasterkeyFileAccess;

    // RecoveryKeyFactory.createRecoveryKey(key 00..3f): crc32 = 0x100ece8c → trailing bytes 8c ce.
    const RECOVERY_KEY_SEQUENTIAL: &str = "ad back bin enter gym gentle own intense van resident sin oh boot dumb debt stake flag tenure hers worship life similarly nail open pray thick shoe visual tend counter warn scenario cave cash jury grass shed league allow obvious build transfer dream normally";
    // From RecoveryKeyFactoryTest in the desktop app.
    const VALID_KEY: &str = "pathway lift abuse plenty export texture gentleman landscape beyond ceiling around leaf cafe charity border breakdown victory surely computer cat linger restrict infer crowd live computer true written amazed investor boot depth left theory snow whereby terminal weekly reject happiness circuit partial cup ad";
    const INVALID_CRC_KEY: &str = "pathway lift abuse plenty export texture gentleman landscape beyond ceiling around leaf cafe charity border breakdown victory surely computer cat linger restrict infer crowd live computer true written amazed investor boot depth left theory snow whereby terminal weekly reject happiness circuit partial cup wrong";

    fn sequential() -> [u8; 64] {
        let mut raw = [0u8; 64];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = i as u8;
        }
        raw
    }

    #[test]
    fn creates_44_word_key_like_java() {
        let enc = WordEncoder::new();
        let key = create_recovery_key(&enc, &sequential());
        assert_eq!(key.split(' ').count(), 44);
        assert_eq!(key, RECOVERY_KEY_SEQUENTIAL);
    }

    #[test]
    fn decodes_own_key_back_to_raw_masterkey() {
        let enc = WordEncoder::new();
        assert_eq!(
            *decode_recovery_key(&enc, RECOVERY_KEY_SEQUENTIAL).unwrap(),
            sequential()
        );
    }

    #[test]
    fn validates_like_java_tests() {
        let enc = WordEncoder::new();
        assert!(validate_recovery_key(&enc, VALID_KEY));
        assert!(!validate_recovery_key(&enc, INVALID_CRC_KEY));
        assert!(!validate_recovery_key(&enc, "pathway"));
        assert!(!validate_recovery_key(
            &enc,
            "Backpfeifengesicht Schweinehund"
        ));
        assert!(!validate_recovery_key(&enc, "pathway lift"));
    }

    #[test]
    fn reset_password_backs_up_old_file_and_writes_new_one() {
        let dir = tempfile::tempdir().unwrap();
        let masterkey_path = dir.path().join("masterkey.cryptomator");
        std::fs::write(&masterkey_path, b"old masterkey file\n").unwrap();
        let enc = WordEncoder::new();
        reset_password(
            &enc,
            dir.path(),
            RECOVERY_KEY_SEQUENTIAL,
            "new-pass",
            &mut DetRng::default(),
        )
        .unwrap();
        let expected_backup = dir.path().join(format!(
            "masterkey.cryptomator{}.bkup",
            crate::backup::generate_file_id_suffix(b"old masterkey file\n")
        ));
        assert_eq!(
            std::fs::read(&expected_backup).unwrap(),
            b"old masterkey file\n"
        );
        let key = MasterkeyFileAccess::new(Vec::new())
            .load(&masterkey_path, "new-pass")
            .unwrap();
        assert_eq!(key.raw(), &sequential());
    }

    #[test]
    fn reset_password_with_invalid_key_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let enc = WordEncoder::new();
        assert!(matches!(
            reset_password(
                &enc,
                dir.path(),
                INVALID_CRC_KEY,
                "x",
                &mut DetRng::default()
            ),
            Err(CoreError::InvalidRecoveryKey(_))
        ));
        assert!(!dir.path().join("masterkey.cryptomator").exists());
    }
}
