//! Scheme selection (`api/CryptorProvider.Scheme`) and the `Cryptor` facade (`api/Cryptor.java`).
use crate::crypto::ctrmac::{CtrMacContentCryptor, CtrMacHeaderCryptor};
use crate::crypto::gcm::{GcmContentCryptor, GcmHeaderCryptor};
use crate::crypto::header::FileHeader;
use crate::crypto::masterkey::Masterkey;
use crate::crypto::rng::Rng;
use crate::crypto::siv::FileNameCryptor;
use crate::error::{CoreError, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// `cipherCombo` claim of `vault.cryptomator`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CipherCombo {
    #[serde(rename = "SIV_CTRMAC")]
    SivCtrMac,
    #[serde(rename = "SIV_GCM")]
    SivGcm,
}

impl CipherCombo {
    pub const ALL: [CipherCombo; 2] = [CipherCombo::SivCtrMac, CipherCombo::SivGcm];

    pub fn as_str(&self) -> &'static str {
        match self {
            CipherCombo::SivCtrMac => "SIV_CTRMAC",
            CipherCombo::SivGcm => "SIV_GCM",
        }
    }
}

impl std::fmt::Display for CipherCombo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for CipherCombo {
    type Err = CoreError;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "SIV_CTRMAC" => Ok(CipherCombo::SivCtrMac),
            "SIV_GCM" => Ok(CipherCombo::SivGcm),
            other => Err(CoreError::InvalidArgument(format!(
                "unknown cipher combo {other}"
            ))),
        }
    }
}

#[derive(Debug)]
pub enum HeaderCryptor {
    Gcm(GcmHeaderCryptor),
    CtrMac(CtrMacHeaderCryptor),
}

impl HeaderCryptor {
    pub fn create(&self, rng: &mut dyn Rng) -> FileHeader {
        match self {
            HeaderCryptor::Gcm(h) => h.create(rng),
            HeaderCryptor::CtrMac(h) => h.create(rng),
        }
    }

    pub fn header_size(&self) -> usize {
        match self {
            HeaderCryptor::Gcm(h) => h.header_size(),
            HeaderCryptor::CtrMac(h) => h.header_size(),
        }
    }

    /// Nonce length the scheme requires in a [`FileHeader`].
    fn nonce_size(&self) -> usize {
        match self {
            HeaderCryptor::Gcm(_) => crate::crypto::gcm::GCM_NONCE_SIZE,
            HeaderCryptor::CtrMac(_) => crate::crypto::ctrmac::NONCE_SIZE,
        }
    }

    fn scheme(&self) -> CipherCombo {
        match self {
            HeaderCryptor::Gcm(_) => CipherCombo::SivGcm,
            HeaderCryptor::CtrMac(_) => CipherCombo::SivCtrMac,
        }
    }

    /// Rejects headers created by the other scheme instead of panicking on the nonce length.
    pub fn encrypt_header(&self, header: &FileHeader) -> Result<Vec<u8>> {
        if header.nonce().len() != self.nonce_size() {
            return Err(CoreError::InvalidArgument(format!(
                "header nonce length {} does not match scheme {}",
                header.nonce().len(),
                self.scheme()
            )));
        }
        Ok(match self {
            HeaderCryptor::Gcm(h) => h.encrypt_header(header),
            HeaderCryptor::CtrMac(h) => h.encrypt_header(header),
        })
    }

    pub fn decrypt_header(&self, ciphertext_header: &[u8]) -> Result<FileHeader> {
        match self {
            HeaderCryptor::Gcm(h) => h.decrypt_header(ciphertext_header),
            HeaderCryptor::CtrMac(h) => h.decrypt_header(ciphertext_header),
        }
    }
}

#[derive(Debug)]
pub enum ContentCryptor {
    Gcm(GcmContentCryptor),
    CtrMac(CtrMacContentCryptor),
}

impl ContentCryptor {
    pub fn cleartext_chunk_size(&self) -> usize {
        match self {
            ContentCryptor::Gcm(c) => c.cleartext_chunk_size(),
            ContentCryptor::CtrMac(c) => c.cleartext_chunk_size(),
        }
    }

    pub fn ciphertext_chunk_size(&self) -> usize {
        match self {
            ContentCryptor::Gcm(c) => c.ciphertext_chunk_size(),
            ContentCryptor::CtrMac(c) => c.ciphertext_chunk_size(),
        }
    }

    pub fn encrypt_chunk(
        &self,
        cleartext_chunk: &[u8],
        chunk_number: u64,
        header: &FileHeader,
        rng: &mut dyn Rng,
    ) -> Vec<u8> {
        match self {
            ContentCryptor::Gcm(c) => c.encrypt_chunk(cleartext_chunk, chunk_number, header, rng),
            ContentCryptor::CtrMac(c) => {
                c.encrypt_chunk(cleartext_chunk, chunk_number, header, rng)
            }
        }
    }

    /// The cleartext is wrapped in [`Zeroizing`] so the plaintext chunk is wiped when it is dropped.
    pub fn decrypt_chunk(
        &self,
        ciphertext_chunk: &[u8],
        chunk_number: u64,
        header: &FileHeader,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let cleartext = match self {
            ContentCryptor::Gcm(c) => c.decrypt_chunk(ciphertext_chunk, chunk_number, header)?,
            ContentCryptor::CtrMac(c) => c.decrypt_chunk(ciphertext_chunk, chunk_number, header)?,
        };
        Ok(Zeroizing::new(cleartext))
    }

    /// Cleartext size of a file body (ciphertext size WITHOUT the header). Mirrors `FileContentCryptor.cleartextSize`,
    /// including the undefined case where trailing bytes are not larger than the per-chunk overhead.
    pub fn cleartext_size(&self, ciphertext_size: u64) -> Result<u64> {
        let cleartext_chunk = self.cleartext_chunk_size() as u64;
        let ciphertext_chunk = self.ciphertext_chunk_size() as u64;
        let overhead = ciphertext_chunk - cleartext_chunk;
        let full_chunks = ciphertext_size / ciphertext_chunk;
        let additional_ciphertext = ciphertext_size % ciphertext_chunk;
        if additional_ciphertext > 0 && additional_ciphertext <= overhead {
            return Err(CoreError::InvalidArgument(format!(
                "Method not defined for input value {ciphertext_size}"
            )));
        }
        let additional_cleartext = if additional_ciphertext == 0 {
            0
        } else {
            additional_ciphertext - overhead
        };
        Ok(cleartext_chunk * full_chunks + additional_cleartext)
    }

    /// Ciphertext size of a file body (WITHOUT the header). Mirrors `FileContentCryptor.ciphertextSize`.
    pub fn ciphertext_size(&self, cleartext_size: u64) -> u64 {
        let cleartext_chunk = self.cleartext_chunk_size() as u64;
        let ciphertext_chunk = self.ciphertext_chunk_size() as u64;
        let overhead = ciphertext_chunk - cleartext_chunk;
        let full_chunks = cleartext_size / cleartext_chunk;
        let additional_cleartext = cleartext_size % cleartext_chunk;
        let additional_ciphertext = if additional_cleartext == 0 {
            0
        } else {
            additional_cleartext + overhead
        };
        ciphertext_chunk * full_chunks + additional_ciphertext
    }
}

/// Bundle of all cryptographic operations for one vault (`api/Cryptor.java`).
#[derive(Debug)]
pub struct Cryptor {
    cipher_combo: CipherCombo,
    file_name_cryptor: FileNameCryptor,
    header_cryptor: HeaderCryptor,
    content_cryptor: ContentCryptor,
}

impl Cryptor {
    pub fn new(cipher_combo: CipherCombo, masterkey: &Masterkey) -> Self {
        let (header_cryptor, content_cryptor) = match cipher_combo {
            CipherCombo::SivGcm => (
                HeaderCryptor::Gcm(GcmHeaderCryptor::new(masterkey)),
                ContentCryptor::Gcm(GcmContentCryptor),
            ),
            CipherCombo::SivCtrMac => (
                HeaderCryptor::CtrMac(CtrMacHeaderCryptor::new(masterkey)),
                ContentCryptor::CtrMac(CtrMacContentCryptor::new(masterkey)),
            ),
        };
        Self {
            cipher_combo,
            file_name_cryptor: FileNameCryptor::new(masterkey),
            header_cryptor,
            content_cryptor,
        }
    }

    pub fn cipher_combo(&self) -> CipherCombo {
        self.cipher_combo
    }

    pub fn file_name_cryptor(&self) -> &FileNameCryptor {
        &self.file_name_cryptor
    }

    pub fn file_header_cryptor(&self) -> &HeaderCryptor {
        &self.header_cryptor
    }

    pub fn file_content_cryptor(&self) -> &ContentCryptor {
        &self.content_cryptor
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rng::DetRng;

    fn masterkey() -> Masterkey {
        let mut raw = [0u8; 64];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = i as u8;
        }
        Masterkey::from_raw(raw)
    }

    #[test]
    fn cipher_combo_names_match_java_enum() {
        assert_eq!(CipherCombo::SivGcm.as_str(), "SIV_GCM");
        assert_eq!(CipherCombo::SivCtrMac.as_str(), "SIV_CTRMAC");
        assert_eq!(
            "SIV_GCM".parse::<CipherCombo>().unwrap(),
            CipherCombo::SivGcm
        );
        assert!("AES_GCM".parse::<CipherCombo>().is_err());
        assert_eq!(
            serde_json::to_string(&CipherCombo::SivCtrMac).unwrap(),
            "\"SIV_CTRMAC\""
        );
        assert_eq!(
            serde_json::from_str::<CipherCombo>("\"SIV_GCM\"").unwrap(),
            CipherCombo::SivGcm
        );
    }

    #[test]
    fn cryptor_dispatches_to_scheme() {
        let gcm = Cryptor::new(CipherCombo::SivGcm, &masterkey());
        let ctr = Cryptor::new(CipherCombo::SivCtrMac, &masterkey());
        assert_eq!(gcm.file_header_cryptor().header_size(), 68);
        assert_eq!(ctr.file_header_cryptor().header_size(), 88);
        assert_eq!(gcm.file_content_cryptor().ciphertext_chunk_size(), 32796);
        assert_eq!(ctr.file_content_cryptor().ciphertext_chunk_size(), 32816);
        assert_eq!(
            gcm.file_name_cryptor().hash_directory_id(""),
            "MN53XCQH5RFQJPKAFCMWDGELQHPPW2YQ"
        );
    }

    #[test]
    fn header_and_chunk_round_trip_through_facade() {
        for combo in [CipherCombo::SivGcm, CipherCombo::SivCtrMac] {
            let cryptor = Cryptor::new(combo, &masterkey());
            let mut rng = DetRng::default();
            let header = cryptor.file_header_cryptor().create(&mut rng);
            let enc = cryptor
                .file_header_cryptor()
                .encrypt_header(&header)
                .unwrap();
            let dec = cryptor.file_header_cryptor().decrypt_header(&enc).unwrap();
            assert_eq!(dec.content_key(), header.content_key());
            let chunk = cryptor
                .file_content_cryptor()
                .encrypt_chunk(b"payload", 3, &header, &mut rng);
            assert_eq!(
                cryptor
                    .file_content_cryptor()
                    .decrypt_chunk(&chunk, 3, &header)
                    .unwrap()
                    .as_slice(),
                b"payload"
            );
        }
    }

    #[test]
    fn encrypt_header_rejects_foreign_nonce_length() {
        let gcm = Cryptor::new(CipherCombo::SivGcm, &masterkey());
        let ctr = Cryptor::new(CipherCombo::SivCtrMac, &masterkey());
        let mut rng = DetRng::default();
        let gcm_header = gcm.file_header_cryptor().create(&mut rng);
        assert_eq!(gcm_header.nonce().len(), 12);
        assert!(matches!(
            ctr.file_header_cryptor().encrypt_header(&gcm_header),
            Err(CoreError::InvalidArgument(_))
        ));
    }

    // Values from FileContentCryptor.cleartextSize/ciphertextSize (Java defaults) and jshell runs.
    #[test]
    fn size_math_matches_java() {
        let gcm = Cryptor::new(CipherCombo::SivGcm, &masterkey());
        let cc = gcm.file_content_cryptor();
        assert_eq!(cc.ciphertext_size(0), 0);
        assert_eq!(cc.ciphertext_size(1), 29);
        assert_eq!(cc.ciphertext_size(32768), 32796);
        assert_eq!(cc.ciphertext_size(32769), 32796 + 29);
        assert_eq!(cc.cleartext_size(0).unwrap(), 0);
        assert_eq!(cc.cleartext_size(29).unwrap(), 1);
        assert_eq!(cc.cleartext_size(32796).unwrap(), 32768);
        assert_eq!(
            cc.cleartext_size(40124 - 68).unwrap(),
            40000,
            "40124-byte GCM file from the jshell run holds 40000 cleartext bytes"
        );
        assert!(
            matches!(cc.cleartext_size(28), Err(CoreError::InvalidArgument(_))),
            "trailing bytes <= overhead are undefined"
        );
        assert!(matches!(
            cc.cleartext_size(32796 + 5),
            Err(CoreError::InvalidArgument(_))
        ));

        let ctr = Cryptor::new(CipherCombo::SivCtrMac, &masterkey());
        let cc = ctr.file_content_cryptor();
        assert_eq!(cc.ciphertext_size(1), 49);
        assert_eq!(cc.cleartext_size(40184 - 88).unwrap(), 40000);
        assert!(cc.cleartext_size(48).is_err());
    }
}
