//! SIV_GCM content encryption (`v2/FileHeaderCryptorImpl.java`, `v2/FileContentCryptorImpl.java`, `v2/Constants.java`).
use crate::crypto::header::{FileHeader, CONTENT_KEY_LEN, PAYLOAD_LEN};
use crate::crypto::masterkey::Masterkey;
use crate::crypto::rng::Rng;
use crate::error::{CoreError, Result};
use aes_gcm::aead::{Aead, KeyInit, Nonce, Payload};
use aes_gcm::Aes256Gcm;
use zeroize::Zeroizing;

pub const GCM_NONCE_SIZE: usize = 12;
pub const PAYLOAD_SIZE: usize = 32 * 1024;
pub const GCM_TAG_SIZE: usize = 16;
pub const CHUNK_SIZE: usize = GCM_NONCE_SIZE + PAYLOAD_SIZE + GCM_TAG_SIZE;
pub const HEADER_SIZE: usize = GCM_NONCE_SIZE + PAYLOAD_LEN + GCM_TAG_SIZE;

fn nonce(bytes: &[u8]) -> Nonce<Aes256Gcm> {
    Nonce::<Aes256Gcm>::try_from(bytes).expect("12-byte nonce")
}

pub struct GcmHeaderCryptor {
    enc_key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for GcmHeaderCryptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GcmHeaderCryptor(<redacted>)")
    }
}

impl GcmHeaderCryptor {
    pub fn new(masterkey: &Masterkey) -> Self {
        Self {
            enc_key: Zeroizing::new(*masterkey.enc_key()),
        }
    }

    pub fn create(&self, rng: &mut dyn Rng) -> FileHeader {
        let mut nonce = vec![0u8; GCM_NONCE_SIZE];
        rng.fill(&mut nonce);
        let mut content_key = [0u8; CONTENT_KEY_LEN];
        rng.fill(&mut content_key);
        FileHeader::new(nonce, -1, content_key)
    }

    pub fn header_size(&self) -> usize {
        HEADER_SIZE
    }

    pub fn encrypt_header(&self, header: &FileHeader) -> Vec<u8> {
        let cipher = Aes256Gcm::new_from_slice(&*self.enc_key).expect("32-byte key");
        let payload = header.encode_payload();
        let ciphertext_and_tag = cipher
            .encrypt(
                &nonce(header.nonce()),
                Payload {
                    msg: &*payload,
                    aad: b"",
                },
            )
            .expect("GCM encryption");
        let mut out = Vec::with_capacity(HEADER_SIZE);
        out.extend_from_slice(header.nonce());
        out.extend_from_slice(&ciphertext_and_tag);
        out
    }

    pub fn decrypt_header(&self, ciphertext_header: &[u8]) -> Result<FileHeader> {
        if ciphertext_header.len() < HEADER_SIZE {
            return Err(CoreError::InvalidArgument(
                "Malformed ciphertext header".into(),
            ));
        }
        let header_nonce = &ciphertext_header[..GCM_NONCE_SIZE];
        let ciphertext_and_tag = &ciphertext_header[GCM_NONCE_SIZE..HEADER_SIZE];
        let cipher = Aes256Gcm::new_from_slice(&*self.enc_key).expect("32-byte key");
        let payload = Zeroizing::new(
            cipher
                .decrypt(
                    &nonce(header_nonce),
                    Payload {
                        msg: ciphertext_and_tag,
                        aad: b"",
                    },
                )
                .map_err(|_| CoreError::AuthenticationFailed("Header tag mismatch.".into()))?,
        );
        FileHeader::decode_payload(header_nonce.to_vec(), &payload)
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct GcmContentCryptor;

impl GcmContentCryptor {
    pub fn cleartext_chunk_size(&self) -> usize {
        PAYLOAD_SIZE
    }

    pub fn ciphertext_chunk_size(&self) -> usize {
        CHUNK_SIZE
    }

    fn aad(chunk_number: u64, header: &FileHeader) -> Vec<u8> {
        let mut aad = Vec::with_capacity(8 + header.nonce().len());
        aad.extend_from_slice(&chunk_number.to_be_bytes());
        aad.extend_from_slice(header.nonce());
        aad
    }

    /// `nonce || AES-GCM(contentKey, nonce, AAD = BE64(chunkNumber) || headerNonce)(cleartext) || tag`
    pub fn encrypt_chunk(
        &self,
        cleartext_chunk: &[u8],
        chunk_number: u64,
        header: &FileHeader,
        rng: &mut dyn Rng,
    ) -> Vec<u8> {
        assert!(
            cleartext_chunk.len() <= PAYLOAD_SIZE,
            "Invalid cleartext chunk size: {}",
            cleartext_chunk.len()
        );
        let mut chunk_nonce = [0u8; GCM_NONCE_SIZE];
        rng.fill(&mut chunk_nonce);
        let cipher = Aes256Gcm::new_from_slice(header.content_key()).expect("32-byte key");
        let ciphertext_and_tag = cipher
            .encrypt(
                &nonce(&chunk_nonce),
                Payload {
                    msg: cleartext_chunk,
                    aad: &Self::aad(chunk_number, header),
                },
            )
            .expect("GCM encryption");
        let mut out = Vec::with_capacity(GCM_NONCE_SIZE + ciphertext_and_tag.len());
        out.extend_from_slice(&chunk_nonce);
        out.extend_from_slice(&ciphertext_and_tag);
        out
    }

    pub fn decrypt_chunk(
        &self,
        ciphertext_chunk: &[u8],
        chunk_number: u64,
        header: &FileHeader,
    ) -> Result<Vec<u8>> {
        if ciphertext_chunk.len() < GCM_NONCE_SIZE + GCM_TAG_SIZE
            || ciphertext_chunk.len() > CHUNK_SIZE
        {
            return Err(CoreError::InvalidArgument(format!(
                "Invalid ciphertext chunk size: {}, expected range [{}, {}]",
                ciphertext_chunk.len(),
                GCM_NONCE_SIZE + GCM_TAG_SIZE,
                CHUNK_SIZE
            )));
        }
        let (chunk_nonce, ciphertext_and_tag) = ciphertext_chunk.split_at(GCM_NONCE_SIZE);
        let cipher = Aes256Gcm::new_from_slice(header.content_key()).expect("32-byte key");
        cipher
            .decrypt(
                &nonce(chunk_nonce),
                Payload {
                    msg: ciphertext_and_tag,
                    aad: &Self::aad(chunk_number, header),
                },
            )
            .map_err(|_| CoreError::AuthenticationFailed("Content tag mismatch.".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rng::DetRng;
    use data_encoding::HEXLOWER;
    use sha2::{Digest, Sha256};

    // cryptolib 2.2.2 v2.CryptorImpl(masterkey 00..3f, DetRandom): header create() draws 12-byte nonce (a0..ab)
    // then 32-byte content key (ac..cb); each encryptChunk draws a fresh 12-byte nonce.
    const ENC_HEADER: &str = "a0a1a2a3a4a5a6a7a8a9aaab19e783d2ba34fd40cec8297cb7cb726dc419efa72a0ef8d720b39839bf6ab7c216b3813867eb99f6a8d57bbc501ceb787b03fa91363626a6";
    const CHUNK0_HELLO_WORLD: &str =
        "cccdcecfd0d1d2d3d4d5d6d7f8dc799de0dfabbf41fe6f59efd689d8af72ab071b366dcabdff36";
    const CHUNK1_EMPTY: &str = "d8d9dadbdcdddedfa0a1a2a389d46c02b523fb8a3877bbf295d9547a";
    const CHUNK7_FULL_SHA256: &str =
        "d2455024dcaf35935ed35ef3bb040eb9c5d3b3492a415a4bfecbc9e6d8f8f93e";

    fn masterkey() -> Masterkey {
        let mut raw = [0u8; 64];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = i as u8;
        }
        Masterkey::from_raw(raw)
    }

    fn hex(s: &str) -> Vec<u8> {
        HEXLOWER.decode(s.as_bytes()).unwrap()
    }

    fn full_chunk() -> Vec<u8> {
        (0..PAYLOAD_SIZE).map(|i| (i * 7) as u8).collect()
    }

    #[test]
    fn created_header_uses_rng_for_nonce_and_content_key() {
        let hc = GcmHeaderCryptor::new(&masterkey());
        let header = hc.create(&mut DetRng::default());
        assert_eq!(header.nonce(), &hex("a0a1a2a3a4a5a6a7a8a9aaab")[..]);
        assert_eq!(header.content_key()[0], 0xac);
        assert_eq!(header.content_key()[31], 0xcb);
        assert_eq!(header.reserved(), -1);
        assert_eq!(hc.header_size(), 68);
    }

    #[test]
    fn encrypts_header_like_java() {
        let hc = GcmHeaderCryptor::new(&masterkey());
        let header = hc.create(&mut DetRng::default());
        assert_eq!(HEXLOWER.encode(&hc.encrypt_header(&header)), ENC_HEADER);
    }

    #[test]
    fn decrypts_java_header() {
        let hc = GcmHeaderCryptor::new(&masterkey());
        let header = hc.decrypt_header(&hex(ENC_HEADER)).unwrap();
        assert_eq!(header.nonce(), &hex("a0a1a2a3a4a5a6a7a8a9aaab")[..]);
        assert_eq!(header.content_key()[0], 0xac);
        assert_eq!(header.reserved(), -1);
    }

    #[test]
    fn tampered_header_fails_authentication() {
        let hc = GcmHeaderCryptor::new(&masterkey());
        let mut bytes = hex(ENC_HEADER);
        bytes[20] ^= 1;
        assert!(matches!(
            hc.decrypt_header(&bytes),
            Err(CoreError::AuthenticationFailed(_))
        ));
        assert!(matches!(
            hc.decrypt_header(&bytes[..67]),
            Err(CoreError::InvalidArgument(_))
        ));
    }

    #[test]
    fn encrypts_chunks_like_java() {
        let hc = GcmHeaderCryptor::new(&masterkey());
        let mut rng = DetRng::default();
        let header = hc.create(&mut rng);
        let cc = GcmContentCryptor;
        assert_eq!(
            HEXLOWER.encode(&cc.encrypt_chunk(b"hello world", 0, &header, &mut rng)),
            CHUNK0_HELLO_WORLD
        );
        assert_eq!(
            HEXLOWER.encode(&cc.encrypt_chunk(b"", 1, &header, &mut rng)),
            CHUNK1_EMPTY
        );
        let chunk7 = cc.encrypt_chunk(&full_chunk(), 7, &header, &mut rng);
        assert_eq!(chunk7.len(), CHUNK_SIZE);
        assert_eq!(
            HEXLOWER.encode(&Sha256::digest(&chunk7)),
            CHUNK7_FULL_SHA256
        );
    }

    #[test]
    fn decrypts_java_chunks() {
        let hc = GcmHeaderCryptor::new(&masterkey());
        let header = hc.decrypt_header(&hex(ENC_HEADER)).unwrap();
        let cc = GcmContentCryptor;
        assert_eq!(
            cc.decrypt_chunk(&hex(CHUNK0_HELLO_WORLD), 0, &header)
                .unwrap(),
            b"hello world"
        );
        assert_eq!(
            cc.decrypt_chunk(&hex(CHUNK1_EMPTY), 1, &header).unwrap(),
            b""
        );
    }

    #[test]
    fn wrong_chunk_number_or_tampering_fails_authentication() {
        let hc = GcmHeaderCryptor::new(&masterkey());
        let header = hc.decrypt_header(&hex(ENC_HEADER)).unwrap();
        let cc = GcmContentCryptor;
        assert!(matches!(
            cc.decrypt_chunk(&hex(CHUNK0_HELLO_WORLD), 1, &header),
            Err(CoreError::AuthenticationFailed(_))
        ));
        let mut tampered = hex(CHUNK0_HELLO_WORLD);
        tampered[15] ^= 1;
        assert!(matches!(
            cc.decrypt_chunk(&tampered, 0, &header),
            Err(CoreError::AuthenticationFailed(_))
        ));
        assert!(matches!(
            cc.decrypt_chunk(&[0u8; 27], 0, &header),
            Err(CoreError::InvalidArgument(_))
        ));
    }

    #[test]
    fn full_chunk_round_trips() {
        let hc = GcmHeaderCryptor::new(&masterkey());
        let mut rng = DetRng::default();
        let header = hc.create(&mut rng);
        let cc = GcmContentCryptor;
        let ct = cc.encrypt_chunk(&full_chunk(), 42, &header, &mut rng);
        assert_eq!(cc.decrypt_chunk(&ct, 42, &header).unwrap(), full_chunk());
    }
}
