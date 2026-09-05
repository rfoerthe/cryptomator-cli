//! SIV_CTRMAC content encryption (`v1/FileHeaderCryptorImpl.java`, `v1/FileContentCryptorImpl.java`, `v1/Constants.java`).
//! AES-CTR with a big-endian 128-bit counter (JCE "AES/CTR/NoPadding") + HMAC-SHA256 with the masterkey's MAC key.
use crate::crypto::header::{FileHeader, CONTENT_KEY_LEN, PAYLOAD_LEN};
use crate::crypto::masterkey::Masterkey;
use crate::crypto::rng::Rng;
use crate::error::{CoreError, Result};
use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

pub const NONCE_SIZE: usize = 16;
pub const PAYLOAD_SIZE: usize = 32 * 1024;
pub const MAC_SIZE: usize = 32;
pub const CHUNK_SIZE: usize = NONCE_SIZE + PAYLOAD_SIZE + MAC_SIZE;
pub const HEADER_SIZE: usize = NONCE_SIZE + PAYLOAD_LEN + MAC_SIZE;

type Aes256Ctr = ctr::Ctr128BE<Aes256>;
type HmacSha256 = Hmac<Sha256>;

fn apply_ctr(key: &[u8; 32], iv: &[u8], data: &mut [u8]) {
    let mut cipher = Aes256Ctr::new_from_slices(key, iv).expect("32-byte key, 16-byte IV");
    cipher.apply_keystream(data);
}

fn hmac(mac_key: &[u8; 32]) -> HmacSha256 {
    HmacSha256::new_from_slice(mac_key).expect("HMAC accepts any key length")
}

pub struct CtrMacHeaderCryptor {
    enc_key: Zeroizing<[u8; 32]>,
    mac_key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for CtrMacHeaderCryptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CtrMacHeaderCryptor(<redacted>)")
    }
}

impl CtrMacHeaderCryptor {
    pub fn new(masterkey: &Masterkey) -> Self {
        Self {
            enc_key: Zeroizing::new(*masterkey.enc_key()),
            mac_key: Zeroizing::new(*masterkey.mac_key()),
        }
    }

    pub fn create(&self, rng: &mut dyn Rng) -> FileHeader {
        let mut nonce = vec![0u8; NONCE_SIZE];
        rng.fill(&mut nonce);
        let mut content_key = [0u8; CONTENT_KEY_LEN];
        rng.fill(&mut content_key);
        FileHeader::new(nonce, -1, content_key)
    }

    pub fn header_size(&self) -> usize {
        HEADER_SIZE
    }

    /// `nonce || AES-CTR(encKey, iv=nonce)(payload) || HMAC-SHA256(macKey, nonce || encryptedPayload)`
    pub fn encrypt_header(&self, header: &FileHeader) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_SIZE);
        out.extend_from_slice(header.nonce());
        let mut payload = header.encode_payload();
        apply_ctr(&self.enc_key, header.nonce(), payload.as_mut());
        out.extend_from_slice(&*payload);
        let mut mac = hmac(&self.mac_key);
        mac.update(&out);
        out.extend_from_slice(&mac.finalize().into_bytes());
        out
    }

    pub fn decrypt_header(&self, ciphertext_header: &[u8]) -> Result<FileHeader> {
        if ciphertext_header.len() < HEADER_SIZE {
            return Err(CoreError::InvalidArgument(
                "Malformed ciphertext header".into(),
            ));
        }
        let nonce_and_payload = &ciphertext_header[..NONCE_SIZE + PAYLOAD_LEN];
        let expected_mac = &ciphertext_header[NONCE_SIZE + PAYLOAD_LEN..HEADER_SIZE];
        let mut mac = hmac(&self.mac_key);
        mac.update(nonce_and_payload);
        mac.verify_slice(expected_mac)
            .map_err(|_| CoreError::AuthenticationFailed("Header MAC doesn't match.".into()))?;
        let nonce = &ciphertext_header[..NONCE_SIZE];
        let mut payload =
            Zeroizing::new(ciphertext_header[NONCE_SIZE..NONCE_SIZE + PAYLOAD_LEN].to_vec());
        apply_ctr(&self.enc_key, nonce, payload.as_mut_slice());
        FileHeader::decode_payload(nonce.to_vec(), &payload)
    }
}

pub struct CtrMacContentCryptor {
    mac_key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for CtrMacContentCryptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CtrMacContentCryptor(<redacted>)")
    }
}

impl CtrMacContentCryptor {
    pub fn new(masterkey: &Masterkey) -> Self {
        Self {
            mac_key: Zeroizing::new(*masterkey.mac_key()),
        }
    }

    pub fn cleartext_chunk_size(&self) -> usize {
        PAYLOAD_SIZE
    }

    pub fn ciphertext_chunk_size(&self) -> usize {
        CHUNK_SIZE
    }

    /// `HMAC-SHA256(macKey, headerNonce || BE64(chunkNumber) || chunkNonce || ciphertext)`
    fn chunk_mac(
        &self,
        header_nonce: &[u8],
        chunk_number: u64,
        nonce_and_ciphertext: &[u8],
    ) -> HmacSha256 {
        let mut mac = hmac(&self.mac_key);
        mac.update(header_nonce);
        mac.update(&chunk_number.to_be_bytes());
        mac.update(nonce_and_ciphertext);
        mac
    }

    /// `nonce || AES-CTR(contentKey, iv=nonce)(cleartext) || chunkMac`
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
        let mut out = Vec::with_capacity(NONCE_SIZE + cleartext_chunk.len() + MAC_SIZE);
        let mut chunk_nonce = [0u8; NONCE_SIZE];
        rng.fill(&mut chunk_nonce);
        out.extend_from_slice(&chunk_nonce);
        let mut ciphertext = cleartext_chunk.to_vec();
        apply_ctr(header.content_key(), &chunk_nonce, &mut ciphertext);
        out.extend_from_slice(&ciphertext);
        let mac = self.chunk_mac(header.nonce(), chunk_number, &out);
        out.extend_from_slice(&mac.finalize().into_bytes());
        out
    }

    pub fn decrypt_chunk(
        &self,
        ciphertext_chunk: &[u8],
        chunk_number: u64,
        header: &FileHeader,
    ) -> Result<Vec<u8>> {
        if ciphertext_chunk.len() < NONCE_SIZE + MAC_SIZE || ciphertext_chunk.len() > CHUNK_SIZE {
            return Err(CoreError::InvalidArgument(format!(
                "Invalid ciphertext chunk size: {}, expected range [{}, {}]",
                ciphertext_chunk.len(),
                NONCE_SIZE + MAC_SIZE,
                CHUNK_SIZE
            )));
        }
        let (nonce_and_ciphertext, expected_mac) =
            ciphertext_chunk.split_at(ciphertext_chunk.len() - MAC_SIZE);
        self.chunk_mac(header.nonce(), chunk_number, nonce_and_ciphertext)
            .verify_slice(expected_mac)
            .map_err(|_| {
                CoreError::AuthenticationFailed(format!(
                    "Authentication of chunk {chunk_number} failed."
                ))
            })?;
        let (chunk_nonce, ciphertext) = nonce_and_ciphertext.split_at(NONCE_SIZE);
        let mut cleartext = ciphertext.to_vec();
        apply_ctr(header.content_key(), chunk_nonce, &mut cleartext);
        Ok(cleartext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rng::DetRng;
    use data_encoding::HEXLOWER;
    use sha2::{Digest, Sha256};

    // cryptolib 2.2.2 v1.CryptorImpl(masterkey 00..3f, DetRandom): header nonce a0..af, content key b0..cf,
    // chunk 0 nonce d0..df, chunk 1 nonce a0..af (counter wrapped at 64).
    const ENC_HEADER: &str = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf2360fe02894783f2bffa5a36bfbe5a57596851aac0fc2b972c4b3a49a3f5155851222e6924aa57c5a12c9850de5595b2e1a07a8fb733a48864582784ef3c2c0dd39f245236529acc";
    const CHUNK0_HELLO_WORLD: &str = "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf07bc829afb3ef90b0c483749798b267733ee79939d12d6ddf38ca30e7d6008344a2e2bb3cd8289df268ad4";
    const CHUNK1_EMPTY: &str = "a0a1a2a3a4a5a6a7a8a9aaabacadaeafbce25e58d844216c94d19cc661b42e587eb94d34f0308748c7ba61dffc6b4f34";
    const CHUNK7_FULL_SHA256: &str =
        "e65c9046e7ff61828986c3d8e47e17cbc7dd623677ee89bfd150cc9a304100fb";

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
    fn encrypts_header_like_java() {
        let hc = CtrMacHeaderCryptor::new(&masterkey());
        let header = hc.create(&mut DetRng::default());
        assert_eq!(header.nonce().len(), 16);
        assert_eq!(hc.header_size(), 88);
        assert_eq!(HEXLOWER.encode(&hc.encrypt_header(&header)), ENC_HEADER);
    }

    #[test]
    fn decrypts_java_header() {
        let hc = CtrMacHeaderCryptor::new(&masterkey());
        let header = hc.decrypt_header(&hex(ENC_HEADER)).unwrap();
        assert_eq!(header.nonce(), &hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")[..]);
        assert_eq!(header.content_key()[0], 0xb0);
        assert_eq!(header.content_key()[31], 0xcf);
        assert_eq!(header.reserved(), -1);
    }

    #[test]
    fn tampered_header_fails_authentication() {
        let hc = CtrMacHeaderCryptor::new(&masterkey());
        let mut bytes = hex(ENC_HEADER);
        bytes[30] ^= 1;
        assert!(matches!(
            hc.decrypt_header(&bytes),
            Err(CoreError::AuthenticationFailed(_))
        ));
        assert!(matches!(
            hc.decrypt_header(&bytes[..87]),
            Err(CoreError::InvalidArgument(_))
        ));
    }

    #[test]
    fn encrypts_chunks_like_java() {
        let hc = CtrMacHeaderCryptor::new(&masterkey());
        let mut rng = DetRng::default();
        let header = hc.create(&mut rng);
        let cc = CtrMacContentCryptor::new(&masterkey());
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
        let hc = CtrMacHeaderCryptor::new(&masterkey());
        let header = hc.decrypt_header(&hex(ENC_HEADER)).unwrap();
        let cc = CtrMacContentCryptor::new(&masterkey());
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
        let hc = CtrMacHeaderCryptor::new(&masterkey());
        let header = hc.decrypt_header(&hex(ENC_HEADER)).unwrap();
        let cc = CtrMacContentCryptor::new(&masterkey());
        assert!(matches!(
            cc.decrypt_chunk(&hex(CHUNK0_HELLO_WORLD), 1, &header),
            Err(CoreError::AuthenticationFailed(_))
        ));
        let mut tampered = hex(CHUNK0_HELLO_WORLD);
        tampered[20] ^= 1;
        assert!(matches!(
            cc.decrypt_chunk(&tampered, 0, &header),
            Err(CoreError::AuthenticationFailed(_))
        ));
        assert!(matches!(
            cc.decrypt_chunk(&[0u8; 47], 0, &header),
            Err(CoreError::InvalidArgument(_))
        ));
    }

    #[test]
    fn full_chunk_round_trips() {
        let hc = CtrMacHeaderCryptor::new(&masterkey());
        let mut rng = DetRng::default();
        let header = hc.create(&mut rng);
        let cc = CtrMacContentCryptor::new(&masterkey());
        let ct = cc.encrypt_chunk(&full_chunk(), 42, &header, &mut rng);
        assert_eq!(cc.decrypt_chunk(&ct, 42, &header).unwrap(), full_chunk());
    }
}
