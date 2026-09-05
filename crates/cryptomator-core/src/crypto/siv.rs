//! Filename encryption (`v2/FileNameCryptorImpl.java`, RFC 5297 AES-SIV via siv-mode).
//! cryptolib calls `siv.encrypt(encKey, macKey, ...)` where the first key is the CTR key and the
//! second the S2V key. RustCrypto expects `S2V key || CTR key`, hence the key is `macKey || encKey`.
use crate::crypto::masterkey::Masterkey;
use crate::error::{CoreError, Result};
use aes_siv::aead::KeyInit;
use aes_siv::siv::Aes256Siv;
use data_encoding::{BASE32, BASE64URL};
use sha1::{Digest, Sha1};
use zeroize::Zeroizing;

pub struct FileNameCryptor {
    /// `macKey || encKey`
    siv_key: Zeroizing<[u8; 64]>,
}

impl std::fmt::Debug for FileNameCryptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FileNameCryptor(<redacted>)")
    }
}

impl FileNameCryptor {
    pub fn new(masterkey: &Masterkey) -> Self {
        let mut siv_key = Zeroizing::new([0u8; 64]);
        siv_key[..32].copy_from_slice(masterkey.mac_key());
        siv_key[32..].copy_from_slice(masterkey.enc_key());
        Self { siv_key }
    }

    fn siv(&self) -> Aes256Siv {
        Aes256Siv::new((&*self.siv_key).into())
    }

    /// `BASE32(SHA1(AES-SIV(dirId)))` – the ciphertext directory name; root uses `""`.
    pub fn hash_directory_id(&self, cleartext_directory_id: &str) -> String {
        let encrypted = self
            .siv()
            .encrypt(
                std::iter::empty::<&[u8]>(),
                cleartext_directory_id.as_bytes(),
            )
            .expect("directory id fits in memory");
        BASE32.encode(&Sha1::digest(&encrypted))
    }

    pub fn encrypt_filename(&self, cleartext_name: &str, associated_data: &[&[u8]]) -> String {
        let encrypted = self
            .siv()
            .encrypt(associated_data.iter().copied(), cleartext_name.as_bytes())
            .expect("file name fits in memory");
        BASE64URL.encode(&encrypted)
    }

    pub fn decrypt_filename(
        &self,
        ciphertext_name: &str,
        associated_data: &[&[u8]],
    ) -> Result<String> {
        let encrypted = BASE64URL
            .decode(ciphertext_name.as_bytes())
            .map_err(|_| CoreError::AuthenticationFailed("Invalid Ciphertext.".into()))?;
        let cleartext = self
            .siv()
            .decrypt(associated_data.iter().copied(), &encrypted)
            .map_err(|_| CoreError::AuthenticationFailed("Invalid Ciphertext.".into()))?;
        String::from_utf8(cleartext)
            .map_err(|_| CoreError::AuthenticationFailed("Invalid Ciphertext.".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIR_ID: &str = "2f3a8f2e-0b8a-4e6f-9c5d-1a2b3c4d5e6f";

    fn cryptor() -> FileNameCryptor {
        let mut raw = [0u8; 64];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = i as u8;
        }
        FileNameCryptor::new(&Masterkey::from_raw(raw))
    }

    // Vectors from cryptolib 2.2.2 FileNameCryptorImpl (identical for SIV_CTRMAC and SIV_GCM).
    #[test]
    fn hashes_root_directory_id() {
        assert_eq!(
            cryptor().hash_directory_id(""),
            "MN53XCQH5RFQJPKAFCMWDGELQHPPW2YQ"
        );
    }

    #[test]
    fn hashes_uuid_directory_id() {
        assert_eq!(
            cryptor().hash_directory_id(DIR_ID),
            "CMKXWDS23EJDGI6W6QGYTCABGFDYURNB"
        );
    }

    #[test]
    fn encrypts_filename_in_root_directory() {
        assert_eq!(
            cryptor().encrypt_filename("hello.txt", &[b""]),
            "9ovGh03FYi0-jGCbRkIA80k29tJKo9BfgA=="
        );
    }

    #[test]
    fn encrypts_unicode_filename_with_directory_id_as_associated_data() {
        assert_eq!(
            cryptor().encrypt_filename("Grüße 🚀.txt", &[DIR_ID.as_bytes()]),
            "ATbLUpvuQpUbOMmcUnUNBnNuMYP-j40I9efry_VkIiU="
        );
    }

    #[test]
    fn decrypts_filenames() {
        let c = cryptor();
        assert_eq!(
            c.decrypt_filename("9ovGh03FYi0-jGCbRkIA80k29tJKo9BfgA==", &[b""])
                .unwrap(),
            "hello.txt"
        );
        assert_eq!(
            c.decrypt_filename(
                "ATbLUpvuQpUbOMmcUnUNBnNuMYP-j40I9efry_VkIiU=",
                &[DIR_ID.as_bytes()]
            )
            .unwrap(),
            "Grüße 🚀.txt"
        );
    }

    #[test]
    fn wrong_associated_data_fails_authentication() {
        let c = cryptor();
        assert!(matches!(
            c.decrypt_filename("9ovGh03FYi0-jGCbRkIA80k29tJKo9BfgA==", &[DIR_ID.as_bytes()]),
            Err(CoreError::AuthenticationFailed(_))
        ));
    }

    #[test]
    fn invalid_base64_fails_authentication() {
        assert!(matches!(
            cryptor().decrypt_filename("not*base64", &[b""]),
            Err(CoreError::AuthenticationFailed(_))
        ));
    }

    #[test]
    fn encryption_is_deterministic_and_round_trips() {
        let c = cryptor();
        let name = "some file (1).pdf";
        let ct = c.encrypt_filename(name, &[DIR_ID.as_bytes()]);
        assert_eq!(ct, c.encrypt_filename(name, &[DIR_ID.as_bytes()]));
        assert_eq!(c.decrypt_filename(&ct, &[DIR_ID.as_bytes()]).unwrap(), name);
    }
}
