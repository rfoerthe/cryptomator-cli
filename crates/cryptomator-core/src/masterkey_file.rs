//! `masterkey.cryptomator` (`common/MasterkeyFile.java`, `common/MasterkeyFileAccess.java`).
use crate::crypto::kdf::scrypt_kek;
use crate::crypto::keywrap::{unwrap_key, wrap_key};
use crate::crypto::masterkey::Masterkey;
use crate::crypto::rng::Rng;
use crate::error::{CoreError, Result};
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::Path;

pub const DEFAULT_MASTERKEY_FILE_VERSION: u32 = 999;
pub const DEFAULT_SCRYPT_SALT_LENGTH: usize = 8;
pub const DEFAULT_SCRYPT_COST_PARAM: u32 = 1 << 15;
pub const DEFAULT_SCRYPT_BLOCK_SIZE: u32 = 8;

mod base64_bytes {
    use data_encoding::BASE64;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> std::result::Result<S::Ok, S::Error> {
        BASE64.encode(bytes).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        BASE64
            .decode(text.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

/// JSON schema of the masterkey file. Field order matches Gson's output so re-serialization is byte-identical.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MasterkeyFile {
    pub version: u32,
    #[serde(rename = "scryptSalt", with = "base64_bytes")]
    pub scrypt_salt: Vec<u8>,
    #[serde(rename = "scryptCostParam")]
    pub scrypt_cost_param: u32,
    #[serde(rename = "scryptBlockSize")]
    pub scrypt_block_size: u32,
    #[serde(rename = "primaryMasterKey", with = "base64_bytes")]
    pub primary_master_key: Vec<u8>,
    #[serde(rename = "hmacMasterKey", with = "base64_bytes")]
    pub hmac_master_key: Vec<u8>,
    #[serde(rename = "versionMac", with = "base64_bytes")]
    pub version_mac: Vec<u8>,
}

impl MasterkeyFile {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes)
            .map_err(|e| CoreError::InvalidMasterkeyFile(format!("unreadable JSON: {e}")))
    }

    /// Pretty-printed JSON, identical to Gson's `setPrettyPrinting()` output (2-space indent, no trailing newline).
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("MasterkeyFile serializes")
    }

    pub fn is_valid(&self) -> bool {
        self.version != 0
            && self.scrypt_cost_param > 1
            && self.scrypt_block_size > 0
            && !self.primary_master_key.is_empty()
            && !self.hmac_master_key.is_empty()
            && !self.version_mac.is_empty()
    }
}

#[derive(Clone)]
pub struct MasterkeyFileAccess {
    pepper: Vec<u8>,
}

/// The pepper is secret; never print it.
impl std::fmt::Debug for MasterkeyFileAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterkeyFileAccess { pepper: <redacted> }")
    }
}

impl MasterkeyFileAccess {
    pub fn new(pepper: Vec<u8>) -> Self {
        Self { pepper }
    }

    pub fn read_alleged_vault_version(bytes: &[u8]) -> Result<u32> {
        Ok(MasterkeyFile::parse(bytes)?.version)
    }

    pub fn load(&self, path: &Path, passphrase: &str) -> Result<Masterkey> {
        let bytes = std::fs::read(path)?;
        self.load_bytes(&bytes, passphrase)
    }

    pub fn load_bytes(&self, bytes: &[u8], passphrase: &str) -> Result<Masterkey> {
        let file = MasterkeyFile::parse(bytes)?;
        if !file.is_valid() {
            return Err(CoreError::InvalidMasterkeyFile("invalid key file".into()));
        }
        self.unlock(&file, passphrase)
    }

    /// Note that `versionMac` is not checked here: cryptolib 2.x writes it for compatibility with
    /// pre-format-8 readers only and moved integrity protection of the vault version to the signed
    /// vault config, so an unlock succeeds regardless of the stored MAC.
    pub fn unlock(&self, file: &MasterkeyFile, passphrase: &str) -> Result<Masterkey> {
        let kek = scrypt_kek(
            passphrase,
            &file.scrypt_salt,
            &self.pepper,
            file.scrypt_cost_param,
            file.scrypt_block_size,
        )?;
        let enc_key =
            unwrap_key(&kek, &file.primary_master_key).map_err(|_| CoreError::InvalidPassphrase)?;
        let mac_key =
            unwrap_key(&kek, &file.hmac_master_key).map_err(|_| CoreError::InvalidPassphrase)?;
        Ok(Masterkey::from_parts(&enc_key, &mac_key))
    }

    /// Writes `versionMac` (HMAC-SHA256 of the big-endian vault version under the MAC key) purely for
    /// legacy compatibility; it is not verified on [`unlock`](Self::unlock) (cryptolib 2.x behaviour —
    /// integrity of the version moved to the signed vault config).
    pub fn lock(
        &self,
        masterkey: &Masterkey,
        passphrase: &str,
        vault_version: u32,
        cost_param: u32,
        rng: &mut dyn Rng,
    ) -> Result<MasterkeyFile> {
        let mut salt = vec![0u8; DEFAULT_SCRYPT_SALT_LENGTH];
        rng.fill(&mut salt);
        let kek = scrypt_kek(
            passphrase,
            &salt,
            &self.pepper,
            cost_param,
            DEFAULT_SCRYPT_BLOCK_SIZE,
        )?;
        let mut mac = Hmac::<Sha256>::new_from_slice(masterkey.mac_key())
            .expect("HMAC accepts any key length");
        mac.update(&vault_version.to_be_bytes());
        let version_mac = mac.finalize().into_bytes().to_vec();
        Ok(MasterkeyFile {
            version: vault_version,
            scrypt_salt: salt,
            scrypt_cost_param: cost_param,
            scrypt_block_size: DEFAULT_SCRYPT_BLOCK_SIZE,
            primary_master_key: wrap_key(&kek, masterkey.enc_key()).to_vec(),
            hmac_master_key: wrap_key(&kek, masterkey.mac_key()).to_vec(),
            version_mac,
        })
    }

    pub fn persist_bytes(
        &self,
        masterkey: &Masterkey,
        passphrase: &str,
        vault_version: u32,
        cost_param: u32,
        rng: &mut dyn Rng,
    ) -> Result<Vec<u8>> {
        Ok(self
            .lock(masterkey, passphrase, vault_version, cost_param, rng)?
            .to_json()
            .into_bytes())
    }

    /// Writes `<path>.tmp` (must not exist) and atomically renames it over `path`.
    pub fn persist(
        &self,
        masterkey: &Masterkey,
        path: &Path,
        passphrase: &str,
        vault_version: u32,
        rng: &mut dyn Rng,
    ) -> Result<()> {
        let bytes = self.persist_bytes(
            masterkey,
            passphrase,
            vault_version,
            DEFAULT_SCRYPT_COST_PARAM,
            rng,
        )?;
        let file_name = path.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
            CoreError::InvalidArgument(format!("not a file path: {}", path.display()))
        })?;
        let tmp_path = path.with_file_name(format!("{file_name}.tmp"));
        {
            use std::io::Write;
            let mut tmp = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp_path)?;
            tmp.write_all(&bytes)?;
            tmp.sync_all()?;
        }
        std::fs::rename(&tmp_path, path)?;
        Ok(())
    }

    pub fn change_passphrase(
        &self,
        bytes: &[u8],
        old_passphrase: &str,
        new_passphrase: &str,
        rng: &mut dyn Rng,
    ) -> Result<Vec<u8>> {
        let original = MasterkeyFile::parse(bytes)?;
        if !original.is_valid() {
            return Err(CoreError::InvalidMasterkeyFile("invalid key file".into()));
        }
        let key = self.unlock(&original, old_passphrase)?;
        let updated = self.lock(
            &key,
            new_passphrase,
            original.version,
            original.scrypt_cost_param,
            rng,
        )?;
        Ok(updated.to_json().into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rng::DetRng;

    const PASSPHRASE: &str = "test-password-123";

    /// Written by cryptolib 2.2.2 `MasterkeyFileAccess.persist(masterkey 00..3f, out, "test-password-123", 999, 1024)`
    /// with the deterministic RNG at counter 8 (salt a8..af).
    const JAVA_FILE_N1024: &str = "{\n  \"version\": 999,\n  \"scryptSalt\": \"qKmqq6ytrq8=\",\n  \"scryptCostParam\": 1024,\n  \"scryptBlockSize\": 8,\n  \"primaryMasterKey\": \"LA//cCFKBRjcCgISzMSIjL0Fn2YQATOR/IVnzFFkaOx24s0tLAXCEw==\",\n  \"hmacMasterKey\": \"E1kytsBb50pNsNR2Oh0a/bQFJ7fozm9WK571i2SfVKRw0m/p0cR9Ew==\",\n  \"versionMac\": \"te38NaywQwzDL8JpI/7fH4rBjoqfEz4JpdlYujCZlz8=\"\n}";

    /// Same masterkey and passphrase, default cost 32768, RNG at counter 0 (salt a0..a7).
    const JAVA_FILE_DEFAULT: &str = "{\n  \"version\": 999,\n  \"scryptSalt\": \"oKGio6Slpqc=\",\n  \"scryptCostParam\": 32768,\n  \"scryptBlockSize\": 8,\n  \"primaryMasterKey\": \"HF3Q2cbpzZVISNl7oZ7XSwt3RAIcWNXco3Vs4LEJFqC1m0153R2tAQ==\",\n  \"hmacMasterKey\": \"kWEWMRWW1WZb43j0RF5AYFN9G43uDEo8Pq8xYmv8W3eU9x0SBpnu7A==\",\n  \"versionMac\": \"te38NaywQwzDL8JpI/7fH4rBjoqfEz4JpdlYujCZlz8=\"\n}";

    fn sequential_key() -> Masterkey {
        let mut raw = [0u8; 64];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = i as u8;
        }
        Masterkey::from_raw(raw)
    }

    #[test]
    fn parses_java_file() {
        let file = MasterkeyFile::parse(JAVA_FILE_N1024.as_bytes()).unwrap();
        assert_eq!(file.version, 999);
        assert_eq!(
            file.scrypt_salt,
            vec![0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf]
        );
        assert_eq!(file.scrypt_cost_param, 1024);
        assert_eq!(file.scrypt_block_size, 8);
        assert_eq!(file.primary_master_key.len(), 40);
        assert!(file.is_valid());
    }

    #[test]
    fn unlocks_java_file_with_correct_passphrase() {
        let access = MasterkeyFileAccess::new(Vec::new());
        let key = access
            .load_bytes(JAVA_FILE_N1024.as_bytes(), PASSPHRASE)
            .unwrap();
        assert_eq!(key.raw(), sequential_key().raw());
    }

    #[test]
    fn wrong_passphrase_is_reported_as_invalid_passphrase() {
        let access = MasterkeyFileAccess::new(Vec::new());
        assert!(matches!(
            access.load_bytes(JAVA_FILE_N1024.as_bytes(), "wrong"),
            Err(CoreError::InvalidPassphrase)
        ));
    }

    #[test]
    fn persist_bytes_is_byte_identical_to_java_output() {
        let access = MasterkeyFileAccess::new(Vec::new());
        let bytes = access
            .persist_bytes(
                &sequential_key(),
                PASSPHRASE,
                999,
                1024,
                &mut DetRng::starting_at(8),
            )
            .unwrap();
        assert_eq!(String::from_utf8(bytes).unwrap(), JAVA_FILE_N1024);
    }

    #[test]
    fn persist_with_default_cost_matches_java() {
        let access = MasterkeyFileAccess::new(Vec::new());
        let bytes = access
            .persist_bytes(
                &sequential_key(),
                PASSPHRASE,
                DEFAULT_MASTERKEY_FILE_VERSION,
                DEFAULT_SCRYPT_COST_PARAM,
                &mut DetRng::default(),
            )
            .unwrap();
        assert_eq!(String::from_utf8(bytes).unwrap(), JAVA_FILE_DEFAULT);
    }

    #[test]
    fn debug_does_not_print_the_pepper() {
        let rendered = format!("{:?}", MasterkeyFileAccess::new(b"s3cr3t-pepper".to_vec()));
        assert_eq!(rendered, "MasterkeyFileAccess { pepper: <redacted> }");
        assert!(!rendered.contains("s3cr3t"));
    }

    #[test]
    fn read_alleged_vault_version_reads_version_field() {
        assert_eq!(
            MasterkeyFileAccess::read_alleged_vault_version(JAVA_FILE_N1024.as_bytes()).unwrap(),
            999
        );
    }

    #[test]
    fn invalid_json_is_invalid_masterkey_file() {
        assert!(matches!(
            MasterkeyFile::parse(b"{\"version\": 7}"),
            Err(CoreError::InvalidMasterkeyFile(_))
        ));
        assert!(matches!(
            MasterkeyFile::parse(b"not json"),
            Err(CoreError::InvalidMasterkeyFile(_))
        ));
    }

    #[test]
    fn change_passphrase_keeps_key_version_and_cost() {
        let access = MasterkeyFileAccess::new(Vec::new());
        let changed = access
            .change_passphrase(
                JAVA_FILE_N1024.as_bytes(),
                PASSPHRASE,
                "new-pass",
                &mut DetRng::default(),
            )
            .unwrap();
        let file = MasterkeyFile::parse(&changed).unwrap();
        assert_eq!(file.scrypt_cost_param, 1024);
        assert_eq!(file.version, 999);
        assert_eq!(
            access.load_bytes(&changed, "new-pass").unwrap().raw(),
            sequential_key().raw()
        );
        assert!(matches!(
            access.load_bytes(&changed, PASSPHRASE),
            Err(CoreError::InvalidPassphrase)
        ));
    }

    #[test]
    fn persist_writes_via_tmp_file_and_replaces_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("masterkey.cryptomator");
        std::fs::write(&path, b"old").unwrap();
        let access = MasterkeyFileAccess::new(Vec::new());
        access
            .persist(
                &sequential_key(),
                &path,
                PASSPHRASE,
                999,
                &mut DetRng::default(),
            )
            .unwrap();
        assert!(!dir.path().join("masterkey.cryptomator.tmp").exists());
        let key = access.load(&path, PASSPHRASE).unwrap();
        assert_eq!(key.raw(), sequential_key().raw());
    }
}
