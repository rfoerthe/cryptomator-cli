//! `vault.cryptomator` (`cryptofs/VaultConfig.java`): a JWT signed with HMAC over the raw 64-byte masterkey.
//! Implemented by hand (base64url header.payload.signature) to control claim order and the accepted algorithms.
use crate::constants::VAULT_VERSION;
use crate::crypto::cryptor::CipherCombo;
use crate::error::{CoreError, Result};
use data_encoding::BASE64URL_NOPAD;
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use serde_json::{json, Map, Value};
use sha2::{Sha256, Sha384, Sha512};

const CLAIM_FORMAT: &str = "format";
const CLAIM_CIPHER_COMBO: &str = "cipherCombo";
const CLAIM_SHORTENING_THRESHOLD: &str = "shorteningThreshold";
const CLAIM_ID: &str = "jti";
const HEADER_KEY_ID: &str = "kid";
const HEADER_ALGORITHM: &str = "alg";

/// `kid` header of the vault config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyId {
    /// `masterkeyfile:<file name>` – password based vault.
    MasterkeyFile {
        file_name: String,
    },
    /// `hub+http(s)://…` – Cryptomator Hub vault (unsupported by crypto).
    Hub {
        uri: String,
    },
    Other(String),
}

impl KeyId {
    pub fn parse(raw: &str) -> Self {
        if let Some(file_name) = raw.strip_prefix("masterkeyfile:") {
            KeyId::MasterkeyFile {
                file_name: file_name.to_string(),
            }
        } else if raw.starts_with("hub+http://") || raw.starts_with("hub+https://") {
            KeyId::Hub {
                uri: raw.to_string(),
            }
        } else {
            KeyId::Other(raw.to_string())
        }
    }

    /// Name of the masterkey file this vault is unlocked with, or the error that explains why this
    /// vault cannot be opened by `crypto` at all. Use this instead of matching on the variants, so
    /// every caller rejects Hub and unknown key ids the same way.
    pub fn require_masterkey_file(&self) -> Result<&str> {
        match self {
            KeyId::MasterkeyFile { file_name } => Ok(file_name),
            KeyId::Hub { uri } => Err(CoreError::HubVaultUnsupported(uri.clone())),
            KeyId::Other(raw) => Err(CoreError::UnsupportedKeyId(raw.clone())),
        }
    }
}

impl std::fmt::Display for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyId::MasterkeyFile { file_name } => write!(f, "masterkeyfile:{file_name}"),
            KeyId::Hub { uri } => f.write_str(uri),
            KeyId::Other(raw) => f.write_str(raw),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwtAlgorithm {
    Hs256,
    Hs384,
    Hs512,
}

impl JwtAlgorithm {
    fn name(&self) -> &'static str {
        match self {
            JwtAlgorithm::Hs256 => "HS256",
            JwtAlgorithm::Hs384 => "HS384",
            JwtAlgorithm::Hs512 => "HS512",
        }
    }

    fn from_name(name: &str) -> Result<Self> {
        match name {
            "HS256" => Ok(JwtAlgorithm::Hs256),
            "HS384" => Ok(JwtAlgorithm::Hs384),
            "HS512" => Ok(JwtAlgorithm::Hs512),
            other => Err(CoreError::VaultConfigLoad(format!(
                "Unsupported signature algorithm: {other}"
            ))),
        }
    }

    fn sign(&self, key: &[u8], signing_input: &[u8]) -> Vec<u8> {
        match self {
            JwtAlgorithm::Hs256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("any key length");
                mac.update(signing_input);
                mac.finalize().into_bytes().to_vec()
            }
            JwtAlgorithm::Hs384 => {
                let mut mac = Hmac::<Sha384>::new_from_slice(key).expect("any key length");
                mac.update(signing_input);
                mac.finalize().into_bytes().to_vec()
            }
            JwtAlgorithm::Hs512 => {
                let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("any key length");
                mac.update(signing_input);
                mac.finalize().into_bytes().to_vec()
            }
        }
    }

    fn verify(&self, key: &[u8], signing_input: &[u8], signature: &[u8]) -> bool {
        match self {
            JwtAlgorithm::Hs256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("any key length");
                mac.update(signing_input);
                mac.verify_slice(signature).is_ok()
            }
            JwtAlgorithm::Hs384 => {
                let mut mac = Hmac::<Sha384>::new_from_slice(key).expect("any key length");
                mac.update(signing_input);
                mac.verify_slice(signature).is_ok()
            }
            JwtAlgorithm::Hs512 => {
                let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("any key length");
                mac.update(signing_input);
                mac.verify_slice(signature).is_ok()
            }
        }
    }
}

/// Decoded but not yet signature-checked vault config.
#[derive(Debug, Clone)]
pub struct UnverifiedVaultConfig {
    token: String,
    signing_input_len: usize,
    header: Map<String, Value>,
    claims: Map<String, Value>,
    signature: Vec<u8>,
}

impl UnverifiedVaultConfig {
    pub fn decode(token: &str) -> Result<Self> {
        let load_err = || CoreError::VaultConfigLoad(format!("Failed to parse config: {token}"));
        let mut parts = token.split('.');
        let (header_b64, claims_b64, signature_b64) =
            match (parts.next(), parts.next(), parts.next(), parts.next()) {
                (Some(h), Some(c), Some(s), None) => (h, c, s),
                _ => return Err(load_err()),
            };
        let decode_json = |part: &str| -> Result<Map<String, Value>> {
            let bytes = BASE64URL_NOPAD
                .decode(part.as_bytes())
                .map_err(|_| load_err())?;
            match serde_json::from_slice::<Value>(&bytes).map_err(|_| load_err())? {
                Value::Object(map) => Ok(map),
                _ => Err(load_err()),
            }
        };
        let header = decode_json(header_b64)?;
        let claims = decode_json(claims_b64)?;
        let signature = BASE64URL_NOPAD
            .decode(signature_b64.as_bytes())
            .map_err(|_| load_err())?;
        Ok(Self {
            token: token.to_string(),
            signing_input_len: header_b64.len() + 1 + claims_b64.len(),
            header,
            claims,
            signature,
        })
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    pub fn header_value(&self, key: &str) -> Option<&Value> {
        self.header.get(key)
    }

    pub fn key_id(&self) -> Result<KeyId> {
        self.header
            .get(HEADER_KEY_ID)
            .and_then(Value::as_str)
            .map(KeyId::parse)
            .ok_or_else(|| CoreError::VaultConfigLoad("vault config has no key id".into()))
    }

    pub fn algorithm(&self) -> Result<JwtAlgorithm> {
        let name = self
            .header
            .get(HEADER_ALGORITHM)
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CoreError::VaultConfigLoad("vault config has no signature algorithm".into())
            })?;
        JwtAlgorithm::from_name(name)
    }

    pub fn alleged_vault_version(&self) -> Option<u32> {
        self.claims
            .get(CLAIM_FORMAT)
            .and_then(Value::as_u64)
            .map(|v| v as u32)
    }

    pub fn alleged_shortening_threshold(&self) -> Option<u32> {
        self.claims
            .get(CLAIM_SHORTENING_THRESHOLD)
            .and_then(Value::as_u64)
            .map(|v| v as u32)
    }

    /// Checks the signature with the raw masterkey, then the `format` claim, then parses the remaining claims.
    pub fn verify(&self, raw_key: &[u8; 64], expected_vault_version: u32) -> Result<VaultConfig> {
        let algorithm = self.algorithm()?;
        let signing_input = &self.token.as_bytes()[..self.signing_input_len];
        if !algorithm.verify(raw_key, signing_input, &self.signature) {
            return Err(CoreError::VaultKeyInvalid);
        }
        let actual = self.alleged_vault_version().ok_or_else(|| {
            CoreError::VaultConfigLoad(format!("Failed to verify vault config: {}", self.token))
        })?;
        if actual != expected_vault_version {
            return Err(CoreError::VaultVersionMismatch {
                expected: expected_vault_version,
                actual,
            });
        }
        let load_err =
            || CoreError::VaultConfigLoad(format!("Failed to verify vault config: {}", self.token));
        let id = self
            .claims
            .get(CLAIM_ID)
            .and_then(Value::as_str)
            .ok_or_else(load_err)?
            .to_string();
        let cipher_combo = self
            .claims
            .get(CLAIM_CIPHER_COMBO)
            .and_then(Value::as_str)
            .ok_or_else(load_err)?
            .parse::<CipherCombo>()
            .map_err(|_| load_err())?;
        let shortening_threshold = self.alleged_shortening_threshold().ok_or_else(load_err)?;
        Ok(VaultConfig {
            id,
            vault_version: actual,
            cipher_combo,
            shortening_threshold,
        })
    }
}

/// Verified vault configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultConfig {
    pub id: String,
    pub vault_version: u32,
    pub cipher_combo: CipherCombo,
    pub shortening_threshold: u32,
}

impl VaultConfig {
    pub fn create_new(cipher_combo: CipherCombo, shortening_threshold: u32) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            vault_version: VAULT_VERSION,
            cipher_combo,
            shortening_threshold,
        }
    }

    /// HS256 token exactly like `VaultConfig.toToken` (java-jwt claim order: kid, alg, typ / jti, format, cipherCombo, shorteningThreshold).
    pub fn to_token(&self, key_id: &str, raw_key: &[u8; 64]) -> String {
        self.to_token_with_algorithm(key_id, raw_key, JwtAlgorithm::Hs256)
    }

    pub fn to_token_with_algorithm(
        &self,
        key_id: &str,
        raw_key: &[u8; 64],
        algorithm: JwtAlgorithm,
    ) -> String {
        let header = json!({ "kid": key_id, "alg": algorithm.name(), "typ": "JWT" });
        let claims = json!({
            "jti": self.id,
            "format": self.vault_version,
            "cipherCombo": self.cipher_combo.as_str(),
            "shorteningThreshold": self.shortening_threshold,
        });
        let header_b64 = BASE64URL_NOPAD.encode(header.to_string().as_bytes());
        let claims_b64 = BASE64URL_NOPAD.encode(claims.to_string().as_bytes());
        let signing_input = format!("{header_b64}.{claims_b64}");
        let signature = algorithm.sign(raw_key, signing_input.as_bytes());
        format!("{signing_input}.{}", BASE64URL_NOPAD.encode(&signature))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // cryptofs 2.10.0: VaultConfig.createNew().cipherCombo(SIV_GCM).shorteningThreshold(220).build().toToken("masterkeyfile:masterkey.cryptomator", key 00..3f)
    const TOKEN: &str = "eyJraWQiOiJtYXN0ZXJrZXlmaWxlOm1hc3RlcmtleS5jcnlwdG9tYXRvciIsImFsZyI6IkhTMjU2IiwidHlwIjoiSldUIn0.eyJqdGkiOiI1YmMwMzg0Yi0xNGFjLTRmZGMtYWVkMC02MmU3YmMwOGZkNWEiLCJmb3JtYXQiOjgsImNpcGhlckNvbWJvIjoiU0lWX0dDTSIsInNob3J0ZW5pbmdUaHJlc2hvbGQiOjIyMH0.0DdfRRefLZici0eI0jDe6lS4sU7H8ZGp9eTqESy29Cg";
    const ID: &str = "5bc0384b-14ac-4fdc-aed0-62e7bc08fd5a";

    fn raw_key() -> [u8; 64] {
        let mut raw = [0u8; 64];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = i as u8;
        }
        raw
    }

    #[test]
    fn decodes_unverified_claims() {
        let cfg = UnverifiedVaultConfig::decode(TOKEN).unwrap();
        assert_eq!(
            cfg.key_id().unwrap(),
            KeyId::MasterkeyFile {
                file_name: "masterkey.cryptomator".into()
            }
        );
        assert_eq!(cfg.algorithm().unwrap(), JwtAlgorithm::Hs256);
        assert_eq!(cfg.alleged_vault_version(), Some(8));
        assert_eq!(cfg.alleged_shortening_threshold(), Some(220));
        assert!(cfg.header_value("hub").is_none());
        assert_eq!(cfg.token(), TOKEN);
    }

    #[test]
    fn verifies_with_correct_key() {
        let cfg = UnverifiedVaultConfig::decode(TOKEN)
            .unwrap()
            .verify(&raw_key(), 8)
            .unwrap();
        assert_eq!(cfg.id, ID);
        assert_eq!(cfg.vault_version, 8);
        assert_eq!(cfg.cipher_combo, CipherCombo::SivGcm);
        assert_eq!(cfg.shortening_threshold, 220);
    }

    #[test]
    fn wrong_key_is_vault_key_invalid() {
        let mut wrong = raw_key();
        wrong[0] ^= 1;
        assert!(matches!(
            UnverifiedVaultConfig::decode(TOKEN)
                .unwrap()
                .verify(&wrong, 8),
            Err(CoreError::VaultKeyInvalid)
        ));
    }

    #[test]
    fn wrong_expected_version_is_version_mismatch() {
        assert!(matches!(
            UnverifiedVaultConfig::decode(TOKEN)
                .unwrap()
                .verify(&raw_key(), 7),
            Err(CoreError::VaultVersionMismatch {
                expected: 7,
                actual: 8
            })
        ));
    }

    #[test]
    fn to_token_is_byte_identical_to_java() {
        let cfg = VaultConfig {
            id: ID.into(),
            vault_version: 8,
            cipher_combo: CipherCombo::SivGcm,
            shortening_threshold: 220,
        };
        assert_eq!(
            cfg.to_token("masterkeyfile:masterkey.cryptomator", &raw_key()),
            TOKEN
        );
    }

    #[test]
    fn create_new_round_trips() {
        let cfg = VaultConfig::create_new(CipherCombo::SivCtrMac, 36);
        assert_eq!(cfg.vault_version, 8);
        assert_eq!(cfg.id.len(), 36);
        let token = cfg.to_token("masterkeyfile:masterkey.cryptomator", &raw_key());
        let verified = UnverifiedVaultConfig::decode(&token)
            .unwrap()
            .verify(&raw_key(), 8)
            .unwrap();
        assert_eq!(verified, cfg);
    }

    #[test]
    fn hub_key_id_is_detected() {
        let cfg = VaultConfig {
            id: ID.into(),
            vault_version: 8,
            cipher_combo: CipherCombo::SivGcm,
            shortening_threshold: 220,
        };
        let token = cfg.to_token("hub+https://hub.example.com/api/vaults/123", &raw_key());
        let key_id = UnverifiedVaultConfig::decode(&token)
            .unwrap()
            .key_id()
            .unwrap();
        assert_eq!(
            key_id,
            KeyId::Hub {
                uri: "hub+https://hub.example.com/api/vaults/123".into()
            }
        );
        assert_eq!(
            key_id.to_string(),
            "hub+https://hub.example.com/api/vaults/123"
        );
        assert_eq!(
            KeyId::parse("hub+http://x/api/vaults/1"),
            KeyId::Hub {
                uri: "hub+http://x/api/vaults/1".into()
            }
        );
        assert_eq!(
            KeyId::parse("unknown:thing"),
            KeyId::Other("unknown:thing".into())
        );
    }

    #[test]
    fn require_masterkey_file_returns_the_file_name() {
        assert_eq!(
            KeyId::parse("masterkeyfile:masterkey.cryptomator")
                .require_masterkey_file()
                .unwrap(),
            "masterkey.cryptomator"
        );
    }

    #[test]
    fn require_masterkey_file_rejects_hub_vaults() {
        let err = KeyId::parse("hub+https://hub.example.com/api/vaults/123")
            .require_masterkey_file()
            .unwrap_err();
        assert!(matches!(err, CoreError::HubVaultUnsupported(ref uri)
            if uri == "hub+https://hub.example.com/api/vaults/123"));
        assert_eq!(
            err.to_string(),
            "Cryptomator Hub vaults are not supported (key id: hub+https://hub.example.com/api/vaults/123)"
        );
    }

    #[test]
    fn require_masterkey_file_rejects_unknown_key_ids() {
        let err = KeyId::parse("unknown:thing")
            .require_masterkey_file()
            .unwrap_err();
        assert!(matches!(err, CoreError::UnsupportedKeyId(ref raw) if raw == "unknown:thing"));
        assert_eq!(err.to_string(), "unsupported key id: unknown:thing");
    }

    #[test]
    fn garbage_is_vault_config_load_error() {
        assert!(matches!(
            UnverifiedVaultConfig::decode("not.a.jwt"),
            Err(CoreError::VaultConfigLoad(_))
        ));
        assert!(matches!(
            UnverifiedVaultConfig::decode("onlyonepart"),
            Err(CoreError::VaultConfigLoad(_))
        ));
    }

    #[test]
    fn accepts_hs512_signatures() {
        let cfg = VaultConfig {
            id: ID.into(),
            vault_version: 8,
            cipher_combo: CipherCombo::SivGcm,
            shortening_threshold: 220,
        };
        let token = cfg.to_token_with_algorithm(
            "masterkeyfile:masterkey.cryptomator",
            &raw_key(),
            JwtAlgorithm::Hs512,
        );
        let unverified = UnverifiedVaultConfig::decode(&token).unwrap();
        assert_eq!(unverified.algorithm().unwrap(), JwtAlgorithm::Hs512);
        assert_eq!(unverified.verify(&raw_key(), 8).unwrap(), cfg);
    }

    /// Splices a forged header (raw JSON) and a signature segment onto the valid `TOKEN`'s claims.
    fn token_with_header(header_json: &str, signature_b64: &str) -> String {
        let claims_b64 = TOKEN.split('.').nth(1).expect("claims segment");
        let header_b64 = BASE64URL_NOPAD.encode(header_json.as_bytes());
        format!("{header_b64}.{claims_b64}.{signature_b64}")
    }

    /// The real HS256 signature segment of `TOKEN`.
    fn valid_signature_segment() -> &'static str {
        TOKEN.split('.').nth(2).expect("signature segment")
    }

    #[test]
    fn alg_none_is_rejected_before_signature_check() {
        let token = token_with_header(
            r#"{"kid":"masterkeyfile:masterkey.cryptomator","alg":"none","typ":"JWT"}"#,
            "",
        );
        let unverified = UnverifiedVaultConfig::decode(&token).unwrap();
        // The algorithm allowlist rejects `none` on its own ...
        assert!(matches!(
            unverified.algorithm(),
            Err(CoreError::VaultConfigLoad(_))
        ));
        // ... and `verify` consults it before comparing any MAC, so the empty signature never
        // reaches the HMAC path: the error is VaultConfigLoad, not VaultKeyInvalid.
        assert!(matches!(
            unverified.verify(&raw_key(), 8),
            Err(CoreError::VaultConfigLoad(_))
        ));
    }

    #[test]
    fn unsupported_algorithm_is_rejected() {
        let token = token_with_header(
            r#"{"kid":"masterkeyfile:masterkey.cryptomator","alg":"RS256","typ":"JWT"}"#,
            valid_signature_segment(),
        );
        let unverified = UnverifiedVaultConfig::decode(&token).unwrap();
        assert!(matches!(
            unverified.algorithm(),
            Err(CoreError::VaultConfigLoad(_))
        ));
        assert!(matches!(
            unverified.verify(&raw_key(), 8),
            Err(CoreError::VaultConfigLoad(_))
        ));
    }

    #[test]
    fn missing_alg_is_rejected() {
        let token = token_with_header(
            r#"{"kid":"masterkeyfile:masterkey.cryptomator","typ":"JWT"}"#,
            valid_signature_segment(),
        );
        let unverified = UnverifiedVaultConfig::decode(&token).unwrap();
        assert!(matches!(
            unverified.algorithm(),
            Err(CoreError::VaultConfigLoad(_))
        ));
        assert!(matches!(
            unverified.verify(&raw_key(), 8),
            Err(CoreError::VaultConfigLoad(_))
        ));
    }
}
