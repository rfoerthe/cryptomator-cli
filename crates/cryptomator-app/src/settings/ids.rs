//! Vault ids (`VaultSettings.generateId`) and display-name normalisation (`VaultSettings.normalizeDisplayName`).
use crate::settings::VaultSettingsJson;
use cryptomator_core::Rng;
use data_encoding::BASE64URL;
use std::path::PathBuf;

/// 9 random bytes -> 12 base64url characters (no padding needed).
pub fn generate_id(rng: &mut dyn Rng) -> String {
    let mut bytes = [0u8; 9];
    rng.fill(&mut bytes);
    BASE64URL.encode(&bytes)
}

/// Guava `CharMatcher.collapseFrom`: every run of matching chars becomes one `replacement`.
fn collapse(input: &str, matches: impl Fn(char) -> bool, replacement: char) -> String {
    let mut out = String::with_capacity(input.len());
    let mut in_run = false;
    for c in input.chars() {
        if matches(c) {
            if !in_run {
                out.push(replacement);
                in_run = true;
            }
        } else {
            out.push(c);
            in_run = false;
        }
    }
    out
}

/// `Character.isISOControl`
fn is_iso_control(c: char) -> bool {
    matches!(c as u32, 0x00..=0x1F | 0x7F..=0x9F)
}

pub fn normalize_display_name(original: &str) -> String {
    if original.trim().is_empty() || original == "." || original == ".." {
        return "_".to_string();
    }
    let without_fancy_whitespace = collapse(original, char::is_whitespace, ' ');
    collapse(
        &without_fancy_whitespace,
        |c| "<>:\"/\\|?*".contains(c) || is_iso_control(c),
        '_',
    )
}

impl VaultSettingsJson {
    /// `VaultSettings.mountName`: normalised display name, falling back to the path's file name, then "Vault".
    pub fn mount_name(&self) -> String {
        let name = match self.display_name.as_deref() {
            Some(name) if !name.is_empty() => name.to_string(),
            _ => self
                .path_buf()
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
                .unwrap_or_else(|| "Vault".to_string()),
        };
        normalize_display_name(&name)
    }

    pub fn path_buf(&self) -> Option<PathBuf> {
        self.path.as_deref().map(PathBuf::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptomator_core::OsRng;

    #[test]
    fn ids_are_12_base64url_chars() {
        let id = generate_id(&mut OsRng);
        assert_eq!(id.len(), 12);
        assert!(
            id.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "{id}"
        );
        assert_ne!(id, generate_id(&mut OsRng));
    }

    // VaultSettingsTest.testNormalize
    #[test]
    fn normalizes_like_java() {
        assert_eq!(normalize_display_name("a\u{000F}a"), "a_a");
        assert_eq!(normalize_display_name(": \\"), "_ _");
        assert_eq!(normalize_display_name("汉语"), "汉语");
        assert_eq!(normalize_display_name(".."), "_");
        assert_eq!(normalize_display_name("a\ta"), "a a");
        assert_eq!(normalize_display_name("\t\n\r"), "_");
        assert_eq!(
            normalize_display_name("a  \u{00A0} b"),
            "a b",
            "unicode whitespace collapses to one space"
        );
        assert_eq!(normalize_display_name("x<>:\"/\\|?*y"), "x_y");
        assert_eq!(normalize_display_name(""), "_");
        assert_eq!(normalize_display_name("."), "_");
    }

    #[test]
    fn mount_name_uses_display_name_or_path() {
        let mut v = VaultSettingsJson::new("id".into(), std::path::Path::new("/tmp/My: Vault"));
        assert_eq!(v.mount_name(), "My_ Vault");
        v.display_name = Some("".into());
        assert_eq!(
            v.mount_name(),
            "My_ Vault",
            "empty display name falls back to the path"
        );
        v.display_name = None;
        v.path = None;
        assert_eq!(v.mount_name(), "Vault");
    }
}
