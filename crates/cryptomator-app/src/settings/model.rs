//! On-disk schema of the desktop app's `settings.json` (`common/settings/SettingsJson.java`,
//! `VaultSettingsJson.java`). Only the fields the CLI uses are typed; everything else is kept
//! verbatim in `extra` so the desktop app's GUI settings survive a round trip. Legacy fields
//! (`preferredVolumeImpl`, `winDriveLetter`, `useCustomMountPath`, `customMountPath`) are read,
//! migrated like `Settings.migrateLegacySettings` / `VaultSettings.migrateLegacySettings` and never written.
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use std::path::Path;

pub const DEFAULT_PORT: u16 = 42427;
pub const DEFAULT_AUTOLOCK_IDLE_SECONDS: u32 = 30 * 60;
pub const DEFAULT_MAX_CLEARTEXT_FILENAME_LENGTH: i32 = -1;

/// `Settings.DEFAULT_KEYCHAIN_PROVIDER` for macOS and Linux.
pub fn default_keychain_provider() -> String {
    if cfg!(target_os = "macos") {
        "org.cryptomator.macos.keychain.MacSystemKeychainAccess".to_string()
    } else {
        "org.cryptomator.linux.keychain.GnomeKeyringKeychainAccess".to_string()
    }
}

fn d_true() -> bool {
    true
}

fn d_port() -> u16 {
    DEFAULT_PORT
}

fn d_idle() -> u32 {
    DEFAULT_AUTOLOCK_IDLE_SECONDS
}

fn d_max_name() -> i32 {
    DEFAULT_MAX_CLEARTEXT_FILENAME_LENGTH
}

/// Jackson `@JsonSetter(nulls = Nulls.AS_EMPTY)`.
fn null_as_empty<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> std::result::Result<Vec<T>, D::Error> {
    Ok(Option::<Vec<T>>::deserialize(d)?.unwrap_or_default())
}

fn null_as_default_provider<'de, D: Deserializer<'de>>(
    d: D,
) -> std::result::Result<String, D::Error> {
    Ok(Option::<String>::deserialize(d)?.unwrap_or_else(default_keychain_provider))
}

/// `common/settings/WhenUnlocked.java`; unknown values fall back to `ASK` (`@JsonEnumDefaultValue`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub enum WhenUnlocked {
    #[serde(rename = "IGNORE")]
    Ignore,
    #[serde(rename = "REVEAL")]
    Reveal,
    #[default]
    #[serde(rename = "ASK")]
    Ask,
}

impl WhenUnlocked {
    pub fn as_str(&self) -> &'static str {
        match self {
            WhenUnlocked::Ignore => "IGNORE",
            WhenUnlocked::Reveal => "REVEAL",
            WhenUnlocked::Ask => "ASK",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "IGNORE" => Some(WhenUnlocked::Ignore),
            "REVEAL" => Some(WhenUnlocked::Reveal),
            "ASK" => Some(WhenUnlocked::Ask),
            _ => None,
        }
    }
}

impl<'de> Deserialize<'de> for WhenUnlocked {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let value = Option::<String>::deserialize(d)?;
        Ok(value
            .as_deref()
            .and_then(WhenUnlocked::parse)
            .unwrap_or_default())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultSettingsJson {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default)]
    pub unlock_after_startup: bool,
    #[serde(default = "d_true")]
    pub reveal_after_mount: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mount_point: Option<String>,
    #[serde(default)]
    pub uses_read_only_mode: bool,
    #[serde(default)]
    pub mount_flags: String,
    #[serde(default = "d_max_name")]
    pub max_cleartext_filename_length: i32,
    #[serde(default)]
    pub action_after_unlock: WhenUnlocked,
    #[serde(default)]
    pub auto_lock_when_idle: bool,
    #[serde(default = "d_idle")]
    pub auto_lock_idle_seconds: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mount_service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_known_key_loader: Option<String>,
    #[serde(default = "d_port")]
    pub port: u16,
    /// Legacy (< 1.7.0), read-only.
    #[serde(default, skip_serializing)]
    pub win_drive_letter: Option<String>,
    #[serde(default, skip_serializing, alias = "usesIndividualMountPath")]
    pub use_custom_mount_path: bool,
    #[serde(default, skip_serializing, alias = "individualMountPath")]
    pub custom_mount_path: Option<String>,
    /// Every other key, preserved verbatim.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl VaultSettingsJson {
    /// `VaultListManager.newVaultSettings`: display name = last path component (or "Vault").
    pub fn new(id: String, path: &Path) -> Self {
        let display_name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "Vault".to_string());
        Self {
            id,
            path: Some(path.to_string_lossy().into_owned()),
            display_name: Some(display_name),
            unlock_after_startup: false,
            reveal_after_mount: true,
            mount_point: None,
            uses_read_only_mode: false,
            mount_flags: String::new(),
            max_cleartext_filename_length: DEFAULT_MAX_CLEARTEXT_FILENAME_LENGTH,
            action_after_unlock: WhenUnlocked::Ask,
            auto_lock_when_idle: false,
            auto_lock_idle_seconds: DEFAULT_AUTOLOCK_IDLE_SECONDS,
            mount_service: None,
            last_known_key_loader: None,
            port: DEFAULT_PORT,
            win_drive_letter: None,
            use_custom_mount_path: false,
            custom_mount_path: None,
            extra: Map::new(),
        }
    }

    /// `VaultSettings.migrateLegacySettings`.
    pub fn migrate_legacy(&mut self) {
        if self.use_custom_mount_path
            && self
                .custom_mount_path
                .as_deref()
                .is_some_and(|p| !p.is_empty())
        {
            self.mount_point = self.custom_mount_path.clone();
        } else if let Some(letter) = self.win_drive_letter.as_deref().filter(|l| !l.is_empty()) {
            self.mount_point = Some(format!("{letter}:\\"));
        }
        self.win_drive_letter = None;
        self.use_custom_mount_path = false;
        self.custom_mount_path = None;
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsJson {
    #[serde(default, deserialize_with = "null_as_empty")]
    pub directories: Vec<VaultSettingsJson>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub written_by_version: Option<String>,
    #[serde(default = "d_true")]
    pub use_keychain: bool,
    #[serde(
        default = "default_keychain_provider",
        deserialize_with = "null_as_default_provider"
    )]
    pub keychain_provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mount_service: Option<String>,
    #[serde(default = "d_port")]
    pub port: u16,
    #[serde(default)]
    pub debug_mode: bool,
    /// Legacy (< 1.7.0), read-only.
    #[serde(default, skip_serializing)]
    pub preferred_volume_impl: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for SettingsJson {
    fn default() -> Self {
        Self {
            directories: Vec::new(),
            written_by_version: None,
            use_keychain: true,
            keychain_provider: default_keychain_provider(),
            mount_service: None,
            port: DEFAULT_PORT,
            debug_mode: false,
            preferred_volume_impl: None,
            extra: Map::new(),
        }
    }
}

impl SettingsJson {
    pub fn parse(bytes: &[u8]) -> std::result::Result<Self, serde_json::Error> {
        let mut settings: Self = serde_json::from_slice(bytes)?;
        settings.migrate_legacy();
        Ok(settings)
    }

    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).expect("settings serialize")
    }

    /// `Settings.migrateLegacySettings` (macOS/Linux branches) plus per-vault migration.
    pub fn migrate_legacy(&mut self) {
        if self.mount_service.is_none() {
            if let Some(legacy) = self.preferred_volume_impl.as_deref() {
                self.mount_service = Some(
                    match legacy {
                        "Dokany" => "org.cryptomator.frontend.dokany.mount.DokanyMountProvider",
                        "FUSE" if cfg!(target_os = "macos") => {
                            "org.cryptomator.frontend.fuse.mount.MacFuseMountProvider"
                        }
                        "FUSE" => "org.cryptomator.frontend.fuse.mount.LinuxFuseMountProvider",
                        _ if cfg!(target_os = "macos") => {
                            "org.cryptomator.frontend.webdav.mount.MacAppleScriptMounter"
                        }
                        _ => "org.cryptomator.frontend.webdav.mount.LinuxGioMounter",
                    }
                    .to_string(),
                );
            }
        }
        self.preferred_volume_impl = None;
        for vault in &mut self.directories {
            vault.migrate_legacy();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // SettingsJsonTest.testDeserialize from the desktop app
    const JAVA_TEST_JSON: &str = r#"{
        "directories": [
            {"id": "1", "path": "/vault1", "mountName": "vault1", "winDriveLetter": "X", "shouldBeIgnored": true},
            {"id": "2", "path": "/vault2", "mountName": "vault2", "winDriveLetter": "Y", "mountFlags":"--foo --bar"}
        ],
        "autoCloseVaults" : true,
        "checkForUpdatesEnabled": true,
        "port": 8080,
        "language": "de-DE",
        "numTrayNotifications": 42,
        "trustedHosts": null
    }"#;

    // Shape of a settings.json written by Cryptomator 1.19.3 (values redacted)
    const DESKTOP_JSON: &str = r#"{
  "directories" : [ {
    "id" : "OefwgtaX5vsy",
    "path" : "/Users/me/Vaults/Test",
    "displayName" : "Test",
    "unlockAfterStartup" : false,
    "revealAfterMount" : true,
    "usesReadOnlyMode" : false,
    "mountFlags" : "",
    "maxCleartextFilenameLength" : 2147483647,
    "actionAfterUnlock" : "REVEAL",
    "autoLockWhenIdle" : false,
    "autoLockIdleSeconds" : 1800,
    "lastKnownKeyLoader" : "masterkeyfile",
    "port" : 42427
  } ],
  "writtenByVersion" : "1.19.3-dmg-6495",
  "autoCloseVaults" : false,
  "debugMode" : false,
  "theme" : "LIGHT",
  "keychainProvider" : "org.cryptomator.macos.keychain.MacSystemKeychainAccess",
  "numTrayNotifications" : 3,
  "port" : 42427,
  "showTrayIcon" : true,
  "compactMode" : false,
  "startHidden" : false,
  "uiOrientation" : "LEFT_TO_RIGHT",
  "useKeychain" : true,
  "windowHeight" : 702,
  "windowWidth" : 1061,
  "windowXPosition" : 202,
  "windowYPosition" : 62,
  "checkForUpdatesEnabled" : true,
  "lastReminderForUpdateCheck" : "2026-09-04T19:34:53Z",
  "lastSuccessfulUpdateCheck" : "2026-09-04T20:10:12Z",
  "useQuickAccess" : true,
  "previouslyUsedVaultDirectory" : "file:///Users/me/pCloud%20Drive/",
  "trustedHosts" : [ ]
}"#;

    #[test]
    fn deserializes_like_java_test() {
        let s = SettingsJson::parse(JAVA_TEST_JSON.as_bytes()).unwrap();
        assert_eq!(s.directories.len(), 2);
        assert_eq!(s.directories[0].path.as_deref(), Some("/vault1"));
        assert_eq!(s.directories[1].path.as_deref(), Some("/vault2"));
        assert_eq!(s.directories[1].mount_flags, "--foo --bar");
        assert_eq!(s.port, 8080);
        assert_eq!(
            s.extra.get("autoCloseVaults"),
            Some(&serde_json::Value::Bool(true))
        );
        assert_eq!(
            s.extra.get("language"),
            Some(&serde_json::Value::String("de-DE".into()))
        );
        assert_eq!(
            s.extra.get("numTrayNotifications"),
            Some(&serde_json::json!(42))
        );
        assert_eq!(s.extra.get("trustedHosts"), Some(&serde_json::Value::Null));
        assert_eq!(
            s.directories[0].extra.get("shouldBeIgnored"),
            Some(&serde_json::Value::Bool(true))
        );
        // legacy winDriveLetter migrates to a mount point and is never written back
        assert_eq!(s.directories[0].mount_point.as_deref(), Some("X:\\"));
        let out = s.to_json_pretty();
        assert!(!out.contains("winDriveLetter"));
        assert!(
            out.contains("\"shouldBeIgnored\": true"),
            "unknown vault keys survive: {out}"
        );
        assert!(out.contains("\"language\": \"de-DE\""));
    }

    #[test]
    fn malformed_input_is_an_error() {
        for input in ["", "<html>", "{invalidjson}", "[]"] {
            assert!(SettingsJson::parse(input.as_bytes()).is_err(), "{input:?}");
        }
    }

    #[test]
    fn null_directories_become_empty() {
        let s = SettingsJson::parse(br#"{"directories": null}"#).unwrap();
        assert!(s.directories.is_empty());
    }

    #[test]
    fn defaults_match_java() {
        let s = SettingsJson::default();
        assert_eq!(s.port, DEFAULT_PORT);
        assert!(s.use_keychain);
        assert_eq!(s.keychain_provider, default_keychain_provider());
        assert!(s.mount_service.is_none());
        let v = VaultSettingsJson::new("abc".into(), std::path::Path::new("/tmp/v"));
        assert_eq!(v.path.as_deref(), Some("/tmp/v"));
        assert_eq!(v.display_name.as_deref(), Some("v"));
        assert!(v.reveal_after_mount);
        assert!(!v.unlock_after_startup);
        assert_eq!(v.auto_lock_idle_seconds, DEFAULT_AUTOLOCK_IDLE_SECONDS);
        assert_eq!(
            v.max_cleartext_filename_length,
            DEFAULT_MAX_CLEARTEXT_FILENAME_LENGTH
        );
        assert_eq!(v.action_after_unlock, WhenUnlocked::Ask);
        assert_eq!(v.port, DEFAULT_PORT);
        assert_eq!(v.mount_flags, "");
        let out = SettingsJson {
            directories: vec![v],
            ..SettingsJson::default()
        }
        .to_json_pretty();
        for needle in [
            "\"useKeychain\": true",
            "\"actionAfterUnlock\": \"ASK\"",
            "\"revealAfterMount\": true",
            "\"port\": 42427",
            "\"maxCleartextFilenameLength\": -1",
        ] {
            assert!(out.contains(needle), "{needle} missing in {out}");
        }
        assert!(
            !out.contains("\"mountPoint\""),
            "None fields are omitted like Jackson NON_NULL"
        );
    }

    #[test]
    fn desktop_file_round_trips_and_keeps_unknown_fields() {
        let s = SettingsJson::parse(DESKTOP_JSON.as_bytes()).unwrap();
        assert_eq!(s.written_by_version.as_deref(), Some("1.19.3-dmg-6495"));
        assert_eq!(s.directories[0].max_cleartext_filename_length, 2147483647);
        assert_eq!(s.directories[0].action_after_unlock, WhenUnlocked::Reveal);
        let out = s.to_json_pretty();
        let again = SettingsJson::parse(out.as_bytes()).unwrap();
        assert_eq!(again, s);
        for needle in [
            "\"theme\": \"LIGHT\"",
            "\"windowHeight\": 702",
            "\"previouslyUsedVaultDirectory\": \"file:///Users/me/pCloud%20Drive/\"",
            "\"trustedHosts\": []",
            "\"lastKnownKeyLoader\": \"masterkeyfile\"",
        ] {
            assert!(out.contains(needle), "{needle} missing in {out}");
        }
    }

    #[test]
    fn preferred_volume_impl_migrates_to_mount_service() {
        let s = SettingsJson::parse(br#"{"preferredVolumeImpl": "FUSE"}"#).unwrap();
        let expected = if cfg!(target_os = "macos") {
            "org.cryptomator.frontend.fuse.mount.MacFuseMountProvider"
        } else {
            "org.cryptomator.frontend.fuse.mount.LinuxFuseMountProvider"
        };
        assert_eq!(s.mount_service.as_deref(), Some(expected));
        assert!(!s.to_json_pretty().contains("preferredVolumeImpl"));
        let s =
            SettingsJson::parse(br#"{"preferredVolumeImpl": "WEBDAV", "mountService": "keep.Me"}"#)
                .unwrap();
        assert_eq!(
            s.mount_service.as_deref(),
            Some("keep.Me"),
            "explicit mountService wins"
        );
        let s = SettingsJson::parse(br#"{"preferredVolumeImpl": "Dokany"}"#).unwrap();
        assert_eq!(
            s.mount_service.as_deref(),
            Some("org.cryptomator.frontend.dokany.mount.DokanyMountProvider")
        );
    }

    #[test]
    fn legacy_custom_mount_path_and_aliases_migrate() {
        let s = SettingsJson::parse(br#"{"directories":[{"id":"a","useCustomMountPath":true,"customMountPath":"/mnt/a"},{"id":"b","usesIndividualMountPath":true,"individualMountPath":"/mnt/b"},{"id":"c","useCustomMountPath":false,"customMountPath":"/ignored","winDriveLetter":"Z"}]}"#).unwrap();
        assert_eq!(s.directories[0].mount_point.as_deref(), Some("/mnt/a"));
        assert_eq!(s.directories[1].mount_point.as_deref(), Some("/mnt/b"));
        assert_eq!(s.directories[2].mount_point.as_deref(), Some("Z:\\"));
        let out = s.to_json_pretty();
        for legacy in [
            "useCustomMountPath",
            "customMountPath",
            "usesIndividualMountPath",
            "individualMountPath",
            "winDriveLetter",
        ] {
            assert!(!out.contains(legacy), "{legacy} must not be written");
        }
    }

    #[test]
    fn unknown_action_after_unlock_falls_back_to_ask() {
        let s = SettingsJson::parse(br#"{"directories":[{"id":"a","actionAfterUnlock":"DANCE"}]}"#)
            .unwrap();
        assert_eq!(s.directories[0].action_after_unlock, WhenUnlocked::Ask);
        assert_eq!(WhenUnlocked::parse("REVEAL"), Some(WhenUnlocked::Reveal));
        assert_eq!(WhenUnlocked::Ignore.as_str(), "IGNORE");
    }

    #[test]
    fn null_keychain_provider_falls_back_to_default() {
        let s = SettingsJson::parse(br#"{"keychainProvider": null}"#).unwrap();
        assert_eq!(s.keychain_provider, default_keychain_provider());
    }
}
