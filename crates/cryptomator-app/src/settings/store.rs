//! Locating, loading and atomically saving `settings.json` (`common/settings/SettingsProvider.java`
//! plus the per-OS `-Dcryptomator.settingsPath` values from the desktop packaging scripts).
use crate::error::{AppError, Result};
use crate::settings::SettingsJson;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const SETTINGS_PATH_ENV: &str = "CRYPTO_SETTINGS_PATH";
const WRITTEN_BY_VERSION: &str = concat!("crypto-", env!("CARGO_PKG_VERSION"));

/// macOS: `~/Library/Application Support/Cryptomator/settings.json`;
/// Linux: `~/.config/Cryptomator/settings.json`, then `~/.Cryptomator/settings.json`.
pub fn default_settings_candidates(home: &Path) -> Vec<PathBuf> {
    if cfg!(target_os = "macos") {
        vec![home.join("Library/Application Support/Cryptomator/settings.json")]
    } else {
        vec![
            home.join(".config/Cryptomator/settings.json"),
            home.join(".Cryptomator/settings.json"),
        ]
    }
}

/// `CRYPTO_SETTINGS_PATH` is a `:`-separated list like Java's `cryptomator.settingsPath`; empty entries are ignored.
pub fn candidates_from_env_value(value: &str) -> Vec<PathBuf> {
    value
        .split(':')
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        .collect()
}

#[derive(Debug, Clone)]
pub struct SettingsStore {
    candidates: Vec<PathBuf>,
}

impl SettingsStore {
    pub fn with_paths(candidates: Vec<PathBuf>) -> Result<Self> {
        if candidates.is_empty() {
            return Err(AppError::InvalidValue {
                key: SETTINGS_PATH_ENV.to_string(),
                message: "at least one settings path is required".to_string(),
            });
        }
        Ok(Self { candidates })
    }

    pub fn at(path: PathBuf) -> Self {
        Self {
            candidates: vec![path],
        }
    }

    pub fn from_env_or_default() -> Result<Self> {
        if let Some(value) = std::env::var_os(SETTINGS_PATH_ENV) {
            return Self::with_paths(candidates_from_env_value(&value.to_string_lossy()));
        }
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or(AppError::NoHomeDirectory)?;
        Self::with_paths(default_settings_candidates(&home))
    }

    /// The first candidate: always the save target (`SettingsProvider.scheduleSave`).
    pub fn preferred_path(&self) -> &Path {
        &self.candidates[0]
    }

    pub fn candidates(&self) -> &[PathBuf] {
        &self.candidates
    }

    /// First candidate that exists wins. Unlike Java, a corrupt file is an error rather than a silent reset.
    pub fn load(&self) -> Result<SettingsJson> {
        for path in &self.candidates {
            match std::fs::read(path) {
                Ok(bytes) => {
                    return SettingsJson::parse(&bytes).map_err(|source| {
                        AppError::SettingsCorrupt {
                            path: path.clone(),
                            source,
                        }
                    })
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(source) => {
                    return Err(AppError::SettingsUnreadable {
                        path: path.clone(),
                        source,
                    })
                }
            }
        }
        Ok(SettingsJson::default())
    }

    /// Writes a process-unique `settings.json.<pid>.tmp` next to the preferred path and renames it
    /// over that path (`SettingsProvider.save`). The tmp name must not collide with the desktop
    /// app's fixed `settings.json.tmp`: a concurrent desktop save would otherwise truncate our tmp
    /// file and we would publish a partial file, which this crate reports as a corrupt settings
    /// file instead of silently resetting it. `create_new` additionally refuses to reuse a
    /// foreign tmp file, and every failure after creation removes the tmp file again.
    pub fn save(&self, settings: &mut SettingsJson) -> Result<()> {
        let path = self.preferred_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if settings.written_by_version.is_none() {
            settings.written_by_version = Some(WRITTEN_BY_VERSION.to_string());
        }
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "settings.json".to_string());
        let tmp_path = path.with_file_name(format!("{file_name}.{}.tmp", std::process::id()));
        let written = std::fs::File::options()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .and_then(|mut tmp| {
                tmp.write_all(settings.to_json_pretty().as_bytes())?;
                tmp.sync_all()
            });
        if let Err(e) = written {
            // Only remove the tmp file if we are the ones who created it.
            if e.kind() != std::io::ErrorKind::AlreadyExists {
                let _ = std::fs::remove_file(&tmp_path);
            }
            return Err(AppError::Io(e));
        }
        if let Err(e) = std::fs::rename(&tmp_path, path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(AppError::Io(e));
        }
        Ok(())
    }

    pub fn update<T>(&self, f: impl FnOnce(&mut SettingsJson) -> Result<T>) -> Result<T> {
        let mut settings = self.load()?;
        let result = f(&mut settings)?;
        self.save(&mut settings)?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::VaultSettingsJson;

    #[test]
    fn default_candidates_per_os() {
        let home = Path::new("/home/u");
        let candidates = default_settings_candidates(home);
        if cfg!(target_os = "macos") {
            assert_eq!(
                candidates,
                vec![PathBuf::from(
                    "/home/u/Library/Application Support/Cryptomator/settings.json"
                )]
            );
        } else {
            assert_eq!(
                candidates,
                vec![
                    PathBuf::from("/home/u/.config/Cryptomator/settings.json"),
                    PathBuf::from("/home/u/.Cryptomator/settings.json")
                ]
            );
        }
        assert_eq!(
            candidates_from_env_value("/a/s.json::/b/s.json:"),
            vec![PathBuf::from("/a/s.json"), PathBuf::from("/b/s.json")]
        );
        assert!(SettingsStore::with_paths(Vec::new()).is_err());
    }

    #[test]
    fn missing_file_loads_defaults_and_save_creates_directories() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deep/er/settings.json");
        let store = SettingsStore::at(path.clone());
        let mut settings = store.load().unwrap();
        assert_eq!(settings, SettingsJson::default());
        settings.directories.push(VaultSettingsJson::new(
            "AAAAAAAAAAAA".into(),
            Path::new("/v"),
        ));
        store.save(&mut settings).unwrap();
        assert!(path.is_file());
        assert!(!dir.path().join("deep/er/settings.json.tmp").exists());
        assert_eq!(
            settings.written_by_version.as_deref(),
            Some(concat!("crypto-", env!("CARGO_PKG_VERSION")))
        );
        let loaded = store.load().unwrap();
        assert_eq!(loaded, settings);
    }

    #[test]
    fn existing_written_by_version_is_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(
            &path,
            br#"{"writtenByVersion":"1.19.3-dmg-6495","theme":"DARK"}"#,
        )
        .unwrap();
        let store = SettingsStore::at(path.clone());
        let mut settings = store.load().unwrap();
        settings.port = 5000;
        store.save(&mut settings).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"writtenByVersion\": \"1.19.3-dmg-6495\""));
        assert!(text.contains("\"theme\": \"DARK\""));
        assert!(text.contains("\"port\": 5000"));
    }

    #[test]
    fn falls_back_to_second_candidate_but_saves_to_first() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first/settings.json");
        let second = dir.path().join("second/settings.json");
        std::fs::create_dir_all(second.parent().unwrap()).unwrap();
        std::fs::write(&second, br#"{"port": 4711}"#).unwrap();
        let store = SettingsStore::with_paths(vec![first.clone(), second.clone()]).unwrap();
        let mut settings = store.load().unwrap();
        assert_eq!(settings.port, 4711);
        store.save(&mut settings).unwrap();
        assert!(first.is_file());
        assert_eq!(
            std::fs::read_to_string(&second).unwrap(),
            r#"{"port": 4711}"#,
            "second candidate untouched"
        );
    }

    #[test]
    fn corrupt_file_is_an_error_not_silently_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, b"{ not json").unwrap();
        let store = SettingsStore::at(path.clone());
        assert!(matches!(
            store.load(),
            Err(AppError::SettingsCorrupt { .. })
        ));
        assert!(store
            .update(|s| {
                s.port = 1;
                Ok(())
            })
            .is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"{ not json");
    }

    #[test]
    fn unreadable_first_candidate_is_an_error_not_a_fallthrough() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first/settings.json");
        let second = dir.path().join("second/settings.json");
        // A directory where a file is expected: readable entry, unreadable content.
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(second.parent().unwrap()).unwrap();
        std::fs::write(&second, br#"{"port": 1}"#).unwrap();
        let store = SettingsStore::with_paths(vec![first.clone(), second]).unwrap();
        match store.load() {
            Err(AppError::SettingsUnreadable { path, .. }) => assert_eq!(path, first),
            other => panic!("expected SettingsUnreadable, got {other:?}"),
        }
    }

    #[test]
    fn failed_save_leaves_no_tmp_behind() {
        let dir = tempfile::tempdir().unwrap();
        // The preferred path itself is a non-empty directory, so `create_dir_all` on its parent
        // and the tmp write both succeed, but the final rename fails (EISDIR/ENOTEMPTY).
        let path = dir.path().join("settings.json");
        std::fs::create_dir_all(path.join("occupied")).unwrap();
        let store = SettingsStore::at(path.clone());
        let mut settings = SettingsJson::default();
        assert!(store.save(&mut settings).is_err());
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "tmp files left behind: {leftovers:?}");
    }

    #[test]
    fn update_loads_applies_and_saves() {
        let dir = tempfile::tempdir().unwrap();
        let store = SettingsStore::at(dir.path().join("settings.json"));
        let id = store
            .update(|s| {
                s.directories.push(VaultSettingsJson::new(
                    "BBBBBBBBBBBB".into(),
                    Path::new("/b"),
                ));
                Ok(s.directories[0].id.clone())
            })
            .unwrap();
        assert_eq!(id, "BBBBBBBBBBBB");
        assert_eq!(store.load().unwrap().directories.len(), 1);
    }
}
