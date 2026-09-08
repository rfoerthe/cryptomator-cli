//! `cli.json`: the settings that only the CLI has, next to the desktop app's `settings.json`.
//!
//! The desktop app keeps its own configuration in `settings.json`, and the CLI writes that file
//! back verbatim (see [`crate::settings`]). Everything the CLI needs *in addition* -- where mount
//! points are created, which mount service to prefer, how verbose the daemon log is -- lives in a
//! separate file so a future desktop version cannot collide with it. Unknown keys are preserved,
//! for the same reason they are in `settings.json`.
use crate::error::{AppError, Result};
use crate::platform::Platform;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// The file name, always a sibling of `settings.json`.
pub const CLI_CONFIG_FILE_NAME: &str = "cli.json";
/// The default log level of the vault daemon.
pub const DEFAULT_LOG_LEVEL: &str = "info";
/// How long a shutting-down daemon tries a graceful unmount before forcing it.
pub const DEFAULT_FORCE_UNMOUNT_AFTER_SECS: u32 = 10;
/// The address the WebDAV back ends bind to when `cli.json` does not say otherwise.
pub const DEFAULT_WEBDAV_BIND: &str = "127.0.0.1";
/// The mode `cli.json` is written with; it names the user's vault mount points.
const FILE_MODE: u32 = 0o600;

/// The contents of `cli.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CliConfig {
    /// Where mount directories are created when neither the vault nor the command line names a
    /// mount point. `None` means [`CliConfig::mount_points_dir`]'s platform default.
    pub mount_points_dir: Option<String>,
    /// The Java class name of the mount service to use when the vault does not name one.
    pub default_mounter: Option<String>,
    /// `error`, `warn`, `info`, `debug` or `trace`.
    pub log_level: String,
    /// Seconds a daemon waits for a graceful unmount on shutdown before forcing it.
    pub force_unmount_on_signal_after_secs: u32,
    /// The address the WebDAV server binds to. `None` means [`DEFAULT_WEBDAV_BIND`]. A
    /// non-loopback address is refused unless `CRYPTO_WEBDAV_ALLOW_NONLOOPBACK=1`: the server has
    /// no authentication.
    pub webdav_bind: Option<String>,
    /// Every other key, preserved verbatim.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            mount_points_dir: None,
            default_mounter: None,
            log_level: DEFAULT_LOG_LEVEL.to_owned(),
            force_unmount_on_signal_after_secs: DEFAULT_FORCE_UNMOUNT_AFTER_SECS,
            webdav_bind: None,
            extra: Map::new(),
        }
    }
}

impl CliConfig {
    /// `cli.json` next to `settings_path`.
    pub fn path_next_to(settings_path: &Path) -> PathBuf {
        settings_path.with_file_name(CLI_CONFIG_FILE_NAME)
    }

    /// Loads `path`; a file that does not exist yields the defaults.
    ///
    /// # Errors
    /// [`AppError::SettingsCorrupt`] if the file is not valid JSON, [`AppError::SettingsUnreadable`]
    /// if it cannot be read. Unlike a missing file, a broken one is never silently replaced --
    /// [`CliConfig::save`] would overwrite whatever the user typed there.
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => {
                serde_json::from_slice(&bytes).map_err(|source| AppError::SettingsCorrupt {
                    path: path.to_path_buf(),
                    source,
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(source) => Err(AppError::SettingsUnreadable {
                path: path.to_path_buf(),
                source,
            }),
        }
    }

    /// Writes `path` through a process-unique temporary file that is renamed over it, like
    /// [`crate::settings::SettingsStore::save`]. The temporary file -- and therefore `cli.json`
    /// itself -- is created 0600, like the state files.
    ///
    /// # Errors
    /// Any I/O error while creating the directory, writing or renaming.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| AppError::InvalidValue {
            key: CLI_CONFIG_FILE_NAME.to_owned(),
            message: e.to_string(),
        })?;
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| CLI_CONFIG_FILE_NAME.to_owned());
        let tmp = path.with_file_name(format!("{file_name}.{}.tmp", std::process::id()));
        let written = std::fs::File::options()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(FILE_MODE)
            .open(&tmp)
            .and_then(|mut file| {
                file.write_all(json.as_bytes())?;
                file.write_all(b"\n")?;
                file.sync_all()
            });
        if let Err(e) = written {
            let _ = std::fs::remove_file(&tmp);
            return Err(AppError::Io(e));
        }
        // The same durable rename the settings file gets: the contents are synced above, the
        // entry that names them is synced by the rename.
        match cryptomator_core::durability::rename_durably(&tmp, path) {
            // Written and named: an unconfirmed durability is a warning, not a failed write.
            Ok(outcome) => {
                outcome.warn_unconfirmed(path.display());
            }
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                return Err(AppError::Io(e));
            }
        }
        Ok(())
    }

    /// Where mount directories are created: the configured value, else the platform's default,
    /// see [`default_mount_points_dir`].
    pub fn mount_points_dir(&self, home: &Path) -> PathBuf {
        self.mount_points_dir_on(Platform::current(), home)
    }

    /// [`CliConfig::mount_points_dir`] for an explicit platform; pure, so both branches can be
    /// checked on any host.
    pub fn mount_points_dir_on(&self, platform: Platform, home: &Path) -> PathBuf {
        match self.mount_points_dir.as_deref().map(str::trim) {
            Some(dir) if !dir.is_empty() => PathBuf::from(dir),
            _ => default_mount_points_dir(platform, home),
        }
    }

    /// The address the WebDAV server binds to.
    ///
    /// # Errors
    /// [`AppError::InvalidValue`] for a value that is not an IP address. A host name is refused
    /// on purpose: resolving one could point the server at an interface the user did not mean.
    pub fn webdav_bind_addr(&self) -> Result<std::net::IpAddr> {
        let raw = self
            .webdav_bind
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(DEFAULT_WEBDAV_BIND);
        raw.parse().map_err(|_| AppError::InvalidValue {
            key: "webdavBind".to_owned(),
            message: format!("expected an IP address, got {raw:?}"),
        })
    }
}

/// The platform's default mount-point base: `~/Library/Application Support/Cryptomator/mnt` on
/// macOS and `~/.local/share/Cryptomator/mnt` elsewhere (Cryptomator's
/// `Environment.getMountPointsDir`).
pub fn default_mount_points_dir(platform: Platform, home: &Path) -> PathBuf {
    if platform.is_macos() {
        home.join("Library/Application Support/Cryptomator/mnt")
    } else {
        home.join(".local/share/Cryptomator/mnt")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn defaults_apply_to_a_missing_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("cli.json");
        let config = CliConfig::load(&path).expect("load a missing file");
        assert_eq!(config, CliConfig::default());
        assert_eq!(config.log_level, "info");
        assert_eq!(config.force_unmount_on_signal_after_secs, 10);
        assert!(config.mount_points_dir.is_none() && config.default_mounter.is_none());
        assert_eq!(
            CliConfig::path_next_to(Path::new("/c/settings.json")),
            PathBuf::from("/c/cli.json")
        );
    }

    #[test]
    fn the_mount_points_dir_falls_back_to_the_platform_default() {
        let home = Path::new("/home/u");
        let macos = PathBuf::from("/home/u/Library/Application Support/Cryptomator/mnt");
        let linux = PathBuf::from("/home/u/.local/share/Cryptomator/mnt");
        // Both branches are checked on every host: the platform is a parameter, not a `cfg!`.
        assert_eq!(default_mount_points_dir(Platform::MacOs, home), macos);
        assert_eq!(default_mount_points_dir(Platform::Linux, home), linux);
        assert_eq!(
            CliConfig::default().mount_points_dir_on(Platform::MacOs, home),
            macos
        );
        assert_eq!(
            CliConfig::default().mount_points_dir_on(Platform::Linux, home),
            linux
        );
        assert_eq!(
            CliConfig::default().mount_points_dir(home),
            default_mount_points_dir(Platform::current(), home),
            "the convenience wrapper uses the host's platform"
        );

        let configured = CliConfig {
            mount_points_dir: Some("/mnt/vaults".to_owned()),
            ..CliConfig::default()
        };
        assert_eq!(
            configured.mount_points_dir(home),
            PathBuf::from("/mnt/vaults")
        );
        let blank = CliConfig {
            mount_points_dir: Some("  ".to_owned()),
            ..CliConfig::default()
        };
        assert_eq!(
            blank.mount_points_dir_on(Platform::Linux, home),
            linux,
            "a blank value is none"
        );
    }

    #[test]
    fn saving_round_trips_and_keeps_unknown_keys() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("deep/cli.json");
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(
            &path,
            br#"{"mountPointsDir":"/mnt","defaultMounter":"org.example.Mounter","logLevel":"debug","forceUnmountOnSignalAfterSecs":3,"futureKey":{"a":[1,2]}}"#,
        )
        .expect("write");

        let mut config = CliConfig::load(&path).expect("load");
        assert_eq!(config.mount_points_dir.as_deref(), Some("/mnt"));
        assert_eq!(
            config.default_mounter.as_deref(),
            Some("org.example.Mounter")
        );
        assert_eq!(config.log_level, "debug");
        assert_eq!(config.force_unmount_on_signal_after_secs, 3);
        assert_eq!(
            config.extra.get("futureKey"),
            Some(&serde_json::json!({"a":[1,2]}))
        );

        config.log_level = "trace".to_owned();
        config.save(&path).expect("save");
        let again = CliConfig::load(&path).expect("load again");
        assert_eq!(again, config, "unknown keys survive a write");
        let written = std::fs::read_to_string(&path).expect("read");
        assert!(written.contains("\"futureKey\""), "{written}");
        assert!(written.contains("\"logLevel\": \"trace\""), "{written}");
        assert!(
            !dir.path().join("deep/cli.json.tmp").exists(),
            "no temporary file is left behind"
        );
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, FILE_MODE, "cli.json is written 0600, got {mode:o}");
    }

    #[test]
    fn the_webdav_bind_address_defaults_to_loopback_and_is_parsed() {
        use std::net::{IpAddr, Ipv4Addr};
        let mut cli = CliConfig::default();
        assert_eq!(cli.webdav_bind, None);
        assert_eq!(
            cli.webdav_bind_addr().expect("the default"),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
        cli.webdav_bind = Some("  ".to_owned());
        assert_eq!(
            cli.webdav_bind_addr().expect("blank is unset"),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
        cli.webdav_bind = Some("::1".to_owned());
        assert_eq!(
            cli.webdav_bind_addr().expect("ipv6 loopback"),
            "::1".parse::<IpAddr>().expect("ipv6")
        );
        cli.webdav_bind = Some("localhost".to_owned());
        let err = cli
            .webdav_bind_addr()
            .expect_err("a name is not an address");
        assert!(err.to_string().contains("webdavBind"), "{err}");
    }

    #[test]
    fn an_unknown_key_next_to_webdav_bind_still_survives_a_round_trip() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("cli.json");
        std::fs::write(
            &path,
            br#"{"webdavBind":"127.0.0.2","somethingElse":{"a":1}}"#,
        )
        .expect("write");
        let cli = CliConfig::load(&path).expect("load");
        assert_eq!(cli.webdav_bind.as_deref(), Some("127.0.0.2"));
        cli.save(&path).expect("save");
        let text = std::fs::read_to_string(&path).expect("read back");
        assert!(text.contains("\"webdavBind\": \"127.0.0.2\""), "{text}");
        assert!(text.contains("somethingElse"), "{text}");
    }

    #[test]
    fn partial_and_broken_files() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("cli.json");
        std::fs::write(&path, br#"{"logLevel":"warn"}"#).expect("write");
        let config = CliConfig::load(&path).expect("load");
        assert_eq!(config.log_level, "warn");
        assert_eq!(
            config.force_unmount_on_signal_after_secs, DEFAULT_FORCE_UNMOUNT_AFTER_SECS,
            "missing keys keep their default"
        );

        std::fs::write(&path, b"nonsense").expect("write");
        assert!(matches!(
            CliConfig::load(&path),
            Err(AppError::SettingsCorrupt { .. })
        ));
    }
}
