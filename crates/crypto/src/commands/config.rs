//! `crypto config get|set` for the settings the CLI understands.
//!
//! Two files, one command: [`KEYS`] live in the desktop app's `settings.json` and [`CLI_KEYS`] in
//! `cli.json` next to it (see [`CliConfig`]). The names do not collide, so `crypto config get`
//! prints them in one flat object and the key alone says which file it belongs to -- a caller
//! never has to know which of the two holds what.
use crate::commands::Ctx;
use crate::exit;
use anyhow::Result;
use cryptomator_app::settings::SettingsJson;
use cryptomator_app::{resolve_mounter, AppError, CliConfig};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

/// The `settings.json` keys, shared with the desktop app.
pub const KEYS: &[&str] = &[
    "mountService",
    "port",
    "useKeychain",
    "keychainProvider",
    "debugMode",
];

/// The `cli.json` keys, which only this CLI has.
pub const CLI_KEYS: &[&str] = &[
    "mountPointsDir",
    "defaultMounter",
    "logLevel",
    "forceUnmountOnSignalAfterSecs",
    "webdavBind",
];

/// The log levels the daemon understands, in increasing verbosity.
const LOG_LEVELS: &[&str] = &["error", "warn", "info", "debug", "trace"];

fn unknown_key(key: &str) -> AppError {
    AppError::InvalidValue {
        key: key.to_string(),
        message: format!(
            "unknown setting; known: {}, {}",
            KEYS.join(", "),
            CLI_KEYS.join(", ")
        ),
    }
}

/// Where `cli.json` is: next to the `settings.json` this run works on.
fn cli_config_path(ctx: &Ctx) -> PathBuf {
    CliConfig::path_next_to(ctx.store.preferred_path())
}

/// `cli.json` as the flat object `config get` prints.
///
/// `mountPointsDir` is the **effective** value -- the platform default when nothing is configured
/// -- because that is what the next `crypto unlock` will use. Without `$HOME` there is no default
/// to compute, and the raw value (usually `null`) is printed instead. `webdavBind` is effective
/// for the same reason: `127.0.0.1` is what the next WebDAV mount binds.
pub fn cli_config_json(cli: &CliConfig) -> Value {
    let mount_points_dir = match std::env::var_os("HOME") {
        Some(home) => Some(
            cli.mount_points_dir(Path::new(&home))
                .to_string_lossy()
                .into_owned(),
        ),
        None => cli.mount_points_dir.clone(),
    };
    // A value the parser cannot make sense of is printed verbatim: `config get` has to be able to
    // show what is in the file, even when the next unlock will refuse it.
    let webdav_bind = match cli.webdav_bind_addr() {
        Ok(addr) => Some(addr.to_string()),
        Err(_) => cli.webdav_bind.clone(),
    };
    json!({
        "mountPointsDir": mount_points_dir,
        "defaultMounter": cli.default_mounter,
        "logLevel": cli.log_level,
        "forceUnmountOnSignalAfterSecs": cli.force_unmount_on_signal_after_secs,
        "webdavBind": webdav_bind,
    })
}

fn parse_bool(key: &str, value: &str) -> Result<bool, AppError> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(AppError::InvalidValue {
            key: key.to_string(),
            message: "expected true or false".to_string(),
        }),
    }
}

pub fn config_json(settings: &SettingsJson) -> Value {
    json!({
        "mountService": settings.mount_service,
        "port": settings.port,
        "useKeychain": settings.use_keychain,
        "keychainProvider": settings.keychain_provider,
        "debugMode": settings.debug_mode,
    })
}

pub fn get(ctx: &Ctx, key: Option<&str>) -> Result<u8> {
    let settings = ctx.store.load()?;
    let cli = CliConfig::load(&cli_config_path(ctx))?;
    let mut all = config_json(&settings);
    // One object, one namespace: the two files' key names are disjoint.
    if let (Some(target), Value::Object(source)) = (all.as_object_mut(), cli_config_json(&cli)) {
        target.extend(source);
    }
    match key {
        None => ctx.out.emit(all.clone(), || {
            KEYS.iter()
                .chain(CLI_KEYS.iter())
                .map(|k| format!("{k}={}", render(&all[*k])))
                .collect::<Vec<_>>()
                .join("\n")
        })?,
        Some(key) => {
            if !KEYS.contains(&key) && !CLI_KEYS.contains(&key) {
                return Err(unknown_key(key).into());
            }
            let value = all[key].clone();
            ctx.out.emit(json!({ key: value }), || render(&value))?;
        }
    }
    Ok(exit::OK)
}

fn render(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// An empty value would be written verbatim into settings.json, where the desktop app cannot
/// resolve it: `mountService` is cleared with the explicit keyword `default` instead.
fn reject_empty(key: &str, value: &str, hint: &str) -> Result<(), AppError> {
    if value.is_empty() {
        return Err(AppError::InvalidValue {
            key: key.to_string(),
            message: format!("value must not be empty; {hint}"),
        });
    }
    Ok(())
}

pub fn set(ctx: &Ctx, key: &str, value: &str) -> Result<u8> {
    if CLI_KEYS.contains(&key) {
        return set_cli(ctx, key, value);
    }
    if !KEYS.contains(&key) {
        return Err(unknown_key(key).into());
    }
    let updated = ctx.store.update(|settings| {
        match key {
            "mountService" => {
                reject_empty(key, value, "use \"default\" for the automatic choice")?;
                settings.mount_service = if value == "default" {
                    None
                } else {
                    Some(resolve_mounter(value)?)
                }
            }
            "port" => {
                settings.port = value.parse().map_err(|_| AppError::InvalidValue {
                    key: key.to_string(),
                    message: "expected a port number 0-65535".to_string(),
                })?
            }
            "useKeychain" => settings.use_keychain = parse_bool(key, value)?,
            "keychainProvider" => {
                reject_empty(key, value, "pass the keychain provider's Java class name")?;
                settings.keychain_provider = value.to_string()
            }
            "debugMode" => settings.debug_mode = parse_bool(key, value)?,
            // Unreachable: the key was checked against `KEYS` above, before `settings.json` was
            // read, so an unknown key never reaches the update closure and never rewrites the file.
            _ => return Err(unknown_key(key)),
        }
        Ok(config_json(settings))
    })?;
    ctx.out.emit(json!({ key: updated[key] }), || {
        format!("{key}={}", render(&updated[key]))
    })?;
    Ok(exit::OK)
}

/// `crypto config set` for the `cli.json` keys: load, change the one key, write the file back.
///
/// Unknown keys in the file survive, like they do in `settings.json` ([`CliConfig`] keeps them).
///
/// # Errors
/// [`AppError::InvalidValue`] (exit code 2) for a value the key cannot hold, plus anything
/// reading or writing `cli.json` reports.
fn set_cli(ctx: &Ctx, key: &str, value: &str) -> Result<u8> {
    let path = cli_config_path(ctx);
    let mut cli = CliConfig::load(&path)?;
    match key {
        "mountPointsDir" => {
            reject_empty(key, value, "pass the directory mount points are created in")?;
            // Like every other path argument: resolved against the shell's cwd, because the
            // daemon that later reads this does not share it.
            let absolute = std::path::absolute(value).map_err(|e| AppError::InvalidValue {
                key: key.to_string(),
                message: format!("cannot resolve path {value}: {e}"),
            })?;
            cli.mount_points_dir = Some(absolute.to_string_lossy().into_owned());
        }
        "defaultMounter" => {
            reject_empty(key, value, "use \"default\" for the automatic choice")?;
            cli.default_mounter = if value == "default" {
                None
            } else {
                Some(resolve_mounter(value)?)
            };
        }
        "logLevel" => {
            let level = value.trim().to_lowercase();
            if !LOG_LEVELS.contains(&level.as_str()) {
                return Err(AppError::InvalidValue {
                    key: key.to_string(),
                    message: format!("expected one of {}", LOG_LEVELS.join(", ")),
                }
                .into());
            }
            cli.log_level = level;
        }
        "forceUnmountOnSignalAfterSecs" => {
            cli.force_unmount_on_signal_after_secs =
                value.parse().map_err(|_| AppError::InvalidValue {
                    key: key.to_string(),
                    message: "expected a number of seconds (0 forces the unmount at once)"
                        .to_string(),
                })?;
        }
        "webdavBind" => {
            reject_empty(key, value, "pass a loopback IP address, e.g. 127.0.0.1")?;
            let addr: std::net::IpAddr =
                value.trim().parse().map_err(|_| AppError::InvalidValue {
                    key: key.to_string(),
                    message: format!("expected an IP address, got {value:?}"),
                })?;
            // The same rule the daemon applies, checked here so a value that could never work is
            // never written (`cryptomator_mount::webdav::check_bind_address`).
            cryptomator_mount::webdav::check_bind_address(addr).map_err(|e| {
                AppError::InvalidValue {
                    key: key.to_string(),
                    message: e.to_string(),
                }
            })?;
            cli.webdav_bind = Some(addr.to_string());
        }
        // Unreachable: `set` dispatches here only for a key in `CLI_KEYS`.
        _ => return Err(unknown_key(key).into()),
    }
    cli.save(&path)?;
    let rendered = cli_config_json(&cli);
    let value = rendered[key].clone();
    ctx.out.emit(json!({ key: value }), || {
        format!("{key}={}", render(&value))
    })?;
    Ok(exit::OK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_unknown_key_message_names_both_files_keys() {
        let message = unknown_key("nope").to_string();
        for key in KEYS.iter().chain(CLI_KEYS.iter()) {
            assert!(message.contains(key), "{key} missing in {message}");
        }
    }

    #[test]
    fn the_cli_config_renders_every_key_it_knows() {
        let rendered = cli_config_json(&CliConfig::default());
        for key in CLI_KEYS {
            assert!(rendered.get(*key).is_some(), "{key} missing in {rendered}");
        }
        assert_eq!(rendered["logLevel"], "info");
        assert_eq!(rendered["forceUnmountOnSignalAfterSecs"], 10);
        assert!(rendered["defaultMounter"].is_null());
        assert_eq!(
            rendered["webdavBind"], "127.0.0.1",
            "the effective address, like mountPointsDir"
        );
    }

    /// A value the file carries but the parser refuses is still printed: `config get` shows what
    /// is there, and the unlock that would use it says why it cannot.
    #[test]
    fn an_unparsable_webdav_bind_is_rendered_verbatim() {
        let cli = CliConfig {
            webdav_bind: Some("localhost".to_owned()),
            ..CliConfig::default()
        };
        assert_eq!(cli_config_json(&cli)["webdavBind"], "localhost");
    }
}
