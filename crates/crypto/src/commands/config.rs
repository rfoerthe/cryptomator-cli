//! `crypto config get|set` for the global settings the CLI understands.
use crate::commands::Ctx;
use crate::exit;
use anyhow::Result;
use cryptomator_app::settings::SettingsJson;
use cryptomator_app::{resolve_mounter, AppError};
use serde_json::{json, Value};

pub const KEYS: &[&str] = &[
    "mountService",
    "port",
    "useKeychain",
    "keychainProvider",
    "debugMode",
];

fn unknown_key(key: &str) -> AppError {
    AppError::InvalidValue {
        key: key.to_string(),
        message: format!("unknown setting; known: {}", KEYS.join(", ")),
    }
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
    let all = config_json(&settings);
    match key {
        None => ctx.out.emit(all.clone(), || {
            KEYS.iter()
                .map(|k| format!("{k}={}", render(&all[*k])))
                .collect::<Vec<_>>()
                .join("\n")
        })?,
        Some(key) => {
            if !KEYS.contains(&key) {
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
            _ => return Err(unknown_key(key)),
        }
        Ok(config_json(settings))
    })?;
    ctx.out.emit(json!({ key: updated[key] }), || {
        format!("{key}={}", render(&updated[key]))
    })?;
    Ok(exit::OK)
}
