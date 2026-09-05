//! Resolving a user-supplied vault reference (id, display name or path) against the settings.
use crate::error::{AppError, Result};
use crate::settings::{SettingsJson, VaultSettingsJson};
use std::path::{Path, PathBuf};

/// Absolute, `.`/`..`-free path; canonicalised (symlinks resolved) when it exists.
pub fn normalize_vault_path(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    };
    if let Ok(canonical) = absolute.canonicalize() {
        return canonical;
    }
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

pub fn resolve_vault_index(settings: &SettingsJson, reference: &str) -> Result<usize> {
    let vaults = &settings.directories;
    if let Some(i) = vaults.iter().position(|v| v.id == reference) {
        return Ok(i);
    }
    let exact: Vec<usize> = vaults
        .iter()
        .enumerate()
        .filter(|(_, v)| v.display_name.as_deref() == Some(reference))
        .map(|(i, _)| i)
        .collect();
    match exact.as_slice() {
        [i] => return Ok(*i),
        [_, ..] => {
            return Err(AppError::AmbiguousVault(
                reference.to_string(),
                exact.iter().map(|i| vaults[*i].id.clone()).collect(),
            ))
        }
        [] => {}
    }
    let lowered = reference.to_lowercase();
    let insensitive: Vec<usize> = vaults
        .iter()
        .enumerate()
        .filter(|(_, v)| {
            v.display_name
                .as_deref()
                .is_some_and(|n| n.to_lowercase() == lowered)
        })
        .map(|(i, _)| i)
        .collect();
    match insensitive.as_slice() {
        [i] => return Ok(*i),
        [_, ..] => {
            return Err(AppError::AmbiguousVault(
                reference.to_string(),
                insensitive.iter().map(|i| vaults[*i].id.clone()).collect(),
            ))
        }
        [] => {}
    }
    let wanted = normalize_vault_path(Path::new(reference));
    if let Some(i) = vaults.iter().position(|v| {
        v.path_buf()
            .is_some_and(|p| normalize_vault_path(&p) == wanted)
    }) {
        return Ok(i);
    }
    Err(AppError::VaultNotFound(reference.to_string()))
}

pub fn resolve_vault<'a>(
    settings: &'a SettingsJson,
    reference: &str,
) -> Result<&'a VaultSettingsJson> {
    let index = resolve_vault_index(settings, reference)?;
    Ok(&settings.directories[index])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::SettingsJson;

    fn settings(dir: &Path) -> SettingsJson {
        let mut s = SettingsJson::default();
        let mut a = VaultSettingsJson::new("AAAAAAAAAAAA".into(), &dir.join("Alpha"));
        a.display_name = Some("Alpha".into());
        let mut b = VaultSettingsJson::new("BBBBBBBBBBBB".into(), &dir.join("Beta"));
        b.display_name = Some("beta".into());
        let mut c = VaultSettingsJson::new("CCCCCCCCCCCC".into(), &dir.join("Gamma"));
        c.display_name = Some("Beta".into());
        s.directories = vec![a, b, c];
        s
    }

    #[test]
    fn resolves_by_id_name_and_path() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("Alpha")).unwrap();
        let s = settings(dir.path());
        assert_eq!(resolve_vault_index(&s, "AAAAAAAAAAAA").unwrap(), 0);
        assert_eq!(resolve_vault(&s, "Alpha").unwrap().id, "AAAAAAAAAAAA");
        assert_eq!(
            resolve_vault(&s, "alpha").unwrap().id,
            "AAAAAAAAAAAA",
            "case-insensitive when unique"
        );
        assert_eq!(
            resolve_vault(&s, dir.path().join("Alpha").to_str().unwrap())
                .unwrap()
                .id,
            "AAAAAAAAAAAA"
        );
        assert_eq!(
            resolve_vault(&s, dir.path().join("Alpha/./").to_str().unwrap())
                .unwrap()
                .id,
            "AAAAAAAAAAAA",
            "path is normalized"
        );
        assert_eq!(
            resolve_vault(&s, dir.path().join("Gamma").to_str().unwrap())
                .unwrap()
                .id,
            "CCCCCCCCCCCC",
            "non-existent paths still match textually"
        );
    }

    #[test]
    fn exact_name_beats_case_insensitive_and_ambiguity_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let s = settings(dir.path());
        assert_eq!(resolve_vault(&s, "beta").unwrap().id, "BBBBBBBBBBBB");
        assert_eq!(resolve_vault(&s, "Beta").unwrap().id, "CCCCCCCCCCCC");
        match resolve_vault(&s, "BETA") {
            Err(AppError::AmbiguousVault(reference, ids)) => {
                assert_eq!(reference, "BETA");
                assert_eq!(
                    ids,
                    vec!["BBBBBBBBBBBB".to_string(), "CCCCCCCCCCCC".to_string()]
                );
            }
            other => panic!("expected ambiguity, got {other:?}"),
        }
    }

    #[test]
    fn unknown_reference_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let s = settings(dir.path());
        assert!(
            matches!(resolve_vault(&s, "nope"), Err(AppError::VaultNotFound(r)) if r == "nope")
        );
        assert!(matches!(
            resolve_vault(&s, "/definitely/not/there"),
            Err(AppError::VaultNotFound(_))
        ));
    }
}
