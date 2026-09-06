//! `crypto lock`: take a vault's volume down and stop its daemon.
//!
//! A running daemon is asked over its socket -- it owns the mount and the file system, and it is
//! the only one that can flush and close them. A daemon that died and left its volume behind is
//! not there to ask; that mount is taken down by path through the mount service that made it, and
//! the leftover state files are removed afterwards.
use crate::cli::LockArgs;
use crate::commands::Ctx;
use crate::exit;
use anyhow::{Context, Result};
use cryptomator_app::{AppError, DaemonClient, RuntimeState, VaultInfo};
use cryptomator_mount::registry;
use serde_json::json;

pub fn lock(ctx: &Ctx, args: LockArgs) -> Result<u8> {
    let registry = ctx.registry();
    let targets: Vec<VaultInfo> = if args.all {
        registry
            .infos()?
            .into_iter()
            .filter(|info| info.state.is_mounted())
            .collect()
    } else {
        // `crypto lock v v` names the same vault twice: dedupe by id so it is locked once and
        // does not show up a second time as a spurious "failed" entry.
        let mut seen = std::collections::HashSet::new();
        args.vaults
            .iter()
            .map(|reference| registry.info(reference))
            .collect::<cryptomator_app::Result<Vec<_>>>()?
            .into_iter()
            .filter(|info| seen.insert(info.id.clone()))
            .collect()
    };

    let mut locked: Vec<String> = Vec::new();
    let mut failed: Vec<(String, String)> = Vec::new();
    // The first failure decides the exit code; the remaining vaults are still locked, so one busy
    // volume does not leave the others mounted.
    let mut code = exit::OK;
    for info in &targets {
        match lock_one(ctx, info, args.force) {
            Ok(()) => locked.push(info.id.clone()),
            Err(err) => {
                eprintln!("error: {}: {err:#}", name_of(info));
                if code == exit::OK {
                    code = exit::code_for(&err);
                }
                failed.push((info.id.clone(), format!("{err:#}")));
            }
        }
    }

    let mut value = json!({ "locked": locked });
    if !failed.is_empty() {
        value["failed"] = json!(failed
            .iter()
            .map(|(id, error)| json!({ "id": id, "error": error }))
            .collect::<Vec<_>>());
    }
    let names: Vec<String> = targets
        .iter()
        .filter(|info| locked.contains(&info.id))
        .map(name_of)
        .collect();
    ctx.out.emit(value, || {
        if names.is_empty() {
            if failed.is_empty() {
                "nothing to lock".to_owned()
            } else {
                String::new()
            }
        } else {
            names
                .iter()
                .map(|name| format!("Locked {name}"))
                .collect::<Vec<_>>()
                .join("\n")
        }
    })?;
    Ok(code)
}

/// The display name of a vault, falling back to its id.
fn name_of(info: &VaultInfo) -> String {
    info.display_name
        .clone()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| info.id.clone())
}

/// Locks one vault: over the socket while its daemon lives, by mount point once it is gone.
///
/// # Errors
/// [`AppError::WrongState`] (exit code 5) for a vault that is not unlocked, the daemon's
/// [`AppError::DaemonError`] with `UNMOUNT_FAILED` (7) for a busy volume, and
/// [`AppError::UnmountFailed`] (7) when a stale mount cannot be taken down.
fn lock_one(ctx: &Ctx, info: &VaultInfo, force: bool) -> Result<()> {
    match info.state {
        RuntimeState::Unlocked => {
            let socket = ctx.state_dir.files(&info.id).socket;
            let mut client = DaemonClient::connect(&socket)?;
            client.lock(force)?;
            Ok(())
        }
        RuntimeState::StaleMount => unmount_stale(ctx, info, force),
        other => Err(AppError::WrongState {
            expected: RuntimeState::Unlocked.as_str().to_owned(),
            actual: other.as_str().to_owned(),
        }
        .into()),
    }
}

/// Takes down a volume whose daemon is gone and removes its state files.
///
/// # Errors
/// [`AppError::UnmountFailed`] when the mount service is not in this build, cannot unmount by
/// path or the unmount itself fails.
fn unmount_stale(ctx: &Ctx, info: &VaultInfo, force: bool) -> Result<()> {
    let mounter = info.mounter.as_deref().unwrap_or_default();
    let mountpoint = info
        .mountpoint
        .as_deref()
        .ok_or_else(|| AppError::UnmountFailed(format!("vault {} has no mount point", info.id)))?;
    let service = registry::service_by_class(mounter)
        .ok_or_else(|| unknown_mounter_error(mounter, mountpoint))?;
    service
        .unmount_path(std::path::Path::new(mountpoint), force)
        .map_err(|err| AppError::UnmountFailed(format!("{mounter}: {err}")))?;
    ctx.state_dir
        .files(&info.id)
        .remove_all()
        .with_context(|| format!("cannot remove the state files of vault {}", info.id))?;
    Ok(())
}

/// The error for a stale mount whose run info names a mount-service class this build does not
/// have (`registry::service_by_class` returned `None`). A pure function of the two strings that
/// end up in the message, so the case is unit-testable without a real mount, state directory or
/// `VaultInfo`.
fn unknown_mounter_error(class: &str, mountpoint: &str) -> AppError {
    AppError::UnmountFailed(format!(
        "the mount service {class} of the volume at {mountpoint} is not part of this build"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `registry::service_by_class(class) == None`, the arm the null mounter can never reach
    /// end-to-end (it is always a class this build knows).
    #[test]
    fn an_unknown_mounter_class_names_itself_and_the_mountpoint() {
        let err = unknown_mounter_error("com.example.NoSuchMounter", "/mnt/v");
        assert!(matches!(err, AppError::UnmountFailed(_)));
        let message = err.to_string();
        assert!(message.contains("com.example.NoSuchMounter"), "{message}");
        assert!(message.contains("/mnt/v"), "{message}");
        assert!(message.contains("not part of this build"), "{message}");
    }
}
