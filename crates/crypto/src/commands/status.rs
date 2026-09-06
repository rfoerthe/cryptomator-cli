//! `crypto status`: what is registered, what is unlocked and where.
//!
//! Everything shown here comes from `settings.json` and the state directory, through
//! [`VaultRegistry`](cryptomator_app::VaultRegistry): the registry probes a daemon's socket to
//! tell an unlocked vault from a leftover, but no request is ever sent. So `status` answers for
//! locked, unlocked, crashed and missing vaults alike, and never blocks on a daemon.
use crate::cli::StatusArgs;
use crate::commands::Ctx;
use crate::exit;
use anyhow::Result;
use cryptomator_app::VaultInfo;

/// Column widths of the human table; a value that does not fit pushes the row wider rather than
/// being cut off, which keeps ids and paths copy-pasteable.
const HEADER: &str = "ID            NAME                  STATE                 MOUNTPOINT";

pub fn status(ctx: &Ctx, args: StatusArgs) -> Result<u8> {
    let registry = ctx.registry();
    let (value, rows) = match args.vault.as_deref() {
        // One vault is one object, not an array of one: `crypto status v --json | jq -r .state`
        // should not need an index. An unknown reference is exit code 3, from `info`.
        Some(reference) => {
            let info = registry.info(reference)?;
            (serde_json::to_value(&info)?, vec![info])
        }
        None => {
            let infos = registry.infos()?;
            (serde_json::to_value(&infos)?, infos)
        }
    };
    ctx.out.emit(value, || render(&rows))?;
    Ok(exit::OK)
}

/// The human table, header included, or the hint that there is nothing to show.
fn render(rows: &[VaultInfo]) -> String {
    if rows.is_empty() {
        return "No vaults registered. Use `crypto vault create` or `crypto vault add`."
            .to_string();
    }
    let mut lines = vec![HEADER.to_string()];
    for info in rows {
        lines.push(format!(
            "{:<12}  {:<20}  {:<20}  {}",
            info.id,
            info.display_name.as_deref().unwrap_or("-"),
            info.state.as_str(),
            info.mountpoint.as_deref().unwrap_or("-"),
        ));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptomator_app::RuntimeState;

    fn info(state: RuntimeState, mountpoint: Option<&str>) -> VaultInfo {
        VaultInfo {
            id: "abc123".to_string(),
            display_name: Some("Secret".to_string()),
            path: Some("/vaults/secret".to_string()),
            state,
            mountpoint: mountpoint.map(str::to_string),
            mounter: None,
            pid: None,
            read_only: None,
        }
    }

    #[test]
    fn the_table_has_a_header_and_a_dash_for_what_is_not_there() {
        assert!(render(&[]).contains("No vaults registered"));

        let rendered = render(&[
            info(RuntimeState::Unlocked, Some("/mnt/secret")),
            info(RuntimeState::Locked, None),
        ]);
        let lines: Vec<&str> = rendered.lines().collect();
        assert_eq!(lines[0], HEADER);
        assert!(lines[1].starts_with("abc123"), "{}", lines[1]);
        assert!(lines[1].contains("Secret"), "{}", lines[1]);
        assert!(lines[1].contains("UNLOCKED"), "{}", lines[1]);
        assert!(lines[1].ends_with("/mnt/secret"), "{}", lines[1]);
        assert!(
            lines[2].ends_with('-'),
            "a locked vault has no mount point: {}",
            lines[2]
        );
    }
}
