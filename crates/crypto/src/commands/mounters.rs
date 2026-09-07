//! `crypto mounters`: the mount services this build knows, and which of them work here.
//!
//! Nothing is discovered at run time -- the registry is written out in
//! [`cryptomator_mount::registry`] -- so this is the authoritative answer to "what can I pass to
//! `--mounter`". Without `--all` only the services that work on this machine are listed; with it,
//! the unsupported ones too, including the null mounter that mounts nothing.
use crate::cli::MountersArgs;
use crate::commands::Ctx;
use crate::exit;
use anyhow::Result;
use cryptomator_mount::api::ServiceInfo;
use cryptomator_mount::registry;

/// The width of the alias column: the longest alias the registry hands out is
/// `webdav-applescript`. The header is built with the same width, so the two cannot drift apart.
const ALIAS_WIDTH: usize = 18;

/// The table header.
fn header() -> String {
    row("ALIAS", "CLASS", "SUPPORTED", "CAPABILITIES")
}

/// One line of the table, header and services alike.
fn row(alias: &str, class: &str, supported: &str, capabilities: &str) -> String {
    format!("{alias:<ALIAS_WIDTH$}  {class:<60}  {supported:<9}  {capabilities}")
}

pub fn mounters(ctx: &Ctx, args: MountersArgs) -> Result<u8> {
    let services = registry::service_infos(args.all);
    ctx.out
        .emit(serde_json::to_value(&services)?, || render(&services))?;
    Ok(exit::OK)
}

/// The human table, header included.
fn render(services: &[ServiceInfo]) -> String {
    if services.is_empty() {
        return "No mount service works on this machine. `crypto mounters --all` lists the ones \
                this build knows."
            .to_string();
    }
    let mut lines = vec![header()];
    for service in services {
        lines.push(row(
            service.alias.as_deref().unwrap_or("-"),
            &service.class_name,
            if service.supported { "yes" } else { "no" },
            &service.capabilities.join(","),
        ));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(alias: Option<&str>, supported: bool) -> ServiceInfo {
        ServiceInfo {
            class_name: "org.example.Mounter".to_string(),
            display_name: "Example".to_string(),
            alias: alias.map(str::to_string),
            supported,
            priority: 100,
            capabilities: vec!["MOUNT_FLAGS".to_string(), "UNMOUNT_FORCED".to_string()],
            default_mount_flags: String::new(),
        }
    }

    #[test]
    fn the_table_shows_the_alias_the_class_and_the_capabilities() {
        assert!(render(&[]).contains("--all"));

        let rendered = render(&[info(Some("fuse-t"), true), info(None, false)]);
        let lines: Vec<&str> = rendered.lines().collect();
        assert_eq!(lines[0], header());
        assert!(lines[1].starts_with("fuse-t"), "{}", lines[1]);
        assert!(lines[1].contains("org.example.Mounter"), "{}", lines[1]);
        assert!(lines[1].contains("yes"), "{}", lines[1]);
        assert!(
            lines[1].ends_with("MOUNT_FLAGS,UNMOUNT_FORCED"),
            "{}",
            lines[1]
        );
        // A service without a short name still lines up.
        assert!(lines[2].starts_with("-  "), "{}", lines[2]);
        assert!(lines[2].contains(" no "), "{}", lines[2]);
        // Every column starts where the header says it does.
        for line in &lines[1..] {
            assert_eq!(
                line.find("org.example.Mounter"),
                lines[0].find("CLASS"),
                "{line}"
            );
        }
    }

    /// The alias column has to be wide enough for the longest alias the registry knows, or the
    /// table shifts by a column for exactly that row.
    #[test]
    fn no_alias_is_wider_than_its_column() {
        for service in registry::service_infos(true) {
            let Some(alias) = service.alias else { continue };
            assert!(
                alias.len() <= ALIAS_WIDTH,
                "{alias} does not fit into {ALIAS_WIDTH} columns"
            );
        }
    }
}
