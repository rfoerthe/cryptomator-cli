//! Short CLI aliases for the Java mount-service class names stored in settings.json.
use crate::error::{AppError, Result};

pub const MOUNTER_ALIASES: &[(&str, &str)] = &[
    (
        "fuse-t",
        "org.cryptomator.frontend.fuse.mount.FuseTMountProvider",
    ),
    (
        "macfuse",
        "org.cryptomator.frontend.fuse.mount.MacFuseMountProvider",
    ),
    (
        "fuse",
        "org.cryptomator.frontend.fuse.mount.LinuxFuseMountProvider",
    ),
    (
        "webdav",
        "org.cryptomator.frontend.webdav.mount.FallbackMounter",
    ),
    (
        "webdav-applescript",
        "org.cryptomator.frontend.webdav.mount.MacAppleScriptMounter",
    ),
    (
        "webdav-gio",
        "org.cryptomator.frontend.webdav.mount.LinuxGioMounter",
    ),
    // The built-in null mounter; only usable with CRYPTO_ENABLE_NULL_MOUNTER=1 and only listed by
    // `crypto mounters --all`.
    ("null", "org.cryptomator.cli.NullMountProvider"),
];

/// Alias (case-insensitive) or a fully qualified Java class name (must contain a dot).
pub fn resolve_mounter(input: &str) -> Result<String> {
    let lowered = input.to_lowercase();
    if let Some((_, class)) = MOUNTER_ALIASES.iter().find(|(alias, _)| *alias == lowered) {
        return Ok((*class).to_string());
    }
    if input.contains('.') {
        return Ok(input.to_string());
    }
    Err(AppError::InvalidValue {
        key: "mounter".to_string(),
        message: format!(
            "unknown mounter {input:?}; use one of {} or a Java class name",
            MOUNTER_ALIASES
                .iter()
                .map(|(a, _)| *a)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    })
}

pub fn alias_for(class_name: &str) -> Option<&'static str> {
    MOUNTER_ALIASES
        .iter()
        .find(|(_, class)| *class == class_name)
        .map(|(alias, _)| *alias)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases_map_to_java_class_names_and_back() {
        assert_eq!(
            resolve_mounter("fuse-t").unwrap(),
            "org.cryptomator.frontend.fuse.mount.FuseTMountProvider"
        );
        assert_eq!(
            resolve_mounter("MacFUSE").unwrap(),
            "org.cryptomator.frontend.fuse.mount.MacFuseMountProvider"
        );
        assert_eq!(
            resolve_mounter("fuse").unwrap(),
            "org.cryptomator.frontend.fuse.mount.LinuxFuseMountProvider"
        );
        assert_eq!(
            resolve_mounter("webdav").unwrap(),
            "org.cryptomator.frontend.webdav.mount.FallbackMounter"
        );
        assert_eq!(
            resolve_mounter("webdav-gio").unwrap(),
            "org.cryptomator.frontend.webdav.mount.LinuxGioMounter"
        );
        assert_eq!(
            alias_for("org.cryptomator.frontend.webdav.mount.MacAppleScriptMounter"),
            Some("webdav-applescript")
        );
        assert_eq!(
            resolve_mounter("null").unwrap(),
            "org.cryptomator.cli.NullMountProvider"
        );
        assert_eq!(
            alias_for("org.cryptomator.cli.NullMountProvider"),
            Some("null")
        );
        assert_eq!(
            resolve_mounter("org.example.Custom").unwrap(),
            "org.example.Custom",
            "class names pass through"
        );
        assert!(matches!(
            resolve_mounter("bogus"),
            Err(AppError::InvalidValue { .. })
        ));
        assert_eq!(
            alias_for("org.cryptomator.frontend.fuse.mount.FuseTMountProvider"),
            Some("fuse-t")
        );
        assert_eq!(alias_for("org.example.Custom"), None);
    }

    /// The two alias tables -- this one and `cryptomator_mount::registry`'s -- are maintained by
    /// hand and have to agree: the CLI resolves `--mounter` here, and `crypto mounters` labels the
    /// services with the registry's names. A class that only one of them knows would print a row
    /// without an alias, or accept a name that resolves to nothing.
    #[test]
    fn both_alias_tables_name_the_same_classes() {
        use cryptomator_mount::registry::alias_for_class;

        for (alias, class) in MOUNTER_ALIASES {
            assert_eq!(
                alias_for_class(class),
                Some(*alias),
                "the mount registry does not know {alias} -> {class}"
            );
            assert_eq!(
                resolve_mounter(alias).expect("a known alias resolves"),
                *class,
                "round trip for {alias}"
            );
        }
        // And the other way round: every alias the registry hands to `crypto mounters` is one the
        // CLI accepts back.
        for service in cryptomator_mount::registry::all_services() {
            let class = service.java_class_name();
            let Some(alias) = alias_for_class(class) else {
                continue;
            };
            assert_eq!(
                resolve_mounter(alias).expect("the registry's alias resolves"),
                class,
                "{alias} is printed by `crypto mounters` but unknown to --mounter"
            );
        }
    }
}
