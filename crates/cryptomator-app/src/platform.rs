//! The host platform, as an explicit value.
//!
//! The default state directory and the default mount-point directory differ between macOS and
//! Linux. Deriving them from `cfg!(target_os = ...)` inside the functions would compile the other
//! platform's branch away, so the tests could only ever check the branch of the host they run on;
//! the platform is therefore a parameter of the pure defaults and only
//! [`Platform::current`] looks at the build target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Platform {
    /// macOS, where the CLI follows `~/Library/Application Support`.
    MacOs,
    /// Linux (and every other unix this builds on), where the XDG directories apply.
    Linux,
}

impl Platform {
    /// The platform this binary was built for.
    pub fn current() -> Self {
        if cfg!(target_os = "macos") {
            Self::MacOs
        } else {
            Self::Linux
        }
    }

    /// Whether this is macOS.
    pub fn is_macos(self) -> bool {
        matches!(self, Self::MacOs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_current_platform_matches_the_build_target() {
        let expected = if cfg!(target_os = "macos") {
            Platform::MacOs
        } else {
            Platform::Linux
        };
        assert_eq!(Platform::current(), expected);
        assert!(Platform::MacOs.is_macos() && !Platform::Linux.is_macos());
    }
}
