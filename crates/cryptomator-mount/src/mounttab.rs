//! Probing the system mount table.
//!
//! Used to tell a live mount from a stale one: after a crash the CLI's state directory may still
//! claim a mount point that the kernel no longer knows about.
use std::path::{Path, PathBuf};

/// Every path the system currently reports as a mount point.
///
/// Reads `/proc/self/mountinfo` on Linux and runs `mount` on macOS; on other targets the list is
/// empty. An unreadable mount table yields an empty list rather than an error - callers only ask
/// whether a specific path is mounted, and "unknown" is safest reported as "not mounted".
pub fn mounted_paths() -> Vec<PathBuf> {
    platform_mounted_paths()
}

/// Whether `path` is a mount point according to [`mounted_paths`].
///
/// Paths are compared canonicalised where possible; a path that cannot be canonicalised (a broken
/// mount, for instance) is compared as given, since the mount table lists it literally.
pub fn is_mountpoint(path: &Path) -> bool {
    let target = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if target == Path::new("/") {
        return true;
    }
    mounted_paths().iter().any(|entry| {
        entry == &target || std::fs::canonicalize(entry).is_ok_and(|canonical| canonical == target)
    })
}

/// Mount points from the contents of `/proc/self/mountinfo`: field 5 of each line, with
/// `\040`-style octal escapes decoded.
pub fn parse_mountinfo(mountinfo: &str) -> Vec<PathBuf> {
    mountinfo
        .lines()
        .filter_map(|line| line.split_whitespace().nth(4))
        .map(|field| PathBuf::from(unescape_octal(field)))
        .collect()
}

/// Mount points from the output of `mount(8)`: lines of the form
/// `<source> on <path> (<options>)`.
pub fn parse_macos_mount(output: &str) -> Vec<PathBuf> {
    output
        .lines()
        .filter_map(|line| {
            let start = line.find(" on ")? + " on ".len();
            let end = line.rfind(" (")?;
            let path = line.get(start..end)?.trim();
            if path.is_empty() {
                None
            } else {
                Some(PathBuf::from(path))
            }
        })
        .collect()
}

/// Decodes the `\040` (space), `\011` (tab), `\012` (newline) and `\134` (backslash) escapes that
/// the kernel writes into `mountinfo`. Any other backslash sequence is kept verbatim.
fn unescape_octal(field: &str) -> String {
    if !field.contains('\\') {
        return field.to_owned();
    }
    let mut out = String::with_capacity(field.len());
    let mut rest = field;
    while let Some(index) = rest.find('\\') {
        out.push_str(&rest[..index]);
        let escape = rest.get(index + 1..index + 4);
        match escape.and_then(|digits| u8::from_str_radix(digits, 8).ok()) {
            Some(byte) if byte.is_ascii() => {
                out.push(byte as char);
                rest = &rest[index + 4..];
            }
            _ => {
                out.push('\\');
                rest = &rest[index + 1..];
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(target_os = "linux")]
fn platform_mounted_paths() -> Vec<PathBuf> {
    match std::fs::read_to_string("/proc/self/mountinfo") {
        Ok(mountinfo) => parse_mountinfo(&mountinfo),
        Err(error) => {
            log::debug!("cannot read /proc/self/mountinfo: {error}");
            Vec::new()
        }
    }
}

#[cfg(target_os = "macos")]
fn platform_mounted_paths() -> Vec<PathBuf> {
    match std::process::Command::new("/sbin/mount").output() {
        Ok(output) if output.status.success() => {
            parse_macos_mount(&String::from_utf8_lossy(&output.stdout))
        }
        Ok(output) => {
            log::debug!("mount(8) exited with {}", output.status);
            Vec::new()
        }
        Err(error) => {
            log::debug!("cannot run mount(8): {error}");
            Vec::new()
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn platform_mounted_paths() -> Vec<PathBuf> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_linux_mountinfo_and_macos_mount_output() {
        let mi = "36 35 98:0 /mnt1 /mnt/my\\040vault rw,relatime - fuse cryptoFs rw\n37 35 0:1 / /proc rw - proc proc rw\n";
        assert_eq!(
            parse_mountinfo(mi),
            vec![PathBuf::from("/mnt/my vault"), PathBuf::from("/proc")]
        );
        let mo = "/dev/disk3s1s1 on / (apfs, sealed, local)\nfuse-t:/vault on /Users/x/mnt/Vault (nfs, nodev)\n";
        assert_eq!(
            parse_macos_mount(mo),
            vec![PathBuf::from("/"), PathBuf::from("/Users/x/mnt/Vault")]
        );
        assert!(is_mountpoint(Path::new("/")));
        assert!(!is_mountpoint(Path::new("/definitely/not/mounted")));
    }

    #[test]
    fn mountinfo_escapes_and_short_lines() {
        assert_eq!(
            parse_mountinfo("25 0 8:1 / /a\\011b\\134c rw - ext4 /dev/sda1 rw"),
            vec![PathBuf::from("/a\tb\\c")]
        );
        // Truncated lines and blank lines are skipped, not panicked on.
        assert_eq!(parse_mountinfo("25 0 8:1 /\n\n"), Vec::<PathBuf>::new());
        assert_eq!(
            parse_macos_mount("garbage without the marker\n"),
            Vec::<PathBuf>::new()
        );
    }

    #[test]
    fn a_fresh_directory_is_not_a_mountpoint() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(!is_mountpoint(dir.path()));
        assert!(mounted_paths().contains(&PathBuf::from("/")));
    }
}
