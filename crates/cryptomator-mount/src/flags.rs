//! Mount flags: the free-form string a user passes with `--mount-flags`, split and classified the
//! way Cryptomator's mount providers do it.
//!
//! Cryptomator hands the flags to libfuse's high-level API, which understands both kernel mount
//! options and libfuse's own options. We drive the kernel (or FUSE-T) directly, so the flags are
//! split in two here: those the FUSE adapter itself has to honour ([`AdapterOptions`]) and those
//! that go to the mount syscall ([`MountFlags::linux_mount_options`]).
use crate::api::MountError;
use std::collections::HashSet;
use std::time::Duration;

/// The default `attr_timeout`/`entry_timeout`, matching libfuse's own default of one second.
pub const DEFAULT_ATTR_TIMEOUT: Duration = Duration::from_secs(1);

/// Splits a mount flag string the way Cryptomator does: at whitespace that precedes a `-`, so
/// values may contain spaces (`-ovolname=My Vault`). Blank tokens are dropped and duplicates are
/// removed, keeping the position of the first occurrence.
pub fn parse_mount_flags(flags: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for token in split_before_dash(flags) {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        if seen.insert(token.to_owned()) {
            out.push(token.to_owned());
        }
    }
    out
}

/// Splits at every run of ASCII whitespace that is directly followed by `-`, i.e. Java's
/// `split("\\s+(?=-)")`. Slicing at ASCII bytes is UTF-8 safe: an ASCII byte never occurs inside a
/// multi-byte sequence.
fn split_before_dash(s: &str) -> Vec<&str> {
    let bytes = s.as_bytes();
    let mut parts = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        if !bytes[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let gap = i;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if bytes.get(i) == Some(&b'-') {
            parts.push(&s[start..gap]);
            start = i;
        }
    }
    parts.push(&s[start..]);
    parts
}

/// The uid and gid of the current process, the defaults for `-ouid=`/`-ogid=`.
pub fn current_uid_gid() -> (u32, u32) {
    (
        nix::unistd::geteuid().as_raw(),
        nix::unistd::getegid().as_raw(),
    )
}

/// Options the FUSE adapter has to honour itself: libfuse's high-level API applies them in
/// userspace, so the kernel never sees them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterOptions {
    /// Owner reported for every file (`-ouid=`).
    pub uid: u32,
    /// Group reported for every file (`-ogid=`).
    pub gid: u32,
    /// How long the kernel may cache attributes (`-oattr_timeout=`).
    pub attr_timeout: Duration,
    /// How long the kernel may cache lookups (`-oentry_timeout=`, defaults to `attr_timeout`).
    pub entry_timeout: Duration,
    /// The volume name shown by the OS (`-ovolname=`, macOS).
    pub volname: Option<String>,
    /// Hide AppleDouble (`._*`) files (`-onoappledouble`, macOS).
    pub no_apple_double: bool,
    /// Let the kernel do permission checks (`-odefault_permissions`).
    pub default_permissions: bool,
    /// Allow other users to access the mount (`-oallow_other`).
    pub allow_other: bool,
    /// Allow root to access the mount (`-oallow_root`).
    pub allow_root: bool,
    /// Unmount automatically when the mounting process exits (`-oauto_unmount`).
    pub auto_unmount: bool,
}

impl AdapterOptions {
    /// The defaults for a mount owned by `uid`/`gid`.
    pub fn for_user(uid: u32, gid: u32) -> Self {
        Self {
            uid,
            gid,
            attr_timeout: DEFAULT_ATTR_TIMEOUT,
            entry_timeout: DEFAULT_ATTR_TIMEOUT,
            volname: None,
            no_apple_double: false,
            default_permissions: false,
            allow_other: false,
            allow_root: false,
            auto_unmount: false,
        }
    }
}

/// A parsed set of mount flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountFlags {
    /// `-r` or `-oro`.
    pub read_only: bool,
    /// Options the adapter applies itself.
    pub adapter: AdapterOptions,
    /// Every other `-o` option, without the `-o` prefix, in the order first seen.
    pub passthrough: Vec<String>,
}

impl MountFlags {
    /// Classifies `flags` (as produced by [`parse_mount_flags`]); `current_uid`/`current_gid` are
    /// the defaults when the flags do not set uid/gid.
    ///
    /// Fails with [`MountError::UnsupportedFlag`] for a flag that is neither `-r` nor `-o…`, and
    /// for a known option whose value does not parse.
    pub fn from_flags(
        flags: &[String],
        current_uid: u32,
        current_gid: u32,
    ) -> Result<Self, MountError> {
        let mut read_only = false;
        let mut adapter = AdapterOptions::for_user(current_uid, current_gid);
        let mut entry_timeout = None;
        let mut passthrough: Vec<String> = Vec::new();
        let mut seen = HashSet::new();

        for flag in flags {
            if flag == "-r" {
                read_only = true;
                continue;
            }
            let Some(option) = flag.strip_prefix("-o") else {
                return Err(MountError::UnsupportedFlag(flag.clone()));
            };
            let (key, value) = match option.split_once('=') {
                Some((k, v)) => (k, Some(v)),
                None => (option, None),
            };
            match (key, value) {
                ("ro", None) => read_only = true,
                ("uid", Some(v)) => adapter.uid = parse_id(flag, v)?,
                ("gid", Some(v)) => adapter.gid = parse_id(flag, v)?,
                ("attr_timeout", Some(v)) => adapter.attr_timeout = parse_seconds(flag, v)?,
                ("entry_timeout", Some(v)) => entry_timeout = Some(parse_seconds(flag, v)?),
                ("volname", Some(v)) => adapter.volname = Some(v.to_owned()),
                ("noappledouble", None) => adapter.no_apple_double = true,
                ("default_permissions", None) => adapter.default_permissions = true,
                ("allow_other", None) => adapter.allow_other = true,
                ("allow_root", None) => adapter.allow_root = true,
                ("auto_unmount", None) => adapter.auto_unmount = true,
                _ => {
                    if seen.insert(option.to_owned()) {
                        passthrough.push(option.to_owned());
                    }
                }
            }
        }
        adapter.entry_timeout = entry_timeout.unwrap_or(adapter.attr_timeout);
        Ok(Self {
            read_only,
            adapter,
            passthrough,
        })
    }

    /// The options to hand to the mount syscall (`fusermount3` on Linux, the FUSE-T/macFUSE mount
    /// helper on macOS).
    ///
    /// The [`AdapterOptions`] are deliberately not among them: `uid`, `gid`, `attr_timeout`,
    /// `entry_timeout`, `volname` and `noappledouble` are libfuse high-level options that the
    /// kernel does not know and `fusermount3` rejects. `allow_other`/`allow_root` are expressed
    /// through fuser's `SessionACL` instead.
    #[cfg(feature = "fuse")]
    pub fn linux_mount_options(&self) -> Vec<fuser::MountOption> {
        use fuser::MountOption;

        let mut options = Vec::with_capacity(self.passthrough.len() + 3);
        if self.read_only {
            options.push(MountOption::RO);
        }
        if self.adapter.default_permissions {
            options.push(MountOption::DefaultPermissions);
        }
        if self.adapter.auto_unmount {
            options.push(MountOption::AutoUnmount);
        }
        for option in &self.passthrough {
            let typed = match option.as_str() {
                "ro" => MountOption::RO,
                "rw" => MountOption::RW,
                "dev" => MountOption::Dev,
                "nodev" => MountOption::NoDev,
                "suid" => MountOption::Suid,
                "nosuid" => MountOption::NoSuid,
                "exec" => MountOption::Exec,
                "noexec" => MountOption::NoExec,
                "atime" => MountOption::Atime,
                "noatime" => MountOption::NoAtime,
                "dirsync" => MountOption::DirSync,
                "sync" => MountOption::Sync,
                "async" => MountOption::Async,
                other => match other.split_once('=') {
                    Some(("fsname", name)) => MountOption::FSName(name.to_owned()),
                    Some(("subtype", name)) => MountOption::Subtype(name.to_owned()),
                    _ => MountOption::CUSTOM(other.to_owned()),
                },
            };
            if !options.contains(&typed) {
                options.push(typed);
            }
        }
        options
    }
}

fn parse_id(flag: &str, value: &str) -> Result<u32, MountError> {
    value
        .parse::<u32>()
        .map_err(|_| MountError::UnsupportedFlag(flag.to_owned()))
}

/// Seconds, decimals included (`5`, `2.5`), as libfuse accepts them.
fn parse_seconds(flag: &str, value: &str) -> Result<Duration, MountError> {
    let seconds = value
        .parse::<f64>()
        .map_err(|_| MountError::UnsupportedFlag(flag.to_owned()))?;
    Duration::try_from_secs_f64(seconds).map_err(|_| MountError::UnsupportedFlag(flag.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_like_java_and_dedups() {
        assert_eq!(
            parse_mount_flags(" -ouid=501 -ogid=20   -ouid=501 -r"),
            vec!["-ouid=501", "-ogid=20", "-r"]
        );
        assert_eq!(parse_mount_flags(""), Vec::<String>::new());
        assert_eq!(
            parse_mount_flags("-ovolname=My Vault -oattr_timeout=5"),
            vec!["-ovolname=My Vault", "-oattr_timeout=5"]
        );
    }

    #[test]
    fn classifies_adapter_and_passthrough_options() {
        let f = MountFlags::from_flags(
            &parse_mount_flags(
                "-oauto_unmount -ouid=501 -ogid=20 -oattr_timeout=5 -ovolname=Secret -r -ononamedattr -orwsize=262144",
            ),
            1000,
            1000,
        )
        .expect("flags parse");
        assert!(f.read_only);
        assert_eq!((f.adapter.uid, f.adapter.gid), (501, 20));
        assert_eq!(f.adapter.attr_timeout, Duration::from_secs(5));
        assert_eq!(f.adapter.entry_timeout, Duration::from_secs(5));
        assert_eq!(f.adapter.volname.as_deref(), Some("Secret"));
        assert!(f.adapter.auto_unmount);
        assert_eq!(f.passthrough, vec!["nonamedattr", "rwsize=262144"]);

        let d = MountFlags::from_flags(&[], 7, 8).expect("empty flags parse");
        assert_eq!(
            (d.adapter.uid, d.adapter.gid, d.adapter.attr_timeout),
            (7, 8, Duration::from_secs(1))
        );
        assert!(matches!(
            MountFlags::from_flags(&parse_mount_flags("--weird"), 0, 0),
            Err(MountError::UnsupportedFlag(_))
        ));
        assert!(matches!(
            MountFlags::from_flags(&parse_mount_flags("-ouid=abc"), 0, 0),
            Err(MountError::UnsupportedFlag(_))
        ));
    }

    #[cfg(feature = "fuse")]
    #[test]
    fn linux_mount_options_keep_kernel_options_and_drop_adapter_options() {
        let f = MountFlags::from_flags(
            &parse_mount_flags(
                "-oauto_unmount -ouid=501 -oattr_timeout=5 -ovolname=Secret -r -ononamedattr -ofsname=cryptoFs -onoatime",
            ),
            1000,
            1000,
        )
        .expect("flags parse");
        let opts = f.linux_mount_options();
        assert!(
            opts.contains(&fuser::MountOption::RO)
                && opts.contains(&fuser::MountOption::AutoUnmount)
        );
        assert!(opts.contains(&fuser::MountOption::CUSTOM("nonamedattr".into())));
        assert!(opts.contains(&fuser::MountOption::FSName("cryptoFs".into())));
        assert!(opts.contains(&fuser::MountOption::NoAtime));
        assert!(!opts
            .iter()
            .any(|o| matches!(o, fuser::MountOption::CUSTOM(s) if s.starts_with("uid="))));
        for forbidden in [
            "uid=",
            "gid=",
            "attr_timeout=",
            "entry_timeout=",
            "volname=",
            "noappledouble",
        ] {
            assert!(
                !opts.iter().any(
                    |o| matches!(o, fuser::MountOption::CUSTOM(s) if s.starts_with(forbidden))
                ),
                "{forbidden} must not reach the mount syscall"
            );
        }
    }

    #[test]
    fn entry_timeout_can_be_set_independently_and_accepts_decimals() {
        let f = MountFlags::from_flags(
            &parse_mount_flags("-oattr_timeout=2.5 -oentry_timeout=0"),
            0,
            0,
        )
        .expect("flags parse");
        assert_eq!(f.adapter.attr_timeout, Duration::from_millis(2500));
        assert_eq!(f.adapter.entry_timeout, Duration::ZERO);
        assert!(matches!(
            MountFlags::from_flags(&parse_mount_flags("-oattr_timeout=-1"), 0, 0),
            Err(MountError::UnsupportedFlag(_))
        ));
    }

    #[test]
    fn ro_flavours_and_remaining_adapter_switches() {
        let f = MountFlags::from_flags(
            &parse_mount_flags(
                "-oro -oallow_other -oallow_root -odefault_permissions -onoappledouble",
            ),
            0,
            0,
        )
        .expect("flags parse");
        assert!(f.read_only);
        assert!(f.adapter.allow_other && f.adapter.allow_root);
        assert!(f.adapter.default_permissions && f.adapter.no_apple_double);
        assert!(f.passthrough.is_empty());
    }

    #[test]
    fn current_uid_gid_matches_the_process() {
        let (uid, gid) = current_uid_gid();
        assert_eq!(uid, nix::unistd::geteuid().as_raw());
        assert_eq!(gid, nix::unistd::getegid().as_raw());
    }
}
