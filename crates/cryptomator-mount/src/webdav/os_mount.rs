//! The two WebDAV mount services that additionally ask the operating system to mount the URL:
//! `MacAppleScriptMounter` (`osascript`, `diskutil`) and `LinuxGioMounter` (`gio`).
//!
//! Both start the very server [`crate::webdav::fallback::FallbackMounter`] starts -- same builder,
//! same context path rules -- and then run one command. The difference the user sees is the mount
//! point: a real directory (`/Volumes/Secret`, `/run/user/1000/gvfs/dav:host=…`) instead of a URL.
//!
//! Deliberately **not** ported: Cryptomator runs `security add-internet-password` before the
//! AppleScript mount so macOS does not ask the user to confirm the anonymous login. Writing to the
//! keychain is M6's decision (ruling 3), so macOS asks instead.
use crate::api::{
    Mount, MountBuilder, MountCapability, MountError, MountService, Mountpoint, UnmountError,
};
use crate::process::{probe_command, run_command, run_unmount_command};
use crate::registry::{LINUX_GIO_CLASS, MAC_APPLESCRIPT_CLASS};
use crate::webdav::fallback::WebDavMountBuilder;
use crate::webdav::server::WebDavServerHandle;
use cryptomator_core::fs::CryptoFs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

/// Java's `getDefaultLoopbackPort()` for both OS mounters.
const DEFAULT_OS_PORT: u16 = 42427;
/// `ProcessUtil.waitFor(mountProcess, 120, SECONDS)` -- the user may have to confirm the
/// connection, and issue #107 made Cryptomator raise this to two minutes.
const APPLESCRIPT_MOUNT_TIMEOUT: Duration = Duration::from_secs(120);
/// `ProcessUtil.waitFor(verifyProcess, 10, SECONDS)`.
const VERIFY_TIMEOUT: Duration = Duration::from_secs(10);
/// `ProcessUtil.waitFor(mountProcess, 30, SECONDS)` for `gio mount`.
const GIO_MOUNT_TIMEOUT: Duration = Duration::from_secs(30);
/// How long the probes in `is_supported` may take; they run on every `crypto mounters` call.
/// Java allows its (broken, see [`LinuxGioMounter::is_supported`]) `gio` check the same 500 ms.
const PROBE_TIMEOUT: Duration = Duration::from_millis(500);
/// Stderr fragments that mean "there was nothing left to unmount".
const TOLERATED_UNMOUNT: &[&str] = &[
    "not currently mounted",
    "not mounted",
    "no such file or directory",
];

const APPLESCRIPT_CAPABILITIES: &[MountCapability] = &[
    MountCapability::LoopbackPort,
    MountCapability::UnmountForced,
    MountCapability::VolumeId,
    MountCapability::VolumeName,
];

const GIO_CAPABILITIES: &[MountCapability] = &[
    MountCapability::LoopbackPort,
    MountCapability::MountToSystemChosenPath,
    MountCapability::VolumeId,
];

/// `mount volume "<uri>"` through AppleScript, the way Finder does it.
#[derive(Debug, Clone, Copy, Default)]
pub struct MacAppleScriptMounter;

impl MountService for MacAppleScriptMounter {
    fn java_class_name(&self) -> &'static str {
        MAC_APPLESCRIPT_CLASS
    }

    fn display_name(&self) -> &'static str {
        "WebDAV (AppleScript)"
    }

    fn priority(&self) -> u32 {
        50
    }

    /// Java compares `os.version` against `10.10`; every macOS this binary runs on is newer, so
    /// what is actually worth checking is that `osascript` is there.
    fn is_supported(&self) -> bool {
        cfg!(target_os = "macos")
            && probe_command("/usr/bin/osascript", &["-e", "return 1"], PROBE_TIMEOUT)
    }

    fn capabilities(&self) -> &'static [MountCapability] {
        APPLESCRIPT_CAPABILITIES
    }

    fn default_loopback_port(&self) -> Option<u16> {
        Some(DEFAULT_OS_PORT)
    }

    fn default_mount_flags(&self) -> String {
        String::new()
    }

    /// A real volume in `/Volumes`, so the daemon may wait for it in the mount table. The mount
    /// only succeeds when [`mount_point_in`] found that path in `mount`'s own output, i.e. when
    /// the kernel already knows about it.
    fn appears_in_mount_table(&self) -> bool {
        true
    }

    fn read_only_follows_file_system(&self) -> bool {
        true
    }

    fn for_file_system(&self, fs: Arc<CryptoFs>) -> Box<dyn MountBuilder> {
        Box::new(WebDavMountBuilder::new(
            fs,
            DEFAULT_OS_PORT,
            // `MountBuilderImpl.getContextPath()` = `volumeId + "/" + volumeName`.
            true,
            Box::new(applescript_mount),
        ))
    }

    /// `diskutil umount` needs nothing but the path, so a volume a crashed daemon left behind can
    /// be taken down by `crypto lock --force`.
    fn unmount_path(&self, mountpoint: &Path, forced: bool) -> Result<(), UnmountError> {
        diskutil_umount(mountpoint, forced)
    }
}

/// `gio mount "dav://…"`, the GNOME/GVfs way.
#[derive(Debug, Clone, Copy, Default)]
pub struct LinuxGioMounter;

impl MountService for LinuxGioMounter {
    fn java_class_name(&self) -> &'static str {
        LINUX_GIO_CLASS
    }

    fn display_name(&self) -> &'static str {
        "WebDAV (gio)"
    }

    fn priority(&self) -> u32 {
        50
    }

    /// Not KDE, a `gvfs` directory for this user, and `gio` on the `PATH`.
    ///
    /// The third check is a **deliberate deviation**: Java runs
    /// `new ProcessBuilder("test", " \`command -v gio\`")`, whose single quoted argument makes
    /// `test` see one non-empty string and exit `0` whatever is installed -- it checks nothing.
    /// `gio --version` checks what the comment there says it wants to check.
    fn is_supported(&self) -> bool {
        cfg!(target_os = "linux")
            && gio_supported_with(
                &std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default(),
                &gvfs_dir(),
                || probe_command("gio", &["--version"], PROBE_TIMEOUT),
            )
    }

    fn capabilities(&self) -> &'static [MountCapability] {
        GIO_CAPABILITIES
    }

    fn default_loopback_port(&self) -> Option<u16> {
        Some(DEFAULT_OS_PORT)
    }

    fn default_mount_flags(&self) -> String {
        String::new()
    }

    /// A gvfs mount is a directory *inside* the one `gvfsd-fuse` mounted, not a mount point of its
    /// own: `/proc/mounts` names `/run/user/<uid>/gvfs` and nothing below it. A daemon waiting for
    /// [`crate::mounttab::is_mountpoint`] on the volume's path would wait forever -- and with no
    /// gvfs directory found there is not even a path, only [`Mountpoint::Uri`].
    fn appears_in_mount_table(&self) -> bool {
        false
    }

    fn read_only_follows_file_system(&self) -> bool {
        true
    }

    fn for_file_system(&self, fs: Arc<CryptoFs>) -> Box<dyn MountBuilder> {
        Box::new(WebDavMountBuilder::new(
            fs,
            DEFAULT_OS_PORT,
            false,
            Box::new(gio_mount),
        ))
    }
}

/// The three conditions Java's `LinuxGioMounter.isSupported()` checks, as a pure function so both
/// the KDE exclusion and the missing-`gvfs` case are testable on any host.
///
/// KDE is excluded because its gvfs integration mounts the share and then cannot read it
/// (cryptomator/cryptomator#1381).
fn gio_supported_with(desktop: &str, gvfs_dir: &Path, gio_present: impl Fn() -> bool) -> bool {
    desktop != "KDE" && gvfs_dir.is_dir() && gio_present()
}

/// `/run/user/<uid>/gvfs`, where gvfs puts its mounts.
fn gvfs_dir() -> PathBuf {
    PathBuf::from("/run/user")
        .join(nix::unistd::geteuid().as_raw().to_string())
        .join("gvfs")
}

/// What happens after the server is up on macOS: mount, verify, find the mount point.
fn applescript_mount(server: WebDavServerHandle) -> Result<Box<dyn Mount>, MountError> {
    let uri = server.root_uri();
    let mut mount = Command::new("/usr/bin/osascript");
    mount.arg("-e").arg(format!("mount volume \"{uri}\""));
    let mounted = run_command(mount, APPLESCRIPT_MOUNT_TIMEOUT)?;
    if !mounted.success() {
        return Err(MountError::Failed(format!(
            "osascript could not mount {uri}: {}",
            first_line(&mounted.stderr)
        )));
    }
    let mut verify = Command::new("/bin/sh");
    verify.arg("-c").arg(format!("mount | grep \"{uri}\""));
    let listed = run_command(verify, VERIFY_TIMEOUT)?;
    let Some(path) = mount_point_in(&listed.stdout, &uri) else {
        // Java throws here too. The volume may well be mounted; say so, because nothing in this
        // process can take it down without a path.
        return Err(MountError::Failed(format!(
            "mounted {uri}, but the mount point is not in the mount table; \
             eject the volume in Finder if it is still there"
        )));
    };
    log::debug!("mounted {uri} on {}", path.display());
    Ok(Box::new(AppleScriptMount {
        server: Some(server),
        path,
    }))
}

/// What happens after the server is up on Linux: `gio mount`, then find the gvfs directory.
fn gio_mount(server: WebDavServerHandle) -> Result<Box<dyn Mount>, MountError> {
    let http_uri = server.root_uri();
    let uri = dav_uri(&http_uri);
    let mut mount = Command::new("sh");
    mount.arg("-c").arg(format!("gio mount \"{uri}\""));
    let mounted = run_command(mount, GIO_MOUNT_TIMEOUT)?;
    if !mounted.success() {
        return Err(MountError::Failed(format!(
            "gio could not mount {uri}: {}",
            first_line(&mounted.stderr)
        )));
    }
    // The directory is named like `dav:host=127.0.0.1,port=42427,ssl=false,prefix=%2Fdix6BcCSNSl5`.
    let host = server.local_addr().ip().to_string();
    let path = gvfs_mount_point(&gvfs_dir(), &host, server.context_path());
    if path.is_none() {
        // Java fails the mount here; `gio mount -u` addresses the volume by URI, so this one can
        // still be taken down -- it only has no path to offer.
        log::warn!(
            "mounted {uri}, but no matching directory appeared in {}; reporting the URL instead",
            gvfs_dir().display()
        );
    }
    Ok(Box::new(GioMount {
        server: Some(server),
        uri,
        http_uri,
        path,
    }))
}

/// The gvfs directory that belongs to `host` and `context_path`, if it is there.
fn gvfs_mount_point(gvfs_dir: &Path, host: &str, context_path: &str) -> Option<PathBuf> {
    let encoded = form_urlencode(context_path);
    let entries = std::fs::read_dir(gvfs_dir).ok()?;
    entries.flatten().find_map(|entry| {
        let name = entry.file_name().to_string_lossy().into_owned();
        (name.contains(host) && name.contains(&encoded)).then(|| entry.path())
    })
}

/// `http://…` -> `dav://…`, Java's `new URI("dav", uri.getSchemeSpecificPart(), null)`.
pub fn dav_uri(http_uri: &str) -> String {
    match http_uri.split_once("://") {
        Some((_, rest)) => format!("dav://{rest}"),
        None => http_uri.to_owned(),
    }
}

/// The mount point in `mount` output, Java's `.* on (\S+) \(.*\)` applied to the line that names
/// `uri`.
///
/// The Java pattern is greedy, so the **last** ` on ` of a line wins; the token after it is the
/// mount point, and it has to be followed by ` (` and a closing `)` -- that is what tells a mount
/// point apart from a volume name that happens to contain " on ".
pub fn mount_point_in(stdout: &str, uri: &str) -> Option<PathBuf> {
    stdout
        .lines()
        .filter(|line| line.contains(uri))
        .find_map(|line| {
            let mut rest = line;
            let mut found = None;
            while let Some(at) = rest.rfind(" on ") {
                let tail = &rest[at + " on ".len()..];
                let mut parts = tail.splitn(2, ' ');
                let candidate = parts.next().unwrap_or_default();
                let options = parts.next().unwrap_or_default();
                if !candidate.is_empty() && options.starts_with('(') && options.contains(')') {
                    found = Some(PathBuf::from(candidate));
                    break;
                }
                rest = &rest[..at];
            }
            found
        })
}

/// `java.net.URLEncoder.encode(raw, UTF_8)`: `A-Z a-z 0-9 . - * _` survive, a space becomes `+`,
/// everything else becomes upper-case percent escapes of its UTF-8 bytes.
///
/// This is *not* RFC 3986 percent encoding -- gvfs names its directories with exactly what Java
/// produces, and `/` must become `%2F` while `*` must stay `*`.
pub fn form_urlencode(raw: &str) -> String {
    use std::fmt::Write;

    let mut out = String::with_capacity(raw.len());
    for byte in raw.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'*' | b'_' => {
                out.push(*byte as char);
            }
            b' ' => out.push('+'),
            other => {
                // Writing into a `String` cannot fail; the result is discarded rather than
                // unwrapped so no input can panic here.
                let _ = write!(out, "%{other:02X}");
            }
        }
    }
    out
}

/// The first non-empty line of a command's stderr, for a one-line error message.
fn first_line(stderr: &str) -> String {
    stderr
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("no output")
        .to_owned()
}

/// `diskutil umount [force] "<path>"`, Java's unmount command verbatim.
///
/// # Errors
/// See [`run_unmount_command`]; a path that is no longer a directory is success.
fn diskutil_umount(path: &Path, forced: bool) -> Result<(), UnmountError> {
    if !path.is_dir() {
        // "unmounting a mounted drive will delete the associated mountpoint" -- Java's own note.
        log::debug!("volume at {} already unmounted", path.display());
        return Ok(());
    }
    let force = if forced { "force " } else { "" };
    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg(format!("diskutil umount {force}\"{}\"", path.display()));
    run_unmount_command(command, TOLERATED_UNMOUNT)
}

/// A volume `osascript` mounted.
///
/// **Dropping or closing it blocks**, for up to 65 s in the worst case: the unmount command gets
/// [`crate::process::UNMOUNT_COMMAND_TIMEOUT`], and stopping the server behind it runs
/// [`WebDavServerHandle::stop`]. Never from an async context.
#[derive(Debug)]
struct AppleScriptMount {
    server: Option<WebDavServerHandle>,
    path: PathBuf,
}

impl AppleScriptMount {
    fn stop_server(&mut self) -> Result<(), UnmountError> {
        let Some(mut server) = self.server.take() else {
            return Ok(());
        };
        server
            .stop()
            .map_err(|e| UnmountError::Failed(e.to_string()))
    }

    fn take_down(&mut self, forced: bool) -> Result<(), UnmountError> {
        diskutil_umount(&self.path, forced)?;
        self.stop_server()
    }
}

impl Mount for AppleScriptMount {
    fn mountpoint(&self) -> Mountpoint {
        Mountpoint::Path(self.path.clone())
    }

    fn unmount(&mut self) -> Result<(), UnmountError> {
        self.take_down(false)
    }

    fn unmount_forced(&mut self) -> Result<(), UnmountError> {
        self.take_down(true)
    }

    fn close(mut self: Box<Self>) -> Result<(), UnmountError> {
        // Only unmount what is still mounted: `close` also runs after a successful `unmount`.
        self.take_down(false)
    }
}

/// A volume `gio` mounted.
///
/// **Dropping or closing it blocks**, see [`AppleScriptMount`].
#[derive(Debug)]
struct GioMount {
    server: Option<WebDavServerHandle>,
    /// `dav://…`, the address `gio mount -u` takes.
    uri: String,
    /// `http://…`, reported when the gvfs directory could not be found.
    http_uri: String,
    path: Option<PathBuf>,
}

impl GioMount {
    fn stop_server(&mut self) -> Result<(), UnmountError> {
        let Some(mut server) = self.server.take() else {
            return Ok(());
        };
        server
            .stop()
            .map_err(|e| UnmountError::Failed(e.to_string()))
    }
}

impl Mount for GioMount {
    /// The gvfs directory, or the URL when it could never be found -- reporting a path that does
    /// not exist would make `crypto status` claim a mount point nobody can open.
    fn mountpoint(&self) -> Mountpoint {
        match &self.path {
            Some(path) => Mountpoint::Path(path.clone()),
            None => Mountpoint::Uri(self.http_uri.clone()),
        }
    }

    fn unmount(&mut self) -> Result<(), UnmountError> {
        // `gio mount -u` addresses the volume by URI, so it works even without the gvfs path.
        if self.path.as_deref().is_none_or(Path::is_dir) {
            let mut command = Command::new("sh");
            command
                .arg("-c")
                .arg(format!("gio mount -u \"{}\"", self.uri));
            run_unmount_command(command, TOLERATED_UNMOUNT)?;
        }
        self.stop_server()
    }

    /// gio has no forced unmount, and neither does Java's `MountImpl`; the trait's default says
    /// so, and [`MountService::capabilities`] does not advertise `UNMOUNT_FORCED`.
    fn close(mut self: Box<Self>) -> Result<(), UnmountError> {
        Mount::unmount(&mut *self)
    }
}

#[cfg(all(test, feature = "webdav"))]
mod tests {
    use super::*;
    use crate::registry::{alias_for_class, all_services, LINUX_GIO_CLASS, MAC_APPLESCRIPT_CLASS};

    /// One line of `mount` output as macOS prints it for a WebDAV volume.
    const MOUNT_LINE: &str =
        "http://127.0.0.1:42427/dix6BcCSNSl5/Secret on /Volumes/Secret (webdav, nodev, noexec, nosuid, read-only, mounted by me)";

    #[test]
    fn the_mount_point_is_the_token_between_on_and_the_options() {
        let uri = "http://127.0.0.1:42427/dix6BcCSNSl5/Secret";
        assert_eq!(
            mount_point_in(MOUNT_LINE, uri),
            Some(PathBuf::from("/Volumes/Secret"))
        );
        // Several volumes, only one of them ours.
        let noise = format!("/dev/disk3s1 on / (apfs, sealed)\n{MOUNT_LINE}\n");
        assert_eq!(
            mount_point_in(&noise, uri),
            Some(PathBuf::from("/Volumes/Secret"))
        );
        // A line for a different vault is not ours.
        assert_eq!(
            mount_point_in(MOUNT_LINE, "http://127.0.0.1:42427/other"),
            None
        );
        assert_eq!(mount_point_in("", uri), None);
        assert_eq!(mount_point_in("no match here", uri), None);
        // Greedy like Java's `.* on (\S+) \(.*\)`: the *last* " on " wins.
        let tricky = "http://h/a on b on /Volumes/x (webdav)";
        assert_eq!(
            mount_point_in(tricky, "http://h/a"),
            Some(PathBuf::from("/Volumes/x"))
        );
        // A candidate that is not followed by ` (options)` is no mount point, and Java's regex
        // finds nothing here either: every ` on ` leaves the `\(.*\)` tail unmatched.
        assert_eq!(
            mount_point_in("http://h/a on /Volumes/Later on (webdav)", "http://h/a"),
            None
        );
    }

    #[test]
    fn the_gvfs_directory_name_is_matched_with_java_url_encoding() {
        // java.net.URLEncoder.encode("/dix6BcCSNSl5/My Vault", UTF-8)
        assert_eq!(
            form_urlencode("/dix6BcCSNSl5/My Vault"),
            "%2Fdix6BcCSNSl5%2FMy+Vault"
        );
        assert_eq!(form_urlencode("a-b_c.d*e"), "a-b_c.d*e");
        assert_eq!(form_urlencode("caf\u{e9}"), "caf%C3%A9");
        assert_eq!(form_urlencode(""), "");
    }

    /// The directory gvfs creates is found by host *and* encoded prefix; a neighbouring mount of
    /// another vault -- or of the same path on another host -- is not ours.
    #[test]
    fn the_gvfs_mount_point_is_the_entry_naming_this_host_and_this_context_path() {
        let dir = tempfile::tempdir().expect("temp dir");
        let ours = dir
            .path()
            .join("dav:host=127.0.0.1,port=42427,ssl=false,prefix=%2Fdix6BcCSNSl5");
        for name in [
            "dav:host=127.0.0.1,port=42427,ssl=false,prefix=%2Fother",
            "dav:host=192.168.0.5,port=42427,ssl=false,prefix=%2Fdix6BcCSNSl5",
        ] {
            std::fs::create_dir(dir.path().join(name)).expect("neighbour");
        }
        assert_eq!(
            gvfs_mount_point(dir.path(), "127.0.0.1", "/dix6BcCSNSl5"),
            None,
            "nothing of ours is there yet"
        );
        std::fs::create_dir(&ours).expect("our mount");
        assert_eq!(
            gvfs_mount_point(dir.path(), "127.0.0.1", "/dix6BcCSNSl5"),
            Some(ours)
        );
        assert_eq!(
            gvfs_mount_point(Path::new("/definitely/not/here"), "127.0.0.1", "/x"),
            None,
            "a missing gvfs directory is not an error"
        );
    }

    #[test]
    fn the_dav_uri_only_swaps_the_scheme() {
        assert_eq!(
            dav_uri("http://127.0.0.1:42427/dix6BcCSNSl5"),
            "dav://127.0.0.1:42427/dix6BcCSNSl5"
        );
        assert_eq!(dav_uri("dav://already"), "dav://already");
    }

    #[test]
    fn the_applescript_service_mirrors_the_java_one() {
        let service = MacAppleScriptMounter;
        assert_eq!(service.java_class_name(), MAC_APPLESCRIPT_CLASS);
        assert_eq!(service.display_name(), "WebDAV (AppleScript)");
        assert_eq!(service.priority(), 50);
        assert_eq!(
            service.capabilities(),
            &[
                MountCapability::LoopbackPort,
                MountCapability::UnmountForced,
                MountCapability::VolumeId,
                MountCapability::VolumeName,
            ]
        );
        assert_eq!(service.default_loopback_port(), Some(42427));
        assert_eq!(service.default_mount_flags(), "");
        assert!(service.appears_in_mount_table(), "a volume, not a URL");
        assert!(service.read_only_follows_file_system());
        assert_eq!(service.is_supported(), cfg!(target_os = "macos"));
    }

    /// Every builder accepts exactly what its service advertises. The AppleScript one is the only
    /// WebDAV builder that takes a volume name -- which is also what makes it append it to the
    /// context path, the whole reason [`WebDavMountBuilder`] carries that switch.
    #[test]
    fn each_builder_accepts_exactly_what_its_service_advertises() {
        let (_vault, fs) = crate::testing::test_fs();
        let mut builder = MacAppleScriptMounter.for_file_system(Arc::clone(&fs));
        builder.set_loopback_port(0).expect("LOOPBACK_PORT");
        builder.set_volume_id("id").expect("VOLUME_ID");
        builder.set_volume_name("My Vault").expect("VOLUME_NAME");
        assert!(builder.set_read_only(true).is_err());
        assert!(builder.set_mountpoint(Path::new("/mnt")).is_err());

        let mut builder = LinuxGioMounter.for_file_system(fs);
        builder.set_loopback_port(0).expect("LOOPBACK_PORT");
        builder.set_volume_id("id").expect("VOLUME_ID");
        assert!(
            builder.set_volume_name("My Vault").is_err(),
            "gio does not advertise VOLUME_NAME"
        );
    }

    #[test]
    fn the_gio_service_mirrors_the_java_one() {
        let service = LinuxGioMounter;
        assert_eq!(service.java_class_name(), LINUX_GIO_CLASS);
        assert_eq!(service.display_name(), "WebDAV (gio)");
        assert_eq!(service.priority(), 50);
        assert_eq!(
            service.capabilities(),
            &[
                MountCapability::LoopbackPort,
                MountCapability::MountToSystemChosenPath,
                MountCapability::VolumeId,
            ]
        );
        assert_eq!(service.default_loopback_port(), Some(42427));
        assert_eq!(service.default_mount_flags(), "");
        assert!(
            !service.appears_in_mount_table(),
            "a directory inside the gvfs mount is not a mount point of its own"
        );
        assert!(service.read_only_follows_file_system());
        assert!(
            service
                .unmount_path(Path::new("/run/user/1000/gvfs/x"), false)
                .is_err(),
            "gio unmounts by URI, so a crashed daemon's mount cannot be taken down by path"
        );
        #[cfg(not(target_os = "linux"))]
        assert!(!service.is_supported(), "gio is a Linux desktop thing");
    }

    #[test]
    fn kde_is_excluded_and_a_missing_gvfs_directory_is_too() {
        assert!(!gio_supported_with("KDE", Path::new("/"), || true));
        assert!(!gio_supported_with(
            "GNOME",
            Path::new("/definitely/not/here"),
            || true
        ));
        assert!(!gio_supported_with("GNOME", Path::new("/"), || false));
        assert!(gio_supported_with("GNOME", Path::new("/"), || true));
    }

    /// The OS mounter sits between the FUSE back ends and the fallback, and both new aliases
    /// resolve. Spelled out per feature set like the registry's own test, so a `webdav`-only
    /// build pins the order too.
    #[test]
    fn the_registry_ranks_the_os_mounters_above_the_fallback() {
        let classes: Vec<&str> = all_services().iter().map(|s| s.java_class_name()).collect();
        let mut expected: Vec<&str> = Vec::new();
        #[cfg(all(feature = "fuse", target_os = "macos"))]
        expected.extend([
            crate::registry::MAC_FUSE_CLASS,
            crate::registry::FUSE_T_CLASS,
        ]);
        #[cfg(all(feature = "fuse", target_os = "linux"))]
        expected.extend([crate::registry::LINUX_FUSE_CLASS]);
        #[cfg(target_os = "macos")]
        expected.extend([MAC_APPLESCRIPT_CLASS]);
        #[cfg(target_os = "linux")]
        expected.extend([LINUX_GIO_CLASS]);
        expected.extend([
            crate::registry::FALLBACK_WEBDAV_CLASS,
            crate::registry::NULL_MOUNTER_CLASS,
        ]);
        assert_eq!(classes, expected);
        assert_eq!(
            alias_for_class(MAC_APPLESCRIPT_CLASS),
            Some("webdav-applescript")
        );
        assert_eq!(alias_for_class(LINUX_GIO_CLASS), Some("webdav-gio"));
        // The class a `--mounter` setting names resolves to the service, not just to a constant.
        #[cfg(target_os = "macos")]
        assert_eq!(
            crate::registry::service_by_class(MAC_APPLESCRIPT_CLASS).map(|s| s.display_name()),
            Some("WebDAV (AppleScript)")
        );
        #[cfg(target_os = "linux")]
        assert_eq!(
            crate::registry::service_by_class(LINUX_GIO_CLASS).map(|s| s.display_name()),
            Some("WebDAV (gio)")
        );
    }
}
