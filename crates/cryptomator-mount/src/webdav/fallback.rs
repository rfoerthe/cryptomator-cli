//! `org.cryptomator.frontend.webdav.mount.FallbackMounter`: the mount service that hands the user
//! a URL and mounts nothing.
//!
//! It is supported everywhere -- no FUSE, no kernel extension, no privileges -- and it is what
//! makes a machine without any of that usable. The builder in here is shared with the two OS
//! mounters in [`crate::webdav::os_mount`], which start the same server and then hand the URL to
//! `osascript` or `gio`; the only differences are the context path (AppleScript appends the volume
//! name) and what happens after the server is up, which the caller passes in as `finish`.
use crate::api::{
    Mount, MountBuilder, MountCapability, MountError, MountService, Mountpoint, UnmountError,
};
use crate::registry::FALLBACK_WEBDAV_CLASS;
use crate::webdav::fs::CryptoDavFs;
use crate::webdav::server::{WebDavServerConfig, WebDavServerHandle};
use crate::webdav::{bind_address, normalize_context_path};
use cryptomator_core::fs::CryptoFs;
use std::sync::Arc;

/// The port the Java fallback mounter defaults to: `0`, i.e. any free one.
const DEFAULT_FALLBACK_PORT: u16 = 0;

/// The capabilities of Java's `FallbackMounter`, verbatim.
const FALLBACK_CAPABILITIES: &[MountCapability] =
    &[MountCapability::LoopbackPort, MountCapability::VolumeId];

/// What a WebDAV service does with the server once it is listening: wrap it in the service's own
/// [`Mount`], after telling the OS about the URL if that is the service's job.
pub type MountFinisher =
    Box<dyn FnOnce(WebDavServerHandle) -> Result<Box<dyn Mount>, MountError> + Send>;

/// The WebDAV back end that only serves a URL.
#[derive(Debug, Clone, Copy, Default)]
pub struct FallbackMounter;

impl MountService for FallbackMounter {
    fn java_class_name(&self) -> &'static str {
        FALLBACK_WEBDAV_CLASS
    }

    fn display_name(&self) -> &'static str {
        "WebDAV (HTTP Address)"
    }

    /// `@Priority(Priority.FALLBACK)` is `Integer.MIN_VALUE`; the lowest this API can express is
    /// `0`, and nothing else but the null mounter sits there.
    fn priority(&self) -> u32 {
        0
    }

    /// Always. A loopback socket needs nothing that could be missing.
    fn is_supported(&self) -> bool {
        true
    }

    fn capabilities(&self) -> &'static [MountCapability] {
        FALLBACK_CAPABILITIES
    }

    fn default_loopback_port(&self) -> Option<u16> {
        Some(DEFAULT_FALLBACK_PORT)
    }

    /// A URL has no mount options.
    fn default_mount_flags(&self) -> String {
        String::new()
    }

    /// Nothing is mounted, so nothing appears in the mount table and nobody may wait for it.
    fn appears_in_mount_table(&self) -> bool {
        false
    }

    fn read_only_follows_file_system(&self) -> bool {
        true
    }

    fn for_file_system(&self, fs: Arc<CryptoFs>) -> Box<dyn MountBuilder> {
        Box::new(WebDavMountBuilder::new(
            fs,
            DEFAULT_FALLBACK_PORT,
            false,
            Box::new(|server| Ok(Box::new(FallbackMount::new(server)) as Box<dyn Mount>)),
        ))
    }
}

/// The builder all three WebDAV services share: it collects the port, the volume id and the
/// volume name, starts the server and lets `finish` turn the running server into a [`Mount`].
pub struct WebDavMountBuilder {
    fs: Arc<CryptoFs>,
    port: u16,
    volume_id: Option<String>,
    volume_name: Option<String>,
    /// `AbstractMountBuilder.getContextPath()`: the AppleScript builder overrides it to
    /// `volumeId + "/" + volumeName`, the other two leave it at the volume id.
    append_volume_name: bool,
    finish: MountFinisher,
}

impl std::fmt::Debug for WebDavMountBuilder {
    /// By hand: the builder holds a boxed closure, which has no `Debug`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebDavMountBuilder")
            .field("port", &self.port)
            .field("volume_id", &self.volume_id)
            .field("volume_name", &self.volume_name)
            .field("append_volume_name", &self.append_volume_name)
            .field("context_path", &self.context_path())
            .finish_non_exhaustive()
    }
}

impl WebDavMountBuilder {
    /// A builder for `fs`. `default_port` is the service's `getDefaultLoopbackPort()`, used until
    /// [`MountBuilder::set_loopback_port`] says otherwise; `append_volume_name` mirrors
    /// `AbstractMountBuilder.getContextPath()`, which only the AppleScript mounter overrides; and
    /// `finish` is what turns the started server into the service's own [`Mount`].
    pub fn new(
        fs: Arc<CryptoFs>,
        default_port: u16,
        append_volume_name: bool,
        finish: MountFinisher,
    ) -> Self {
        Self {
            fs,
            port: default_port,
            volume_id: None,
            volume_name: None,
            append_volume_name,
            finish,
        }
    }

    /// The servlet context path, normalised like `AbstractMountBuilder.normalizedContextPath()`.
    /// Without a volume id that is `/`, i.e. the server root.
    pub fn context_path(&self) -> String {
        let raw = match (&self.volume_id, self.append_volume_name, &self.volume_name) {
            (Some(id), true, Some(name)) => format!("{id}/{name}"),
            (Some(id), _, _) => id.clone(),
            (None, _, _) => String::new(),
        };
        normalize_context_path(&raw)
    }
}

impl MountBuilder for WebDavMountBuilder {
    fn set_loopback_port(&mut self, port: u16) -> Result<(), MountError> {
        self.port = port;
        Ok(())
    }

    fn set_volume_id(&mut self, id: &str) -> Result<(), MountError> {
        self.volume_id = Some(id.to_owned());
        Ok(())
    }

    /// Accepted by every WebDAV builder, used only by the AppleScript one -- exactly like Java,
    /// where `AbstractMountBuilder` inherits the no-op and `MacAppleScriptMounter` overrides it.
    /// A service that does not advertise `VOLUME_NAME` never has this called by
    /// `mounting::mounter`.
    fn set_volume_name(&mut self, name: &str) -> Result<(), MountError> {
        self.volume_name = Some(name.to_owned());
        Ok(())
    }

    /// Starts the server and hands it to `finish`. A `finish` that fails takes the server down
    /// with it (the handle is dropped), like Java's `finally { serverHandle.close(); }`.
    ///
    /// **Blocking**, because [`WebDavServerHandle::start`] is: it waits for the server's health
    /// probe on the calling thread and must not be called from inside a tokio runtime.
    ///
    /// # Errors
    /// [`MountError::Failed`] carrying the [`crate::webdav::WebDavServerError`] -- a taken port
    /// above all -- or whatever `finish` reports.
    fn mount(self: Box<Self>) -> Result<Box<dyn Mount>, MountError> {
        let this = *self;
        let context_path = this.context_path();
        let server = WebDavServerHandle::start(WebDavServerConfig {
            fs: CryptoDavFs::new(this.fs),
            bind: bind_address(),
            port: this.port,
            context_path,
        })?;
        (this.finish)(server)
    }
}

/// A mount that is nothing but the running server: the user reaches the vault at
/// [`Mountpoint::Uri`] and mounts it in Finder, Nautilus or `curl` himself.
#[derive(Debug)]
pub struct FallbackMount {
    uri: String,
    server: Option<WebDavServerHandle>,
}

impl FallbackMount {
    /// The mount for a server that is already up.
    pub fn new(server: WebDavServerHandle) -> Self {
        Self {
            uri: server.root_uri(),
            server: Some(server),
        }
    }

    /// Stops the server if it is still running; stopping twice is success, like unmounting a
    /// volume that is already gone.
    fn stop(&mut self) -> Result<(), UnmountError> {
        let Some(mut server) = self.server.take() else {
            return Ok(());
        };
        server
            .stop()
            .map_err(|e| UnmountError::Failed(e.to_string()))
    }
}

impl Mount for FallbackMount {
    fn mountpoint(&self) -> Mountpoint {
        Mountpoint::Uri(self.uri.clone())
    }

    fn unmount(&mut self) -> Result<(), UnmountError> {
        self.stop()
    }

    /// The same as [`Mount::unmount`]: a server is never busy in a way that force would change.
    /// The *service* does not advertise `UNMOUNT_FORCED` (neither does Java's), so
    /// `MountHandle::unmount(true)` refuses before it ever gets here -- but a caller that reaches
    /// this must not be left with a running server.
    fn unmount_forced(&mut self) -> Result<(), UnmountError> {
        self.stop()
    }

    fn close(mut self: Box<Self>) -> Result<(), UnmountError> {
        self.stop()
    }
}

#[cfg(all(test, feature = "webdav"))]
mod tests {
    use super::*;
    use crate::registry::{alias_for_class, all_services, service_infos, FALLBACK_WEBDAV_CLASS};
    use crate::testing::{env_lock, test_fs};
    use crate::webdav::server::probe_context_root;
    use std::net::SocketAddr;
    use std::time::Duration;

    /// The fallback mounter configured the way `mounting::mounter` configures it. The returned
    /// `TempDir` is the vault and has to outlive the mount, so every caller binds it.
    ///
    /// The environment lock is held across `mount()`: it reads [`bind_address`] and the
    /// non-loopback override, and the unit tests in [`crate::webdav`] and
    /// [`crate::webdav::server`] change both.
    fn fallback_mount(port: u16, volume_id: &str) -> (tempfile::TempDir, Box<dyn Mount>) {
        let (dir, fs) = test_fs();
        let service = FallbackMounter;
        let mut builder = service.for_file_system(fs);
        builder.set_loopback_port(port).expect("LOOPBACK_PORT");
        builder.set_volume_id(volume_id).expect("VOLUME_ID");
        let _guard = env_lock();
        (dir, builder.mount().expect("mount"))
    }

    fn address_of(mount: &dyn Mount) -> SocketAddr {
        let Mountpoint::Uri(uri) = mount.mountpoint() else {
            panic!("the fallback mounter reports a URI")
        };
        let rest = uri.strip_prefix("http://").expect("an http url");
        let authority = rest.split('/').next().expect("an authority");
        authority.parse().expect("host:port")
    }

    #[test]
    fn the_service_mirrors_the_java_fallback_mounter() {
        let service = FallbackMounter;
        assert_eq!(service.java_class_name(), FALLBACK_WEBDAV_CLASS);
        assert_eq!(service.display_name(), "WebDAV (HTTP Address)");
        assert_eq!(service.priority(), 0);
        assert!(
            service.is_supported(),
            "the fallback works everywhere; that is the point of it"
        );
        assert_eq!(
            service.capabilities(),
            &[MountCapability::LoopbackPort, MountCapability::VolumeId]
        );
        assert_eq!(service.default_loopback_port(), Some(0));
        assert_eq!(service.default_mount_flags(), "");
        assert!(
            !service.appears_in_mount_table(),
            "a URL never shows up in the mount table"
        );
        assert!(
            service.read_only_follows_file_system(),
            "it serves the CryptoFs the daemon opened, read-only-ness included"
        );
        assert!(
            service
                .unmount_path(std::path::Path::new("/mnt/x"), false)
                .is_err(),
            "there is no path to unmount"
        );
    }

    /// The setters follow the capability set: the two advertised ones work, the rest refuse.
    #[test]
    fn the_builder_only_accepts_what_the_service_advertises() {
        let (_vault, fs) = test_fs();
        let mut builder = FallbackMounter.for_file_system(fs);
        builder.set_loopback_port(4711).expect("LOOPBACK_PORT");
        builder.set_volume_id("id").expect("VOLUME_ID");
        // Not advertised, but inherited from `AbstractMountBuilder` so task 6 can override it.
        builder.set_volume_name("Secret").expect("a no-op setter");
        assert!(builder
            .set_mountpoint(std::path::Path::new("/mnt"))
            .is_err());
        assert!(builder.set_mount_flags("-oro").is_err());
        assert!(builder.set_read_only(true).is_err());
        assert!(builder.set_file_system_name("crypto").is_err());
    }

    /// `append_volume_name` is what task 6's AppleScript mounter switches on; the fallback leaves
    /// it off, so the volume name never reaches the URL.
    #[test]
    fn the_context_path_follows_the_volume_id_and_the_append_switch() {
        let (_vault, fs) = test_fs();
        let finish: MountFinisher = Box::new(|_| unreachable!("this builder never mounts"));
        let mut plain = WebDavMountBuilder::new(Arc::clone(&fs), 0, false, finish);
        assert_eq!(plain.context_path(), "/", "no volume id: the server root");
        plain.set_volume_id("id").expect("VOLUME_ID");
        plain.set_volume_name("My Vault").expect("VOLUME_NAME");
        assert_eq!(plain.context_path(), "/id");
        assert!(format!("{plain:?}").contains("/id"), "{plain:?}");

        let finish: MountFinisher = Box::new(|_| unreachable!("this builder never mounts"));
        let mut appending = WebDavMountBuilder::new(fs, 0, true, finish);
        appending.set_volume_id("id").expect("VOLUME_ID");
        assert_eq!(
            appending.context_path(),
            "/id",
            "without a name there is nothing to append"
        );
        appending.set_volume_name("My Vault").expect("VOLUME_NAME");
        assert_eq!(appending.context_path(), "/id/My_Vault");
    }

    #[test]
    fn a_mount_serves_a_loopback_url_built_from_the_volume_id() {
        let (_vault, mut mount) = fallback_mount(0, "dix6BcCSNSl5");
        let Mountpoint::Uri(uri) = mount.mountpoint() else {
            panic!("a URI")
        };
        assert!(uri.starts_with("http://127.0.0.1:"), "{uri}");
        assert!(uri.ends_with("/dix6BcCSNSl5"), "{uri}");
        let addr = address_of(mount.as_ref());
        assert!(probe_context_root(
            addr,
            "/dix6BcCSNSl5",
            Duration::from_secs(5)
        ));
        mount.unmount().expect("unmount");
        assert!(
            !probe_context_root(addr, "/dix6BcCSNSl5", Duration::from_millis(300)),
            "the unmount stopped the server"
        );
        std::net::TcpListener::bind(addr).expect("the port is free again");
        mount.close().expect("close after unmount is a no-op");
    }

    #[test]
    fn a_volume_id_with_reserved_characters_is_normalised_into_the_url() {
        let (_vault, mount) = fallback_mount(0, "My Vault!!");
        let Mountpoint::Uri(uri) = mount.mountpoint() else {
            panic!("a URI")
        };
        assert!(uri.ends_with("/My_Vault_"), "{uri}");
    }

    #[test]
    fn dropping_the_mount_stops_the_server() {
        let addr = {
            let (_vault, mount) = fallback_mount(0, "dropme");
            address_of(mount.as_ref())
        };
        std::net::TcpListener::bind(addr).expect("the port is free again");
    }

    #[test]
    fn a_forced_unmount_stops_the_server_just_like_a_graceful_one() {
        // The *service* does not advertise UNMOUNT_FORCED (Java does not either), but a mount
        // that is asked anyway must not leave the server running.
        let (_vault, mut mount) = fallback_mount(0, "forced");
        let addr = address_of(mount.as_ref());
        mount.unmount_forced().expect("forced unmount");
        std::net::TcpListener::bind(addr).expect("the port is free again");
    }

    #[test]
    fn the_registry_offers_the_fallback_under_its_alias_and_ranks_it_last() {
        let _guard = env_lock();
        std::env::remove_var(crate::registry::ENABLE_NULL_MOUNTER_ENV);
        assert_eq!(alias_for_class(FALLBACK_WEBDAV_CLASS), Some("webdav"));
        let services = all_services();
        let classes: Vec<&str> = services.iter().map(|s| s.java_class_name()).collect();
        let fallback = classes
            .iter()
            .position(|c| *c == FALLBACK_WEBDAV_CLASS)
            .expect("the fallback is registered");
        assert_eq!(
            fallback,
            classes.len() - 2,
            "only the null mounter comes after it: {classes:?}"
        );
        let info = service_infos(false)
            .into_iter()
            .find(|info| info.class_name == FALLBACK_WEBDAV_CLASS)
            .expect("`crypto mounters` lists it without --all");
        assert_eq!(info.alias.as_deref(), Some("webdav"));
        assert!(info.supported);
        assert_eq!(
            info.capabilities,
            vec!["LOOPBACK_PORT".to_owned(), "VOLUME_ID".to_owned()]
        );
    }
}
