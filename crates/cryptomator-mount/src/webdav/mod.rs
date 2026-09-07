//! The WebDAV back ends: a `dav-server` file system over `CryptoFs`, a loopback HTTP server and
//! the three mount services Cryptomator ships (`FallbackMounter`, `MacAppleScriptMounter`,
//! `LinuxGioMounter`).
//!
//! The server is what the desktop app calls the "WebDAV fallback": it needs no FUSE, no kernel
//! extension and no privileges, and it is the only back end that works on a machine with nothing
//! installed. Every request is answered from the very `Arc<CryptoFs>` the daemon opened.
use crate::api::MountError;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::RwLock;

pub mod fallback;
pub mod fs;
pub mod os_mount;
pub mod server;

pub use fallback::{FallbackMount, FallbackMounter, MountFinisher, WebDavMountBuilder};
pub use fs::{fs_error, CryptoDavEntry, CryptoDavFile, CryptoDavFs, CryptoDavMeta};
pub use os_mount::{LinuxGioMounter, MacAppleScriptMounter};
pub use server::{
    probe_context_root, strip_prefix_for, WebDavServerConfig, WebDavServerError,
    WebDavServerHandle, HEALTH_TIMEOUT,
};

/// Set to `1` to let [`set_bind_address`] accept an address the rest of the network can reach.
pub const ALLOW_NONLOOPBACK_ENV: &str = "CRYPTO_WEBDAV_ALLOW_NONLOOPBACK";

/// The address every WebDAV server binds to. Loopback, because the server has no authentication
/// -- exactly like Cryptomator's, which uses `InetAddress.getLoopbackAddress()`.
static BIND_ADDRESS: RwLock<IpAddr> = RwLock::new(IpAddr::V4(Ipv4Addr::LOCALHOST));

/// The address the next server binds to.
pub fn bind_address() -> IpAddr {
    *BIND_ADDRESS
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The bind policy, on its own so that both [`set_bind_address`] and
/// [`WebDavServerHandle::start`] can apply it.
///
/// `start` re-checks rather than trusting its caller: [`WebDavServerConfig::bind`] is a plain
/// `IpAddr` that anything could fill in, and the one thing that must never happen is a vault
/// served, unauthenticated, on an address the rest of the network can reach.
///
/// # Errors
/// [`MountError::Failed`] for an address that is not a loopback address, unless
/// [`ALLOW_NONLOOPBACK_ENV`] is `1`.
pub fn check_bind_address(addr: IpAddr) -> Result<(), MountError> {
    let allowed = std::env::var(ALLOW_NONLOOPBACK_ENV).is_ok_and(|value| value == "1");
    if !addr.is_loopback() && !allowed {
        return Err(MountError::Failed(format!(
            "webdavBind {addr} is not a loopback address; the WebDAV server has no \
             authentication. Set {ALLOW_NONLOOPBACK_ENV}=1 to override."
        )));
    }
    Ok(())
}

/// Sets the address every following server binds to (`cli.json`'s `webdavBind`).
///
/// One process serves one vault, so this is process-wide rather than threaded through the
/// builder chain. A non-loopback address is refused: the server serves the decrypted vault
/// without asking for a password, and binding it to a reachable interface would publish it.
///
/// # Errors
/// [`MountError::Failed`] for an address that is not a loopback address, unless
/// [`ALLOW_NONLOOPBACK_ENV`] is `1`.
pub fn set_bind_address(addr: IpAddr) -> Result<(), MountError> {
    check_bind_address(addr)?;
    *BIND_ADDRESS
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = addr;
    Ok(())
}

/// `AbstractMountBuilder.normalizedContextPath`: split on `/`, drop blank segments, replace every
/// run of characters that are not RFC 3986 unreserved (`A-Z a-z 0-9 - . _ ~`) with a single `_`,
/// and join the result back under a leading `/`.
///
/// The result never ends in `/` unless it *is* `/` (Cryptomator's `WebDavServletFactory` trims
/// trailing slashes the same way), so it can be used as `DavConfig::strip_prefix` directly.
pub fn normalize_context_path(raw: &str) -> String {
    let mut path = String::from("/");
    for segment in raw.split('/').filter(|s| !s.trim().is_empty()) {
        if path.len() > 1 {
            path.push('/');
        }
        let mut previous_was_reserved = false;
        for c in segment.chars() {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~') {
                path.push(c);
                previous_was_reserved = false;
            } else if !previous_was_reserved {
                path.push('_');
                previous_was_reserved = true;
            }
        }
    }
    path
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn a_volume_id_becomes_a_single_context_segment() {
        assert_eq!(normalize_context_path("dix6BcCSNSl5"), "/dix6BcCSNSl5");
        assert_eq!(normalize_context_path("/dix6BcCSNSl5/"), "/dix6BcCSNSl5");
    }

    #[test]
    fn reserved_characters_collapse_into_one_underscore() {
        // RFC 3986 unreserved chars survive, every run of anything else becomes a single "_".
        assert_eq!(normalize_context_path("My Vault!!"), "/My_Vault_");
        assert_eq!(normalize_context_path("a-b._~c"), "/a-b._~c");
        assert_eq!(normalize_context_path("id/My Vault"), "/id/My_Vault");
        assert_eq!(normalize_context_path("id//  //name"), "/id/name");
    }

    #[test]
    fn an_empty_volume_id_is_the_server_root() {
        assert_eq!(normalize_context_path(""), "/");
        assert_eq!(normalize_context_path("   "), "/");
        assert_eq!(normalize_context_path("///"), "/");
    }

    #[test]
    fn the_bind_address_defaults_to_loopback_and_refuses_public_addresses() {
        let _guard = crate::testing::env_lock();
        std::env::remove_var(ALLOW_NONLOOPBACK_ENV);
        set_bind_address(IpAddr::V4(Ipv4Addr::LOCALHOST)).expect("loopback is always allowed");
        assert_eq!(bind_address(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        let err = set_bind_address(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)))
            .expect_err("0.0.0.0 would expose the vault to the network");
        assert!(err.to_string().contains("loopback"), "{err}");
        assert_eq!(bind_address(), IpAddr::V4(Ipv4Addr::LOCALHOST), "unchanged");
        std::env::set_var(ALLOW_NONLOOPBACK_ENV, "1");
        set_bind_address(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))).expect("explicitly allowed");
        assert_eq!(bind_address(), IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
        std::env::remove_var(ALLOW_NONLOOPBACK_ENV);
        set_bind_address(IpAddr::V4(Ipv4Addr::LOCALHOST)).expect("reset for the other tests");
    }
}
