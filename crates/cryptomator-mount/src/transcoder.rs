//! Unicode normalisation between the FUSE side and the vault.
//!
//! Cryptomator stores cleartext names in NFC. macOS applications hand FUSE names in NFD (HFS+ and
//! APFS both present decomposed names), so a macOS mount has to decompose on the way out and
//! compose on the way in; on Linux both sides are NFC and the transcoder is a no-op.
use std::ffi::{OsStr, OsString};
use unicode_normalization::{is_nfc_quick, is_nfd_quick, IsNormalized, UnicodeNormalization};

/// The normal form the FUSE side of the mount uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuseNormalization {
    /// Composed - Linux, and every FUSE peer that does not decompose.
    Nfc,
    /// Decomposed - macOS.
    Nfd,
}

/// Translates file names between the FUSE side (see [`FuseNormalization`]) and the vault, which is
/// always NFC.
#[derive(Debug, Clone, Copy)]
pub struct NameTranscoder {
    fuse: FuseNormalization,
}

impl NameTranscoder {
    /// A transcoder for a FUSE peer using `fuse` as its normal form.
    pub fn new(fuse: FuseNormalization) -> Self {
        Self { fuse }
    }

    /// [`FuseNormalization::Nfd`] on macOS, [`FuseNormalization::Nfc`] everywhere else.
    pub fn for_platform_default() -> Self {
        #[cfg(target_os = "macos")]
        let fuse = FuseNormalization::Nfd;
        #[cfg(not(target_os = "macos"))]
        let fuse = FuseNormalization::Nfc;
        Self::new(fuse)
    }

    /// The normal form used on the FUSE side.
    pub fn fuse_normalization(&self) -> FuseNormalization {
        self.fuse
    }

    /// A name coming from the FUSE peer, composed for the vault. `None` if the peer sent a name
    /// that is not valid UTF-8 - the vault has no encoding for such a name.
    pub fn fuse_to_vault(&self, name: &OsStr) -> Option<String> {
        let name = name.to_str()?;
        Some(match is_nfc_quick(name.chars()) {
            IsNormalized::Yes => name.to_owned(),
            _ => name.nfc().collect(),
        })
    }

    /// A name from the vault, in the normal form the FUSE peer expects.
    pub fn vault_to_fuse(&self, name: &str) -> OsString {
        match self.fuse {
            FuseNormalization::Nfc => OsString::from(name),
            FuseNormalization::Nfd => match is_nfd_quick(name.chars()) {
                IsNormalized::Yes => OsString::from(name),
                _ => OsString::from(name.nfd().collect::<String>()),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;

    #[test]
    fn nfd_on_fuse_side_nfc_in_vault() {
        let t = NameTranscoder::new(FuseNormalization::Nfd);
        assert_eq!(
            t.fuse_to_vault(OsStr::new("cafe\u{301}.txt"))
                .expect("valid utf-8"),
            "caf\u{e9}.txt"
        );
        assert_eq!(
            t.vault_to_fuse("caf\u{e9}.txt"),
            OsString::from("cafe\u{301}.txt")
        );
        let id = NameTranscoder::new(FuseNormalization::Nfc);
        assert_eq!(
            id.vault_to_fuse("caf\u{e9}.txt"),
            OsString::from("caf\u{e9}.txt")
        );
        assert!(t.fuse_to_vault(OsStr::from_bytes(&[0xff, 0xfe])).is_none());
    }

    #[test]
    fn round_trip_and_ascii_are_stable() {
        for t in [
            NameTranscoder::new(FuseNormalization::Nfc),
            NameTranscoder::new(FuseNormalization::Nfd),
        ] {
            for name in ["plain.txt", "caf\u{e9}.txt", "\u{1f600}.txt", "d\u{131}r"] {
                let fuse = t.vault_to_fuse(name);
                assert_eq!(
                    t.fuse_to_vault(&fuse).expect("valid utf-8"),
                    name,
                    "round trip of {name:?} with {:?}",
                    t.fuse_normalization()
                );
            }
        }
        assert_eq!(
            NameTranscoder::new(FuseNormalization::Nfd).vault_to_fuse("plain.txt"),
            OsString::from("plain.txt")
        );
    }

    #[test]
    fn platform_default_matches_the_target() {
        let t = NameTranscoder::for_platform_default();
        if cfg!(target_os = "macos") {
            assert_eq!(t.fuse_normalization(), FuseNormalization::Nfd);
        } else {
            assert_eq!(t.fuse_normalization(), FuseNormalization::Nfc);
        }
    }
}
