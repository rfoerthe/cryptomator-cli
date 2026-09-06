//! Mounting on macOS through a dynamically loaded libfuse (macFUSE or FUSE-T).
//!
//! There is no macOS equivalent of Linux's `/dev/fuse` + `fusermount3`: the kernel extension
//! (macFUSE) and the NFS server (FUSE-T) are both reached through the vendor's `libfuse` 2.x
//! compatibility entry points. Neither is a build dependency -- the user installs one of them, or
//! neither -- so they are loaded at run time and called through their documented C signatures.
//! Spike A verified this against FUSE-T 1.2.7, see
//! `docs/superpowers/spikes/2026-09-06-spike-c-fuse-t-linux-abi.md`.
use crate::api::MountError;
use libloading::{Library, Symbol};
use std::ffi::{c_char, c_int, CString};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// `argv[0]` handed to libfuse's option parser. libfuse only ever prints it in usage messages,
/// but FUSE-T copies it into the NFS server's process title, so it should say who mounted this.
const PROGRAM_NAME: &str = "cryptomator-cli";

/// libfuse 2.x `struct fuse_args`.
///
/// `allocated` stays 0: the argv array below belongs to this process, so libfuse must not try to
/// free it (`fuse_opt_free_args` only frees what it allocated itself).
#[repr(C)]
struct FuseArgs {
    argc: c_int,
    argv: *const *const c_char,
    allocated: c_int,
}

/// A loaded libfuse 2.x compatible library.
///
/// Keep the value alive for as long as the mount it produced: unloading the library while
/// FUSE-T's server threads still run inside it would take the process down with it.
#[derive(Debug)]
pub struct LibFuse {
    lib: Library,
    path: PathBuf,
}

impl LibFuse {
    /// Loads the library at `path`.
    ///
    /// # Errors
    /// [`MountError::Failed`] if the file is missing or not a loadable library.
    pub fn load(path: &Path) -> Result<Self, MountError> {
        // SAFETY: `dlopen` runs the library's initialisers, which is why this is unsafe. The path
        // is one of the vendor libraries the provider knows (or the operator's own override);
        // nothing here is derived from vault contents.
        let lib = unsafe { Library::new(path) }.map_err(|err| {
            MountError::Failed(format!("could not load {}: {err}", path.display()))
        })?;
        Ok(Self {
            lib,
            path: path.to_path_buf(),
        })
    }

    /// The library this was loaded from.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Mounts `mountpoint` and returns the descriptor the FUSE session speaks on.
    ///
    /// `opts` are the values of `-o` options **without** the `-o` prefix (`"volname=Secret"`);
    /// each is passed as its own `-o` argument, exactly as a command line would.
    ///
    /// # Errors
    /// [`MountError::UnsupportedFlag`] for an option containing a NUL byte, [`MountError::MountPoint`]
    /// for a mount point containing one, and [`MountError::Failed`] if the symbol is missing or
    /// the mount itself fails.
    pub fn mount(&self, mountpoint: &Path, opts: &[String]) -> Result<OwnedFd, MountError> {
        let mut argv_owned = Vec::with_capacity(1 + 2 * opts.len());
        argv_owned.push(cstring(PROGRAM_NAME).map_err(|_| {
            MountError::Failed("the program name is not a valid C string".to_owned())
        })?);
        for opt in opts {
            argv_owned
                .push(cstring("-o").map_err(|_| {
                    MountError::Failed("\"-o\" is not a valid C string".to_owned())
                })?);
            argv_owned
                .push(cstring(opt).map_err(|_| MountError::UnsupportedFlag(format!("-o{opt}")))?);
        }
        let argc = c_int::try_from(argv_owned.len())
            .map_err(|_| MountError::Failed("too many mount options".to_owned()))?;
        // A C `argv` is NULL-terminated and the terminator is not counted in `argc`; libfuse's
        // option parser walks the array with `argv[argc]` in a few places, so the sentinel has to
        // be there even though every caller passes `argc` as well.
        let argv: Vec<*const c_char> = argv_owned
            .iter()
            .map(|arg| arg.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        let args = FuseArgs {
            argc,
            argv: argv.as_ptr(),
            allocated: 0,
        };
        let path = CString::new(mountpoint.as_os_str().as_bytes()).map_err(|_| {
            MountError::MountPoint(
                mountpoint.to_path_buf(),
                "the path contains a NUL byte".to_owned(),
            )
        })?;

        // SAFETY: `fuse_mount_compat25` is libfuse 2.x's mount entry point, declared as
        // `int fuse_mount_compat25(const char *mountpoint, struct fuse_args *args)`; the type
        // below spells exactly that signature, and `FuseArgs` mirrors `struct fuse_args`.
        let mount: Symbol<unsafe extern "C" fn(*const c_char, *const FuseArgs) -> c_int> =
            unsafe { self.lib.get(b"fuse_mount_compat25\0") }.map_err(|err| {
                MountError::Failed(format!(
                    "{} has no fuse_mount_compat25: {err}",
                    self.path.display()
                ))
            })?;
        // SAFETY: both pointers stay valid for the duration of the call -- `path` and
        // `argv_owned`/`argv` outlive it -- and libfuse neither stores nor frees them
        // (`allocated == 0`).
        let raw_fd = unsafe { mount(path.as_ptr(), &args) };
        if raw_fd < 0 {
            return Err(MountError::Failed(format!(
                "mounting {} through {} failed: {}",
                mountpoint.display(),
                self.path.display(),
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: `fuse_mount_compat25` returned a fresh descriptor it no longer owns; wrapping it
        // in `OwnedFd` gives it exactly one owner, which closes it.
        Ok(unsafe { OwnedFd::from_raw_fd(raw_fd) })
    }

    /// Asks the library to unmount `mountpoint`.
    ///
    /// The providers unmount with `umount(8)` instead (that is what Cryptomator does, and it works
    /// for a mount this process did not make); this is the library's own way, kept for a caller
    /// that has the library at hand and wants no child process.
    ///
    /// # Errors
    /// [`MountError::MountPoint`] for a path containing a NUL byte, [`MountError::Failed`] if the
    /// symbol is missing. `fuse_unmount_compat22` itself reports nothing.
    pub fn unmount(&self, mountpoint: &Path) -> Result<(), MountError> {
        let path = CString::new(mountpoint.as_os_str().as_bytes()).map_err(|_| {
            MountError::MountPoint(
                mountpoint.to_path_buf(),
                "the path contains a NUL byte".to_owned(),
            )
        })?;
        // SAFETY: `void fuse_unmount_compat22(const char *mountpoint)` -- the type below is that
        // signature.
        let unmount: Symbol<unsafe extern "C" fn(*const c_char)> =
            unsafe { self.lib.get(b"fuse_unmount_compat22\0") }.map_err(|err| {
                MountError::Failed(format!(
                    "{} has no fuse_unmount_compat22: {err}",
                    self.path.display()
                ))
            })?;
        // SAFETY: `path` outlives the call and the callee only reads the string.
        unsafe { unmount(path.as_ptr()) };
        Ok(())
    }
}

fn cstring(value: &str) -> Result<CString, std::ffi::NulError> {
    CString::new(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn loading_something_that_is_not_a_library_fails() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("libnot-a-dylib.dylib");
        let mut file = std::fs::File::create(&path).expect("create file");
        file.write_all(b"not a mach-o file").expect("write file");
        let err = LibFuse::load(&path).expect_err("loading a text file fails");
        match err {
            MountError::Failed(message) => assert!(message.contains("libnot-a-dylib"), "{message}"),
            other => panic!("expected Failed, got {other:?}"),
        }
        let err = LibFuse::load(&dir.path().join("missing.dylib"))
            .expect_err("loading a missing file fails");
        assert!(matches!(err, MountError::Failed(_)), "{err:?}");
    }

    #[test]
    fn the_c_string_helper_rejects_interior_nuls() {
        assert!(cstring("volname=Secret").is_ok());
        assert!(cstring("vol\0name").is_err());
    }
}
