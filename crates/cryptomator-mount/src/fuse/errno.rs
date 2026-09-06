//! `io::Error` → errno, the FUSE counterpart of Cryptomator's exception handlers.
use cryptomator_core::fs::FilesystemLoop;
use fuser::Errno;
use std::io;

/// Maps an error from the core file system to the errno the kernel expects.
///
/// An error that carries an OS error code passes it through unchanged; everything else is
/// classified by [`io::ErrorKind`]. The core reports a symlink loop as `ErrorKind::Other` with a
/// [`FilesystemLoop`] payload (`ErrorKind::FilesystemLoop` is still unstable), which becomes
/// `ELOOP`. Anything unrecognised becomes `EIO` rather than a silently wrong success.
pub fn errno_for(err: &io::Error) -> Errno {
    if let Some(code) = err.raw_os_error() {
        return Errno::from_i32(code);
    }
    match err.kind() {
        io::ErrorKind::NotFound => Errno::ENOENT,
        io::ErrorKind::AlreadyExists => Errno::EEXIST,
        io::ErrorKind::NotADirectory => Errno::ENOTDIR,
        io::ErrorKind::IsADirectory => Errno::EISDIR,
        io::ErrorKind::DirectoryNotEmpty => Errno::ENOTEMPTY,
        io::ErrorKind::PermissionDenied => Errno::EACCES,
        io::ErrorKind::ReadOnlyFilesystem => Errno::EROFS,
        io::ErrorKind::InvalidInput => Errno::EINVAL,
        io::ErrorKind::InvalidData => Errno::EIO,
        io::ErrorKind::UnexpectedEof => Errno::EIO,
        io::ErrorKind::Unsupported => Errno::ENOTSUP,
        io::ErrorKind::Other if is_filesystem_loop(err) => Errno::ELOOP,
        _ => Errno::EIO,
    }
}

fn is_filesystem_loop(err: &io::Error) -> bool {
    err.get_ref()
        .and_then(|inner| inner.downcast_ref::<FilesystemLoop>())
        .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kind(kind: io::ErrorKind) -> Errno {
        errno_for(&io::Error::new(kind, "test"))
    }

    #[test]
    fn every_kind_the_core_produces_has_an_errno() {
        assert_eq!(kind(io::ErrorKind::NotFound), Errno::ENOENT);
        assert_eq!(kind(io::ErrorKind::AlreadyExists), Errno::EEXIST);
        assert_eq!(kind(io::ErrorKind::NotADirectory), Errno::ENOTDIR);
        assert_eq!(kind(io::ErrorKind::IsADirectory), Errno::EISDIR);
        assert_eq!(kind(io::ErrorKind::DirectoryNotEmpty), Errno::ENOTEMPTY);
        assert_eq!(kind(io::ErrorKind::PermissionDenied), Errno::EACCES);
        assert_eq!(kind(io::ErrorKind::ReadOnlyFilesystem), Errno::EROFS);
        assert_eq!(kind(io::ErrorKind::InvalidInput), Errno::EINVAL);
        assert_eq!(kind(io::ErrorKind::InvalidData), Errno::EIO);
        assert_eq!(kind(io::ErrorKind::UnexpectedEof), Errno::EIO);
        assert_eq!(kind(io::ErrorKind::Unsupported), Errno::ENOTSUP);
        assert_eq!(kind(io::ErrorKind::Other), Errno::EIO);
        assert_eq!(kind(io::ErrorKind::WouldBlock), Errno::EIO);
    }

    #[test]
    fn an_os_error_keeps_its_code() {
        assert_eq!(
            errno_for(&io::Error::from_raw_os_error(libc::ENOSPC)),
            Errno::ENOSPC
        );
        // The OS code wins over the kind mapping.
        assert_eq!(
            errno_for(&io::Error::from_raw_os_error(libc::EPERM)),
            Errno::EPERM
        );
    }

    #[test]
    fn a_symlink_loop_becomes_eloop() {
        let err = io::Error::other(FilesystemLoop("/a".to_owned()));
        assert_eq!(errno_for(&err), Errno::ELOOP);
        assert_eq!(errno_for(&io::Error::other("something else")), Errno::EIO);
    }
}
