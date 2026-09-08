//! Making a write survive a power cut.
//!
//! `write(tmp) + fsync(tmp) + rename(tmp, target)` is atomic with respect to *readers*: nobody
//! ever sees a half-written file. It is not durable: the rename lives in the directory, and the
//! directory has its own dirty pages. After a crash the file's contents can be on the platter
//! while the entry that names it is not -- and for `masterkey.cryptomator` that means a vault
//! with no key file at all.
//!
//! The fix is one more `fsync`, on the directory. Whether it actually happened cannot be observed
//! from a test -- no file system reports it -- so what the tests below pin is the behaviour
//! around it: the rename takes effect, the errors are the right ones, and a caller cannot
//! silently get the non-durable version.
use std::io;
use std::path::Path;

/// `fsync` on a directory, so a rename or a creation inside it survives a power cut.
///
/// A directory is opened read-only: `O_WRONLY` on a directory is `EISDIR` on Linux, and read-only
/// is enough for `fsync` on both platforms this runs on.
///
/// # Errors
/// [`io::ErrorKind::NotFound`] when `dir` is not there, [`io::ErrorKind::NotADirectory`] when it
/// is a file, and whatever the file system reports otherwise -- except the two kinds named at
/// [`is_directory_sync_unsupported`], which are answered with `Ok(())`.
pub fn sync_dir(dir: &Path) -> io::Result<()> {
    let handle = std::fs::File::open(dir)?;
    // `metadata()` on the open handle rather than on the path: it cannot race with a rename, and
    // it is what makes "a file is not a directory" an error instead of a pointless fsync.
    if !handle.metadata()?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            format!("{} is not a directory", dir.display()),
        ));
    }
    match handle.sync_all() {
        Err(e) if is_directory_sync_unsupported(&e) => Ok(()),
        other => other,
    }
}

/// Whether an `fsync` on a *directory* handle failed because that file system does not do it at
/// all, rather than because the sync itself went wrong.
///
/// SMB/CIFS shares and several FUSE file systems answer `fsync` on a directory with `EINVAL`
/// (`InvalidInput`) or `ENOTSUP` (`Unsupported`). There is nothing a caller could do about it and
/// nothing about the write itself is wrong, so those two are not errors here. Everything else is
/// passed on -- `EIO` above all, which is how a disk reports that the data did not make it.
fn is_directory_sync_unsupported(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::InvalidInput | io::ErrorKind::Unsupported
    )
}

/// `fsync` on a file that is not open any more -- after [`std::fs::copy`], which hands back no
/// handle to sync.
///
/// Opened for writing: `fsync` on a read-only descriptor is allowed on Linux and macOS but not
/// everywhere, and every caller here syncs a temporary file it created itself.
///
/// # Errors
/// Whatever opening the file or the sync reports.
pub fn sync_file(path: &Path) -> io::Result<()> {
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)?
        .sync_all()
}

/// [`sync_dir`] on the directory that holds `path`, for a file that was *created* rather than
/// renamed into place.
///
/// `create_new` + `write_all` + `sync_all` has the same hole as a rename: the bytes are on the
/// platter and the entry that names them is not.
///
/// # Errors
/// [`io::ErrorKind::InvalidInput`] when `path` has no parent directory (`/`), otherwise whatever
/// [`sync_dir`] reports.
pub fn sync_parent_dir(path: &Path) -> io::Result<()> {
    sync_dir(&parent_dir(path)?)
}

/// `rename(from, to)` plus an `fsync` on the directory holding `to`, so the new name is on the
/// platter and not only in the page cache.
///
/// Both paths are usually in the same directory (a temporary file next to its target, which is
/// what nearly every caller does); when they are not, the directory `from` left is synced as
/// well, because the disappearance of the old name has to be durable too -- otherwise a crash can
/// resurrect a file under both names.
///
/// # Errors
/// [`io::ErrorKind::InvalidInput`] when `to` has no parent directory that could be synced
/// (`rename` has not run in that case), otherwise whatever the rename or the directory sync
/// reports.
pub fn rename_durably(from: &Path, to: &Path) -> io::Result<()> {
    let to_parent = parent_dir(to)?;
    std::fs::rename(from, to)?;
    sync_dir(&to_parent)?;
    // A cross-directory move: the old name is gone from another directory, and that removal has
    // its own dirty page. `from`'s parent is only unavailable for a bare relative name, which
    // `parent_dir` maps to the working directory -- so a missing parent here cannot happen and an
    // error would be a real one.
    let from_parent = parent_dir(from)?;
    if from_parent != to_parent {
        sync_dir(&from_parent)?;
    }
    Ok(())
}

/// The directory that holds `path`.
///
/// An empty parent means `path` was relative and bare (`"x"`); the current directory is what holds
/// it then. `Path::parent` of `/` is `None`, and a path with no directory at all cannot be made
/// durable -- that is a caller's bug, and it is reported before anything is moved.
fn parent_dir(path: &Path) -> io::Result<std::path::PathBuf> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} has no parent directory to sync", path.display()),
        )
    })?;
    Ok(if parent.as_os_str().is_empty() {
        Path::new(".").to_path_buf()
    } else {
        parent.to_path_buf()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syncing_a_real_directory_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        sync_dir(dir.path()).expect("a directory that exists can be synced");
    }

    /// A caller that passes a path that is not there has a bug, and must hear about it rather
    /// than get a silent `Ok`.
    #[test]
    fn syncing_a_missing_directory_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let err = sync_dir(&dir.path().join("nope")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    /// A file is not a directory, and opening one to fsync it would sync the wrong thing.
    #[test]
    fn syncing_a_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, b"x").unwrap();
        let err = sync_dir(&file).unwrap_err();
        assert_eq!(
            err.kind(),
            io::ErrorKind::NotADirectory,
            "a file must not pass as a directory: {err}"
        );
        assert!(err.to_string().contains("is not a directory"), "{err}");
    }

    /// The two kinds a file system uses to say "I do not fsync directories" are the only ones that
    /// may be swallowed; an `EIO` means the write did not make it and has to reach the caller.
    #[test]
    fn only_an_unsupported_directory_sync_is_ignored() {
        for kind in [io::ErrorKind::InvalidInput, io::ErrorKind::Unsupported] {
            assert!(is_directory_sync_unsupported(&io::Error::new(kind, "x")));
        }
        for kind in [
            io::ErrorKind::Other,
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::NotFound,
        ] {
            assert!(!is_directory_sync_unsupported(&io::Error::new(kind, "x")));
        }
    }

    #[test]
    fn a_durable_rename_moves_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let from = dir.path().join("tmp");
        let to = dir.path().join("final");
        std::fs::write(&from, b"payload").unwrap();
        rename_durably(&from, &to).unwrap();
        assert!(!from.exists());
        assert_eq!(std::fs::read(&to).unwrap(), b"payload");
    }

    /// Overwriting is what every caller here does (`masterkey.cryptomator.tmp` over an existing
    /// key file), so it has to keep working.
    #[test]
    fn a_durable_rename_replaces_an_existing_target() {
        let dir = tempfile::tempdir().unwrap();
        let from = dir.path().join("tmp");
        let to = dir.path().join("final");
        std::fs::write(&to, b"old").unwrap();
        std::fs::write(&from, b"new").unwrap();
        rename_durably(&from, &to).unwrap();
        assert_eq!(std::fs::read(&to).unwrap(), b"new");
    }

    /// Both ends of a move between directories are synced, and both ends of it hold afterwards.
    #[test]
    fn a_durable_rename_across_directories_moves_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("a");
        let target = dir.path().join("b");
        std::fs::create_dir(&source).unwrap();
        std::fs::create_dir(&target).unwrap();
        let from = source.join("f");
        let to = target.join("f");
        std::fs::write(&from, b"payload").unwrap();
        rename_durably(&from, &to).unwrap();
        assert!(!from.exists());
        assert_eq!(std::fs::read(&to).unwrap(), b"payload");
    }

    /// A target with no parent directory cannot be made durable, and the message has to say so
    /// rather than blame the rename.
    #[test]
    fn a_target_without_a_parent_is_an_invalid_input() {
        let dir = tempfile::tempdir().unwrap();
        let from = dir.path().join("tmp");
        std::fs::write(&from, b"x").unwrap();
        let err = rename_durably(&from, Path::new("/")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(from.exists(), "the rename must not have run");
    }

    /// The rename must not have happened when the source is missing -- and the error is the
    /// rename's own, not the directory sync's.
    #[test]
    fn a_missing_source_fails_before_anything_is_synced() {
        let dir = tempfile::tempdir().unwrap();
        let err = rename_durably(&dir.path().join("nope"), &dir.path().join("target")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(!dir.path().join("target").exists());
    }

    /// A missing target directory is the rename's error, and nothing is left behind.
    #[test]
    fn a_missing_target_directory_surfaces_the_renames_error() {
        let dir = tempfile::tempdir().unwrap();
        let from = dir.path().join("tmp");
        std::fs::write(&from, b"x").unwrap();
        let err = rename_durably(&from, &dir.path().join("gone").join("target")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(from.exists(), "the source is still there after a failure");
    }

    /// A copied file has no handle left to sync, so it is synced by path.
    #[test]
    fn a_closed_file_can_be_synced_by_its_path() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, b"x").unwrap();
        sync_file(&file).expect("an existing file can be synced");
        assert_eq!(
            sync_file(&dir.path().join("nope")).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }

    /// The parent of a freshly created file is synced by its path, and a file that has no
    /// directory at all is the caller's bug.
    #[test]
    fn a_created_files_directory_can_be_synced_by_the_files_path() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, b"x").unwrap();
        sync_parent_dir(&file).expect("the directory holding a new file can be synced");
        assert_eq!(
            sync_parent_dir(Path::new("/")).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    /// A bare relative name has `""` as its parent; the working directory is what holds it, and
    /// that is what gets synced rather than an unopenable empty path.
    #[test]
    fn a_bare_relative_name_syncs_the_working_directory() {
        assert_eq!(parent_dir(Path::new("x")).unwrap(), Path::new("."));
        assert_eq!(parent_dir(Path::new("a/x")).unwrap(), Path::new("a"));
        assert_eq!(
            parent_dir(Path::new("/")).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
