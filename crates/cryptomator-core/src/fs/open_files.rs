//! `fh/OpenCryptoFiles`: one `OpenCryptoFile` per (normalised) ciphertext path, shared by all
//! handles; the last handle flushes and closes it. `TwoPhaseMove` keeps entries consistent while a
//! ciphertext file is renamed.
use super::events::EventSink;
use super::open_file::{OpenCryptoFile, OpenOptions};
use super::stats::CryptoFsStats;
use crate::crypto::rng::Rng;
use crate::Cryptor;
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

pub type RngFactory = Arc<dyn Fn() -> Box<dyn Rng + Send> + Send + Sync>;
type Registry = Arc<Mutex<HashMap<PathBuf, Arc<Mutex<OpenCryptoFile>>>>>;

pub struct OpenCryptoFiles {
    cryptor: Arc<Cryptor>,
    stats: Arc<CryptoFsStats>,
    events: EventSink,
    rng_factory: RngFactory,
    files: Registry,
}

impl std::fmt::Debug for OpenCryptoFiles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenCryptoFiles")
            .field("open", &self.len())
            .finish_non_exhaustive()
    }
}

fn normalize(path: &Path) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}

impl OpenCryptoFiles {
    pub fn new(
        cryptor: Arc<Cryptor>,
        stats: Arc<CryptoFsStats>,
        events: EventSink,
        rng_factory: RngFactory,
    ) -> Self {
        Self {
            cryptor,
            stats,
            events,
            rng_factory,
            files: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn len(&self) -> usize {
        super::lock(&self.files).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The open file for a ciphertext path, if any (without opening it).
    pub fn get(&self, ciphertext_path: &Path) -> Option<Arc<Mutex<OpenCryptoFile>>> {
        super::lock(&self.files)
            .get(&normalize(ciphertext_path))
            .cloned()
    }

    /// Lock order everywhere: registry map first, then the file.
    pub fn open(&self, ciphertext_path: &Path, options: OpenOptions) -> io::Result<FileHandle> {
        let options = options.normalized();
        let key = normalize(ciphertext_path);
        let mut files = super::lock(&self.files);
        let file = match files.get(&key) {
            Some(existing) => {
                if options.create_new {
                    return Err(super::already_exists(key.display()));
                }
                let mut open = super::lock(existing);
                if options.write {
                    open.reopen_writable()?;
                }
                if options.truncate {
                    open.truncate(0)?;
                }
                open.retain();
                existing.clone()
            }
            None => {
                let open = OpenCryptoFile::open(
                    self.cryptor.clone(),
                    (self.rng_factory)(),
                    self.stats.clone(),
                    self.events.clone(),
                    &key,
                    options,
                )?;
                let arc = Arc::new(Mutex::new(open));
                files.insert(key, arc.clone());
                arc
            }
        };
        Ok(FileHandle {
            file,
            files: self.files.clone(),
            readable: options.read,
            writable: options.write,
            released: false,
        })
    }

    /// `OpenCryptoFiles.delete`: forgets the mapping and marks the open file as deleted.
    pub fn delete(&self, ciphertext_path: &Path) {
        if let Some(file) = super::lock(&self.files).remove(&normalize(ciphertext_path)) {
            super::lock(&file).set_path(None);
        }
    }

    /// Reserves `dst` and, after the physical rename, `commit()` re-keys an open `src`.
    pub fn prepare_move(&self, src: &Path, dst: &Path) -> io::Result<TwoPhaseMove> {
        let (src, dst) = (normalize(src), normalize(dst));
        let mut files = super::lock(&self.files);
        if files.contains_key(&dst) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{}: destination file is currently open", dst.display()),
            ));
        }
        let moved = files.get(&src).cloned();
        if let Some(file) = &moved {
            files.insert(dst.clone(), file.clone());
        }
        Ok(TwoPhaseMove {
            files: self.files.clone(),
            src,
            dst,
            moved,
            committed: false,
        })
    }

    /// Flushes and closes every open file (even if handles are still around).
    pub fn close_all(&self) -> io::Result<()> {
        let files: Vec<Arc<Mutex<OpenCryptoFile>>> =
            super::lock(&self.files).drain().map(|(_, f)| f).collect();
        let mut first_error = None;
        for file in files {
            if let Err(e) = super::lock(&file).flush() {
                first_error.get_or_insert(e);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

/// A cleartext view on a shared `OpenCryptoFile` (`CleartextFileChannel`).
pub struct FileHandle {
    pub(crate) file: Arc<Mutex<OpenCryptoFile>>,
    files: Registry,
    readable: bool,
    writable: bool,
    released: bool,
}

impl std::fmt::Debug for FileHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileHandle")
            .field("readable", &self.readable)
            .field("writable", &self.writable)
            .finish_non_exhaustive()
    }
}

impl FileHandle {
    pub fn is_readable(&self) -> bool {
        self.readable
    }
    pub fn is_writable(&self) -> bool {
        self.writable
    }
    pub fn size(&self) -> u64 {
        super::lock(&self.file).size()
    }
    pub fn read_at(&self, buf: &mut [u8], position: u64) -> io::Result<usize> {
        if !self.readable {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "handle not opened for reading",
            ));
        }
        super::lock(&self.file).read_at(buf, position)
    }
    pub fn read_exact_at(&self, buf: &mut [u8], position: u64) -> io::Result<()> {
        let mut done = 0;
        while done < buf.len() {
            match self.read_at(&mut buf[done..], position + done as u64)? {
                0 => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "read past end of file",
                    ))
                }
                n => done += n,
            }
        }
        Ok(())
    }
    pub fn write_at(&self, data: &[u8], position: u64) -> io::Result<usize> {
        if !self.writable {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "handle not opened for writing",
            ));
        }
        super::lock(&self.file).write_at(data, position)
    }
    pub fn write_all_at(&self, data: &[u8], position: u64) -> io::Result<()> {
        let mut done = 0;
        while done < data.len() {
            done += self.write_at(&data[done..], position + done as u64)?;
        }
        Ok(())
    }
    pub fn truncate(&self, size: u64) -> io::Result<()> {
        if !self.writable {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "handle not opened for writing",
            ));
        }
        super::lock(&self.file).truncate(size)
    }
    pub fn flush(&self) -> io::Result<()> {
        super::lock(&self.file).flush()
    }
    pub fn sync(&self, metadata: bool) -> io::Result<()> {
        super::lock(&self.file).sync(metadata)
    }
    pub fn set_last_modified(&self, time: SystemTime) {
        super::lock(&self.file).set_last_modified(time)
    }

    /// Flushes; when this was the last handle the file leaves the registry and its mtime is restored.
    pub fn close(mut self) -> io::Result<()> {
        self.release()
    }

    fn release(&mut self) -> io::Result<()> {
        if self.released {
            return Ok(());
        }
        self.released = true;
        let mut files = super::lock(&self.files);
        let mut file = super::lock(&self.file);
        let result = file.flush();
        if file.release() == 0 {
            files.retain(|_, f| !Arc::ptr_eq(f, &self.file));
            let mtime = file.persist_last_modified();
            // a deleted file has no mtime to restore
            if let Err(e) = mtime {
                if e.kind() != io::ErrorKind::NotFound && result.is_ok() {
                    return Err(e);
                }
            }
        }
        result
    }
}

impl Drop for FileHandle {
    fn drop(&mut self) {
        let _ = self.release(); // errors are reported by an explicit close()
    }
}

pub struct TwoPhaseMove {
    files: Registry,
    src: PathBuf,
    dst: PathBuf,
    moved: Option<Arc<Mutex<OpenCryptoFile>>>,
    committed: bool,
}

impl std::fmt::Debug for TwoPhaseMove {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TwoPhaseMove")
            .field("src", &self.src)
            .field("dst", &self.dst)
            .finish_non_exhaustive()
    }
}

impl TwoPhaseMove {
    pub fn commit(mut self) {
        let mut files = super::lock(&self.files);
        if let Some(file) = &self.moved {
            super::lock(file).set_path(Some(self.dst.clone()));
            files.remove(&self.src);
        }
        self.committed = true;
    }
}

impl Drop for TwoPhaseMove {
    fn drop(&mut self) {
        if !self.committed {
            if let Some(file) = &self.moved {
                let mut files = super::lock(&self.files);
                if files.get(&self.dst).is_some_and(|f| Arc::ptr_eq(f, file)) {
                    files.remove(&self.dst);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rng::DetRng;
    use crate::crypto::stream::decrypt_all;
    use crate::fs::{discard_events, testutil};

    fn registry(cryptor: Arc<Cryptor>) -> OpenCryptoFiles {
        OpenCryptoFiles::new(
            cryptor,
            Arc::new(CryptoFsStats::default()),
            discard_events(),
            Arc::new(|| Box::new(DetRng::default())),
        )
    }

    #[test]
    fn handles_share_one_open_file_and_close_on_last_drop() {
        let (dir, cryptor, _) = testutil::new_vault(220);
        let files = registry(cryptor.clone());
        let path = dir.path().join("f");
        let a = files.open(&path, OpenOptions::write_new()).unwrap();
        a.write_all_at(b"hello world", 0).unwrap();
        assert_eq!(
            a.read_at(&mut [0u8; 1], 0).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied,
            "write-only handle"
        );
        let b = files.open(&path, OpenOptions::read_only()).unwrap();
        let mut buf = [0u8; 5];
        b.read_exact_at(&mut buf, 6).unwrap();
        assert_eq!(&buf, b"world");
        assert_eq!(files.len(), 1);
        assert!(Arc::ptr_eq(&a.file, &b.file));
        assert!(
            files.open(&path, OpenOptions::write_new()).is_err(),
            "CREATE_NEW on an open file"
        );
        drop(a);
        assert_eq!(files.len(), 1, "still open through b");
        assert!(b.write_at(b"x", 0).is_err(), "read-only handle");
        b.close().unwrap();
        assert_eq!(files.len(), 0);
        assert_eq!(
            decrypt_all(&cryptor, &std::fs::read(&path).unwrap()).unwrap(),
            b"hello world"
        );
    }

    #[test]
    fn a_writable_handle_upgrades_a_read_only_open_file() {
        let (dir, cryptor, _) = testutil::new_vault(220);
        let files = registry(cryptor.clone());
        let path = dir.path().join("f");
        files
            .open(&path, OpenOptions::write_new())
            .unwrap()
            .close()
            .unwrap();
        let r = files.open(&path, OpenOptions::read_only()).unwrap();
        let w = files.open(&path, OpenOptions::read_write()).unwrap();
        w.write_all_at(b"data", 0).unwrap();
        assert_eq!(r.size(), 4);
        drop(w);
        drop(r);
        assert_eq!(
            decrypt_all(&cryptor, &std::fs::read(&path).unwrap()).unwrap(),
            b"data"
        );
    }

    #[test]
    fn two_phase_move_and_delete_update_open_files() {
        let (dir, cryptor, _) = testutil::new_vault(220);
        let files = registry(cryptor);
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        let h = files.open(&src, OpenOptions::write_new()).unwrap();
        {
            let m = files.prepare_move(&src, &dst).unwrap();
            assert!(files.get(&dst).is_some(), "reserved during the move");
            drop(m); // rollback
            assert!(files.get(&dst).is_none());
        }
        let m = files.prepare_move(&src, &dst).unwrap();
        std::fs::rename(&src, &dst).unwrap();
        m.commit();
        assert!(files.get(&src).is_none());
        assert_eq!(
            super::super::lock(&files.get(&dst).unwrap()).path(),
            Some(dst.as_path())
        );
        // moving onto an open destination is refused
        let other = dir.path().join("other");
        let _o = files.open(&other, OpenOptions::write_new()).unwrap();
        assert_eq!(
            files.prepare_move(&dst, &other).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        files.delete(&dst);
        assert!(files.get(&dst).is_none());
        assert_eq!(super::super::lock(&h.file).path(), None);
        h.close().unwrap();
        files.close_all().unwrap();
        assert_eq!(files.len(), 0);
    }
}
