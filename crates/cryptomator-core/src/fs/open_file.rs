//! One open ciphertext file (`fh/OpenCryptoFile`, `fh/ChunkCache`, `fh/ChunkLoader`, `fh/ChunkSaver`,
//! `ch/CleartextFileChannel`): positional cleartext reads/writes over a cache of at most five
//! decrypted chunks. Not thread-safe by itself; `OpenCryptoFiles` wraps it in a `Mutex`.
use super::events::{EventSink, FilesystemEvent};
use super::stats::CryptoFsStats;
use crate::crypto::header::FileHeader;
use crate::crypto::rng::Rng;
use crate::Cryptor;
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
use zeroize::Zeroizing;

pub const MAX_CACHED_CLEARTEXT_CHUNKS: usize = 5;

/// `EffectiveOpenOptions` (subset: no APPEND/DSYNC/DELETE_ON_CLOSE – positional API).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OpenOptions {
    pub read: bool,
    pub write: bool,
    pub create: bool,
    pub create_new: bool,
    pub truncate: bool,
}

impl OpenOptions {
    pub fn read_only() -> Self {
        Self {
            read: true,
            ..Self::default()
        }
    }
    pub fn read_write() -> Self {
        Self {
            read: true,
            write: true,
            ..Self::default()
        }
    }
    pub fn write_new() -> Self {
        Self {
            write: true,
            create_new: true,
            ..Self::default()
        }
    }
    pub fn write_truncate() -> Self {
        Self {
            write: true,
            create: true,
            truncate: true,
            ..Self::default()
        }
    }
    /// `EffectiveOpenOptions.cleanAndValidate`: no WRITE ⇒ READ and no create/truncate; CREATE_NEW wins over CREATE.
    pub fn normalized(mut self) -> Self {
        if !self.write {
            self.read = true;
            self.create = false;
            self.create_new = false;
            self.truncate = false;
        }
        if self.create_new {
            self.create = false;
        }
        self
    }
}

struct Chunk {
    data: Zeroizing<Vec<u8>>,
    dirty: bool,
}

/// LRU cache keyed by chunk index (`ChunkCache` with `MAX_CACHED_CLEARTEXT_CHUNKS`).
#[derive(Default)]
struct ChunkCache {
    chunks: HashMap<u64, Chunk>,
    lru: VecDeque<u64>, // front = least recently used
}

impl ChunkCache {
    fn len(&self) -> usize {
        self.chunks.len()
    }
    fn contains(&self, index: u64) -> bool {
        self.chunks.contains_key(&index)
    }
    /// Marks `index` as most recently used; a cache miss only reorders the (absent) entry.
    fn touch(&mut self, index: u64) {
        self.lru.retain(|i| *i != index);
        self.lru.push_back(index);
    }
    fn insert(&mut self, index: u64, chunk: Chunk) {
        self.touch(index);
        self.chunks.insert(index, chunk);
    }
    fn pop_lru(&mut self) -> Option<(u64, Chunk)> {
        let index = self.lru.pop_front()?;
        self.chunks.remove(&index).map(|c| (index, c))
    }
    fn get_mut(&mut self, index: u64) -> Option<&mut Chunk> {
        self.chunks.get_mut(&index)
    }
    fn indices(&self) -> Vec<u64> {
        let mut v: Vec<u64> = self.chunks.keys().copied().collect();
        v.sort_unstable();
        v
    }
    fn any_dirty(&self) -> bool {
        self.chunks.values().any(|c| c.dirty)
    }
    fn clear(&mut self) {
        self.chunks.clear();
        self.lru.clear();
    }
}

/// Zeroes followed by the caller's bytes (`ByteSource.repeatingZeroes(gap).followedBy(src)`).
struct ByteSource<'a> {
    zeroes: u64,
    src: &'a [u8],
}

impl ByteSource<'_> {
    fn remaining(&self) -> u64 {
        self.zeroes + self.src.len() as u64
    }
    /// `dst` must not be longer than [`Self::remaining`].
    fn copy_to(&mut self, dst: &mut [u8]) {
        let zeroes = self.zeroes.min(dst.len() as u64) as usize;
        dst[..zeroes].fill(0);
        self.zeroes -= zeroes as u64;
        let n = dst.len() - zeroes;
        dst[zeroes..].copy_from_slice(&self.src[..n]);
        self.src = &self.src[n..];
    }
}

pub struct OpenCryptoFile {
    cryptor: Arc<Cryptor>,
    rng: Box<dyn Rng + Send>,
    stats: Arc<CryptoFsStats>,
    events: EventSink,
    /// `None` once the file was deleted while open.
    path: Option<PathBuf>,
    file: File,
    writable: bool,
    header: FileHeader,
    encrypted_header: Vec<u8>,
    header_persisted: bool,
    size: u64,
    chunks: ChunkCache,
    last_modified: Option<SystemTime>,
    handles: usize,
}

impl std::fmt::Debug for OpenCryptoFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenCryptoFile")
            .field("path", &self.path)
            .field("size", &self.size)
            .field("handles", &self.handles)
            .finish_non_exhaustive()
    }
}

fn read_fully_at(file: &File, buf: &mut [u8], position: u64) -> io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match file.read_at(&mut buf[total..], position + total as u64) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

impl OpenCryptoFile {
    pub fn open(
        cryptor: Arc<Cryptor>,
        mut rng: Box<dyn Rng + Send>,
        stats: Arc<CryptoFsStats>,
        events: EventSink,
        path: &Path,
        options: OpenOptions,
    ) -> io::Result<Self> {
        let options = options.normalized();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(options.write)
            .create(options.create)
            .create_new(options.create_new)
            .open(path)?;
        let ciphertext_size = file.metadata()?.len();
        let header_cryptor = cryptor.file_header_cryptor();
        let (header, encrypted_header, header_persisted, last_modified) =
            if options.create_new || (options.create && ciphertext_size == 0) {
                // `FileHeaderHolder.createNew`: encrypt right away so the nonce is never reused
                let header = header_cryptor.create(&mut *rng);
                let encrypted = header_cryptor
                    .encrypt_header(&header)
                    .map_err(|e| super::invalid_data(e.to_string()))?;
                (header, encrypted, false, Some(SystemTime::now()))
            } else {
                let mut buf = vec![0u8; header_cryptor.header_size()];
                let read = read_fully_at(&file, &mut buf, 0)?;
                if read != buf.len() {
                    events(FilesystemEvent::DecryptionFailed {
                        ciphertext_path: path.to_path_buf(),
                        reason: "truncated file header".into(),
                    });
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!("Unable to read header of file {}", path.display()),
                    ));
                }
                let header = header_cryptor.decrypt_header(&buf).map_err(|e| {
                    events(FilesystemEvent::DecryptionFailed {
                        ciphertext_path: path.to_path_buf(),
                        reason: e.to_string(),
                    });
                    super::invalid_data(format!(
                        "Unable to decrypt header of file {}: {e}",
                        path.display()
                    ))
                })?;
                (
                    header,
                    buf,
                    true,
                    file.metadata().and_then(|m| m.modified()).ok(),
                )
            };
        let size = Self::initial_size(&cryptor, ciphertext_size);
        let mut this = Self {
            cryptor,
            rng,
            stats,
            events,
            path: Some(path.to_path_buf()),
            file,
            writable: options.write,
            header,
            encrypted_header,
            header_persisted,
            size,
            chunks: ChunkCache::default(),
            last_modified,
            handles: 1,
        };
        if options.truncate {
            this.truncate(0)?;
        }
        Ok(this)
    }

    /// `OpenCryptoFile.initFileSize`: an undefined ciphertext size counts as an empty file.
    fn initial_size(cryptor: &Cryptor, ciphertext_size: u64) -> u64 {
        if ciphertext_size == 0 {
            return 0;
        }
        let header = cryptor.file_header_cryptor().header_size() as u64;
        match ciphertext_size
            .checked_sub(header)
            .map(|payload| cryptor.file_content_cryptor().cleartext_size(payload))
        {
            Some(Ok(size)) => size,
            _ => 0, // "Invalid cipher text file size. Assuming empty file."
        }
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }
    pub fn set_path(&mut self, path: Option<PathBuf>) {
        self.path = path;
    }
    pub fn is_writable(&self) -> bool {
        self.writable
    }
    /// Re-opens the ciphertext with write access (a second, writable handle joined a read-only one).
    pub fn reopen_writable(&mut self) -> io::Result<()> {
        if self.writable {
            return Ok(());
        }
        let Some(path) = &self.path else {
            return Err(super::invalid_input("file was deleted"));
        };
        self.file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;
        self.writable = true;
        Ok(())
    }
    pub fn size(&self) -> u64 {
        self.size
    }
    pub fn last_modified(&self) -> Option<SystemTime> {
        self.last_modified
    }
    pub fn set_last_modified(&mut self, time: SystemTime) {
        self.last_modified = Some(time);
    }
    pub fn handles(&self) -> usize {
        self.handles
    }
    pub fn retain(&mut self) {
        self.handles += 1;
    }
    /// Returns the remaining handle count.
    pub fn release(&mut self) -> usize {
        self.handles = self.handles.saturating_sub(1);
        self.handles
    }

    /// `CleartextFileChannel.readLocked`: returns 0 at or beyond EOF.
    pub fn read_at(&mut self, dst: &mut [u8], position: u64) -> io::Result<usize> {
        if position >= self.size {
            return Ok(0);
        }
        let limit = (self.size - position).min(dst.len() as u64) as usize;
        let chunk_size = self.cryptor.file_content_cryptor().cleartext_chunk_size() as u64;
        let mut read = 0usize;
        while read < limit {
            let pos = position + read as u64;
            let index = pos / chunk_size;
            let offset = (pos % chunk_size) as usize;
            let chunk = self.chunk(index)?;
            let available = chunk.data.len().saturating_sub(offset);
            if available == 0 {
                break; // inconsistent ciphertext: shorter than its size claims
            }
            let len = available.min(limit - read);
            dst[read..read + len].copy_from_slice(&chunk.data[offset..offset + len]);
            read += len;
        }
        self.stats.add_bytes_read(read as u64);
        Ok(read)
    }

    /// `CleartextFileChannel.writeLocked`: a position beyond EOF zero-fills the gap first.
    pub fn write_at(&mut self, src: &[u8], position: u64) -> io::Result<usize> {
        if !self.writable {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "file not opened for writing",
            ));
        }
        let old_size = self.size;
        if position.checked_add(src.len() as u64).is_none() {
            return Err(super::invalid_input("file offset out of range"));
        }
        let written = if position > old_size {
            let gap = position - old_size;
            self.write_internal(ByteSource { zeroes: gap, src }, old_size)? - gap
        } else {
            self.write_internal(ByteSource { zeroes: 0, src }, position)?
        };
        // `CleartextFileChannel.writeLocked` counts the caller's bytes, not the zero-filled gap.
        self.stats.add_bytes_written(written);
        Ok(written as usize)
    }

    fn write_internal(&mut self, mut src: ByteSource<'_>, position: u64) -> io::Result<u64> {
        self.write_header_if_needed()?;
        let chunk_size = self.cryptor.file_content_cryptor().cleartext_chunk_size();
        let mut written: u64 = 0;
        while src.remaining() > 0 {
            let current = position
                .checked_add(written)
                .ok_or_else(|| super::invalid_input("file offset out of range"))?;
            let index = current / chunk_size as u64;
            let offset = (current % chunk_size as u64) as usize;
            let len = src.remaining().min((chunk_size - offset) as u64) as usize;
            if offset == 0 && len == chunk_size {
                // complete chunk: no need to load and decrypt it first
                let mut data = Zeroizing::new(vec![0u8; chunk_size]);
                src.copy_to(&mut data);
                self.put_chunk(index, Chunk { data, dirty: true })?;
            } else {
                let chunk = self.chunk(index)?;
                if chunk.data.len() < offset + len {
                    chunk.data.resize(offset + len, 0);
                }
                src.copy_to(&mut chunk.data[offset..offset + len]);
                chunk.dirty = true;
            }
            written += len as u64;
        }
        let end = position
            .checked_add(written)
            .ok_or_else(|| super::invalid_input("file offset out of range"))?;
        self.size = self.size.max(end);
        self.last_modified = Some(SystemTime::now());
        Ok(written)
    }

    /// `CleartextFileChannel.truncateLocked`
    pub fn truncate(&mut self, new_size: u64) -> io::Result<()> {
        if !self.writable {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "file not opened for writing",
            ));
        }
        if new_size >= self.size {
            return Ok(());
        }
        let chunk_size = self.cryptor.file_content_cryptor().cleartext_chunk_size() as u64;
        let size_of_incomplete_chunk = (new_size % chunk_size) as usize;
        if size_of_incomplete_chunk > 0 {
            let chunk = self.chunk(new_size / chunk_size)?;
            chunk.data.truncate(size_of_incomplete_chunk);
            chunk.dirty = true;
        }
        let ciphertext_size = self.cryptor.file_header_cryptor().header_size() as u64
            + self
                .cryptor
                .file_content_cryptor()
                .ciphertext_size(new_size);
        self.flush()?;
        self.chunks.clear(); // no chunk after new_size may be written during a later eviction
        self.file.set_len(ciphertext_size)?;
        self.size = new_size;
        self.last_modified = Some(SystemTime::now());
        Ok(())
    }

    /// Whether [`flush`](Self::flush) would write anything -- an unwritten header or a dirty
    /// chunk. Always `false` for a read-only file, whose `flush` is a no-op.
    pub fn is_dirty(&self) -> bool {
        self.writable && (!self.header_persisted || self.chunks.any_dirty())
    }

    /// Persists the header (if new) and every dirty chunk; a no-op for read-only files.
    pub fn flush(&mut self) -> io::Result<()> {
        if !self.writable {
            return Ok(());
        }
        self.write_header_if_needed()?;
        for index in self.chunks.indices() {
            if let Some(chunk) = self.chunks.get_mut(index) {
                if chunk.dirty {
                    encrypt_and_write(
                        &self.cryptor,
                        &mut *self.rng,
                        &self.file,
                        &self.header,
                        &self.stats,
                        index,
                        &chunk.data,
                    )?;
                    chunk.dirty = false;
                }
            }
        }
        Ok(())
    }

    /// `force`: flush + fsync (+ mtime when `metadata`).
    pub fn sync(&mut self, metadata: bool) -> io::Result<()> {
        self.flush()?;
        if metadata {
            self.file.sync_all()?;
            self.persist_last_modified()
        } else {
            self.file.sync_data()
        }
    }

    /// `CleartextFileChannel.persistLastModified`: writes chunk by chunk changed the ciphertext's
    /// mtime; restore the cleartext one and touch atime.
    pub fn persist_last_modified(&mut self) -> io::Result<()> {
        let mut times = std::fs::FileTimes::new().set_accessed(SystemTime::now());
        if let (true, Some(modified)) = (self.writable, self.last_modified) {
            times = times.set_modified(modified);
        }
        self.file.set_times(times)
    }

    fn write_header_if_needed(&mut self) -> io::Result<()> {
        if !self.header_persisted {
            self.file.write_all_at(&self.encrypted_header, 0)?;
            self.header_persisted = true;
        }
        Ok(())
    }

    /// `ChunkCache.getChunk`
    fn chunk(&mut self, index: u64) -> io::Result<&mut Chunk> {
        self.stats.add_chunk_cache_access();
        if !self.chunks.contains(index) {
            self.stats.add_chunk_cache_miss();
            let data = self.load_chunk(index)?;
            self.put_chunk(index, Chunk { data, dirty: false })?;
        }
        self.chunks.touch(index);
        self.chunks
            .get_mut(index)
            .ok_or_else(|| io::Error::other(format!("chunk {index} vanished from the cache")))
    }

    /// `ChunkLoader.load`: beyond EOF the chunk is empty.
    fn load_chunk(&mut self, index: u64) -> io::Result<Zeroizing<Vec<u8>>> {
        let position = ciphertext_position(&self.cryptor, index)?;
        let content = self.cryptor.file_content_cryptor();
        let ciphertext_chunk_size = content.ciphertext_chunk_size();
        let mut buf = vec![0u8; ciphertext_chunk_size];
        let read = read_fully_at(&self.file, &mut buf, position)?;
        if read == 0 {
            return Ok(Zeroizing::new(Vec::new()));
        }
        let cleartext = content
            .decrypt_chunk(&buf[..read], index, &self.header)
            .map_err(|e| {
                (self.events)(FilesystemEvent::DecryptionFailed {
                    ciphertext_path: self.path.clone().unwrap_or_default(),
                    reason: e.to_string(),
                });
                super::invalid_data(format!("Unauthentic ciphertext in chunk {index}: {e}"))
            })?;
        self.stats.add_bytes_decrypted(cleartext.len() as u64);
        Ok(cleartext)
    }

    /// `ChunkCache.putChunk` + eviction: the least recently used chunk is saved before it leaves the cache.
    fn put_chunk(&mut self, index: u64, chunk: Chunk) -> io::Result<()> {
        if !self.chunks.contains(index) {
            while self.chunks.len() >= MAX_CACHED_CLEARTEXT_CHUNKS {
                let Some((evicted_index, evicted)) = self.chunks.pop_lru() else {
                    break;
                };
                if evicted.dirty {
                    encrypt_and_write(
                        &self.cryptor,
                        &mut *self.rng,
                        &self.file,
                        &self.header,
                        &self.stats,
                        evicted_index,
                        &evicted.data,
                    )?;
                }
            }
        }
        self.chunks.insert(index, chunk);
        Ok(())
    }
}

/// `ChunkSaver.save`
fn encrypt_and_write(
    cryptor: &Cryptor,
    rng: &mut dyn Rng,
    file: &File,
    header: &FileHeader,
    stats: &CryptoFsStats,
    index: u64,
    cleartext: &[u8],
) -> io::Result<()> {
    let position = ciphertext_position(cryptor, index)?;
    stats.add_bytes_encrypted(cleartext.len() as u64);
    let ciphertext = cryptor
        .file_content_cryptor()
        .encrypt_chunk(cleartext, index, header, rng);
    file.write_all_at(&ciphertext, position)
}

/// Where chunk `index` starts in the ciphertext. Cleartext offsets up to `u64::MAX` map to
/// ciphertext offsets slightly beyond it, so the arithmetic is checked instead of wrapping onto
/// an unrelated chunk.
fn ciphertext_position(cryptor: &Cryptor, index: u64) -> io::Result<u64> {
    index
        .checked_mul(cryptor.file_content_cryptor().ciphertext_chunk_size() as u64)
        .and_then(|p| p.checked_add(cryptor.file_header_cryptor().header_size() as u64))
        .ok_or_else(|| super::invalid_input("file offset out of range"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rng::DetRng;
    use crate::crypto::stream::{decrypt_all, encrypt_all};
    use crate::fs::{discard_events, testutil};
    use crate::{CipherCombo, Cryptor};
    use proptest::prelude::*;

    fn cryptor(combo: CipherCombo) -> Arc<Cryptor> {
        Arc::new(Cryptor::new(combo, &testutil::masterkey()))
    }

    fn open(
        cryptor: &Arc<Cryptor>,
        path: &Path,
        options: OpenOptions,
    ) -> io::Result<OpenCryptoFile> {
        OpenCryptoFile::open(
            cryptor.clone(),
            Box::new(DetRng::default()),
            Arc::new(CryptoFsStats::default()),
            discard_events(),
            path,
            options,
        )
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 7) as u8).collect()
    }

    #[test]
    fn chunk_offsets_reject_overflow_but_cover_huge_files() {
        let cryptor = cryptor(CipherCombo::SivGcm);
        let cleartext_chunk = cryptor.file_content_cryptor().cleartext_chunk_size() as u64;
        // a cleartext offset of 2^62 is still addressable
        assert!(ciphertext_position(&cryptor, (1u64 << 62) / cleartext_chunk).is_ok());
        let err = ciphertext_position(&cryptor, u64::MAX).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("out of range"), "{err}");
        // the same guard on the writing side, before any chunk is touched
        let dir = tempfile::tempdir().unwrap();
        let mut f = open(&cryptor, &dir.path().join("f"), OpenOptions::write_new()).unwrap();
        assert_eq!(
            f.write_at(b"x", u64::MAX).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn reads_java_written_files_at_arbitrary_offsets() {
        let (dir, cryptor, _) = testutil::new_vault(220);
        let data = pattern(100_000);
        let path = dir.path().join("f");
        std::fs::write(
            &path,
            encrypt_all(&cryptor, &mut DetRng::default(), &data).unwrap(),
        )
        .unwrap();
        let mut f = open(&cryptor, &path, OpenOptions::read_only()).unwrap();
        assert_eq!(f.size(), 100_000);
        for (pos, len) in [
            (0, 10),
            (32_760, 20),
            (65_535, 2),
            (99_990, 100),
            (100_000, 5),
            (200_000, 1),
        ] {
            let mut buf = vec![0u8; len];
            let n = f.read_at(&mut buf, pos).unwrap();
            let expected_len = (100_000u64.saturating_sub(pos) as usize).min(len);
            assert_eq!(n, expected_len, "pos {pos}");
            let start = (pos as usize).min(data.len());
            assert_eq!(&buf[..n], &data[start..start + n]);
        }
        assert!(f.write_at(b"x", 0).is_err(), "read-only handle");
    }

    #[test]
    fn empty_file_is_header_only_and_reads_as_empty() {
        let (dir, cryptor, _) = testutil::new_vault(220);
        let path = dir.path().join("empty");
        let mut f = open(&cryptor, &path, OpenOptions::write_new()).unwrap();
        f.flush().unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            cryptor.file_header_cryptor().header_size() as u64
        );
        drop(f);
        let f = open(&cryptor, &path, OpenOptions::read_only()).unwrap();
        assert_eq!(f.size(), 0);
        // Java writes header + empty chunk via streams; that file has cleartext size 0 too
        std::fs::write(
            &path,
            encrypt_all(&cryptor, &mut DetRng::default(), b"").unwrap(),
        )
        .unwrap();
        let f = open(&cryptor, &path, OpenOptions::read_only()).unwrap();
        assert_eq!(f.size(), 0);
    }

    #[test]
    fn writes_across_chunks_gaps_and_truncates_like_java() {
        for combo in [CipherCombo::SivGcm, CipherCombo::SivCtrMac] {
            let dir = tempfile::tempdir().unwrap();
            let cryptor = cryptor(combo);
            let path = dir.path().join("f");
            let mut f = open(&cryptor, &path, OpenOptions::write_new()).unwrap();
            let data = pattern(70_000);
            assert_eq!(f.write_at(&data[..40_000], 0).unwrap(), 40_000);
            assert_eq!(f.write_at(&data[40_000..], 40_000).unwrap(), 30_000);
            assert_eq!(f.size(), 70_000);
            // overwrite in the middle of chunk 1
            f.write_at(&[0xFF; 100], 33_000).unwrap();
            // gap: zero fill between EOF and the new position
            assert_eq!(f.write_at(b"tail", 80_000).unwrap(), 4);
            assert_eq!(f.size(), 80_004);
            f.flush().unwrap();
            let mut expected = data.clone();
            expected[33_000..33_100].copy_from_slice(&[0xFF; 100]);
            expected.resize(80_000, 0);
            expected.extend_from_slice(b"tail");
            assert_eq!(
                decrypt_all(&cryptor, &std::fs::read(&path).unwrap()).unwrap(),
                expected
            );
            let ciphertext_len = cryptor.file_header_cryptor().header_size() as u64
                + cryptor.file_content_cryptor().ciphertext_size(80_004);
            assert_eq!(std::fs::metadata(&path).unwrap().len(), ciphertext_len);
            // truncate inside chunk 1, then to a chunk boundary, then to 0
            f.truncate(33_050).unwrap();
            assert_eq!(f.size(), 33_050);
            expected.truncate(33_050);
            assert_eq!(
                decrypt_all(&cryptor, &std::fs::read(&path).unwrap()).unwrap(),
                expected
            );
            f.truncate(32_768).unwrap();
            expected.truncate(32_768);
            assert_eq!(
                decrypt_all(&cryptor, &std::fs::read(&path).unwrap()).unwrap(),
                expected
            );
            f.truncate(0).unwrap();
            assert_eq!(
                std::fs::metadata(&path).unwrap().len(),
                cryptor.file_header_cryptor().header_size() as u64
            );
            // growing again after truncate to 0 reuses the header (no size 0 file)
            f.write_at(b"again", 0).unwrap();
            f.flush().unwrap();
            assert_eq!(
                decrypt_all(&cryptor, &std::fs::read(&path).unwrap()).unwrap(),
                b"again"
            );
        }
    }

    #[test]
    fn cache_evicts_least_recently_used_and_saves_dirty_chunks() {
        let (dir, cryptor, _) = testutil::new_vault(220);
        let path = dir.path().join("f");
        let mut f = open(&cryptor, &path, OpenOptions::write_new()).unwrap();
        let chunk = cryptor.file_content_cryptor().cleartext_chunk_size();
        let data = pattern(chunk * 8 + 5);
        // write chunk by chunk, out of order: more than MAX_CACHED chunks are dirty at once
        for i in (0..9).rev() {
            let start = i * chunk;
            let end = (start + chunk).min(data.len());
            f.write_at(&data[start..end], start as u64).unwrap();
        }
        assert!(f.chunks.len() <= MAX_CACHED_CLEARTEXT_CHUNKS);
        let stats = f.stats.snapshot();
        assert!(
            stats.bytes_encrypted > 0,
            "evictions wrote chunks before flush"
        );
        f.flush().unwrap();
        assert_eq!(
            decrypt_all(&cryptor, &std::fs::read(&path).unwrap()).unwrap(),
            data
        );
        assert_eq!(f.stats.snapshot().bytes_written, data.len() as u64);
    }

    #[test]
    fn open_options_semantics() {
        let (dir, cryptor, _) = testutil::new_vault(220);
        let path = dir.path().join("f");
        assert_eq!(
            open(&cryptor, &path, OpenOptions::read_only())
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        let mut f = open(&cryptor, &path, OpenOptions::write_new()).unwrap();
        f.write_at(b"hello", 0).unwrap();
        f.flush().unwrap();
        drop(f);
        assert_eq!(
            open(&cryptor, &path, OpenOptions::write_new())
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        let f = open(&cryptor, &path, OpenOptions::read_write()).unwrap();
        assert_eq!(f.size(), 5);
        drop(f);
        let mut f = open(&cryptor, &path, OpenOptions::write_truncate()).unwrap();
        assert_eq!(f.size(), 0);
        f.write_at(b"x", 0).unwrap();
        f.flush().unwrap();
        drop(f);
        assert_eq!(
            decrypt_all(&cryptor, &std::fs::read(&path).unwrap()).unwrap(),
            b"x"
        );
        // a file with a garbage header cannot be opened for reading
        std::fs::write(&path, vec![0u8; 200]).unwrap();
        assert_eq!(
            open(&cryptor, &path, OpenOptions::read_only())
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        // truncated header
        std::fs::write(&path, vec![0u8; 10]).unwrap();
        assert!(open(&cryptor, &path, OpenOptions::read_only()).is_err());
    }

    #[derive(Debug, Clone)]
    enum Op {
        Write { pos: u64, len: usize },
        Truncate(u64),
    }

    fn ops() -> impl Strategy<Value = Vec<Op>> {
        prop::collection::vec(
            prop_oneof![
                (0u64..120_000, 1usize..40_000).prop_map(|(pos, len)| Op::Write { pos, len }),
                (0u64..120_000).prop_map(Op::Truncate),
            ],
            1..12,
        )
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(24))]
        #[test]
        fn random_writes_and_truncates_match_an_in_memory_model(ops in ops()) {
            let dir = tempfile::tempdir().unwrap();
            let cryptor = cryptor(CipherCombo::SivGcm);
            let path = dir.path().join("f");
            let mut f = open(&cryptor, &path, OpenOptions::write_new()).unwrap();
            let mut model: Vec<u8> = Vec::new();
            for (i, op) in ops.iter().enumerate() {
                match *op {
                    Op::Write { pos, len } => {
                        let data: Vec<u8> = (0..len).map(|j| (i * 31 + j) as u8).collect();
                        prop_assert_eq!(f.write_at(&data, pos).unwrap(), len);
                        let end = pos as usize + len;
                        if model.len() < end { model.resize(end, 0); }
                        model[pos as usize..end].copy_from_slice(&data);
                    }
                    Op::Truncate(size) => {
                        f.truncate(size).unwrap();
                        model.truncate(size as usize);
                    }
                }
                prop_assert_eq!(f.size(), model.len() as u64);
                let mut buf = vec![0u8; model.len()];
                let n = f.read_at(&mut buf, 0).unwrap();
                prop_assert_eq!(&buf[..n], &model[..]);
            }
            f.flush().unwrap();
            prop_assert_eq!(decrypt_all(&cryptor, &std::fs::read(&path).unwrap()).unwrap(), model);
        }
    }
}
