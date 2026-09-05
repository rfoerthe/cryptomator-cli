//! Whole-file streaming encryption (`common/EncryptingWritableByteChannel.java`, `common/DecryptingReadableByteChannel.java`).
//! Java always flushes a final chunk on close, even an empty one; `finish()` reproduces that.
use crate::crypto::cryptor::Cryptor;
use crate::crypto::header::FileHeader;
use crate::crypto::rng::Rng;
use std::io::{self, Read, Write};
use zeroize::Zeroizing;

/// Streaming encryptor: cleartext in, `header || chunk*` out.
///
/// **Dropping the writer without calling [`finish`](Self::finish) discards the buffered cleartext and
/// never writes the mandatory final chunk.** The ciphertext produced so far is then truncated and no
/// longer decryptable as a whole file (`DecryptingReader` fails on the missing tail), so every
/// successful write path must end in `finish()`. `Drop` deliberately does not flush: it could not
/// report an I/O error.
pub struct EncryptingWriter<'a, W: Write> {
    dest: W,
    cryptor: &'a Cryptor,
    rng: &'a mut dyn Rng,
    header: FileHeader,
    /// Buffered cleartext of the chunk currently being filled; wiped on drop.
    buffer: Zeroizing<Vec<u8>>,
    header_written: bool,
    chunk_number: u64,
}

impl<W: Write> std::fmt::Debug for EncryptingWriter<'_, W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptingWriter")
            .field("chunk_number", &self.chunk_number)
            .finish_non_exhaustive()
    }
}

impl<'a, W: Write> EncryptingWriter<'a, W> {
    pub fn new(dest: W, cryptor: &'a Cryptor, rng: &'a mut dyn Rng) -> Self {
        let header = cryptor.file_header_cryptor().create(rng);
        let capacity = cryptor.file_content_cryptor().cleartext_chunk_size();
        Self {
            dest,
            cryptor,
            rng,
            header,
            buffer: Zeroizing::new(Vec::with_capacity(capacity)),
            header_written: false,
            chunk_number: 0,
        }
    }

    fn write_header_on_first_write(&mut self) -> io::Result<()> {
        if !self.header_written {
            let encrypted = self
                .cryptor
                .file_header_cryptor()
                .encrypt_header(&self.header)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            self.dest.write_all(&encrypted)?;
            self.header_written = true;
        }
        Ok(())
    }

    fn encrypt_and_flush_buffer(&mut self) -> io::Result<()> {
        let chunk = self.cryptor.file_content_cryptor().encrypt_chunk(
            &self.buffer,
            self.chunk_number,
            &self.header,
            self.rng,
        );
        self.chunk_number += 1;
        self.dest.write_all(&chunk)?;
        self.buffer.clear();
        Ok(())
    }

    /// Writes the header (if nothing was written yet) and the final chunk, then returns the destination.
    pub fn finish(mut self) -> io::Result<W> {
        self.write_header_on_first_write()?;
        self.encrypt_and_flush_buffer()?;
        self.dest.flush()?;
        Ok(self.dest)
    }
}

impl<W: Write> Write for EncryptingWriter<'_, W> {
    fn write(&mut self, src: &[u8]) -> io::Result<usize> {
        self.write_header_on_first_write()?;
        let chunk_size = self.cryptor.file_content_cryptor().cleartext_chunk_size();
        let mut written = 0;
        while written < src.len() {
            let room = chunk_size - self.buffer.len();
            let take = room.min(src.len() - written);
            self.buffer.extend_from_slice(&src[written..written + take]);
            written += take;
            if self.buffer.len() == chunk_size {
                self.encrypt_and_flush_buffer()?;
            }
        }
        Ok(written)
    }

    /// Flushes the destination only.
    ///
    /// Chunks are all-or-nothing (each carries its own nonce and tag), so a partially filled chunk
    /// cannot be emitted here; buffered cleartext stays buffered until it is full or
    /// [`finish`](Self::finish) is called.
    fn flush(&mut self) -> io::Result<()> {
        self.dest.flush()
    }
}

pub struct DecryptingReader<'a, R: Read> {
    src: R,
    cryptor: &'a Cryptor,
    header: Option<FileHeader>,
    /// Cleartext of the chunk currently being served; wiped on drop.
    cleartext: Zeroizing<Vec<u8>>,
    position: usize,
    reached_eof: bool,
    chunk_number: u64,
}

impl<R: Read> std::fmt::Debug for DecryptingReader<'_, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptingReader")
            .field("chunk_number", &self.chunk_number)
            .finish_non_exhaustive()
    }
}

impl<'a, R: Read> DecryptingReader<'a, R> {
    pub fn new(src: R, cryptor: &'a Cryptor) -> Self {
        Self {
            src,
            cryptor,
            header: None,
            cleartext: Zeroizing::new(Vec::new()),
            position: 0,
            reached_eof: false,
            chunk_number: 0,
        }
    }

    /// Reads until `buf` is full or the source hits EOF; returns the number of bytes read.
    fn fill(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut total = 0;
        while total < buf.len() {
            match self.src.read(&mut buf[total..]) {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(total)
    }

    fn load_header_if_necessary(&mut self) -> io::Result<()> {
        if self.header.is_none() {
            let mut header_buf = vec![0u8; self.cryptor.file_header_cryptor().header_size()];
            let read = self.fill(&mut header_buf)?;
            if read != header_buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Unable to read header from channel.",
                ));
            }
            let header = self
                .cryptor
                .file_header_cryptor()
                .decrypt_header(&header_buf)
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Unauthentic ciphertext: {e}"),
                    )
                })?;
            self.header = Some(header);
        }
        Ok(())
    }

    /// Returns false at EOF.
    fn load_next_cleartext_chunk(&mut self) -> io::Result<bool> {
        let mut ciphertext_chunk =
            vec![0u8; self.cryptor.file_content_cryptor().ciphertext_chunk_size()];
        let read = self.fill(&mut ciphertext_chunk)?;
        if read == 0 {
            self.reached_eof = true;
            return Ok(false);
        }
        let header = self.header.as_ref().expect("header loaded before chunks");
        self.cleartext = self
            .cryptor
            .file_content_cryptor()
            .decrypt_chunk(&ciphertext_chunk[..read], self.chunk_number, header)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Unauthentic ciphertext: {e}"),
                )
            })?;
        self.chunk_number += 1;
        self.position = 0;
        Ok(true)
    }
}

impl<R: Read> Read for DecryptingReader<'_, R> {
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        self.load_header_if_necessary()?;
        let mut result = 0;
        while result < dst.len() && !self.reached_eof {
            if self.position < self.cleartext.len() || self.load_next_cleartext_chunk()? {
                let available = &self.cleartext[self.position..];
                let take = available.len().min(dst.len() - result);
                dst[result..result + take].copy_from_slice(&available[..take]);
                self.position += take;
                result += take;
            }
        }
        Ok(result)
    }
}

pub fn encrypt_all(cryptor: &Cryptor, rng: &mut dyn Rng, cleartext: &[u8]) -> io::Result<Vec<u8>> {
    let mut writer = EncryptingWriter::new(Vec::new(), cryptor, rng);
    writer.write_all(cleartext)?;
    writer.finish()
}

pub fn decrypt_all(cryptor: &Cryptor, ciphertext: &[u8]) -> io::Result<Vec<u8>> {
    let mut reader = DecryptingReader::new(ciphertext, cryptor);
    let mut out = Vec::new();
    reader.read_to_end(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::cryptor::{CipherCombo, Cryptor};
    use crate::crypto::masterkey::Masterkey;
    use crate::crypto::rng::DetRng;
    use data_encoding::HEXLOWER;
    use sha2::{Digest, Sha256};

    // cryptolib 2.2.2 EncryptingWritableByteChannel with a fresh deterministic CryptorImpl per stream.
    const GCM_STREAM_EMPTY: &str = "a0a1a2a3a4a5a6a7a8a9aaab19e783d2ba34fd40cec8297cb7cb726dc419efa72a0ef8d720b39839bf6ab7c216b3813867eb99f6a8d57bbc501ceb787b03fa91363626a6cccdcecfd0d1d2d3d4d5d6d739cd8eb4a54f66cd826f0381487942a4";
    const GCM_DIRID_UUID: &str = "a0a1a2a3a4a5a6a7a8a9aaab19e783d2ba34fd40cec8297cb7cb726dc419efa72a0ef8d720b39839bf6ab7c216b3813867eb99f6a8d57bbc501ceb787b03fa91363626a6cccdcecfd0d1d2d3d4d5d6d7a2df2690b799eeb51ea269f50546f6f049df5670afc00da82d04a938442fc7b39f8e0be99b3cada7d91cbee0ff263c10e6b0debf";
    const GCM_STREAM_40000_SHA256: &str =
        "d8cff2ee78a481ed855805e9ef095f8d593b223cc5dd4325c8b3fbf2e0584dfa";
    const CTRMAC_STREAM_EMPTY: &str = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf2360fe02894783f2bffa5a36bfbe5a57596851aac0fc2b972c4b3a49a3f5155851222e6924aa57c5a12c9850de5595b2e1a07a8fb733a48864582784ef3c2c0dd39f245236529accd0d1d2d3d4d5d6d7d8d9dadbdcdddedf70d82713a3f441f675b5b8c0c348e1d981285c7907cdf92b9b56d65c65e8c5f2";
    const CTRMAC_STREAM_40000_SHA256: &str =
        "85ac051a68fd5a1811046347a521d317e9355c464f6f3cb8cf6e8723845136fe";
    const DIR_ID: &str = "2f3a8f2e-0b8a-4e6f-9c5d-1a2b3c4d5e6f";

    fn cryptor(combo: CipherCombo) -> Cryptor {
        let mut raw = [0u8; 64];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = i as u8;
        }
        Cryptor::new(combo, &Masterkey::from_raw(raw))
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 7) as u8).collect()
    }

    #[test]
    fn empty_stream_writes_header_and_one_empty_chunk() {
        for (combo, expected) in [
            (CipherCombo::SivGcm, GCM_STREAM_EMPTY),
            (CipherCombo::SivCtrMac, CTRMAC_STREAM_EMPTY),
        ] {
            let c = cryptor(combo);
            let out = encrypt_all(&c, &mut DetRng::default(), b"").unwrap();
            assert_eq!(HEXLOWER.encode(&out), expected, "{combo}");
            assert_eq!(decrypt_all(&c, &out).unwrap(), b"");
        }
    }

    #[test]
    fn dirid_backup_of_uuid_matches_java() {
        let c = cryptor(CipherCombo::SivGcm);
        let out = encrypt_all(&c, &mut DetRng::default(), DIR_ID.as_bytes()).unwrap();
        assert_eq!(HEXLOWER.encode(&out), GCM_DIRID_UUID);
        assert_eq!(decrypt_all(&c, &out).unwrap(), DIR_ID.as_bytes());
    }

    #[test]
    fn multi_chunk_stream_matches_java_and_round_trips() {
        for (combo, expected_sha, expected_len) in [
            (CipherCombo::SivGcm, GCM_STREAM_40000_SHA256, 40124usize),
            (
                CipherCombo::SivCtrMac,
                CTRMAC_STREAM_40000_SHA256,
                40184usize,
            ),
        ] {
            let c = cryptor(combo);
            let data = pattern(40000);
            let mut rng = DetRng::default();
            let mut writer = EncryptingWriter::new(Vec::new(), &c, &mut rng);
            // write in odd-sized pieces to exercise buffering across chunk boundaries
            for piece in data.chunks(12345) {
                writer.write_all(piece).unwrap();
            }
            let out = writer.finish().unwrap();
            assert_eq!(out.len(), expected_len, "{combo}");
            assert_eq!(
                HEXLOWER.encode(&Sha256::digest(&out)),
                expected_sha,
                "{combo}"
            );
            let mut reader = DecryptingReader::new(&out[..], &c);
            let mut got = Vec::new();
            reader.read_to_end(&mut got).unwrap();
            assert_eq!(got, data);
        }
    }

    #[test]
    fn small_reads_return_all_data() {
        let c = cryptor(CipherCombo::SivGcm);
        let data = pattern(70000);
        let out = encrypt_all(&c, &mut DetRng::default(), &data).unwrap();
        let mut reader = DecryptingReader::new(&out[..], &c);
        let mut got = Vec::new();
        let mut buf = [0u8; 1000];
        loop {
            let n = reader.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got, data);
    }

    #[test]
    fn truncated_header_is_unexpected_eof() {
        let c = cryptor(CipherCombo::SivGcm);
        let out = encrypt_all(&c, &mut DetRng::default(), b"abc").unwrap();
        let err = decrypt_all(&c, &out[..40]).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn tampered_chunk_is_invalid_data() {
        let c = cryptor(CipherCombo::SivGcm);
        let mut out = encrypt_all(&c, &mut DetRng::default(), b"abc").unwrap();
        let last = out.len() - 1;
        out[last] ^= 1;
        let err = decrypt_all(&c, &out).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}
