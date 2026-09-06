use std::io;
use std::os::fd::AsFd;
use std::os::fd::BorrowedFd;
use std::sync::{Arc, Mutex};

use nix::errno::Errno;

use crate::dev_fuse::DevFuse;
use crate::passthrough::BackingId;

/// The size of a `fuse_in_header`, i.e. the smallest request there can be.
const IN_HEADER_LEN: usize = std::mem::size_of::<crate::ll::fuse_abi::fuse_in_header>();

/// The `len` field of a `fuse_in_header`: the total size of the request, header included, in
/// native byte order. `None` while fewer than those four bytes have been read.
fn announced_len(read_so_far: &[u8]) -> Option<usize> {
    let head: [u8; 4] = read_so_far.get(..4)?.try_into().ok()?;
    Some(u32::from_ne_bytes(head) as usize)
}

/// A raw communication channel to the FUSE kernel driver
#[derive(Debug, Clone)]
pub(crate) struct Channel {
    device: Arc<DevFuse>,
    /// Bytes that arrived after the request [`receive_retrying`](Channel::receive_retrying) last
    /// returned, waiting to be served as the next request. Always empty on `/dev/fuse`; see that
    /// method. Shared by every clone of this channel, because they share the file descriptor the
    /// bytes were taken from -- a cloned *fd* (`clone_fd`) starts with its own empty one.
    spill: Arc<Mutex<Vec<u8>>>,
}

impl AsFd for Channel {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.device.as_fd()
    }
}

impl Channel {
    /// Create a new communication channel to the kernel driver by mounting the
    /// given path. The kernel driver will delegate filesystem operations of
    /// the given path to the channel.
    pub(crate) fn new(device: Arc<DevFuse>) -> Self {
        Self {
            device,
            spill: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Receives data up to the capacity of the given buffer (can block).
    fn receive(&self, buffer: &mut [u8]) -> nix::Result<usize> {
        nix::unistd::read(&self.device, buffer)
    }

    /// Receives exactly one whole request (can block), retrying on errors that are safe to retry
    /// (ENOENT, EINTR, EAGAIN).
    ///
    /// - ENOENT: Operation interrupted. According to FUSE, this is safe to retry.
    /// - EINTR: Interrupted system call, retry.
    /// - EAGAIN: Explicitly instructed to try again.
    ///
    /// The caller treats the returned bytes as one request, so this has to deliver exactly that:
    /// reading keeps going until the buffer holds the `len` bytes the `fuse_in_header` announces,
    /// and anything read beyond that request is kept for the next call.
    ///
    /// On `/dev/fuse` neither ever happens: the device is message oriented and hands out exactly
    /// one whole request per `read`, so the first read is already the whole request and nothing is
    /// left over. A channel that is a **stream socket** -- which is what FUSE-T's
    /// `fuse_mount_compat25` returns on macOS -- has no message boundaries at all, and both halves
    /// matter there:
    ///
    /// * FUSE-T sends a WRITE request as a header write followed by a separate data write, so a
    ///   single `read` may return only the first 80 bytes of a 4176-byte request. Handing that to
    ///   the request parser produced a request whose payload was missing, and the peer then waited
    ///   for a reply that never came.
    /// * Two requests written in quick succession coalesce in the socket buffer and arrive in one
    ///   `read`. The event loop parses the first and would drop the second on the floor -- the
    ///   peer waits for that reply forever and the volume stalls.
    ///
    /// `Ok(0)` means end of file: the peer hung up, i.e. the volume was unmounted. A partial
    /// request left in the buffer at that point is discarded with it, because there is no longer
    /// anyone to answer. A request longer than the buffer is returned as far as it was read, as
    /// before; the parser rejects it and the session ends.
    ///
    /// Concurrency: clones of one channel share the leftover bytes, but two threads reading the
    /// same stream socket would tear requests apart regardless of this buffer. That cannot happen
    /// -- [`Session::run`](crate::Session::run) rejects `n_threads != 1` off Linux, and on Linux
    /// the channel is `/dev/fuse`, where the leftover buffer is never used.
    pub(crate) fn receive_retrying(&self, buffer: &mut [u8]) -> nix::Result<usize> {
        let capacity = buffer.len();
        let mut filled = self.take_spill(buffer);
        loop {
            match announced_len(&buffer[..filled]) {
                // A length no request can have, or one this buffer can never hold: reading on
                // would not help, so the bytes go to the parser, which rejects them and ends the
                // session -- exactly what happened before this fork.
                Some(len) if !(IN_HEADER_LEN..=capacity).contains(&len) => return Ok(filled),
                // The whole request is here; whatever follows it belongs to the next one.
                Some(len) if len <= filled => {
                    self.keep_spill(&buffer[len..filled]);
                    return Ok(len);
                }
                // Fewer than four bytes, or a request that is still incomplete. Neither can
                // survive a full buffer, but a `read` of zero bytes would spin.
                _ if filled >= capacity => return Ok(filled),
                _ => {}
            }
            match self.receive(&mut buffer[filled..]) {
                Ok(0) => return Ok(0), // EOF, dropping any partial request with it
                Ok(size) => filled += size,
                Err(Errno::ENOENT | Errno::EINTR | Errno::EAGAIN) => continue,
                Err(err) => return Err(err),
            }
        }
    }

    /// Moves the bytes left over from the last call to the front of `buffer` and reports how many
    /// there were. A poisoned lock means a reader panicked mid-request; the leftover is then
    /// meaningless and starting from nothing is the best that can be done.
    fn take_spill(&self, buffer: &mut [u8]) -> usize {
        let Ok(mut spill) = self.spill.lock() else {
            return 0;
        };
        let len = spill.len().min(buffer.len());
        buffer[..len].copy_from_slice(&spill[..len]);
        spill.clear();
        len
    }

    /// Remembers `rest` for the next call.
    fn keep_spill(&self, rest: &[u8]) {
        if let Ok(mut spill) = self.spill.lock() {
            spill.clear();
            spill.extend_from_slice(rest);
        }
    }

    /// Returns a sender object for this channel. The sender object can be
    /// used to send to the channel. Multiple sender objects can be used
    /// and they can safely be sent to other threads.
    pub(crate) fn sender(&self) -> ChannelSender {
        // Since write/writev syscalls are threadsafe, we can simply create
        // a sender by using the same file and use it in other threads.
        ChannelSender(self.device.clone())
    }

    /// Clone the FUSE device fd using FUSE_DEV_IOC_CLONE ioctl.
    ///
    /// This creates a new fd that can read FUSE requests independently,
    /// enabling true parallel request processing. The kernel distributes
    /// requests across all cloned fds.
    ///
    /// Requires Linux 4.5+. Returns an error on older kernels or non-Linux.
    #[cfg(target_os = "linux")]
    pub(crate) fn clone_fd(&self) -> io::Result<Channel> {
        use std::os::fd::AsRawFd;

        let new_dev = DevFuse::open()?;

        let mut source_fd = self.device.as_raw_fd() as u32;
        // SAFETY: fuse_dev_ioc_clone is a valid ioctl for /dev/fuse
        unsafe {
            crate::ll::ioctl::fuse_dev_ioc_clone(new_dev.as_raw_fd(), &mut source_fd)?;
        }

        Ok(Channel::new(Arc::new(new_dev)))
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ChannelSender(Arc<DevFuse>);

impl ChannelSender {
    pub(crate) fn send(&self, bufs: &[io::IoSlice<'_>]) -> io::Result<()> {
        write_all_vectored(bufs, |slices| nix::sys::uio::writev(&self.0, slices))
    }

    pub(crate) fn open_backing(&self, fd: BorrowedFd<'_>) -> std::io::Result<BackingId> {
        BackingId::create(&self.0, fd)
    }

    pub(crate) unsafe fn wrap_backing(&self, id: u32) -> BackingId {
        unsafe { BackingId::wrap_raw(&self.0, id) }
    }
}

/// Writes every byte of `bufs` through `writev`, looping until they are all gone.
///
/// `/dev/fuse` is message oriented and hands out one whole reply per `writev`, which is why
/// upstream only `debug_assert!`s the count. FUSE-T's channel is a **stream socket**: a blocking
/// write on one returns a *partial* count when a signal is delivered after some bytes have already
/// gone out (`SA_RESTART` does not undo a partial transfer), and replies run to `rwsize` bytes. A
/// truncated reply desynchronises the stream for good -- the peer reads the tail of one reply as
/// the head of the next and the volume hangs, the same failure mode the request-framing patch
/// fixed on the read side.
///
/// `writev` is a parameter rather than the file descriptor so the loop is testable with a writer
/// that accepts a fixed number of bytes per call.
///
/// # Errors
/// [`io::ErrorKind::WriteZero`] if the writer accepts nothing while bytes are still pending, and
/// whatever `writev` reports other than `EINTR`, which is retried.
fn write_all_vectored(
    bufs: &[io::IoSlice<'_>],
    mut writev: impl FnMut(&[io::IoSlice<'_>]) -> nix::Result<usize>,
) -> io::Result<()> {
    // `advance_slices` needs to rewrite the slice list in place, and the caller's is shared.
    let mut owned: Vec<io::IoSlice<'_>> = bufs.to_vec();
    let mut rest: &mut [io::IoSlice<'_>] = &mut owned;
    while !rest.is_empty() {
        match writev(rest) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "the FUSE channel accepted none of the reply",
                ));
            }
            Ok(written) => io::IoSlice::advance_slices(&mut rest, written),
            Err(Errno::EINTR) => {}
            Err(err) => return Err(err.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod send_test {
    use super::*;
    use std::cell::RefCell;

    fn slices<'a>(parts: &'a [&'a [u8]]) -> Vec<io::IoSlice<'a>> {
        parts.iter().map(|p| io::IoSlice::new(p)).collect()
    }

    /// The case the fork is about: a stream socket that takes a few bytes at a time. Every byte
    /// has to arrive, in order, across as many calls as it takes.
    #[test]
    fn a_short_write_is_resumed_until_everything_is_out() {
        let sink = RefCell::new(Vec::new());
        let calls = RefCell::new(0usize);
        let bufs = slices(&[b"header--", b"payload", b"!"]);
        write_all_vectored(&bufs, |slices| {
            *calls.borrow_mut() += 1;
            // Accept at most three bytes per call, taken from the front of the list.
            let mut taken = 0;
            for slice in slices {
                for byte in slice.iter() {
                    if taken == 3 {
                        break;
                    }
                    sink.borrow_mut().push(*byte);
                    taken += 1;
                }
                if taken == 3 {
                    break;
                }
            }
            Ok(taken)
        })
        .expect("the write completes");
        assert_eq!(sink.into_inner(), b"header--payload!");
        assert_eq!(calls.into_inner(), 6, "16 bytes at 3 bytes per call");
    }

    #[test]
    fn a_writer_that_takes_everything_is_called_once() {
        let calls = RefCell::new(0usize);
        let bufs = slices(&[b"one", b"two"]);
        write_all_vectored(&bufs, |slices| {
            *calls.borrow_mut() += 1;
            Ok(slices.iter().map(|s| s.len()).sum())
        })
        .expect("the write completes");
        assert_eq!(calls.into_inner(), 1);
    }

    /// A signal delivered before any byte went out: `writev` reports `EINTR` and the whole reply
    /// is still pending.
    #[test]
    fn eintr_is_retried() {
        let calls = RefCell::new(0usize);
        let bufs = slices(&[b"abc"]);
        write_all_vectored(&bufs, |slices| {
            let mut calls = calls.borrow_mut();
            *calls += 1;
            if *calls < 3 {
                return Err(Errno::EINTR);
            }
            Ok(slices.iter().map(|s| s.len()).sum())
        })
        .expect("the write completes");
        assert_eq!(calls.into_inner(), 3);
    }

    #[test]
    fn a_writer_that_accepts_nothing_is_write_zero() {
        let bufs = slices(&[b"abc"]);
        let err = write_all_vectored(&bufs, |_| Ok(0)).expect_err("no progress");
        assert_eq!(err.kind(), io::ErrorKind::WriteZero);
    }

    #[test]
    fn other_errors_are_reported() {
        let bufs = slices(&[b"abc"]);
        let err = write_all_vectored(&bufs, |_| Err(Errno::EPIPE)).expect_err("EPIPE");
        assert_eq!(err.raw_os_error(), Some(Errno::EPIPE as i32));
    }

    #[test]
    fn nothing_to_write_calls_the_writer_not_at_all() {
        let calls = RefCell::new(0usize);
        write_all_vectored(&[], |_| {
            *calls.borrow_mut() += 1;
            Ok(0)
        })
        .expect("an empty write is a no-op");
        assert_eq!(calls.into_inner(), 0);
    }
}
