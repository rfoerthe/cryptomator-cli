# Vendored fuser 0.18.0

Upstream: https://github.com/cberner/fuser (MIT, see LICENSE.md). Vendored because FUSE-T on macOS
speaks the Linux struct layouts while fuser hard-codes the macFUSE layouts under `target_os = "macos"`.

Patches. All but the last three are under `#[cfg(target_os = "macos")]` and change nothing on
Linux; the EOF patch, the request-framing patch and the short-write patch are unconditional but
inert on `/dev/fuse`, which never returns a zero-length read, never splits a request across two
reads and never accepts a reply only in part (see the last three bullets):
- `KernelAbi { Native, Linux }` and `Config.abi: KernelAbi` in `src/mnt/mount_options.rs`
  (`Native` = upstream behaviour, `Linux` = Linux struct layouts), re-exported from `src/lib.rs`.
- Linux-layout twins `fuse_attr_linux`, `fuse_entry_out_linux`, `fuse_attr_out_linux`,
  `fuse_create_out_linux`, `fuse_direntplus_linux`, `fuse_setattr_in_linux`,
  `fuse_getxattr_in_linux` and `fuse_setxattr_in_linux` in `src/ll/fuse_abi.rs`, with `From`
  conversions to/from the native structs.
- Replies (`entry`, `attr`, `create`, `readdirplus`) serialise the twin when `abi == Linux`:
  `ResponseStruct::new_entry/new_attr/new_create` became the enums `ResponseEntry`, `ResponseAttr`
  and `ResponseCreate` in `src/ll/reply.rs`, and `DirEntryPlus` carries the `abi`.
- Requests (`setattr`, `getxattr`, `listxattr`, `setxattr`) parse the twin when `abi == Linux`:
  `op::parse` takes an `abi` argument and the affected `arg` fields became `ArgRef`, which is
  either a zero-copy view into the request buffer or an owned struct widened from the twin.
  The Darwin-only extras (`crtime`, `chgtime`, `bkuptime`, `flags`, `position`) read back as
  absent/0.
- `abi` is threaded from `Config` through `Session` → `SessionEventLoop` → `RequestWithSender` →
  `Reply::new(unique, sender, abi)` (`src/session.rs`, `src/request.rs`, `src/reply.rs`).
- `AnyRequest::parse(data, abi)` added; `TryFrom<&[u8]>` keeps working and implies
  `KernelAbi::Native`.
- New macOS-only tests: `src/ll/reply.rs::abi_test` (reply byte layouts) and
  `src/ll/request.rs::abi_test` (request parsing), plus `default_abi_is_native` in
  `src/mnt/mount_options.rs`. The reply fixture uses distinct non-zero values in every field
  (`rdev`, Darwin `flags = 0xdead`, four different timestamps) and pins both the Linux offsets
  (atime 24, mtime 32, ctime 40, nsec 48/52/56, mode 60, nlink 64, uid 68, gid 72, rdev 76,
  blksize 80, flags 84 — expected to be **0**, because Darwin `chflags(2)` bits are not
  `FUSE_ATTR_*`) and the untouched native ones (crtime 48, crtimensec 68, rdev 88, flags 92).
- `FUSE_KERNEL_MINOR_VERSION` is unchanged (19 on macOS); the FUSE-T handshake is fine with it.
- A zero-length read on the FUSE channel ends the session with `Ok(())` instead of the previous
  `io::ErrorKind::InvalidData` / "Invalid request" (`src/session.rs`, `SessionEventLoop::event_loop`,
  plus the matching arm in `Session::handshake`). `/dev/fuse` never returns 0 - it raises `ENODEV`
  on unmount - but FUSE-T's channel is a plain socket that is simply closed, so EOF is how a
  FUSE-T `umount` announces itself. Covered by
  `src/session.rs::abi_session_test::linux_abi_session_answers_getattr_and_ends_cleanly_on_eof`,
  which runs a whole `KernelAbi::Linux` session over a `socketpair`.
- `Channel::receive_retrying` returns **exactly one** request (`src/channel.rs`): it keeps reading
  until the buffer holds the `len` bytes the `fuse_in_header` announces, and keeps whatever was
  read past that request (`Channel::spill`) for the next call. The caller
  (`SessionEventLoop::event_loop`) has always treated one read as one request, so both halves are
  needed to keep that true on a channel without message boundaries.
  On `/dev/fuse` neither half ever triggers: the device is message oriented and hands out exactly
  one whole request per `read`, so the first read already satisfies the loop and the spill buffer
  stays empty -- on Linux nothing changes but one `Mutex` lock on an empty `Vec` per request.
  FUSE-T's channel is a **stream socket**, and both halves were found by the crypto CLI's mount
  end-to-end test:
  - It sends a WRITE as a header write followed by a separate data write, so a single `read` may
    return only the first 80 bytes of a 4176-byte request. The parser then saw a request without
    its payload, the peer never got a reply, and the mount stalled for ~40 s per write before the
    client gave up. Intermittent, because the two writes usually coalesce in the socket buffer.
  - Conversely, two requests written in quick succession *do* coalesce and arrive in one `read`.
    The event loop answered the first and dropped the second on the floor; nobody ever replied to
    it and the volume stalled until the NFS client gave up. Also intermittent -- it took a few
    end-to-end runs to hit, and it is what a 30 s "the mount stopped answering" looked like.
  Covered by two tests in `src/session.rs::abi_session_test`, both of which run a whole
  `KernelAbi::Linux` session over a `socketpair`:
  `a_request_split_across_two_writes_is_read_as_one` writes a 4 KiB WRITE request in two pieces
  with a pause in between, and `two_requests_that_arrive_in_one_read_are_both_answered` writes
  INIT+GETATTR and then three GETATTRs in single `write_all`s and insists on a reply for each.
  Both peers have a read timeout, so a regression fails rather than hangs.
- `ChannelSender::send` writes the whole reply (`src/channel.rs`): the `writev` moved into
  `write_all_vectored`, which loops with `IoSlice::advance_slices` until nothing is pending,
  retries `EINTR` and reports `ErrorKind::WriteZero` when the channel accepts nothing. Upstream
  writes once and only `debug_assert_eq!`s the byte count (compiled out in release), because
  `/dev/fuse` is message oriented and takes a whole reply per `writev`. FUSE-T's channel is the
  same stream socket the framing patch is about: a blocking write on one returns a *partial* count
  when a signal lands after some bytes have gone out (`SA_RESTART` does not undo a partial
  transfer), replies run to `rwsize=262144` bytes, and the CLI installs SIGINT/SIGTERM/SIGHUP
  handlers that can be delivered on the FUSE thread. A truncated reply desynchronises the stream
  permanently -- the peer reads the tail of one reply as the head of the next -- which is the read
  side's failure mode mirrored. Covered by `src/channel.rs::send_test` (six tests over a fake
  writer: short writes resumed in order, a single full write, `EINTR` retried, `WriteZero`, other
  errors propagated, an empty write as a no-op).

## Touched upstream files

Exactly ten files under `src/` differ from the registry source (`diff -qr` against
`~/.cargo/registry/src/*/fuser-0.18.0/src`), plus one deletion:

| File | Why |
|---|---|
| `src/channel.rs` | `Channel::receive_retrying` returns exactly one request: it reassembles one that arrives in several reads and spills what follows it into `Channel::spill` (stream-socket channels); `ChannelSender::send` loops over short writes through `write_all_vectored`, plus `mod send_test` |
| `src/lib.rs` | `pub use ... KernelAbi`; `#![allow(clippy::io_other_error)]`; dropped the `experimental` module declaration |
| `src/ll/fuse_abi.rs` | the eight Linux-layout twins + `From` impls; `IntoBytes` on the three request twins (so tests can build wire buffers); five per-item `#[allow(dead_code)]` |
| `src/ll/mod.rs` | re-exports `ResponseEntry`, `ResponseAttr` and `ResponseCreate` |
| `src/ll/reply.rs` | the three response enums; `DirEntryPlus.abi`; the `DirEntPlusList::push` branch; `mod abi_test`; two lint allows |
| `src/ll/request.rs` | `ArgRef`; the three `fetch_*` helpers; `op::parse(..., abi)`; `AnyRequest.abi` + `AnyRequest::parse`; `mod abi_test` |
| `src/mnt/mount_options.rs` | `KernelAbi`, `Config.abi`, test `default_abi_is_native` |
| `src/reply.rs` | `Reply::new(unique, sender, abi)`; `ReplyRaw.abi`; `ReplyDirectory(Plus)::new(..., abi)` |
| `src/request.rs` | `RequestWithSender.abi` and `new(..., abi)`; dropped an unused `use std::convert::TryFrom` |
| `src/session.rs` | `SessionEventLoop.abi` from `config.abi`; handshake parses/answers with `config.abi`; EOF (`Ok(0)`) ends the session cleanly; `mod abi_session_test` |
| `src/experimental.rs` | **deleted** (see Packaging changes) |

Lint suppressions (our gate runs `cargo clippy --workspace --all-targets -- -D warnings`, which is
stricter than upstream's; suppressing keeps future rebases cheap). The complete list:
- `#[allow(dead_code)]` on five items in `src/ll/fuse_abi.rs` — `cuse_init_in`, `cuse_init_out`,
  `fuse_ioctl_iovec`, `fuse_notify_retrieve_out` and `fuse_notify_retrieve_in`, which describe
  parts of the kernel ABI fuser does not implement yet. Deliberately per item and not a
  module-wide `#![allow(dead_code)]`, so that an unwired Linux twin of ours still warns.
- `#![allow(clippy::io_other_error)]` in `src/lib.rs` for three
  `io::Error::new(ErrorKind::Other, _)` calls in `src/notify.rs`, `src/passthrough.rs` and
  `src/session.rs`.
- `#[cfg_attr(not(target_os = "macos"), expect(dead_code))]` on `DirEntryPlus.abi`
  (`src/ll/reply.rs`) — off macOS the field is never read.
- `#[allow(clippy::too_many_arguments)]` on `DirEntryPlus::new` (`src/ll/reply.rs`) — the added
  `abi` parameter pushes it over clippy's threshold.

Packaging changes:
- `examples/`, `tests/`, `.github/`, `benches/`, `Makefile`, `deny.toml`, Docker files and the
  upstream `CHANGELOG.md`/`AGENTS.md`/`CLAUDE.md` were dropped.
- `Cargo.toml`: `publish = false`; the `[[example]]` sections and the dev-dependencies that only
  served examples and integration tests (`bincode`, `clap`, `env_logger`, `nix`, `serde`) were
  removed. `tempfile` stays because `src/mnt/mod.rs` uses it in a unit test.
- The unused `experimental` feature was dropped: the feature entry and the optional `async-trait`
  and `tokio` dependencies are gone from `Cargo.toml`, `src/experimental.rs` was deleted and its
  `#[cfg(feature = "experimental")] pub mod experimental;` declaration removed from `src/lib.rs`.
  Because the crate is a workspace member, those optional dependencies would otherwise sit in the
  workspace `Cargo.lock` (and thus in our supply-chain surface) without ever being built.
  `grep -c 'name = "tokio"' Cargo.lock` is 0.
- The crate is a member of the workspace and is wired in through `[patch.crates-io]` in the
  workspace `Cargo.toml`, so `cargo build -p fuser` on macOS needs `--features macos-no-mount`
  (a bare `cargo build -p fuser` would look for macFUSE via `pkg-config`). Building the workspace
  unifies that feature in from `cryptomator-mount`.

Upstream-worthy as a feature-less runtime switch; see
`docs/superpowers/spikes/2026-09-04-spike-a-fuse-t.md` and
`docs/superpowers/spikes/2026-09-06-spike-c-fuse-t-linux-abi.md`.
