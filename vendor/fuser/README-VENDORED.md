# Vendored fuser 0.18.0

Upstream: https://github.com/cberner/fuser (MIT, see LICENSE.md). Vendored because FUSE-T on macOS
speaks the Linux struct layouts while fuser hard-codes the macFUSE layouts under `target_os = "macos"`.

Patches (all under `#[cfg(target_os = "macos")]`, no behaviour change on Linux):
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

## Touched upstream files

Exactly nine files under `src/` differ from the registry source (`diff -qr` against
`~/.cargo/registry/src/*/fuser-0.18.0/src`), plus one deletion:

| File | Why |
|---|---|
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
