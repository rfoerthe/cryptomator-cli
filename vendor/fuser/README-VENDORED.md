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
  `src/mnt/mount_options.rs`.
- `FUSE_KERNEL_MINOR_VERSION` is unchanged (19 on macOS); the FUSE-T handshake is fine with it.

Lint suppressions (our gate runs `cargo clippy --workspace --all-targets -- -D warnings`, which is
stricter than upstream's; suppressing keeps future rebases cheap):
- `#![allow(dead_code)]` in `src/ll/fuse_abi.rs` for `cuse_init_in`, `cuse_init_out`,
  `fuse_ioctl_iovec`, `fuse_notify_retrieve_in` and `fuse_notify_retrieve_out`, which describe
  parts of the kernel ABI fuser does not implement yet.
- `#![allow(clippy::io_other_error)]` in `src/lib.rs` for three
  `io::Error::new(ErrorKind::Other, _)` calls in `src/notify.rs`, `src/passthrough.rs` and
  `src/session.rs`.

Packaging changes:
- `examples/`, `tests/`, `.github/`, `benches/`, `Makefile`, `deny.toml`, Docker files and the
  upstream `CHANGELOG.md`/`AGENTS.md`/`CLAUDE.md` were dropped.
- `Cargo.toml`: `publish = false`; the `[[example]]` sections and the dev-dependencies that only
  served examples and integration tests (`bincode`, `clap`, `env_logger`, `nix`, `serde`) were
  removed. `tempfile` stays because `src/mnt/mod.rs` uses it in a unit test.
- The crate is a member of the workspace and is wired in through `[patch.crates-io]` in the
  workspace `Cargo.toml`, so `cargo build -p fuser` on macOS needs `--features macos-no-mount`
  (a bare `cargo build -p fuser` would look for macFUSE via `pkg-config`). Building the workspace
  unifies that feature in from `cryptomator-mount`.

Upstream-worthy as a feature-less runtime switch; see
`docs/superpowers/spikes/2026-09-04-spike-a-fuse-t.md`.
