# M4: FUSE-Mount + Daemon – Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `crypto unlock <VAULT>` mounts a vault via FUSE (Linux libfuse3/`fusermount3`, macOS FUSE-T; macFUSE path implemented but unverified) in a background daemon; `crypto lock|status|stats|events|mounters` talk to the daemon over a Unix socket. Files written through the mount are read unchanged by cryptofs (Java).

**Architecture:** Three layers. (1) `cryptomator-mount`: `MountService`/`MountBuilder`/`Mount` API (port of `integrations-api`), flag parser, name transcoder, a fuser-independent, testable operation core `fuse/ops.rs` over `Arc<CryptoFs>` (inode/handle tables, errno mapping) and the thin `impl fuser::Filesystem` in `fuse/adapter.rs`; providers for Linux (`fuser::Session::new`, pure-rust/fusermount3), FUSE-T and macFUSE (dlopen `fuse_mount_compat25` → `Session::from_fd`). (2) `cryptomator-app`: state dir, `cli.json`, vault registry (UNLOCKED/STALE_MOUNT), `Mounter` (port of `Mounter.SettledMounter`), daemon protocol/client/server (std threads + `UnixListener`, no tokio). (3) `crypto`: `unlock` (password + scrypt in the parent process, name length probe, spawn the daemon, wait for ready), `lock`, `status`, `stats`, `events`, `mounters`, hidden `__daemon`. fuser 0.18.0 is patched as `vendor/fuser` with a **runtime ABI switch** (`KernelAbi::{Native, Linux}`), because FUSE-T expects the Linux struct layouts (Spike A).

**Tech Stack:** Rust stable ≥ 1.85; `fuser` 0.18.0 (vendored, MIT, `[patch.crates-io]`), `libloading` 0.9, `nix` 0.31 (features `process`, `signal`, `user`, `fs`), `libc` 0.2 (only in the binary, for `setsid`), `signal-hook` 0.3, `log` 0.4 (+ our own file logger), `serde`/`serde_json`, `data-encoding`; tests with `tempfile`, `assert_cmd`. Java 21+/Maven for interop.

**Spec:** `docs/superpowers/specs/2026-09-04-crypto-cli-design.md` (sections `cryptomator-mount`, `cryptomator-app` → `cli_config.rs`, `state_dir.rs`, `registry.rs`, `mounting/mounter.rs`, `daemon/*`, command grammar `unlock/lock/status/stats/events/mounters/__daemon`, daemon design, exit codes, milestone M4, Spike A)

## Global Constraints

- Working directory `/Users/rfoerthe/work/cryptomator-cli`, branch `feature/m4-fuse-daemon` (from `main@dd5c038`).
- License AGPL-3.0-only; `vendor/fuser` keeps its MIT `LICENSE` and gets a `README-VENDORED.md` with the patch list. `#![forbid(unsafe_code)]` stays in `cryptomator-core` and `cryptomator-app`; `cryptomator-mount` (dlopen/FFI) and the binary (`pre_exec`) may use `unsafe` with a `// SAFETY:` comment. No `unwrap()`/`expect()` on input data in library/binary code (tests may). MSRV 1.85 (no `io::ErrorKind` variants newer than 1.85).
- `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo test --workspace --locked` clean before every commit; the commit message ends with `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`. After dependency changes, run `cargo build` once without `--locked` and commit `Cargo.lock`.
- `tests/fixtures/` read-only; change nothing under `~/.m2` or in the desktop checkout; install **no** FUSE software (FUSE-T 1.2.7 is installed: `/usr/local/lib/libfuse-t.dylib`; macFUSE is NOT installed; `fusermount3` is missing on the Mac). Tests may only really mount under `CRYPTO_E2E_MOUNT=1` (and `#[ignore]`); all other tests run without FUSE, without root, without network.
- Java parity (Desktop 1.19 / fuse-nio-adapter 6.0.1 / integrations-api 1.9): class names `org.cryptomator.frontend.fuse.mount.{LinuxFuseMountProvider,MacFuseMountProvider,FuseTMountProvider}`; capabilities exactly as in Java (Linux `{MOUNT_FLAGS, MOUNT_TO_EXISTING_DIR}`; macFUSE `{MOUNT_FLAGS, UNMOUNT_FORCED, READ_ONLY, MOUNT_TO_EXISTING_DIR, MOUNT_TO_SYSTEM_CHOSEN_PATH, VOLUME_ID, VOLUME_NAME}`; FUSE-T `{MOUNT_FLAGS, UNMOUNT_FORCED, READ_ONLY, MOUNT_TO_EXISTING_DIR, VOLUME_NAME}`); default flags Linux `-oauto_unmount -ouid=<uid> -ogid=<gid> -oattr_timeout=5`, macFUSE `-ouid=<uid> -ogid=<gid> -oatomic_o_trunc -oauto_xattr -oauto_cache -onoappledouble -odefault_permissions`, FUSE-T `-ononamedattr -orwsize=262144 -ouid=<uid> -ogid=<gid>` (**without** `-obackend=smb`, Spike A); `-ononamedattr` is always appended for FUSE-T; flag parsing as in `AbstractMountBuilder.setMountFlags` (split on `\s+-`, set semantics); `-r` for read-only, `-ovolname=<name>` for VOLUME_NAME; `-obackend=fskit` rejected for macFUSE; mount point policy as in `Mounter.prepareMountPoint`; service selection `vault.mountService` → `settings.mountService` → first supported one in priority order (macOS `[MacFuse(100), FuseT(90)]`, Linux `[LinuxFuse(100)]`); macFUSE and FUSE-T are mutually exclusive (`CONFLICTING_MOUNT_SERVICES`); unmount Linux `fusermount3 -u -- <name>` (cwd = parent), forced `-uz`; macOS `umount -- <p>` / `umount -f -- <p>`; `uid`/`gid`/`attr_timeout`/`entry_timeout` are interpreted by the adapter (Java: libfuse high-level), `attr_timeout` defaults to 1 s when not set; directory listing returns `.`/`..`; `chown` no-op (Java), `chmod` no-op with success (ruling, see below); xattr → `ENOTSUP`; on macOS, `rmdir` first deletes `._*`/`.DS_Store` children (Java `deleteAppleDoubleFiles`); names NFD on the FUSE side (macOS) ↔ NFC in the vault.
- Daemon design (spec, with deviations per ruling): the parent process does scrypt + config verification + name length probe (`maxCleartextFilenameLength == -1` and not read-only: `ciphertextLimit < shorteningThreshold ? cleartextLimit : i32::MAX`, persisted as in `Vault.createCryptoFileSystem`), starts `current_exe() __daemon --vault-id ID --socket P --state-dir D [--settings …]` detached (`setsid`, cwd `/`, stdin `/dev/null`, stdout/stderr → `<id>.log`, env without `CRYPTO_PASSWORD`), connects (retry ≤ 30 s) and **sends the 64-byte raw key as the first message over the socket** (`{"op":"unlock","key":<base64>,…}`, ruling: no fd 3), waits for `ready`/`failed`, zeroizes the key. State files `<id>.sock` (0600), `<id>.pid`, `<id>.json`, `<id>.log` in the state dir (0700; macOS `~/Library/Application Support/Cryptomator/cli-run`, Linux `$XDG_RUNTIME_DIR/crypto` otherwise `/tmp/crypto-<uid>`; override `--state-dir`/`CRYPTO_STATE_DIR`). Protocol is newline JSON, the daemon greets first with `{"hello":"crypto-daemon","protocol":1,"vaultId":…,"pid":…}`; requests `{"id":n,"op":…}`; responses `{"id":n,"ok":true,"result":{…}}` / `{"id":n,"ok":false,"error":{"code":…,"message":…}}`; events with `seq`, ring buffer 1000; stats sampler 1 s (`lastActivity`), auto-lock tick 60 s (settings re-read on every tick); shutdown: unmount → join → `CryptoFs::close` → delete state files → exit; unmount error → keep running and report.
- Exit codes: 0 ok, 1 general, 2 usage, 3 vault not found, 4 invalid password, 5 wrong state (including "already unlocked"/"not unlocked"), **6 mount failed, 7 unmount failed (note `--force`), 10 daemon unreachable**, 9 hub, 12 no vault directory. `--json`: one object, NDJSON with `--follow`.
- Passwords/keys never in argv, logs, error messages or JSON; raw key only as `Zeroizing`; the socket message containing the key is wiped after parsing; log file 0600.
- Rulings (comment them in the code, document them in Task 16): (1) fuser fork with a runtime `KernelAbi` instead of a compile feature, so that one binary serves macFUSE (native) and FUSE-T (Linux layout); (2) daemon with std threads/`UnixListener` instead of tokio (tokio arrives with WebDAV in M5); (3) key handover over the socket instead of fd 3; (4) `chmod` is a successful no-op (cryptofs permissions come from the ciphertext files; Java sets POSIX permissions on the ciphertext, which does not change the vault); (5) `--port`, `--store-password`, `--no-store-password` only appear with M5/M6; (6) a built-in **null mounter** (`org.cryptomator.cli.NullMountProvider`, only active with `CRYPTO_ENABLE_NULL_MOUNTER=1`, visible in `mounters` only with `--all`) makes the daemon and CLI lifecycle testable without FUSE; (7) the macFUSE provider is implemented but unverified (not installed) and is documented as such; (8) FUSE-T without `backend=smb`.
- M3 promises that M4 delivers: `fs` write commands refuse while a daemon is running (exit 5); `fs_loop` → `ELOOP`; directory cache (20 s) and `DirIdLoader` cache with expiry; `CryptoFs` gets `Drop` → `close_all`.

---

## File structure

```
Cargo.toml                                          + [patch.crates-io] fuser = { path = "vendor/fuser" }; deps nix, libc, signal-hook, log
vendor/fuser/                                       Copy of fuser 0.18.0 (src, Cargo.toml, LICENSE, build.rs) + README-VENDORED.md
vendor/fuser/src/mnt/mount_options.rs               + `KernelAbi`, field `Config.abi`
vendor/fuser/src/ll/fuse_abi.rs                     + Linux layouts on macOS: fuse_attr_linux, fuse_setattr_in_linux, fuse_getxattr_in_linux, fuse_setxattr_in_linux
vendor/fuser/src/ll/reply.rs, src/reply.rs          ABI-aware replies (entry/attr/create/readdirplus)
vendor/fuser/src/ll/request.rs, src/request.rs      ABI-aware parsing (setattr/getxattr/setxattr)
vendor/fuser/src/session.rs                         pass `abi` through (from_fd/new → event loop → requests/replies)
crates/cryptomator-core/src/fs/mod.rs               + `FilesystemLoop` marker error (for ELOOP)
crates/cryptomator-core/src/fs/path_mapper.rs       + 20 s expiry in the dir_cache
crates/cryptomator-core/src/fs/dir_id.rs            + 20 s expiry in the DirIdLoader cache
crates/cryptomator-core/src/fs/crypto_fs.rs         + impl Drop (close_all)
crates/cryptomator-mount/Cargo.toml                 features: fuse (default), null-mounter (always compiled, activated via env)
crates/cryptomator-mount/src/lib.rs
crates/cryptomator-mount/src/api.rs                 MountCapability, MountService, MountBuilder, Mount, Mountpoint, MountError, UnmountError
crates/cryptomator-mount/src/flags.rs               parse_mount_flags, MountFlags (adapter options + passthrough)
crates/cryptomator-mount/src/transcoder.rs          NameTranscoder (NFC/NFD)
crates/cryptomator-mount/src/mounttab.rs            is_mountpoint (mount / /proc/self/mountinfo)
crates/cryptomator-mount/src/registry.rs            services(), lookup(class), aliases, conflicts, NullMountProvider
crates/cryptomator-mount/src/fuse/mod.rs
crates/cryptomator-mount/src/fuse/errno.rs          io::Error → Errno
crates/cryptomator-mount/src/fuse/inodes.rs         InodeTable
crates/cryptomator-mount/src/fuse/handles.rs        FileHandles, DirHandles
crates/cryptomator-mount/src/fuse/ops.rs            VaultOps (fuser-free, testable)
crates/cryptomator-mount/src/fuse/adapter.rs        CryptoFuse: impl fuser::Filesystem
crates/cryptomator-mount/src/fuse/session.rs        FuseSessionHandle (BackgroundSession + unmount)
crates/cryptomator-mount/src/fuse/linux.rs          LinuxFuseMountProvider
crates/cryptomator-mount/src/fuse/macos_dl.rs       LibFuse (dlopen), fuse_mount/unmount
crates/cryptomator-mount/src/fuse/fuset.rs          FuseTMountProvider
crates/cryptomator-mount/src/fuse/macfuse.rs        MacFuseMountProvider
crates/cryptomator-mount/examples/spike_macos_dlopen.rs  Spike C (KernelAbi::Linux for FUSE-T)
crates/cryptomator-mount/tests/mount_e2e.rs         #[ignore], CRYPTO_E2E_MOUNT=1
docs/superpowers/spikes/2026-09-06-spike-c-fuse-t-linux-abi.md
crates/cryptomator-app/Cargo.toml                   + cryptomator-mount, log, nix, signal-hook, data-encoding
crates/cryptomator-app/src/state_dir.rs             StateDir, VaultStateFiles, RunInfo
crates/cryptomator-app/src/cli_config.rs            CliConfig (cli.json)
crates/cryptomator-app/src/registry.rs              VaultRegistry, VaultInfo, RuntimeState
crates/cryptomator-app/src/mounting/mod.rs, mounter.rs   Mounter (SettledMounter port), MountHandle
crates/cryptomator-app/src/daemon/mod.rs, protocol.rs, client.rs, server.rs, logging.rs
crates/cryptomator-app/src/error.rs                 + MountFailed, UnmountFailed, DaemonUnreachable, DaemonError
crates/crypto/src/cli.rs                            + unlock/lock/status/stats/events/mounters/__daemon, --state-dir
crates/crypto/src/commands/{unlock,lock,status,stats,events,mounters,daemon}.rs
crates/crypto/src/commands/fs.rs                    + refusal when UNLOCKED
crates/crypto/src/exit.rs                           + 6/7/10
crates/crypto/tests/cli_daemon.rs                   Lifecycle with the null mounter
.github/workflows/ci.yml                            + Jobs mount-e2e-linux (fuse3), mount-e2e-macos (FUSE-T, continue-on-error)
README.md, CHANGELOG.md, Spec                       updated
```

Shared types (overview; details in the tasks):

- `fuser::KernelAbi::{Native, Linux}` in `fuser::Config.abi` (Task 1).
- `cryptomator_mount::api::{MountCapability, MountService, MountBuilder, Mount, Mountpoint, MountError, UnmountError, ServiceInfo}` (Task 3); `flags::{MountFlags, parse_mount_flags, AdapterOptions}` (Task 3); `transcoder::NameTranscoder` (Task 3); `mounttab::is_mountpoint` (Task 3).
- `cryptomator_mount::fuse::{VaultOps, CryptoFuse, FuseSessionHandle}` (Tasks 4–6); Provider (Task 7); `registry::{services, all_services, service_by_class, NULL_MOUNTER_CLASS}` (Task 7).
- `cryptomator_app::{state_dir::StateDir, cli_config::CliConfig, registry::{VaultRegistry, VaultInfo, RuntimeState}, mounting::{Mounter, MountHandle}, daemon::{protocol::*, client::DaemonClient, server::{DaemonConfig, run_daemon}}}` (Tasks 9–11).

---

### Task 1: Vendor fuser and add the runtime ABI switch

**Files:**
- Create: `vendor/fuser/**` (copy of `~/.cargo/registry/src/index.crates.io-*/fuser-0.18.0/`: `Cargo.toml`, `build.rs`, `LICENSE`, `README.md`, `src/**`; **without** `examples/`, `docs/`, `tests/`, `.github/`), `vendor/fuser/README-VENDORED.md`
- Modify: `Cargo.toml` (Workspace), `vendor/fuser/src/mnt/mount_options.rs`, `vendor/fuser/src/ll/fuse_abi.rs`, `vendor/fuser/src/ll/reply.rs`, `vendor/fuser/src/reply.rs`, `vendor/fuser/src/ll/request.rs`, `vendor/fuser/src/request.rs`, `vendor/fuser/src/session.rs`

**Interfaces:**
- Produces: `fuser::KernelAbi { Native, Linux }` (`Copy`, `Default = Native`), `fuser::Config { …, pub abi: KernelAbi }`; `Session::from_fd(fs, fd, acl, config)` and `Session::new` respect `config.abi`. On Linux, `Native` and `Linux` are identical.

Background (Spike A): FUSE-T detects our client as `libfuse3` and reads the **Linux** layouts; under `target_os = "macos"` fuser writes the macFUSE layouts. Affected (all `#[cfg(target_os = "macos")]` fields in `fuse_abi.rs`): replies `fuse_attr` (in `fuse_entry_out`, `fuse_attr_out`, the `fuse_create` reply = entry_out + open_out, `readdirplus` entries); requests `fuse_setattr_in` (macOS appends `bkuptime, chgtime, crtime, bkuptimensec, chgtimensec, crtimensec, flags`), `fuse_getxattr_in` / `fuse_setxattr_in` (macOS: `position`, `padding`). FUSE-T does not send the macOS-only operations `FUSE_SETVOLNAME/GETXTIMES/EXCHANGE`. `FUSE_KERNEL_MINOR_VERSION = 19` stays (handshake ok in the spike).

- [ ] **Step 1: Vendor and wire up**

```bash
SRC=$(ls -d ~/.cargo/registry/src/index.crates.io-*/fuser-0.18.0 | head -1)
mkdir -p vendor/fuser && cp -R "$SRC"/{Cargo.toml,build.rs,LICENSE,README.md,src} vendor/fuser/
rm -rf vendor/fuser/src/../examples  # (only if it was copied along)
```

Extend `Cargo.toml` (workspace):

```toml
[patch.crates-io]
fuser = { path = "vendor/fuser" }
```

and in `[workspace.dependencies]`: `nix = { version = "0.31", features = ["process", "signal", "user", "fs"] }`, `libc = "0.2"`, `signal-hook = "0.3"`, `log = "0.4"`. In `vendor/fuser/Cargo.toml`: add `[package] publish = false`; remove the `[[example]]` blocks and the `[dev-dependencies]` that only examples/tests need, so `--locked` builds do not pull unnecessary crates (keep everything `src/` needs; `cargo build -p fuser` must succeed).

`vendor/fuser/README-VENDORED.md`:

```markdown
# Vendored fuser 0.18.0

Upstream: https://github.com/cberner/fuser (MIT, see LICENSE). Vendored because FUSE-T on macOS
speaks the Linux struct layouts while fuser hard-codes the macFUSE layouts under `target_os = "macos"`.

Patches (all under `#[cfg(target_os = "macos")]`, no behaviour change on Linux):
- `Config.abi: KernelAbi` (`Native` = upstream behaviour, `Linux` = Linux struct layouts).
- Linux-layout twins `fuse_attr_linux`, `fuse_setattr_in_linux`, `fuse_getxattr_in_linux`,
  `fuse_setxattr_in_linux` in `src/ll/fuse_abi.rs`.
- Replies (`entry`, `attr`, `create`, `readdirplus`) serialise the twin when `abi == Linux`.
- Requests (`setattr`, `getxattr`, `setxattr`) parse the twin when `abi == Linux`.
- `examples/`, `docs/`, `tests/` dropped.
Upstream-worthy as a feature-less runtime switch; see docs/superpowers/spikes/2026-09-04-spike-a-fuse-t.md.
```

- [ ] **Step 2: Failing test in the fork**

In `vendor/fuser/src/ll/reply.rs` (test module, macOS only):

```rust
#[cfg(all(test, target_os = "macos"))]
mod abi_tests {
    use super::*;
    use crate::{FileAttr, FileType, INodeNo, KernelAbi};
    use std::time::{Duration, UNIX_EPOCH};

    fn attr() -> FileAttr {
        FileAttr {
            ino: INodeNo(1), size: 0, blocks: 1, atime: UNIX_EPOCH, mtime: UNIX_EPOCH, ctime: UNIX_EPOCH,
            crtime: UNIX_EPOCH, kind: FileType::Directory, perm: 0o755, nlink: 1, uid: 501, gid: 20,
            rdev: 0, flags: 0, blksize: 512,
        }
    }

    #[test]
    fn linux_abi_attr_out_is_88_byte_layout() {
        let native = ResponseStruct::new_attr(&Duration::from_secs(1), &(&attr()).into(), KernelAbi::Native).to_bytes();
        let linux = ResponseStruct::new_attr(&Duration::from_secs(1), &(&attr()).into(), KernelAbi::Linux).to_bytes();
        assert_eq!(native.len(), 16 + 104);
        assert_eq!(linux.len(), 16 + 88);
        // Linux layout: mode at attr offset 60, nlink 64, uid 68, gid 72, rdev 76, blksize 80, flags 84
        let a = &linux[16..];
        let u32_at = |o: usize| u32::from_ne_bytes(a[o..o + 4].try_into().unwrap());
        assert_eq!(u32_at(60), 0o040755);
        assert_eq!(u32_at(64), 1);
        assert_eq!(u32_at(68), 501);
        assert_eq!(u32_at(72), 20);
        assert_eq!(u32_at(80), 512);
    }
}
```

(The concrete constructor names/signatures must be adapted to fuser's existing `ResponseStruct::new_attr/new_entry/new_create`; the test must check the byte layouts, not names.)

- [ ] **Step 3: Patch**

`mount_options.rs`:

```rust
/// Which kernel struct layouts the peer expects. macFUSE uses the Darwin layouts fuser ships under
/// `target_os = "macos"`; FUSE-T (a userspace NFS/SMB server) expects the Linux ones.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub enum KernelAbi {
    #[default]
    Native,
    Linux,
}
```

`Config` gets `pub abi: KernelAbi` (default `Native`; `#[non_exhaustive]` stays, construction via `Config::default()` + field assignment). `lib.rs`: `pub use crate::mnt::mount_options::KernelAbi;`.

`fuse_abi.rs` (macOS): twins without the macOS fields:

```rust
#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Debug, IntoBytes, Clone, Copy, KnownLayout, Immutable)]
pub(crate) struct fuse_attr_linux {
    pub(crate) ino: u64, pub(crate) size: u64, pub(crate) blocks: u64,
    pub(crate) atime: i64, pub(crate) mtime: i64, pub(crate) ctime: i64,
    pub(crate) atimensec: u32, pub(crate) mtimensec: u32, pub(crate) ctimensec: u32,
    pub(crate) mode: u32, pub(crate) nlink: u32, pub(crate) uid: u32, pub(crate) gid: u32,
    pub(crate) rdev: u32, pub(crate) blksize: u32, pub(crate) flags: u32,
}
#[cfg(target_os = "macos")]
impl From<&fuse_attr> for fuse_attr_linux { /* field by field, flags = 0 */ }
```

likewise `fuse_entry_out_linux { nodeid, generation, entry_valid, attr_valid, entry_valid_nsec, attr_valid_nsec, attr: fuse_attr_linux }`, `fuse_attr_out_linux { attr_valid, attr_valid_nsec, dummy, attr: fuse_attr_linux }`, `fuse_setattr_in_linux` (= the fields up to and including `unused5`), `fuse_getxattr_in_linux { size, padding }`, `fuse_setxattr_in_linux { size, flags }`.

Reply path: the `Reply*` objects (`src/reply.rs`) get an `abi: KernelAbi` field, set by the request dispatcher (`src/request.rs` `reply::<T>()` → `Reply::new(unique, sender, abi)`); `ll::ResponseStruct::new_entry/new_attr/new_create` and `DirEntryPlus::new` take the `abi` parameter and serialise the twins on macOS when `abi` is `Linux`. Request path: `ll::request::AnyRequest`/`Operation` parsing takes `abi`; with `Linux`, `setattr/getxattr/setxattr` are parsed via the twins and converted into the same `Operation` variants (`crtime/chgtime/bkuptime/flags` = `None`, `position` = 0). `session.rs`: `Session` stores `abi` from `config`, `SessionEventLoop` passes it through to `RequestWithSender::new`. On Linux (`not(target_os = "macos")`) all branches are `Native` paths (`let _ = abi;`), so that no `dead_code` arises.

- [ ] **Step 4: Tests**

Run: `cargo test -p fuser --locked` (macOS) and `cargo build --workspace --locked`
Expected: PASS including `abi_tests`; the workspace builds with `fuser (path+vendor/fuser)` in `Cargo.lock`.

- [ ] **Step 5: Gate + Commit** ("Vendor fuser 0.18.0 with a runtime Linux-ABI switch for FUSE-T")

---

### Task 2: Spike C – verify FUSE-T with the Linux ABI

**Files:**
- Modify: `crates/cryptomator-mount/examples/spike_macos_dlopen.rs`
- Create: `docs/superpowers/spikes/2026-09-06-spike-c-fuse-t-linux-abi.md`

**Interfaces:** none new; gate for Tasks 6/7.

- [ ] **Step 1: Adapt the example**

In the example: for `fuse-t`, reduce the options to `["-o", "nonamedattr"]` (no `backend=smb`) and set `config.abi = KernelAbi::Linux`; for `macfuse`, `KernelAbi::Native`. `attr()` returns `nlink: 2` for the root directory; implement `statfs` with `reply.statfs(1_000_000, 500_000, 500_000, 1000, 500, 4096, 255, 4096)` (FUSE-T asks for STATFS first).

- [ ] **Step 2: Run it (macOS, FUSE-T installed)**

```bash
mkdir -p /tmp/spike-c-mnt
cargo run -p cryptomator-mount --example spike_macos_dlopen -- fuse-t /tmp/spike-c-mnt &
sleep 3; mount | grep spike-c-mnt; cat /tmp/spike-c-mnt/hello.txt; ls -la /tmp/spike-c-mnt; umount /tmp/spike-c-mnt; wait
```

Expected: the mount appears in the mount table, `cat` prints `Hello from crypto spike A!`, `umount` terminates the program with `session ended (unmounted)`. On failure: inspect the FUSE-T log `~/Library/Logs/fuse-t/fuse-t.log`, recompute the struct offsets (Spike A table), fix up the fork — **Task 2 is not finished until the mount works** (root-cause analysis in the spike document; `fuse_open_out`/`fuse_statfs_out`/`fuse_init_out` may be affected as well; check all layouts against `fuse_kernel.h` from libfuse 3).

- [ ] **Step 3: Spike document** following the pattern of Spike A (setup, backend/result table, observations, consequence), plus a manual finding on `ls -la` (attributes correct: `drwxr-xr-x`, uid/gid).

- [ ] **Step 4: Gate + Commit** ("Spike C: FUSE-T mounts with the Linux-ABI fuser session")

---

### Task 3: Mount API, flag parser, transcoder, mount table

**Files:**
- Modify: `crates/cryptomator-mount/Cargo.toml`, `crates/cryptomator-mount/src/lib.rs`
- Create: `crates/cryptomator-mount/src/api.rs`, `flags.rs`, `transcoder.rs`, `mounttab.rs`

**Interfaces:**
- Produces (`api.rs`):

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum MountCapability { FileSystemName, LoopbackHostName, LoopbackPort, MountFlags, MountToExistingDir, MountWithinExistingParent, MountAsDriveLetter, MountToSystemChosenPath, ReadOnly, UnmountForced, VolumeId, VolumeName }
impl MountCapability { pub fn java_name(self) -> &'static str /* "FILE_SYSTEM_NAME" … */ }

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum Mountpoint { Path(PathBuf), Uri(String) }

#[derive(Debug, thiserror::Error)]
pub enum MountError { #[error("mount point {0}: {1}")] MountPoint(PathBuf, String), #[error("unsupported mount flag {0}")] UnsupportedFlag(String), #[error("{0}")] Failed(String), #[error(transparent)] Io(#[from] std::io::Error) }
#[derive(Debug, thiserror::Error)]
pub enum UnmountError { #[error("unmount failed: {0}")] Failed(String), #[error("filesystem busy")] Busy, #[error(transparent)] Io(#[from] std::io::Error) }

pub trait Mount: Send {
    fn mountpoint(&self) -> Mountpoint;
    fn unmount(&mut self) -> Result<(), UnmountError>;          // graceful
    fn unmount_forced(&mut self) -> Result<(), UnmountError>;   // only if UnmountForced capability
    fn close(self: Box<Self>) -> Result<(), UnmountError>;      // join session; unmount first if still mounted
}
pub trait MountBuilder: Send {
    fn set_file_system_name(&mut self, _: &str) -> Result<(), MountError> { Err(unsupported()) }
    fn set_loopback_port(&mut self, _: u16) -> Result<(), MountError> { Err(unsupported()) }
    fn set_mountpoint(&mut self, _: &Path) -> Result<(), MountError> { Err(unsupported()) }
    fn set_mount_flags(&mut self, _: &str) -> Result<(), MountError> { Err(unsupported()) }
    fn set_read_only(&mut self, _: bool) -> Result<(), MountError> { Err(unsupported()) }
    fn set_volume_id(&mut self, _: &str) -> Result<(), MountError> { Err(unsupported()) }
    fn set_volume_name(&mut self, _: &str) -> Result<(), MountError> { Err(unsupported()) }
    fn mount(self: Box<Self>) -> Result<Box<dyn Mount>, MountError>;
}
pub trait MountService: Send + Sync {
    fn java_class_name(&self) -> &'static str;
    fn display_name(&self) -> &'static str;
    fn priority(&self) -> u32;
    fn is_supported(&self) -> bool;
    fn capabilities(&self) -> &'static [MountCapability];
    fn has_capability(&self, c: MountCapability) -> bool { self.capabilities().contains(&c) }
    fn default_mount_flags(&self) -> String;
    fn default_loopback_port(&self) -> Option<u16> { None }
    fn for_file_system(&self, fs: Arc<CryptoFs>) -> Box<dyn MountBuilder>;
}
#[derive(Debug, Clone, serde::Serialize)] #[serde(rename_all = "camelCase")]
pub struct ServiceInfo { pub class_name: String, pub display_name: String, pub alias: Option<String>, pub supported: bool, pub priority: u32, pub capabilities: Vec<String>, pub default_mount_flags: String }
```

- Produces (`flags.rs`): `parse_mount_flags(&str) -> Vec<String>` (Java split, set semantics: order of first mention, duplicates removed); `struct MountFlags { pub read_only: bool, pub adapter: AdapterOptions, pub passthrough: Vec<String> /* "-o…" strings without the prefix, e.g. "volname=X" */ }`; `struct AdapterOptions { pub uid: u32, pub gid: u32, pub attr_timeout: Duration /* 1 s */, pub entry_timeout: Duration /* = attr_timeout when not set */, pub volname: Option<String>, pub no_apple_double: bool, pub default_permissions: bool, pub allow_other: bool, pub allow_root: bool, pub auto_unmount: bool }`; `MountFlags::from_flags(flags: &[String], current_uid: u32, current_gid: u32) -> Result<MountFlags, MountError>` (recognises `-r`/`-oro` → read_only; `-ouid=`/`-ogid=` (u32), `-oattr_timeout=`/`-oentry_timeout=` (seconds, decimals allowed), `-ovolname=`, `-onoappledouble`, `-odefault_permissions`, `-oallow_other`, `-oallow_root`, `-oauto_unmount`; everything else ends up in `passthrough`; flags that do not start with `-o` or `-r` → `UnsupportedFlag`); `MountFlags::linux_mount_options(&self) -> Vec<fuser::MountOption>` (typed: `ro`, `default_permissions`, `auto_unmount`, `fsname=`, `subtype=`, `dev/nodev/suid/nosuid/exec/noexec/atime/noatime/sync/async/dirsync`; **not** passed on: `uid/gid/attr_timeout/entry_timeout/volname/noappledouble` (adapter); the rest `CUSTOM`).
- Produces (`transcoder.rs`): `#[derive(Clone, Copy)] pub enum FuseNormalization { Nfc, Nfd }`, `pub struct NameTranscoder { fuse: FuseNormalization }` with `fuse_to_vault(&OsStr) -> Option<String>` (UTF-8 + NFC), `vault_to_fuse(&str) -> OsString` (NFD on macOS providers), `for_platform_default()` (Linux Nfc, macOS Nfd).
- Produces (`mounttab.rs`): `pub fn is_mountpoint(path: &Path) -> bool` (Linux `/proc/self/mountinfo` field 5 with `\040` unescaping; macOS `mount` command: lines `… on <path> (…)`), `pub fn mounted_paths() -> Vec<PathBuf>`.

- [ ] **Step 1: Failing tests** (unit tests per module)

`flags.rs`:

```rust
#[test]
fn splits_like_java_and_dedups() {
    assert_eq!(parse_mount_flags(" -ouid=501 -ogid=20   -ouid=501 -r"), vec!["-ouid=501", "-ogid=20", "-r"]);
    assert_eq!(parse_mount_flags(""), Vec::<String>::new());
    assert_eq!(parse_mount_flags("-ovolname=My Vault -oattr_timeout=5"), vec!["-ovolname=My Vault", "-oattr_timeout=5"]);
}
#[test]
fn classifies_adapter_and_passthrough_options() {
    let f = MountFlags::from_flags(&parse_mount_flags("-oauto_unmount -ouid=501 -ogid=20 -oattr_timeout=5 -ovolname=Secret -r -ononamedattr -orwsize=262144"), 1000, 1000).unwrap();
    assert!(f.read_only);
    assert_eq!((f.adapter.uid, f.adapter.gid), (501, 20));
    assert_eq!(f.adapter.attr_timeout, Duration::from_secs(5));
    assert_eq!(f.adapter.entry_timeout, Duration::from_secs(5));
    assert_eq!(f.adapter.volname.as_deref(), Some("Secret"));
    assert!(f.adapter.auto_unmount);
    assert_eq!(f.passthrough, vec!["nonamedattr", "rwsize=262144"]);
    let opts = f.linux_mount_options();
    assert!(opts.contains(&fuser::MountOption::RO) && opts.contains(&fuser::MountOption::AutoUnmount));
    assert!(opts.contains(&fuser::MountOption::CUSTOM("nonamedattr".into())));
    assert!(!opts.iter().any(|o| matches!(o, fuser::MountOption::CUSTOM(s) if s.starts_with("uid="))));
    let d = MountFlags::from_flags(&[], 7, 8).unwrap();
    assert_eq!((d.adapter.uid, d.adapter.gid, d.adapter.attr_timeout), (7, 8, Duration::from_secs(1)));
    assert!(matches!(MountFlags::from_flags(&parse_mount_flags("--weird"), 0, 0), Err(MountError::UnsupportedFlag(_))));
    assert!(matches!(MountFlags::from_flags(&parse_mount_flags("-ouid=abc"), 0, 0), Err(MountError::UnsupportedFlag(_))));
}
```

`transcoder.rs`:

```rust
#[test]
fn nfd_on_fuse_side_nfc_in_vault() {
    let t = NameTranscoder::new(FuseNormalization::Nfd);
    assert_eq!(t.fuse_to_vault(OsStr::new("cafe\u{301}.txt")).unwrap(), "caf\u{e9}.txt");
    assert_eq!(t.vault_to_fuse("caf\u{e9}.txt"), OsString::from("cafe\u{301}.txt"));
    let id = NameTranscoder::new(FuseNormalization::Nfc);
    assert_eq!(id.vault_to_fuse("caf\u{e9}.txt"), OsString::from("caf\u{e9}.txt"));
    assert!(t.fuse_to_vault(OsStr::from_bytes(&[0xff, 0xfe])).is_none());
}
```

`mounttab.rs`:

```rust
#[test]
fn parses_linux_mountinfo_and_macos_mount_output() {
    let mi = "36 35 98:0 /mnt1 /mnt/my\\040vault rw,relatime - fuse cryptoFs rw\n37 35 0:1 / /proc rw - proc proc rw\n";
    assert_eq!(parse_mountinfo(mi), vec![PathBuf::from("/mnt/my vault"), PathBuf::from("/proc")]);
    let mo = "/dev/disk3s1s1 on / (apfs, sealed, local)\nfuse-t:/vault on /Users/x/mnt/Vault (nfs, nodev)\n";
    assert_eq!(parse_macos_mount(mo), vec![PathBuf::from("/"), PathBuf::from("/Users/x/mnt/Vault")]);
    assert!(is_mountpoint(Path::new("/")));
    assert!(!is_mountpoint(Path::new("/definitely/not/mounted")));
}
```

`api.rs`: `capabilities` Java names (`MountCapability::MountToExistingDir.java_name() == "MOUNT_TO_EXISTING_DIR"`), `Mountpoint` serialises as `{"path": …}` / `{"uri": …}`.

- [ ] **Step 2: Implementation** per the interfaces; `Cargo.toml` of the mount crate: `serde`, `serde_json`, `thiserror`, `unicode-normalization`, `nix` (features `fs`, `user`), `log`; `fuser`/`libloading` behind the `fuse` feature (default).

- [ ] **Step 3: Tests** `cargo test -p cryptomator-mount` → PASS

- [ ] **Step 4: Gate + Commit** ("Add mount service API, flag parser, name transcoder and mount table probe")

---

### Task 4: Errno mapping, inode and handle tables (+ `FilesystemLoop` marker in the core)

**Files:**
- Create: `crates/cryptomator-mount/src/fuse/mod.rs`, `fuse/errno.rs`, `fuse/inodes.rs`, `fuse/handles.rs`
- Modify: `crates/cryptomator-core/src/fs/mod.rs` (`FilesystemLoop`), `crates/cryptomator-core/src/fs/symlinks.rs` (uses it)

**Interfaces:**
- Core: `pub struct FilesystemLoop(pub String)` (`Display` "…: too many levels of symbolic links", `std::error::Error`); `fs_loop(path)` creates `io::Error::new(Other, FilesystemLoop(path.to_string()))`; test: `err.get_ref().and_then(|e| e.downcast_ref::<FilesystemLoop>()).is_some()`.
- `errno.rs`: `pub fn errno_for(err: &io::Error) -> fuser::Errno`: `raw_os_error()` → `Errno::from_i32`; otherwise by kind: NotFound→ENOENT, AlreadyExists→EEXIST, NotADirectory→ENOTDIR, IsADirectory→EISDIR, DirectoryNotEmpty→ENOTEMPTY, PermissionDenied→EACCES, ReadOnlyFilesystem→EROFS, InvalidInput→EINVAL, InvalidData→EIO, UnexpectedEof→EIO, Unsupported→ENOTSUP, `Other` carrying `FilesystemLoop` → ELOOP, otherwise EIO.
- `inodes.rs`:

```rust
pub struct InodeTable { /* Mutex<Inner> */ }
struct Inner { by_ino: HashMap<u64, Entry>, by_path: HashMap<CleartextPath, u64>, next: u64 }
struct Entry { path: CleartextPath, lookups: u64 }
impl InodeTable {
    pub fn new() -> Self;                                            // ino 1 = root, lookups = u64::MAX/2 (never forgotten)
    pub fn path(&self, ino: u64) -> Option<CleartextPath>;
    pub fn lookup(&self, path: &CleartextPath) -> u64;               // get-or-insert, lookups += 1
    pub fn forget(&self, ino: u64, n: u64);                          // remove when lookups reaches 0 (never ino 1)
    pub fn rename(&self, from: &CleartextPath, to: &CleartextPath);  // re-keys `from` and every descendant (rebase)
    pub fn remove_path(&self, path: &CleartextPath);                 // after unlink/rmdir: drop the path→ino mapping but keep ino→path until forget (like libfuse: open handles keep working)
    pub fn len(&self) -> usize;
}
```

- `handles.rs`: `pub struct FileHandles { … }` with `insert(OpenFileEntry) -> u64` (starting at 1, monotonic), `get(u64) -> Option<Arc<OpenFileEntry>>`, `remove(u64) -> Option<OpenFileEntry>`; `pub struct OpenFileEntry { pub handle: cryptomator_core::fs::FileHandle, pub path: CleartextPath, pub append: bool, pub writable: bool }`; `pub struct DirHandles` likewise with `DirSnapshot { pub entries: Vec<DirListing> }`, `DirListing { pub name: OsString, pub ino: u64, pub kind: fuser::FileType }` (including `.`/`..`).

- [ ] **Step 1: Failing tests** (`inodes.rs`)

```rust
#[test]
fn lookup_forget_rename_and_remove() {
    let t = InodeTable::new();
    assert_eq!(t.path(1).unwrap(), CleartextPath::root());
    let a = t.lookup(&CleartextPath::parse("/a"));
    let ab = t.lookup(&CleartextPath::parse("/a/b"));
    assert_eq!(t.lookup(&CleartextPath::parse("/a")), a, "stable");
    assert!(a >= 2 && ab > a);
    t.rename(&CleartextPath::parse("/a"), &CleartextPath::parse("/x"));
    assert_eq!(t.path(ab).unwrap().to_string(), "/x/b");
    assert_eq!(t.lookup(&CleartextPath::parse("/x")), a);
    t.remove_path(&CleartextPath::parse("/x/b"));
    assert_eq!(t.path(ab).unwrap().to_string(), "/x/b", "ino survives until forget");
    assert_ne!(t.lookup(&CleartextPath::parse("/x/b")), ab, "a re-created path gets a fresh ino");
    t.forget(a, 1);
    assert!(t.path(a).is_some(), "two lookups, one forget");
    t.forget(a, 1);
    assert!(t.path(a).is_none());
    t.forget(1, u64::MAX);
    assert!(t.path(1).is_some(), "root is never forgotten");
}
```

`errno.rs`: table of all kinds listed above + `raw_os_error(libc::ENOSPC)` → `Errno::ENOSPC` + `FilesystemLoop` → `ELOOP`.

- [ ] **Step 2: Implementation** (mutex via the `lock` helper as in the core, no poison panic).

- [ ] **Step 3: Tests** `cargo test -p cryptomator-mount fuse:: && cargo test -p cryptomator-core fs::symlinks` → PASS

- [ ] **Step 4: Gate + Commit** ("Add errno mapping, inode and handle tables for the FUSE adapter")

---

### Task 5: `VaultOps` – the fuser-free operation core

**Files:**
- Create: `crates/cryptomator-mount/src/fuse/ops.rs`

**Interfaces:**

```rust
pub struct VaultOpsConfig { pub transcoder: NameTranscoder, pub options: AdapterOptions, pub read_only: bool, pub delete_apple_double: bool /* macOS providers */, pub max_name_length: u32 /* statfs namelen = max_cleartext_name_length */ }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attr { pub ino: u64, pub size: u64, pub blocks: u64, pub atime: SystemTime, pub mtime: SystemTime, pub ctime: SystemTime, pub crtime: SystemTime, pub kind: fuser::FileType, pub perm: u16, pub nlink: u32, pub uid: u32, pub gid: u32, pub blksize: u32 }
pub struct Statfs { pub blocks: u64, pub bfree: u64, pub bavail: u64, pub files: u64, pub ffree: u64, pub bsize: u32, pub namelen: u32, pub frsize: u32 }
pub struct Created { pub attr: Attr, pub fh: u64 }
pub struct VaultOps { fs: Arc<CryptoFs>, inodes: InodeTable, files: FileHandles, dirs: DirHandles, cfg: VaultOpsConfig, vault_path: PathBuf }
impl VaultOps {
    pub fn new(fs: Arc<CryptoFs>, cfg: VaultOpsConfig) -> Self;
    pub fn lookup(&self, parent: u64, name: &OsStr) -> Result<Attr, Errno>;
    pub fn forget(&self, ino: u64, n: u64);
    pub fn getattr(&self, ino: u64, fh: Option<u64>) -> Result<Attr, Errno>;
    pub fn setattr(&self, ino: u64, fh: Option<u64>, size: Option<u64>, atime: Option<TimeOrNow>, mtime: Option<TimeOrNow>) -> Result<Attr, Errno>;  // mode/uid/gid ignored (ruling)
    pub fn readlink(&self, ino: u64) -> Result<Vec<u8>, Errno>;
    pub fn mkdir(&self, parent: u64, name: &OsStr) -> Result<Attr, Errno>;
    pub fn unlink(&self, parent: u64, name: &OsStr) -> Result<(), Errno>;   // EISDIR for directories
    pub fn rmdir(&self, parent: u64, name: &OsStr) -> Result<(), Errno>;    // ENOTDIR for non-dirs; AppleDouble sweep when configured
    pub fn symlink(&self, parent: u64, link_name: &OsStr, target: &Path) -> Result<Attr, Errno>;
    pub fn rename(&self, parent: u64, name: &OsStr, newparent: u64, newname: &OsStr, noreplace: bool, exchange: bool) -> Result<(), Errno>;  // exchange → EINVAL
    pub fn open(&self, ino: u64, flags: OpenFlags) -> Result<u64, Errno>;   // acc_mode + O_TRUNC + O_APPEND; write on read-only vault → EROFS; directory → EISDIR
    pub fn create(&self, parent: u64, name: &OsStr, flags: OpenFlags) -> Result<Created, Errno>;  // O_EXCL → create_new else create; EEXIST
    pub fn read(&self, fh: u64, offset: u64, size: u32) -> Result<Vec<u8>, Errno>;
    pub fn write(&self, fh: u64, offset: u64, data: &[u8]) -> Result<u32, Errno>;  // append → at current size
    pub fn flush(&self, fh: u64) -> Result<(), Errno>;
    pub fn release(&self, fh: u64) -> Result<(), Errno>;                     // close(); EBADF if unknown
    pub fn fsync(&self, fh: u64, datasync: bool) -> Result<(), Errno>;
    pub fn opendir(&self, ino: u64) -> Result<u64, Errno>;                   // snapshot listing incl. "." and ".." with inos
    pub fn readdir(&self, fh: u64, offset: u64) -> Result<Vec<(DirListing, u64 /* next offset */)>, Errno>;
    pub fn releasedir(&self, fh: u64) -> Result<(), Errno>;
    pub fn statfs(&self) -> Result<Statfs, Errno>;                           // nix::sys::statvfs on vault_path; namelen = cfg.max_name_length
    pub fn access(&self, ino: u64, mask: AccessFlags) -> Result<(), Errno>; // exists + (write && read_only → EROFS)
    pub fn is_in_use(&self) -> bool;                                         // any open file handle
}
```

Rules: cleartext names go through `transcoder.fuse_to_vault` (None → `EINVAL`); `Attr` from `FileAttributes`: `kind` from `file_type`, `perm = mode & 0o7777` (read-only: write bits cleared by CryptoFs), `nlink = 1` (root 2), `uid/gid = cfg.options`, `blksize = 4096`, `blocks = size.div_ceil(512)`, times from the attributes (`created`/`crtime` falls back to `modified`); `setattr` with `size`: via `fh` (when given) or temporarily `open_file(read_write)` + `truncate` + `close`; `atime/mtime`: `TimeOrNow::Now` → `SystemTime::now()`, then `fs.set_times`; `readlink`: `read_link` → `vault_to_fuse` bytes; `rename`: `noreplace` → `replace_existing=false`, otherwise `true`; then `inodes.rename`; `unlink/rmdir`: `fs.delete` (rmdir: `symlink_metadata` must report `is_dir` beforehand) → `inodes.remove_path`; `open`: `OpenAccMode::O_RDONLY` → `read_only()`, `O_WRONLY|O_RDWR` → `read_write()` (+ `truncate` on `O_TRUNC`), `append` on `O_APPEND`; the statistics counters stay in `CryptoFs`.

- [ ] **Step 1: Failing tests** (test vault via `cryptomator_core` — for this the mount crate needs `cryptomator-core` with the `det-rng` feature as a dev-dependency; the helper `test_fs()` creates a vault with `initialize` + `open_vault_with_key`, like `crates/cryptomator-core/src/fs/crypto_fs.rs::tests::test_fs`, but through the public API: `initialize(dir, &key, SivGcm, 220, DEFAULT_KEY_ID, &mut DetRng::default())`, `open_vault_with_key`, `CryptoFs::open(opened, CryptoFsOptions::default())`)

```rust
#[test]
fn full_file_lifecycle_through_ops() {
    let (_dir, ops) = test_ops(false);
    let root = ops.getattr(1, None).unwrap();
    assert_eq!(root.kind, fuser::FileType::Directory);
    let d = ops.mkdir(1, OsStr::new("docs")).unwrap();
    let c = ops.create(d.ino, OsStr::new("a.txt"), OpenFlags(libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL)).unwrap();
    assert_eq!(ops.write(c.fh, 0, b"hello").unwrap(), 5);
    assert_eq!(ops.write(c.fh, 5, b" world").unwrap(), 6);
    ops.flush(c.fh).unwrap();
    ops.release(c.fh).unwrap();
    let a = ops.lookup(d.ino, OsStr::new("a.txt")).unwrap();
    assert_eq!(a.size, 11);
    let fh = ops.open(a.ino, OpenFlags(libc::O_RDONLY)).unwrap();
    assert_eq!(ops.read(fh, 6, 100).unwrap(), b"world");
    assert_eq!(ops.read(fh, 11, 10).unwrap(), b"");
    assert_eq!(ops.write(fh, 0, b"x").unwrap_err(), Errno::EBADF, "read-only handle");
    ops.release(fh).unwrap();
    let fh = ops.open(a.ino, OpenFlags(libc::O_WRONLY | libc::O_APPEND)).unwrap();
    ops.write(fh, 0, b"!").unwrap();
    ops.release(fh).unwrap();
    assert_eq!(ops.getattr(a.ino, None).unwrap().size, 12);
    let t = ops.setattr(a.ino, None, Some(5), None, None).unwrap();
    assert_eq!(t.size, 5);
    let fh = ops.open(a.ino, OpenFlags(libc::O_RDWR | libc::O_TRUNC)).unwrap();
    assert_eq!(ops.getattr(a.ino, Some(fh)).unwrap().size, 0);
    ops.release(fh).unwrap();
    // directory listing with . and ..
    let dh = ops.opendir(d.ino).unwrap();
    let names: Vec<String> = ops.readdir(dh, 0).unwrap().into_iter().map(|(e, _)| e.name.to_string_lossy().into_owned()).collect();
    assert_eq!(names, vec![".", "..", "a.txt"]);
    assert!(ops.readdir(dh, 3).unwrap().is_empty());
    ops.releasedir(dh).unwrap();
    // rename keeps inode, unlink/rmdir
    ops.rename(d.ino, OsStr::new("a.txt"), 1, OsStr::new("b.txt"), false, false).unwrap();
    assert_eq!(ops.lookup(1, OsStr::new("b.txt")).unwrap().ino, a.ino);
    assert_eq!(ops.lookup(d.ino, OsStr::new("a.txt")).unwrap_err(), Errno::ENOENT);
    assert_eq!(ops.rename(1, OsStr::new("b.txt"), 1, OsStr::new("docs"), true, false).unwrap_err(), Errno::EEXIST);
    assert_eq!(ops.rmdir(1, OsStr::new("b.txt")).unwrap_err(), Errno::ENOTDIR);
    assert_eq!(ops.unlink(1, OsStr::new("docs")).unwrap_err(), Errno::EISDIR);
    ops.unlink(1, OsStr::new("b.txt")).unwrap();
    ops.rmdir(1, OsStr::new("docs")).unwrap();
    assert_eq!(ops.lookup(1, OsStr::new("docs")).unwrap_err(), Errno::ENOENT);
    assert!(!ops.is_in_use());
}

#[test]
fn symlinks_transcoding_and_read_only() {
    let (_dir, ops) = test_ops(false);
    let l = ops.symlink(1, OsStr::new("link"), Path::new("docs/a.txt")).unwrap();
    assert_eq!(l.kind, fuser::FileType::Symlink);
    assert_eq!(ops.readlink(l.ino).unwrap(), b"docs/a.txt");
    // NFD name from FUSE is stored NFC and served back NFD
    let f = ops.create(1, OsStr::new("cafe\u{301}.txt"), OpenFlags(libc::O_WRONLY | libc::O_CREAT)).unwrap();
    ops.release(f.fh).unwrap();
    assert!(ops.lookup(1, OsStr::new("caf\u{e9}.txt")).is_ok(), "NFC lookup also works after transcoding");
    let dh = ops.opendir(1).unwrap();
    let names: Vec<OsString> = ops.readdir(dh, 0).unwrap().into_iter().map(|(e, _)| e.name).collect();
    assert!(names.contains(&OsString::from("cafe\u{301}.txt")));
    let (_dir, ro) = test_ops(true);
    assert_eq!(ro.mkdir(1, OsStr::new("d")).unwrap_err(), Errno::EROFS);
    assert_eq!(ro.access(1, AccessFlags::W_OK).unwrap_err(), Errno::EROFS);
    assert!(ro.access(1, AccessFlags::R_OK).is_ok());
    let s = ro.statfs().unwrap();
    assert!(s.bsize > 0 && s.namelen == 10 * 1024);
}

#[test]
fn rmdir_sweeps_apple_double_files_when_configured() { /* create "._x" and ".DS_Store" inside a dir via ops with delete_apple_double = true; rmdir succeeds; with false → ENOTEMPTY */ }
```

(`test_ops(read_only)` configures `NameTranscoder::new(FuseNormalization::Nfd)` and `uid/gid` 501/20.)

- [ ] **Step 2: Implementation** per the rules.

- [ ] **Step 3: Tests** `cargo test -p cryptomator-mount fuse::ops` → PASS (3 tests)

- [ ] **Step 4: Gate + Commit** ("Add the fuser-independent FUSE operation core over CryptoFs")

---

### Task 6: `impl fuser::Filesystem` and session handle

**Files:**
- Create: `crates/cryptomator-mount/src/fuse/adapter.rs`, `fuse/session.rs`

**Interfaces:**
- `pub struct CryptoFuse { ops: Arc<VaultOps> }` with `impl fuser::Filesystem`: every method calls `ops` and translates `Result<_, Errno>` into `reply.*`/`reply.error`; TTLs from `AdapterOptions` (`attr_timeout`, `entry_timeout`), `Generation(0)`; `init` leaves `KernelConfig` unchanged (returns `Ok(())`); `destroy` = no-op; `readdir` iterates `ops.readdir(fh, offset)` and stops at `reply.add(..) == true`; `readdirplus` → `ENOSYS` (FUSE-T/libfuse fall back to readdir); `setattr` passes `size/atime/mtime/fh` through; `mknod` → `ENOSYS`; `link` → `EPERM`; `getxattr/listxattr/setxattr/removexattr` → `ENOTSUP`; `getlk/setlk/bmap/ioctl/poll/fallocate/lseek/copy_file_range` → defaults (ENOSYS); macOS: `setvolname` → `reply.ok()`, `getxtimes` → `xtimes(UNIX_EPOCH, crtime)`, `exchange` → `EINVAL`.
- `session.rs`: `pub struct FuseSessionHandle { bg: Option<fuser::BackgroundSession>, ops: Arc<VaultOps>, mountpoint: PathBuf, unmounter: Box<dyn Fn(bool /*forced*/) -> Result<(), UnmountError> + Send> }` with `spawn_from_fd(ops, fd: OwnedFd, abi: KernelAbi, unmounter) -> io::Result<Self>` (`Session::from_fd(CryptoFuse, fd, SessionACL::Owner, config)` → `spawn()`), `spawn_mounted(ops, mountpoint, options: Vec<MountOption>, acl, unmounter)` (Linux: `Session::new`), `unmount(&mut self, forced: bool) -> Result<(), UnmountError>` (calls `unmounter`, waits up to 10 s for the session thread to end (`guard` via `join` on a helper thread with a timeout — or polling `is_mountpoint`), on timeout without `forced` → `UnmountError::Busy`), `join(self) -> io::Result<()>`, `is_in_use()`.

- [ ] **Step 1: Failing test** (compile/type test without a mount): `fn assert_filesystem<T: fuser::Filesystem>() {}` with `CryptoFuse`; plus an `errno` round trip in `reply`-free helpers (`ttl()` returns `attr_timeout`).

- [ ] **Step 2: Implementation**; note: `Filesystem: Send + Sync + 'static`; `CryptoFuse` holds only `Arc<VaultOps>` (`VaultOps: Send + Sync` — compile-time assert as in M3).

- [ ] **Step 3: Tests + Gate + Commit** ("Add fuser Filesystem adapter and session handle")

---

### Task 7: Providers (Linux, FUSE-T, macFUSE, null) and registry

**Files:**
- Create: `crates/cryptomator-mount/src/fuse/macos_dl.rs`, `fuse/linux.rs`, `fuse/fuset.rs`, `fuse/macfuse.rs`, `crates/cryptomator-mount/src/registry.rs`
- Modify: `crates/cryptomator-mount/src/lib.rs`, `crates/cryptomator-app/src/mounters.rs` (alias `null` → `org.cryptomator.cli.NullMountProvider`)

**Interfaces:**
- `macos_dl.rs` (macOS only): `pub struct LibFuse { lib: libloading::Library, path: PathBuf }` with `load(path) -> Result<Self, MountError>`, `mount(&self, mountpoint: &Path, opts: &[String] /* "-o" values */) -> Result<OwnedFd, MountError>` (argv `["cryptomator-cli", "-o", opt, …]`, `fuse_mount_compat25`), `unmount(&self, mountpoint)` (`fuse_unmount_compat22`). `// SAFETY:` comments as in the spike example.
- `fuset.rs`: `pub struct FuseTMountProvider` (`FUSE_T_DYLIB = "/usr/local/lib/libfuse-t.dylib"`, env override `CRYPTO_FUSE_T_LIB` for tests), `priority 90`, `display_name "FUSE-T (Experimental)"`, caps/defaults as in the Global Constraints, builder: `set_mountpoint` requires an existing directory, `combined_flags` = flags ∪ `-r` ∪ `-ovolname=` ∪ `-ononamedattr`; `mount()`: `LibFuse::load` → `MountFlags::from_flags` → `LibFuse::mount(mountpoint, passthrough ∪ ["uid=", "gid=" still included? NO: uid/gid are NOT passed on, they are for the adapter; `volname`, `nonamedattr`, `rwsize` etc. are passed on])` → `FuseSessionHandle::spawn_from_fd(.., KernelAbi::Linux, umount command)` → `Box<dyn Mount>` (`FuseMount { session, mountpoint, forced_supported: true }`); unmount: `umount -- <p>` (10 s), forced `umount -f -- <p>`; "not currently mounted" on stderr → ok.
- `macfuse.rs`: `MacFuseMountProvider` (`/usr/local/lib/libosxfuse.2.dylib`, `/usr/local/lib/libfuse.2.dylib`; env `CRYPTO_MACFUSE_LIB`), `priority 100`, `display_name "macFUSE"`, `set_mountpoint` allows `/Volumes/<x>` (non-existent) or an existing directory; without a mountpoint, `/Volumes/<volumeId>`; `-obackend=fskit` → `UnsupportedFlag`; `KernelAbi::Native`; transcoder Nfd; **marked as "(unverified)" in the doc comment and in `ServiceInfo.display_name`**.
- `linux.rs`: `LinuxFuseMountProvider`, `priority 100`, `display_name "FUSE"`, supported when `fusermount3 -V` works (2 s timeout, `std::process::Command` + thread with `wait_timeout` via polling); `mount()`: `FuseSessionHandle::spawn_mounted(ops, mountpoint, flags.linux_mount_options(), acl)` with `acl` = `All` for `allow_other`, `RootAndOwner` for `allow_root`, otherwise `Owner` — **in fuser, `auto_unmount` requires `acl != Owner`**: ruling: when `auto_unmount` is set without `allow_*` (the Java default!), `AutoUnmount` is NOT handed to fuser (we unmount ourselves on lock; add a comment). Unmount `fusermount3 -u -- <name>` with cwd = parent (10 s), forced `-uz`; "not mounted"/"entry for … not found" → ok.
- `registry.rs`: `pub const NULL_MOUNTER_CLASS: &str = "org.cryptomator.cli.NullMountProvider"`; `pub struct NullMountProvider` (`is_supported()` ⇔ env `CRYPTO_ENABLE_NULL_MOUNTER=1`; caps `{MOUNT_FLAGS, MOUNT_TO_EXISTING_DIR, READ_ONLY, VOLUME_NAME, UNMOUNT_FORCED}`; `mount()` creates a file `.crypto-null-mount` containing the volume name in the mountpoint and removes it on unmount; `unmount` fails (`Busy`) as long as the environment variable `CRYPTO_NULL_MOUNT_BUSY=1` is set — for lock tests); `pub fn all_services() -> Vec<Box<dyn MountService>>` (platform order by priority, null last), `pub fn services() -> Vec<Box<dyn MountService>>` (only `is_supported`), `pub fn service_by_class(class: &str) -> Option<Box<dyn MountService>>`, `pub fn conflicting_classes(class: &str) -> &'static [&'static str]`, `pub fn service_infos(all: bool) -> Vec<ServiceInfo>`.

- [ ] **Step 1: Failing tests**: capability sets and default flags per provider (uid/gid from `nix::unistd::geteuid/getegid`), `FuseT` `combined_flags` contains `-ononamedattr` exactly once and `-r` when read-only, macFUSE rejects `-obackend=fskit`, `is_supported` via an env override pointing at a temp file; null mounter: `all_services()` contains it, `services()` only with the env var; one complete null mount (mount → `.crypto-null-mount` exists → unmount → gone; `CRYPTO_NULL_MOUNT_BUSY=1` → `Busy`, forced → ok).

- [ ] **Step 2: Implementation**; add the `null` alias in `mounters.rs` (app).

- [ ] **Step 3: Tests + Gate + Commit** ("Add FUSE mount providers for Linux, FUSE-T, macFUSE and a null mounter for tests")

---

### Task 8: Mount E2E test (FUSE-T on this Mac) + Java cross-check

**Files:**
- Create: `crates/cryptomator-mount/tests/mount_e2e.rs`
- Modify: `crates/crypto/tests/java_interop.rs` (test `java_reads_files_written_through_the_mount`, `#[ignore]`, only with `CRYPTO_E2E_MOUNT=1`)

- [ ] **Step 1: Test** (`#[ignore = "mounts a real FUSE filesystem; CRYPTO_E2E_MOUNT=1"]`): vault created with `initialize` in a temp dir, best supported service (`registry::services()[0]`, null mounter excluded; without FUSE → the test reports "skipped" and ends ok), mountpoint = temp dir, `set_mount_flags(default)`, `set_volume_name("e2e")`, `mount()`; then via `std::fs` on the mountpoint: `create_dir`, `write` 100 000 bytes (pattern), `read` back, `metadata().len()`, `rename`, `symlink` + `read_link`, `remove_file`, the listing contains names without `.`, NFD name `cafe\u{301}.txt` → appears in the vault as NFC (check with `CryptoFs::read_dir` after the unmount), `unmount()` + `close()`; afterwards `is_mountpoint == false` and `CryptoFs` reads the tree. Timeout protection: all accesses on a thread with a 30 s limit.
- [ ] **Step 2: Java cross-check**: the same tree, then `verify_with_java` → the manifest matches `crypto fs tree --json --hash`.
- [ ] **Step 3: Run locally**: `CRYPTO_E2E_MOUNT=1 cargo test -p cryptomator-mount --test mount_e2e -- --ignored --nocapture` and the interop test; put the result (including the `mount` line) in the report; document deviations (e.g. FUSE-T quirks such as extra `._` files) and handle them in the adapter if needed.
- [ ] **Step 4: Gate + Commit** ("Add end-to-end mount test and Java verification of mount-written files")

---

### Task 9: State dir, `cli.json`, vault registry, `Mounter`

**Files:**
- Modify: `crates/cryptomator-app/Cargo.toml` (+ `cryptomator-mount`, `log`, `nix`, `data-encoding`), `crates/cryptomator-app/src/lib.rs`, `src/error.rs`
- Create: `crates/cryptomator-app/src/state_dir.rs`, `src/cli_config.rs`, `src/registry.rs`, `src/mounting/mod.rs`, `src/mounting/mounter.rs`

**Interfaces:**
- `error.rs`: `AppError::{MountFailed(String), UnmountFailed(String), DaemonUnreachable(String), DaemonError { code: String, message: String }, MountPointInvalid(PathBuf, String)}`.
- `state_dir.rs`:

```rust
pub const STATE_DIR_ENV: &str = "CRYPTO_STATE_DIR";
#[derive(Debug, Clone)] pub struct StateDir { root: PathBuf }
impl StateDir {
    pub fn from_env_or_default() -> Result<Self>;   // env → macOS ~/Library/Application Support/Cryptomator/cli-run → Linux $XDG_RUNTIME_DIR/crypto → /tmp/crypto-<uid>
    pub fn at(root: PathBuf) -> Self;
    pub fn ensure(&self) -> Result<()>;              // create_dir_all + chmod 0700 (only when we created it or it is ours)
    pub fn files(&self, vault_id: &str) -> VaultStateFiles;
    pub fn list_run_infos(&self) -> Result<Vec<RunInfo>>;
}
#[derive(Debug, Clone)] pub struct VaultStateFiles { pub socket: PathBuf, pub pid: PathBuf, pub info: PathBuf, pub log: PathBuf }
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)] #[serde(rename_all = "camelCase")]
pub struct RunInfo { pub vault_id: String, pub path: String, pub mounter: String, pub mountpoint: Option<String>, pub pid: u32, pub started_at: u64 /* epoch secs */, pub read_only: bool }
impl VaultStateFiles {
    pub fn write_pid(&self, pid: u32) -> Result<()>; pub fn read_pid(&self) -> Option<u32>;
    pub fn write_info(&self, info: &RunInfo) -> Result<()>; pub fn read_info(&self) -> Option<RunInfo>;
    pub fn remove_all(&self) -> Result<()>;          // sock/pid/info (log stays)
}
pub fn process_alive(pid: u32) -> bool;              // nix::sys::signal::kill(pid, None)
```

- `cli_config.rs`: `cli.json` next to `settings.json` (`SettingsStore::preferred_path().with_file_name("cli.json")`):

```rust
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)] #[serde(rename_all = "camelCase", default)]
pub struct CliConfig { pub mount_points_dir: Option<String>, pub default_mounter: Option<String>, pub log_level: String /* "info" */, pub force_unmount_on_signal_after_secs: u32 /* 10 */, #[serde(flatten)] pub extra: Map<String, Value> }
impl CliConfig { pub fn load(path: &Path) -> Result<Self> /* missing → default */; pub fn save(&self, path: &Path) -> Result<()> /* tmp+rename */; pub fn mount_points_dir(&self, home: &Path) -> PathBuf /* macOS ~/Library/Application Support/Cryptomator/mnt, Linux ~/.local/share/Cryptomator/mnt */ }
```

- `registry.rs`:

```rust
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)] #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuntimeState { Locked, Unlocked, StaleMount, Missing, VaultConfigMissing, AllMissing, NeedsMigration, Error }
#[derive(Debug, Clone, serde::Serialize)] #[serde(rename_all = "camelCase")]
pub struct VaultInfo { pub id: String, pub display_name: Option<String>, pub path: Option<String>, pub state: RuntimeState, pub mountpoint: Option<String>, pub mounter: Option<String>, pub pid: Option<u32>, pub read_only: Option<bool> }
pub struct VaultRegistry { store: SettingsStore, state_dir: StateDir }
impl VaultRegistry {
    pub fn new(store: SettingsStore, state_dir: StateDir) -> Self;
    pub fn runtime_state(&self, vault_id: &str) -> Result<(RuntimeState, Option<RunInfo>)>;  // socket connectable → Unlocked; else pid alive → Unlocked (daemon starting); else info.mountpoint still mounted (is_mountpoint) → StaleMount; else stale files removed → disk state (determine_vault_state)
    pub fn infos(&self) -> Result<Vec<VaultInfo>>;
    pub fn info(&self, reference: &str) -> Result<VaultInfo>;
}
```

- `mounting/mounter.rs` (port of `Mounter` + `SettledMounter`):

```rust
pub struct MountRequest<'a> { pub vault: &'a VaultSettingsJson, pub settings: &'a SettingsJson, pub cli: &'a CliConfig, pub home: &'a Path, pub overrides: MountOverrides }
#[derive(Debug, Default, Clone)] pub struct MountOverrides { pub mounter: Option<String> /* class */, pub mount_point: Option<PathBuf>, pub mount_options: Vec<String> /* "-o…" appended */, pub read_only: Option<bool>, pub volume_name: Option<String> }
pub struct MountHandle { pub mount: Box<dyn Mount>, pub supports_forced: bool, pub cleanup: Option<PathBuf> /* created mount dir to remove after unmount */, pub service_class: String }
pub fn choose_service(req: &MountRequest, services: &[Box<dyn MountService>]) -> Result<Box<dyn MountService>>;   // overrides.mounter → vault.mount_service → cli.default_mounter → settings.mount_service → first supported; unknown/unsupported → MountFailed
pub fn mount(req: &MountRequest, fs: Arc<CryptoFs>) -> Result<MountHandle>;
```

Mount point policy exactly as in `Mounter.prepareMountPoint`: user path (`overrides.mount_point` → `vault.mount_point`) → validate (existing directory for `MountToExistingDir`; non-existent `/Volumes/…` for `MountToSystemChosenPath`), otherwise `MountPointInvalid`; without a user path: `MountToSystemChosenPath` → no mountpoint; `MountToExistingDir` → create `mountPointsDir/<mountName>` (`cleanup = Some(dir)`); apply capabilities as in `SettledMounter.prepare` (`FILE_SYSTEM_NAME="cryptoFs"`, `READ_ONLY`, `MOUNT_FLAGS` (empty → default) with `overrides.mount_options` appended, `VOLUME_ID=id`, `VOLUME_NAME=mount_name`; `LOOPBACK_PORT` not before M5).

- [ ] **Step 1: Failing tests**: state dir defaults per OS (with `HOME`/`XDG_RUNTIME_DIR` overrides passed as parameters, not as global env), `ensure` sets 0700, `RunInfo` round trip, `process_alive(std::process::id())`; `CliConfig` default/load/save/unknown keys preserved; `runtime_state`: no state → `Locked` (disk); info + PID of a terminated process + a path that is not mounted → files removed, `Locked`; info with `mountpoint = "/"` (always mounted) + dead PID → `StaleMount`; `choose_service` ordering with fake services (`is_supported` via the constructor); `mount` with `NullMountProvider`: the mount point policy creates `mountPointsDir/<mountName>`, `cleanup` is set, `.crypto-null-mount` exists; a user path that does not exist → `MountPointInvalid`.

- [ ] **Step 2: Implementation**; `lib.rs` re-exports `state_dir::*`, `cli_config::CliConfig`, `registry::*`, `mounting::*`.

- [ ] **Step 3: Tests + Gate + Commit** ("Add state dir, cli.json, vault registry and the mounter port")

---

### Task 10: Daemon protocol and client

**Files:**
- Create: `crates/cryptomator-app/src/daemon/mod.rs`, `daemon/protocol.rs`, `daemon/client.rs`

**Interfaces (`protocol.rs`, everything `serde` + `Serialize/Deserialize`, camelCase):**

```rust
pub const PROTOCOL_VERSION: u32 = 1;
pub struct Hello { pub hello: String /* "crypto-daemon" */, pub protocol: u32, pub vault_id: String, pub pid: u32 }
#[serde(tag = "op", rename_all = "camelCase")]
pub enum Request {
    Unlock { id: u64, key: String /* base64 of 64 raw bytes */, mounter: Option<String>, mount_point: Option<String>, mount_options: Vec<String>, read_only: Option<bool>, volume_name: Option<String>, max_cleartext_name_length: usize },
    Status { id: u64 }, Stats { id: u64 }, Lock { id: u64, force: bool }, Events { id: u64, follow: bool, since: u64 }, Ping { id: u64 }, Shutdown { id: u64 },
}
pub struct Response { pub id: u64, pub ok: bool, #[serde(skip_serializing_if = "Option::is_none")] pub result: Option<serde_json::Value>, #[serde(skip_serializing_if = "Option::is_none")] pub error: Option<ErrorBody> }
pub struct ErrorBody { pub code: String /* "MOUNT_FAILED" | "UNMOUNT_FAILED" | "ALREADY_UNLOCKED" | "NOT_UNLOCKED" | "BAD_REQUEST" | "INTERNAL" */, pub message: String }
pub struct StatusResult { pub vault_id: String, pub state: String /* "STARTING" | "UNLOCKED" | "LOCKING" */, pub mountpoint: Option<String>, pub mounter: String, pub read_only: bool, pub started_at: u64, pub uptime_secs: u64, pub last_activity: u64, pub in_use: bool }
pub struct StatsResult { pub bytes_per_second_read: u64, pub bytes_per_second_written: u64, pub bytes_per_second_encrypted: u64, pub bytes_per_second_decrypted: u64, pub cache_hit_rate: f64, pub total_bytes_read: u64, pub total_bytes_written: u64, pub total_bytes_encrypted: u64, pub total_bytes_decrypted: u64, pub files_read: u64, pub files_written: u64, pub total_files_accessed: u64, pub last_activity: u64 }
pub struct EventRecord { pub seq: u64, pub timestamp: u64, pub kind: String, pub message: String, pub cleartext_path: Option<String>, pub ciphertext_path: Option<String> }
pub struct EventsResult { pub events: Vec<EventRecord>, pub next_seq: u64 }
pub struct StreamItem { pub id: u64, pub event: EventRecord }   // for follow streams: one line per event, terminated by a final Response
pub fn write_line<W: Write>(w: &mut W, value: &impl Serialize) -> io::Result<()>;
pub fn read_line<R: BufRead>(r: &mut R) -> io::Result<Option<String>>;  // None on EOF; max 1 MiB
```

The key in `Request::Unlock` is a `String` — after decoding, the line/struct is wiped via `zeroize` (`Zeroizing<String>` for the raw line; `key` in a `Zeroizing<String>` via a detour that avoids `#[serde(with = …)]`: should `Request::Unlock` hold `key: Zeroizing<String>`? `serde` support for `Zeroizing<String>` is not available → ruling: field `key: String`, `impl Drop for Request` wipes it (`key.zeroize()`) — plus an explicit `zeroize` after decoding).

**`client.rs`:**

```rust
pub struct DaemonClient { stream: BufReader<UnixStream>, writer: UnixStream, next_id: u64, pub hello: Hello }
impl DaemonClient {
    pub fn connect(socket: &Path) -> Result<Self>;                        // one attempt; reads Hello; NotFound/ConnectionRefused → DaemonUnreachable
    pub fn connect_with_retry(socket: &Path, deadline: Duration) -> Result<Self>;  // 100 ms backoff
    pub fn call(&mut self, request: Request) -> Result<serde_json::Value>;   // sends, reads until a Response with the same id; error → AppError::DaemonError; sets `id` from next_id
    pub fn stream(&mut self, request: Request, mut on_item: impl FnMut(EventRecord) -> bool /* continue? */) -> Result<()>;  // for follow
    pub fn status(&mut self) -> Result<StatusResult>; pub fn stats(&mut self) -> Result<StatsResult>; pub fn lock(&mut self, force: bool) -> Result<()>; pub fn events(&mut self, since: u64) -> Result<EventsResult>; pub fn ping(&mut self) -> Result<()>;
}
```

- [ ] **Step 1: Failing tests**: exact serialisation (`{"op":"lock","id":3,"force":true}`; `Response` without the `result` field on error; `StreamItem`); `read_line` EOF/limit; `DaemonClient` against an in-process fake server (thread with a `UnixListener` in a temp dir: writes Hello, answers `Ping` with `ok`, `Lock{force:false}` with error `UNMOUNT_FAILED`, `Events{follow:true}` with two `StreamItem`s + a closing Response); `connect` to a non-existent socket → `DaemonUnreachable`; `connect_with_retry` finds a socket that appears 300 ms later.

- [ ] **Step 2: Implementation**

- [ ] **Step 3: Tests + Gate + Commit** ("Add daemon protocol and client")

---

### Task 11: Daemon server

**Files:**
- Create: `crates/cryptomator-app/src/daemon/server.rs`, `daemon/logging.rs`

**Interfaces:**

```rust
pub struct DaemonConfig { pub vault_id: String, pub state_dir: StateDir, pub store: SettingsStore, pub cli: CliConfig, pub home: PathBuf, pub services: Vec<Box<dyn MountService>>, pub unlock_timeout: Duration /* 60 s */, pub stats_interval: Duration /* 1 s */, pub autolock_tick: Duration /* 60 s; env CRYPTO_AUTOLOCK_TICK_SECS overrides for tests */, pub force_unmount_after: Duration /* cli.force_unmount_on_signal_after_secs */ }
pub fn run_daemon(config: DaemonConfig, shutdown: Arc<AtomicBool> /* set by signal handler */) -> Result<()>;
```

Flow (`run_daemon`): `state_dir.ensure()`; remove the socket file if leftovers exist; `UnixListener::bind` + chmod 0600; write the PID; logger (`logging.rs`: `log::Log` impl writing to `<id>.log`, 0600, level from `cli.log_level`, format `2026-09-06T10:00:00Z INFO target: msg`); **Phase 1 (STARTING)**: accept connections (each on its own thread), send Hello; only `Ping`/`Status`/`Shutdown` plus exactly one `Unlock` are allowed; without an `Unlock` within `unlock_timeout` → cleanup + exit 1. `Unlock`: key base64 → `[u8;64]` (`Zeroizing`) → `Masterkey::from_raw` → `open_vault_with_key(path, key)` → `CryptoFs::open(opened, CryptoFsOptions { read_only, max_cleartext_name_length, events: sink → ring buffer })` → `mounting::mount(MountRequest{… overrides from Unlock}, Arc<CryptoFs>)` → write `RunInfo` → reply `ok` with `{"mountpoint": …}`; error → reply `MOUNT_FAILED` + cleanup + exit 6. **Phase 2 (UNLOCKED)**: requests `Status/Stats/Lock/Events/Ping/Shutdown`; stats sampler thread (1 s): snapshot deltas → `StatsResult` fields (`bytes_per_second_*`, `cache_hit_rate = hits/accesses` for the interval), `last_activity` when `accesses_read + accesses_written` grows; auto-lock thread (tick): reload the settings (`store.load()`), `auto_lock_when_idle && idle >= auto_lock_idle_seconds` → graceful lock (log errors, continue); `Lock{force}`: `handle.mount.unmount()`/`unmount_forced()` (only if `supports_forced`, otherwise error `UNMOUNT_FAILED` with a note) → on success `close()`, remove the `cleanup` dir, `fs.close()`, reply `ok`, then shutdown; on error reply `UNMOUNT_FAILED` and keep running; `Events{follow}`: ring buffer (`VecDeque<EventRecord>` max 1000, `seq` starting at 1) from `since`; with `follow` the connection stays open and receives new events (condvar) until the client disconnects or shutdown; `shutdown` (signal/request): graceful like lock, forced after `force_unmount_after`; finally `remove_all()`, exit 0.

The daemon's `Status.state`: `STARTING` until the mount is done, `UNLOCKED`, `LOCKING` during the unmount. The daemon refuses a second `Unlock` (`ALREADY_UNLOCKED`).

- [ ] **Step 1: Failing tests** (in-process, null mounter, temp dir, `DaemonConfig` with `services = vec![Box::new(NullMountProvider)]`, `CRYPTO_ENABLE_NULL_MOUNTER=1` via a constructor flag instead of env, small intervals): a thread starts `run_daemon`; `DaemonClient::connect_with_retry`; `Status` → `STARTING`; `Unlock` with the key of a vault created via `initialize` (settings entry in a temp-dir `settings.json`) → `ok`, mountpoint = `mountPointsDir/<mountName>`, `.crypto-null-mount` exists, `RunInfo` written; second `Unlock` → `ALREADY_UNLOCKED`; `Stats` returns the fields; events: sink event (triggered by an `fs` access to a broken `dir.c9r`, or more simply: in tests the server offers `inject_event`) → `Events{since:0}` returns it; `Lock{force:false}` with `CRYPTO_NULL_MOUNT_BUSY=1` (constructor flag) → `UNMOUNT_FAILED`, the daemon is alive (`Ping` ok); `Lock{force:true}` → ok, the thread ends, state files gone, mount dir removed. Second test: auto-lock with `autoLockWhenIdle=true`, `autoLockIdleSeconds=1`, tick 1 s → the daemon terminates within 5 s. Third test: unlock timeout (200 ms) without an unlock → exit result Err, files gone. Fourth: wrong key (`open_vault_with_key` → `VaultKeyInvalid`) → `MOUNT_FAILED` … ruling: code `MOUNT_FAILED` with message `vault key does not match` (exit 6 in the CLI).

- [ ] **Step 2: Implementation** (threads: accept loop, one per connection, stats, autolock; shared `Arc<Mutex<DaemonState>>`; `shutdown: Arc<AtomicBool>` + condvar; no busy loops).

- [ ] **Step 3: Tests + Gate + Commit** ("Add the vault daemon server")

---

### Task 12: CLI `unlock`, `lock`, `__daemon`, `--state-dir`, `fs` refusal

**Files:**
- Modify: `crates/crypto/Cargo.toml` (+ `libc`, `signal-hook`, `cryptomator-mount`), `src/cli.rs`, `src/main.rs`, `src/exit.rs`, `src/commands/mod.rs`, `src/commands/fs.rs`
- Create: `src/commands/unlock.rs`, `src/commands/lock.rs`, `src/commands/daemon.rs`, `crates/crypto/tests/cli_daemon.rs`

**Grammar:**

```rust
/// Unlock and mount a vault in a background daemon
Unlock(UnlockArgs),   // vault; --mounter <ALIAS|CLASS>; --mount-point <PATH>; --mount-option=<-o…> (repeatable, require_equals, allow_hyphen_values); --read-only; --volume-name <N>; --foreground; --reveal; PasswordArgs
/// Unmount and lock vaults
Lock(LockArgs),       // vaults: Vec<String> (allow_hyphen_values) | --all; --force
#[command(name = "__daemon", hide = true)] Daemon(DaemonArgs),  // --vault-id, --socket, --state-dir
```

Global: `#[arg(long, global = true, value_name = "PATH", env = "CRYPTO_STATE_DIR")] state_dir: Option<PathBuf>` → `Ctx.state_dir: StateDir`. `exit.rs`: `MOUNT_FAILED = 6`, `UNMOUNT_FAILED = 7`, `DAEMON_UNREACHABLE = 10`; mapping `AppError::MountFailed/MountPointInvalid → 6`, `UnmountFailed → 7`, `DaemonUnreachable → 10`, `DaemonError{code}`: `UNMOUNT_FAILED → 7`, `MOUNT_FAILED → 6`, `ALREADY_UNLOCKED/NOT_UNLOCKED → 5`, otherwise 1.

`unlock` (`commands/unlock.rs`): check the registry state (`Unlocked` → exit 5 "already unlocked at <mp>"; `StaleMount` → exit 5 with a note about `crypto lock --force`); `locked_vault`; hub check; password; `open_vault` (scrypt) → name length probe/persistence as in the Global Constraints (only when not read-only and `max_cleartext_filename_length == -1`; result via `store.update`) → determine `max_cleartext_name_length`; `masterkey.raw()` base64 in a `Zeroizing<String>`; daemon spawn (`current_exe()`, args `__daemon --vault-id … --socket … --state-dir …` + `--settings` when set; `env_remove("CRYPTO_PASSWORD")`; `stdin(null)`, stdout/stderr → log file (append, 0600); `// SAFETY` `pre_exec(|| { libc::setsid(); Ok(()) })`; `current_dir("/")`); `--foreground`: instead run `run_daemon` in-process on a thread + the client on the main thread, signals (`signal_hook::flag::register(SIGINT/SIGTERM, shutdown)`); client `connect_with_retry(30 s)` → `Unlock{…}` → result: human `Unlocked <name> at <mountpoint>` / JSON `{ "id", "mountpoint", "mounter", "pid" }`; `--reveal` or `actionAfterUnlock == REVEAL` → `open <mp>` (macOS) / `xdg-open <mp>` (Linux), ignore errors; on `failed` → log tail (last 20 lines) to stderr, exit 6.

`lock`: for every reference (or all `Unlocked/StaleMount` with `--all`): `Unlocked` → client `Lock{force}` → success/error (7); `StaleMount` → unmount command directly (`registry`/provider `unmount_stale(mountpoint, forced)` → `cryptomator_mount::registry::service_by_class(info.mounter).unmount_path(...)` — extend the `MountService` trait with `fn unmount_path(&self, mountpoint: &Path, forced: bool) -> Result<(), UnmountError>` in Task 7 (default `Err`) → **an addendum to Task 7 is allowed within this task**), then remove the state files; `Locked` → exit 5 "not unlocked". JSON `{ "locked": [ids] }`. `--all` without unlocked vaults → ok, "nothing to lock".

`fs` commands (M3 promise): `open_fs` checks `registry.runtime_state` → `Unlocked|StaleMount` → `WrongState { expected: "LOCKED", actual: "UNLOCKED (mounted at …)" }` (exit 5), for read commands too (ruling: simpler and safer).

- [ ] **Step 1: Failing tests (`tests/cli_daemon.rs`)** with `Sandbox` (+ `--state-dir <sandbox>/state`, env `CRYPTO_ENABLE_NULL_MOUNTER=1`, `CRYPTO_AUTOLOCK_TICK_SECS=1`): `vault create v` → `unlock v --mounter null --json` → fields, `mountpoint` = `<sandbox>/home/…/mnt/v`? (point `HOME` at the sandbox; write a `cli.json` with `mountPointsDir=<sandbox>/mnt`) → `.crypto-null-mount` exists; `status v --json` → `UNLOCKED`; a second `unlock v` → exit 5; `fs ls v` → exit 5; `lock v` → ok, file gone, `status` → `LOCKED`; `lock v` again → exit 5; `unlock` with `CRYPTO_NULL_MOUNT_BUSY=1`, then `lock v` → exit 7, `lock v --force` → ok; `unlock v --foreground` in a background process (`std::process::Command` spawn) + `lock v` terminates it (exit 0 within 10 s); stale: after `unlock`, kill the daemon with `kill -9 <pid>`, `status` → `STALE_MOUNT` … with the null mounter nothing is really mounted → `is_mountpoint` false → the registry cleans up → `LOCKED` (the test checks exactly that). Wrong password → exit 4 without a daemon; `unlock nope` → exit 3; `--mounter bogus` → exit 2.

- [ ] **Step 2: Implementation**

- [ ] **Step 3: Tests + Gate + Commit** ("Add crypto unlock and lock with a detached vault daemon")

---

### Task 13: CLI `status`, `stats`, `events`, `mounters`, `config` for `cli.json`

**Files:**
- Modify: `src/cli.rs`, `src/main.rs`, `src/commands/config.rs`
- Create: `src/commands/{status,stats,events,mounters}.rs`; extend the tests in `tests/cli_daemon.rs`

**Grammar:** `Status { vault: Option<String> }`; `Stats(StatsArgs { vault, --follow, --interval <SECS=1> })`; `Events(EventsArgs { vault, --follow, --since <SEQ=0> })`; `Mounters { --all }`.

Output: `status` human table `ID  NAME  STATE  MOUNTPOINT` (all vaults; with an argument only one), JSON `VaultInfo` (array); `stats` human `read 0 B/s  write 0 B/s  cache 0%  total read …  files …  last activity …`, JSON `StatsResult`, `--follow` → NDJSON per interval until Ctrl-C; `events` human `seq  time  KIND  message`, JSON `EventRecord` array / NDJSON with `--follow`; `mounters` human `ALIAS  CLASS  SUPPORTED  CAPABILITIES`, JSON `ServiceInfo` array (without `--all` only the supported ones; the null mounter only with `--all`). `config get|set` keys `mountPointsDir`, `defaultMounter` (alias or class), `logLevel` (`error|warn|info|debug|trace`), `forceUnmountOnSignalAfterSecs` → `cli.json`.

- [ ] **Step 1: Failing tests**: `status --json` before/after unlock; `stats v --json` fields; `events v --json` empty → `[]`; `mounters --json` contains the null mounter only with `--all` and `supported=true` only with the env var; `config set mountPointsDir <dir>` takes effect on the next `unlock`; `config get logLevel` → `info`.

- [ ] **Step 2: Implementation + tests + Gate + Commit** ("Add status, stats, events, mounters and cli.json settings")

---

### Task 14: Signals, forced-unmount escalation, auto-lock in foreground mode, reveal

**Files:**
- Modify: `src/commands/unlock.rs`, `crates/cryptomator-app/src/daemon/server.rs`

- SIGINT/SIGTERM/SIGHUP in the daemon (detached and foreground) → `shutdown` → graceful unmount; forced after `force_unmount_on_signal_after_secs`; then exit 0 (or 7 if forced fails as well, the mount stays in place → log + state files remain, so that `status` shows `STALE_MOUNT`).
- Auto-lock test via the CLI: `vault set v --auto-lock-idle 1` + `unlock` (tick 1 s) → within 5 s `status` → `LOCKED`.
- Reveal: `--reveal` calls `open`/`xdg-open`; overridable in tests via the env var `CRYPTO_REVEAL_CMD=<script>` (writes the path into a file).

- [ ] **Step 1/2/3**: tests (`tests/cli_daemon.rs`: `--foreground` + SIGTERM → the process ends with 0 and the null mount is gone; busy + SIGTERM → forced after 1 s (`config set forceUnmountOnSignalAfterSecs 1`)), implementation, Gate + Commit ("Handle signals, forced unmount escalation, auto-lock and reveal")

---

### Task 15: M3 addenda for daemon operation

**Files:**
- Modify: `crates/cryptomator-core/src/fs/path_mapper.rs`, `fs/dir_id.rs`, `fs/crypto_fs.rs`, `fs/open_files.rs`

- `CryptoPathMapper::dir_cache`: entries carry an `Instant`; hits older than 20 s are discarded and reloaded (Java `CiphertextDirCache` `expireAfterWrite(20 s)`); `DirIdLoader`: same expiry (Java has none, but without an expiry a long-running daemon never sees foreign changes to `dir.c9r` — ruling); `CryptoFs`: `impl Drop` → `open_files.close_all()` (errors ignored, logged via `log::warn`); `FileHandle::release`: flush **outside** the registry lock (hold the file lock, take the registry lock only for the removal) — the lock order stays registry → file, because `release` first takes the file lock, flushes, releases it, then locks registry + file and checks the handle count; tests: expiry via an injectable clock offset (`#[cfg(test)] fn advance(&self, d: Duration)`), Drop closes handles (the file is flushed afterwards), `release` under concurrency (two threads write two files in parallel without a deadlock).

- [ ] **Step 1/2/3**: tests, implementation, Gate + Commit ("Add cache expiry, Drop-close and lock-free flush for long-running mounts")

---

### Task 16: CI, documentation, spec

**Files:**
- Modify: `.github/workflows/ci.yml`, `README.md`, `CHANGELOG.md`, `docs/superpowers/specs/2026-09-04-crypto-cli-design.md`, `docs/superpowers/spikes/2026-09-04-spike-a-fuse-t.md` (reference to Spike C)

- CI: job `mount-e2e-linux` (ubuntu-22.04: `sudo apt-get install -y fuse3`, `CRYPTO_E2E_MOUNT=1 cargo test -p cryptomator-mount --test mount_e2e --locked -- --ignored`), job `mount-e2e-macos` (macos-15: `brew install --cask macos-fuse-t/homebrew-cask/fuse-t`, same test, `continue-on-error: true` — FUSE-T may need an approval), the `test` job sets `CRYPTO_ENABLE_NULL_MOUNTER=1` for `cli_daemon`.
- README: sections "Mounting" (prerequisites macOS FUSE-T/macFUSE, Linux `fuse3`; `unlock/lock/status/stats/events/mounters`; state dir; `cli.json` keys; signals; `--foreground`), extend the command table, exit codes 6/7/10, note that macFUSE is unverified, FUSE-T limitations (no xattr, NFS backend).
- CHANGELOG `### M4 – FUSE mount and daemon` including the eight rulings and the M3 addenda; spec: M4 ✅ (footnote: WebDAV/port M5, keychain M6), align the `cryptomator-mount` section with the implementation (`ops.rs`, null mounter, `KernelAbi`, no `backend=smb`, key over the socket, std threads), correct the daemon design accordingly.

- [ ] **Step 1/2/3**: changes, Gate (including `cargo test -p crypto --test java_interop --locked -- --ignored` and locally `CRYPTO_E2E_MOUNT=1 … mount_e2e`), Commit ("Document M4 and add mount end-to-end CI jobs")

---

## Self-check

- **Spec coverage M4:** `api.rs`/`registry.rs`/`flags.rs`/`transcoder.rs` (3, 7); `fuse/adapter.rs` + inode/handle tables + errno mapping (4–6); `fuse/linux.rs`, `macos_dl.rs`, `macfuse.rs`, `fuset.rs` (7) with the fuser Linux ABI (1) and the follow-up spike (2); `Mounter` (9); `daemon/{protocol,client,server}` (10, 11); `state_dir.rs`, `cli_config.rs`, `registry.rs` (9); CLI `unlock/lock/status/stats/events/mounters/__daemon` (12–14); auto-lock (11, 14); mount E2E Linux CI + FUSE-T macOS (8, 16); coexistence with the desktop app = a manual step. Not in M4 (assigned elsewhere by the spec): WebDAV/`--port` (M5), keychain/`--store-password` (M6), `fs` access to mounted vaults (stays refused).
- **Type consistency:** `KernelAbi` (1) in 2, 6, 7; `MountService/MountBuilder/Mount/MountCapability/MountError/UnmountError/ServiceInfo` (3) in 7, 9, 11, 12, 13; `MountFlags/AdapterOptions/parse_mount_flags` (3) in 5, 7; `NameTranscoder` (3) in 5, 7; `is_mountpoint` (3) in 6, 9, 12; `FilesystemLoop`/`errno_for` (4) in 5, 6; `InodeTable/FileHandles/DirHandles/DirListing` (4) in 5; `VaultOps/VaultOpsConfig/Attr` (5) in 6, 7; `CryptoFuse/FuseSessionHandle` (6) in 7; `NullMountProvider/services/all_services/service_by_class/conflicting_classes/service_infos` (7) in 9, 11, 12, 13; `StateDir/VaultStateFiles/RunInfo/process_alive`, `CliConfig`, `VaultRegistry/VaultInfo/RuntimeState`, `Mounter::{choose_service, mount}/MountRequest/MountOverrides/MountHandle` (9) in 11, 12, 13; `protocol::*`, `DaemonClient` (10) in 11, 12, 13; `DaemonConfig/run_daemon` (11) in 12, 14; `unmount_path` (addendum 12→7) in 12.
- **Placeholders:** none; where signatures have to be adapted to fuser internals (Task 1), the target behaviour is specified byte-exactly.
- **Exit code mapping:** `MountFailed/MountPointInvalid` → 6, `UnmountFailed`/daemon `UNMOUNT_FAILED` → 7, `DaemonUnreachable` → 10, `ALREADY_UNLOCKED/NOT_UNLOCKED`/`WrongState` → 5, `MountFailed` on a wrong key in the daemon → 6 (password errors are already caught in the parent process with 4).

## Execution

`superpowers:subagent-driven-development` with Opus 5 subagents; order 1 → 16. Tasks 2 and 8 perform real FUSE-T mounts on this Mac (no root required); the implementer must document the results (mount table, `cat`, `umount`) in the report. Tasks 12–14 set `CRYPTO_ENABLE_NULL_MOUNTER=1` in the tests.
