# Spike A: FUSE-T / macFUSE via dlopen + fuser::Session::from_fd

> **Addendum (M4):** option 1 of the consequence below has been implemented and proven —
> `docs/superpowers/spikes/2026-09-06-spike-c-fuse-t-linux-abi.md` (**spike C**) mounts FUSE-T
> successfully with `KernelAbi::Linux` from the fork `vendor/fuser`. The switch is a
> run-time decision (`Config::abi`) instead of a feature, so that one binary serves macFUSE and FUSE-T.
> macFUSE remains unverified (still not installed). The
> "NO-GO" result below therefore applies to **unmodified** fuser 0.18 and is superseded by the fork.

Question: does `fuse_mount_compat25` from `libfuse-t.dylib` yield an fd over which fuser 0.18 can speak the kernel FUSE protocol?

Setup: `cargo run -p cryptomator-mount --example spike_macos_dlopen -- <fuse-t|macfuse> /tmp/spike-mnt`

Environment: macOS 26.6.2 (build 25G83), Apple Silicon, Rust workspace `crypto`, fuser 0.18.0 (`macos-no-mount`), libloading 0.9.

| Backend | Installed (version) | fuse_mount fd | Handshake | cat hello.txt | umount | Result |
|---|---|---|---|---|---|---|
| FUSE-T | yes (1.2.7, `/usr/local/lib/libfuse-t.dylib` → `libfuse-t-1.2.7.dylib`) | ok (fd = 4) | ok (`proto=7.19`, recognised by FUSE-T as `client=libfuse3`) | fails (the mount never appears in the mount table) | not applicable (never mounted) | **NO-GO** |
| macFUSE | no (`/usr/local/lib/libfuse.2.dylib` missing) | — | — | — | — | **BLOCKED** |

## Observations

### macFUSE — BLOCKED

macFUSE is not installed; the spike aborts as intended:

```
$ ./target/debug/examples/spike_macos_dlopen macfuse /tmp/spike-mnt-macfuse
/usr/local/lib/libfuse.2.dylib not found – install FUSE-T (brew install --cask macos-fuse-t/homebrew-cask/fuse-t) or macFUSE
EXIT=2
```

To be made up as soon as macFUSE is installed (installing it is a user decision, kext/system extension was out of scope for this spike):

```bash
# install macFUSE (user decision, requires system extension approval)
brew install --cask macfuse
mkdir -p /tmp/spike-mnt
cargo run -p cryptomator-mount --example spike_macos_dlopen -- macfuse /tmp/spike-mnt
# second shell:
cat /tmp/spike-mnt/hello.txt; umount /tmp/spike-mnt
```

### FUSE-T — NO-GO, but not because of the transport

The dlopen path itself works completely:

```
$ ./target/debug/examples/spike_macos_dlopen fuse-t /tmp/spike-mnt
mounted at /tmp/spike-mnt; in another shell run: cat /tmp/spike-mnt/hello.txt && umount /tmp/spike-mnt
spike failed: Invalid request
EXIT=1
```

Reproducible across all runs. In detail (determined with a temporary diagnostic example and the `log` logger enabled, not committed):

1. `fuse_mount_compat25` returns a valid fd (`fd = 4`).
2. `Session::from_fd` completes the handshake **successfully**. FUSE-T confirms this in its own log (`~/Library/Logs/fuse-t/fuse-t.log`):
   `fuse session negotiated profile=v3 client=libfuse3 proto=7.19 max_write=16777216 flags=0xe0000001`
3. FUSE-T starts its NFS server (`Server version 1.2.7 running at 127.0.0.1:52100`) and sends real kernel FUSE requests over the fd, which fuser delivers correctly: `STATFS`, `GETATTR` (twice each on inode 1).
4. Right after the `GETATTR` reply FUSE-T tears down the connection (`Connection closed`); the fd returns EOF. fuser reports that as `Short read of FUSE request header (0 < 40)` and, following from it, `Invalid request` — so the error message is misleading, it is an **EOF**, not a parse error on our side.

The actual reason is in FUSE-T's debug log — FUSE-T decodes our `GETATTR` reply incorrectly:

```
Getattr reply: {136 0 6}, {AttrValid:1 AttrValidNsec:0 Dummy:0 Attr:{Ino:1 Size:0 Blocks:1
  Atime:0 Mtime:0 Ctime:0 Crtime:0 Atimensec:0 Mtimensec:0 Ctimensec:0 Crtimensec:0
  Mode:0 Nlink:0 Uid:0 Gid:16877 Rdev:1 Flags:20 Blksize:501 Padding:0}}
```

What the spike had sent was `mode=0o40755 (=16877)`, `nlink=1`, `uid=501`, `gid=20`, `rdev=0`, `flags=0`, `blksize=512`. The values land in FUSE-T's struct shifted by exactly three `u32` fields.

**Root cause: a `fuse_attr` layout mismatch.** Under `#[cfg(target_os = "macos")]` fuser activates the macFUSE variant of `fuse_attr` (`src/ll/fuse_abi.rs`) with the additional fields `crtime: u64`, `crtimensec: u32` and `flags: u32` **before** `blksize` — 104 bytes in total. FUSE-T, in contrast, reads the **Linux** layout (88 bytes, without `crtime`/`crtimensec`, `blksize` before `flags`), consistent with the fact that it recognises our client as `libfuse3`. Interpreting our buffer against the Linux offsets, every observable field matches exactly:

| FUSE-T field | Linux offset | Value at that offset in fuser's macOS layout | Reported by FUSE-T |
|---|---|---|---|
| Mode | 60 | `mtimensec` = 0 | 0 |
| Nlink | 64 | `ctimensec` = 0 | 0 |
| Uid | 68 | `crtimensec` = 0 | 0 |
| Gid | 72 | `mode` = 16877 | 16877 |
| Rdev | 76 | `nlink` = 1 | 1 |
| Blksize | 80 | `uid` = 501 | 501 |
| Flags | 84 | `gid` = 20 | 20 |

Because `Mode` therefore arrives as `0`, the root inode is for FUSE-T neither a directory nor any other valid type — FUSE-T aborts the mount. Nothing ever appears in the mount table, so `cat`/`umount` cannot be carried out.

Secondary causes ruled out (each tested individually):

- **Not** the negotiated minor version: FUSE-T offers 7.23; INIT replies with minor 19/23 and a length of 40/80 bytes all lead to an identical, clean message flow.
- **Not** `statfs`: even with realistic values instead of fuser's default (0 blocks), FUSE-T aborts at the same point.
- **Not** the mount point: `/tmp/spike-mnt` and `$HOME/spike-mnt` behave the same.
- **Not** the development environment's sandbox: identical result with the sandbox disabled.
- **Not** missing mount permissions: a manual `mount -t nfs` as a normal user fails with `Connection refused` (that is, permitted), not with `Operation not permitted`.
- **Note on the brief:** the prescribed option `-o backend=smb` is unusable on this system anyway — FUSE-T 1.2.7 ships only the NFS helper (`/Library/Application Support/fuse-t/bin/go-nfsv4`), no SMB backend. With `backend=smb` even FUSE-T's own mount call fails (`mount -t smbfs …`, `exit status 64`). The spike code keeps the option as the brief specifies; the diagnosis above was additionally carried out with the default backend (NFS), which gets further (`STATFS`+`GETATTR` instead of just `GETATTR`) and exposes the root cause.

## Consequence for M4

**Plan in a lowlevel/ABI adaptation for FUSE-T — the plain dlopen path with an unmodified fuser 0.18 is not enough.**

An important nuance for the planning: transport and handshake are *not* the problem. `dlopen` → `fuse_mount_compat25` → `fuser::Session::from_fd` works, and real kernel FUSE protocol flows over the fd in both directions. The obstacle is exclusively the **struct ABI of the replies**: FUSE-T expects the Linux variants, fuser produces the macFUSE variants under macOS. Options:

1. **fuser with the Linux ABI under macOS** (preferred, smallest intervention): a fork/patch that makes the `#[cfg(target_os = "macos")]` fields in `fuse_abi.rs` switchable, so that `Session::from_fd` writes the Linux layout when talking to FUSE-T. This affects `fuse_attr` at least; the remaining `#[cfg(target_os = "macos")]` structs have to be reviewed before the implementation. Suitable for upstream as a feature flag (e.g. `abi-linux`).
2. **Our own `fuse_lowlevel_ops` FFI backend** for FUSE-T, as foreseen in the spec as a fallback — considerably more work, but independent of fuser's ABI decisions.
3. **The macFUSE path** is untouched by the root cause and is plausible with fuser as planned (macFUSE uses exactly the ABI that fuser produces under macOS) — **not verified yet**, since macFUSE is not installed. That is the next spike step, as soon as the user installs macFUSE.

## Reproduction

```bash
mkdir -p /tmp/spike-mnt
cargo run -p cryptomator-mount --example spike_macos_dlopen -- fuse-t /tmp/spike-mnt
tail -f ~/Library/Logs/fuse-t/fuse-t.log   # FUSE-T's view; considerably more talkative with -o debug
```
