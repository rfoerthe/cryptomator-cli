# Spike C: FUSE-T with the Linux ABI of the fuser session

Question: does FUSE-T mount when `fuser::Session::from_fd` runs with `Config { abi: KernelAbi::Linux, .. }`
— that is, with the Linux struct layouts instead of the macFUSE ones? Spike A had identified the
`fuse_attr` layout as the root cause of the failed mount (NO-GO); task 1 built the
run-time switch into the fork `vendor/fuser`. Spike C is the end-to-end proof.

## Setup

Environment: macOS 26.6.2 (build 25G83), Apple Silicon, rustc 1.98.0, workspace `crypto`,
`vendor/fuser` (fuser 0.18.0 + Linux ABI patch), libloading 0.9.
FUSE-T 1.2.7 (`/usr/local/lib/libfuse-t.dylib`), macFUSE **not** installed.

Changes to the spike example compared with spike A
(`crates/cryptomator-mount/examples/spike_macos_dlopen.rs`):

- `fuse-t`: options are now only `["-o", "nonamedattr"]` — `-o backend=smb` is gone (FUSE-T 1.2.7
  ships no SMB backend on this system, see spike A), `config.abi = KernelAbi::Linux`.
- `macfuse`: unchanged `["-o", "noappledouble"]` and `KernelAbi::Native`.
- The root inode reports `nlink: 2` (`.` plus the entry in the parent directory).
- `statfs` implemented: `reply.statfs(1_000_000, 500_000, 500_000, 1000, 500, 4096, 255, 4096)`.
  FUSE-T sends STATFS as the very first operation and before **every** GETATTR.

```bash
mkdir -p /tmp/spike-c-mnt
cargo run -p cryptomator-mount --example spike_macos_dlopen -- fuse-t /tmp/spike-c-mnt &
sleep 5
mount | grep spike-c-mnt
cat /tmp/spike-c-mnt/hello.txt
ls -la /tmp/spike-c-mnt
umount /tmp/spike-c-mnt
```

## Result

| Backend | Version | mount fd | Handshake | mount table | `cat` | `ls -la` | `umount` | Result |
|---|---|---|---|---|---|---|---|---|
| FUSE-T (`KernelAbi::Linux`) | 1.2.7 | ok | ok (`proto=7.19`, `client=libfuse3`) | ok (`fuse-t:/crypto-spike … (nfs, nodev, nosuid, mounted by rfoerthe)`) | ok (`Hello from crypto spike A!`) | ok (`drwxr-xr-x`, uid/gid 501/20, `nlink 2`) | ok, the program ends with `session ended (unmounted)` | **GO** |
| FUSE-T (`KernelAbi::Native`) | 1.2.7 | ok | ok | — | — | — | — | NO-GO (spike A) |
| macFUSE | not installed | — | — | — | — | — | — | BLOCKED (unchanged) |

## Observations

### Verbatim output of the GO run

```
$ mount | grep spike-c-mnt
fuse-t:/crypto-spike on /private/tmp/spike-c-mnt (nfs, nodev, nosuid, mounted by rfoerthe)

$ cat /tmp/spike-c-mnt/hello.txt
Hello from crypto spike A!

$ ls -la /tmp/spike-c-mnt
total 4000001
drwxr-xr-x   2 rfoerthe  staff     0 Jan  1  1970 .
drwxrwxrwt  57 root      wheel  1824 Sep  6 10:01 ..
-r--r--r--   1 rfoerthe  staff    27 Jan  1  1970 hello.txt

$ ls -lan /tmp/spike-c-mnt
total 4000001
drwxr-xr-x   2 501  20     0 Jan  1  1970 .
drwxrwxrwt  57 0    0   1824 Sep  6 09:59 ..
-r--r--r--   1 501  20    27 Jan  1  1970 hello.txt

$ stat -f '%N mode=%Sp uid=%u gid=%g nlink=%l size=%z' /tmp/spike-c-mnt /tmp/spike-c-mnt/hello.txt
/tmp/spike-c-mnt mode=drwxr-xr-x uid=501 gid=20 nlink=2 size=0
/tmp/spike-c-mnt/hello.txt mode=-r--r--r-- uid=501 gid=20 nlink=1 size=27

$ df -h /tmp/spike-c-mnt
Filesystem              Size    Used   Avail Capacity iused ifree %iused  Mounted on
fuse-t:/crypto-spike   3.8Gi   1.9Gi   1.9Gi    50%     500   500   50%   /private/tmp/spike-c-mnt

$ umount /tmp/spike-c-mnt        # rc=0

# output of the spike program:
mounted at /tmp/spike-c-mnt; in another shell run: cat /tmp/spike-c-mnt/hello.txt && umount /tmp/spike-c-mnt
session ended (unmounted)

$ mount | grep spike             # empty, rc=1
```

The attributes are completely correct: `drwxr-xr-x` for the root directory, `-r--r--r--` for
`hello.txt`, uid 501 / gid 20 (the real values from `geteuid`/`getegid`), `nlink` 2 and 1 respectively,
size 27 = `len("Hello from crypto spike A!\n")`. `df` mirrors the `statfs` reply:
1,000,000 × 4096 = 3.8 GiB, 500,000 free, 500 of 1000 inodes used.

### The proof in the FUSE-T log

With `-o debug` (added for the diagnosis only, not committed) FUSE-T logs every
reply. The same GETATTR reply that arrived shifted by three `u32` in spike A is now
decoded correctly:

```
# Spike A (KernelAbi::Native), WRONG:
wire: recv body unique=6 payload=120
Getattr reply: … Mode:0 Nlink:0 Uid:0 Gid:16877 Rdev:1 Flags:20 Blksize:501 Padding:0

# Spike C (KernelAbi::Linux), CORRECT:
wire: recv body unique=4 payload=104
Getattr reply: {120 0 4}, {AttrValid:1 AttrValidNsec:0 Dummy:0 Attr:{Ino:1 Size:0 Blocks:1
  Atime:0 Mtime:0 Ctime:0 Crtime:0 Atimensec:0 Mtimensec:0 Ctimensec:0 Crtimensec:0
  Mode:16877 Nlink:2 Uid:501 Gid:20 Rdev:0 Flags:0 Blksize:512 Padding:0}}
```

`payload` 120 → 104 is the payload of `fuse_attr_out` (16-byte prefix + `fuse_attr`): 104 bytes
macFUSE layout vs. 88 bytes Linux layout. `Mode:16877` is `0o40755`, so finally a
directory — exactly the value FUSE-T choked on in spike A.

### What FUSE-T mounts and sends

```
Mounting: /tmp/spike-c-mnt
mount [-o port=52100,mountport=52100,vers=4 -t nfs fuse-t:/crypto-spike /tmp/spike-c-mnt]
```

FUSE-T translates FUSE into NFSv4 and mounts via `mount -t nfs` against its own
loopback server. That is why the mount shows up as `nfs` in the `mount` table, not as `fusefs`,
and `umount` is a perfectly ordinary NFS `umount` — no `umount -f`, no root privileges.

Opcode statistics of a complete run (mount + `cat` + `ls -la` + `umount`):

| Opcode | Name | Count |
|---|---|---|
| 3 | GETATTR | 33 |
| 17 | STATFS | 22 |
| 1 | LOOKUP | 11 |
| 28 | READDIR | 2 |
| 27 / 29 | OPENDIR / RELEASEDIR | 1 each |
| 14 / 15 / 25 / 18 | OPEN / READ / FLUSH / RELEASE | 1 each |

Notable:

- **STATFS + GETATTR before almost every NFS operation.** FUSE-T fetches `StatFS 1` and `GetAttr 1`
  before every NFSv4 COMPOUND (`mount`, `secinfo`, `statfs`, `pathconf`, `lookup`, `access`, …).
  That is why `statfs` is not a "nice to have": fuser's default reports 0 blocks, and to the
  NFS client that looks like a full/broken file system.
- **macOS metadata noise.** LOOKUPs that will never exist but still have to be answered
  (all with `ENOENT`): `._.` (2×), `.DS_Store`, `.hidden`, `.Spotlight-V100`,
  `.metadata_never_index`, `.metadata_never_index_unless_rootfs`,
  `.metadata_direct_scope_only`, `Applications`, `DCIM`. The `._` requests arrive despite
  `-o nonamedattr` — the option suppresses named streams (AppleDouble as extended attributes),
  not the Finder's/`ls`'s search for AppleDouble sidecar files.
- **No READDIRPLUS (44), no GETXATTR (22)** in this run — the adapter must not rely on that,
  though; both paths have already been converted in the fork.
- `umount` produces **no** FUSE_DESTROY: FUSE-T simply closes the connection
  (`Connection closed`).

### An additional fork patch: EOF ends the session cleanly

The mount and `cat` worked immediately with the task 1 fork; only the exit did not. On the first
run the program ended with

```
spike failed: Invalid request
```

instead of `session ended (unmounted)`. The cause is not an ABI problem but the transport:
`/dev/fuse` returns `ENODEV` on unmount, and that is exactly what fuser treats as a clean end
(`session.rs`, `Err(Errno::ENODEV) => return Ok(())`). FUSE-T's channel, in contrast, is a socket that
is simply closed on unmount — `read()` returns **0**. fuser passed those 0 bytes on to
`RequestWithSender::new`, which returns `None` as expected, out of which the event loop made
`io::ErrorKind::InvalidData` / "Invalid request". (The same misleading message as in
spike A, but there with the `fuse_attr` mismatch as the actual cause.)

Patch in `vendor/fuser/src/session.rs`: `Ok(0)` ends `SessionEventLoop::event_loop` with
`Ok(())`; during the handshake `Ok(0)` leads to the existing `NotConnected` error. A read of 0 bytes
can never be a valid FUSE request, and on Linux the case does not occur — so there the patch
is a no-op.

Covered by an end-to-end test over a `socketpair`
(`vendor/fuser/src/session.rs::abi_session_test::linux_abi_session_answers_getattr_and_ends_cleanly_on_eof`):
INIT → GETATTR (the reply has to be an 88-byte `fuse_attr` with `mode` @60, `nlink` @64, `uid` @68, `gid` @72,
`blksize` @80) → close the peer → `Session::run()` has to return `Ok(())`. Without the patch
the test fails with exactly `Err(Custom { kind: InvalidData, error: "Invalid request" })`.

Further `#[cfg(target_os = "macos")]` deviations did **not** have to be touched. Every struct used in
this run was checked against `fuse_kernel.h` of libfuse 3:
`fuse_init_out` (identical), `fuse_statfs_out`/`fuse_kstatfs` (identical — FUSE-T decodes the
reply verbatim, see `Statfs reply` above), `fuse_open_out` (identical), `fuse_read_in`,
`fuse_write_in`, `fuse_dirent` (all identical). What remains in `fuse_abi.rs` as macOS special cases is only
the structs task 1 has already given Linux twins (`fuse_attr` and everything that
embeds it, plus `fuse_setattr_in`, `fuse_getxattr_in`, `fuse_setxattr_in`), plus the
Darwin-only opcodes `FUSE_SETVOLNAME`/`FUSE_GETXTIMES`/`FUSE_EXCHANGE`, which FUSE-T never sends.

## Consequence for M4

**The way is clear: `dlopen(libfuse-t.dylib)` → `fuse_mount_compat25` → `Session::from_fd` with
`KernelAbi::Linux` is a viable FUSE-T backend.** A separate `fuse_lowlevel_ops` FFI backend
(fallback option 2 from spike A) is not needed.

For the adapter task (task 6/7) this means:

1. **`abi` belongs to the backend, not to the platform.** FUSE-T ⇒ `KernelAbi::Linux`,
   macFUSE ⇒ `KernelAbi::Native`. The value has to come from the same place that decides
   which `.dylib` is loaded.
2. **Converted structs** (from task 1, confirmed here): `fuse_attr` and everything that
   embeds it — `fuse_entry_out`, `fuse_attr_out`, `fuse_create_out`, `fuse_direntplus` — as well as,
   on the request side, `fuse_setattr_in`, `fuse_getxattr_in` (also for LISTXATTR) and
   `fuse_setxattr_in`. Everything else is the same between macFUSE and Linux.
3. **`statfs` is mandatory.** FUSE-T asks for STATFS before practically every operation; fuser's
   default reply (0 blocks) is not enough. The vault adapter should report real values from the
   backing store.
4. **`nlink` for directories.** The spike A version had the root with `nlink: 1`; the
   NFSv4 path did not fail because of it, but the correct value is `2 + number of subdirectories`.
5. **Catch the AppleDouble/Spotlight noise.** `._*`, `.DS_Store`, `.hidden`, `.Spotlight-V100`,
   `.metadata_*` are requested on every directory access. `-o nonamedattr` does not prevent
   it. For an encrypted vault that means: these names either have to be answered quickly with
   `ENOENT` (no round trip into the encryption) or — if they are supposed to be allowed
   — end up as ordinary files in the vault. A negative lookup cache in the adapter
   would be worthwhile here.
6. **Unmount = EOF.** No FUSE_DESTROY. The daemon has to treat an `Ok(())` from `Session::run()` as
   "cleanly unmounted" and must not wait for `Destroy`. The fork patch above makes sure of
   that.
7. **The mount is an NFS mount.** The `mount` table says `nfs`, and the mount point shows up
   under `/private/tmp/...`. Anyone checking the mount status via `mount`/`statfs` must not test for
   `fusefs` as the file system type. `umount` without special privileges is enough.

## E2E findings (task 8, a real vault mount)

Task 8 mounts a real vault through the finished provider for the first time
(`crates/cryptomator-mount/tests/mount_e2e.rs`, FUSE-T 1.2.7, macOS 26.6.2). What stood out beyond
the spike observations:

1. **The channel is a stream socket — message framing is the reader's job.** The `SO_TYPE` of the
   descriptor returned by `fuse_mount_compat25` is `SOCK_STREAM` (RCVBUF/SNDBUF 4 MiB each).
   fuser treats every `read` as exactly one request; on a stream socket that is wrong in
   **both** directions:
   * **Too little:** FUSE-T sends a WRITE as **two** `write()`s (`wire: send unique=31
     opcode=16 … bytes=80` + `wire: send data bytes=4096`). A single `read` returned only the
     first 80 bytes; the parser saw a request without payload, the reply never came, the
     NFS client waited ~40 s per write and the session was dead afterwards. Intermittent,
     because the two `write()`s usually coalesce in the socket buffer — with a 10 KiB payload it never
     showed up, with 100 KiB always.
   * **Too much:** exactly that coalescing also hits **two consecutive requests**. The
     event loop answered the first and silently discarded the second; the client waited forever for
     its reply and the mount stalled. Symptom in the E2E test: "the mount stopped answering:
     no result within 30 s", after which the test process hung in an uninterruptible `U` state on the
     mount point. Occurred in ~1 out of 5 runs and only became visible through repeat runs.
   Fix in the fork: `Channel::receive_retrying` returns **exactly one** request — it keeps reading until
   the buffer contains the `len` announced in the `fuse_in_header`, and keeps everything read beyond
   that in `Channel::spill` for the next call (`vendor/fuser/src/channel.rs`, tests
   `session::abi_session_test::a_request_split_across_two_writes_is_read_as_one` and
   `…::two_requests_that_arrive_in_one_read_are_both_answered`). On `/dev/fuse` both are a
   no-op: there every `read` returns exactly one complete request, and the spill buffer stays empty.
   **Consequence for any further socket transport: message framing is mandatory — in both
   directions.**
2. **macOS' NFS client creates an AppleDouble sidecar file `._<name>` for every new node.**
   After `mkdir docs` a `Create` of `._docs` follows immediately, after every file a `._datei`, for
   symlinks too. Without a countermeasure an extra encrypted entry ends up in the vault for every
   node. `-ononamedattr` changes nothing about it (identical with **and** without the option);
   macFUSE prevents it with `-onoappledouble` in the kernel, FUSE-T has no counterpart.
   Fix in the adapter: `VaultOpsConfig::refuse_apple_double` (on for FUSE-T) answers
   `create`/`mkdir`/`symlink`/`rename` on `._*` with `EPERM` — the same errno that macFUSE's
   kernel extension returns. The client discards the sidecar file and the user's actual operation
   still succeeds; the vault stays clean. `.DS_Store` is deliberately **not**
   affected (the Finder writes that for the user; the `rmdir` sweep covers it).
   Incidentally, the client deletes the sidecar file along with its node when the node disappears — so an
   `rmdir` of a directory just created does not fail because of it.
3. **`ro` is accepted.** A read-only mount (`-o ro` to `fuse_mount_compat25`) shows up as
   `fuse-t:/e2e-ro on … (nfs, nodev, nosuid, read-only, mounted by rfoerthe)`; `write(2)` and
   `mkdir(2)` fail with **EROFS (30)**, reading works. The adapter's own EROFS stays in place as a
   second line of defence.
4. **The mount appears in the mount table asynchronously.** `fuse_mount_compat25` returns
   as soon as the server is listening; the `mount -t nfs` runs afterwards. Anyone calling `umount` right
   away gets "not currently mounted", the session keeps running and the mount shows up afterwards. That is why the E2E test
   waits (up to 20 s) for `is_mountpoint`. For tasks 9/10 that means: after `mount()`, wait for
   the mount table before reporting the state as "mounted".
5. **Mount point paths are canonicalised.** A temp dir under `/var/folders/...` appears as
   `/private/var/folders/...` in the table; `mounttab::is_mountpoint` canonicalises both sides
   and therefore matches.
6. **NFSv4 locking is not implemented by FUSE-T** (`Implement txLockCommon`,
   `Implement txLocku`, `opReleaseLockowner: implement` in the log, on every write). The
   client copes anyway; byte-range locks over the mount are therefore not to be expected.
7. **Residual noise as in spike C:** `._.`, `.DS_Store`, `.hidden`, `.Spotlight-V100`, `Applications`,
   `DCIM` are still requested and answered with `ENOENT`; STATFS still runs before almost every
   operation. After both fixes the complete E2E tree (write 100,000 bytes, read,
   append, rename, symlink, NFD name, unlink, rmdir, two listings, `stat`) takes **~130 ms**.
8. **`umount` without `-f` is still enough**, and the session ends via EOF; since task 8 `close()`
   is limited to ten seconds and reports `Busy` afterwards instead of blocking.
9. **`umount` right after the last write sporadically reports "filesystem busy"**, even though
   nothing is open any more — the NFS client holds the mount for a moment longer. A few hundred
   milliseconds later the same call works. `umount_macos` therefore retries a `Busy` for up
   to 5 s (`UNMOUNT_BUSY_RETRY`) before giving up; a genuinely occupied mount is still
   reported as `Busy`, just 5 s later.
10. **A `umount` can hang in the kernel** (process state `U`, not killable with `SIGKILL`)
   when the NFS server underneath the mount is gone — observed as collateral damage of the stalled mount
   from point 1, once for more than ten minutes. That is why `run_unmount_command` no longer waits
   for the child itself after the `kill`, but hands it to a throwaway thread (`reap`); the caller
   is thereby free again after `UNMOUNT_COMMAND_TIMEOUT` in this case too.

## Reproduction

```bash
mkdir -p /tmp/spike-c-mnt
cargo run -p cryptomator-mount --example spike_macos_dlopen -- fuse-t /tmp/spike-c-mnt &
sleep 5; mount | grep spike-c-mnt; cat /tmp/spike-c-mnt/hello.txt; ls -la /tmp/spike-c-mnt
umount /tmp/spike-c-mnt; wait
tail -f ~/Library/Logs/fuse-t/fuse-t.log   # considerably more talkative with "-o", "debug" in extra_opts
```
