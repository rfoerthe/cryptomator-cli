# Changelog

## Unreleased

### M0 – Scaffold and spikes

- Cargo workspace (`cryptomator-core`, `cryptomator-mount`, `cryptomator-app`, `crypto`), AGPL-3.0-only,
  pinned toolchain, release profile, CI on ubuntu-22.04 and macos-15.
- Spike A (FUSE-T/macFUSE via `dlopen` + `fuser::Session::from_fd`): FUSE-T 1.2.7 is a NO-GO with an
  unmodified fuser 0.18 — the transport works, but fuser writes the macFUSE `fuse_attr` layout while
  FUSE-T parses the Linux one. macFUSE untested (not installed).
  See `docs/superpowers/spikes/2026-09-04-spike-a-fuse-t.md`.
- Spike B (read the desktop keychain entry on macOS): BLOCKED, no desktop entry existed and the ACL
  dialog needs a human. See `docs/superpowers/spikes/2026-09-04-spike-b-keychain.md`.

### M1 – Core crypto (vault format 8)

- `Masterkey`, scrypt KEK derivation, RFC 3394 key wrapping.
- AES-SIV file name encryption and directory id hashing (`FileNameCryptor`).
- File headers and content chunks for both cipher combos (`SIV_GCM`, `SIV_CTRMAC`) behind the
  `Cryptor` / `HeaderCryptor` / `ContentCryptor` facade, including Java-identical size math.
- Streaming `EncryptingWriter` / `DecryptingReader` with Java's always-write-a-final-chunk semantics.
- `masterkey.cryptomator` read/write (byte-identical to Gson output), passphrase change,
  atomic `.tmp` + rename persistence.
- `vault.cryptomator` JWT decoding, signature verification (HS256/384/512) and creation;
  Hub and unknown `kid` values are rejected via `KeyId::require_masterkey_file`.
- `.bkup` backup helper (`attempt_backup`) mirroring cryptofs `BackupHelper`.
- Recovery keys: 4096-word encoding, validation, and password reset from a recovery key.
- CLI: `crypto recovery-key validate --recovery-key-stdin`.
- Java fixture generator (`tools/fixture-gen`) plus eight checked-in reference vaults; integration
  tests unlock every fixture and verify the complete decrypted tree against `expected.json`.

### M2 – Vault metadata

- `settings.json` model and store shared with the desktop app: all fields the app uses plus unknown
  keys preserved, Java defaults, legacy key migration, atomic save (a `create_new`, pid-suffixed
  `settings.json.<pid>.tmp` + rename, so it never collides with the desktop app's `settings.json.tmp`),
  paths for macOS/Linux and the `--settings` / `$CRYPTO_SETTINGS_PATH` overrides.
- Vault references: resolution by id, display name or path; generated ids (base64url of 9 random
  bytes) and `normalize_display_name` following the app's mount-name rules.
- Vault state detection (`LOCKED`, `MISSING`, `VAULT_CONFIG_MISSING`, `ALL_MISSING`, `NEEDS_MIGRATION`) including the automatic
  `masterkey.cryptomator.bkup` restore of `BackupRestorer`.
- `crypto vault create` (config, root dir, `dirid.c9r`, `WELCOME.rtf` inside the encrypted content
  and `IMPORTANT.rtf` in the vault directory next to `vault.cryptomator`), `vault add`,
  `vault remove`, `vault list`, `vault info`, `vault set`.
- `crypto config get|set` for the global settings (`mountService`, `port`, `useKeychain`,
  `keychainProvider`, `debugMode`).
- `crypto password change` (with `.bkup` of the old masterkey file) and `crypto recovery-key show` /
  `recovery-key reset-password`.
- Passphrase sources `--password-stdin` / `--password-file` / `--password-env` / `$CRYPTO_PASSWORD` /
  TTY prompt, NFC normalisation, minimum length and confirmation for new passwords. `password change`
  does not take the new password from `$CRYPTO_PASSWORD`, which holds the current one.
- `crypto vault set --mount-flags` requires the `=` form (`--mount-flags="-ovolname=Secret"`), so a
  forgotten value cannot swallow the next flag.
- Interop: the Java harness verifies vaults created by `crypto` for both cipher combos
  (`cargo test -p crypto --test java_interop -- --ignored`, CI job `interop-java`) and re-verifies the
  checked-in fixtures after `crypto password change` — with the new passphrase accepted and the old
  one rejected.
- Deferred to M4: `settings.json` writes are atomic (tmp + rename) but not locked — the `flock` on
  `settings.json.lock` and the warning about a running desktop app ship with the daemon, which owns
  settings-writer coordination. Until then, close the desktop app before `vault add/remove/set` and
  `config set`.
- Deliberate deviation from the desktop app: a `settings.json` that cannot be parsed is reported as
  an error instead of being silently replaced with defaults, so a broken or foreign file never costs
  the user their vault list.

### M3 – File system and mount-less operations

- `cryptomator_core::fs`: the complete cleartext layer of cryptofs, ported without a mount.
  - `CleartextPath` (NFC-normalised, always absolute), `CiphertextFilePath` and the `d/XX/YYYY…`
    path mapper with its directory cache and prefix invalidation on rename.
  - `dir_id.rs` / `long_names.rs`: directory ids incl. `dirid.c9r` backups, and `.c9s` shortening
    with `name.c9s` inflation.
  - `dir_stream.rs`: the listing pipeline of `CryptoDirectoryStream` — `.c9r`/`.c9s` nodes, name
    decryption with narrowing, `BrokenDirectoryFilter`, `.c9u` (Hub) nodes and sync-conflict
    resolution that renames a conflicting copy to `name (1).ext` like the desktop app.
  - `open_file.rs` / `open_files.rs`: chunk cache (5 chunks), dirty tracking,
    `read_at`/`write_at`/`truncate`/`flush`/`sync`, sparse zero-fill beyond EOF, the open-file
    registry and the two-phase move of open files.
  - `symlinks.rs`, `attrs.rs`, `events.rs`, `stats.rs`: symlink create/read/resolve, file
    attributes, an event sink for recoverable anomalies, and access/byte statistics.
  - `crypto_fs.rs`: the `CryptoFs` facade (`open`, `read_dir`, `metadata`, `symlink_metadata`,
    `open_file`, `read_file`, `write_file`, `copy_to_writer`, `write_from_reader`, `create_dir`,
    `create_dir_all`, `create_symlink`, `read_link`, `delete`, `delete_recursive`, `rename`,
    `close`), plus `capabilities.rs` (`determine_supported_cleartext_file_name_length` probe) and
    `name_decryptor.rs` (`decrypt_filename`).
- CLI: `crypto fs ls|tree|cat|get|put|rm|mkdir|mv` for mount-less access to a registered `LOCKED`
  vault, and `crypto name decrypt|locate` to translate between cleartext and ciphertext names.
  `fs tree --json --hash` prints the same manifest shape as the Java fixture generator, sorted per
  directory by UTF-16 code units so it matches Java's `Path.toString()` order above the BMP.
- `crypto fs put` is non-destructive: the content is encrypted into a sibling temp file
  (`<name>.<pid>.tmp` in the destination directory) and only a completely written temp file is
  renamed over the destination. A reader that fails half way through no longer truncates the old
  file (with `--force`) or leaves a partial one that looks complete (without it); the temp file is
  removed on every failure. Without `--force` an existing destination is rejected before the first
  byte is read.
- Vault ids that start with `-` (base64url ids do, about one in 32) work as command arguments:
  every vault reference accepts leading dashes instead of being parsed as an unknown flag. `--`
  remains the general escape hatch.
- Interop is now bidirectional: besides the vaults `crypto` creates, a tree that `CryptoFs` writes
  (nesting, 200-character names, unicode incl. NFD input and emoji, sizes at the chunk boundaries
  32767/32768/32769/65536, symlinks, renames to and from shortened names for files, directories and
  symlinks, a truncate to a non-boundary size, a copy and an overwrite) is opened by the real
  cryptofs, and its manifest must equal `crypto fs tree --json --hash` entry for entry
  (`cargo test -p crypto --test java_interop -- --ignored`).
- Deliberate deviations from cryptofs, all of them chosen for a short-lived CLI process:
  1. Relative symlink targets resolve against the link's parent directory (POSIX semantics);
     cryptofs resolves them against the vault root.
  2. A vault opened read-only never resolves sync conflicts on disk. cryptofs renames the
     conflicting node anyway; `crypto` reports it as an event and leaves it out of the listing.
  3. ~~The directory cache has no 20 s expiry~~ — resolved in M4: both the directory mapping cache
     and the directory id cache expire 20 s after they were loaded (cryptofs' `expireAfterWrite`;
     the id cache has no expiry in cryptofs, but a mount that runs for days has to notice a
     `dir.c9r` a sync client rewrote).
  4. `fs mv` never moves *into* an existing directory: the destination is always the complete new
     path, so a typo renames instead of silently filing the source away somewhere.
  5. `.c9s` node directories for shortened names are only created when a file is opened for
     writing, so a failed read never leaves an empty node directory behind.
- Two further rulings the code carries: `dirid.c9r` is never swept when a directory delete fails
  (Java's `CiphertextDirectoryDeleter` removes it with the other leftovers and leaves a surviving
  directory without its dir id backup), and `bytes_written` counts only the caller's bytes, not the
  zero-filled gap of a sparse write.
- Not in M3 (the spec assigns them to M4): cache expiry (now shipped, see M4), `.c9u`/`FileIsInUseEvent` creation
  (Hub only) and `fs` access to a mounted vault. `fs`/`name` require state `LOCKED` as recorded in
  the vault directory; a *running* mount cannot be detected yet, and the README says so instead of
  promising a refusal that does not exist.

### M4 – FUSE mount and the vault daemon

- A vault can be mounted. `cryptomator-mount` carries the whole mount layer: the service API
  (`api.rs`), the registry with the Java class names and the CLI aliases (`registry.rs`), the
  mount-flag parser of `AbstractMountBuilder.setMountFlags` (`flags.rs`), the macOS NFD ↔ vault NFC
  name transcoder (`transcoder.rs`), the mount-table reader (`mounttab.rs`) and, under `fuse/`, the
  file system itself: `ops.rs` (the vault operations, inode and handle tables, errno mapping,
  AppleDouble handling), `adapter.rs` (`impl fuser::Filesystem` on top of them), `session.rs` (the
  session on a thread of its own, unmount and join) and the four providers.
- Three real back ends and one for tests: **Linux FUSE** (`fusermount3`, `-oauto_unmount -ouid
  -ogid -oattr_timeout=5`), **macFUSE** and **FUSE-T** (both `dlopen`ed through
  `fuse_mount_compat25`, the fd handed to `fuser::Session::from_fd`), and a **null mounter** that
  mounts nothing and only exists when `$CRYPTO_ENABLE_NULL_MOUNTER=1` is set, so the daemon, the
  signals and the auto-lock can be tested without a driver.
- `vendor/fuser` is fuser 0.18 with a patch this port needs: the kernel ABI became a **runtime**
  choice (`Config::abi`, `KernelAbi::{Native, Linux}`) instead of a `#[cfg(target_os)]` decision, so
  one binary can write the Linux struct layouts FUSE-T expects and the macFUSE layouts macFUSE
  expects. Spike A had found that layout to be the reason FUSE-T never mounted with stock fuser;
  Spike C proved the switch end to end. Two transport fixes came with the end-to-end test: requests
  that FUSE-T coalesces into one read are split instead of being dropped, and a zero-length read on
  a socket is an end of stream rather than an error.
- FUSE-T serves an NFS mount, which brings its own rules: no extended attributes (`-ononamedattr`
  is always appended), no `-obackend=smb` (1.2.7 ships only the NFS helper), and the `._<name>`
  AppleDouble side cars macOS' NFS client writes next to every node are refused with `EPERM` —
  otherwise a vault fills up with one encrypted `._x` per file, directory and symlink. macFUSE keeps
  those away from userspace itself. Both macOS back ends sweep `._*` and `.DS_Store` out of a
  directory before removing it, like the desktop app's `deleteAppleDoubleFiles`.
- A graceful unmount retries for five seconds while the volume is merely settling, a forced one does
  not, and an unmount that hangs is left to a reaping thread instead of blocking the daemon.
- The mount end-to-end test (`crates/cryptomator-mount/tests/mount_e2e.rs`, `CRYPTO_E2E_MOUNT=1
  cargo test -p cryptomator-mount --test mount_e2e -- --ignored`) writes 100 KB across chunk
  boundaries, appends, renames, symlinks, an NFD name and a read-only mount through a real driver
  and checks the result in the vault afterwards. It runs in CI on `ubuntu-22.04` with `fuse3`, and
  advisory (`continue-on-error`) on `macos-15` with the FUSE-T cask.
- CLI: `crypto unlock <VAULT>` mounts a vault in a detached per-vault daemon and `crypto lock`
  takes it down again. The password is read, normalised and turned into the vault key in the
  `crypto unlock` process; the key reaches the daemon as the first message on its 0600 control
  socket, so it never appears in `argv`, in the environment or in a file. The daemon is spawned
  with `setsid(2)`, its working directory at `/`, `$CRYPTO_PASSWORD` removed and stdout/stderr
  appended to `<state dir>/<id>.log`; a failed unlock prints the last 20 lines of that log.
  `--foreground` runs the same daemon in the calling process instead, where SIGINT and SIGTERM lock
  the vault.
- `crypto lock <VAULT>…` asks the daemon over its socket, `--force` unmounts a busy volume, and
  `--all` locks every unlocked vault (`{"locked": [ids]}`, plus `"failed"` when something refused;
  the first failure decides the exit code and the remaining vaults are still locked). A volume a
  crashed daemon left behind is taken down by mount point through the mount service that made it,
  and its leftover state files are removed.
- Global `--state-dir <PATH>` / `$CRYPTO_STATE_DIR` for the directory holding the socket, pid, run
  info and log of every unlocked vault. Exit codes `6` (mount failed), `7` (unmount failed) and
  `10` (daemon unreachable) join the existing table.
- `crypto fs …` now refuses a vault that a daemon has unlocked or a crashed daemon left mounted
  (exit `5`), reading included — the M3 caveat that a running mount could not be detected is
  resolved. The mount holds state that is not on disk yet, and two writers on one vault directory
  would corrupt each other's ciphertext.
- `maxCleartextFilenameLength` is probed on the first unlock of a writable vault and written back to
  `settings.json`; a read-only unlock cannot probe (the probe writes) and takes the cryptofs default.
- CLI: `crypto status [VAULT]` prints the registered vaults with their runtime state and mount point
  (an array, or that vault's object with an argument). It reads `settings.json` and the state
  directory only — no request reaches a daemon — so it answers for locked, unlocked and crashed
  vaults alike, and cleans up the state files a crashed daemon left behind on the way.
- CLI: `crypto stats <VAULT>` and `crypto events <VAULT>` ask the vault's daemon over its socket and
  therefore need an unlocked vault (exit `5` otherwise). Both take `--follow` — `stats` samples every
  `--interval` seconds, `events` streams as they happen and continues after `--since <SEQ>` — print a
  notice on standard error, stop on Ctrl-C with exit `0`, and emit NDJSON with `--json`.
- CLI: `crypto mounters [--all]` lists the mount services of this build with their alias, Java class
  name, whether they work here and their capabilities.
- `cli.json` next to `settings.json` is now readable and writable through `crypto config get|set`:
  `mountPointsDir` (absolutized), `defaultMounter` (alias or class name, `default` clears),
  `logLevel` and `forceUnmountOnSignalAfterSecs`. `crypto config get` prints the keys of both files
  in one flat object, and `config get mountPointsDir` reports the effective value including the
  platform default.
- `DaemonClient::set_read_timeout` and `stream_until` make a follow stream interruptible: a read
  that times out becomes an idle callback instead of a blocked process, and `protocol::read_line_into`
  keeps a message that arrives split across such a timeout from being lost.
- A daemon stops on SIGINT, SIGTERM **and SIGHUP** — detached as well as in `--foreground` — and runs
  the same teardown a `crypto lock` runs: graceful unmount, then, after
  `forceUnmountOnSignalAfterSecs`, a forced one, then exit `0` with the state files removed. A volume
  that survives even that (or a mounter without a forced unmount) makes the daemon exit `7` and keep
  its run info, so `crypto status` reports `STALE_MOUNT` and `crypto lock --force` can address the
  volume it left behind.
- Idle auto-lock (`crypto vault set <VAULT> --auto-lock-idle <SECONDS>`) works the same way in the
  foreground as it does detached: the daemon unmounts itself and ends with exit `0`.
- `--reveal` and `actionAfterUnlock=REVEAL` now really open the mount point (`open` / `xdg-open`),
  detached and best effort; `$CRYPTO_REVEAL_CMD` replaces the command, which is also how the hook is
  tested without a file manager appearing.
- `crypto unlock` no longer waits forever for a daemon whose mount hangs: the `unlock` call has a
  70 second deadline, after which the daemon is asked to stop (SIGTERM before SIGKILL, so its own
  unmount still runs) and the command fails with exit `6` pointing at the daemon's log.
- `crypto stats --follow` and `crypto events --follow` end with exit `0` when the vault is locked
  underneath them after at least one line was printed; a daemon that is unreachable from the start
  is still exit `10`.
- A closed pipe is a successful end for every command, not just for the follow streams:
  `crypto vault list | head -3` exits `0` and prints nothing about it.
- Three core changes a mount that runs for days needs: the directory mapping and directory id
  caches expire 20 s after a load (cryptofs' `CiphertextDirCache.MAX_CACHE_AGE`, so foreign changes
  to `dir.c9r` are picked up within 40 s at the latest -- the two caches expire independently, and a
  mapping re-cached from a still-fresh id can carry it 20 s further -- and the M3 deviation "no
  dir-cache expiry" is resolved), dropping a `CryptoFs` without calling `close` flushes its open
  files instead of losing the buffered cleartext, and closing a file handle flushes it with only
  that file locked, so one slow `close` no longer blocks every other `open`, `rename` or `delete`.
  A directory id is also loaded under the cache lock now, so two threads racing on a missing
  `dir.c9r` cannot invent two different ids. Both caches now share one `ExpiringMap` whose pruning
  is amortised (a scan only when the map has roughly doubled or a whole TTL has passed since the
  last one), so a cache miss during a hot `find`, backup run or Spotlight index no longer pays for
  an O(n) scan that finds nothing to remove.
- **Fixed: `crypto unlock` answered before the volume was there.** FUSE-T mounts asynchronously --
  its helper drives the `mount -t nfs` only after the mount call has returned -- so for roughly
  200 ms the mount point was still the bare directory underneath, and everything a script wrote
  there landed beside the vault, with no error and no trace. The daemon now waits for the mount
  point to appear in the system mount table (`mounttab::is_mountpoint`, every 50 ms for at most
  10 s) before it writes the run info and answers; a volume that never appears fails the unlock
  with `MOUNT_FAILED` after the mount has been released, exactly like any other mount failure. The
  wait is skipped for services whose volumes never reach the mount table
  (`MountService::appears_in_mount_table`, `false` only for the null mounter). `crypto unlock V &&
  cp file $MP/` is safe now; `crypto unlock --mounter`'s help no longer advertises the `webdav`
  alias, which has no back end before M5, and names `null` instead.
- Documentation: `docs/daemon-protocol.md` describes the wire protocol (handshake, every request and
  its fields, the error codes and the exit codes they map to, follow streams and `nextSeq`, the
  state files and the order they are written in, stale detection, and how the key travels), and the
  README gained a "Mounting" chapter with the prerequisites per platform, the FUSE-T limits, the
  state directory and an exit-code table.

- After the final review: the vendored fuser's `ChannelSender::send` loops over short writes
  instead of assuming an atomic `writev` (a signal on the FUSE thread could truncate a reply on
  FUSE-T's stream socket and desynchronise the channel for good); the state directory's
  symlink/owner check now guards every *read* path as well (`status`, `lock`, `stats`, `events`,
  `fs` -- a foreign directory on the shared default locations could otherwise feed the CLI a forged
  run info and a socket that answers); an inode a `rename` overwrote no longer resolves to the file
  that took its name (a `setattr(size)` on it would have truncated the wrong file); the loser of a
  daemon start-up race takes back only its *own* pid file; `create` answers `EROFS` before it looks
  at AppleDouble names; a `readdir` batch whose first entry does not fit answers `EINVAL` instead
  of an empty listing the kernel reads as the end of the directory; the state files' temporary file
  is created with `O_EXCL`; and the vault key no longer passes through a plain `[u8; 64]` on its
  way into `Masterkey` (`Masterkey::from_zeroizing`).
- The declared MSRV is **1.89**, not 1.85: `aes 0.9.3` needs 1.89 and `libloading 0.9` needs 1.88,
  both since M1. The workspace's own code is still 1.85-clean; only the dependency set is not.
- Documented: `-oallow_other` hands every local user full access to the decrypted vault unless
  `-odefault_permissions` is passed with it.

#### Decisions taken along the way

*Mounting*

- The kernel ABI is a **runtime** switch in the vendored fuser fork, not a compile-time feature: one
  binary serves macFUSE and FUSE-T, at the price of a larger patch than a `cfg` flag would be.
- FUSE-T runs on its NFS backend; `-obackend=smb` is not passed on. A read-only mount on a service
  without a `READ_ONLY` capability gets `-oro` appended rather than having `--read-only` silently
  dropped, which is what the desktop app does.
- Refusing AppleDouble side cars is decided by the back end (on for FUSE-T, off for macFUSE), while
  the `._*`/`.DS_Store` sweep before `rmdir` is decided by the platform — both macOS back ends do
  it, whatever the mount flags say, because Finder leaves those files behind either way.
- `chmod` is a successful no-op: a vault stores no permission bits, and failing the call would break
  ordinary copies.
- The null mounter is test-only and hidden behind an environment variable, so a normal build cannot
  be talked into "mounting" nothing.

*Daemon and protocol*

- The daemon is plain `std`: threads, a `UnixListener` and condition variables. tokio arrives with
  WebDAV in M5, where hyper needs one; until then it would be a dependency without a job.
- The vault key travels over the `0600` control socket as the first message, not over an inherited
  file descriptor. The trust boundary is the same (both need the same uid) and it keeps the key out
  of `argv`, the environment and any file.
- The daemon publishes its state files as pid → socket → run info. A bound socket answers before
  `accept` runs, so the detection cannot see a live daemon as a crashed one; the run info comes last
  because only then is there a mount point to name.
- `nextSeq` in an `events` answer is the newest event's own `seq`, and `since` is exclusive
  (`seq > since`), so a client passes the value straight back to continue where it stopped.
- `inUse` in a `status` answer means the access counters grew during the last sampling interval, and
  one operation lock serialises mount and unmount against the shutdown sequence.

*Command line*

- `crypto fs …` and `crypto name …` refuse a vault that is `UNLOCKED` or `STALE_MOUNT` with exit
  `5`, reading included: the mount may hold changes that are not on disk yet, and two writers on one
  vault directory would corrupt each other's ciphertext.
- `crypto status <VAULT> --json` prints that vault's object, without an argument an array. A
  `--follow` stream ends with exit `0` once it has printed at least one line — a lock underneath it
  or a closed pipe is a normal end — while a daemon that was already gone is exit `10`.
- `crypto lock` takes its vaults as ordinary positionals, so a vault id starting with `-` needs the
  usual `--` separator.

*Core*

- The two directory caches share one `ExpiringMap` with amortised pruning and no fixed size cap:
  expiry plus pruning on a miss bounds them, and a cap would only add a second eviction rule to
  reason about.
- An event sink must not re-enter the file system it belongs to; the daemon's sink only appends to
  its ring buffer.

#### Follow-ups from earlier milestones

- **Resolved:** the directory caches now expire (M3 deviation 3), and `fs`/`name` now really detect
  a running mount instead of the README explaining that they cannot (M3).
- **Still open:** `.c9u`/`FileIsInUseEvent` creation stays unimplemented — those markers exist only
  with a Hub owner and are ignored on listing, by design. The `flock` on `settings.json.lock` and the
  warning about a running desktop app that M2 deferred to "the milestone with the daemon" did **not**
  ship with M4 either; the atomic tmp + rename write was all there was until M5 closed it (below).

#### Known limitations and follow-ups

- **macFUSE is unverified.** It has never been installed on a machine this port was tested on, so
  that provider has never mounted anything. FUSE-T 1.2.7 and Linux `fuse3` are covered by the
  end-to-end test.
- **A Finder copy of a file carrying extended attributes or a resource fork onto a FUSE-T mount has
  not been tried.** That is the case where refusing the AppleDouble side cars could surface as a
  failed copy; if it does, the refusal has to become a mount flag instead of a default.
- **Coexistence with the Cryptomator desktop app** — unlocking in one and looking at the vault in the
  other — is a manual check nobody has run.
- The daemon reads its socket through a `BufReader`, whose internal buffer keeps the base64 vault key
  of the `unlock` line until later traffic overwrites it. Every decoded copy is wiped; the buffer is
  not, and M5 did not change that either.
- `crypto status` does not distinguish the daemon's `STARTING` phase: for the few milliseconds
  between the pid file and the run info a vault shows as `UNLOCKED` with a null mount point.
- The state files are named after a sanitised vault id, so two *hand-written* ids in `settings.json`
  that differ only in characters outside `[A-Za-z0-9_-]` would share them. Generated ids are
  base64url and never collide.
- `CryptoFs::open` still does its I/O while holding the open-file registry lock, so one slow `open`
  delays the others. Pre-existing since M3, unchanged here.
- The branch that puts a mount back into the daemon's state when a forced unmount is asked of a
  service that has none is not covered by a test — no mount service in this build lacks a forced
  unmount.
- `crypto unlock --port` arrived with M5 and `--store-password` with M6 (both below).
- The unlock timeouts are compiled in: 60 seconds for the daemon to receive an `unlock`, 70 for the
  whole call. A mount slower than that needs a rebuild, not a setting.

### M5 – WebDAV

- **`cryptomator-mount::webdav`**: a `dav_server::fs::DavFileSystem` over `CryptoFs`
  (`CryptoDavFs`/`CryptoDavFile`), a loopback HTTP server on hyper 1 with a tokio runtime of its
  own, and the three mount services Cryptomator ships — `FallbackMounter` (the URL, nothing else),
  `MacAppleScriptMounter` (`osascript -e 'mount volume …'`, a volume under `/Volumes`) and
  `LinuxGioMounter` (`gio mount dav://…`, a gvfs volume) — with the Java class names, priorities,
  capabilities and default ports of webdav-nio-adapter 3.0.2.
- **`crypto unlock --mounter webdav|webdav-applescript|webdav-gio [--port <N>]`**: the daemon serves
  the vault over HTTP on the loopback interface and answers with a URL
  (`http://127.0.0.1:<port>/<vault id>`) or, for the two OS mounters, with the path of the volume
  they mounted. `crypto status`, the run info and `--json`'s `mountpoint` carry the same string, and
  the unlock prints a one-line hint for mounting a URL by hand.
- The desktop app's **port rule**: `--port` wins (including `--port 0` for any free port), else the
  vault's own `port` when the vault names a `mountService`, else `settings.json`'s `port` (42427).
  `crypto vault set <VAULT> --port <N>` stores one. A port that is taken fails the unlock with exit
  `6` and names both ways out. New in the protocol: `Request::Unlock.port` (absent reads as `null`).
- **`webdavBind` in `cli.json`** (default `127.0.0.1`): the address the server binds. Only a
  loopback address is accepted — the server has no authentication — unless
  `CRYPTO_WEBDAV_ALLOW_NONLOOPBACK=1` says otherwise; an unusable value fails a WebDAV unlock with
  exit `6` naming the key and leaves a FUSE unlock alone.
- **Java parity in the servlet's behaviour**: symbolic links are invisible (neither listed nor
  addressable), `Range`/`If-Range` GETs, class-2 locking (`MemLs`, so Finder and `gio` can lock),
  `414` for a name the vault cannot store, NFC path normalisation, and no `quota-*` on macOS 15.4
  and newer, where reporting it delays the mount by 90 seconds.
- **`process.rs`**: the subprocess helpers (`run_command`, `run_unmount_command`, `probe_command`,
  `wait_for_exit`) moved out of `fuse/mount.rs` and are now shared with the WebDAV OS mounters —
  every external command is an argument vector, never a shell string.
- **Tests and CI**: `webdav_http.rs` drives the real server over HTTP in the ordinary `cargo test`
  run (PROPFIND, ranged GET, PUT, MKCOL, MOVE, COPY, DELETE, LOCK/UNLOCK, the port-in-use and
  shutdown paths). `webdav_e2e.rs` and the WebDAV case in `cli_daemon.rs` mount a *real* volume and
  need `CRYPTO_E2E_WEBDAV=1`; the new CI jobs `webdav-e2e-macos` (advisory) and `webdav-e2e-linux`
  (`curl` against the server) run them.
- **Resolved (deferred in M2, still open after M4):** every `settings.json` write happens under an
  exclusive `flock` on `settings.json.lock` — an empty 0600 file next to `settings.json`, created
  once and never removed. `SettingsStore::update` holds it across load, change and rename, so two
  `crypto` processes cannot lose each other's changes; a lock another process holds is retried for
  five seconds (50 ms apart) and then reported as `… is locked by another process` (exit `1`).
- The desktop app takes no lock, so `crypto` warns instead: `vault create/add/remove/set`,
  `config set` and `unlock` print a line to stderr when the app answers on its IPC socket
  (`ipc.socket` next to `settings.json`, per its `-Dcryptomator.ipcSocketPath` packaging value;
  `$CRYPTO_DESKTOP_IPC_SOCKET` overrides it, and the probe gives up after 200 ms). Read-only
  commands stay silent, and a socket file nobody listens on does not count as a running app.
- **Resolved (deferred in M4):** `crypto password change` and `crypto recovery-key show` /
  `recovery-key reset-password` no longer accept an *unlocked* vault. The runtime check
  (`VaultRegistry::require_locked`) moved out of `fs`/`unlock` and into `commands::locked_vault`, so
  every command that resolves a vault that way refuses a vault a daemon is serving — and one a
  crashed daemon left mounted — with the same exit `5` wording. `recovery-key validate`, which takes
  no vault, is unaffected.
- The vendored fuser sends a reply that goes out in one piece without copying the slice list: the
  first `writev` is made against the caller's own `IoSlice`s and only a genuinely short write
  allocates the owned copy `IoSlice::advance_slices` needs. `/dev/fuse` always takes the fast path.
  An ops-level test now pins that a `rename` over a kernel-held inode takes the name away from it.

#### Decisions taken along the way

*The bridge into the vault*

- `DavFileSystem` is async, `CryptoFs` is not, so **every core call runs on tokio's blocking pool**
  (two worker threads, up to 64 blocking threads) — never `block_in_place`, which would stall the
  runtime's own worker.
- **Stopping the server drops its runtime** rather than abandoning it, and waits (up to 65 s) for
  the blocking calls still in flight. A WebDAV write is flushed when the file handle is dropped, so
  a shutdown that did not wait could lose the last bytes of a copy. The daemon therefore stops the
  mount off the signal path.
- **`dav-server` is built without default features**: its `hyper` feature only serves `warp-compat`,
  the server speaks hyper itself, and neither `localfs` nor `memfs` is compiled in. HTTP/1 only.
- **The health probe is a `GET` on the context path.** `2xx`, `3xx` and `405` mean the server is up
  — there is no directory browsing, exactly as in Java — `404` and `5xx` do not.
- **A zero-fill gap is bounded at 256 MiB** and answered with `413` beyond that. Java and the FUSE
  adapter zero-fill without a limit; there a syscall asks for it, here an unauthenticated local HTTP
  request does, and nothing else bounds it.
- **A `Content-Range` PUT never truncates.** `truncate` is what `dav-server` asked for and nothing
  more, so a partial update writes into the file instead of wiping it first.
- **A name that is too long is `414`**, checked by the adapter itself: `CryptoFs` reports it as
  `InvalidInput`, which is indistinguishable from any other bad input.
- **Requests are normalised to NFC and answers stay NFC.** Cryptomator rewrites multistatus answers
  to NFD for the `WebDAVFS` user agent; the user agent is not visible from inside a `DavFileSystem`.

*Mounting and the command line*

- **Read-only follows the file system.** The WebDAV services serve the very `CryptoFs` the daemon
  opened, so `MountService::read_only_follows_file_system()` says so and the mounter neither demands
  a `READ_ONLY` capability nor appends `-oro`.
- **The bind address is process-wide.** One daemon serves one vault, so `webdavBind` is applied once
  from `cli.json` instead of being threaded through the builder chain — and it is applied inside
  `unlock`, where an unusable value is a failed mount (exit `6`) rather than a daemon that never
  answers.
- **A stale mount is always a path.** A run info whose mount point is a URL is never a stale mount:
  that server died with its daemon, so there is nothing left to take down.
- **`--volume-name` is refused** by a service without the `VOLUME_NAME` capability (Java ignores it
  silently), and **`--reveal` opens nothing for a URL** — a browser is not the vault, and
  `$CRYPTO_REVEAL_CMD` does not change that.
- **No keychain entry before the AppleScript mount.** Java stores an anonymous internet password
  first so macOS does not ask about the unencrypted connection. M6 brought the vault keychain but
  deliberately not this: it is an *internet* password for the WebDAV server, unrelated to vault
  passphrases, and it is deferred to M8. macOS therefore still asks.
- **The OS mounts unmount themselves when dropped**, blocking and logging failures like their FUSE
  siblings, so a dropped mount cannot strand a Finder volume.

#### Deliberate deviations from webdav-nio-adapter 3.0.2

- **No reference-counted shared server** (`WebDavServerManager`): one daemon, one vault, one server,
  so two unlocked vaults need two ports.
- `LinuxGioMounter.isSupported()` probes **`gio --version`**; Java's
  `new ProcessBuilder("test", " \`command -v gio\`")` hands `/usr/bin/test` one non-empty string and
  therefore always succeeds, whatever is installed.
- `dav-server` answers **`DAV: 1,2,3,sabredav-partialupdate`** where Java answers `DAV: 1, 2`. The
  extra classes are what the library really implements; no client of ours needs fewer.
- A `MacAppleScriptMounter` mount whose mount point cannot be found in the mount table **fails**,
  like Java's — but the error says so and names the URL, because the volume may well be mounted.
- The zero-fill bound and the refused `--volume-name` above.

#### Known limitations and follow-ups

- **`webdav-gio` has never mounted anything.** No machine this port was tested on had a gvfs session
  and hosted CI runners have none, so the Linux OS mounter rests on its unit tests and the HTTP-level
  end-to-end check alone.
- **The macOS end-to-end mount needs a GUI session.** `osascript -e 'mount volume …'` talks to
  Finder, so the `webdav-e2e-macos` job is advisory (`continue-on-error`) and skips where the runner
  has no window server. It was run by hand on a Mac instead.
- **macFUSE is still unverified**, and **coexistence with the Cryptomator desktop app** is still a
  manual check nobody has run (both carried over from M4).
- `crypto lock --force` cannot be used on a `webdav` or `webdav-gio` mount: neither service
  advertises `UNMOUNT_FORCED`, exactly as in Java. The graceful `crypto lock` always works.
- The `DAV:` header deviation above has not been tried against every WebDAV client; Finder, `gio`
  and `curl` are the ones that were.
- The daemon still reads its socket through a `BufReader` that keeps the base64 vault key of the
  `unlock` line until later traffic overwrites it. Every decoded copy is wiped; the buffer is not
  (carried over from M4).
- `Request::Shutdown` is implemented and documented but no CLI command sends it — `lock` unmounts
  first, and a stale mount has no daemon left to ask.
- The mounter alias table exists twice, in `cryptomator-mount::registry` and in
  `cryptomator_app::mounters`, kept in step by a parity test rather than by one owner.
- The timeouts are still compiled in: 60 seconds for the daemon to receive an `unlock`, 70 for the
  whole call, and 10 for the mount table to show the volume.
- `--store-password` and the keychain (`password store`/`forget`) were carried into M6 and are
  delivered there (below). The keychain item that would stop macOS asking about the unencrypted
  connection is a separate *internet* password and moved on to M8.

### M6 – Keychain

- **`cryptomator_app::keychain`**: the Rust twin of
  `org.cryptomator.integrations.keychain.KeychainAccessProvider` (integrations-api 1.9.0) —
  `store`, `load`, `delete`, `change`, `is_supported`, `is_locked`, `java_class_name`,
  `display_name`, `priority`. `load` answers `None` where Java answers `null`; `delete`/`change`
  answer "was there an entry?" as a `bool`, like `MacKeychain.deletePassword`.
- **macOS**: the login keychain through `security-framework` 3.7 — generic password, service
  `Cryptomator` (override `$CRYPTO_KEYCHAIN_SERVICE`, the desktop app's
  `cryptomator.integrationsMac.keychainServiceName`), account = the vault id. `errSecItemNotFound`
  (-25300) is "nothing stored", not a failure. `kSecAttrLabel` is set explicitly, because
  `SecItemAdd` leaves it empty and a nameless row in Keychain Access is what the label is there to
  avoid.
- **macOS legacy items are migrated on read.** Cryptomator once wrote items under the service name
  `"Cryptomator\0"` (a trailing NUL, `MacKeychain.tryMigratePassword`). When nothing is found under
  the current service, `crypto` looks under `<service>\0` through the legacy `SecKeychain…` API —
  the only one that can express a NUL in a service name — and moves a hit across.
- **Linux**: the FreeDesktop Secret Service through `secret-service` 5.2 (blocking API, `zbus`,
  pure-Rust crypto) — the default collection with a `login` fallback, item label `Cryptomator`,
  attributes `{Vault, Name}`, and a lookup by `Vault` alone so a renamed vault keeps its password.
  `GnomeKeyringKeychainAccess` is the same backend without `Name`, and it is the default on Linux
  because `Settings.DEFAULT_KEYCHAIN_PROVIDER` picks it. `KDEWalletKeychainAccess` exists only to
  report itself unusable and point at `secret-service`, which KWallet's own bridge serves.
- **Provider selection follows `KeychainModule.provideKeychainAccessProvider`**: nothing when
  `useKeychain` is off, otherwise the supported provider whose class name matches
  `keychainProvider`, otherwise the highest-priority supported one. Every `is_supported()` probe
  runs under a 5-second budget, so choosing a provider cannot cost 30 seconds per candidate.
- **Password sources gained two steps**: `--password-keychain` (the keychain and nothing else,
  checked ahead of every other source; a missing entry is exit `8`) and an implicit keychain lookup
  between `$CRYPTO_PASSWORD` and the prompt. `--no-keychain` removes the implicit step for one run
  and makes `--password-keychain` exit `8`.
- **New commands and flags**: `crypto password store|forget <VAULT>`, `crypto keychain test`,
  `crypto unlock --store-password|--no-store-password`, `crypto vault create --store-password`,
  `crypto vault remove --forget-password`, and `crypto config set keychainProvider` with the
  aliases `macos`, `touchid`, `secret-service`, `gnome-keyring`, `kde` and `kwallet` (an alias is
  stored as the Java class name, so the desktop app keeps reading its own setting).
- `password store` **verifies the passphrase against the masterkey file before saving it**; an
  unverified password in the keychain would break every later unlock silently.
- `password change` and `recovery-key reset-password` **carry a stored password along**, like
  `KeychainManager.changePassphrase`: only when one is stored, and a keychain that refuses is a
  warning rather than a failed password change.
- **Exit code `8` is live**: no usable provider, `--no-keychain`/`useKeychain false` on a keychain
  command, a locked keyring, a 30-second timeout, or `--password-keychain` with nothing stored.
- **The CLI installs a logger**, so what the library reports through `log::warn!` reaches standard
  error as `warning: …`: a provider whose probe did not answer, a Secret Service item that could
  not be cleaned up, a `keychain test` entry that may have been left behind. It is a *delegating*
  logger — `crypto unlock --foreground` runs a daemon in the same process, and `log` accepts one
  logger per process, so the daemon's log file is swapped in behind the same handle instead of
  losing the race (`daemon::logging`).
- **`$CRYPTO_KEYCHAIN_FAKE` announces itself** once per run, naming the file the passphrases sit in
  in the clear. It stays enabled in release builds — the CLI tests run the shipped binary — so
  saying so is what keeps it a test switch.
- **Every keychain call runs on a worker thread with a 30-second `recv_timeout`**, so a macOS ACL
  dialog nobody answers ends the command instead of hanging it (spike B). The worker is detached
  rather than cancelled — a thread blocked in `securityd` cannot be interrupted — and it holds its
  own end of a one-shot channel, so a late answer can never reach a later call.
- **Tests**: a file-backed fake keychain behind `$CRYPTO_KEYCHAIN_FAKE` covers every CLI flow on
  every OS, and while it is set it is the *only* provider, so no test can reach a developer's real
  keychain. The real keychain is touched only by `crates/cryptomator-app/tests/keychain_e2e.rs`,
  which is `#[ignore]`d *and* gated on `CRYPTO_E2E_KEYCHAIN=1`, isolates itself under the service
  name `crypto-e2e-<pid>`, and skips rather than hangs when a dialog appears. New CI jobs
  `keychain-e2e-linux` (gnome-keyring under `dbus-run-session`, plus a `secret-tool` check of the
  raw attribute names) and `keychain-e2e-macos`, both `continue-on-error`.
- **Follow-ups from M5**: `host_header_allowed` is re-exported from `webdav`, a `Host` header with
  an empty port (`localhost:`) is refused, and `DavFile::seek` has a test for seeking before the
  start of the file.

#### Decisions taken along the way

- **`$CRYPTO_PASSWORD` outranks the implicit keychain step.** It is a source a script sets on
  purpose and it can never make the operating system open a dialog; a keychain lookup can.
  `--password-keychain`, being explicit, outranks everything including `$CRYPTO_PASSWORD`.
- **`TouchIdKeychainAccess` is not a provider of its own.** It and `MacSystemKeychainAccess`
  address the same generic-password items — only `requireOsAuthentication` differs, and the CLI
  cannot set it — so a `settings.json` naming the Touch-ID provider is served by the macOS backend.
- **`change()` updates the item in place instead of Java's delete-and-store.** Deleting an entry
  and writing a new one would drop the macOS ACL with it, and the user would be asked to approve
  `crypto` all over again. `SecItemUpdate` with a label-less query keeps the ACL and also updates
  an item that lives under the desktop app's label rather than ours.
- **The macOS label is the vault's display name** (its id when it has none), where the desktop app
  labels every item `Cryptomator`. The label is the column Keychain Access shows; the item is
  addressed by service and account, so the two programs still find each other's entries.
- **`store` on Linux removes superseded items.** `replace = true` only replaces an item whose
  attribute set is *identical*, and `Name` is part of that set, so a renamed vault would otherwise
  end up with two items carrying the same `Vault` and `load` would pick one at random.
- **A missing keychain entry is never an error in the implicit step** — the prompt takes over —
  but a locked keyring, a refused prompt, a timeout or a backend failure are, because silently
  asking for a password the machine already has stored would hide a real problem.
- **A keychain failure after the fact is a warning, not an exit code**: `--store-password` after a
  successful mount, and the entry update after `password change`/`recovery-key reset-password`.
  The mount stands and the new passphrase is already on disk; `crypto password store` repairs the
  entry.
- **`crypto keychain test` reports on an unsupported provider instead of hiding it.** It picks from
  the unfiltered provider list, so the machine whose keychain does not work still gets a
  `supported: false` line rather than one bare error — and it prints its document *before* it
  fails.
- **The self-test key is random** (`crypto-selftest-<16 hex>`) and the command fails outright when
  the machine has no randomness, rather than falling back to a fixed key two concurrent runs would
  fight over.
- **The 30-second call budget and the 5-second probe budget are compiled in**, like the unlock
  timeouts: a machine that needs them longer needs a rebuild, not a setting.

#### Known limitations and follow-ups

- **Reading an entry the desktop app wrote has not been verified end to end.** It needs a person at
  the machine to answer the macOS ACL dialog and a desktop vault with a stored passphrase; spike B
  could not do it and this milestone did not either. What is verified is our own round trip and,
  in the E2E test, an entry seeded with `security add-generic-password -A`. Signing release
  binaries with a stable Developer-ID identity (M8) is what makes "Always Allow" stick.
- **The Linux backend has never run on real hardware here.** The development machine is a Mac;
  the code compiles and lints for Linux and its pure parts are unit-tested, but no `store`, `load`,
  `delete` or `change` has executed against a Secret Service. The `keychain-e2e-linux` CI job is
  the first place any of it runs, and the `secret-tool` check there is the first thing that
  compares the raw attribute names against something outside our own code — it still cannot compare
  them against the desktop app.
- **Touch-ID entries are best effort.** `TouchIdKeychainAccess` is served by the plain macOS
  backend, so passwords `crypto` writes carry no Touch-ID access control; `security-framework`'s
  password API cannot request one without unsafe code.
- **KWallet is unsupported.** The provider exists only to say so and to point at `secret-service`.
- **`change()` keeps the ACL by updating in place** — a deliberate deviation from Java's
  delete-and-store. The consequence is that a stale label (the desktop app's, or an earlier display
  name) survives a password change.
- **`crypto unlock --json` has no `stored` field.** `vault create --json` reports `stored`, and
  `password store --json` reports `{id, stored}`, but an unlock that saved a password says so only
  on stderr.
- **`--password-keychain` shows up in `crypto password store --help`.** It comes with the shared
  `PasswordArgs` group; using it there would mean verifying a stored password against the vault and
  storing it again, which is harmless but pointless.
- **Keychain calls must not run concurrently in one process.** A pending macOS prompt serialises
  keychain access, so a second call made next to a waiting one blocks too and burns its own 30
  seconds. Every command makes its keychain calls one at a time; nothing enforces it structurally.
- **The keychain item for the WebDAV mount is not written.** Java stores an anonymous *internet*
  password before the AppleScript mount so macOS does not ask about the unencrypted connection.
  It is unrelated to vault passphrases and would need its own code (protocol, host, port, path);
  it is deferred to M8.
- Still open from earlier milestones: macFUSE is unverified (M4), `LinuxGioMounter` has never run
  on a real GNOME desktop (M5), and coexistence with a running desktop app is still a manual step
  nobody has taken.
