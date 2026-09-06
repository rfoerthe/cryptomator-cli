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
  ship with M4; the atomic tmp + rename write is still all there is, so close the desktop app before
  `crypto vault add/remove/set` and `crypto config set`.

#### Known limitations and follow-ups

- **macFUSE is unverified.** It has never been installed on a machine this port was tested on, so
  that provider has never mounted anything. FUSE-T 1.2.7 and Linux `fuse3` are covered by the
  end-to-end test.
- **A Finder copy of a file carrying extended attributes or a resource fork onto a FUSE-T mount has
  not been tried.** That is the case where refusing the AppleDouble side cars could surface as a
  failed copy; if it does, the refusal has to become a mount flag instead of a default.
- **Coexistence with the Cryptomator desktop app** — unlocking in one and looking at the vault in the
  other — is a manual check nobody has run.
- `crypto password change` and `crypto recovery-key show`/`reset-password` still accept an
  *unlocked* vault: they resolve it through `locked_vault_path`, which only checks the on-disk
  state. Neither corrupts ciphertext, but both should refuse like the `fs`/`name` commands do;
  deferred to M5.
- The daemon reads its socket through a `BufReader`, whose internal buffer keeps the base64 vault key
  of the `unlock` line until later traffic overwrites it. Every decoded copy is wiped; the buffer is
  an M5 follow-up.
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
- `crypto unlock --port` (WebDAV) and `--store-password` (keychain) do not exist yet; they arrive
  with M5 and M6.
- The unlock timeouts are compiled in: 60 seconds for the daemon to receive an `unlock`, 70 for the
  whole call. A mount slower than that needs a rebuild, not a setting.
