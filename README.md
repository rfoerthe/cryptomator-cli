# crypto – Cryptomator on the command line

`crypto` is a Rust command line client for [Cryptomator](https://cryptomator.org) vaults (vault format 8)
for macOS and Linux. It shares the desktop app's `settings.json` and keychain entries.

Status: early development. Vault format 8 read and write, mount-less access, and FUSE mounting with
a per-vault daemon work; WebDAV, the keychain, `crypto health`, restore and migration do not exist
yet. See `docs/superpowers/specs/2026-09-04-crypto-cli-design.md` for the design and
`docs/daemon-protocol.md` for the daemon's wire protocol.

## Build

    cargo build --release

## Commands

Every command accepts `--settings <PATH>` and `--json`. Vaults are addressed by id, display name or
path (`<VAULT>` below). Vault ids are base64url and may start with `-`; they are accepted as they
are, and `--` before the first positional (`crypto fs ls -- -abcDEF123456 /`) is the general escape
hatch for any argument that begins with a dash.

`--json` prints one JSON document per command — except where the command's payload is the file
itself: `fs cat` and `fs get -` always write the raw bytes to standard output, with or without
`--json`.

| Command | What it does | Example |
|---|---|---|
| `vault create` | Creates a vault directory, writes `masterkey.cryptomator`, `vault.cryptomator`, the root dir and the readme files, and registers it | `crypto vault create ~/Vaults/Secret --name Secret` |
| `vault add` | Registers an existing vault directory | `crypto vault add ~/Vaults/Secret` |
| `vault list` | Lists registered vaults with id, name, path and state | `crypto vault list --json` |
| `vault info` | Shows the settings and the vault configuration of one vault | `crypto vault info Secret` |
| `vault set` | Changes per-vault settings (mount point, mounter, flags, auto-lock, …) | `crypto vault set Secret --mount-point ~/mnt/secret --read-only true` |
| `vault remove` | Unregisters a vault; its files stay on disk | `crypto vault remove Secret` |
| `config get` | Prints one or all settings, from `settings.json` and `cli.json` together | `crypto config get port` |
| `config set` | Changes a setting (`mountService`, `port`, `useKeychain`, `keychainProvider`, `debugMode`, `mountPointsDir`, `defaultMounter`, `logLevel`, `forceUnmountOnSignalAfterSecs`) | `crypto config set port 42427` |
| `password change` | Changes the vault password and backs the old masterkey file up as `.bkup` | `crypto password change Secret --new-password-stdin` |
| `recovery-key show` | Prints the 44-word recovery key of a vault (needs the password) | `crypto recovery-key show Secret` |
| `recovery-key reset-password` | Sets a new password from a recovery key, without the old one | `crypto recovery-key reset-password Secret --recovery-key-stdin` |
| `recovery-key validate` | Checks whether a recovery key is well-formed | `printf '%s' "$KEY" \| crypto recovery-key validate --recovery-key-stdin` |
| `unlock` | Mounts a vault in a background daemon | `crypto unlock Secret --mounter fuse-t` |
| `lock` | Unmounts a vault and stops its daemon | `crypto lock Secret --force` |
| `status` | Lists the registered vaults with their runtime state and mount point | `crypto status --json` |
| `stats` | Throughput and cache counters of an unlocked vault | `crypto stats Secret --follow` |
| `events` | The event log of an unlocked vault | `crypto events Secret --since 42` |
| `mounters` | The mount services this build knows and which of them work here | `crypto mounters --all` |
| `fs ls` | Lists a directory inside a locked vault | `crypto fs ls Secret /2026 -l` |
| `fs tree` | Walks a directory tree; `--json --hash` prints the fixture-manifest shape | `crypto fs tree Secret --json --hash` |
| `fs cat` | Writes a vault file to standard output | `crypto fs cat Secret /notes.md` |
| `fs get` | Copies a file out of the vault (`-` for standard output) | `crypto fs get Secret /2026/report.pdf ./report.pdf` |
| `fs put` | Copies a local file into the vault (`-` for standard input) | `crypto fs put Secret ./report.pdf /2026/report.pdf` |
| `fs rm` | Deletes a file, symlink or directory (`-r` for non-empty ones) | `crypto fs rm Secret /2026/old -r` |
| `fs mkdir` | Creates a directory (`-p` for parents) | `crypto fs mkdir Secret /2026/invoices -p` |
| `fs mv` | Moves or renames inside the vault | `crypto fs mv Secret /draft.md /2026/notes.md` |
| `name decrypt` | Decrypts the names of ciphertext nodes below `<vault>/d/` | `crypto name decrypt Secret d/AB/CDEF…/xyz.c9r` |
| `name locate` | Shows the ciphertext node of a cleartext path | `crypto name locate Secret /2026/report.pdf --contents` |

`crypto vault create` uses `SIV_GCM` and a shortening threshold of 220 like the desktop app;
`--shortening-threshold` (36–220) and `--no-register` change that. `--show-recovery-key` prints the
recovery key right after creation.

### `crypto recovery-key validate --recovery-key-stdin`

Checks whether a recovery key is well-formed: 44 dictionary words, an even word count, and a valid
CRC-32 checksum over the 64-byte masterkey it encodes. It does not touch a vault and does not reveal
whether the key belongs to any particular vault.

The key is read from standard input (it never appears in the process list or the shell history) and
`--recovery-key-stdin` is required, so the source is always explicit:

    printf '%s' "$RECOVERY_KEY" | crypto recovery-key validate --recovery-key-stdin

It prints `valid` and exits `0`, or prints `invalid` and exits `4`. Error messages never quote the
input.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | success — including a reader that closed the pipe (`crypto vault list \| head -3`) and a `--follow` stream stopped with Ctrl-C |
| `1` | anything else that failed |
| `2` | usage: an unknown flag or mounter, no password source, a value the setting does not take |
| `3` | the vault reference names no registered vault, or more than one |
| `4` | wrong password, invalid recovery key, a new password below the minimum length |
| `5` | wrong vault state: already unlocked, not unlocked, needs migration, read-only, or an `fs`/`name` command on a vault that is not `LOCKED` |
| `6` | the mount failed — a mount point that cannot be used, a mounter that refused, a conflicting mount service, or a daemon that stopped answering while it mounted |
| `7` | the unmount failed; a volume still in use needs `crypto lock … --force` |
| `9` | a Hub vault, which this build cannot open |
| `10` | the vault's daemon cannot be reached |
| `12` | the path is not a vault directory |

`8` (keychain unavailable) and `11` (health findings) are reserved for M6 and M7 and are never
returned today.

## Mounting

A mounted vault looks like an ordinary directory: `crypto unlock` hands the vault to a FUSE back
end, and everything below the mount point is encrypted on the way in and decrypted on the way out.
`crypto mounters` says what this build can use and what works on this machine.

### Prerequisites

`crypto` does not ship a file system driver; one has to be installed:

| Platform | Back end | Install | `--mounter` |
|---|---|---|---|
| macOS | **FUSE-T** (no kernel extension) | `brew install --cask macos-fuse-t/homebrew-cask/fuse-t` | `fuse-t` |
| macOS | macFUSE (system extension, needs approval and a reboot) | `brew install --cask macfuse` | `macfuse` |
| Linux | libfuse 3 | `apt install fuse3` (or your distribution's equivalent) | `fuse` |

A back end is detected, not configured: FUSE-T by `/usr/local/lib/libfuse-t.dylib`, macFUSE by
`/usr/local/lib/libfuse.2.dylib` or `libosxfuse.2.dylib`, Linux FUSE by a working `fusermount3 -V`.
`crypto mounters` lists what answered, `crypto mounters --all` also the ones that did not:

    $ crypto mounters
    ALIAS   CLASS                                                   SUPPORTED  CAPABILITIES
    fuse-t  org.cryptomator.frontend.fuse.mount.FuseTMountProvider  yes        MOUNT_FLAGS,UNMOUNT_FORCED,READ_ONLY,MOUNT_TO_EXISTING_DIR,VOLUME_NAME

Without `--mounter` and without a `mountService` on the vault, the service with the highest
priority that works here is chosen (macOS: macFUSE before FUSE-T; Linux: FUSE); `crypto config set
defaultMounter <ALIAS>` fixes one for every vault, `crypto vault set <VAULT> --mounter <ALIAS>` for
one of them. macFUSE and FUSE-T cannot be in use side by side: unlocking through one of them while
another vault is already mounted through the other is refused (exit `6`), as in the desktop app.

**macFUSE is not verified.** It was never installed on a machine this port was built or tested on,
so the macFUSE code path has never mounted anything. FUSE-T (1.2.7) and Linux `fuse3` are covered
by the mount end-to-end test.

### What FUSE-T can and cannot do

FUSE-T serves its volume as a **local NFS mount** — it shows up in `mount` as
`fuse-t:/<volume-name> on <mount point> (nfs, …)`, not as a `fuse` file system. That has
consequences a macFUSE or Linux mount does not have:

- **No extended attributes.** `xattr` calls answer `ENOTSUP`, and `-ononamedattr` is always
  appended to the mount flags. Finder tags, quarantine flags and resource forks are lost on the way
  into the vault.
- **AppleDouble side cars are refused.** macOS' NFS client writes a `._<name>` file next to *every*
  node it creates, to carry exactly those attributes. Left alone, a vault mounted through FUSE-T
  would fill up with one encrypted `._x` per file, directory and symlink, so the adapter answers
  their creation with `EPERM` — the errno macFUSE's kernel extension returns for the same thing.
  The user's own operation is untouched by that, but **copying a file that carries extended
  attributes or a resource fork in Finder may fail**; that case is on the list below.
- **No `-obackend=smb`.** FUSE-T 1.2.7 ships only the NFS helper (`go-nfsv4`); its own mount call
  fails with the SMB backend. The NFS default is used and the option is not passed on.
- Default flags: `-ononamedattr -orwsize=262144 -ouid=<uid> -ogid=<gid>`.

macFUSE is mounted with `-ouid=<uid> -ogid=<gid> -oatomic_o_trunc -oauto_xattr -oauto_cache
-onoappledouble -odefault_permissions` and keeps the side cars away from userspace itself;
`-obackend=fskit` is refused. On Linux the defaults are `-oauto_unmount -ouid=<uid> -ogid=<gid>
-oattr_timeout=5`. Both macOS back ends sweep `._*` and `.DS_Store` out of a directory before they
remove it, like the desktop app's `deleteAppleDoubleFiles` — otherwise a directory that looks empty
in Finder could never be deleted.

`--mount-option=-o…` adds flags (repeatable, and the `=` form is required so a forgotten value
cannot swallow the next flag); `crypto vault set <VAULT> --mount-flags="…"` stores them.

### Still to verify by hand

Three things the automated tests cannot reach. Until someone has run them, the README does not
claim they work:

1. **macFUSE**, at all — install it, `crypto unlock <VAULT> --mounter macfuse`, and run the same
   round trip the end-to-end test runs on FUSE-T.
2. **A Finder copy of a file carrying extended attributes or a resource fork onto a FUSE-T mount**,
   which is where the refused AppleDouble side cars could surface as a failed copy. If it does, the
   refusal has to become a flag rather than a default.
3. **Coexistence with the Cryptomator desktop app**: the app and `crypto` share `settings.json`, and
   the app rewrites the whole file from memory when it exits. Unlocking a vault in one and looking
   at it in the other, in both orders, is not covered by any test.

### Unlocking and locking

`crypto unlock <VAULT>` reads the password, derives the vault key and hands it to a **background
daemon** that owns the mount from then on. The password stays in the `crypto unlock` process and the
key is sent over the daemon's private control socket — it never appears in the process list, the
environment or a file. The protocol between the two is documented in
[`docs/daemon-protocol.md`](docs/daemon-protocol.md).

    crypto unlock Secret                       # mounts and returns; the daemon keeps running
    crypto unlock Secret --json                # {"id":…,"mountpoint":…,"mounter":…,"pid":…}
    crypto lock Secret                         # unmounts and stops the daemon
    crypto lock --all --force                  # everything, even while volumes are in use

- **`--mounter <ALIAS|CLASS>`** picks the mount service (`fuse-t`, `macfuse`, `fuse`), `--mount-point`
  where to mount, `--mount-option=-o…` (repeatable) adds mount flags, `--read-only` and
  `--volume-name` do what they say. An unknown mounter name is a usage error (exit `2`). Relative
  paths are resolved before the daemon is spawned — it runs with its working directory at `/`.
- **`--foreground`** serves the vault in this process instead of detaching; Ctrl-C locks it again.
  The same daemon, the same protocol, the same teardown — only the process is yours, and the wait
  before a forced unmount is announced on your standard error instead of only in the log.
- **A FUSE-T volume needs a moment to appear.** `crypto unlock` returns as soon as the mount call
  has, but FUSE-T mounts asynchronously: for a few hundred milliseconds afterwards the mount point
  is still the empty directory underneath, and anything written there lands beside the vault instead
  of in it. Wait for the volume before you write to it, e.g.
  `until mount | grep -q "on $MP "; do sleep 0.1; done`.
- **`--reveal`** (or the vault's `actionAfterUnlock=REVEAL`) opens the mount point in the file
  manager afterwards — `open` on macOS, `xdg-open` on Linux. `$CRYPTO_REVEAL_CMD` replaces that
  command (split on whitespace, the mount point is appended); failures are ignored either way,
  since a headless session is not a failed unlock.
- **Auto-lock** is the daemon's, not the shell's: a vault whose `autoLockWhenIdle` is on
  (`crypto vault set <VAULT> --auto-lock-idle <SECONDS>`) unmounts itself once nothing has touched
  it for that long, detached and in the foreground alike. The daemon then ends with exit `0`.
- **Exit codes:** `5` for a vault that is already unlocked or not unlocked, `6` when the mount fails
  (the last lines of the daemon's log are printed) or when the daemon stops answering while it
  mounts, `7` when an unmount fails — a busy volume needs `crypto lock … --force` — and `10` when
  the daemon cannot be reached. See [the table](#exit-codes).
- **A crashed daemon** leaves its volume mounted (`STALE_MOUNT`); `crypto lock <VAULT> --force` takes
  it down by mount point and removes the leftover state files. If nothing is mounted any more, the
  leftovers are cleaned up on their own the next time a command looks at the vault.
- **`--mounter null`** mounts nothing at all. It exists for the test suite — it is only offered when
  `$CRYPTO_ENABLE_NULL_MOUNTER=1` is set, and "mounting" means writing a marker file into the mount
  point — so that the daemon, `lock`, `status`, `stats`, `events`, the signals and the auto-lock can
  be tested without a FUSE driver. Nothing in normal use needs it.

`crypto unlock` gives the mount 60 seconds and then gives up on the daemon (70 seconds for the whole
call, so a daemon that has stopped answering is not waited for either); the daemon is asked to stop
— SIGTERM before SIGKILL, so its own unmount still runs — and the command fails with exit `6`
pointing at the log. Both values are compiled in.

### The state directory

The daemon writes four files per vault: `<id>.sock` (its control socket, `0600`), `<id>.pid`,
`<id>.json` (the run info: mount point, mounter, pid, start time, read-only) and `<id>.log`. The log
survives a lock, the other three are removed with the daemon.

    --state-dir <PATH>                         # for one command
    $CRYPTO_STATE_DIR                          # for the environment

Without either, the default is `~/Library/Application Support/Cryptomator/cli-run` on macOS and
`$XDG_RUNTIME_DIR/crypto` on Linux, falling back to `/tmp/crypto-<uid>` where the session has no
run-time directory. The directory is created `0700` and has to be a real directory belonging to you
— a symbolic link or someone else's directory is refused rather than used, because whoever owns that
path would own the socket the vault key travels over.

### Signals

A daemon — detached or `--foreground` — stops on **SIGINT** (Ctrl-C), **SIGTERM** (plain `kill`) and
**SIGHUP** (the terminal went away). All three run the same teardown, escalating the way
`crypto lock --force` would:

1. unmount the volume gracefully;
2. if that fails because the volume is busy, wait `forceUnmountOnSignalAfterSecs` (`cli.json`,
   `10` by default) and unmount it forcefully;
3. remove socket, pid file and run info, and exit `0`.

`crypto lock` is still the better way to stop one: it reports the failure to *you* instead of to the
daemon's log. A volume that survives even the forced unmount (or a mounter without a forced unmount
at all) makes the daemon exit `7` and **keep its run info**, so `crypto status` reports
`STALE_MOUNT` and `crypto lock <VAULT> --force` can address the volume it left behind. `SIGKILL`
skips all of this by definition and leaves exactly that stale mount behind.

## Watching an unlocked vault

`crypto status` answers from `settings.json` and the state directory alone — it never sends a
request, so it works for locked, unlocked and crashed vaults alike:

    crypto status                              # ID  NAME  STATE  MOUNTPOINT, one row per vault
    crypto status Secret --json                # one object: id, displayName, path, state,
                                               # mountpoint, mounter, pid, readOnly

The states are the ones `crypto vault list` shows plus `UNLOCKED` and `STALE_MOUNT`. Naming a vault
that is not registered is exit `3`; without an argument the output is an array, with one it is that
vault's object.

`crypto stats` and `crypto events` ask the daemon, so they need the vault to be **unlocked** (exit
`5` otherwise, exit `10` if the daemon is gone):

    crypto stats Secret                        # read 0 B/s  write 0 B/s  cache 0%  total read …
    crypto stats Secret --follow --interval 5  # one line (or one JSON object) every 5 seconds
    crypto events Secret                       # seq  time  KIND  message, oldest first
    crypto events Secret --follow --json       # one JSON object per event, as it happens

The per-second numbers are the deltas of the daemon's last sampling interval (one second), the
totals are read at request time. The event log lives in the daemon, so it starts empty with every
unlock and holds the last thousand entries; `--since <SEQ>` continues after the `seq` of the last
event you saw. Both `--follow` modes print a notice on standard error, keep going until **Ctrl-C**
and then exit `0`; with `--json` they print one object per line (NDJSON), not one document. They
also end with `0` when the vault is locked underneath them (by `crypto lock`, an auto-lock or a
signal) after they have printed at least one line, and when their reader closes the pipe — so
`crypto stats Secret --follow | head -3` is a normal end, not an error. A daemon that is already
gone before the first line is still exit `10`.

`crypto mounters` lists the mount services of this build — the `ALIAS` column is what `--mounter`
and `defaultMounter` accept, and `CLASS` is the Java class name stored in `settings.json`. Without
`--all` only the services that work on this machine are listed.

## Mount-less access

`crypto fs …` and `crypto name …` read and write vault contents **without a mount**, straight through
the cleartext layer. The vault has to be registered and in state `LOCKED` (exit `5` otherwise): a
vault a daemon has unlocked, and one a crashed daemon left mounted, are both refused — reading
included, because the mount may be holding changes that are not on disk yet. `crypto lock` is the way
out. Hub vaults are rejected before any password is read. Passwords come from the sources listed
above.

- **Read-only vaults.** `usesReadOnlyMode` (from `crypto vault set … --read-only true`) is respected:
  `put`, `rm`, `mkdir` and `mv` fail with exit `5`, listing and reading still work.
- **`fs put -`** reads the file from standard input and therefore excludes `--password-stdin`
  (exit `2`); use `--password-env`/`--password-file` or `$CRYPTO_PASSWORD` in that case.
- **`fs put` never damages the destination.** The content is encrypted into a sibling temp file
  (`<name>.<pid>.tmp` in the destination directory) and only a completely written temp file is
  renamed into place; a source that fails half way through leaves the old file untouched and the
  temp file is removed. Without `--force` an existing destination is rejected before anything is
  written.
- **Names are NFC-normalised** like in the desktop app, so a decomposed `café.txt` and a composed
  `café.txt` address the same file.
- **Sync conflicts** are resolved during a listing exactly as the desktop app does it: a ciphertext
  node that a sync tool renamed is renamed back on disk and shows up as `name (1).ext`. In a
  read-only vault nothing on disk is touched — the conflicting copy is reported as a warning on
  standard error and left out of the listing (a deviation from cryptofs, which renames anyway).
- **`fs mv` never moves *into* a directory.** The destination is always the full new path, so
  `crypto fs mv Secret /a.txt /dir` renames `a.txt` to `dir` (and fails if `dir` exists) rather than
  creating `/dir/a.txt`. `--force` replaces an existing destination, directories only when they are
  empty.
- **`fs rm`** deletes files, symlinks and empty directories; a non-empty directory needs `-r`.
- **`fs get`/`fs put`** never overwrite without `--force`; `fs get -` streams to standard output.
- **Symlinks** are listed and read, never followed for `ls`/`tree`. Relative targets resolve against
  the link's parent directory (POSIX semantics; cryptofs resolves them against the vault root).

## Password sources

A password is taken from the first source that is present, so a password never has to appear on the
command line:

1. `--password-stdin` – the next line of standard input (the trailing newline is removed)
2. `--password-file <FILE>` – at most 5000 bytes of UTF-8, one trailing newline removed
3. `--password-env <VAR>` – the named environment variable (it must be set)
4. `$CRYPTO_PASSWORD` – the implicit fallback when no flag is given
5. an interactive prompt, but only when standard input is a terminal

Without a usable source the command fails with a usage error instead of hanging. Passwords are NFC
normalised like the desktop app and never appear in error messages or logs.

New passwords must be at least 8 characters long (override with `$CRYPTO_MIN_PW_LENGTH`) and are
asked twice when they are typed at the prompt. `vault create` reads the new passphrase through the
plain `--password-stdin` / `--password-file` / `--password-env` flags and the `$CRYPTO_PASSWORD`
fallback listed above, because there is no old password to keep apart from it. `password change` and
`recovery-key reset-password` take the *new* passphrase from `--new-password-stdin` /
`--new-password-file` / `--new-password-env` instead, in the same order. `password change`
deliberately does **not** fall back to `$CRYPTO_PASSWORD` for the *new* password: that variable holds
the current one, and silently reusing it would keep the old password.

## Settings file

`crypto` reads and writes the same `settings.json` as the Cryptomator desktop app:

- macOS: `~/Library/Application Support/Cryptomator/settings.json`
- Linux: `~/.config/Cryptomator/settings.json`, then `~/.Cryptomator/settings.json`

`--settings <PATH>` overrides the location for a single run, `$CRYPTO_SETTINGS_PATH` for the whole
environment (a `:`-separated list like Java's `-Dcryptomator.settingsPath`; the first entry is the
file that gets written). Saving is atomic (`settings.json.<pid>.tmp` + rename) and keeps unknown fields, so
a file written by the desktop app survives a round trip.

### `cli.json`

Everything the CLI needs *in addition* lives in `cli.json`, a sibling of `settings.json`, so a
future desktop version cannot collide with it. Unknown keys are preserved there too, and the file
is written 0600. `crypto config get|set` reads and writes both files in one flat namespace:

| Key | What it does | Default |
|---|---|---|
| `mountPointsDir` | Where mount directories are created when neither the vault nor `--mount-point` names one | `~/Library/Application Support/Cryptomator/mnt` (macOS), `~/.local/share/Cryptomator/mnt` (Linux) |
| `defaultMounter` | Mount service for vaults that name none; an alias is stored as the Java class name, `default` clears it | unset (the best available service) |
| `logLevel` | Verbosity of the daemon log: `error`, `warn`, `info`, `debug`, `trace` | `info` |
| `forceUnmountOnSignalAfterSecs` | How long a daemon waits after a failed graceful unmount, on `lock`/shutdown/signal, before forcing it | `10` |

    crypto config set mountPointsDir ~/mnt     # relative paths resolve against the shell's cwd
    crypto config set defaultMounter fuse-t
    crypto config get mountPointsDir           # the effective value, default included

Because the file is shared, **close the desktop app before `crypto vault add` or `crypto vault
remove`**: the running app keeps its own copy in memory and overwrites the file when it exits.
A `settings.json` that cannot be parsed is reported as an error — unlike the desktop app, `crypto`
never silently replaces it.

## Test fixtures

`tests/fixtures/` holds eight reference vaults created with the real Java implementation
(cryptofs 2.10.0 / cryptolib 2.2.2). The Rust tests read them without Java. To regenerate them you
need a JDK 21+ and Maven:

    mvn -q -f tools/fixture-gen/pom.xml compile exec:exec

The output directory defaults to `tests/fixtures` and can be overridden with
`-Dfixture.arg1=<path>`. The same harness opens a vault written by `crypto` and prints its cleartext
tree, which is how the interop test checks that the Java implementation accepts our vaults:

    mvn -q -f tools/fixture-gen/pom.xml compile exec:exec -Dfixture.cmd=verify -Dfixture.arg1=<vault> -Dfixture.arg2=<passphrase>
    cargo test -p crypto --test java_interop -- --ignored

Regeneration changes nonces and salts but keeps each vault's masterkey and the passphrase
`test-password-123`; see `tools/fixture-gen/README.md`.

## License

AGPL-3.0-only. The vault format implementation is a port of
[cryptolib](https://github.com/cryptomator/cryptolib) and [cryptofs](https://github.com/cryptomator/cryptofs) (AGPL-3.0).
