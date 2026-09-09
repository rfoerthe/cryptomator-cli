# crypto – Cryptomator on the command line

`crypto` is a Rust command line client for [Cryptomator](https://cryptomator.org) vaults (vault format 8)
for macOS and Linux. It shares the desktop app's `settings.json` and keychain entries.

Status: 0.1.0, the first release. Vault format 8 read and write, mount-less access, FUSE mounting
with a per-vault daemon, a loopback WebDAV server, the keychain, the health checks, the migration of
older vault formats, the rebuilding of lost key files, shell completions, manpages and packages for
macOS and Debian. See `docs/superpowers/specs/2026-09-04-crypto-cli-design.md` for the design,
`docs/daemon-protocol.md` for the daemon's wire protocol and [`docs/release.md`](docs/release.md)
for how a release is cut.

## Install

`crypto` does not ship a file system driver, and it does not need one to run: every command except
a real mount works without any FUSE software, and `crypto unlock --mounter webdav` serves a vault
over loopback HTTP instead. [Prerequisites](#prerequisites) says what a real mount needs.

### macOS

    brew install --formula packaging/homebrew/crypto.rb

**Not before the first release.** The committed formula's checksums are placeholders (sixty-four
zeroes) and its download URLs point at a release that does not exist yet, so the command above
fails until someone has back-ported the rendered formula from the first release — see
[`docs/release.md`](docs/release.md). **Until then, build from source** (below), or take the
tarball: download `crypto-<version>-universal-apple-darwin.tar.gz` from the
[releases](https://github.com/rfoerthe/cryptomator-cli/releases), check it against `SHA256SUMS`
and unpack it. That binary is a Universal Mach-O — arm64 and x86_64 in one file — built for macOS
12 and later. Single-architecture tarballs (`aarch64-apple-darwin`, `x86_64-apple-darwin`) exist
too, and are the smaller download.

The release binaries are **not signed with a Developer ID**. Gatekeeper therefore quarantines a
downloaded tarball (`xattr -d com.apple.quarantine crypto` clears it) and, more visibly, macOS
re-asks for keychain access after every new build — see *macOS asks the first time* under
[Stored passwords](#stored-passwords-keychain). `docs/release.md` has the `codesign`/`notarytool`
commands for anyone who wants to sign their own build.

### Debian and Ubuntu

    sudo apt install ./crypto_<version>-1_<arch>.deb   # amd64 and arm64

The package depends on `fuse3` (for `fusermount3`, which the Linux mount back end calls at run
time) and recommends `gnome-keyring` and `libsecret-tools` — the keychain is optional, and
`secret-tool` is only for inspecting the entries by hand. It installs the binary, all 43 manpages
and the bash, zsh and fish completions. `dpkg -i` works too, with `sudo apt-get install -f`
afterwards to pull the dependencies in.

### Any Linux, from the tarball

    tar xzf crypto-<version>-x86_64-unknown-linux-gnu.tar.gz
    cd crypto-<version>-x86_64-unknown-linux-gnu
    sudo install -m 755 crypto /usr/local/bin/crypto
    sudo install -m 644 man/*.1 /usr/local/share/man/man1/

`aarch64-unknown-linux-gnu` is built as well. The binaries link against glibc (built on Ubuntu
22.04, so glibc 2.35 or newer) and *not* against libfuse; there is no musl build.

### From source

    cargo install --path crates/crypto --locked

or, for a build tree, `cargo build --release` — the binary lands in `target/release/crypto`. Rust
1.89 or newer. `cargo install` places only the binary; the manpages and completion scripts come
from `cargo xtask man` and `cargo xtask completions` (see below).

### Verifying a download

    sha256sum --ignore-missing -c SHA256SUMS      # shasum -a 256 --ignore-missing -c on macOS

`SHA256SUMS` covers every tarball and both `.deb`s of a release, so `--ignore-missing` is what
keeps it quiet about the ones you did not download.

### Shell completions

The packages install them. To install one by hand, or for a shell they do not cover:

    crypto completions zsh    > ~/.zfunc/_crypto
    crypto completions bash   > /etc/bash_completion.d/crypto
    crypto completions fish   > ~/.config/fish/completions/crypto.fish
    crypto completions elvish >> ~/.config/elvish/rc.elv
    crypto completions powershell                              # paste into $PROFILE

zsh needs `~/.zfunc` on its `fpath` (`fpath+=~/.zfunc` before `compinit`); the other four are
picked up from the paths above as they are.

The script is generated from the live grammar, so it can never fall behind the commands. The
tarballs carry the same five scripts in `completions/`.

### Manpages

`man crypto` for the overview and `man crypto-vault-create`, `man crypto-fs-put` and so on for the
subcommands — 43 pages, one per visible command. They are **generated, not committed**: a checked-in
manpage is wrong from the first commit that touches the grammar. The packages and the tarballs
(`man/`) ship them; in a build tree, `cargo xtask man` writes them into `target/man/`.

### Which build is this?

    $ crypto --version
    crypto 0.1.0 (33dbe47, aarch64-apple-darwin)

Version, short commit and target triple — quote the whole line in a bug report. A build from a
source tarball with no git repository around it says `unknown` for the commit unless
`$CRYPTO_GIT_SHA` is set.

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
| `config set` | Changes a setting (`mountService`, `port`, `useKeychain`, `keychainProvider`, `debugMode`, `mountPointsDir`, `defaultMounter`, `logLevel`, `forceUnmountOnSignalAfterSecs`, `webdavBind`) | `crypto config set port 42427` |
| `password change` | Changes the vault password and backs the old masterkey file up as `.bkup` | `crypto password change Secret --new-password-stdin` |
| `password store` | Verifies a password and saves it in the keychain | `crypto password store Secret` |
| `password forget` | Removes a vault's password from the keychain | `crypto password forget Secret` |
| `keychain test` | Names the keychain provider and self-tests it | `crypto keychain test --json` |
| `completions` | Prints the completion script for one shell to standard output | `crypto completions zsh > ~/.zfunc/_crypto` |
| `recovery-key show` | Prints the 44-word recovery key of a vault (needs the password) | `crypto recovery-key show Secret` |
| `recovery-key reset-password` | Sets a new password from a recovery key, without the old one | `crypto recovery-key reset-password Secret --recovery-key-stdin` |
| `recovery-key validate` | Checks whether a recovery key is well-formed | `printf '%s' "$KEY" \| crypto recovery-key validate --recovery-key-stdin` |
| `recovery-key restore` | Rebuilds a lost `masterkey.cryptomator` and/or `vault.cryptomator` | `crypto recovery-key restore Secret --all --recovery-key-stdin` |
| `health` | Checks a vault for structural damage, optionally repairs it | `crypto health Secret --fix` |
| `migrate` | Brings a vault of format 5, 6 or 7 up to format 8 | `crypto migrate Old --yes` |
| `unlock` | Mounts a vault in a background daemon (FUSE, or WebDAV with `--port <PORT>`) | `crypto unlock Secret --mounter fuse-t` |
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

### Restoring the masterkey or the vault config

When `masterkey.cryptomator` or `vault.cryptomator` is gone — and the `.bkup` files next to them are
gone too, because otherwise `crypto` restores from those by itself — `crypto recovery-key restore`
rebuilds them. Which secret it needs depends on which file is missing:

| Mode | What it needs | What it writes |
|---|---|---|
| `--config` | the vault password (the masterkey file is still there) | `vault.cryptomator` |
| `--masterkey` | the recovery key and a new password | `masterkey.cryptomator` |
| `--all` | the recovery key and a new password | both files |

    crypto recovery-key restore Secret --config
    printf '%s' "$RECOVERY_KEY" | crypto recovery-key restore Secret --all --recovery-key-stdin \
        --new-password-file ./new.txt

The recovery key comes from `--recovery-key-stdin` or `--recovery-key-file`, the new password from
`--new-password-stdin`/`--new-password-file`/`--new-password-env`, exactly as for
`recovery-key reset-password`. `--masterkey` writes no config, so it refuses `--cipher-combo` and
`--shortening-threshold` (exit `2`) rather than ignoring them.

For a new `vault.cryptomator` the **cipher combo is detected** by decrypting the header of the first
encrypted file in the vault, trying `SIV_CTRMAC` and then `SIV_GCM`. `--cipher-combo
SIV_GCM|SIV_CTRMAC` names it by hand, which is the only way for a vault that holds no encrypted file
yet; a combo the vault contradicts is refused (exit `2`), and so is a vault whose combo can neither
be detected nor given. `--shortening-threshold` (36–220, default 220) goes into the new config —
use the value the vault was created with, or long file names will be laid out differently from the
ones already in it.

A vault that lost **both** key files can no longer be registered (`crypto vault add` exits `12`), so
`restore` also accepts a plain directory path — any directory holding a `d/` — and works on it
without touching `settings.json`. It prints a hint to register the vault afterwards, and `--json`
then reports `"vault": null` and `"registered": false`:

    crypto recovery-key restore ~/Vaults/Secret --all --recovery-key-stdin < key.txt
    crypto vault add ~/Vaults/Secret --name Secret

Both files are written into a temporary directory first, validated there (the masterkey is loaded
back, the config's signature checked, and `--all` opens the whole pair as a vault) and only then
moved into place. An existing file is backed up as `<name>.<checksum>.bkup` before it is replaced;
`--json` lists the backups it made under `backups`, alongside `restored`, `cipherCombo`,
`shorteningThreshold` and `keychainUpdated`.

Nothing is written until the validation passed, so a restore that fails leaves the vault as it was
— with one window: `--all` moves two files, and the two moves are not one transaction. It moves
`vault.cryptomator` first and `masterkey.cryptomator` second, so a failure between them leaves the
new config next to the *old* masterkey file, and `restore --masterkey` with the same recovery key
finishes the job. Both replaced files are in the `.bkup` copies named above until then.

A vault of format 5 or 6 is refused (exit `5`, naming `crypto migrate`), even when it lost both key
files and therefore looks restorable: those formats keep their long names in `m/`, and writing a
format 8 config over their BASE32 names would make the vault unmigratable and unopenable. Migrate
first, restore afterwards. A format 7 vault has no `m/` and shares its layout with format 8, so a
restore on one is fine — it does the 7 → 8 step's job with new key files.

`crypto` checks that *its own* daemon is not serving the vault, and nothing else: a vault the
**Cryptomator desktop app** has unlocked looks `LOCKED` here. `restore` therefore prints a warning
to stderr when the app answers on its IPC socket (see [Settings file](#settings-file)); lock the
vault in the app before restoring its key files.

## Limits on the masterkey file

`masterkey.cryptomator` decides how much memory unlocking a vault costs, and it is a file that can
come from anywhere — a shared vault, a cloud folder, a mail attachment. scrypt's working set is
`128 · N · r` bytes, so a file asking for `"scryptCostParam": 16777216` would make `crypto` request
16 GiB before a password has even been read. Cryptomator itself puts no limit on the two values;
`crypto` checks them when the file is *read*, before any key is derived:

| Field | Accepted | What Cryptomator writes |
|---|---|---|
| `scryptCostParam` (`N`) | a power of two, `2` … `1048576` (`2^20`) | `32768` (`2^15`) |
| `scryptBlockSize` (`r`) | `1` … `64` | `8` |
| working set `128 · N · r` | at most 2 GiB | 32 MiB |

A file outside these limits is an invalid masterkey file (exit `1`); rejecting it costs nothing but
the JSON parse. No vault written by a Cryptomator release comes near them — the defaults are a
factor of 64 below the memory limit — and the file's own values are named in the error message.

## Durability of writes

Every file `crypto` writes on its own behalf — `masterkey.cryptomator` (created, or rewritten by
`password change`), its `.bkup` copy, `vault.cryptomator`, a health report, a restored file, the
temporary file `fs put` streams into and `fs get` writes, plus `settings.json`, `cli.json` and the
state files — is written to a temporary name, `fsync`ed, and only then renamed over its target;
after the rename the *directory* is `fsync`ed as well. The second sync is the one that is easy to
forget and the one that matters here: a rename lives in the directory's own dirty pages, so without
it a power cut can leave a vault whose masterkey file has correct contents on the platter and no
directory entry naming them — a vault with no key file at all. On the few file systems that answer
`fsync` on a directory with "not supported" (some SMB shares, some FUSE file systems) the sync is
skipped rather than turned into an error; every other failure is reported. Reported, though, is
not the same as failed: a directory sync that fails *after* the rename already succeeded is a
`warning: wrote <path> but could not confirm durability: <error>` on stderr and the command still
exits `0` — the file is on disk under its final name, and only the guarantee that the name survives
a power cut is missing. A rename that itself fails is an error, and the write is undone. Data written *through* a
mount is a different matter: there `crypto` syncs when the kernel or the WebDAV client asks it to
(`fsync(2)`, `close(2)`), exactly like any other file system.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | success — including a reader that closed the pipe (`crypto vault list \| head -3`) and a `--follow` stream stopped with Ctrl-C |
| `1` | anything else that failed |
| `2` | usage: an unknown flag or mounter, no password source, a value the setting does not take |
| `3` | the vault reference names no registered vault, or more than one |
| `4` | wrong password, invalid recovery key, a new password below the minimum length |
| `5` | wrong vault state: already unlocked, not unlocked, needs migration (run `crypto migrate`), read-only, or an `fs`/`name`/`password change`/`recovery-key show`/`recovery-key reset-password` command on a vault that is not `LOCKED` |
| `6` | the mount failed — a mount point that cannot be used, a mounter that refused, a conflicting mount service, a WebDAV port that is already in use, or a daemon that stopped answering while it mounted |
| `7` | the unmount failed; a volume still in use needs `crypto lock … --force` |
| `8` | the keychain could not serve the request: no usable provider, `--no-keychain` or `useKeychain false` on a keychain command, a locked keyring, a call that timed out after 30 s, or `--password-keychain` for a vault with nothing stored |
| `9` | a Hub vault, which this build cannot open |
| `10` | the vault's daemon cannot be reached |
| `11` | `crypto health` found at least one finding of the severity given by `--fail-on` (default `CRITICAL`) |
| `12` | the path is not a vault directory |

## Mounting

A mounted vault looks like an ordinary directory: `crypto unlock` hands the vault to a FUSE back
end — or, without one, to a loopback WebDAV server (see [WebDAV](#webdav)) — and everything below
the mount point is encrypted on the way in and decrypted on the way out.
`crypto mounters` says what this build can use and what works on this machine.

### Prerequisites

`crypto` does not ship a file system driver. For a real file-system mount one has to be installed;
`--mounter webdav` needs none, because it serves the vault over loopback HTTP instead (see
[WebDAV](#webdav)):

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

> **`-oallow_other` opens the decrypted vault to every local user.** It lifts the kernel's
> owner-only restriction, and the adapter itself grants every access it is asked about, so without
> `-odefault_permissions` (off by default) any other account on the machine can read and write the
> whole vault. Pass the two together — `--mount-option=-oallow_other
> --mount-option=-odefault_permissions` — or leave `allow_other` out. The same goes for
> `-oallow_root`, on a smaller scale.

### Still to verify by hand

Five things the automated tests cannot reach. Until someone has run them, the README does not
claim they work:

1. **macFUSE**, at all — install it, `crypto unlock <VAULT> --mounter macfuse`, and run the same
   round trip the end-to-end test runs on FUSE-T.
2. **A Finder copy of a file carrying extended attributes or a resource fork onto a FUSE-T mount**,
   which is where the refused AppleDouble side cars could surface as a failed copy. If it does, the
   refusal has to become a flag rather than a default.
3. **Coexistence with the Cryptomator desktop app**: the app and `crypto` share `settings.json`, and
   the app rewrites the whole file from memory when it exits. Unlocking a vault in one and looking
   at it in the other, in both orders, is not covered by any test.
4. **`--mounter webdav-gio` on a real GNOME desktop.** Its unit tests cover the command line it
   builds and the gvfs path it derives, but no machine this port was tested on had a gvfs session,
   and hosted CI runners have none either. The macOS side (`webdav-applescript`) and the server
   itself are covered end to end.
5. **The anonymous WebDAV internet password** that `--mounter webdav-applescript` writes before it
   mounts (see [WebDAV](#webdav)). Only the argument vector is under test: running
   `security add-internet-password` writes to the real login keychain and can open a dialog, so it
   was never executed unattended. What is unverified is whether the item it writes actually stops
   macOS from asking about the unencrypted connection — the failure mode is a dialog too many, not
   a failed mount.

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

- **`--mounter <ALIAS|CLASS>`** picks the mount service (`fuse-t`, `macfuse`, `fuse`, `webdav`,
  `webdav-applescript`, `webdav-gio`), `--mount-point` where to mount, `--mount-option=-o…`
  (repeatable) adds mount flags, `--port <N>` the TCP port of a loopback (WebDAV) mounter (`0`
  picks any free one), `--read-only` and `--volume-name` do what they say. An unknown mounter name
  is a usage error (exit `2`); an option the chosen mount service has no capability for is a failed
  mount (exit `6`) that names both the flag and the service, rather than being silently dropped.
  Relative paths are resolved before the daemon is spawned — it runs with its working directory at
  `/`.
- **`--mounter webdav`** needs no driver at all: the daemon serves the vault over HTTP on the
  loopback interface and `unlock` answers with a **URL** (`http://127.0.0.1:<port>/<vault id>`)
  instead of a path — in `--json`'s `mountpoint`, in the `MOUNTPOINT` column of `crypto status`,
  and in the run info. Mounting that URL is a separate step, and the unlock prints a one-line hint
  for it on standard error; `--reveal` opens nothing for a URL, because a browser is not the vault.
  `--mounter webdav-applescript` (macOS) and `--mounter webdav-gio` (Linux) do the mounting too and
  answer with the path of the volume. [WebDAV](#webdav) has the whole story: the port rule, the
  bind address, what `crypto lock --force` can and cannot do, and the limitations.
- **`--foreground`** serves the vault in this process instead of detaching; Ctrl-C locks it again.
  The same daemon, the same protocol, the same teardown — only the process is yours, and the wait
  before a forced unmount is announced on your standard error instead of only in the log.
- **The unlock returns only once the volume is really there.** FUSE-T mounts asynchronously: its
  helper drives the actual mount *after* the mount call has returned, and for a few hundred
  milliseconds the mount point is still the empty directory underneath. So the daemon waits for the
  volume to turn up in the system mount table (up to 10 seconds, checked every 50 ms) before it
  answers — `crypto unlock V && cp file $MP/` is safe, no `until mount | grep …` needed. A volume
  that never appears fails the unlock with `MOUNT_FAILED` (exit `6`), unmounted and with the daemon
  gone.
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

### WebDAV

`crypto` does not need a FUSE driver at all. The three WebDAV mount services serve the vault over
**HTTP on the loopback interface** from inside the daemon, and either hand you the URL or ask the
operating system to mount it for you.

They are chosen automatically when no FUSE back end works on this machine — their Java priorities
put them below every FUSE provider (`50` for the two OS-integrated ones, `0` for the plain
fallback), so on a Mac without macFUSE and FUSE-T an ordinary `crypto unlock Secret` ends in a
Finder volume, as long as there is a GUI session; over SSH or headless use `--mounter webdav`,
because the auto-choice only checks that `/usr/bin/osascript` exists and the AppleScript mount then
fails with exit `6` instead of falling back to the URL. All three can also be asked for by name,
with `--mounter webdav`, `--mounter webdav-applescript` or `--mounter webdav-gio`:

| Alias | Class (what `settings.json` stores) | Where it works | What `unlock` answers with |
|---|---|---|---|
| `webdav` | `org.cryptomator.frontend.webdav.mount.FallbackMounter` | macOS and Linux | the URL; mounting it is your step |
| `webdav-applescript` | `org.cryptomator.frontend.webdav.mount.MacAppleScriptMounter` | macOS (`/usr/bin/osascript`) | the `/Volumes/<name>` Finder mounted |
| `webdav-gio` | `org.cryptomator.frontend.webdav.mount.LinuxGioMounter` | Linux (`gio --version` answers) | the gvfs path under `/run/user/<uid>/gvfs` |

`crypto mounters` lists the ones that work here, `crypto mounters --all` the rest as well. Only the
platform's own is built in, so asking a Mac for `webdav-gio` (or Linux for `webdav-applescript`) is
a failed mount (exit `6`, "not available") rather than an unknown name.

    $ crypto unlock Secret --mounter webdav --port 0
    Unlocked Secret at http://127.0.0.1:53219/UARWQsp1etRW
    Mount it in Finder: Go -> Connect to Server, then enter http://127.0.0.1:53219/UARWQsp1etRW

The URL is `http://<webdavBind>:<port>/<vault id>` — the vault id is the servlet context path, the
same one the desktop app uses (the AppleScript mounter appends the volume name, so its own URL is
`…/<vault id>/<name>`). It is what `--json`'s `mountpoint`, the `MOUNTPOINT` column of
`crypto status` and the run info carry, and `crypto lock` stops the server and frees the port.

**Mounting the URL by hand.** Everything that speaks WebDAV reaches the decrypted vault:

- **macOS Finder:** *Go → Connect to Server* (Cmd-K), paste the `http://…` URL, *Connect*, and the
  volume appears under `/Volumes`. macOS asks whether you really want to connect to an unencrypted
  server, because a URL you mount by hand has no keychain entry to suppress that. Without Finder:
  `mount_webdav -S -i "<url>" <empty directory>`.

  `crypto unlock --mounter webdav-applescript` does not ask: like the desktop app, it runs
  `security add-internet-password -a anonymous -s <host> -P <port> -r http -D "Cryptomator WebDAV
  Access" -T …/NetAuthSysAgent` before the mount, which puts an anonymous *internet* password for
  that loopback server in your login keychain and lets `NetAuthSysAgent` — the helper behind
  Finder's WebDAV mounts — read it. The item carries no password (nothing secret is passed on the
  command line) and has nothing to do with the vault passwords below; it is written for
  `webdav-applescript` only, never by `--mounter webdav` or `webdav-gio`. Writing it is best
  effort: if `security` fails, the mount goes ahead and macOS asks after all. Keychain Access lists
  it under the server's address, kind *Cryptomator WebDAV Access*, and it can be deleted there.
- **GNOME:** `gio mount "dav://127.0.0.1:<port>/<vault id>"` — note the `dav:` scheme, not `http:` —
  or Nautilus's *Other Locations → Connect to Server* with the same `dav://` address.
- **Anything else:** `curl -X PROPFIND -H 'Depth: 1' <url>/`, `rclone`, a WebDAV-capable editor.

**The port.** `--port 0` takes any free port and is the safe choice for a second vault or a machine
where the desktop app is running. Without `--port` the rule is the desktop app's: the vault's own
`port` when the vault names a `mountService` (`crypto vault set <VAULT> --port <N>` stores one),
otherwise `settings.json`'s `port` — both default to `42427`. A port that is already taken fails
the unlock with exit `6` and names both ways out in the message.

**No authentication.** The server asks for no credentials: whoever can reach the port can read and
write the decrypted vault. Loopback keeps it off the network but **not** away from other accounts on
this machine: any local process, whatever its uid, can read and write the decrypted vault while it
is unlocked. Cryptomator's own WebDAV server has the same property; the FUSE back ends do not.
Prefer a FUSE back end on a shared machine.

`crypto config set webdavBind ::1` moves the server to another loopback address; a non-loopback
address is refused (exit `2`) unless `CRYPTO_WEBDAV_ALLOW_NONLOOPBACK=1` is set, and setting that
publishes the decrypted vault to everyone who can reach that interface.

**The `Host` header is checked.** A request is served only if its `Host` is a literal address —
with or without a port, `[::1]` brackets included — or the name `localhost`, or if there is no
`Host` at all (an HTTP/1.0 client). Anything else is `400`. That closes DNS rebinding: a web page
the browser loaded from a name the attacker controls can otherwise re-point that name at
`127.0.0.1` and reach this server as same-origin, and neither the port (`42427` by default) nor the
vault id in the URL is a secret. Every real client — Finder, `mount_webdav`, `gio`, `curl`,
`rclone` — sends the address it dialled, so the rule is invisible to them.

**Locking.** `crypto lock <VAULT>` always works — it stops the server, and with the two OS mounters
it unmounts the volume first (`diskutil umount`, `gio mount -u`). `crypto lock <VAULT> --force` is
refused on the plain `webdav` fallback with exit `7` ("does not support forced unmount"): there is
nothing in the system mount table to force, and Cryptomator gives `FallbackMounter` no
`UNMOUNT_FORCED` capability either — lock it without `--force`. `webdav-gio` has none either (a
gvfs mount is not a mount point of its own); only `webdav-applescript` has one,
`diskutil umount force`. A killed `webdav` daemon leaves nothing behind at all — there was
never a volume — so its vault is `LOCKED` again, never `STALE_MOUNT`. A Finder volume from
`webdav-applescript` does outlive its daemon and is reported as `STALE_MOUNT`, which
`crypto lock <VAULT> --force` takes down by path. A gvfs mount from `webdav-gio` outlives it too,
but gvfs mounts are not mount points of their own and `crypto` cannot see them; the server behind
it is dead either way, and `gio mount -u "dav://…"` clears the entry.

**Limitations.**

- One daemon serves one vault, so two unlocked vaults need two ports. The desktop app's shared,
  reference-counted WebDAV host does not exist here.
- **No extended attributes.** WebDAV has no notion of them, so Finder tags, quarantine flags and
  resource forks do not survive the trip — and nothing sweeps `.DS_Store` or `._*` side cars out of
  the vault the way the macOS FUSE back ends do; whatever the client writes is stored.
- **Symbolic links inside the vault are invisible** over WebDAV — neither listed nor addressable —
  exactly as in Cryptomator's own servlet.
- As a consequence, **a directory whose only remaining child is a symlink cannot be deleted** over
  WebDAV: the client never sees the link, so it cannot remove it first, and `DELETE` on the
  directory answers `409` for as long as the link is there. Remove it through a FUSE mount, or with
  `crypto rm`.
- Names are normalised to **NFC** on the way in, and answers are not translated back to NFD for
  macOS clients (Cryptomator's servlet does that for the `WebDAVFS` user agent; the user agent is
  not visible from inside the file system implementation).
- A single `Content-Range` PUT that would leave a gap of more than **256 MiB** of zeros is refused
  with `413`, rather than materialising the zeros. A local HTTP request is not a syscall, and
  nothing else bounds it.
- The server answers `DAV: 1,2,3,sabredav-partialupdate` where Cryptomator answers `DAV: 1, 2`.
  Those are the classes `dav-server` really implements; class 2 locking is there, so Finder and
  `gio` are happy.
- Disk usage (`quota-available-bytes`/`quota-used-bytes`) is not reported on macOS 15.4 and newer,
  where reporting it delays the mount by 90 seconds — the same suppression the desktop app has.

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

## Health checks

`crypto health <VAULT>` reads the ciphertext of a locked vault and reports everything that does not
fit the vault format. These are the checks the desktop app runs in its "Vault Health" window, with
the same names and the same wording, so the two reports can be compared line by line.

| Check | `--check` name | What it looks at |
|---|---|---|
| Directory Check | `dirid` | every `dir.c9r`: whether its target content directory exists, whether a directory id is used twice, whether every content directory is reachable, and whether it has its `dirid.c9r` backup |
| Resource Type Check | `type` | whether each `.c9r`/`.c9s` directory says what it is (`dir.c9r`, `symlink.c9r`, `contents.c9r`) |
| Shortened Names Check | `shortened` | whether each `.c9s` directory has a `name.c9s` whose content hashes back to the directory's own name |

Findings have four severities: `GOOD` (nothing to say), `INFO` (worth knowing, no impact), `WARN`
(the structure is damaged, no data lost yet) and `CRITICAL` (data was lost — restore from a backup
if you can):

| Severity | Findings |
|---|---|
| `GOOD` | `HealthyDir`, `KnownType`, `ValidShortenedFile` |
| `INFO` | `MissingDirIdBackup`\*, `LooseDirFile`\* |
| `WARN` | `MissingContentDir`\*, `OrphanContentDir`\*, `TrailingBytesInNameFile`\*, `LongShortNamesMismatch`\* |
| `CRITICAL` | `DirIdCollision`, `EmptyDirFile`, `ObeseDirFile`, `UnknownType`\*, `AmbiguousType`, `MissingLongName`, `ObeseNameFile`, `NotDecodableLongName` |

\* has a fix.

    crypto health Secret                       # report everything, exit 11 if anything is CRITICAL
    crypto health Secret --check dirid,type    # only two of the three checks
    crypto health Secret --fail-on WARN        # exit 11 for warnings too
    crypto health Secret --fix                 # repair what can be repaired, then check again
    crypto health Secret --no-report           # do not write the log file

The vault must be `LOCKED` (exit `5` otherwise), and a vault of an older format is sent to
`crypto migrate` rather than checked. "Locked" here means locked *as far as `crypto` can tell*: the
runtime check only asks `crypto`'s own daemon, and a vault the **Cryptomator desktop app** has
unlocked and mounted is indistinguishable from a locked one on disk. `--fix` moves, renames and
deletes nodes, so it prints a warning to stderr when the desktop app answers on its IPC socket (see
[Settings file](#settings-file)) — lock the vault there first. A run without `--fix` only reads and
stays silent.

### `--fix`

`--fix` applies the repair of every finding that has one and is at least as severe as
`--fix-severity` (default `WARN`; `INFO` and `CRITICAL` are the other two values — `INFO` is
accepted here, unlike for `--fail-on`, because the two `INFO` findings are the ones a freshly
migrated vault has). Then it runs the checks again, because a repair can uncover the next finding:
adopting an orphan creates a directory that in turn lacks its `dirid.c9r` backup. That loop runs to
a fixpoint, at most **three rounds**, and each finding is attempted once per run. The exit code
comes from the final run.

A fix that fails does not stop the run: it is printed as a `FAILED` line, marked `"fixed": false`
in the JSON, and the loop carries on. Plenty of findings have no fix at all — an empty `dir.c9r`, a
`name.c9s` that is simply gone, two directories claiming the same directory id: nothing in the vault
still holds what it would take to reconstruct them. **`--fix` is not a way back to a healthy
vault**, it is a way to stop losing more.

Orphaned content directories are not deleted. Their contents are adopted into a `/LOST+FOUND`
directory inside the vault, under one subdirectory per orphan named after the orphan's hash, with
the original file names where those could still be decrypted and `file1_<run>`,
`directory2_<run>`, `symlink3_<run>` … where they could not.

### The report

Unless `--no-report` is given, a text report is written into the current directory as
`healthReport_<vault>_<YYYYMMDD-HHMMSS>.log` — the desktop app's file name, with a **UTC** timestamp
— in the format of Java's `ReportWriter`, banner and `Check <name>` sections included, so a report
from either program reads the same. That automatic file never replaces an existing one (a second run
in the same second becomes `…-1.log`); `--report FILE` writes exactly where it is told and does
replace. The report lists every finding including the `GOOD` ones, and it contains ciphertext paths
only — never a cleartext file name, never the password.

`--json` prints one object: `vault`, `path`, `checks`, `failOn`, `report` (the absolute path, or
`null`), `summary` (`{critical, warn, info, good}`) and `findings`, each with `check`, `kind`,
`severity`, `message`, `paths`, `fixable` and `fixed`. With `--fix` it gains `fixSeverity`, `rounds`
and `fixes` (one `{kind, paths, describe, outcome}` per attempt); `findings` and `summary` then
describe the state *after* the repairs.

## Migrating older vaults

Vaults created before Cryptomator 1.6 use an older on-disk format. `crypto` reads format 8 only and
reports such a vault as `NEEDS_MIGRATION`; `crypto migrate` brings it forward, one format at a time,
until it is a format 8 vault:

| Step | What changes |
|---|---|
| 5 → 6 | the passphrase is re-encoded as Unicode NFC and the masterkey file is rewritten |
| 6 → 7 | every name in the vault is rewritten from BASE32 to base64url, directories and symlinks become `.c9r` directories, long names move from `m/…lng` into `name.c9s`, and `m/` is deleted (but see *skipped nodes* below) |
| 7 → 8 | `vault.cryptomator` is written (format 8, `SIV_CTRMAC`, shortening threshold 220) and the masterkey file loses its version |

    crypto migrate Old --dry-run     # list the steps and the renames, change nothing
    crypto migrate Old               # ask for confirmation, then migrate
    crypto migrate Old --yes         # no question (required when there is no terminal)

The migration happens in place. Before a step rewrites the masterkey file it copies it next to
itself as `masterkey.cryptomator.<checksum>.bkup`, exactly like the desktop app — but the 6 → 7 step
renames every file in the vault and there is no undo for that, so **make a backup of the whole vault
first**. Nothing is written before the password has been checked. A vault that is already at format
8 is not an error: `crypto migrate` says so and exits `0`, as does a run answered with anything but
`y` at the confirmation. A vault older than format 5 is refused (exit `5`); open it once with
Cryptomator 1.4 or newer first.

A format 5 vault predates the rule that a passphrase is normalised to NFC before it reaches scrypt —
normalising it is exactly what the 5 → 6 step does. `crypto` therefore retries a rejected format 5
passphrase in its decomposed (NFD) form, and after the migration the vault opens with the composed
one. If the password is stored in the keychain, that entry is updated to the normalised form, so
unlocking keeps working; a keychain that refuses is a warning, not a failed migration.

The steps are separately durable: a run that dies between two of them says which format the vault
reached, and running `crypto migrate` again continues from there. A migrated format 7 vault has no
directory-id backups (that format had none), which `crypto health` reports as `INFO
MissingDirIdBackup` — `crypto health <VAULT> --fix --fix-severity INFO` writes them, and the command
says so when it is done.

### Skipped nodes

The 6 → 7 step cannot migrate every node: a `<32 chars>.lng` whose entry under `m/` is missing,
unreadable or absurdly large has no readable long name, a name that is not valid BASE32 decodes to
nothing, and a node whose target name is taken three times over (`""`, `_1`, `_2`) has nowhere to
go. Such a node keeps its old name, and `crypto migrate` says so — on stderr, in the summary line
(`N node(s) were left with their old names`) and under `skipped` in `--json`. `--dry-run` lists the
same nodes before anything is written.

**`m/` is then kept**, which is a deliberate deviation from the desktop app: it deletes the
metadata directory unconditionally, and with it the only copy of those nodes' long names. A
leftover `m/` costs nothing (formats 7 and 8 never look at it), but `crypto migrate` never
revisits a vault it already brought to format 8 -- once the skipped nodes are dealt with, remove
`m/` by hand.

While it works, the migration probes the storage by creating and deleting `<vault>/c` — Java's
`FileSystemCapabilityChecker`, which removes that directory recursively whether or not the probe
created it. A `c/` directory of your own in the vault root will be gone afterwards. `--dry-run`
never probes and never deletes anything.

Like `crypto health --fix`, `crypto migrate` only knows about `crypto`'s own daemon. A vault the
**Cryptomator desktop app** has unlocked looks `LOCKED` here, so the command warns on stderr when
the app answers on its IPC socket (see [Settings file](#settings-file)); `--dry-run` writes nothing
and stays silent.

`--json` prints `{vault, path, from, to, steps, migrated, renamed, skipped, backups,
keychainUpdated}`, or `{…, renames: [{old, new}], skipped, dryRun: true}` for `--dry-run`.

## Password sources

A password is taken from the first source that is present, so a password never has to appear on the
command line:

0. `--password-keychain` – the keychain and nothing else. It is checked before every other source,
   including `$CRYPTO_PASSWORD`, and a vault with nothing stored fails with exit `8` instead of
   falling back or asking
1. `--password-stdin` – the next line of standard input (the trailing newline is removed)
2. `--password-file <FILE>` – at most 5000 bytes of UTF-8, one trailing newline removed
3. `--password-env <VAR>` – the named environment variable (it must be set)
4. `$CRYPTO_PASSWORD` – the implicit fallback when no flag is given
5. the keychain, implicitly – when `useKeychain` is on, a provider works on this machine, you did
   not pass `--no-keychain`, and a password is stored for this vault. Nothing stored means this step
   is simply skipped
6. an interactive prompt, but only when standard input is a terminal

`$CRYPTO_PASSWORD` deliberately outranks the implicit keychain step: it is a source a script sets on
purpose, and it can never make the operating system open a dialog. `--no-keychain` removes step 5
from the list for one run and turns step 0 into exit `8` (there is no keychain to read), whatever
`settings.json` says — and the flags are mutually exclusive, so `--password-keychain` together with
any other `--password-*` flag is a usage error.

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

`password change` and `recovery-key show` / `recovery-key reset-password` need the vault to be
`LOCKED` in the same sense `crypto fs` does (exit `5` otherwise): a vault a daemon is serving, or one
a crashed daemon left mounted, holds a live key that rewriting the masterkey file would invalidate.
`crypto lock` — with `--force` for the volume a crashed daemon left behind — is the way out.
`recovery-key validate` takes no vault and is unaffected.

## Stored passwords (keychain)

`crypto` keeps vault passwords where the Cryptomator desktop app keeps them, so a password saved in
one program is found by the other.

| | macOS | Linux |
|---|---|---|
| backend | the login keychain, generic password | FreeDesktop Secret Service (gnome-keyring, KeePassXC, …) |
| provider classes | `org.cryptomator.macos.keychain.MacSystemKeychainAccess` (alias `macos`), `…TouchIdKeychainAccess` (alias `touchid`) | `org.cryptomator.linux.keychain.GnomeKeyringKeychainAccess` (alias `gnome-keyring`, the default), `…SecretServiceKeychainAccess` (alias `secret-service`), `…KDEWalletKeychainAccess` (aliases `kde`, `kwallet`) |
| where the entry lives | service `Cryptomator`, account = the vault id | the default collection (falling back to `login`), item label `Cryptomator`, attributes `Vault` = the vault id and — for `secret-service` only — `Name` = the display name |
| found by | service and account | the `Vault` attribute alone, so a renamed vault keeps its password |

`$CRYPTO_KEYCHAIN_SERVICE` overrides the service name (macOS) and the item label (Linux) for a whole
environment; it is the equivalent of the desktop app's
`cryptomator.integrationsMac.keychainServiceName`.

On macOS the *label* Keychain Access shows for an item `crypto` writes is the vault's display name
(its id when it has no name), while the desktop app labels its items `Cryptomator`. Only the label
differs: both programs address the same item by service and account, so each finds what the other
wrote.

### Commands

| Command | What it does |
|---|---|
| `crypto password store <VAULT>` | asks for the password, **verifies it against the vault** and only then saves it |
| `crypto password forget <VAULT>` | removes the saved password; nothing stored is not an error |
| `crypto unlock <VAULT> --store-password` | saves the password once the vault is mounted (`--no-store-password` spells out the default) |
| `crypto vault create <PATH> --store-password` | saves the new password |
| `crypto vault remove <VAULT> --forget-password` | removes the saved password along with the registration |
| `crypto keychain test` | names the provider and does a store/load/delete round trip with a throwaway key |

`crypto password change` and `crypto recovery-key reset-password` carry a stored password along by
themselves, exactly like the desktop app: if one is stored it follows the change, and if none is
stored nothing happens. A keychain that refuses at that point is a warning, not a failed password
change — the new password is already on disk by then, and `crypto password store <VAULT>` repairs the
entry. A `--store-password` that fails *after* the vault is mounted is a warning too, for the same
reason: the mount stands.

### Settings

    crypto config set useKeychain false                 # never touch a keychain
    crypto config set keychainProvider secret-service   # pick a backend by alias or class name

`keychainProvider` takes an alias — `macos`, `touchid`, `secret-service`, `gnome-keyring`, `kde`,
`kwallet` — or a fully qualified Java class name; what is written to `settings.json` is always the
class name, so the desktop app keeps reading its own setting. Anything else is refused with exit `2`.
A provider that names nothing usable on this machine is *not* an error: the highest-priority
provider that does work takes over, exactly as `KeychainModule.provideKeychainAccessProvider` does.
`--no-keychain` overrides both settings for one run.

`crypto keychain test` is the command to run when an unlock does not find a stored password. It
prints the provider, whether it is supported and whether it is locked, and the result of a round
trip — and only *then* fails with exit `8` if something went wrong, so the diagnosis is on standard
output either way:

    $ crypto keychain test --json
    {
      "provider": "org.cryptomator.macos.keychain.MacSystemKeychainAccess",
      "displayName": "macOS Keychain",
      "supported": true,
      "locked": false,
      "roundTrip": "ok"
    }

The throwaway key is `crypto-selftest-<random>` and is deleted again, so the test can never touch a
vault's own entry.

### Things worth knowing

- **Every keychain call gives up after 30 seconds**, and choosing a provider gives each candidate 5
  seconds to say whether it works at all. A call that runs out of time reports exit `8` with *the
  keychain did not answer within 30 s; a system dialog may be waiting for you*. Without that, a
  dialog nobody is looking at would hang the command forever. Both budgets are compiled in. Giving
  up is not cancelling: the worker that made the call keeps running with its copy of the password
  until the backend answers, so a `store` that timed out — and was reported as *not stored* — may
  still land seconds later. Run `crypto keychain test` and, if in doubt, `crypto password
  store <VAULT>` again; the entry is overwritten, never doubled.
- **macOS asks the first time.** An entry written by Cryptomator.app belongs, as far as the keychain
  ACL is concerned, to Cryptomator.app; `crypto` is a different program, so macOS puts up a dialog
  asking whether it may be read. Choose **“Always Allow”** and it asks once. Until release binaries
  are signed with a stable Developer-ID identity, a rebuilt or re-signed binary can count as a
  different program and ask again. Entries `crypto` wrote itself do not prompt. Over SSH or in any
  session without a window server there is nobody to answer, so use `--password-stdin`,
  `--password-file` or `$CRYPTO_PASSWORD` there.
- **Touch ID is read-only in effect.** A `keychainProvider` of `TouchIdKeychainAccess` is served by
  the plain macOS backend — the items are the same ones, so reading, updating and deleting all work
  — but a password `crypto` writes carries no Touch-ID access control.
- **macOS: old entries are migrated when they are read.** Cryptomator once stored items under the
  service name `"Cryptomator\0"`, with a trailing NUL. When nothing is found under the current
  service name, `crypto` looks there too and moves a hit across, the way
  `MacKeychain.tryMigratePassword` does.
- **Linux needs a running Secret Service** on the session bus — `gnome-keyring-daemon
  --components=secrets`, KeePassXC with its Secret Service integration, and so on. Without one the
  implicit keychain step is simply skipped, and `crypto keychain test` says why.
- **KWallet is not supported.** `KDEWalletKeychainAccess` exists only to report itself unusable and
  to point at `crypto config set keychainProvider secret-service`, which KWallet's own Secret Service
  bridge serves.
- **Keychain calls are not concurrent.** One `crypto` process makes one keychain call at a time; two
  processes racing for the same entry are not coordinated by anything but the backend itself.
- **`$CRYPTO_KEYCHAIN_FAKE=<file>` is for tests only.** It replaces every real backend with a JSON
  file (mode 0600) and, while it is set, it is the *only* provider — nothing can reach the real
  keychain by accident. It stores passwords in the clear; do not point it at anything you keep.
  Every run that uses it says so on standard error, naming the file.
- **Warnings go to standard error.** Anything the keychain layer reports on the way — a provider
  whose probe did not answer in 5 seconds, an entry that could not be cleaned up — is printed as
  `warning: …`, so `--json` output on standard output stays one machine-readable document.

## Settings file

`crypto` reads and writes the same `settings.json` as the Cryptomator desktop app:

- macOS: `~/Library/Application Support/Cryptomator/settings.json`
- Linux: `~/.config/Cryptomator/settings.json`, then `~/.Cryptomator/settings.json`

`--settings <PATH>` overrides the location for a single run, `$CRYPTO_SETTINGS_PATH` for the whole
environment (a `:`-separated list like Java's `-Dcryptomator.settingsPath`; the first entry is the
file that gets written). Saving is atomic (`settings.json.<pid>.tmp` + rename) and keeps unknown fields, so
a file written by the desktop app survives a round trip.

Every write additionally takes an exclusive `flock` on **`settings.json.lock`**, an empty 0600 file
next to `settings.json` that is created once and never removed. Load, change and rename happen under
that one lock, so two `crypto` processes never lose each other's changes; a lock somebody else holds
is retried for five seconds and then reported as `… is locked by another process` (exit `1`).

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
| `webdavBind` | The address the WebDAV server binds to. Only a loopback address is accepted — the server has no authentication; `CRYPTO_WEBDAV_ALLOW_NONLOOPBACK=1` overrides that, at your own risk. It is read only by a mounter that binds a port (the WebDAV ones), so an unusable value fails a WebDAV unlock with exit `6` naming the key and leaves a FUSE unlock of the same daemon alone | `127.0.0.1` |

    crypto config set mountPointsDir ~/mnt     # relative paths resolve against the shell's cwd
    crypto config set defaultMounter fuse-t
    crypto config get mountPointsDir           # the effective value, default included
    crypto config set webdavBind 127.0.0.2     # a non-loopback address is refused (exit 2)

Because the file is shared, **close the desktop app before `crypto vault add` or `crypto vault
remove`**: the running app keeps its own copy in memory and overwrites the file when it exits — and
it takes no lock, so `settings.json.lock` cannot serialise against it. A command that writes settings
(`vault create/add/remove/set`, `config set`, `unlock`) therefore prints a warning to stderr when the
app answers on its IPC socket, `ipc.socket` next to `settings.json` (the app's own
`-Dcryptomator.ipcSocketPath`; `$CRYPTO_DESKTOP_IPC_SOCKET` overrides the path). A socket file with
nobody listening — what a crashed app leaves behind — does not count as running.

The same probe carries a second, larger warning: `crypto health --fix`, `crypto migrate` and
`crypto recovery-key restore` rewrite the *contents* of a vault, and the automatic "is anybody
serving this vault?" check only asks `crypto`'s own daemon. A vault the desktop app has unlocked
and mounted looks `LOCKED` on disk, so those three commands say **lock this vault in the app
first** when it answers.
A `settings.json` that cannot be parsed is reported as an error — unlike the desktop app, `crypto`
never silently replaces it.

## Test fixtures

`tests/fixtures/` holds twelve reference vaults created with the real Java implementation. The Rust
tests read them without Java. Eight of them are ordinary format 8 vaults written by cryptofs 2.10.0
/ cryptolib 2.2.2; the other four exist for the health checks and the migration:

- **`broken_health`** — a healthy `SIV_GCM` vault damaged on the ciphertext level in nine ways
  (orphaned content directory, missing `dirid.c9r`, missing content directory, a loose `dir.c9r`, a
  repeated directory id, a node of unknown type, a mismatched, a truncated and a missing
  `name.c9s`). `expected-findings.json` next to its manifest lists what the *real* cryptofs health
  checks report for it, and the Rust tests compare against that file rather than against
  themselves.
- **`legacy_v7`, `legacy_v6`, `legacy_v5`** — pre-format-8 vaults written by the cryptofs release
  that actually produced each format (1.9.15, 1.8.9 and 1.3.2), with `.lng` long names in 6 and 5
  and, in `legacy_v5`, an NFD umlaut passphrase that only the 5 → 6 migration step normalises.

To regenerate them you need a JDK 25+ and Maven (cryptofs 2.10.0 is compiled for 25; the three
legacy generators are content with 21):

    mvn -q -f tools/fixture-gen/pom.xml compile exec:exec                       # the eight format 8 vaults
    mvn -q -f tools/fixture-gen/pom.xml compile exec:exec \
        -Dfixture.cmd=broken -Dfixture.arg1=$(pwd)/tests/fixtures               # broken_health
    mvn -q -f tools/fixture-gen/legacy-v7/pom.xml compile exec:exec             # legacy_v7
    mvn -q -f tools/fixture-gen/legacy-v6/pom.xml compile exec:exec             # legacy_v6
    mvn -q -f tools/fixture-gen/legacy-v5/pom.xml compile exec:exec             # legacy_v5

The three legacy generators are standalone Maven modules, not part of the reactor — their class
paths are mutually incompatible — and the first run of each needs network, because those cryptofs
releases are on Maven Central but not in `~/.m2`. Reading the committed fixtures needs none of that.

The output directory defaults to `tests/fixtures` and can be overridden with
`-Dfixture.arg1=<path>` (absolute — `exec:exec` resolves relative paths against the module
directory). The same harness opens a vault written by `crypto` and prints its cleartext tree, which
is how the interop test checks that the Java implementation accepts our vaults — including the
vaults `crypto migrate` lifted out of formats 7, 6 and 5, and one whose key files
`crypto recovery-key restore` rebuilt:

    mvn -q -f tools/fixture-gen/pom.xml compile exec:exec -Dfixture.cmd=verify -Dfixture.arg1=<vault> -Dfixture.arg2=<passphrase>
    cargo test -p crypto --test java_interop -- --ignored

Regeneration changes nonces and salts but keeps each vault's masterkey and the passphrase
`test-password-123` (`legacy_v5` is the exception: it needs a non-ASCII one). Commit a regenerated
vault together with its manifest; see `tools/fixture-gen/README.md`.

## License

AGPL-3.0-only. The vault format implementation is a port of
[cryptolib](https://github.com/cryptomator/cryptolib) and [cryptofs](https://github.com/cryptomator/cryptofs) (AGPL-3.0).
