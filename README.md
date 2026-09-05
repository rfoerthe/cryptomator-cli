# crypto – Cryptomator on the command line

`crypto` is a Rust command line client for [Cryptomator](https://cryptomator.org) vaults (vault format 8)
for macOS and Linux. It shares the desktop app's `settings.json` and keychain entries.

Status: early development. See `docs/superpowers/specs/2026-09-04-crypto-cli-design.md`.

## Build

    cargo build --release

## Commands

Every command accepts `--settings <PATH>` and `--json`. Vaults are addressed by id, display name or
path (`<VAULT>` below).

| Command | What it does | Example |
|---|---|---|
| `vault create` | Creates a vault directory, writes `masterkey.cryptomator`, `vault.cryptomator`, the root dir and the readme files, and registers it | `crypto vault create ~/Vaults/Secret --name Secret` |
| `vault add` | Registers an existing vault directory | `crypto vault add ~/Vaults/Secret` |
| `vault list` | Lists registered vaults with id, name, path and state | `crypto vault list --json` |
| `vault info` | Shows the settings and the vault configuration of one vault | `crypto vault info Secret` |
| `vault set` | Changes per-vault settings (mount point, mounter, flags, auto-lock, …) | `crypto vault set Secret --mount-point ~/mnt/secret --read-only true` |
| `vault remove` | Unregisters a vault; its files stay on disk | `crypto vault remove Secret` |
| `config get` | Prints one or all global settings | `crypto config get port` |
| `config set` | Changes a global setting (`mountService`, `port`, `useKeychain`, `keychainProvider`, `debugMode`) | `crypto config set port 42427` |
| `password change` | Changes the vault password and backs the old masterkey file up as `.bkup` | `crypto password change Secret --new-password-stdin` |
| `recovery-key show` | Prints the 44-word recovery key of a vault (needs the password) | `crypto recovery-key show Secret` |
| `recovery-key reset-password` | Sets a new password from a recovery key, without the old one | `crypto recovery-key reset-password Secret --recovery-key-stdin` |
| `recovery-key validate` | Checks whether a recovery key is well-formed | `printf '%s' "$KEY" \| crypto recovery-key validate --recovery-key-stdin` |

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
