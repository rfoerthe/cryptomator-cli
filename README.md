# crypto – Cryptomator on the command line

`crypto` is a Rust command line client for [Cryptomator](https://cryptomator.org) vaults (vault format 8)
for macOS and Linux. It shares the desktop app's `settings.json` and keychain entries.

Status: early development. See `docs/superpowers/specs/2026-09-04-crypto-cli-design.md`.

## Build

    cargo build --release

## Commands

### `crypto recovery-key validate --recovery-key-stdin`

Checks whether a recovery key is well-formed: 44 dictionary words, an even word count, and a valid
CRC-32 checksum over the 64-byte masterkey it encodes. It does not touch a vault and does not reveal
whether the key belongs to any particular vault.

The key is read from standard input (it never appears in the process list or the shell history) and
`--recovery-key-stdin` is required, so the source is always explicit:

    printf '%s' "$RECOVERY_KEY" | crypto recovery-key validate --recovery-key-stdin

It prints `valid` and exits `0`, or prints `invalid` and exits `4`. Error messages never quote the
input.

## Test fixtures

`tests/fixtures/` holds eight reference vaults created with the real Java implementation
(cryptofs 2.10.0 / cryptolib 2.2.2). The Rust tests read them without Java. To regenerate them you
need a JDK 21+ and Maven:

    mvn -q -f tools/fixture-gen/pom.xml compile exec:exec

The output directory defaults to `tests/fixtures` and can be overridden with `-Dfixtures.out=<path>`.
Regeneration changes nonces and salts but keeps each vault's masterkey and the passphrase
`test-password-123`; see `tools/fixture-gen/README.md`.

## License

AGPL-3.0-only. The vault format implementation is a port of
[cryptolib](https://github.com/cryptomator/cryptolib) and [cryptofs](https://github.com/cryptomator/cryptofs) (AGPL-3.0).
