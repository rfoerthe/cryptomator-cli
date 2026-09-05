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
