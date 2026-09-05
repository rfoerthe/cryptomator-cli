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
- Interop is now bidirectional: besides the vaults `crypto` creates, a tree that `CryptoFs` writes
  (nesting, 200-character names, unicode incl. NFD input and emoji, sizes at the chunk boundaries
  32767/32768/32769/65536, symlinks, a rename and an overwrite) is opened by the real cryptofs, and
  its manifest must equal `crypto fs tree --json --hash` entry for entry
  (`cargo test -p crypto --test java_interop -- --ignored`).
- Deliberate deviations from cryptofs, all of them chosen for a short-lived CLI process:
  1. Relative symlink targets resolve against the link's parent directory (POSIX semantics);
     cryptofs resolves them against the vault root.
  2. A vault opened read-only never resolves sync conflicts on disk. cryptofs renames the
     conflicting node anyway; `crypto` reports it as an event and leaves it out of the listing.
  3. The directory cache has no 20 s expiry (M4 adds it with the daemon) — a CLI process is short
     lived, and a stale entry cannot outlive it.
  4. `fs mv` never moves *into* an existing directory: the destination is always the complete new
     path, so a typo renames instead of silently filing the source away somewhere.
  5. `.c9s` node directories for shortened names are only created when a file is opened for
     writing, so a failed read never leaves an empty node directory behind.
- Two further rulings the code carries: `dirid.c9r` is never swept when a directory delete fails
  (Java's `CiphertextDirectoryDeleter` removes it with the other leftovers and leaves a surviving
  directory without its dir id backup), and `bytes_written` counts only the caller's bytes, not the
  zero-filled gap of a sparse write.
- Not in M3 (the spec assigns them to M4): cache expiry, `.c9u`/`FileIsInUseEvent` creation
  (Hub only) and `fs` access to a mounted vault.
