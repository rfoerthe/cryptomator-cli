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
