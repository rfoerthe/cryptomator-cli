# fixture-gen

Java harness around the real cryptofs 2.10.0 / cryptolib 2.2.2. It has three modes: it creates the
reference vaults under `tests/fixtures/`, it creates the deliberately damaged vault `broken_health`
for the health-check tests, and it opens a vault written by `crypto` to prove that the Java
implementation accepts it. The three generators for the pre-format-8 reference vaults live in the
standalone modules `legacy-v7/`, `legacy-v6/` and `legacy-v5/` — see "Legacy fixtures" below.

Regenerate the fixtures (JDK 25+, Maven — cryptofs 2.10.0 is compiled for 25):

    mvn -q -f tools/fixture-gen/pom.xml compile exec:exec

Regenerate the damaged vault `tests/fixtures/broken_health` (`-Dfixture.arg1` must be **absolute**;
`exec:exec` resolves relative paths against the module directory, not the repository root):

    mvn -q -f tools/fixture-gen/pom.xml compile exec:exec \
        -Dfixture.cmd=broken -Dfixture.arg1=$(pwd)/tests/fixtures

`broken` first writes a healthy SIV_GCM vault (threshold 220) and then damages it on the ciphertext
level in nine ways; `expected-findings.json` next to `fixture.json` lists the nine findings the real
cryptofs health checks report for it, one object per finding with `check` (`dirid`, `type`,
`shortened`), `severity` (`INFO`, `WARN`, `CRITICAL`), `result` (the Java `DiagnosticResult` class)
and a vault-relative `path`:

| # | damage | finding |
|---|---|---|
| 1 | the `.c9r` node of `/orphaned` is deleted, its content dir stays | `dirid` WARN `OrphanContentDir` |
| 2 | `dirid.c9r` removed from the content dir of `/nodirid` | `dirid` INFO `MissingDirIdBackup` |
| 3 | the content dir of `/nocontent` is deleted, its `dir.c9r` stays | `dirid` WARN `MissingContentDir` |
| 4 | an empty `dir.c9r` in the root content dir (parent ends in neither `.c9r` nor `.c9s`) | `dirid` INFO `LooseDirFile` |
| 5 | a new node whose `dir.c9r` repeats the dir id of `/keep` | `dirid` CRITICAL `DirIdCollision` |
| 6 | a new `.c9r` directory with neither `dir.c9r` nor `symlink.c9r` nor `contents.c9r` | `type` CRITICAL `UnknownType` |
| 7 | `name.c9s` of the `M…` node replaced by a synthetic, otherwise unused long name | `shortened` WARN `LongShortNamesMismatch` |
| 8 | `garbage` appended to the `name.c9s` of the `T…` node | `shortened` WARN `TrailingBytesInNameFile` |
| 9 | `name.c9s` of the `N…` node deleted | `shortened` CRITICAL `MissingLongName` |

No damage leaves an empty directory behind — git cannot track those, so the checked-in fixture would
otherwise differ from the generated one. Damage 1 therefore removes the whole node instead of only
its `dir.c9r`, and `/orphaned` and `/nodirid` keep ordinary child files.

`fixture.json` gained a `kind` field: `clean` for the ordinary fixtures, `broken` for this one. The
Rust tests that walk every fixture (`fixtures_content.rs`, `fixtures_masterkey.rs`) skip everything
that is not `clean`; manifests written before the field existed count as clean.

Verify a foreign vault — prints the cleartext tree as JSON on stdout and exits `0`, or prints a stack
trace and exits `3`:

    mvn -q -f tools/fixture-gen/pom.xml compile exec:exec \
        -Dfixture.cmd=verify -Dfixture.arg1=/path/to/vault -Dfixture.arg2=<passphrase>

The passphrase in `-Dfixture.arg2` is visible in the process list of every user on the machine, so
this harness is for test vaults only — never pass a real vault's passphrase to it.

The cipher combo and the shortening threshold are read from the vault's own `vault.cryptomator`, so
the same call verifies `SIV_GCM` and `SIV_CTRMAC` vaults. `crates/crypto/tests/java_interop.rs`
drives this mode (`cargo test -p crypto --test java_interop -- --ignored`).

`exec:exec` forks a JVM; `exec:java` cannot be used because `java.nio.file.spi.FileSystemProvider`
discovers the cryptofs provider only via the system class loader. The command line comes from the
properties `fixture.cmd` (default `gen`), `fixture.arg1` (default `tests/fixtures` next to the POM)
and `fixture.arg2` (default empty; empty arguments are dropped before `Gen` parses them).

Regeneration changes nonces and salts but keeps each vault's masterkey (SHA-512 of the fixture name) and passphrase
`test-password-123`. Commit the result; Rust tests read the fixtures without Java.

Regeneration is not byte-reproducible: cryptofs draws a random scrypt salt, a random `jti` for
`vault.cryptomator`, a random UUID for every directory id and random nonces for every file. What is
stable is the masterkey, the cleartext structure and — because SIV name encryption is deterministic —
every ciphertext name below the root content dir `d/<hash of "">`. For `broken_health` this means
seven of the nine paths in `expected-findings.json` survive a regeneration unchanged; only the two
content dirs of `/orphaned` and `/nodirid` are named after random directory ids. Always commit
`expected-findings.json` together with the vault it describes.

## Legacy fixtures (vault formats 7, 6 and 5)

`tests/fixtures/legacy_v{7,6,5}` are written by three **standalone** Maven modules next to this one,
each pinning the cryptofs release that actually produced that vault format. They are deliberately not
a reactor: their class paths are mutually incompatible, and `tools/fixture-gen/pom.xml` has to stay a
single-module build because `crates/crypto/tests/java_interop.rs` points at exactly that POM.

| module | cryptofs | `Constants.VAULT_VERSION` | writes |
|---|---|---|---|
| `legacy-v7/` | 1.9.15 | 7 | `legacy_v7` |
| `legacy-v6/` | 1.8.9 | 6 | `legacy_v6` |
| `legacy-v5/` | 1.3.2 | 5 | `legacy_v5` |

The first build **needs network**: these three artifacts are not in `~/.m2` and Maven downloads them
from Maven Central. Without network the build stops with `Could not resolve dependencies` — do not
work around it by changing the pinned versions.

    mvn -q -f tools/fixture-gen/legacy-v7/pom.xml compile exec:exec
    mvn -q -f tools/fixture-gen/legacy-v6/pom.xml compile exec:exec
    mvn -q -f tools/fixture-gen/legacy-v5/pom.xml compile exec:exec
    cargo test -p cryptomator-core --test migration --locked

`fixture.arg1` defaults to `<module>/../../../tests/fixtures`, i.e. the repository's fixture
directory; it is absolute because `exec:exec` resolves relative paths against the module directory.
All three run on JDK 26 (only `sun.misc.Unsafe` deprecation warnings from the bundled Guava, and an
SLF4J "no binding" notice — neither module declares a logging binding, because slf4j-simple 2.x would
clash with the slf4j-api 1.7.x these cryptofs versions bring).

### What each format looks like on disk

| | format 7 | format 6 | format 5 |
|---|---|---|---|
| vault config | none — the format lives in `masterkey.cryptomator`'s `version` | none | none |
| file names | `BASE64URL(SIV) + .c9r` | base32 of the SIV ciphertext | same as 6 |
| directories | `<name>.c9r/` holding `dir.c9r` | file `0<base32>` holding the dir id | same as 6 |
| symlinks | `<name>.c9r/symlink.c9r` | file `1S<base32>` | **none** — cryptofs 1.3.2 cannot create them |
| long names | `<BASE64URL(SHA1)>.c9s/` with `name.c9s` + `contents.c9r`, threshold 220 ciphertext chars | `<BASE32(SHA1)>.lng` in `d/`, inflated form in `m/xx/yy/*.lng`, threshold 129 | same as 6 |
| `m/` | absent | present | present |
| masterkey `version` | 7 | 6 | 5 |

Formats 5 and 6 are the same structure; they differ only in the passphrase that reaches scrypt. Up to
cryptofs 1.3.x the passphrase went into the KDF exactly as typed (format 5); from 1.4.0 on
`CryptoFileSystemProvider.initialize` and `CryptoFileSystemProperties.Builder.withPassphrase`
normalise it to NFC, and `Version6Migrator` rewrites an existing masterkey file accordingly
(format 6). `legacy_v5` therefore uses `tästpaß-123` in **NFD** (`a` + U+0308); only that form opens
it, and the manifest carries the NFC form as `passphraseNfc` for the migration tests. `legacy_v6` and
`legacy_v7` use the usual `test-password-123`.

`legacy_v5` and `legacy_v6` also carry an unreferenced second `.lng` file under `m/` (cryptofs 1.3.x
and 1.6.x persist the deflated form of the `0`-prefixed *directory* variant of a long name while
probing whether the node is a directory). That is the real library's output, not a defect.

### Manifest schema

Every legacy fixture has a `fixture.json` — and, unlike the format-8 fixtures, **no** `expected.json`
and **no** `masterkeyHex`: these vaults are only ever opened with their passphrase, and `kind` keeps
them out of the tests that walk every fixture.

```json
{ "name": "legacy_v5", "kind": "legacy", "format": 5, "vaultVersion": 5,
  "shorteningThreshold": 129, "passphrase": "…NFD…", "passphraseNfc": "…NFC…",
  "expected": [ { "path": "/hello.txt", "type": "file", "size": 15, "sha256": "…" }, … ] }
```

`format` and `vaultVersion` are two names for the same number. `shorteningThreshold` is the
ciphertext name length above which a name is stored out of line (220 for format 7, 129 for 5 and 6);
neither is configurable in these formats. `expected` is the cleartext tree — the same node shape the
format-8 fixtures keep in `expected.json` — so a migration test can compare the content of a migrated
vault against it.

Every fixture holds a 0-byte, a 1-byte and a 40 KiB file, two levels of nested directories, a
154-character name that is shortened in every format, NFC non-ASCII names and (except in
`legacy_v5`) a symlink. No directory is left empty, so the checked-in fixture is byte-identical to
the generated one. Each is well under 200 KB.

Regeneration is not byte-reproducible: salt, directory ids and nonces are random per run. The
manifest is written in the same run as the vault, so the two always match — commit them together.
