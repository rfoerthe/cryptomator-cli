# fixture-gen

Java harness around the real cryptofs 2.10.0 / cryptolib 2.2.2. It has three modes: it creates the
reference vaults under `tests/fixtures/`, it creates the deliberately damaged vault `broken_health`
for the health-check tests, and it opens a vault written by `crypto` to prove that the Java
implementation accepts it.

Regenerate the fixtures (JDK 21+, Maven):

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
