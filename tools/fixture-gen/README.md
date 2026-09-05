# fixture-gen

Java harness around the real cryptofs 2.10.0 / cryptolib 2.2.2. It has two modes: it creates the
reference vaults under `tests/fixtures/`, and it opens a vault written by `crypto` to prove that the
Java implementation accepts it.

Regenerate the fixtures (JDK 21+, Maven):

    mvn -q -f tools/fixture-gen/pom.xml compile exec:exec

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
