# fixture-gen

Java harness that creates reference vaults with the real cryptofs 2.10.0 / cryptolib 2.2.2 under `tests/fixtures/`.

Regenerate (JDK 21+, Maven):

    mvn -q -f tools/fixture-gen/pom.xml compile exec:exec

`exec:exec` forks a JVM; `exec:java` cannot be used because `java.nio.file.spi.FileSystemProvider`
discovers the cryptofs provider only via the system class loader. The output directory defaults to
`tests/fixtures` next to the POM and can be overridden with `-Dfixtures.out=/some/path`.

Regeneration changes nonces and salts but keeps each vault's masterkey (SHA-512 of the fixture name) and passphrase
`test-password-123`. Commit the result; Rust tests read the fixtures without Java.
