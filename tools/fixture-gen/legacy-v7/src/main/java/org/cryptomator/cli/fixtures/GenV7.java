package org.cryptomator.cli.fixtures;

import org.cryptomator.cryptofs.CryptoFileSystem;
import org.cryptomator.cryptofs.CryptoFileSystemProperties;
import org.cryptomator.cryptofs.CryptoFileSystemProvider;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Writes {@code tests/fixtures/legacy_v7} with cryptofs 1.9.15, whose
 * {@code common.Constants.VAULT_VERSION} is 7. Vault format 7 has no {@code vault.cryptomator}:
 * the format lives in the {@code version} field of the masterkey file. Names are
 * {@code BASE64URL(SIV) + ".c9r"}; a ciphertext name longer than
 * {@code MAX_CIPHERTEXT_NAME_LENGTH} (220) is stored as a {@code .c9s} directory holding
 * {@code name.c9s} plus {@code contents.c9r}. There is no {@code m/} directory any more.
 *
 * Usage: {@code GenV7 <fixturesDir>}
 */
public final class GenV7 {

    static final String NAME = "legacy_v7";
    static final String PASSPHRASE = "test-password-123";
    /** cryptofs 1.9.15 {@code common.Constants.MAX_CIPHERTEXT_NAME_LENGTH}; not configurable in format 7. */
    static final int SHORTENING_THRESHOLD = 220;

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("usage: GenV7 <fixturesDir>");
            System.exit(2);
        }
        Path vault = Path.of(args[0]).resolve(NAME);
        LegacySupport.recreate(vault);
        CryptoFileSystemProvider.initialize(vault, LegacySupport.MASTERKEY, PASSPHRASE);
        CryptoFileSystemProperties props = CryptoFileSystemProperties.cryptoFileSystemProperties()
                .withPassphrase(PASSPHRASE)
                .withMasterkeyFilename(LegacySupport.MASTERKEY)
                .build();
        List<Map<String, Object>> expected = new ArrayList<>();
        try (CryptoFileSystem fs = CryptoFileSystemProvider.newFileSystem(vault, props)) {
            LegacySupport.populate(fs, true);
            LegacySupport.walk(fs.getPath("/"), expected);
        }
        LegacySupport.writeManifest(vault, NAME, 7, SHORTENING_THRESHOLD, PASSPHRASE, PASSPHRASE, expected);
        System.out.println("generated " + NAME);
    }

    private GenV7() {}
}
