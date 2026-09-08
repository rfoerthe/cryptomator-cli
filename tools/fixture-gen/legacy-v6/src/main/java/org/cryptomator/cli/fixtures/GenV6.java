package org.cryptomator.cli.fixtures;

import org.cryptomator.cryptofs.CryptoFileSystem;
import org.cryptomator.cryptofs.CryptoFileSystemProperties;
import org.cryptomator.cryptofs.CryptoFileSystemProvider;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Writes {@code tests/fixtures/legacy_v6} with cryptofs 1.8.9, whose {@code Constants.VAULT_VERSION}
 * is 6. Vault format 6 has no {@code vault.cryptomator} either; names are base32 of the SIV
 * ciphertext, directories carry the prefix {@code 0} and symlinks the prefix {@code 1S}. A
 * ciphertext name longer than {@code SHORT_NAMES_MAX_LENGTH} (129) is replaced by
 * {@code BASE32(SHA1(name)) + ".lng"} and its long form is stored under {@code m/xx/yy/}.
 *
 * Formats 6 and 5 differ only in the normalisation of the passphrase, never on disk — see GenV5.
 *
 * Usage: {@code GenV6 <fixturesDir>}
 */
public final class GenV6 {

    static final String NAME = "legacy_v6";
    static final String PASSPHRASE = "test-password-123";
    /** cryptofs 1.8.9 {@code Constants.SHORT_NAMES_MAX_LENGTH}; not configurable in format 6. */
    static final int SHORTENING_THRESHOLD = 129;

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("usage: GenV6 <fixturesDir>");
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
        LegacySupport.writeManifest(vault, NAME, 6, SHORTENING_THRESHOLD, PASSPHRASE, PASSPHRASE, expected);
        System.out.println("generated " + NAME);
    }

    private GenV6() {}
}
