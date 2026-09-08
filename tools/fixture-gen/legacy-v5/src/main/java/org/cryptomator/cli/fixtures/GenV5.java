package org.cryptomator.cli.fixtures;

import org.cryptomator.cryptofs.CryptoFileSystem;
import org.cryptomator.cryptofs.CryptoFileSystemProperties;
import org.cryptomator.cryptofs.CryptoFileSystemProvider;

import java.nio.file.Path;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Writes {@code tests/fixtures/legacy_v5} with cryptofs 1.3.2, whose {@code Constants.VAULT_VERSION}
 * is 5 — the last release before the format-6 bump. On disk, formats 5 and 6 are the same thing
 * (base32 names, {@code 0} prefix for directories, {@code m/xx/yy/*.lng} for long names); they
 * differ only in how the passphrase reaches scrypt:
 *
 * <ul>
 *   <li>up to cryptofs 1.3.x the passphrase went into the KDF exactly as typed — that is vault
 *       format 5;</li>
 *   <li>from 1.4.0 on, {@code CryptoFileSystemProvider.initialize} and
 *       {@code CryptoFileSystemProperties.Builder.withPassphrase} normalise it to NFC first, and
 *       {@code Version6Migrator} rewrites an existing masterkey file accordingly — that is
 *       vault format 6.</li>
 * </ul>
 *
 * The fixture therefore uses a passphrase whose NFD and NFC forms differ and initialises the vault
 * with the <b>NFD</b> form. Only that form opens it; the NFC form is what the 5 → 6 migration has to
 * switch it over to. Both are in the manifest ({@code passphrase} / {@code passphraseNfc}).
 *
 * cryptofs 1.3.2 has no symlink support yet, so this fixture has no symlink (see
 * {@link LegacySupport#populate}).
 *
 * Usage: {@code GenV5 <fixturesDir>}
 */
public final class GenV5 {

    static final String NAME = "legacy_v5";

    /** {@code "tästpaß-123"} in NFD: the umlaut is {@code a} + U+0308 COMBINING DIAERESIS. */
    static final String PASSPHRASE_NFD = "ta\u0308stpa\u00df-123";
    /** The same passphrase in NFC; the 5 -> 6 migration switches the vault over to this form. */
    static final String PASSPHRASE_NFC = Normalizer.normalize(PASSPHRASE_NFD, Normalizer.Form.NFC);

    /** cryptofs 1.3.2 {@code Constants.NAME_SHORTENING_THRESHOLD}; not configurable in format 5. */
    static final int SHORTENING_THRESHOLD = 129;

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("usage: GenV5 <fixturesDir>");
            System.exit(2);
        }
        if (PASSPHRASE_NFD.equals(PASSPHRASE_NFC)) {
            throw new IllegalStateException("the point of legacy_v5 is that NFD and NFC differ");
        }
        if (!Normalizer.isNormalized(PASSPHRASE_NFD, Normalizer.Form.NFD)) {
            throw new IllegalStateException("PASSPHRASE_NFD is not in NFD");
        }
        Path vault = Path.of(args[0]).resolve(NAME);
        LegacySupport.recreate(vault);
        CryptoFileSystemProvider.initialize(vault, LegacySupport.MASTERKEY, PASSPHRASE_NFD);
        CryptoFileSystemProperties props = CryptoFileSystemProperties.cryptoFileSystemProperties()
                .withPassphrase(PASSPHRASE_NFD)
                .withMasterkeyFilename(LegacySupport.MASTERKEY)
                .build();
        List<Map<String, Object>> expected = new ArrayList<>();
        try (CryptoFileSystem fs = CryptoFileSystemProvider.newFileSystem(vault, props)) {
            LegacySupport.populate(fs, false);
            LegacySupport.walk(fs.getPath("/"), expected);
        }
        LegacySupport.writeManifest(vault, NAME, 5, SHORTENING_THRESHOLD,
                PASSPHRASE_NFD, PASSPHRASE_NFC, expected);
        System.out.println("generated " + NAME);
    }

    private GenV5() {}
}
