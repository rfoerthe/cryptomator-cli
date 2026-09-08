package org.cryptomator.cli.fixtures;

import com.google.gson.GsonBuilder;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Everything the three legacy generators share. Deliberately duplicated into every
 * {@code legacy-v*} module: the modules carry mutually incompatible cryptofs versions on their
 * class paths and must not depend on each other. Only {@link FileSystem} (never
 * {@code CryptoFileSystem}) appears in the signatures, so the same source compiles against
 * cryptofs 1.6.2, 1.8.9 and 1.9.15 alike.
 */
final class LegacySupport {

    static final String MASTERKEY = "masterkey.cryptomator";

    /**
     * 154 cleartext characters. Longer than cryptofs 1.9.15's {@code MAX_CLEARTEXT_NAME_LENGTH}
     * (146), so format 7 stores it as {@code .c9s}; its base32 ciphertext is ~272 characters, far
     * beyond {@code SHORT_NAMES_MAX_LENGTH} (129), so formats 6 and 5 store it as {@code m/xx/yy/*.lng}.
     */
    static final String LONG_NAME = "l".repeat(150) + ".txt";

    /** A file large enough to span several 32 KiB content chunks without blowing the 200 KB budget. */
    static final int BLOB_SIZE = 40 * 1024;

    private static final HexFormat HEX = HexFormat.of();

    private LegacySupport() {}

    /** Removes a previous run's output so the generator always writes a pristine vault. */
    static void recreate(Path vault) throws IOException {
        if (Files.exists(vault)) {
            deleteRecursively(vault);
        }
        Files.createDirectories(vault);
    }

    /**
     * The cleartext tree of every legacy fixture: a 0-byte, a 1-byte and a 40 KiB file, two nesting
     * levels, one name past the shortening threshold, NFC non-ASCII names and — where the cryptofs
     * version supports it — one symlink. No directory stays empty: git cannot track those, and the
     * checked-in fixture has to be byte-identical to the generated one.
     *
     * @param withSymlink cryptofs 1.6.2 has no symlink support yet ({@code createSymbolicLink}
     *                    throws {@code UnsupportedOperationException}), so {@code legacy_v5} passes
     *                    {@code false}. 1.8.9 and 1.9.15 write the {@code 1S…} / {@code symlink.c9r}
     *                    form and pass {@code true}.
     */
    static void populate(FileSystem fs, boolean withSymlink) throws IOException {
        write(fs, "/hello.txt", "Hello, legacy!\n");
        Files.write(fs.getPath("/empty.bin"), new byte[0]);
        Files.write(fs.getPath("/one-byte.bin"), new byte[]{42});
        Files.write(fs.getPath("/blob.bin"), blob());
        Files.createDirectory(fs.getPath("/docs"));
        write(fs, "/docs/notes.md", "# Notes\n\nlegacy\n");
        Files.createDirectory(fs.getPath("/docs/deep"));
        write(fs, "/docs/deep/inner.txt", "nested\n");
        write(fs, "/" + LONG_NAME, "long name\n");
        write(fs, "/Gr\u00fc\u00dfe.txt", "nfc umlaut\n");                    // "Grüße.txt" in NFC
        Files.createDirectory(fs.getPath("/\u65e5\u672c\u8a9e"));               // "日本語"
        write(fs, "/\u65e5\u672c\u8a9e/\u30d5\u30a1\u30a4\u30eb.txt", "japanese\n"); // "日本語/ファイル.txt"
        if (withSymlink) {
            Files.createSymbolicLink(fs.getPath("/link.txt"), fs.getPath("hello.txt"));
        }
    }

    /** Deterministic filler, identical to the byte pattern the format-8 {@code sizes} fixture uses. */
    static byte[] blob() {
        byte[] data = new byte[BLOB_SIZE];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i * 7);
        }
        return data;
    }

    /** Records path, type, size, SHA-256 and symlink target of every node below {@code dir}. */
    static void walk(Path dir, List<Map<String, Object>> out) throws IOException {
        try (var stream = Files.newDirectoryStream(dir)) {
            List<Path> children = new ArrayList<>();
            stream.forEach(children::add);
            children.sort(Comparator.comparing(Path::toString));
            for (Path child : children) {
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("path", child.toString());
                if (Files.isSymbolicLink(child)) {
                    entry.put("type", "symlink");
                    entry.put("target", Files.readSymbolicLink(child).toString());
                    out.add(entry);
                } else if (Files.isDirectory(child)) {
                    entry.put("type", "dir");
                    out.add(entry);
                    walk(child, out);
                } else {
                    byte[] data = Files.readAllBytes(child);
                    entry.put("type", "file");
                    entry.put("size", data.length);
                    entry.put("sha256", sha256(data));
                    out.add(entry);
                }
            }
        }
    }

    /**
     * Writes {@code fixture.json}. {@code kind} is always {@code legacy}: these vaults have no
     * {@code vault.cryptomator} and no raw masterkey in the manifest, so the Rust tests that walk
     * every fixture skip them. {@code format} and {@code vaultVersion} always carry the same number
     * (two names for one value, because plan and brief use different ones).
     */
    static void writeManifest(Path vault, String name, int format, int shorteningThreshold,
                              String passphrase, String passphraseNfc,
                              List<Map<String, Object>> expected) throws IOException {
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("name", name);
        meta.put("kind", "legacy");
        meta.put("format", format);
        meta.put("vaultVersion", format);
        meta.put("shorteningThreshold", shorteningThreshold);
        meta.put("passphrase", passphrase);
        meta.put("passphraseNfc", passphraseNfc);
        meta.put("expected", expected);
        var gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
        Files.write(vault.resolve("fixture.json"),
                (gson.toJson(meta) + "\n").getBytes(StandardCharsets.UTF_8));
    }

    static void write(FileSystem fs, String path, String content) throws IOException {
        Files.write(fs.getPath(path), content.getBytes(StandardCharsets.UTF_8));
    }

    static String sha256(byte[] data) throws IOException {
        try {
            return HEX.formatHex(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new IOException(e);
        }
    }

    static void deleteRecursively(Path path) throws IOException {
        try (var stream = Files.walk(path)) {
            stream.sorted(Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.delete(p);
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            });
        }
    }
}
