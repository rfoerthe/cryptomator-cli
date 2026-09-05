package org.cryptomator.cli.fixtures;

import com.google.gson.GsonBuilder;
import org.cryptomator.cryptofs.CryptoFileSystem;
import org.cryptomator.cryptofs.CryptoFileSystemProperties;
import org.cryptomator.cryptofs.CryptoFileSystemProvider;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.common.MasterkeyFileAccess;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Generates reference vaults with cryptofs 2.10.0 and verifies foreign vaults with it.
 * Usage: Gen gen <outputDir> | Gen verify <vaultDir> <passphrase>
 * Each vault uses passphrase "test-password-123"; its masterkey is SHA-512(name) so regeneration only changes nonces.
 */
public final class Gen {

    static final String PASSPHRASE = "test-password-123";
    static final URI KEY_ID = URI.create("masterkeyfile:masterkey.cryptomator");
    static final HexFormat HEX = HexFormat.of();

    record Spec(String name, CryptorProvider.Scheme scheme, int threshold, Populator populator) {}

    interface Populator {
        void populate(CryptoFileSystem fs) throws IOException;
    }

    public static void main(String[] args) throws Exception {
        List<String> argv = java.util.Arrays.stream(args).filter(a -> !a.isEmpty()).toList();
        if (argv.size() == 2 && argv.get(0).equals("gen")) {
            Path out = Path.of(argv.get(1));
            Files.createDirectories(out);
            for (Spec spec : specs()) {
                generate(out.resolve(spec.name()), spec);
                System.out.println("generated " + spec.name());
            }
        } else if (argv.size() == 3 && argv.get(0).equals("verify")) {
            System.exit(verify(Path.of(argv.get(1)), argv.get(2)));
        } else {
            System.err.println("usage: Gen gen <outputDir> | Gen verify <vaultDir> <passphrase>");
            System.exit(2);
        }
    }

    /**
     * Opens a vault written by another implementation with the real cryptofs and prints its cleartext tree as JSON.
     * The cipher combo and the shortening threshold are not configured here on purpose: cryptofs reads both from the
     * vault's own {@code vault.cryptomator}, so the same call verifies SIV_GCM and SIV_CTRMAC vaults alike.
     */
    static int verify(Path vault, String passphrase) {
        try {
            var access = new MasterkeyFileAccess(new byte[0], new SecureRandom());
            try (Masterkey masterkey = access.load(vault.resolve("masterkey.cryptomator"), passphrase)) {
                CryptoFileSystemProperties props = CryptoFileSystemProperties.cryptoFileSystemProperties()
                        .withKeyLoader(uri -> masterkey.copy())
                        .build();
                List<Map<String, Object>> entries = new ArrayList<>();
                try (CryptoFileSystem fs = CryptoFileSystemProvider.newFileSystem(vault, props)) {
                    walk(fs.getPath("/"), entries);
                    for (Map<String, Object> entry : entries) {
                        if ("file".equals(entry.get("type"))) {
                            Files.readAllBytes(fs.getPath((String) entry.get("path"))); // authenticate every chunk
                        }
                    }
                }
                var gson = new GsonBuilder().disableHtmlEscaping().create();
                System.out.println(gson.toJson(entries));
                return 0;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return 3;
        }
    }

    static List<Spec> specs() {
        Populator basic = fs -> {
            write(fs, "/hello.txt", "Hello, Cryptomator!\n");
            Files.createDirectory(fs.getPath("/docs"));
            write(fs, "/docs/notes.md", "# Notes\n\nsome text\n");
        };
        return List.of(
                new Spec("siv_gcm_basic", CryptorProvider.Scheme.SIV_GCM, 220, basic),
                new Spec("siv_ctrmac_basic", CryptorProvider.Scheme.SIV_CTRMAC, 220, basic),
                new Spec("long_names", CryptorProvider.Scheme.SIV_GCM, 220, fs -> {
                    write(fs, "/" + "a".repeat(146) + ".txt", "146 chars: exactly at the .c9s boundary?\n");
                    write(fs, "/" + "b".repeat(147) + ".txt", "147 chars\n");
                    write(fs, "/" + "c".repeat(200) + ".txt", "200 chars\n");
                    Files.createDirectory(fs.getPath("/" + "d".repeat(200)));
                    write(fs, "/" + "d".repeat(200) + "/inner.txt", "inside long dir\n");
                }),
                new Spec("threshold_36", CryptorProvider.Scheme.SIV_GCM, 36, fs -> {
                    write(fs, "/short.txt", "short name, still shortened at threshold 36\n");
                    Files.createDirectory(fs.getPath("/dir"));
                    write(fs, "/dir/file.txt", "nested\n");
                }),
                new Spec("symlinks", CryptorProvider.Scheme.SIV_GCM, 220, fs -> {
                    write(fs, "/target.txt", "link target\n");
                    Files.createDirectory(fs.getPath("/sub"));
                    Files.createSymbolicLink(fs.getPath("/relative-link"), fs.getPath("target.txt"));
                    Files.createSymbolicLink(fs.getPath("/absolute-link"), fs.getPath("/target.txt"));
                    Files.createSymbolicLink(fs.getPath("/dir-link"), fs.getPath("sub"));
                    Files.createSymbolicLink(fs.getPath("/dangling"), fs.getPath("does-not-exist"));
                }),
                new Spec("nested", CryptorProvider.Scheme.SIV_GCM, 220, fs -> {
                    Files.createDirectories(fs.getPath("/l1/l2/l3/l4/l5"));
                    write(fs, "/l1/l2/l3/l4/l5/deep.txt", "deep\n");
                    write(fs, "/l1/one.txt", "1\n");
                }),
                new Spec("sizes", CryptorProvider.Scheme.SIV_GCM, 220, fs -> {
                    for (int size : new int[]{0, 1, 32767, 32768, 32769, 65536, 100000}) {
                        byte[] data = new byte[size];
                        for (int i = 0; i < size; i++) data[i] = (byte) (i * 7);
                        Files.write(fs.getPath("/size-" + size + ".bin"), data);
                    }
                }),
                new Spec("unicode", CryptorProvider.Scheme.SIV_GCM, 220, fs -> {
                    write(fs, "/Grüße 🚀.txt", "nfc\n");
                    write(fs, "/café.txt", "nfd e + combining acute\n");
                    Files.createDirectory(fs.getPath("/日本語"));
                    write(fs, "/日本語/ファイル.txt", "japanese\n");
                })
        );
    }

    static void generate(Path vault, Spec spec) throws Exception {
        if (Files.exists(vault)) {
            deleteRecursively(vault);
        }
        Files.createDirectories(vault);
        byte[] raw = MessageDigest.getInstance("SHA-512").digest(spec.name().getBytes(StandardCharsets.UTF_8));
        SecureRandom csprng = new SecureRandom();
        try (Masterkey masterkey = new Masterkey(raw)) {
            new MasterkeyFileAccess(new byte[0], csprng).persist(masterkey, vault.resolve("masterkey.cryptomator"), PASSPHRASE);
            CryptoFileSystemProperties props = CryptoFileSystemProperties.cryptoFileSystemProperties()
                    .withKeyLoader(uri -> masterkey.copy())
                    .withCipherCombo(spec.scheme())
                    .withShorteningThreshold(spec.threshold())
                    .build();
            CryptoFileSystemProvider.initialize(vault, props, KEY_ID);
            List<Map<String, Object>> expected = new ArrayList<>();
            try (CryptoFileSystem fs = CryptoFileSystemProvider.newFileSystem(vault, props)) {
                spec.populator().populate(fs);
                walk(fs.getPath("/"), expected);
            }
            Map<String, Object> meta = new LinkedHashMap<>();
            meta.put("name", spec.name());
            meta.put("cipherCombo", spec.scheme().name());
            meta.put("shorteningThreshold", spec.threshold());
            meta.put("passphrase", PASSPHRASE);
            meta.put("masterkeyHex", HEX.formatHex(raw));
            var gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
            Files.writeString(vault.resolve("fixture.json"), gson.toJson(meta) + "\n", StandardCharsets.UTF_8);
            Files.writeString(vault.resolve("expected.json"), gson.toJson(expected) + "\n", StandardCharsets.UTF_8);
        }
    }

    static void walk(Path dir, List<Map<String, Object>> out) throws IOException {
        try (var stream = Files.newDirectoryStream(dir)) {
            List<Path> children = new ArrayList<>();
            stream.forEach(children::add);
            children.sort(java.util.Comparator.comparing(Path::toString));
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

    static void write(CryptoFileSystem fs, String path, String content) throws IOException {
        Files.writeString(fs.getPath(path), content, StandardCharsets.UTF_8);
    }

    static String sha256(byte[] data) throws IOException {
        try {
            return HEX.formatHex(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IOException(e);
        }
    }

    static void deleteRecursively(Path path) throws IOException {
        try (var stream = Files.walk(path)) {
            stream.sorted(java.util.Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.delete(p);
                } catch (IOException e) {
                    throw new java.io.UncheckedIOException(e);
                }
            });
        }
    }

    private Gen() {}
}
