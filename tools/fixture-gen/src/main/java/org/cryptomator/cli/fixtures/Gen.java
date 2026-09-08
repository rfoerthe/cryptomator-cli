package org.cryptomator.cli.fixtures;

import com.google.common.io.BaseEncoding;
import com.google.gson.GsonBuilder;
import org.cryptomator.cryptofs.CryptoFileSystem;
import org.cryptomator.cryptofs.CryptoFileSystemProperties;
import org.cryptomator.cryptofs.CryptoFileSystemProvider;
import org.cryptomator.cryptolib.api.Cryptor;
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
 * Usage: Gen gen <outputDir> | Gen broken <outputDir> | Gen verify <vaultDir> <passphrase>
 * Each vault uses passphrase "test-password-123"; its masterkey is SHA-512(name) so regeneration only changes nonces.
 */
public final class Gen {

    static final String PASSPHRASE = "test-password-123";
    static final URI KEY_ID = URI.create("masterkeyfile:masterkey.cryptomator");
    static final HexFormat HEX = HexFormat.of();
    static final BaseEncoding BASE64URL = BaseEncoding.base64Url();

    /** The damaged vault; `broken` first generates it healthy and then breaks it on the ciphertext level. */
    static final String BROKEN_NAME = "broken_health";
    static final int BROKEN_THRESHOLD = 220;
    static final String ROOT_DIR_ID = "";

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
        } else if (argv.size() == 2 && argv.get(0).equals("broken")) {
            Path out = Path.of(argv.get(1));
            Files.createDirectories(out);
            broken(out);
            System.out.println("generated " + BROKEN_NAME);
        } else if (argv.size() == 3 && argv.get(0).equals("verify")) {
            System.exit(verify(Path.of(argv.get(1)), argv.get(2)));
        } else {
            System.err.println("usage: Gen gen <outputDir> | Gen broken <outputDir> | Gen verify <vaultDir> <passphrase>");
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
        generate(vault, spec, "clean");
    }

    /**
     * Writes a fresh vault plus its {@code fixture.json} / {@code expected.json}.
     * {@code kind} lands in the manifest and tells the Rust test suite which fixtures are ordinary
     * format-8 vaults ({@code clean}) and which ones are deliberately damaged ({@code broken}) or of
     * an older vault format ({@code legacy}) and therefore excluded from the whole-tree assertions.
     */
    static void generate(Path vault, Spec spec, String kind) throws Exception {
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
            meta.put("kind", kind);
            meta.put("cipherCombo", spec.scheme().name());
            meta.put("shorteningThreshold", spec.threshold());
            meta.put("passphrase", PASSPHRASE);
            meta.put("masterkeyHex", HEX.formatHex(raw));
            var gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
            Files.writeString(vault.resolve("fixture.json"), gson.toJson(meta) + "\n", StandardCharsets.UTF_8);
            Files.writeString(vault.resolve("expected.json"), gson.toJson(expected) + "\n", StandardCharsets.UTF_8);
        }
    }

    // --- `broken`: one vault with nine deliberate damages plus the manifest of the findings ---------

    /**
     * Generates {@value #BROKEN_NAME}: a healthy SIV_GCM vault that is afterwards damaged on the
     * ciphertext level in nine ways. {@code expected-findings.json} lists exactly the nine non-GOOD
     * findings a health check has to report; {@code expected.json} is removed because the cleartext
     * tree of a damaged vault is meaningless.
     */
    static void broken(Path out) throws Exception {
        Path vault = out.resolve(BROKEN_NAME);
        Spec spec = new Spec(BROKEN_NAME, CryptorProvider.Scheme.SIV_GCM, BROKEN_THRESHOLD, fs -> {
            write(fs, "/healthy.txt", "this file stays intact\n");
            Files.createDirectory(fs.getPath("/keep"));                // intact; lends its dir id to damage 5
            write(fs, "/keep/inside.txt", "kept\n");
            Files.createDirectory(fs.getPath("/orphaned"));            // damage 1: loses its .c9r node
            write(fs, "/orphaned/adopted.txt", "adopt me\n");
            write(fs, "/orphaned/second.txt", "adopt me too\n");       // keeps the orphan content dir committable
            Files.createDirectory(fs.getPath("/nodirid"));             // damage 2: loses its dirid.c9r
            write(fs, "/nodirid/still-here.txt", "still here\n");      // keeps that content dir committable
            Files.createDirectory(fs.getPath("/nocontent"));           // damage 3: loses its content dir
            write(fs, "/" + "L".repeat(200) + ".txt", "shortened\n");  // healthy .c9s, for contrast
            write(fs, "/" + "M".repeat(200) + ".txt", "mismatch\n");   // damage 7
            write(fs, "/" + "T".repeat(200) + ".txt", "trailing\n");   // damage 8
            write(fs, "/" + "N".repeat(200) + ".txt", "noname\n");     // damage 9
        });
        generate(vault, spec, "broken");
        List<Map<String, Object>> findings = damage(vault, spec);
        var gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
        Files.writeString(vault.resolve("expected-findings.json"), gson.toJson(findings) + "\n", StandardCharsets.UTF_8);
        Files.delete(vault.resolve("expected.json"));
    }

    /**
     * Breaks the freshly generated vault in nine ways and returns one manifest entry per damage.
     * Only ciphertext level operations, so masterkey and vault config stay valid and the vault keeps
     * unlocking. No damage leaves an empty directory behind: git cannot track those, and the checked-in
     * fixture has to be byte-identical to the generated one.
     */
    static List<Map<String, Object>> damage(Path vault, Spec spec) throws Exception {
        byte[] raw = MessageDigest.getInstance("SHA-512").digest(spec.name().getBytes(StandardCharsets.UTF_8));
        List<Map<String, Object>> findings = new ArrayList<>();
        try (Masterkey masterkey = new Masterkey(raw);
             Cryptor cryptor = CryptorProvider.forScheme(spec.scheme()).provide(masterkey.copy(), new SecureRandom())) {
            Path rootContent = contentDir(vault, cryptor, ROOT_DIR_ID);

            // 1 - orphan content dir. Removing the whole .c9r node instead of only its dir.c9r keeps the
            // fixture git-clean: an emptied node directory would be dropped on checkout and would also
            // report a second UnknownType.
            Path orphanNode = node(vault, cryptor, spec, ROOT_DIR_ID, "orphaned");
            Path orphanContent = contentDir(vault, cryptor, dirId(orphanNode));
            deleteRecursively(orphanNode);
            findings.add(finding("dirid", "WARN", "OrphanContentDir", vault, orphanContent));

            // 2 - content dir without its dir id backup.
            Path noBackupContent = contentDir(vault, cryptor, dirId(node(vault, cryptor, spec, ROOT_DIR_ID, "nodirid")));
            Files.delete(noBackupContent.resolve("dirid.c9r"));
            findings.add(finding("dirid", "INFO", "MissingDirIdBackup", vault, noBackupContent));

            // 3 - dir.c9r pointing at a directory that no longer exists.
            Path noContentNode = node(vault, cryptor, spec, ROOT_DIR_ID, "nocontent");
            deleteRecursively(contentDir(vault, cryptor, dirId(noContentNode)));
            findings.add(finding("dirid", "WARN", "MissingContentDir", vault, noContentNode.resolve("dir.c9r")));

            // 4 - loose dir.c9r: its parent is the root content dir, whose name ends in neither .c9r nor
            // .c9s. Java reports LooseDirFile before it looks at the size, so the empty file is no
            // EmptyDirFile.
            Path looseDirFile = rootContent.resolve("dir.c9r");
            Files.writeString(looseDirFile, "", StandardCharsets.UTF_8);
            findings.add(finding("dirid", "INFO", "LooseDirFile", vault, looseDirFile));

            // 5 - two dir.c9r files carrying the same dir id.
            String keepDirId = dirId(node(vault, cryptor, spec, ROOT_DIR_ID, "keep"));
            Path collideNode = rootContent.resolve(cipherName(cryptor, "collide", ROOT_DIR_ID));
            Files.createDirectory(collideNode);
            Files.writeString(collideNode.resolve("dir.c9r"), keepDirId, StandardCharsets.UTF_8);
            findings.add(finding("dirid", "CRITICAL", "DirIdCollision", vault, collideNode.resolve("dir.c9r")));

            // 6 - a .c9r directory with neither dir.c9r nor symlink.c9r nor contents.c9r.
            Path unknownNode = rootContent.resolve(cipherName(cryptor, "unknown", ROOT_DIR_ID));
            Files.createDirectory(unknownNode);
            Files.writeString(unknownNode.resolve("x"), "no type marker in here\n", StandardCharsets.UTF_8);
            findings.add(finding("type", "CRITICAL", "UnknownType", vault, unknownNode));

            // 7 - name.c9s holds a syntactically valid ciphertext name that deflates to a different
            // short name. The name is synthetic (no node of the vault carries it), so the eventual fix
            // renames the node instead of colliding with an existing one.
            Path mismatchNode = node(vault, cryptor, spec, ROOT_DIR_ID, "M".repeat(200) + ".txt");
            Files.writeString(mismatchNode.resolve("name.c9s"),
                    cipherName(cryptor, "S".repeat(200) + ".txt", ROOT_DIR_ID), StandardCharsets.UTF_8);
            findings.add(finding("shortened", "WARN", "LongShortNamesMismatch", vault, mismatchNode));

            // 8 - name.c9s with trailing bytes behind the .c9r suffix (cryptofs issue 121).
            Path trailingNameFile = node(vault, cryptor, spec, ROOT_DIR_ID, "T".repeat(200) + ".txt").resolve("name.c9s");
            Files.writeString(trailingNameFile, Files.readString(trailingNameFile, StandardCharsets.UTF_8) + "garbage",
                    StandardCharsets.UTF_8);
            findings.add(finding("shortened", "WARN", "TrailingBytesInNameFile", vault, trailingNameFile));

            // 9 - .c9s directory without name.c9s; contents.c9r keeps it committable.
            Path noNameNode = node(vault, cryptor, spec, ROOT_DIR_ID, "N".repeat(200) + ".txt");
            Files.delete(noNameNode.resolve("name.c9s"));
            findings.add(finding("shortened", "CRITICAL", "MissingLongName", vault, noNameNode));
        }
        return findings;
    }

    static Map<String, Object> finding(String check, String severity, String result, Path vault, Path target) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("check", check);
        entry.put("severity", severity);
        entry.put("result", result);
        entry.put("path", relative(vault, target));
        return entry;
    }

    /** Vault relative path with {@code /} as separator, the form the manifest and the Rust side use. */
    static String relative(Path vault, Path target) {
        StringBuilder out = new StringBuilder();
        for (Path part : vault.relativize(target)) {
            if (out.length() > 0) {
                out.append('/');
            }
            out.append(part);
        }
        return out.toString();
    }

    /** {@code <vault>/d/<hash[0,2]>/<hash[2,32]>} — the content directory of {@code dirId}. */
    static Path contentDir(Path vault, Cryptor cryptor, String dirId) {
        String hash = cryptor.fileNameCryptor().hashDirectoryId(dirId);
        return vault.resolve("d").resolve(hash.substring(0, 2)).resolve(hash.substring(2));
    }

    /** The (unshortened) ciphertext name of {@code cleartext} inside the directory {@code dirId}. */
    static String cipherName(Cryptor cryptor, String cleartext, String dirId) {
        return cryptor.fileNameCryptor().encryptFilename(BASE64URL, cleartext, dirId.getBytes(StandardCharsets.UTF_8))
                + ".c9r";
    }

    /** BASE64URL(SHA1(name)) + ".c9s", exactly like cryptofs' LongFileNameProvider. */
    static String deflate(String ciphertextName) throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-1").digest(ciphertextName.getBytes(StandardCharsets.UTF_8));
        return BASE64URL.encode(hash) + ".c9s";
    }

    /** The existing ciphertext node of {@code cleartextName} inside the directory {@code parentDirId}. */
    static Path node(Path vault, Cryptor cryptor, Spec spec, String parentDirId, String cleartextName) throws Exception {
        String name = cipherName(cryptor, cleartextName, parentDirId);
        String stored = name.length() > spec.threshold() ? deflate(name) : name;
        Path node = contentDir(vault, cryptor, parentDirId).resolve(stored);
        if (!Files.exists(node)) {
            throw new IOException("no ciphertext node for " + cleartextName + " at " + node);
        }
        return node;
    }

    /** The directory id a {@code .c9r}/{@code .c9s} directory node points at. */
    static String dirId(Path node) throws IOException {
        return Files.readString(node.resolve("dir.c9r"), StandardCharsets.UTF_8);
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
