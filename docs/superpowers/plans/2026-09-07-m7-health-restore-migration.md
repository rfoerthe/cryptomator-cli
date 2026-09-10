# M7: Health checks, `recovery-key restore`, and the v5→v6→v7→v8 migrators – Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `crypto` finds, reports, and repairs the damage the desktop app shows in its "Vault Health" window (`crypto health <VAULT> [--check …] [--fix] [--fix-severity …] [--report FILE|--no-report] [--fail-on …]`, exit **11**), restores a lost `masterkey.cryptomator` and/or `vault.cryptomator` from a recovery key (`crypto recovery-key restore <VAULT> (--masterkey|--config|--all)`), and lifts legacy vaults of formats 5, 6, and 7 to format 8 in one pass (`crypto migrate <VAULT> [--yes] [--dry-run]`). On top of that come the fixtures that make this verifiable: an intentionally damaged vault and one legacy vault per old format, both produced by the Java harness.

**Architecture:** Three new module trees in `cryptomator-core`, plus three commands in the binary. (1) `health/` – `mod.rs` carries the `HealthCheck` trait, the result type `DiagnosticResult` with `Severity`, the `Fix` trait, and the `CheckContext` (vault path, `Cryptor`, `VaultConfig`, RNG); `dir_id.rs`, `file_type.rs`, and `shortened.rs` are the three Java checks one to one, including all 8 + 3 + 6 result types and their `fix()` implementations; `report.rs` writes the text report in the format of `ui/health/ReportWriter.java`. (2) `migration/` – `mod.rs` is Java's `Migrators` (detect the version, step by step up to 8, backups, capability check), `v6.rs`/`v7.rs`/`v8.rs` are the three migrators, where `v7.rs` with `FilePathMigration` (BASE32→BASE64URL, `0`/`1S` prefixes, `.lng` inflation from `m/`, three `_n` attempts) is the single biggest item. (3) `recovery/restore.rs` – `RecoveryDirectory` (a temp directory that is written to first and then moved out of), `restore_masterkey`, `restore_config`, `restore_all`, and `detect_cipher_combo`. In the binary a thin command layer sits on top of each of them, handling password sources, exit codes, `--json`, and the report path. The fixtures are produced by the existing Maven harness `tools/fixture-gen/`, which for this becomes a reactor with three additional modules (cryptofs 1.9.15 / 1.8.9 / 1.6.2).

**Tech Stack:** Rust stable ≥ 1.89, no new crate dependencies – everything needed is already in the workspace (`data-encoding` for BASE32/BASE64URL, `sha1`, `crc32fast`, `uuid`, `unicode-normalization` for the NFC normalization in v6, `zeroize`, `serde_json`, `clap` 4.6, `tempfile`, `assert_cmd` 2, `proptest` 1). Java side: Maven reactor, JDK ≥ 21, cryptofs 2.10.0 (current) plus 1.9.15 / 1.8.9 / 1.6.2 (legacy, **from Maven Central, not in the local `~/.m2`** – the first run of the fixture tasks needs network access).

**Spec:** `docs/superpowers/specs/2026-09-04-crypto-cli-design.md` (module table `health/{mod,dir_id,file_type,shortened,report}.rs`, `migration/{mod,v6,v7,v8}.rs`, `recovery/restore.rs`; command grammar `crypto health`, `crypto migrate`, `crypto recovery-key restore`; exit codes **11** and **5**; milestone **M7**; test strategy point 1 (`gen-legacy-v7/v6/v5`, `verify`) and point 2 (`migration.rs`); finding 8 (legacy cryptofs on Maven Central); risk 8 (migration 6→7 is the single biggest item); footnotes `[^m4-scope]`, `[^m5-scope]`, `[^m6-scope]`).

## Global Constraints

- Working directory `/Users/rfoerthe/work/cryptomator-cli`, branch `feature/m7-health-restore-migration` (off `main@be22e3c`). Never commit `.superpowers/` or `.idea/`.
- License AGPL-3.0-only. `#![forbid(unsafe_code)]` still applies in `cryptomator-core` **and** `cryptomator-app`; the new modules need no `unsafe`. No `unwrap()`/`expect()` on input data in library/binary code (tests may). **MSRV 1.89** (`rust-version` in the workspace). **No new crate dependency** – whoever needs one has taken the wrong route and should justify in the report why.
- `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo test --workspace --locked` clean before **every** commit; the commit message ends with `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.
- `~/.m2` and the desktop checkout (`/Users/rfoerthe/work/pro/cryptomator/…`) are **only read** (`unzip -p`, `cat`) and never modified. Maven downloads the legacy artifacts into `~/.m2` on the first run – that is the only write access allowed there, and it happens through Maven itself, not by hand.
- **`tests/fixtures/` is read-only for implementers – with exactly two exceptions: Task 1 and Task 2.** These two tasks create new fixture directories via the generator (`broken_health/`, `legacy_v7/`, `legacy_v6/`, `legacy_v5/`). No other task may create, change, or delete a file under `tests/fixtures/`, and **nobody** edits fixture files by hand: what the generator does not produce does not belong there.
- **Every test that writes works on a copy in a tempdir.** Health fixes, migrators, and restore change vaults; no test may touch a checked-in fixture. The existing helper `crates/crypto/tests/common/mod.rs::copy_recursively`, or a helper of the same name in `crates/cryptomator-core/tests/common/mod.rs`, copies into `tempfile::tempdir()`. A test that opens `tests/fixtures/**` directly may only do so for reading.
- Passwords and recovery keys never appear in argv, logs, error messages, reports, or JSON. Every passphrase and every recovery key travels through the code as `Zeroizing<String>`. **The health report contains no cleartext names** – only ciphertext paths, just like Java's `ReportWriter` (the `details()` values are exclusively paths, sizes, and types).
- Never run a real keychain E2E: no `CRYPTO_E2E_KEYCHAIN=1`, no unattended `security` command. All tests of this milestone that touch a keychain (only Task 12 does, for updating the entry after the NFC normalization) use the fake from `CRYPTO_KEYCHAIN_FAKE` via `Sandbox::crypto_keychain`.
- Never leave a mount or daemon behind. M7 mounts nothing; the only contact is that `health`, `migrate`, and `restore` must **reject** a running daemon (`VaultRegistry::require_locked`).
- Exit codes (`crates/crypto/src/exit.rs`): 0 ok, 1 general, 2 usage, 3 vault not found, 4 password/recovery key invalid, 5 wrong state, 6 mount, 7 unmount, 8 keychain, 9 hub, 10 daemon, **11 health findings ≥ `--fail-on` (new, was reserved)**, 12 no vault directory.
- Java parity (cryptofs 2.10.0, Cryptomator 1.19.x). The constants, severities, message texts, and orderings below are copied from the source and quoted verbatim in the tasks; anyone deviating from them makes the reports of the two programs incomparable. The four deliberate deviations are listed in the rulings.

### Rulings for this milestone (comment them in the code, document them in Task 14)

1. **Paths in results are vault-relative.** Java is inconsistent here (`DirIdCheck` returns absolute paths, `LooseDirFile.fix` performs an ineffective `pathToVault.resolve(dirFile)` on them; `OrphanContentDir` returns `d`-relative paths). We **always** return vault-relative (`d/AB/CDEF…/dir.c9r`), and every `Fix` resolves against `ctx.vault_path`. That makes reports machine-readable and reproducible.
2. **`--fail-on` is `CRITICAL` by default.** Java does not have the switch (the UI only displays). But a CLI has to return an exit code that means something in a cron job: `CRITICAL` = "data loss has already happened" is the threshold that deserves a report. `--fail-on WARN` tightens it, and there are no other values (`GOOD`/`INFO` as an error threshold would be pointless, because `GOOD` occurs en masse in every healthy vault).
3. **`--fix` repairs from `WARN` up, not from `INFO`.** `--fix-severity` moves the threshold to `CRITICAL`. `INFO` findings (`MissingDirIdBackup`, `LooseDirFile`) have fixes, but they are cosmetic; whoever wants them uses `--fix --fix-severity WARN` (the default) — which does **not** include them. Whoever wants *everything* is out of luck: the threshold knows only `WARN` and `CRITICAL`, because the grammar in the spec names exactly these two values. Documented as a deliberate gap; `INFO` fixes remain reachable through the desktop app.
4. **After `--fix` the checks run again.** A fix can produce new findings (the LOST+FOUND adoption creates directories that the next run sees as `HealthyDir`) and resolve old ones. `crypto health --fix` therefore runs twice and prints both ("before"/"after"); the exit code is decided by the **second** run. Without that second run, `--fix` could never return exit 0.
5. **The report path is the current directory.** Java writes to `env.getLogDir().orElse(user.home)` as `healthReport_<displayName>_<yyyyMMdd-HHmmss>.log`. The CLI has no log directory for a foreground command (the state dir belongs to the daemons and often lives under `/tmp`). We keep Java's **file name** exactly and place the file in the **cwd**; the path is named on stderr, or appears in the JSON under `report`. `--report FILE` overrides, `--no-report` suppresses. The timestamp is **UTC** instead of the system time zone, because the workspace has no time zone database and M7 gets no new dependency.
6. **Migration runs in place with backups, in a loop up to format 8.** Java's `Migrators.migrate` runs exactly *one* migrator and leaves the repetition to the app. `crypto migrate` loops internally (5→6→7→8) and reports the chain. Before each step the migrators create the same backups as Java (`attempt_backup` on `masterkey.cryptomator`, in v8 additionally implicitly via the new `vault.cryptomator`, which `open_vault` backs up when first opened). No copy of the whole vault – with several GB that would not be a safeguard but a second source of errors. The note "back it up beforehand" is part of the confirmation prompt.
7. **`--dry-run` is mandatory, not a convenience.** 6→7 renames every file in the vault. `crypto migrate --dry-run` lists the planned renames (old → new, including the `_n` collision resolution as far as it can be determined without writing) and the steps that would touch the key files, and changes nothing.
8. **Already at format 8 is not an error.** `crypto migrate` on a current vault reports "already at version 8" and ends with **0**. Exit **5** remains the state "needs migration" for all *other* commands (`unlock`, `fs`, `health`, …).
9. **Non-TTY without `--yes` is exit 2.** Both `migrate`'s confirmation prompt and Java's `REQUIRES_FULL_VAULT_DIR_SCAN` query in v7 become `AppError::NoPasswordSource`-style usage errors without a terminal — concretely `AppError::InvalidValue { key: "--yes", … }` → exit 2. A script that wants to migrate says so with `--yes`.
10. **`recovery-key restore --config` takes the vault password, not the recovery key.** That is Java's `RecoveryKeyCreationController.restoreWithPassword`: the `masterkey.cryptomator` is still there, only the `vault.cryptomator` is missing. `--masterkey` and `--all` take the recovery key plus a *new* password. Whoever mixes up the combination gets a usage error naming the right flag in the text.
11. **The check catalog is fixed, not pluggable.** Java loads `HealthCheck` via the `ServiceLoader`. We have three checks, they are called `dirid`, `type`, `shortened`, and `--check` takes a comma-separated list of them (default: all three, in this order). An unknown name is exit 2 with the list of valid ones.

---

## File structure

```
tools/fixture-gen/pom.xml                                   → reactor POM (packaging pom, <modules>)
tools/fixture-gen/gen-current/pom.xml                       NEW: the previous module (cryptofs 2.10.0)
tools/fixture-gen/gen-current/src/main/java/.../Gen.java    moved, + `broken` command
tools/fixture-gen/gen-legacy-v7/pom.xml                     NEW: cryptofs 1.9.15 → format 7
tools/fixture-gen/gen-legacy-v7/src/main/java/.../GenV7.java   NEW
tools/fixture-gen/gen-legacy-v6/pom.xml                     NEW: cryptofs 1.8.9  → format 6
tools/fixture-gen/gen-legacy-v6/src/main/java/.../GenV6.java   NEW
tools/fixture-gen/gen-legacy-v5/pom.xml                     NEW: cryptofs 1.6.2  → format 6, then stamped back down to 5
tools/fixture-gen/gen-legacy-v5/src/main/java/.../GenV5.java   NEW
tools/fixture-gen/README.md                                 docs for the new commands
tests/fixtures/broken_health/                               NEW (Task 1, generator only)
tests/fixtures/legacy_v7/  legacy_v6/  legacy_v5/           NEW (Task 2, generator only)

crates/cryptomator-core/src/lib.rs                          + pub mod health; pub mod migration; re-exports
crates/cryptomator-core/src/health/mod.rs                   NEW: Severity, DiagnosticResult, Fix, HealthCheck, CheckContext, run_checks, CHECK_IDS
crates/cryptomator-core/src/health/dir_id.rs                NEW: DirIdCheck + 8 result types + fixes
crates/cryptomator-core/src/health/orphan.rs                NEW: the LOST+FOUND fix from OrphanContentDir
crates/cryptomator-core/src/health/file_type.rs             NEW: CiphertextFileTypeCheck + 3 result types
crates/cryptomator-core/src/health/shortened.rs             NEW: ShortenedNamesCheck + 6 result types
crates/cryptomator-core/src/health/report.rs                NEW: ReportWriter format
crates/cryptomator-core/src/migration/mod.rs                NEW: Migrators, MigrationStep, MigrationPlan, assert_all_capabilities
crates/cryptomator-core/src/migration/v6.rs                 NEW: 5→6 (NFC)
crates/cryptomator-core/src/migration/v7.rs                 NEW: 6→7 (FilePathMigration, PreMigration, delete m/)
crates/cryptomator-core/src/migration/v8.rs                 NEW: 7→8 (vault.cryptomator)
crates/cryptomator-core/src/recovery/restore.rs             NEW: RecoveryDirectory, restore_*, detect_cipher_combo
crates/cryptomator-core/src/recovery/mod.rs                 + pub mod restore;
crates/cryptomator-core/src/error.rs                        + CoreError::{FileNameTooLong, MissingCapability, CipherComboUndetectable, MigrationBlocked}
crates/cryptomator-core/tests/common/mod.rs                 + fixture(), copy_fixture()
crates/cryptomator-core/tests/health.rs                     NEW: the three checks against broken_health
crates/cryptomator-core/tests/migration.rs                  NEW: the migrators against legacy_v{5,6,7}

crates/crypto/src/exit.rs                                   + HEALTH_FINDINGS = 11
crates/crypto/src/cli.rs                                    + Command::{Health, Migrate}, RecoveryKeyCommand::Restore
crates/crypto/src/commands/mod.rs                           + migratable_vault()
crates/crypto/src/commands/health.rs                        NEW: `crypto health`
crates/crypto/src/commands/migrate.rs                       NEW: `crypto migrate`
crates/crypto/src/commands/recovery.rs                      + restore()
crates/crypto/src/main.rs                                   + dispatch
crates/crypto/src/output.rs                                 + format_compact_timestamp()
crates/crypto/tests/cli_health.rs                           NEW
crates/crypto/tests/cli_migrate.rs                          NEW
crates/crypto/tests/cli.rs                                  + recovery-key restore
crates/crypto/tests/cli_daemon.rs                           log assertion for the detached daemon (addendum)
crates/crypto/tests/java_interop.rs                         + migrated legacy vaults through `verify`
.github/workflows/ci.yml                                    interop-java downloads the legacy artifacts too
README.md, CHANGELOG.md, Spec                               docs
```

### Common types (details in the tasks)

- `cryptomator_core::health::{Severity, DiagnosticResult, Fix, HealthCheck, CheckContext, run_checks, checks_by_ids, CHECK_IDS, ALL_CHECKS}` (Task 3).
- `cryptomator_core::health::dir_id::{DirIdCheck, DIR_ID_CHECK_NAME}` (Task 4), `health::orphan::AdoptOrphan` (Task 5).
- `cryptomator_core::health::file_type::{CiphertextFileTypeCheck, TYPE_CHECK_NAME}` and `health::shortened::{ShortenedNamesCheck, SHORTENED_CHECK_NAME}` (Task 6).
- `cryptomator_core::health::report::{write_report, report_file_name, REPORT_HEADER, CHECK_SEPARATOR}` (Task 7).
- `cryptomator_core::migration::{Migrators, MigrationStep, MigrationPlan, PlannedRename, assert_all_capabilities}` (Task 10, extended in 11).
- `cryptomator_core::recovery::restore::{RecoveryDirectory, restore_masterkey, restore_config, restore_all, detect_cipher_combo}` (Task 13).
- `crypto::exit::HEALTH_FINDINGS` (Task 8), `crypto::commands::migratable_vault` (Task 12).

---

### Task 1: Damaged fixture `broken_health` from the Java harness

**Files:**
- Modify: `tools/fixture-gen/pom.xml` (reactor), `tools/fixture-gen/README.md`
- Create: `tools/fixture-gen/gen-current/pom.xml`
- Move: `tools/fixture-gen/src/main/java/org/cryptomator/cli/fixtures/Gen.java` → `tools/fixture-gen/gen-current/src/main/java/org/cryptomator/cli/fixtures/Gen.java`
- Create (generator output, **the only permitted change under `tests/fixtures/`**): `tests/fixtures/broken_health/`
- Test: `crates/cryptomator-core/tests/common/mod.rs`, `crates/cryptomator-core/tests/health.rs`

**Interfaces:**
- Consumes: the existing `Gen.java` (cryptofs 2.10.0), `Gen.PASSPHRASE = "test-password-123"`, `Gen.KEY_ID`.
- Produces:
  - Maven: `mvn -q -f tools/fixture-gen/pom.xml compile` builds the reactor; `mvn -q -f tools/fixture-gen/gen-current/pom.xml compile exec:exec -Dfixture.cmd=broken -Dfixture.arg1=<outDir>` produces `<outDir>/broken_health`.
  - `tests/fixtures/broken_health/` – a SIV_GCM vault, threshold 220, passphrase `test-password-123`, plus `fixture.json` (as before) and `expected-findings.json`:
    ```json
    [ { "check": "dirid", "severity": "WARN",  "result": "OrphanContentDir", "path": "d/…/…" }, … ]
    ```
  - Rust: `cryptomator_core::tests::common::{fixture, copy_fixture}` (in `crates/cryptomator-core/tests/common/mod.rs`).

- [ ] **Step 1: Create the reactor**

`tools/fixture-gen/pom.xml` becomes the aggregator; the previous content (dependencies, exec plugin) moves into `gen-current/pom.xml` and gets a `<parent>` there. New aggregator POM:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.cryptomator.cli</groupId>
  <artifactId>fixture-gen</artifactId>
  <version>0.1.0</version>
  <packaging>pom</packaging>
  <properties>
    <maven.compiler.release>21</maven.compiler.release>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    <fixture.cmd>gen</fixture.cmd>
    <fixture.arg1>${project.basedir}/../../tests/fixtures</fixture.arg1>
    <fixture.arg2></fixture.arg2>
  </properties>
  <modules>
    <module>gen-current</module>
    <module>gen-legacy-v7</module>
    <module>gen-legacy-v6</module>
    <module>gen-legacy-v5</module>
  </modules>
</project>
```

`gen-current/pom.xml` inherits from it and keeps everything as before unchanged – dependencies (cryptofs 2.10.0, gson 2.13.2, slf4j-simple 2.0.17), the `exec-maven-plugin` with `exec:exec` and the forked JVM invocation, plus `<exec.mainClass>org.cryptomator.cli.fixtures.Gen</exec.mainClass>`. The default of `fixture.arg1` becomes `${project.basedir}/../../../tests/fixtures` (one level deeper than before).

**The `gen-legacy-*` modules are created by Task 2.** So that this task builds on its own, they are **not** listed in `<modules>` here yet; Task 2 adds the three lines. In this task the reactor therefore has exactly one module entry, `gen-current`.

- [ ] **Step 2: Verify that the reactor builds unchanged and reproduces the old fixtures**

Run: `cd /Users/rfoerthe/work/cryptomator-cli && mvn -q -f tools/fixture-gen/pom.xml compile`
Expected: BUILD SUCCESS, no output.

Run: `cargo test -p crypto --test java_interop --locked -- --ignored`
Expected: all tests green (the interop test calls `-f tools/fixture-gen/pom.xml`; it has to be switched over to `gen-current/pom.xml` – that is part of this step, `crates/crypto/tests/java_interop.rs::run_java_verify` gets `"tools/fixture-gen/gen-current/pom.xml"`).

- [ ] **Step 3: The `broken` command in `Gen.java`**

`main` gets a third branch; `argv.get(0).equals("broken")` with one argument (the output directory). The flow: first create a healthy vault `broken_health` with a known structure (same mechanics as `generate`, masterkey = SHA-512("broken_health")), then damage the ciphertext in a targeted way and record the expected findings.

```java
static final String BROKEN_NAME = "broken_health";

static void broken(Path out) throws Exception {
    Path vault = out.resolve(BROKEN_NAME);
    Spec spec = new Spec(BROKEN_NAME, CryptorProvider.Scheme.SIV_GCM, 220, fs -> {
        write(fs, "/healthy.txt", "this file stays intact\n");
        Files.createDirectory(fs.getPath("/keep"));           // stays intact
        write(fs, "/keep/inside.txt", "kept\n");
        Files.createDirectory(fs.getPath("/orphaned"));       // becomes the orphan directory
        write(fs, "/orphaned/adopted.txt", "adopt me\n");
        Files.createDirectory(fs.getPath("/nodirid"));        // loses its dirid.c9r
        Files.createDirectory(fs.getPath("/nocontent"));      // loses its content directory
        write(fs, "/" + "L".repeat(200) + ".txt", "shortened\n");   // becomes .c9s
        write(fs, "/" + "M".repeat(200) + ".txt", "mismatch\n");    // .c9s with the wrong name
        write(fs, "/" + "T".repeat(200) + ".txt", "trailing\n");    // .c9s with trailing bytes
        write(fs, "/" + "N".repeat(200) + ".txt", "noname\n");      // .c9s without name.c9s
    });
    generate(vault, spec);                                    // also writes fixture.json/expected.json
    List<Map<String, Object>> findings = damage(vault);
    var gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
    Files.writeString(vault.resolve("expected-findings.json"), gson.toJson(findings) + "\n", StandardCharsets.UTF_8);
    Files.delete(vault.resolve("expected.json"));  // the cleartext tree is meaningless after the damage
}
```

- [ ] **Step 4: `damage(Path vault)` – the nine damage cases**

`damage` opens the vault with cryptolib (masterkey from `fixture.json`), builds a `Cryptor` for the name functions, and from then on writes only at the ciphertext level. Each case produces one line in `expected-findings.json` with `check`, `severity`, `result`, and `path` (vault-relative, with `/` as the separator – Ruling 1).

| # | Damage | Expected finding |
|---|---|---|
| 1 | delete the file `dir.c9r` in the `.c9r` node of `/orphaned` (the content directory stays) | `dirid` WARN `OrphanContentDir` on `d/XX/YYY…` |
| 2 | delete the `dirid.c9r` in the content directory of `/nodirid` | `dirid` INFO `MissingDirIdBackup` |
| 3 | delete the content directory of `/nocontent` recursively (the `dir.c9r` stays) | `dirid` WARN `MissingContentDir` |
| 4 | create an empty file `d/XX/YYY…/dir.c9r` next to the root directory, where `XX/YYY…` is the root content directory → the parent name does not end in `.c9r`/`.c9s` | `dirid` INFO `LooseDirFile` |
| 5 | write the dirId of `/keep` a second time in a newly created `d/<root>/collide.c9r/dir.c9r` | `dirid` CRITICAL `DirIdCollision` |
| 6 | create a new `d/<root>/unknown.c9r/` that contains neither `dir.c9r` nor `symlink.c9r` nor `contents.c9r` (put an irrelevant file `x` inside so that the directory exists and is not empty) | `type` CRITICAL `UnknownType` |
| 7 | overwrite the `name.c9s` in the `.c9s` node of `M…` with the name of a *different* node | `shortened` WARN `LongShortNamesMismatch` |
| 8 | append the text `garbage` to the `name.c9s` of `T…` | `shortened` WARN `TrailingBytesInNameFile` |
| 9 | delete the `name.c9s` in the `.c9s` node of `N…` | `shortened` CRITICAL `MissingLongName` |

Case 4 needs a parent name that has *no* `.c9r`/`.c9s` suffix: Java checks `parentDirName.endsWith(".c9r") || endsWith(".c9s")`. The root content directory `d/XX/YYY…` is 30 BASE32 characters — so `Files.writeString(rootContentDir.resolve("dir.c9r"), "")`. It is empty at the same time, but `EmptyDirFile` is not reported: the `LooseDirFile` branch comes **before** the size check and ends with `CONTINUE`.

Beyond the nine lines, `expected-findings.json` contains **no** `GOOD` findings – the Rust test only counts those, it does not compare them individually.

Helper function for cases 5/6, because new ciphertext names are needed there:

```java
static String cipherName(Cryptor cryptor, String clear, String dirId) {
    return cryptor.fileNameCryptor().encryptFilename(BaseEncoding.base64Url(), clear,
            dirId.getBytes(StandardCharsets.UTF_8)) + ".c9r";
}
static Path contentDir(Path vault, Cryptor cryptor, String dirId) {
    String h = cryptor.fileNameCryptor().hashDirectoryId(dirId);
    return vault.resolve("d").resolve(h.substring(0, 2)).resolve(h.substring(2));
}
```

- [ ] **Step 5: Generate the fixture and check its size**

Run:
```bash
cd /Users/rfoerthe/work/cryptomator-cli
mvn -q -f tools/fixture-gen/gen-current/pom.xml compile exec:exec \
    -Dfixture.cmd=broken -Dfixture.arg1=tests/fixtures
du -sh tests/fixtures/broken_health
```
Expected: the directory exists and is **under 200 KB**. If it is larger, the file contents are too long – they are all single-line, so that must not happen; otherwise shorten the contents and regenerate.

Run: `cat tests/fixtures/broken_health/expected-findings.json`
Expected: nine objects, each with `check` ∈ {`dirid`,`type`,`shortened`}, `severity` ∈ {`INFO`,`WARN`,`CRITICAL`} and a vault-relative `path`.

- [ ] **Step 6: Rust test helpers and the first (still trivially green) test**

`crates/cryptomator-core/tests/common/mod.rs` gets:

```rust
use std::path::{Path, PathBuf};

pub fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures").join(name)
}

/// Copies a fixture into a tempdir. Every test that writes (health fixes, migration,
/// restore) works exclusively on such a copy -- `tests/fixtures/` stays untouched.
pub fn copy_fixture(name: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let dst = dir.path().join(name);
    copy_recursively(&fixture(name), &dst);
    (dir, dst)
}

pub fn copy_recursively(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).expect("create dir");
    for entry in std::fs::read_dir(src).expect("read dir") {
        let entry = entry.expect("entry");
        let target = dst.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_recursively(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).expect("copy");
        }
    }
}
```

New file `crates/cryptomator-core/tests/health.rs` with the manifest type and a test that only proves the fixture is there and readable:

```rust
mod common;
use serde::Deserialize;

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExpectedFinding {
    pub check: String,
    pub severity: String,
    pub result: String,
    pub path: String,
}

pub fn expected_findings() -> Vec<ExpectedFinding> {
    let raw = std::fs::read_to_string(common::fixture("broken_health").join("expected-findings.json"))
        .expect("expected-findings.json");
    serde_json::from_str(&raw).expect("valid manifest")
}

#[test]
fn the_broken_fixture_carries_nine_expected_findings() {
    let findings = expected_findings();
    assert_eq!(findings.len(), 9, "{findings:#?}");
    assert!(findings.iter().any(|f| f.result == "OrphanContentDir"));
    assert!(findings.iter().any(|f| f.result == "MissingLongName"));
    // The vault still opens -- what is damaged is the structure, not the key.
    let (_tmp, vault) = common::copy_fixture("broken_health");
    cryptomator_core::open_vault(
        &vault,
        &cryptomator_core::MasterkeyFileAccess::new(Vec::new()),
        "test-password-123",
    )
    .expect("the vault still opens");
}
```

- [ ] **Step 7: Tests, Gate, Commit**

Run: `cargo test -p cryptomator-core --test health --locked`
Expected: 1 passed.

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked`
Expected: everything green.

```bash
git add tools/fixture-gen tests/fixtures/broken_health crates/cryptomator-core/tests crates/crypto/tests/java_interop.rs
git commit -m "test: damaged reference vault broken_health from the Java harness

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 2: Legacy fixtures v7, v6, and v5

**Files:**
- Modify: `tools/fixture-gen/pom.xml` (three `<module>` entries), `tools/fixture-gen/README.md`
- Create: `tools/fixture-gen/gen-legacy-v7/{pom.xml,src/main/java/org/cryptomator/cli/fixtures/GenV7.java}`
- Create: `tools/fixture-gen/gen-legacy-v6/{pom.xml,src/main/java/org/cryptomator/cli/fixtures/GenV6.java}`
- Create: `tools/fixture-gen/gen-legacy-v5/{pom.xml,src/main/java/org/cryptomator/cli/fixtures/GenV5.java}`
- Create (generator output): `tests/fixtures/legacy_v7/`, `tests/fixtures/legacy_v6/`, `tests/fixtures/legacy_v5/`
- Test: `crates/cryptomator-core/tests/migration.rs`

**Interfaces:**
- Consumes: `common::{fixture, copy_fixture}` (Task 1), `cryptomator_core::{determine_vault_version, needs_migration, VaultState, determine_vault_state}`.
- Produces: three fixture directories, each with a `fixture.json`:
  ```json
  { "name": "legacy_v7", "vaultVersion": 7, "passphrase": "test-password-123",
    "masterkeyHex": "…", "expected": [ { "path": "/hello.txt", "type": "file", "sha256": "…" }, … ] }
  ```
  For `legacy_v5`, `"passphrase"` is the **NFD** form of `"tästpaß-123"` (i.e. `a` + U+0308 instead of `ä`), plus the NFC form as `"passphraseNfc"`.

**Important upfront (verified):** `~/.m2` contains **only** cryptofs 2.10.0. The three legacy artifacts are present on Maven Central (`https://repo1.maven.org/maven2/org/cryptomator/cryptofs/{1.9.15,1.8.9,1.6.2}/` → HTTP 200, checked), but they are downloaded on the first build: **this task needs network access.** Without network, Maven aborts with `Could not resolve dependencies`; then the task is to be deferred, not worked around.

**Second finding (verified):** `Constants.VAULT_VERSION` in cryptofs is **1.9.15 = 7**, **1.8.9 = 6** and **1.6.2 = 6** – there is no library that writes format 5. Formats 5 and 6 differ solely in the passphrase normalization (the `Version6Migrator` only rewrites the masterkey file with an NFC passphrase, the directory structure stays the same). `gen-legacy-v5` therefore uses **1.6.2** to create a vault with an **NFD** passphrase and afterwards stamps the masterkey file down to `version: 5`, including a recomputed `versionMac` = HMAC-SHA256(hmacMasterKey, BE32(5)). That is exactly what a real v5 vault is.

- [ ] **Step 1: `gen-legacy-v7`**

`tools/fixture-gen/gen-legacy-v7/pom.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>org.cryptomator.cli</groupId>
    <artifactId>fixture-gen</artifactId>
    <version>0.1.0</version>
  </parent>
  <artifactId>gen-legacy-v7</artifactId>
  <properties>
    <exec.mainClass>org.cryptomator.cli.fixtures.GenV7</exec.mainClass>
    <fixture.arg1>${project.basedir}/../../../tests/fixtures</fixture.arg1>
  </properties>
  <dependencies>
    <dependency><groupId>org.cryptomator</groupId><artifactId>cryptofs</artifactId><version>1.9.15</version></dependency>
    <dependency><groupId>com.google.code.gson</groupId><artifactId>gson</artifactId><version>2.13.2</version></dependency>
    <dependency><groupId>org.slf4j</groupId><artifactId>slf4j-simple</artifactId><version>2.0.17</version></dependency>
  </dependencies>
  <build><plugins><plugin>
    <groupId>org.codehaus.mojo</groupId><artifactId>exec-maven-plugin</artifactId><version>3.5.0</version>
    <configuration>
      <executable>java</executable>
      <arguments>
        <argument>-classpath</argument><classpath/>
        <argument>${exec.mainClass}</argument>
        <argument>${fixture.arg1}</argument>
      </arguments>
    </configuration>
  </plugin></plugins></build>
</project>
```

`GenV7.java` – cryptofs 1.x has a completely different API from 2.x: no `Masterkey` object, no `withKeyLoader`, passphrase-based instead.

```java
package org.cryptomator.cli.fixtures;

import com.google.gson.GsonBuilder;
import org.cryptomator.cryptofs.CryptoFileSystem;
import org.cryptomator.cryptofs.CryptoFileSystemProperties;
import org.cryptomator.cryptofs.CryptoFileSystemProvider;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

/** Creates a vault in format 7 with cryptofs 1.9.15 (Constants.VAULT_VERSION == 7). */
public final class GenV7 {

    static final String NAME = "legacy_v7";
    static final String PASSPHRASE = "test-password-123";
    static final String MASTERKEY = "masterkey.cryptomator";

    public static void main(String[] args) throws Exception {
        Path out = Path.of(args[0]);
        Path vault = out.resolve(NAME);
        LegacySupport.recreate(vault);
        CryptoFileSystemProvider.initialize(vault, MASTERKEY, PASSPHRASE);
        CryptoFileSystemProperties props = CryptoFileSystemProperties.cryptoFileSystemProperties()
                .withPassphrase(PASSPHRASE).withMasterkeyFilename(MASTERKEY).build();
        List<Map<String, Object>> expected = new ArrayList<>();
        try (CryptoFileSystem fs = CryptoFileSystemProvider.newFileSystem(vault, props)) {
            LegacySupport.populate(fs);
            LegacySupport.walk(fs.getPath("/"), expected);
        }
        LegacySupport.writeManifest(vault, NAME, 7, PASSPHRASE, null, expected);
        System.out.println("generated " + NAME);
    }

    private GenV7() {}
}
```

`LegacySupport` is a small class that exists as a copy in **each** of the three legacy modules (the modules share no code, because they have incompatible cryptofs versions on the classpath and `CryptoFileSystem` has different signatures in 1.6.2/1.8.9/1.9.15). Its content:

```java
static void recreate(Path vault) throws IOException {          // deletes recursively and creates anew
static void populate(CryptoFileSystem fs) throws IOException {
    Files.writeString(fs.getPath("/hello.txt"), "Hello, legacy!\n", StandardCharsets.UTF_8);
    Files.createDirectory(fs.getPath("/docs"));
    Files.writeString(fs.getPath("/docs/notes.md"), "# Notes\n\nlegacy\n", StandardCharsets.UTF_8);
    Files.createDirectory(fs.getPath("/docs/deep"));
    Files.writeString(fs.getPath("/docs/deep/inner.txt"), "nested\n", StandardCharsets.UTF_8);
    // A name that grows longer than 129 characters and therefore lands in v5/v6 as a `.lng` in `m/`
    // (Constants.SHORT_NAMES_MAX_LENGTH == 129), or in v7 as a `.c9s`:
    Files.writeString(fs.getPath("/" + "l".repeat(150) + ".txt"), "long name\n", StandardCharsets.UTF_8);
    Files.createSymbolicLink(fs.getPath("/link.txt"), fs.getPath("hello.txt"));
}
static void walk(Path dir, List<Map<String, Object>> out) throws IOException {   // like Gen.walk
static void writeManifest(Path vault, String name, int version, String passphrase,
                          String passphraseNfc, List<Map<String, Object>> expected) throws IOException
```

`walk` and `sha256` are taken verbatim from `gen-current/…/Gen.java` (path, type, size, SHA-256, symlink target). `writeManifest` writes `fixture.json` with `name`, `vaultVersion`, `passphrase`, optionally `passphraseNfc`, `masterkeyHex` (the raw key cannot be read out of the generated masterkey file – the field is omitted here, unlike in `Gen`) and `expected`.

- [ ] **Step 2: `gen-legacy-v6`**

Identical to Step 1, but `<version>1.8.9</version>`, class `GenV6`, `NAME = "legacy_v6"`, `vaultVersion = 6`. In 1.8.9 `Constants` lives in the package `org.cryptomator.cryptofs` (not `…cryptofs.common`) – that does not matter for `GenV6`, because only the public provider API is used, which is identical (`initialize(Path, String, CharSequence)`, `newFileSystem(Path, CryptoFileSystemProperties)`, builder with `withPassphrase`/`withMasterkeyFilename`).

The vault produced this way has the v6 structure: `d/XX/YYY…/BASE32==` for files, `0BASE32==` for directories, `1SBASE32==` for symlinks, and `m/xx/yy/<32 BASE32 characters>.lng` for the 150-character name.

- [ ] **Step 3: `gen-legacy-v5`**

`<version>1.6.2</version>`, class `GenV5`, `NAME = "legacy_v5"`. Two differences from Step 2:

1. The passphrase is **NFD**: `String PASSPHRASE_NFD = "tästpaß-123";` (that is `t`, `a`, U+0308 COMBINING DIAERESIS, `stpaß-123`) and `String PASSPHRASE_NFC = java.text.Normalizer.normalize(PASSPHRASE_NFD, java.text.Normalizer.Form.NFC);`. The vault is initialized with **PASSPHRASE_NFD**; cryptolib 1.x does not normalize, so the KEK is derived from exactly these bytes. An `assert !PASSPHRASE_NFD.equals(PASSPHRASE_NFC)` in the generator makes sure the difference is really there.
2. After the file system is closed, the masterkey file is stamped over to version 5:

```java
static void stampVersion5(Path masterkeyFile) throws Exception {
    var gson = new com.google.gson.Gson();
    var obj = gson.fromJson(Files.readString(masterkeyFile), com.google.gson.JsonObject.class);
    obj.addProperty("version", 5);
    byte[] hmacKey = Base64.getDecoder().decode(obj.get("hmacMasterKey").getAsString());
    // This is the *wrapped* HMAC key -- the versionMac is formed with the *unwrapped*
    // one. So go through cryptolib instead of computing it yourself:
    //   Cryptor c = Cryptors.version1(csprng).createFromKeyFile(KeyFile.parse(bytes), pass, 6);
    //   byte[] mac = c.fileHeaderCryptor() ...   -- not public in 1.x.
    // Solution: let cryptolib write the versionMac bytes itself, by rewriting the vault with
    // `CryptoFileSystemProvider.changePassphrase(vault, MASTERKEY, pass, pass)` -- but that
    // cannot set the version.
    throw new UnsupportedOperationException("see Step 4");
}
```

The block above is **deliberately** a dead end and stands here so that the implementer does not run into it again: the `versionMac` needs the unwrapped HMAC key, which cryptolib 1.x does not hand out. The viable route is in Step 4.

- [ ] **Step 4: Stamp version 5 correctly – via our own `MasterkeyFileAccess`**

The `versionMac` is **not** computed in Java but in Rust, in an `#[ignore]` test that finishes the fixture. Reason: `crates/cryptomator-core/src/masterkey_file.rs` can already do exactly that (`MasterkeyFileAccess::{load, persist}` with a `vault_version` parameter, `lock()` writes `versionMac` = HMAC-SHA256 over `vault_version.to_be_bytes()` under the MAC key), and cryptolib 1.x and 2.x write bit-identical masterkey files.

`GenV5.main` therefore creates a vault with `version: 6` and the NFD passphrase and reports that in the manifest as `"vaultVersion": 5, "stampPending": true`. After that, the following runs in `crates/cryptomator-core/tests/migration.rs`:

```rust
/// Stamps `tests/fixtures/legacy_v5/masterkey.cryptomator` over from version 6 to 5. Runs once
/// after `mvn … GenV5` and is the only test that writes into `tests/fixtures/` -- hence `#[ignore]`.
/// Invocation: `cargo test -p cryptomator-core --test migration -- --ignored stamp_legacy_v5`
#[test]
#[ignore = "regenerates a checked-in fixture; run only after the Java generator"]
fn stamp_legacy_v5() {
    let vault = common::fixture("legacy_v5");
    let masterkey = vault.join("masterkey.cryptomator");
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(vault.join("fixture.json")).unwrap()).unwrap();
    let passphrase = manifest["passphrase"].as_str().unwrap().to_string();
    let access = cryptomator_core::MasterkeyFileAccess::new(Vec::new());
    let key = access.load(&masterkey, &passphrase).expect("the NFD passphrase opens it");
    access
        .persist(&key, &masterkey, &passphrase, 5, &mut cryptomator_core::OsRng)
        .expect("rewrite as version 5");
    assert_eq!(cryptomator_core::determine_vault_version(&vault).unwrap(), 5);
}
```

The test run then also flips `stampPending` to `false` — no: simpler and stateless, `writeManifest` leaves the field out entirely and writes `"vaultVersion": 5` directly; the Rust test is the second part of the same generator step and is documented as such in `tools/fixture-gen/README.md`. After the stamping the file is finished and gets checked in.

- [ ] **Step 5: Generate all three fixtures**

Run:
```bash
cd /Users/rfoerthe/work/cryptomator-cli
mvn -q -f tools/fixture-gen/pom.xml compile                      # downloads 1.9.15/1.8.9/1.6.2 into ~/.m2
mvn -q -f tools/fixture-gen/gen-legacy-v7/pom.xml exec:exec
mvn -q -f tools/fixture-gen/gen-legacy-v6/pom.xml exec:exec
mvn -q -f tools/fixture-gen/gen-legacy-v5/pom.xml exec:exec
cargo test -p cryptomator-core --test migration --locked -- --ignored stamp_legacy_v5
du -sh tests/fixtures/legacy_v*
```
Expected: three directories, each **under 200 KB**; `generated legacy_v7|v6|v5` on stdout; the Rust test green.

If the first `mvn` call fails with `Could not resolve dependencies`, the network is missing – record it in the report and abort the task, do not change the versions.

- [ ] **Step 6: Prove the structure of the three fixtures**

Run:
```bash
ls tests/fixtures/legacy_v7/d/*/*/ | head
ls tests/fixtures/legacy_v6/ && ls tests/fixtures/legacy_v6/m/*/*/ | head
ls tests/fixtures/legacy_v5/ && head -c 200 tests/fixtures/legacy_v5/masterkey.cryptomator
```
Expected: `legacy_v7` has `.c9r`/`.c9s` names and **no** `m/`; `legacy_v6` and `legacy_v5` have BASE32 names with `0`/`1S` prefixes and an `m/xx/yy/…lng`; the v5 masterkey file starts with `{"version": 5,` (or `"version":5`).

- [ ] **Step 7: Rust test over the detected versions**

In `crates/cryptomator-core/tests/migration.rs`:

```rust
mod common;
use cryptomator_core::{determine_vault_state, determine_vault_version, needs_migration, VaultState};

#[test]
fn the_legacy_fixtures_report_their_formats() {
    for (name, version) in [("legacy_v7", 7u32), ("legacy_v6", 6), ("legacy_v5", 5)] {
        let vault = common::fixture(name);
        assert_eq!(determine_vault_version(&vault).unwrap(), version, "{name}");
        assert!(needs_migration(&vault).unwrap(), "{name}");
        assert_eq!(determine_vault_state(&vault).unwrap(), VaultState::NeedsMigration, "{name}");
        assert!(!vault.join("vault.cryptomator").exists(), "{name} has no vault config yet");
    }
    // v6 and v5 have the metadata directory, v7 no longer does.
    assert!(common::fixture("legacy_v6").join("m").is_dir());
    assert!(common::fixture("legacy_v5").join("m").is_dir());
    assert!(!common::fixture("legacy_v7").join("m").exists());
}

#[test]
fn the_v5_fixture_needs_an_nfd_passphrase() {
    let vault = common::fixture("legacy_v5");
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(vault.join("fixture.json")).unwrap()).unwrap();
    let nfd = manifest["passphrase"].as_str().unwrap();
    let nfc = manifest["passphraseNfc"].as_str().unwrap();
    assert_ne!(nfd, nfc, "the point of the v5 fixture is that the two forms differ");
    let access = cryptomator_core::MasterkeyFileAccess::new(Vec::new());
    assert!(access.load(&vault.join("masterkey.cryptomator"), nfd).is_ok());
    assert!(access.load(&vault.join("masterkey.cryptomator"), nfc).is_err(),
            "before the 5->6 migration only the NFD form opens the vault");
}
```

- [ ] **Step 8: Docs, gate, commit**

`tools/fixture-gen/README.md` gets a section "Legacy fixtures" with the four commands from Step 5, the note about the network requirement on the first run, and the sentence that `legacy_v5` is only finished after the Rust stamping step.

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked`
Expected: green (the `stamp_legacy_v5` test does not run there, it is `#[ignore]`).

```bash
git add tools/fixture-gen tests/fixtures/legacy_v7 tests/fixtures/legacy_v6 tests/fixtures/legacy_v5 crates/cryptomator-core/tests/migration.rs
git commit -m "test: legacy reference vaults for formats 7, 6 and 5

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 3: The health scaffolding – `Severity`, `DiagnosticResult`, `Fix`, `HealthCheck`, `CheckContext`

**Files:**
- Create: `crates/cryptomator-core/src/health/mod.rs`
- Modify: `crates/cryptomator-core/src/lib.rs`, `crates/cryptomator-core/src/error.rs`
- Test: in `crates/cryptomator-core/src/health/mod.rs` (`#[cfg(test)] mod tests`)

**Interfaces:**
- Consumes: `crate::crypto::cryptor::Cryptor`, `crate::crypto::rng::{Rng, OsRng}`, `crate::vault_config::VaultConfig`, `crate::vault::open::OpenedVault`, `crate::error::{CoreError, Result}`.
- Produces:
```rust
pub const CHECK_IDS: [&str; 3] = ["dirid", "type", "shortened"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity { Good, Info, Warn, Critical }
impl Severity {
    pub fn as_str(self) -> &'static str;          // "GOOD" | "INFO" | "WARN" | "CRITICAL"
    pub fn parse_threshold(s: &str) -> Result<Severity>;  // only "WARN" | "CRITICAL", case-insensitive
}

pub trait Fix: std::fmt::Debug + Send {
    fn apply(&self, ctx: &CheckContext) -> std::io::Result<()>;
}

#[derive(Debug)]
pub struct DiagnosticResult {
    pub severity: Severity,
    pub check: &'static str,        // one of the CHECK_IDS
    pub message: String,            // word for word with Java's toString()
    pub paths: Vec<PathBuf>,        // vault-relative (Ruling 1)
    pub fix: Option<Box<dyn Fix>>,
}
impl DiagnosticResult {
    pub fn new(check: &'static str, severity: Severity, message: String, paths: Vec<PathBuf>) -> Self;
    pub fn with_fix(self, fix: Box<dyn Fix>) -> Self;
    pub fn fixable(&self) -> bool;
}

pub trait HealthCheck: std::fmt::Debug {
    fn id(&self) -> &'static str;              // "dirid" | "type" | "shortened"
    fn name(&self) -> &'static str;            // Java's HealthCheck.name(), for the report
    fn run(&self, ctx: &CheckContext, sink: &mut dyn FnMut(DiagnosticResult));
}

#[derive(Debug)]
pub struct CheckContext { pub vault_path: PathBuf, pub cryptor: Cryptor, pub config: VaultConfig, rng: Mutex<Box<dyn Rng + Send>> }
impl CheckContext {
    pub fn new(opened: OpenedVault) -> Self;                       // OsRng
    pub fn with_rng(opened: OpenedVault, rng: Box<dyn Rng + Send>) -> Self;
    pub fn data_dir(&self) -> PathBuf;                             // <vault>/d
    pub fn resolve(&self, relative: &Path) -> PathBuf;             // vault_path.join(relative)
    pub fn relativize(&self, absolute: &Path) -> PathBuf;          // strip_prefix(vault_path), otherwise unchanged
    pub fn rng<T>(&self, f: impl FnOnce(&mut dyn Rng) -> T) -> T;  // serialized through the mutex
}

pub fn all_checks() -> Vec<Box<dyn HealthCheck>>;
pub fn checks_by_ids(ids: &[String]) -> Result<Vec<Box<dyn HealthCheck>>>;
pub fn run_checks(checks: &[Box<dyn HealthCheck>], ctx: &CheckContext) -> Vec<DiagnosticResult>;
```
plus `CoreError::UnknownHealthCheck(String)` (→ exit 2 through the `CoreError::InvalidArgument` neighbourhood; see Step 3).

- [ ] **Step 1: Failing test for `Severity` and the catalog**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severities_order_from_good_to_critical() {
        assert!(Severity::Good < Severity::Info);
        assert!(Severity::Info < Severity::Warn);
        assert!(Severity::Warn < Severity::Critical);
        assert_eq!(Severity::Critical.as_str(), "CRITICAL");
    }

    #[test]
    fn only_warn_and_critical_are_thresholds() {
        assert_eq!(Severity::parse_threshold("warn").unwrap(), Severity::Warn);
        assert_eq!(Severity::parse_threshold("CRITICAL").unwrap(), Severity::Critical);
        assert!(Severity::parse_threshold("INFO").is_err());
        assert!(Severity::parse_threshold("").is_err());
    }

    #[test]
    fn the_catalogue_has_three_checks_in_a_fixed_order() {
        let ids: Vec<_> = all_checks().iter().map(|c| c.id()).collect();
        assert_eq!(ids, vec!["dirid", "type", "shortened"]);
        assert_eq!(ids, CHECK_IDS.to_vec());
    }

    #[test]
    fn checks_by_ids_keeps_the_catalogue_order_and_dedupes() {
        let selected = checks_by_ids(&["shortened".into(), "dirid".into(), "dirid".into()]).unwrap();
        let ids: Vec<_> = selected.iter().map(|c| c.id()).collect();
        assert_eq!(ids, vec!["dirid", "shortened"]);
    }

    #[test]
    fn an_unknown_check_names_the_valid_ones() {
        let err = checks_by_ids(&["bogus".into()]).unwrap_err().to_string();
        assert!(err.contains("bogus") && err.contains("dirid") && err.contains("shortened"), "{err}");
    }
}
```

- [ ] **Step 2: Run – must fail**

Run: `cargo test -p cryptomator-core health::tests --locked`
Expected: FAIL, `unresolved module` / `cannot find`.

- [ ] **Step 3: Implement**

`health/mod.rs` with the types from the Interfaces block. Details that leave nothing to guess:

- `Severity` derives `PartialOrd, Ord` in the declaration order `Good, Info, Warn, Critical` – `--fail-on` and `--fix-severity` hang off that.
- `parse_threshold` accepts `"warn"`/`"critical"` case-insensitively and otherwise returns
  `CoreError::InvalidArgument(format!("unknown severity {input:?}; expected WARN or CRITICAL"))`.
- `checks_by_ids` walks **`CHECK_IDS` in catalog order** and picks up every ID that occurs in `ids` (which gives dedup and a stable order, independent of how the user sorted them). It then checks that every element of `ids` is in `CHECK_IDS`, and otherwise reports
  `CoreError::InvalidArgument(format!("unknown check {id:?}; valid checks are {}", CHECK_IDS.join(", ")))`.
- `all_checks()` returns `vec![Box::new(DirIdCheck), Box::new(CiphertextFileTypeCheck), Box::new(ShortenedNamesCheck)]`. **In this task the three types do not exist yet.** Until Task 4/6 deliver them, `all_checks()` contains exactly this:
  ```rust
  pub fn all_checks() -> Vec<Box<dyn HealthCheck>> {
      // Task 4 replaces the first line, Task 6 the second and third, with the real checks.
      vec![
          Box::new(Placeholder { id: "dirid", name: "Directory Check" }),
          Box::new(Placeholder { id: "type", name: "Resource Type Check" }),
          Box::new(Placeholder { id: "shortened", name: "Shortened Names Check" }),
      ]
  }

  /// Only until Task 4/6: a check that finds nothing. It is here so that `run_checks`, `--check`
  /// and the report can already be tested in this task.
  #[derive(Debug)]
  struct Placeholder { id: &'static str, name: &'static str }
  impl HealthCheck for Placeholder {
      fn id(&self) -> &'static str { self.id }
      fn name(&self) -> &'static str { self.name }
      fn run(&self, _ctx: &CheckContext, _sink: &mut dyn FnMut(DiagnosticResult)) {}
  }
  ```
- `run_checks` calls each check in turn, collects into a `Vec`, and returns it **in the order check → time of finding**. No concurrency: Java streams via an executor, we do not need that and a deterministic report is worth more.
- Panics from a check are **not** caught; a panic is a bug, not a finding. We reproduce Java's `CheckFailed` (CRITICAL) for the one case Java catches too: a `walkdir` error while traversing – the checks do that themselves in Task 4/6.
- `CheckContext::relativize` uses `strip_prefix(&self.vault_path).unwrap_or(absolute)` and returns a `PathBuf`.
- `CheckContext::rng` locks the `Mutex` with `lock().unwrap_or_else(|e| e.into_inner())` (the same pattern as `Ctx::keychain`).

`lib.rs`: `pub mod health;` and
```rust
pub use health::{
    all_checks, checks_by_ids, run_checks, CheckContext, DiagnosticResult, Fix, HealthCheck,
    Severity, CHECK_IDS,
};
```

- [ ] **Step 4: Run – must pass**

Run: `cargo test -p cryptomator-core health --locked`
Expected: 5 passed.

- [ ] **Step 5: Gate and commit**

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked`

```bash
git add crates/cryptomator-core/src/health crates/cryptomator-core/src/lib.rs
git commit -m "feat(core): health check trait, diagnostic results and check context

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 4: `DirIdCheck` – eight result types and the fixes without LOST+FOUND

**Files:**
- Create: `crates/cryptomator-core/src/health/dir_id.rs`
- Modify: `crates/cryptomator-core/src/health/mod.rs` (`all_checks`, `pub mod dir_id;`)
- Test: `crates/cryptomator-core/tests/health.rs`

**Interfaces:**
- Consumes: `health::{CheckContext, DiagnosticResult, Fix, HealthCheck, Severity}` (Task 3), `crate::constants::{DATA_DIR_NAME, DIR_FILE_NAME, DIR_ID_BACKUP_FILE_NAME, CRYPTOMATOR_FILE_SUFFIX, DEFLATED_FILE_SUFFIX, MAX_DIR_ID_LENGTH}`, `crate::fs::dir_id::write_dir_id_backup`, `crate::fs::CiphertextDirectory`, `common::{fixture, copy_fixture}` (Task 1).
- Produces:
```rust
pub const DIR_ID_CHECK_NAME: &str = "Directory Check";
pub const DIR_ID_CHECK_ID: &str = "dirid";
pub const MAX_TRAVERSAL_DEPTH: usize = 4;      // d/2/30/Fo0==.c9r/dir.c9r

#[derive(Debug)] pub struct DirIdCheck;
impl HealthCheck for DirIdCheck { … }

// Fixes (each `pub(crate)`, because they are only reachable via `DiagnosticResult::fix`):
#[derive(Debug)] struct DeleteLooseDirFile { dir_file: PathBuf }
#[derive(Debug)] struct WriteDirIdBackup   { dir_id: String, content_dir: PathBuf }
#[derive(Debug)] struct CreateContentDir   { dir_id: String }
```

**Java template, verbatim (cryptofs 2.10.0 `health/dirid/*`).** The eight results, their severity, their `toString()`, and their fix:

| Result | Severity | Message (Java format string) | Fix |
|---|---|---|---|
| `HealthyDir` | GOOD | `Good directory %s (%s) -> %s` (dirFile, dirId, dir) | – |
| `MissingDirIdBackup` | INFO | `Directory ID backup for directory %s is missing.` (contentDir) | `DirectoryIdBackup.write(cryptor, {dirId, absCipherDir})` |
| `LooseDirFile` | INFO | `A dir.c9r without proper parent found: (%s). .` (dirFile) | `Files.deleteIfExists(pathToVault.resolve(dirFile))` |
| `ObeseDirFile` | CRITICAL | `Unexpected file size of %s: %d should be ≤ %d` (dirFile, size, 36) | – |
| `EmptyDirFile` | CRITICAL | `File %s is empty, expected content` (dirFile) | – |
| `DirIdCollision` | CRITICAL | `Directory ID reused: %s found in %s and %s` (dirId, dirFile, otherDirFile) | – |
| `MissingContentDir` | WARN | `dir.c9r file (%s) points to non-existing directory.` (dirFile) | `createDirectories(d/h[0..2]/h[2..32])` + `DirectoryIdBackup.write` |
| `OrphanContentDir` | WARN | `Orphan directory: %s` (contentDir) | LOST+FOUND adoption → **Task 5** |

The message of `LooseDirFile` really does end in `". ."` – a typo in the original, adopted verbatim so that reports stay comparable.

- [ ] **Step 1: Failing test against `broken_health`**

In `crates/cryptomator-core/tests/health.rs` (the helpers `expected_findings`/`ExpectedFinding` are already there from Task 1):

```rust
use cryptomator_core::health::{CheckContext, DiagnosticResult, Severity};
use cryptomator_core::{open_vault, MasterkeyFileAccess};
use std::path::{Path, PathBuf};

fn open_broken() -> (tempfile::TempDir, PathBuf, CheckContext) {
    let (tmp, vault) = common::copy_fixture("broken_health");
    let opened = open_vault(&vault, &MasterkeyFileAccess::new(Vec::new()), "test-password-123")
        .expect("the broken fixture still opens");
    (tmp, vault, CheckContext::new(opened))
}

fn run(id: &str, ctx: &CheckContext) -> Vec<DiagnosticResult> {
    let checks = cryptomator_core::checks_by_ids(&[id.to_string()]).expect("known check");
    cryptomator_core::run_checks(&checks, ctx)
}

/// How often a message with this prefix occurs. The result types themselves are private --
/// the message is their public identity, exactly as in Java's report.
fn count(results: &[DiagnosticResult], prefix: &str) -> usize {
    results.iter().filter(|r| r.message.starts_with(prefix)).count()
}

#[test]
fn the_dirid_check_finds_every_damaged_directory() {
    let (_tmp, _vault, ctx) = open_broken();
    let results = run("dirid", &ctx);
    assert_eq!(count(&results, "Orphan directory:"), 1);
    assert_eq!(count(&results, "Directory ID backup for directory"), 1);
    assert_eq!(count(&results, "dir.c9r file ("), 1);
    assert_eq!(count(&results, "A dir.c9r without proper parent found:"), 1);
    assert_eq!(count(&results, "Directory ID reused:"), 1);
    assert!(count(&results, "Good directory") >= 1, "the intact directories are still good");
    assert!(results.iter().all(|r| r.check == "dirid"));
    // Ruling 1: every path is vault-relative.
    assert!(results.iter().flat_map(|r| &r.paths).all(|p| p.is_relative()), "{results:#?}");
    assert!(results.iter().flat_map(|r| &r.paths).all(|p| p.starts_with("d")), "{results:#?}");
}

#[test]
fn the_severities_match_the_fixture_manifest() {
    let (_tmp, _vault, ctx) = open_broken();
    let results = run("dirid", &ctx);
    for expected in expected_findings().into_iter().filter(|f| f.check == "dirid") {
        let found = results
            .iter()
            .find(|r| r.paths.iter().any(|p| p.to_string_lossy().replace('\\', "/") == expected.path))
            .unwrap_or_else(|| panic!("no dirid finding for {}", expected.path));
        assert_eq!(found.severity.as_str(), expected.severity, "{}", expected.path);
    }
}

#[test]
fn a_healthy_vault_has_only_good_dirid_results() {
    let (_tmp, vault) = common::copy_fixture("nested");
    let opened = open_vault(&vault, &MasterkeyFileAccess::new(Vec::new()), "test-password-123").unwrap();
    let ctx = CheckContext::new(opened);
    let results = run("dirid", &ctx);
    assert!(!results.is_empty());
    assert!(results.iter().all(|r| r.severity == Severity::Good), "{results:#?}");
}

#[test]
fn the_three_fixable_dirid_findings_repair_the_vault() {
    let (_tmp, _vault, ctx) = open_broken();
    let before = run("dirid", &ctx);
    for result in &before {
        // The orphan fix only arrives with Task 5; here the three others are applied.
        if result.message.starts_with("Orphan directory:") { continue; }
        if let Some(fix) = &result.fix {
            fix.apply(&ctx).expect("the fix applies");
        }
    }
    let after = run("dirid", &ctx);
    assert_eq!(count(&after, "Directory ID backup for directory"), 0);
    assert_eq!(count(&after, "dir.c9r file ("), 0);
    assert_eq!(count(&after, "A dir.c9r without proper parent found:"), 0);
    // The orphan finding stays, because its fix was skipped.
    assert_eq!(count(&after, "Orphan directory:"), 1);
    // Idempotence: a second pass of the same fixes changes nothing any more.
    for result in &after {
        if result.message.starts_with("Orphan directory:") { continue; }
        if let Some(fix) = &result.fix { fix.apply(&ctx).expect("idempotent"); }
    }
    assert_eq!(run("dirid", &ctx).len(), after.len());
}
```

- [ ] **Step 2: Run – must fail**

Run: `cargo test -p cryptomator-core --test health --locked`
Expected: FAIL – the `Placeholder` from Task 3 returns nothing, so `assert_eq!(count(…), 1)` fails.

- [ ] **Step 3: The scan**

`DirIdCheck::run` in two phases, exactly like `DirIdCheck.check`:

**Phase 1 – traversal** (`walkdir` is not in the workspace, so `std::fs::read_dir` recursively with a depth limit of 4 starting at `d/`, measured like Java's `Files.walkFileTree(dataDirPath, Set.of(), 4, visitor)`: `d` = depth 0, `d/XX` = 1, `d/XX/YYY…` = 2, `d/XX/YYY…/name.c9r` = 3, `d/XX/YYY…/name.c9r/dir.c9r` = 4). Collected are:
- `dir_ids: BTreeMap<String, Option<PathBuf>>` – pre-seeded with `("".to_string(), None)` (Java's "we always have the empty dirId for the root").
- `second_level_dirs: BTreeSet<PathBuf>` – every path that has exactly two name components relative to `d/` (that is, `XX/YYY…`).

`BTreeMap`/`BTreeSet` instead of `HashMap`/`HashSet`: the report should look the same for the same vault.

When visiting a **file** named `dir.c9r` (Java's `visitFile` → `visitDirFile`):
1. parent name ends in neither `.c9r` nor `.c9s` → `LooseDirFile` (INFO, fix `DeleteLooseDirFile`), continue with the next sibling node (`CONTINUE`).
2. size > `MAX_DIR_ID_LENGTH` (36) → `ObeseDirFile` (CRITICAL, no fix).
3. size == 0 → `EmptyDirFile` (CRITICAL, no fix).
4. otherwise read the content as UTF-8 (`String::from_utf8_lossy`, like Java's `new String(bytes, UTF_8)`); if the dirId is already in `dir_ids` → `DirIdCollision` (CRITICAL) with the *other* path, otherwise insert it.
After cases 2–4 Java follows with `SKIP_SIBLINGS` – inside a `.c9r` directory there is nothing more to see after `dir.c9r`. Our recursive variant breaks out of the loop over the siblings at that point.

**Phase 2 – resolve the pairs:**
```rust
for (dir_id, dir_file) in std::mem::take(&mut dir_ids) {
    let hash = ctx.cryptor.file_name_cryptor().hash_directory_id(&dir_id);
    let expected = Path::new(&hash[..2]).join(&hash[2..]);
    if second_level_dirs.remove(&expected) {
        let rel = Path::new(DATA_DIR_NAME).join(&expected);
        if ctx.resolve(&rel).join(DIR_ID_BACKUP_FILE_NAME).exists() {
            sink(healthy_dir(&dir_id, dir_file.as_deref(), &rel));
        } else {
            sink(missing_dir_id_backup(&dir_id, &rel));
        }
    } else {
        sink(missing_content_dir(&dir_id, dir_file.as_deref()));
    }
}
for dir in second_level_dirs { sink(orphan_content_dir(&dir)); }
```
Two Java quirks come along: the root has `dir_file == None` (Java sets `null`), and its `HealthyDir` text then contains `null`; we write `-` instead and record that in the doc comment (printing a Rust `None` as `"None"` would read worse than either). And: the `MissingContentDir` finding for the *root* (dirId `""`) can only occur if `d/<roothash>` is missing – the message then reads `dir.c9r file (-) points to non-existing directory.`

- [ ] **Step 4: The three fixes**

```rust
#[derive(Debug)] struct DeleteLooseDirFile { dir_file: PathBuf }
impl Fix for DeleteLooseDirFile {
    fn apply(&self, ctx: &CheckContext) -> std::io::Result<()> {
        match std::fs::remove_file(ctx.resolve(&self.dir_file)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),   // Java's deleteIfExists
            other => other,
        }
    }
}

#[derive(Debug)] struct WriteDirIdBackup { dir_id: String, content_dir: PathBuf }
impl Fix for WriteDirIdBackup {
    fn apply(&self, ctx: &CheckContext) -> std::io::Result<()> {
        let dir = CiphertextDirectory { dir_id: self.dir_id.clone(), path: ctx.resolve(&self.content_dir) };
        match ctx.rng(|rng| crate::fs::dir_id::write_dir_id_backup(&ctx.cryptor, &dir, rng)) {
            // CREATE_NEW: an already existing dirid.c9r is the success case of a second run.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            other => other,
        }
    }
}

#[derive(Debug)] struct CreateContentDir { dir_id: String }
impl Fix for CreateContentDir {
    fn apply(&self, ctx: &CheckContext) -> std::io::Result<()> {
        let hash = ctx.cryptor.file_name_cryptor().hash_directory_id(&self.dir_id);
        // Java: substring(2, 32) instead of substring(2) -- the hash is exactly 32 characters long,
        // so it is the same; the shorter form is used here.
        let dir = ctx.data_dir().join(&hash[..2]).join(&hash[2..]);
        std::fs::create_dir_all(&dir)?;
        let ct = CiphertextDirectory { dir_id: self.dir_id.clone(), path: dir };
        match ctx.rng(|rng| crate::fs::dir_id::write_dir_id_backup(&ctx.cryptor, &ct, rng)) {
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            other => other,
        }
    }
}
```

The `AlreadyExists` tolerance is our addition and the reason why `--fix` is idempotent: Java throws there (except in `prepareStepParent`, which catches the case itself).

- [ ] **Step 5: Wire up `all_checks`**

In `health/mod.rs` replace the first `Placeholder` line with `Box::new(dir_id::DirIdCheck)` and add `pub mod dir_id;`. The other two placeholders stay until Task 6.

- [ ] **Step 6: Tests, gate, commit**

Run: `cargo test -p cryptomator-core --test health --locked`
Expected: 5 passed (the four new ones plus the fixture test from Task 1).

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked`

```bash
git add crates/cryptomator-core/src/health crates/cryptomator-core/tests/health.rs
git commit -m "feat(core): DirIdCheck with all eight diagnostic results

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 5: The LOST+FOUND fix of `OrphanContentDir`

**Files:**
- Create: `crates/cryptomator-core/src/health/orphan.rs`
- Modify: `crates/cryptomator-core/src/health/dir_id.rs` (`orphan_content_dir` gets the fix), `crates/cryptomator-core/src/health/mod.rs` (`pub mod orphan;`)
- Test: `crates/cryptomator-core/tests/health.rs`

**Interfaces:**
- Consumes: `health::{CheckContext, Fix}`, `crate::constants::{RECOVERY_DIR_NAME, RECOVERY_DIR_ID, ROOT_DIR_ID, DIR_FILE_NAME, DIR_ID_BACKUP_FILE_NAME, INFLATED_FILE_NAME, SYMLINK_FILE_NAME, CRYPTOMATOR_FILE_SUFFIX, DEFLATED_FILE_SUFFIX, MIN_CIPHER_NAME_LENGTH, DATA_DIR_NAME}`, `crate::fs::dir_id::{read_dir_id_backup, write_dir_id_backup}`, `crate::fs::CiphertextDirectory`, `crate::crypto::rng::Rng`.
- Produces:
```rust
pub(crate) const FILE_PREFIX: &str = "file";
pub(crate) const DIR_PREFIX: &str = "directory";
pub(crate) const SYMLINK_PREFIX: &str = "symlink";
pub(crate) const LONG_NAME_SUFFIX_BASE: &str = "_withVeryLongName";

#[derive(Debug)] pub(crate) struct AdoptOrphan { pub content_dir: PathBuf }   // vault-relative, e.g. d/AB/CDE…
impl Fix for AdoptOrphan { fn apply(&self, ctx: &CheckContext) -> std::io::Result<()>; }

// visible for testing (crate-private, exercised in this module's unit tests):
pub(crate) fn prepare_recovery_dir(ctx: &CheckContext) -> std::io::Result<PathBuf>;
pub(crate) fn prepare_step_parent(ctx: &CheckContext, recovery_dir: &Path, clear_name: &str)
    -> std::io::Result<CiphertextDirectory>;
pub(crate) fn clear_name_to_be_shortened(threshold: u32) -> String;
pub(crate) fn run_id(rng: &mut dyn Rng) -> String;
```

**Java template: `OrphanContentDir.fix` (cryptofs 2.10.0), step by step.**

- [ ] **Step 1: Failing test**

```rust
#[test]
fn the_orphan_fix_adopts_the_lost_files_into_lost_and_found() {
    let (_tmp, vault, ctx) = open_broken();
    let before = run("dirid", &ctx);
    let orphan = before.iter().find(|r| r.message.starts_with("Orphan directory:")).expect("an orphan");
    orphan.fix.as_ref().expect("the orphan is fixable").apply(&ctx).expect("adoption succeeds");

    // The orphaned directory is gone …
    assert!(!ctx.resolve(&orphan.paths[0]).exists(), "the orphaned content dir was removed");
    // … and a LOST+FOUND node sits in the vault root.
    let root = cryptomator_core::root_content_dir(&vault, &ctx.cryptor);
    let lost_and_found = ctx.cryptor.file_name_cryptor().encrypt_filename("LOST+FOUND", &[b""]) + ".c9r";
    let dir_file = root.join(&lost_and_found).join("dir.c9r");
    assert_eq!(std::fs::read_to_string(&dir_file).unwrap(), "recovery");

    // The finding has disappeared after the fix, and the vault is fully healthy again
    // in the sense that no orphaned directory is left over.
    let after = run("dirid", &ctx);
    assert_eq!(count(&after, "Orphan directory:"), 0, "{after:#?}");
}

#[test]
fn the_adopted_file_is_readable_through_the_cleartext_layer() {
    use cryptomator_core::fs::{CleartextPath, CryptoFs, CryptoFsOptions};
    let (_tmp, vault, ctx) = open_broken();
    let orphan = run("dirid", &ctx).into_iter().find(|r| r.message.starts_with("Orphan directory:")).unwrap();
    orphan.fix.unwrap().apply(&ctx).unwrap();

    let opened = open_vault(&vault, &MasterkeyFileAccess::new(Vec::new()), "test-password-123").unwrap();
    let fs = CryptoFs::open(opened, CryptoFsOptions::default()).expect("mount-less fs");
    let entries = fs.read_dir(&CleartextPath::root().join("LOST+FOUND")).expect("LOST+FOUND exists");
    assert_eq!(entries.len(), 1, "one step-parent directory per adopted orphan");
    let step_parent = CleartextPath::root().join("LOST+FOUND").join(&entries[0].name);
    let adopted = fs.read_dir(&step_parent).expect("step parent lists");
    // The orphan had a dirid.c9r, so the real names could be decrypted.
    assert!(adopted.iter().any(|e| e.name == "adopted.txt"), "{adopted:#?}");
}

#[test]
fn applying_the_orphan_fix_twice_is_harmless() {
    let (_tmp, _vault, ctx) = open_broken();
    let orphan = run("dirid", &ctx).into_iter().find(|r| r.message.starts_with("Orphan directory:")).unwrap();
    orphan.fix.as_ref().unwrap().apply(&ctx).unwrap();
    // The second call hits a directory that no longer exists: NotFound is not an error.
    orphan.fix.as_ref().unwrap().apply(&ctx).expect("second run is a no-op");
}
```

The exact names `CryptoFs::open`, `CryptoFsOptions::default`, `CleartextPath::root`, `fs.read_dir` and the field `DirEntry::name` are to be taken over from M3; they are in `crates/cryptomator-core/tests/crypto_fs_fixtures.rs` and are already used exactly that way there – the implementer reads the signatures there instead of guessing them (`grep -n "CryptoFs::" crates/cryptomator-core/tests/crypto_fs_fixtures.rs`).

- [ ] **Step 2: Run – must fail**

Run: `cargo test -p cryptomator-core --test health --locked orphan`
Expected: FAIL, `the orphan is fixable` panics (in Task 4 `orphan_content_dir` still has no fix).

- [ ] **Step 3: `prepare_recovery_dir`**

```rust
/// `OrphanContentDir.prepareRecoveryDir`: creates `/LOST+FOUND` (dirId "recovery") and returns its
/// content directory -- absolute, because the adoption moves things there.
pub(crate) fn prepare_recovery_dir(ctx: &CheckContext) -> std::io::Result<PathBuf> {
    let names = ctx.cryptor.file_name_cryptor();
    let root_hash = names.hash_directory_id(ROOT_DIR_ID);
    let root = ctx.data_dir().join(&root_hash[..2]).join(&root_hash[2..]);
    let cipher_name = format!("{}{CRYPTOMATOR_FILE_SUFFIX}",
        names.encrypt_filename(RECOVERY_DIR_NAME, &[ROOT_DIR_ID.as_bytes()]));
    let dir_file = root.join(&cipher_name).join(DIR_FILE_NAME);
    if !dir_file.symlink_metadata().is_ok() {
        std::fs::create_dir_all(dir_file.parent().expect("has a parent"))?;
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(&dir_file)?;
        std::io::Write::write_all(&mut f, RECOVERY_DIR_ID.as_bytes())?;
    } else {
        let existing = std::fs::read_to_string(&dir_file)?;
        if existing != RECOVERY_DIR_ID {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("Directory /{RECOVERY_DIR_NAME} already exists, but with wrong directory id."),
            ));
        }
    }
    let hash = names.hash_directory_id(RECOVERY_DIR_ID);
    let dir = ctx.data_dir().join(&hash[..2]).join(&hash[2..]);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}
```
`symlink_metadata` instead of `exists()`, because Java checks `Files.notExists(…, NOFOLLOW_LINKS)`.

- [ ] **Step 4: `prepare_step_parent`, `clear_name_to_be_shortened`, `run_id`**

```rust
/// `OrphanContentDir.prepareStepParent`: a subdirectory of LOST+FOUND whose cleartext name is the
/// hash of the orphaned directory (`<2 chars><30 chars>`), so that it can be found again.
pub(crate) fn prepare_step_parent(ctx: &CheckContext, recovery_dir: &Path, clear_name: &str)
    -> std::io::Result<CiphertextDirectory>
{
    let names = ctx.cryptor.file_name_cryptor();
    let cipher = format!("{}{CRYPTOMATOR_FILE_SUFFIX}",
        names.encrypt_filename(clear_name, &[RECOVERY_DIR_ID.as_bytes()]));
    let dir_file = recovery_dir.join(&cipher).join(DIR_FILE_NAME);
    let uuid = if dir_file.symlink_metadata().is_ok() {
        std::fs::read_to_string(&dir_file)?
    } else {
        std::fs::create_dir_all(dir_file.parent().expect("has a parent"))?;
        let uuid = uuid::Uuid::new_v4().to_string();
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(&dir_file)?;
        std::io::Write::write_all(&mut f, uuid.as_bytes())?;
        uuid
    };
    let hash = names.hash_directory_id(&uuid);
    let path = ctx.data_dir().join(&hash[..2]).join(&hash[2..]);
    std::fs::create_dir_all(&path)?;
    let ct = CiphertextDirectory { dir_id: uuid, path };
    // FileAlreadyExists = an earlier repair attempt was already here; Java catches exactly that.
    if let Err(e) = ctx.rng(|rng| crate::fs::dir_id::write_dir_id_backup(&ctx.cryptor, &ct, rng)) {
        if e.kind() != std::io::ErrorKind::AlreadyExists { return Err(e); }
    }
    Ok(ct)
}

/// `OrphanContentDir.createClearnameToBeShortened`. The arithmetic comes from Java and is wrong
/// there (`%` instead of `/`), but is reproduced deliberately: it only produces a name that is
/// long enough to be shortened, and both programs should hand out the same names.
pub(crate) fn clear_name_to_be_shortened(threshold: u32) -> String {
    let needed = (threshold as i64 - 4) / 4 * 3 - 16;
    let times = (needed.rem_euclid(LONG_NAME_SUFFIX_BASE.len() as i64) + 1) as usize;
    LONG_NAME_SUFFIX_BASE.repeat(times)
}

/// `Integer.toString((short) UUID.randomUUID().getMostSignificantBits(), 32)`: the lower 16 bits
/// as a *signed* number in base 32 with the digits 0-9a-v; negative values get a
/// leading '-'.
pub(crate) fn run_id(rng: &mut dyn Rng) -> String {
    let mut buf = [0u8; 2];
    rng.fill(&mut buf);
    let mut value = i64::from(i16::from_be_bytes(buf));
    if value == 0 { return "0".to_string(); }
    let negative = value < 0;
    value = value.abs();
    let digits = b"0123456789abcdefghijklmnopqrstuv";
    let mut out = Vec::new();
    while value > 0 { out.push(digits[(value % 32) as usize]); value /= 32; }
    if negative { out.push(b'-'); }
    out.reverse();
    String::from_utf8(out).expect("ascii")
}
```

Unit tests in the same module: `clear_name_to_be_shortened(220)` yields `needed = 146`, `146 % 17 = 10`, so 11 repetitions of 17 characters = 187 characters; `run_id` returns `"0"` for `[0x00, 0x00]`, `"-1"` for `[0xff, 0xff]` and `"11"` for `[0x00, 0x21]` (33 = 1·32 + 1).

- [ ] **Step 5: `AdoptOrphan::apply`**

```rust
impl Fix for AdoptOrphan {
    fn apply(&self, ctx: &CheckContext) -> std::io::Result<()> {
        let orphan = ctx.resolve(&self.content_dir);
        if !orphan.is_dir() { return Ok(()); }            // already adopted (idempotence)
        // Cleartext name of the step-parent directory = the hash of the orphan, i.e. `<XX><YYY…>`.
        let hash_name = format!("{}{}",
            self.content_dir.parent().and_then(Path::file_name).unwrap_or_default().to_string_lossy(),
            self.content_dir.file_name().unwrap_or_default().to_string_lossy());

        let recovery_dir = prepare_recovery_dir(ctx)?;
        if recovery_dir == orphan { return Ok(()); }      // LOST+FOUND was itself the orphan
        let step_parent = prepare_step_parent(ctx, &recovery_dir, &hash_name)?;

        let run = ctx.rng(run_id);
        let long_suffix = clear_name_to_be_shortened(ctx.config.shortening_threshold);
        let dir_id = crate::fs::dir_id::read_dir_id_backup(&ctx.cryptor, &orphan).ok();
        let (mut files, mut dirs, mut links) = (1u32, 1u32, 1u32);

        let mut entries: Vec<_> = std::fs::read_dir(&orphan)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);    // deterministic numbering
        for entry in &entries {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !matches_encrypted_content_pattern(&name) { continue; }
            let shortened = name.ends_with(DEFLATED_FILE_SUFFIX);
            let path = entry.path();
            let new_clear_name = match dir_id.as_deref().and_then(|id| decrypt_orphan_name(ctx, &path, shortened, id)) {
                Some(name) => name,
                None => {
                    let (prefix, counter) = match determine_type(&path) {
                        CiphertextFileType::Directory => (DIR_PREFIX, &mut dirs),
                        CiphertextFileType::Symlink => (SYMLINK_PREFIX, &mut links),
                        CiphertextFileType::File => (FILE_PREFIX, &mut files),
                    };
                    let n = *counter; *counter += 1;
                    format!("{prefix}{n}_{run}{}", if shortened { long_suffix.as_str() } else { "" })
                }
            };
            adopt(ctx, &path, &new_clear_name, shortened, &step_parent)?;
        }

        let _ = std::fs::remove_file(orphan.join(DIR_ID_BACKUP_FILE_NAME));
        for entry in std::fs::read_dir(&orphan)? {           // everything that does not belong to Cryptomator
            let entry = entry?;
            move_path(&entry.path(), &step_parent.path.join(entry.file_name()))?;
        }
        std::fs::remove_dir(&orphan)
    }
}
```

The four helpers:
- `matches_encrypted_content_pattern(name)` = `name.chars().count() >= MIN_CIPHER_NAME_LENGTH && (name.ends_with(".c9r") || name.ends_with(".c9s"))` (Java's `DirectoryStreamFactory` filter).
- `determine_type(path)` = `dir.c9r` present → `Directory`, otherwise `symlink.c9r` → `Symlink`, otherwise `File` (`symlink_metadata`, no following).
- `decrypt_orphan_name(ctx, path, shortened, dir_id)` reads the `name.c9s` when `shortened`, otherwise the file name, cuts off the last 4 characters (`.c9r`) and calls `ctx.cryptor.file_name_cryptor().decrypt_filename(&name, &[dir_id])`; every error yields `None` (Java logs a warning and falls back to the counter name).
- `adopt(ctx, old, new_clear_name, shortened, step_parent)`:
  ```rust
  let cipher = format!("{}{CRYPTOMATOR_FILE_SUFFIX}", ctx.cryptor.file_name_cryptor()
      .encrypt_filename(new_clear_name, &[step_parent.dir_id.as_bytes()]));
  if shortened {
      let deflated = format!("{}{DEFLATED_FILE_SUFFIX}", BASE64URL.encode(&sha1(cipher.as_bytes())));
      let target = step_parent.path.join(&deflated);
      move_path(old, &target)?;
      std::fs::write(target.join(INFLATED_FILE_NAME), cipher.as_bytes())?;   // TRUNCATE_EXISTING
  } else {
      move_path(old, &step_parent.path.join(&cipher))?;
  }
  ```
  `BASE64URL` is `data_encoding::BASE64URL` (with padding) as in `fs/long_names.rs::deflate`; `sha1` uses `sha1::Sha1` just like there. The implementer takes both lines from `crates/cryptomator-core/src/fs/long_names.rs`, so that the deflation stays bit-identical with the rest of the codebase.
- `move_path(from, to)` is `std::fs::rename` with a fallback to copy-and-delete on `ErrorKind::CrossesDevices` (the orphan and LOST+FOUND both live under `d/`, so practically never – but a vault can be assembled across mount boundaries).

- [ ] **Step 6: Attach the fix to `orphan_content_dir`**

In `dir_id.rs` the `OrphanContentDir` branch gets
```rust
.with_fix(Box::new(crate::health::orphan::AdoptOrphan { content_dir: rel.clone() }))
```
where `rel` is the vault-relative path `d/XX/YYY…`.

- [ ] **Step 7: Tests, gate, commit**

Run: `cargo test -p cryptomator-core --test health --locked && cargo test -p cryptomator-core health::orphan --locked`
Expected: all green.

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked`

```bash
git add crates/cryptomator-core/src/health crates/cryptomator-core/tests/health.rs
git commit -m "feat(core): adopt orphaned content directories into LOST+FOUND

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 6: `CiphertextFileTypeCheck` and `ShortenedNamesCheck`

**Files:**
- Create: `crates/cryptomator-core/src/health/file_type.rs`, `crates/cryptomator-core/src/health/shortened.rs`
- Modify: `crates/cryptomator-core/src/health/mod.rs` (`all_checks` – the last two placeholders disappear)
- Test: `crates/cryptomator-core/tests/health.rs`

**Interfaces:**
- Consumes: `health::{CheckContext, DiagnosticResult, Fix, HealthCheck, Severity}`, `crate::constants::{DATA_DIR_NAME, CRYPTOMATOR_FILE_SUFFIX, DEFLATED_FILE_SUFFIX, DIR_FILE_NAME, SYMLINK_FILE_NAME, CONTENTS_FILE_NAME, INFLATED_FILE_NAME}`, `crate::fs::long_names::MAX_FILENAME_BUFFER_SIZE` (= 10240).
- Produces:
```rust
pub const TYPE_CHECK_NAME: &str = "Resource Type Check";
pub const TYPE_CHECK_ID: &str = "type";
#[derive(Debug)] pub struct CiphertextFileTypeCheck;

pub const SHORTENED_CHECK_NAME: &str = "Shortened Names Check";
pub const SHORTENED_CHECK_ID: &str = "shortened";
#[derive(Debug)] pub struct ShortenedNamesCheck;

// crate-private, `visible for testing` as in Java:
pub(crate) enum SyntaxResult { Valid, Invalid, TrailingBytes }
pub(crate) fn check_syntax(long_name: &str) -> SyntaxResult;
pub(crate) fn deflate_name(long_name: &str) -> String;      // BASE64URL(SHA1(name)) + ".c9s"
```

**Java template, verbatim.** Both checks run with depth limit **3** starting at `d/` (that is, down to `d/XX/YYY…/name.c9r`) and look only at **directories**.

`CiphertextFileTypeCheck` (name "Resource Type Check"): for every directory whose name ends in `.c9r` or `.c9s`, the set of type files is determined – `dir.c9r` → DIRECTORY, `symlink.c9r` → SYMLINK, and **only for `.c9s`** also `contents.c9r` → FILE (each `Files.isRegularFile(…, NOFOLLOW_LINKS)`):

| Size of the set | Result | Severity | Message | Fix |
|---|---|---|---|---|
| 0 | `UnknownType` | CRITICAL | `C9r dir %s of unknown type.` | `Files.delete(pathToVault.resolve(cipherDir))` |
| 1 | `KnownType` | GOOD | `Node %s with determined type %s.` (type as `DIRECTORY`/`SYMLINK`/`FILE`) | – |
| >1 | `AmbiguousType` | CRITICAL | `Node %s of ambiguous type. Possible types are: %s` | – |

The type set in `AmbiguousType` is printed like Java's `EnumSet.toString()`: `[DIRECTORY, SYMLINK]` in **enum declaration order** – in `CiphertextFileType` (cryptofs `common/CiphertextFileType`) that is `FILE, DIRECTORY, SYMLINK`. Our `crate::fs::CiphertextFileType` has the same order; the implementer verifies that with `grep -n "enum CiphertextFileType" -A 6 crates/cryptomator-core/src/fs/ciphertext_path.rs` and sorts by it when formatting.

`ShortenedNamesCheck` (name "Shortened Names Check"): for every directory whose name ends in `.c9s`:

| Condition | Result | Severity | Message | Fix |
|---|---|---|---|---|
| `name.c9s` is missing or is not a regular file | `MissingLongName` | CRITICAL | `Shortened resource %s either misses name.c9s or the file has invalid content.` | – |
| size > 10240 | `ObeseNameFile` | CRITICAL | `Long filename file %s with size %d exceeds limit of %d for this type.` | – |
| Syntax `Invalid` | `NotDecodableLongName` | CRITICAL | `String "%s" stored in %s is not a valid Cryptomator filename.` (longName, nameFile) | – |
| Syntax `TrailingBytes` | `TrailingBytesInNameFile` | WARN | `Encrypted filename "%s" stored in %s contains trailing bytes.` | truncate to `…​.c9r` |
| directory name ≠ `deflate(longName)` | `LongShortNamesMismatch` | WARN | `Name of %s is not a base64url encoded SHA1 hash of String inside name.c9s.` | `rename(c9sDir, sibling(expectedShortName))` |
| otherwise | `ValidShortenedFile` | GOOD | `Found valid shortened resource at %s.` | – |

`check_syntax` (Java's `DirVisitor.checkSyntax`, bug cryptofs#121):
```rust
pub(crate) fn check_syntax(to_analyse: &str) -> SyntaxResult {
    let Some(pos) = to_analyse.find(CRYPTOMATOR_FILE_SUFFIX) else { return SyntaxResult::Invalid };
    if data_encoding::BASE64URL.decode(to_analyse[..pos].as_bytes()).is_err() {
        return SyntaxResult::Invalid;
    }
    if to_analyse.len() > pos + CRYPTOMATOR_FILE_SUFFIX.len() {
        return SyntaxResult::TrailingBytes;
    }
    SyntaxResult::Valid
}
```
Java's `BaseEncoding.base64Url().canDecode` accepts padded and unpadded input; `data_encoding::BASE64URL` is padded. For real Cryptomator names (always padded, length ≡ 0 mod 4) this is identical; the difference only affects broken input, where both are supposed to say "invalid" and we do it more strictly. Record as a comment.

- [ ] **Step 1: Failing tests**

In `crates/cryptomator-core/tests/health.rs`:

```rust
#[test]
fn the_type_check_finds_the_node_without_a_type_file() {
    let (_tmp, _vault, ctx) = open_broken();
    let results = run("type", &ctx);
    assert_eq!(count(&results, "C9r dir "), 1);
    assert!(count(&results, "Node ") >= 5, "the intact nodes are known types");
    assert!(results.iter().all(|r| r.check == "type"));
}

#[test]
fn the_shortened_check_finds_all_three_broken_c9s_nodes() {
    let (_tmp, _vault, ctx) = open_broken();
    let results = run("shortened", &ctx);
    assert_eq!(count(&results, "Shortened resource "), 1);          // MissingLongName
    assert_eq!(count(&results, "Encrypted filename "), 1);          // TrailingBytesInNameFile
    assert_eq!(count(&results, "Name of "), 1);                     // LongShortNamesMismatch
    assert_eq!(count(&results, "Found valid shortened resource at "), 1);
}

#[test]
fn the_type_and_shortened_fixes_repair_what_they_can() {
    let (_tmp, _vault, ctx) = open_broken();
    for id in ["type", "shortened"] {
        for result in run(id, &ctx) {
            if let Some(fix) = result.fix { fix.apply(&ctx).expect("the fix applies"); }
        }
    }
    let after: Vec<_> = ["type", "shortened"].iter().flat_map(|id| run(id, &ctx)).collect();
    assert_eq!(count(&after, "Encrypted filename "), 0, "the trailing bytes were cut");
    assert_eq!(count(&after, "Name of "), 0, "the c9s dir was renamed");
    assert_eq!(count(&after, "Shortened resource "), 1, "MissingLongName has no fix");
    // The finding stays: Java's `Files.delete` only clears *empty* directories, and the
    // fixture directory contains the file `x` (an empty directory does not survive git).
    assert_eq!(count(&after, "C9r dir "), 1, "a non-empty unknown node is not deleted");
}

#[test]
fn an_empty_unknown_node_is_deleted() {
    let (_tmp, _vault, ctx) = open_broken();
    // Same as in the fixture, only empty -- the way it looks when the desktop app creates it.
    let root = cryptomator_core::root_content_dir(&ctx.vault_path, &ctx.cryptor);
    let name = ctx.cryptor.file_name_cryptor().encrypt_filename("empty", &[b""]) + ".c9r";
    std::fs::create_dir(root.join(&name)).unwrap();
    let found = run("type", &ctx).into_iter()
        .find(|r| r.paths.iter().any(|p| p.ends_with(&name)))
        .expect("the empty node is an unknown type");
    found.fix.expect("deletable").apply(&ctx).expect("delete");
    assert!(!root.join(&name).exists());
}

#[test]
fn a_healthy_vault_passes_all_three_checks() {
    for name in ["siv_gcm_basic", "siv_ctrmac_basic", "long_names", "unicode", "symlinks", "nested", "threshold_36"] {
        let (_tmp, vault) = common::copy_fixture(name);
        let opened = open_vault(&vault, &MasterkeyFileAccess::new(Vec::new()), "test-password-123").unwrap();
        let ctx = CheckContext::new(opened);
        let results = cryptomator_core::run_checks(&cryptomator_core::all_checks(), &ctx);
        assert!(!results.is_empty(), "{name}");
        let bad: Vec<_> = results.iter().filter(|r| r.severity > Severity::Good).collect();
        assert!(bad.is_empty(), "{name}: {bad:#?}");
    }
}

#[test]
fn check_syntax_matches_the_java_cases() {
    use cryptomator_core::health::shortened::{check_syntax, deflate_name, SyntaxResult};
    assert!(matches!(check_syntax("abcd.c9r"), SyntaxResult::Valid));
    assert!(matches!(check_syntax("abcd.c9r\n"), SyntaxResult::TrailingBytes));
    assert!(matches!(check_syntax("abcd"), SyntaxResult::Invalid));
    assert!(matches!(check_syntax("!!!!.c9r"), SyntaxResult::Invalid));
    assert!(deflate_name("abcd.c9r").ends_with(".c9s"));
}
```

For this test to compile, `check_syntax`, `deflate_name` and `SyntaxResult` are `pub` instead of `pub(crate)` and the module `shortened` is `pub` – that is the Rust equivalent of Java's "visible for testing".

- [ ] **Step 2: Run – must fail**

Run: `cargo test -p cryptomator-core --test health --locked`
Expected: FAIL (the placeholders return nothing).

- [ ] **Step 3: Implement `file_type.rs`**

A recursive walk starting at `d/` with depth limit 3 that looks only at directories. An I/O error during traversal produces – like Java's `catch (IOException)` – **one** finding
`DiagnosticResult::new(TYPE_CHECK_ID, Severity::Critical, "Check failed: Traversal of data dir failed. See log for details.".into(), vec![])`
and ends the check. `UnknownType::fix` is `std::fs::remove_dir(ctx.resolve(&cipher_dir))` with `NotFound` as success; Java uses `Files.delete`, which fails on a *non-empty* directory – we adopt that. A `remove_dir_all` would be more convenient and wrong: payload data can sit in a node of unknown type (a `contents.c9r` in a `.c9r` instead of a `.c9s` directory, for instance), and a fix must never delete what it does not understand.

That explains the two-part assertion in Step 1: the checked-in fixture contains the file `x` in `unknown.c9r/` (an empty directory does not survive git), so its finding persists after `--fix`; the extra test `an_empty_unknown_node_is_deleted` creates a truly empty node and shows that the fix takes effect there.

- [ ] **Step 4: Implement `shortened.rs`**

The same walk with depth limit 3, only `.c9s` directories. The order of the checks is the Java order (missing → obese → syntax → deflation → valid), each branch ends with `return`. `deflate_name` is verbatim the arithmetic of `crate::fs::long_names::deflate`, but on a `&str` instead of a path – the implementer pulls the three lines out of `fs/long_names.rs::deflate` into a shared `pub(crate) fn deflate_str(name: &str) -> String` and points both callers at it (DRY; `deflate` itself keeps its signature unchanged so that M3 code is not touched).

The two fixes:
```rust
#[derive(Debug)] struct TruncateTrailingBytes { name_file: PathBuf, long_name: String }
impl Fix for TruncateTrailingBytes {
    fn apply(&self, ctx: &CheckContext) -> std::io::Result<()> {
        let end = self.long_name.find(CRYPTOMATOR_FILE_SUFFIX)
            .map(|p| p + CRYPTOMATOR_FILE_SUFFIX.len())
            .unwrap_or(self.long_name.len());
        std::fs::write(ctx.resolve(&self.name_file), &self.long_name.as_bytes()[..end])
    }
}

#[derive(Debug)] struct RenameToExpectedShortName { c9s_dir: PathBuf, expected: String }
impl Fix for RenameToExpectedShortName {
    fn apply(&self, ctx: &CheckContext) -> std::io::Result<()> {
        let from = ctx.resolve(&self.c9s_dir);
        let to = from.with_file_name(&self.expected);
        if to.exists() { return Ok(()); }        // already renamed (idempotence)
        std::fs::rename(from, to)
    }
}
```

- [ ] **Step 5: Finish `all_checks`**

`health/mod.rs`: replace the two remaining `Placeholder` lines with `Box::new(file_type::CiphertextFileTypeCheck)` and `Box::new(shortened::ShortenedNamesCheck)`, **delete** `struct Placeholder` together with its `impl`, and add `pub mod file_type; pub mod shortened;`.

- [ ] **Step 6: Tests, gate, commit**

Run: `cargo test -p cryptomator-core --test health --locked`
Expected: all green, including `a_healthy_vault_passes_all_three_checks` over seven fixtures.

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked`

```bash
git add crates/cryptomator-core/src/health crates/cryptomator-core/tests/health.rs
git commit -m "feat(core): ciphertext file type and shortened names health checks

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 7: The text report in the format of `ReportWriter`

**Files:**
- Create: `crates/cryptomator-core/src/health/report.rs`
- Modify: `crates/cryptomator-core/src/health/mod.rs` (`pub mod report;`), `crates/cryptomator-core/src/lib.rs` (re-export)
- Test: in `crates/cryptomator-core/src/health/report.rs`

**Interfaces:**
- Consumes: `health::{DiagnosticResult, HealthCheck, Severity}`.
- Produces:
```rust
pub const REPORT_HEADER: &str = "\
*******************************************
*     Cryptomator Vault Health Report     *
*******************************************
";
pub const CHECK_SEPARATOR: &str = "------------------------------";   // 30 hyphens

/// `healthReport_<vaultName>_<yyyyMMdd-HHmmss>.log` -- Java's file name, but UTC (Ruling 5).
pub fn report_file_name(vault_name: &str, at: std::time::SystemTime) -> String;

/// Writes the report of `ReportWriter.writeReport`. `sections` is a list of
/// (check display name, its results in order of finding).
pub fn render_report(
    vault_id: &str,
    vault_name: &str,
    vault_path: &std::path::Path,
    sections: &[(&str, Vec<&DiagnosticResult>)],
) -> String;

pub fn write_report(path: &std::path::Path, contents: &str) -> std::io::Result<()>;
```

**Java template, verbatim (`ui/health/ReportWriter.java`).** Three format strings, one time format:

```java
REPORT_HEADER = """
    *******************************************
    *     Cryptomator Vault Health Report     *
    *******************************************
    Analyzed vault: %s (Current name "%s")
    Vault storage path: %s
    """;                                          // vaultConfig.getId(), displayName, path
REPORT_CHECK_HEADER = "\n\nCheck %s\n------------------------------\n";   // two blank lines before it
REPORT_CHECK_RESULT = "%8s - %s\n";                                       // severity right-aligned to 8
TIME_STAMP = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss");
```
(In the original, `REPORT_CHECK_HEADER` contains two lines of three spaces each; Java's text blocks strip trailing whitespace per line, leaving two blank lines.)

The check header is followed by `"STATUS: SUCCESS\nRESULTS:\n"` and then one line per result from `REPORT_CHECK_RESULT`. The `CANCELED` and `FAILED` branches do not exist for us: `crypto health` cancels nothing, and a check that cannot run reports that as a `CheckFailed` finding inside `SUCCESS`.

- [ ] **Step 1: Failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::{DiagnosticResult, Severity};
    use std::path::Path;
    use std::time::{Duration, UNIX_EPOCH};

    fn result(sev: Severity, message: &str) -> DiagnosticResult {
        DiagnosticResult::new("dirid", sev, message.to_string(), vec![])
    }

    #[test]
    fn the_report_matches_the_desktop_apps_layout() {
        let good = result(Severity::Good, "Good directory d/AB/CD (x) -> d/EF/GH");
        let bad = result(Severity::Critical, "File d/AB/CD/dir.c9r is empty, expected content");
        let text = render_report(
            "5bc0384b-14ac-4fdc-aed0-62e7bc08fd5a",
            "Secret",
            Path::new("/vaults/Secret"),
            &[("Directory Check", vec![&good, &bad]), ("Resource Type Check", vec![])],
        );
        let expected = "\
*******************************************
*     Cryptomator Vault Health Report     *
*******************************************
Analyzed vault: 5bc0384b-14ac-4fdc-aed0-62e7bc08fd5a (Current name \"Secret\")
Vault storage path: /vaults/Secret


Check Directory Check
------------------------------
STATUS: SUCCESS
RESULTS:
    GOOD - Good directory d/AB/CD (x) -> d/EF/GH
CRITICAL - File d/AB/CD/dir.c9r is empty, expected content


Check Resource Type Check
------------------------------
STATUS: SUCCESS
RESULTS:
";
        assert_eq!(text, expected);
    }

    #[test]
    fn the_file_name_is_javas_with_a_utc_stamp() {
        // 2026-09-04T15:04:05Z
        let at = UNIX_EPOCH + Duration::from_secs(1_788_534_245);
        assert_eq!(report_file_name("Secret", at), "healthReport_Secret_20260904-150405.log");
    }

    #[test]
    fn a_vault_name_with_separators_cannot_escape_the_directory() {
        let at = UNIX_EPOCH;
        let name = report_file_name("../../etc/pw", at);
        assert!(!name.contains('/') && !name.contains('\\'), "{name}");
        assert!(name.starts_with("healthReport_"), "{name}");
    }
}
```

The 1788534245 is to be double-checked with `date -u -r 1788534245 +%Y%m%d-%H%M%S`; if it deviates, the constant in the test is corrected, not the formatting.

- [ ] **Step 2: Run – must fail**

Run: `cargo test -p cryptomator-core health::report --locked`
Expected: FAIL, module missing.

- [ ] **Step 3: Implement**

`render_report` builds the string with `write!` into a `String`. The severity column is `format!("{:>8}", severity.as_str())`. The file name:

```rust
pub fn report_file_name(vault_name: &str, at: std::time::SystemTime) -> String {
    // Anything that could span a path is dropped -- the display name comes from
    // settings.json and is therefore user input.
    let safe: String = vault_name
        .chars()
        .map(|c| if c.is_alphanumeric() || matches!(c, '-' | '_' | '.') { c } else { '_' })
        .collect();
    format!("healthReport_{safe}_{}.log", compact_utc(at))
}
```
`compact_utc` is the same civil-calendar algorithm as in `crates/crypto/src/output.rs::format_timestamp`, only with the format `yyyyMMdd-HHmmss`. So that it does not exist twice, the conversion "seconds since epoch → (y, m, d, h, min, s)" moves into `report.rs` as `pub fn civil_utc(at: SystemTime) -> (i64, u32, u32, u32, u32, u32)`, and Task 14 switches `crypto::output::format_timestamp` over to it. In this task `output.rs` stays unchanged; the duplicated algorithm lives for one task.

`write_report` is `std::fs::write` with `CREATE | TRUNCATE` (Java's options) – so plainly `std::fs::write(path, contents)`.

- [ ] **Step 4: Run and gate**

Run: `cargo test -p cryptomator-core health::report --locked`
Expected: 3 passed.

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked`

- [ ] **Step 5: Commit**

```bash
git add crates/cryptomator-core/src/health crates/cryptomator-core/src/lib.rs
git commit -m "feat(core): health report in the desktop app's ReportWriter format

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 8: `crypto health` – command, exit 11, JSON and report

**Files:**
- Create: `crates/crypto/src/commands/health.rs`, `crates/crypto/tests/cli_health.rs`
- Modify: `crates/crypto/src/cli.rs`, `crates/crypto/src/main.rs`, `crates/crypto/src/exit.rs`, `crates/crypto/src/commands/mod.rs`

**Interfaces:**
- Consumes: `cryptomator_core::{all_checks, checks_by_ids, run_checks, CheckContext, DiagnosticResult, Severity, open_vault, MasterkeyFileAccess}`, `cryptomator_core::health::report::{render_report, report_file_name, write_report}`, `crypto::commands::{locked_vault, keychain_source, Ctx}`, `cryptomator_app::{read_passphrase_with_keychain, PasswordArgs, SystemIo}`.
- Produces:
```rust
// crates/crypto/src/exit.rs
pub const HEALTH_FINDINGS: u8 = 11;

// crates/crypto/src/cli.rs
#[derive(Args, Debug)]
pub struct HealthArgs {
    #[arg(allow_hyphen_values = true)]
    pub vault: String,
    /// Which checks to run (default: all)
    #[arg(long, value_name = "LIST", value_delimiter = ',')]
    pub check: Vec<String>,
    /// Apply the fixes of the findings that have one
    #[arg(long)]
    pub fix: bool,
    /// Lowest severity that `--fix` repairs
    #[arg(long, value_name = "WARN|CRITICAL", default_value = "WARN")]
    pub fix_severity: String,
    /// Where to write the text report (default: ./healthReport_<vault>_<stamp>.log)
    #[arg(long, value_name = "FILE", conflicts_with = "no_report")]
    pub report: Option<PathBuf>,
    /// Write no report file
    #[arg(long)]
    pub no_report: bool,
    /// Lowest severity that makes the command exit 11
    #[arg(long, value_name = "WARN|CRITICAL", default_value = "CRITICAL")]
    pub fail_on: String,
    #[command(flatten)]
    pub password: PasswordArgs,
}

// crates/crypto/src/commands/health.rs
pub fn run(ctx: &Ctx, args: HealthArgs) -> anyhow::Result<u8>;
pub(crate) fn to_json(result: &DiagnosticResult, fixed: Option<bool>) -> serde_json::Value;
```

**This task does not deliver `--fix` yet.** `args.fix` is parsed and rejected in Step 5 with a clear message; Task 9 fills it in.

- [ ] **Step 1: Failing CLI tests**

`crates/crypto/tests/cli_health.rs`:

```rust
mod common;
use common::Sandbox;
use predicates::prelude::*;
use serde_json::Value;

/// Registers a fixture under its name and returns the vault path.
fn vault(fx: &Sandbox, fixture: &str) -> std::path::PathBuf {
    fx.add_fixture(fixture)
}

#[test]
fn a_healthy_vault_exits_zero_and_reports_only_good_findings() {
    let fx = Sandbox::new();
    vault(&fx, "siv_gcm_basic");
    let out = fx
        .crypto(&["--json", "health", "siv_gcm_basic", "--no-report"])
        .env("CRYPTO_PASSWORD", "test-password-123")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&out).unwrap();
    let findings = value["findings"].as_array().expect("an array of findings");
    assert!(!findings.is_empty());
    assert!(findings.iter().all(|f| f["severity"] == "GOOD"), "{findings:#?}");
    assert!(findings.iter().all(|f| f["fixed"].is_null()), "nothing was fixed without --fix");
    for key in ["check", "severity", "message", "paths", "fixable"] {
        assert!(findings[0].get(key).is_some(), "missing {key}");
    }
    assert_eq!(value["report"], Value::Null);
}

#[test]
fn a_broken_vault_exits_eleven() {
    let fx = Sandbox::new();
    vault(&fx, "broken_health");
    fx.crypto(&["health", "broken_health", "--no-report"])
        .env("CRYPTO_PASSWORD", "test-password-123")
        .assert()
        .code(11)
        .stdout(predicate::str::contains("CRITICAL"));
}

#[test]
fn fail_on_warn_catches_what_fail_on_critical_lets_pass() {
    let fx = Sandbox::new();
    vault(&fx, "broken_health");
    // Only the shortened check without a CRITICAL finding: the trailing-bytes case is WARN …
    fx.crypto(&["health", "broken_health", "--check", "dirid", "--fail-on", "WARN", "--no-report"])
        .env("CRYPTO_PASSWORD", "test-password-123")
        .assert()
        .code(11);
    // … while `dirid` also has a CRITICAL finding, so both thresholds bite. The proof that
    // the threshold works comes from the healthy vault: there even WARN has no consequence.
    vault(&fx, "nested");
    fx.crypto(&["health", "nested", "--fail-on", "WARN", "--no-report"])
        .env("CRYPTO_PASSWORD", "test-password-123")
        .assert()
        .success();
}

#[test]
fn check_selects_and_an_unknown_check_is_a_usage_error() {
    let fx = Sandbox::new();
    vault(&fx, "broken_health");
    let out = fx
        .crypto(&["--json", "health", "broken_health", "--check", "type", "--fail-on", "WARN", "--no-report"])
        .env("CRYPTO_PASSWORD", "test-password-123")
        .assert()
        .code(11)
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&out).unwrap();
    assert!(value["findings"].as_array().unwrap().iter().all(|f| f["check"] == "type"));
    assert_eq!(value["checks"], serde_json::json!(["type"]));

    fx.crypto(&["health", "broken_health", "--check", "bogus", "--no-report"])
        .env("CRYPTO_PASSWORD", "test-password-123")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("dirid"));
}

#[test]
fn the_report_lands_where_it_was_asked_for() {
    let fx = Sandbox::new();
    vault(&fx, "broken_health");
    let report = fx.path("report.log");
    fx.crypto(&["health", "broken_health", "--report"])
        .arg(&report)
        .env("CRYPTO_PASSWORD", "test-password-123")
        .assert()
        .code(11);
    let text = std::fs::read_to_string(&report).expect("the report was written");
    assert!(text.starts_with("*******************************************"));
    assert!(text.contains("Check Directory Check"));
    assert!(text.contains("STATUS: SUCCESS"));
    assert!(text.contains("CRITICAL - "));
    assert!(!text.contains("test-password"), "no secret ever reaches the report");
}

#[test]
fn without_report_flags_the_file_appears_in_the_working_directory() {
    let fx = Sandbox::new();
    vault(&fx, "siv_gcm_basic");
    let cwd = fx.path("cwd");
    std::fs::create_dir_all(&cwd).unwrap();
    fx.crypto(&["health", "siv_gcm_basic"])
        .current_dir(&cwd)
        .env("CRYPTO_PASSWORD", "test-password-123")
        .assert()
        .success();
    let written: Vec<_> = std::fs::read_dir(&cwd)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(written.len(), 1, "{written:?}");
    assert!(written[0].starts_with("healthReport_siv_gcm_basic_") && written[0].ends_with(".log"),
            "{written:?}");
}

#[test]
fn health_refuses_a_vault_a_daemon_is_serving() {
    // A vault whose state is not LOCKED is exit 5. Without a daemon this can be reproduced with
    // a vault whose vault.cryptomator is missing: the state is then
    // VAULT_CONFIG_MISSING.
    let fx = Sandbox::new();
    let path = vault(&fx, "siv_gcm_basic");
    std::fs::remove_file(path.join("vault.cryptomator")).unwrap();
    for entry in std::fs::read_dir(&path).unwrap() {
        let entry = entry.unwrap();
        if entry.file_name().to_string_lossy().starts_with("vault.cryptomator.") {
            std::fs::remove_file(entry.path()).unwrap();     // otherwise the bkup restore kicks in
        }
    }
    fx.crypto(&["health", "siv_gcm_basic", "--no-report"])
        .env("CRYPTO_PASSWORD", "test-password-123")
        .assert()
        .code(5);
}
```

`Sandbox::add_fixture` already exists (`crates/crypto/tests/common/mod.rs:167`); it copies a fixture into the sandbox and registers it. The implementer checks with `sed -n '160,190p' crates/crypto/tests/common/mod.rs` whether it returns the path, and adjusts the helper function `vault` if not.

- [ ] **Step 2: Run – must fail**

Run: `cargo test -p crypto --test cli_health --locked`
Expected: FAIL, `unrecognized subcommand 'health'`.

- [ ] **Step 3: Grammar and exit code**

`exit.rs`: `pub const HEALTH_FINDINGS: u8 = 11;` (only the constant; it is returned directly by the command, not through an error type – a finding is not an error).
`cli.rs`: `HealthArgs` as above and `Command::Health(HealthArgs)` with the doc comment `/// Check a vault for structural damage and optionally repair it`.
`main.rs`: `Command::Health(args) => commands::health::run(&ctx, args),`.

- [ ] **Step 4: The command**

```rust
pub fn run(ctx: &Ctx, args: HealthArgs) -> Result<u8> {
    let (vault, path) = locked_vault(ctx, &args.vault)?;         // exit 5 for everything not LOCKED
    let fail_on = Severity::parse_threshold(&args.fail_on)?;
    let ids = if args.check.is_empty() { CHECK_IDS.map(String::from).to_vec() } else { args.check.clone() };
    let checks = checks_by_ids(&ids)?;                            // exit 2 on an unknown name
    let passphrase = read_passphrase_with_keychain(
        &args.password, "Password: ",
        || Ok(keychain_source(ctx.keychain()?.as_ref(), &vault)),
        &mut SystemIo,
    )?;
    let opened = open_vault(&path, &MasterkeyFileAccess::new(Vec::new()), &passphrase)?;
    let vault_id = opened.config.id.clone();
    let check_ctx = CheckContext::new(opened);
    let results = run_checks(&checks, &check_ctx);
    // … report, output, exit code (Steps 5-7)
}
```

The order is deliberate: `--fail-on`/`--check` are validated **before** the password prompt, so that a typo is not noticed only after a prompt.

- [ ] **Step 5: Reject `--fix` for now**

```rust
if args.fix {
    return Err(AppError::InvalidValue {
        key: "--fix".to_string(),
        message: "not implemented yet".to_string(),
    }.into());
}
```
Task 9 replaces this block; until then `--fix` is a clean exit 2 instead of a lie. The marker `not implemented yet` is the only one in the repo and is found in Task 9 with `grep -rn "not implemented yet" crates/`.

- [ ] **Step 6: Write the report**

```rust
let report_path = if args.no_report {
    None
} else {
    Some(args.report.clone().unwrap_or_else(|| {
        PathBuf::from(report_file_name(
            vault.display_name.as_deref().unwrap_or(&vault.id),
            SystemTime::now(),
        ))
    }))
};
if let Some(report_path) = &report_path {
    let sections: Vec<(&str, Vec<&DiagnosticResult>)> = checks
        .iter()
        .map(|c| (c.name(), results.iter().filter(|r| r.check == c.id()).collect()))
        .collect();
    let text = render_report(&vault_id, label, &path, &sections);
    write_report(report_path, &text)
        .with_context(|| format!("cannot write the health report to {}", report_path.display()))?;
    if !ctx.out.json {
        eprintln!("report written to {}", report_path.display());
    }
}
```

- [ ] **Step 7: Output and exit code**

```rust
pub(crate) fn to_json(result: &DiagnosticResult, fixed: Option<bool>) -> serde_json::Value {
    json!({
        "check": result.check,
        "severity": result.severity.as_str(),
        "message": result.message,
        "paths": result.paths,
        "fixable": result.fixable(),
        "fixed": fixed,            // without --fix always null
    })
}
```
`--json` returns **one** object (as everywhere in the CLI):
```json
{ "vault": "…id…", "path": "/vaults/Secret", "checks": ["dirid","type","shortened"],
  "report": "/…/healthReport_….log", "summary": {"GOOD": 12, "INFO": 1, "WARN": 2, "CRITICAL": 3},
  "failOn": "CRITICAL", "findings": [ … ] }
```
The human-readable output is one line per finding in the report format (`{:>8} - {message}`) **without** the `GOOD` lines (those are noise on a terminal), followed by a summary
`12 good, 1 info, 2 warnings, 3 critical` and, if a report was written, its path on stderr.

```rust
let worst = results.iter().map(|r| r.severity).max().unwrap_or(Severity::Good);
Ok(if worst >= fail_on { exit::HEALTH_FINDINGS } else { exit::OK })
```

- [ ] **Step 8: Tests, gate, commit**

Run: `cargo test -p crypto --test cli_health --locked`
Expected: 7 passed.

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked`

```bash
git add crates/crypto/src crates/crypto/tests/cli_health.rs
git commit -m "feat(cli): crypto health with exit code 11, JSON output and a text report

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 9: `crypto health --fix` and `--fix-severity`

**Files:**
- Modify: `crates/crypto/src/commands/health.rs`, `crates/crypto/tests/cli_health.rs`

**Interfaces:**
- Consumes: everything from Task 8, plus `DiagnosticResult::fix` and `Fix::apply`.
- Produces: no new public names; `commands::health::run` gets the `--fix` path.

**Ruling 4 in detail.** `--fix` proceeds like this:
1. First run: all selected checks.
2. For every finding with `severity >= fix_severity` **and** `fix.is_some()`: `fix.apply(&check_ctx)`. Success → `fixed: true`, error → `fixed: false` plus a warning on stderr with the finding's message and the I/O error. A failed fix does **not** abort the run; the next finding is independent of it.
3. Second run of the same checks on the same `CheckContext`.
4. Output: both runs; exit code from the **second**.

The order of the fixes is the order in which they were found. That matters for `dirid`: `CreateContentDir` (MissingContentDir) runs before `AdoptOrphan` (OrphanContentDir), because phase 2 of the check first resolves the pairs and only then reports the orphans — so a directory that was only just created cannot be adopted as an orphan in the same pass.

- [ ] **Step 1: Failing tests**

```rust
#[test]
fn fix_repairs_what_it_can_and_reruns_the_checks() {
    let fx = Sandbox::new();
    vault(&fx, "broken_health");
    let out = fx
        .crypto(&["--json", "health", "broken_health", "--fix", "--no-report"])
        .env("CRYPTO_PASSWORD", "test-password-123")
        .assert()
        .code(11)                       // the CRITICAL cases without a fix remain
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&out).unwrap();
    let before = value["before"]["findings"].as_array().unwrap();
    let after = value["after"]["findings"].as_array().unwrap();
    // Before: the three WARN cases with a fix were repaired …
    assert!(before.iter().any(|f| f["fixed"] == true));
    // … and no longer show up afterwards.
    for message in ["Orphan directory:", "dir.c9r file (", "Encrypted filename ", "Name of "] {
        assert!(
            !after.iter().any(|f| f["message"].as_str().unwrap().starts_with(message)),
            "{message} survived --fix: {after:#?}"
        );
    }
    // INFO stays: --fix-severity is WARN.
    assert!(after.iter().any(|f| f["severity"] == "INFO"), "{after:#?}");
    assert!(value["after"]["summary"]["CRITICAL"].as_u64().unwrap() > 0);
}

#[test]
fn fix_severity_critical_leaves_the_warnings_alone() {
    let fx = Sandbox::new();
    vault(&fx, "broken_health");
    let out = fx
        .crypto(&["--json", "health", "broken_health", "--fix", "--fix-severity", "CRITICAL", "--no-report"])
        .env("CRYPTO_PASSWORD", "test-password-123")
        .assert()
        .code(11)
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&out).unwrap();
    let after = value["after"]["findings"].as_array().unwrap();
    assert!(after.iter().any(|f| f["message"].as_str().unwrap().starts_with("Orphan directory:")),
            "a WARN finding is untouched at --fix-severity CRITICAL");
}

#[test]
fn fix_is_idempotent() {
    let fx = Sandbox::new();
    vault(&fx, "broken_health");
    let run = || {
        let out = fx
            .crypto(&["--json", "health", "broken_health", "--fix", "--no-report"])
            .env("CRYPTO_PASSWORD", "test-password-123")
            .assert()
            .code(11)
            .get_output()
            .stdout
            .clone();
        serde_json::from_slice::<Value>(&out).unwrap()["after"]["summary"].clone()
    };
    let first = run();
    let second = run();
    assert_eq!(first, second, "a second --fix run changes nothing");
}

#[test]
fn a_fixed_vault_is_still_readable() {
    let fx = Sandbox::new();
    vault(&fx, "broken_health");
    fx.crypto(&["health", "broken_health", "--fix", "--no-report"])
        .env("CRYPTO_PASSWORD", "test-password-123")
        .assert()
        .code(11);
    // The intact file is unchanged, and the adopted one shows up under LOST+FOUND.
    fx.crypto(&["fs", "cat", "broken_health", "/healthy.txt"])
        .env("CRYPTO_PASSWORD", "test-password-123")
        .assert()
        .success()
        .stdout(predicate::str::contains("this file stays intact"));
    fx.crypto(&["fs", "ls", "broken_health", "/LOST+FOUND"])
        .env("CRYPTO_PASSWORD", "test-password-123")
        .assert()
        .success();
}

#[test]
fn fix_without_json_prints_before_and_after() {
    let fx = Sandbox::new();
    vault(&fx, "broken_health");
    fx.crypto(&["health", "broken_health", "--fix", "--no-report"])
        .env("CRYPTO_PASSWORD", "test-password-123")
        .assert()
        .code(11)
        .stdout(predicate::str::contains("before the fixes"))
        .stdout(predicate::str::contains("after the fixes"))
        .stdout(predicate::str::contains("fixed"));
}
```

- [ ] **Step 2: Run – must fail**

Run: `cargo test -p crypto --test cli_health --locked fix`
Expected: FAIL with exit 2 (`--fix: not implemented yet`).

- [ ] **Step 3: Replace the rejection block**

`grep -n "not implemented yet" crates/crypto/src/commands/health.rs` finds the block from Task 8, Step 5. In its place, after the first `run_checks`, comes:

```rust
let fix_severity = Severity::parse_threshold(&args.fix_severity)?;   // already above, before the password
let mut first = results;
let mut fixed_flags: Vec<Option<bool>> = vec![None; first.len()];
if args.fix {
    for (i, result) in first.iter().enumerate() {
        if result.severity < fix_severity { continue; }
        let Some(fix) = &result.fix else { continue };
        match fix.apply(&check_ctx) {
            Ok(()) => fixed_flags[i] = Some(true),
            Err(err) => {
                fixed_flags[i] = Some(false);
                eprintln!("warning: could not fix \"{}\": {err}", result.message);
            }
        }
    }
}
let second = if args.fix { Some(run_checks(&checks, &check_ctx)) } else { None };
```

- [ ] **Step 4: Output for both runs**

Without `--fix` the JSON from Task 8 stays unchanged (backwards compatibility for scripts). With `--fix` it takes the form

```json
{ "vault": "…", "path": "…", "checks": [ … ], "report": "…", "failOn": "CRITICAL",
  "fixSeverity": "WARN",
  "before": { "summary": { … }, "findings": [ … with "fixed": true|false|null … ] },
  "after":  { "summary": { … }, "findings": [ … "fixed": null … ] } }
```
The top-level `findings` field is then missing; `before`/`after` are missing without `--fix`. A script tells the two forms apart by exactly the flag it set itself.

Human-readable output with `--fix`:
```
before the fixes
    WARN - Orphan directory: d/AB/CDEF…            [fixed]
CRITICAL - File d/…/dir.c9r is empty, expected content
12 good, 1 info, 2 warnings, 3 critical

after the fixes
CRITICAL - File d/…/dir.c9r is empty, expected content
15 good, 1 info, 0 warnings, 1 critical
```
The suffix is `[fixed]` for `Some(true)` and `[fix failed]` for `Some(false)`.

The report (Task 8, Step 6) is written with the results of the **second** run – it should describe the state the vault is in now.

Exit code: `worst` over `second.as_ref().unwrap_or(&first)`.

- [ ] **Step 5: Tests, gate, commit**

Run: `cargo test -p crypto --test cli_health --locked`
Expected: 12 passed.

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked`

```bash
git add crates/crypto/src/commands/health.rs crates/crypto/tests/cli_health.rs
git commit -m "feat(cli): crypto health --fix with a second pass and before/after output

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 10: `migration/{mod,v6,v8}.rs` – version detection, 5→6 and 7→8

**Files:**
- Create: `crates/cryptomator-core/src/migration/mod.rs`, `crates/cryptomator-core/src/migration/v6.rs`, `crates/cryptomator-core/src/migration/v8.rs`
- Modify: `crates/cryptomator-core/src/lib.rs`, `crates/cryptomator-core/src/error.rs`
- Test: `crates/cryptomator-core/tests/migration.rs`

**Interfaces:**
- Consumes: `crate::{determine_vault_version, needs_migration}`, `crate::masterkey_file::{MasterkeyFileAccess, DEFAULT_MASTERKEY_FILE_VERSION}`, `crate::backup::attempt_backup`, `crate::constants::{MASTERKEY_FILENAME, VAULTCONFIG_FILENAME, DEFAULT_KEY_ID, VAULT_VERSION}`, `crate::vault_config::VaultConfig`, `crate::crypto::cryptor::CipherCombo`, `crate::crypto::rng::Rng`, `unicode_normalization::UnicodeNormalization`.
- Produces:
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationStep { FiveToSix, SixToSeven, SevenToEight }
impl MigrationStep {
    pub fn from_version(v: u32) -> Option<Self>;      // 5|6|7 -> Some, otherwise None
    pub fn as_str(self) -> &'static str;              // "5->6" | "6->7" | "7->8"
}

#[derive(Debug, Clone)]
pub struct MigrationPlan {
    pub from_version: u32,
    pub steps: Vec<MigrationStep>,
    /// Only filled for 6->7 (Task 11); empty otherwise.
    pub renames: Vec<PlannedRename>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedRename { pub from: PathBuf, pub to: PathBuf }   // both vault-relative

/// `FileSystemCapabilityChecker.assertAllCapabilities`
pub fn assert_all_capabilities(vault_path: &Path) -> Result<()>;

#[derive(Debug)]
pub struct Migrators;
impl Migrators {
    pub fn needs_migration(vault_path: &Path) -> Result<bool>;
    pub fn plan(vault_path: &Path) -> Result<MigrationPlan>;
    /// Migrates step by step up to format 8. `progress` is called before every step.
    pub fn migrate(
        vault_path: &Path,
        passphrase: &str,
        full_scan_allowed: bool,
        progress: &mut dyn FnMut(MigrationStep),
        rng: &mut dyn Rng,
    ) -> Result<Vec<MigrationStep>>;
}
```
plus the new errors:
```rust
// crates/cryptomator-core/src/error.rs
#[error("the storage does not support {capability}: {path}")]
MissingCapability { path: PathBuf, capability: &'static str },   // "read access" | "write access"
#[error("ciphertext name too long for this storage: {path} needs {needed} chars, the storage allows {allowed}")]
FileNameTooLong { path: PathBuf, needed: usize, allowed: usize },
#[error("migration cannot continue: {0}")]
MigrationBlocked(String),
```
All three land in `exit.rs::core_code` in the `GENERAL` group, except `MigrationBlocked`, which goes to `WRONG_STATE` (5): "the vault cannot be migrated as it is" is exactly the state error.

**Java template.** `Migrators.determineVaultVersion` (we already have it as `determine_vault_version`), `Migration.isApplicable` (5→6, 6→7, 7→8), `Version6Migrator`, `Version8Migrator`, `FileSystemCapabilityChecker.assertAllCapabilities`.

- [ ] **Step 1: Failing tests**

In `crates/cryptomator-core/tests/migration.rs`:

```rust
use cryptomator_core::migration::{MigrationStep, Migrators};
use cryptomator_core::{MasterkeyFileAccess, OsRng};

fn manifest(vault: &std::path::Path) -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(vault.join("fixture.json")).unwrap()).unwrap()
}

#[test]
fn the_plan_lists_every_step_up_to_format_eight() {
    for (name, steps) in [
        ("legacy_v5", vec![MigrationStep::FiveToSix, MigrationStep::SixToSeven, MigrationStep::SevenToEight]),
        ("legacy_v6", vec![MigrationStep::SixToSeven, MigrationStep::SevenToEight]),
        ("legacy_v7", vec![MigrationStep::SevenToEight]),
    ] {
        let plan = Migrators::plan(&common::fixture(name)).unwrap();
        assert_eq!(plan.steps, steps, "{name}");
    }
    let plan = Migrators::plan(&common::fixture("siv_gcm_basic")).unwrap();
    assert!(plan.steps.is_empty(), "a format 8 vault has nothing to do");
    assert_eq!(plan.from_version, 8);
}

#[test]
fn five_to_six_normalises_the_passphrase_and_keeps_the_key() {
    let (_tmp, vault) = common::copy_fixture("legacy_v5");
    let m = manifest(&vault);
    let (nfd, nfc) = (m["passphrase"].as_str().unwrap(), m["passphraseNfc"].as_str().unwrap());
    let access = MasterkeyFileAccess::new(Vec::new());
    let before = access.load(&vault.join("masterkey.cryptomator"), nfd).unwrap();

    cryptomator_core::migration::v6::migrate(&vault, nfd, &mut OsRng).unwrap();

    assert_eq!(cryptomator_core::determine_vault_version(&vault).unwrap(), 6);
    let after = access.load(&vault.join("masterkey.cryptomator"), nfc).expect("NFC opens it now");
    assert_eq!(before.raw(), after.raw(), "the masterkey itself is unchanged");
    assert!(access.load(&vault.join("masterkey.cryptomator"), nfd).is_err(),
            "the NFD form no longer opens the vault");
    // A backup of the old file sits next to it.
    let backups: Vec<_> = std::fs::read_dir(&vault).unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("masterkey.cryptomator.") && n.ends_with(".bkup"))
        .collect();
    assert_eq!(backups.len(), 1, "{backups:?}");
}

#[test]
fn seven_to_eight_writes_a_vault_config_with_siv_ctrmac() {
    let (_tmp, vault) = common::copy_fixture("legacy_v7");
    let pass = manifest(&vault)["passphrase"].as_str().unwrap().to_string();
    cryptomator_core::migration::v8::migrate(&vault, &pass, &mut OsRng).unwrap();

    assert_eq!(cryptomator_core::determine_vault_version(&vault).unwrap(), 8);
    let config = cryptomator_core::read_vault_config(&vault).unwrap();
    assert_eq!(config.alleged_vault_version(), Some(8));
    assert_eq!(config.alleged_cipher_combo().as_deref(), Some("SIV_CTRMAC"));
    assert_eq!(config.alleged_shortening_threshold(), Some(220));
    assert_eq!(config.key_id().unwrap().require_masterkey_file().unwrap(), "masterkey.cryptomator");
    // The masterkey file now carries 999 and opens with the same passphrase.
    let raw = std::fs::read(vault.join("masterkey.cryptomator")).unwrap();
    assert_eq!(MasterkeyFileAccess::read_alleged_vault_version(&raw).unwrap(), 999);
    // And the whole thing is a vault that open_vault accepts.
    cryptomator_core::open_vault(&vault, &MasterkeyFileAccess::new(Vec::new()), &pass).unwrap();
}

#[test]
fn seven_to_eight_refuses_to_overwrite_an_existing_config() {
    let (_tmp, vault) = common::copy_fixture("legacy_v7");
    let pass = manifest(&vault)["passphrase"].as_str().unwrap().to_string();
    std::fs::write(vault.join("vault.cryptomator"), b"not a jwt").unwrap();
    let err = cryptomator_core::migration::v8::migrate(&vault, &pass, &mut OsRng).unwrap_err();
    assert!(err.to_string().contains("vault.cryptomator"), "{err}");
}

#[test]
fn a_wrong_passphrase_changes_nothing() {
    let (_tmp, vault) = common::copy_fixture("legacy_v7");
    let before = std::fs::read(vault.join("masterkey.cryptomator")).unwrap();
    assert!(cryptomator_core::migration::v8::migrate(&vault, "wrong", &mut OsRng).is_err());
    assert_eq!(std::fs::read(vault.join("masterkey.cryptomator")).unwrap(), before);
    assert!(!vault.join("vault.cryptomator").exists());
}

#[test]
fn the_capability_check_passes_on_a_normal_directory_and_cleans_up() {
    let dir = tempfile::tempdir().unwrap();
    cryptomator_core::migration::assert_all_capabilities(dir.path()).unwrap();
    assert!(!dir.path().join("c").exists(), "the probe directory is removed");
}
```

- [ ] **Step 2: Run – must fail**

Run: `cargo test -p cryptomator-core --test migration --locked`
Expected: FAIL, module `migration` is missing.

- [ ] **Step 3: `assert_all_capabilities`**

```rust
/// `FileSystemCapabilityChecker.assertAllCapabilities`: read first, then write.
pub fn assert_all_capabilities(vault_path: &Path) -> Result<()> {
    std::fs::read_dir(vault_path).map_err(|_| CoreError::MissingCapability {
        path: vault_path.to_path_buf(), capability: "read access",
    })?;
    let check_dir = vault_path.join("c");
    let result = (|| -> std::io::Result<()> {
        std::fs::create_dir_all(&check_dir)?;
        let tmp = check_dir.join("write-access-probe");
        std::fs::create_dir(&tmp)?;
        std::fs::remove_dir(&tmp)
    })();
    let _ = std::fs::remove_dir_all(&check_dir);      // Java: deleteRecursivelySilently in the finally
    result.map_err(|_| CoreError::MissingCapability {
        path: check_dir, capability: "write access",
    })?;
    Ok(())
}
```
Java uses `Files.createTempDirectory(checkDir, "write-access")`; a fixed name is enough and makes the test deterministic, because the directory disappears again immediately.

- [ ] **Step 4: `v6.rs`**

```rust
//! 5 -> 6, port of `migration/v6/Version6Migrator.java`. Version 6 encodes the passphrase in
//! Unicode NFC; the key itself stays the same.
pub fn migrate(vault_path: &Path, passphrase: &str, rng: &mut dyn Rng) -> Result<()> {
    let masterkey_file = vault_path.join(MASTERKEY_FILENAME);
    let access = MasterkeyFileAccess::new(Vec::new());
    let masterkey = access.load(&masterkey_file, passphrase)?;    // check first …
    attempt_backup(&masterkey_file)?;                             // … then back up (Java order)
    let normalized: Zeroizing<String> = Zeroizing::new(passphrase.nfc().collect());
    access.persist(&masterkey, &masterkey_file, &normalized, 6, rng)
}
```
The order "load, then back up" is Java's and it matters: a wrong passphrase must leave neither a backup nor a change behind. `attempt_backup` is the same helper that `open_vault` uses (`.bkup` suffix from SHA-256).

- [ ] **Step 5: `v8.rs`**

```rust
//! 7 -> 8, port of `migration/v8/Version8Migrator.java`: the masterkey file is split into
//! `masterkey.cryptomator` (only KDF parameters now) and `vault.cryptomator` (format and
//! vault-specific metadata).
pub fn migrate(vault_path: &Path, passphrase: &str, rng: &mut dyn Rng) -> Result<()> {
    let masterkey_file = vault_path.join(MASTERKEY_FILENAME);
    let config_file = vault_path.join(VAULTCONFIG_FILENAME);
    let access = MasterkeyFileAccess::new(Vec::new());
    let masterkey = access.load(&masterkey_file, passphrase)?;
    attempt_backup(&masterkey_file)?;
    // Java: SIV_CTRMAC and threshold 220 fixed -- format 7 knew nothing else.
    let config = VaultConfig::create_new(CipherCombo::SivCtrMac, 220);
    let token = config.to_token(DEFAULT_KEY_ID, masterkey.raw());
    // CREATE_NEW: an already existing vault.cryptomator is an error, not something to overwrite.
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&config_file)
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::AlreadyExists => CoreError::MigrationBlocked(format!(
                "{} already exists; the vault may already be migrated", config_file.display())),
            _ => CoreError::Io(e),
        })?;
    std::io::Write::write_all(&mut file, token.as_bytes())?;
    file.sync_all()?;
    access.persist(&masterkey, &masterkey_file, passphrase, DEFAULT_MASTERKEY_FILE_VERSION, rng)
}
```
`VaultConfig::create_new` sets `vault_version = VAULT_VERSION` (8) and a random `jti` – exactly like Java's `withJWTId(UUID.randomUUID())`. `DEFAULT_MASTERKEY_FILE_VERSION` is 999, Java's `persist(…, 999)`.

`CipherCombo::SivCtrMac` is the variant name from `crypto/cryptor.rs`; the implementer verifies it with `grep -n "enum CipherCombo" -A 6 crates/cryptomator-core/src/crypto/cryptor.rs`.

- [ ] **Step 6: `mod.rs` – plan and loop**

```rust
impl Migrators {
    pub fn plan(vault_path: &Path) -> Result<MigrationPlan> {
        let from_version = determine_vault_version(vault_path)?;
        let mut steps = Vec::new();
        let mut v = from_version;
        while let Some(step) = MigrationStep::from_version(v) {
            steps.push(step);
            v += 1;
        }
        Ok(MigrationPlan { from_version, steps, renames: Vec::new() })
    }

    pub fn migrate(
        vault_path: &Path, passphrase: &str, full_scan_allowed: bool,
        progress: &mut dyn FnMut(MigrationStep), rng: &mut dyn Rng,
    ) -> Result<Vec<MigrationStep>> {
        assert_all_capabilities(vault_path)?;
        let mut done = Vec::new();
        // The passphrase changes in 5->6 (NFC); the following steps need the new form.
        let mut current: Zeroizing<String> = Zeroizing::new(passphrase.to_string());
        loop {
            let version = determine_vault_version(vault_path)?;
            let Some(step) = MigrationStep::from_version(version) else { break };
            progress(step);
            match step {
                MigrationStep::FiveToSix => {
                    v6::migrate(vault_path, &current, rng)?;
                    current = Zeroizing::new(current.nfc().collect());
                }
                MigrationStep::SixToSeven => v7::migrate(vault_path, &current, full_scan_allowed, rng)?,
                MigrationStep::SevenToEight => v8::migrate(vault_path, &current, rng)?,
            }
            done.push(step);
        }
        Ok(done)
    }
}
```
`MigrationStep::from_version` returns `None` for `0..=4` and `>= 8`. A vault with version 4 or lower is therefore **not a migration target**; `plan()` returns an empty step list and `migrate` does nothing. The command in Task 12 catches this case and reports `MigrationBlocked("vault format 4 is older than this tool can migrate; use Cryptomator 1.4 or newer first")`. Java throws `NoApplicableMigratorException` there.

**In this task `v7` does not exist yet.** Until Task 11 the `SixToSeven` branch reads:
```rust
MigrationStep::SixToSeven => return Err(CoreError::MigrationBlocked(
    "the 6->7 migrator arrives with the next task".to_string())),
```
The test `the_plan_lists_every_step_up_to_format_eight` runs anyway (it does not migrate), and `five_to_six_…`/`seven_to_eight_…` call the migrators directly.

`lib.rs`: `pub mod migration;` plus `pub use migration::{MigrationPlan, MigrationStep, Migrators, PlannedRename};`.

- [ ] **Step 7: Tests, gate, commit**

Run: `cargo test -p cryptomator-core --test migration --locked`
Expected: 8 passed (the two from Task 2 plus six new ones; `stamp_legacy_v5` stays `#[ignore]`).

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked`

```bash
git add crates/cryptomator-core/src crates/cryptomator-core/tests/migration.rs
git commit -m "feat(core): vault migrators 5->6 and 7->8 with version detection

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 11: `migration/v7.rs` – the 6→7 name migration

**Files:**
- Create: `crates/cryptomator-core/src/migration/v7.rs`
- Modify: `crates/cryptomator-core/src/migration/mod.rs` (`pub mod v7;`, the `SixToSeven` branch, `MigrationPlan::renames`)
- Test: `crates/cryptomator-core/tests/migration.rs`, unit tests in `v7.rs`

**Interfaces:**
- Consumes: `migration::{assert_all_capabilities, PlannedRename}` (Task 10), `crate::fs::capabilities::{determine_supported_ciphertext_file_name_length, max_cleartext_file_name_length}`, `crate::masterkey_file::MasterkeyFileAccess`, `crate::backup::attempt_backup`, `data_encoding::{BASE32, BASE64URL}`, `sha1::Sha1`.
- Produces:
```rust
pub const OLD_SHORTENED_FILENAME_SUFFIX: &str = ".lng";
pub const OLD_DIRECTORY_PREFIX: &str = "0";
pub const OLD_SYMLINK_PREFIX: &str = "1S";
pub const SHORTENING_THRESHOLD: usize = 220;
pub const MAX_FILENAME_BUFFER_SIZE: u64 = 10 * 1024;
pub const MIGRATION_ATTEMPTS: usize = 3;

/// A single file name before the migration. Port of `migration/v7/FilePathMigration.java`.
#[derive(Debug, Clone)]
pub struct FilePathMigration { old_path: PathBuf, old_canonical_name: String }

impl FilePathMigration {
    /// `None` if the name is already migrated or is not a Cryptomator name at all.
    pub fn parse(vault_root: &Path, old_path: &Path) -> Result<Option<Self>>;
    pub fn old_path(&self) -> &Path;
    pub fn is_directory(&self) -> bool;                       // starts with "0"
    pub fn is_symlink(&self) -> bool;                         // starts with "1S"
    pub fn old_canonical_name_without_type_prefix(&self) -> &str;
    pub fn decoded_ciphertext(&self) -> Result<Vec<u8>>;      // BASE32 decoding
    pub fn new_inflated_name(&self) -> Result<String>;        // BASE64URL(…) + ".c9r"
    pub fn new_deflated_name(&self) -> Result<String>;        // if needed BASE64URL(SHA1(…)) + ".c9s"
    pub fn target_path(&self, attempt_suffix: &str) -> Result<PathBuf>;
    pub fn migrate(&self) -> Result<PathBuf>;
}

pub fn inflate(vault_root: &Path, long_file_name: &str) -> Result<String>;
pub fn plan_renames(vault_root: &Path) -> Result<Vec<PlannedRename>>;
pub fn migrate(vault_root: &Path, passphrase: &str, full_scan_allowed: bool, rng: &mut dyn Rng) -> Result<()>;
```

**Java template, verbatim.** The four regular expressions and constants from `FilePathMigration.java`:
```java
OLD_SHORTENED_FILENAME_SUFFIX = ".lng";
OLD_SHORTENED_FILENAME_PATTERN = "[A-Z2-7]{32}";
OLD_CANONICAL_FILENAME_PATTERN = "(0|1S)?([A-Z2-7]{8})*[A-Z2-7=]{8}";
BASE32 = BaseEncoding.base32();            // RFC 4648, uppercase, '=' padding
BASE64 = BaseEncoding.base64Url();         // with padding
SHORTENING_THRESHOLD = 220;
MAX_FILENAME_BUFFER_SIZE = 10 * 1024;
```
Both patterns are used with `find()`, **not** with `matches()`: a name with a conflict suffix like `ABCDEFGH (1)` yields the group `ABCDEFGH`. Without a regex crate we rebuild that by hand – Step 3.

- [ ] **Step 1: Failing unit tests for the name arithmetic**

In `v7.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn migration(name: &str) -> FilePathMigration {
        FilePathMigration { old_path: PathBuf::from("/v/d/AB/CD").join(name),
                            old_canonical_name: canonical(name).expect("a canonical name") }
    }

    #[test]
    fn the_canonical_name_is_found_inside_a_conflicting_name() {
        assert_eq!(canonical("MFRGGZDFMZTWQ2LK").as_deref(), Some("MFRGGZDFMZTWQ2LK"));
        assert_eq!(canonical("MFRGGZDFMZTWQ2LK (1)").as_deref(), Some("MFRGGZDFMZTWQ2LK"));
        assert_eq!(canonical("0MFRGGZDFMZTWQ2LK").as_deref(), Some("0MFRGGZDFMZTWQ2LK"));
        assert_eq!(canonical("1SMFRGGZDFMZTWQ2LK").as_deref(), Some("1SMFRGGZDFMZTWQ2LK"));
        // Padding is only allowed in the last block.
        assert_eq!(canonical("MFRGGZDFMZTWQ2L=").as_deref(), Some("MFRGGZDFMZTWQ2L="));
        assert_eq!(canonical("nope").as_deref(), None);
        assert_eq!(canonical("SHORT").as_deref(), None);          // fewer than 8 characters
    }

    #[test]
    fn base32_becomes_base64url_with_a_c9r_suffix() {
        // BASE32("Hello!!!") -> the bytes -> BASE64URL
        let m = migration("JBSWY3DPEHPK3PXP");
        assert_eq!(m.new_inflated_name().unwrap(), "SGVsbG8h3q2-7w==.c9r");
    }

    #[test]
    fn the_type_prefix_is_stripped_before_decoding() {
        let dir = migration("0JBSWY3DPEHPK3PXP");
        assert!(dir.is_directory() && !dir.is_symlink());
        assert_eq!(dir.old_canonical_name_without_type_prefix(), "JBSWY3DPEHPK3PXP");
        let link = migration("1SJBSWY3DPEHPK3PXP");
        assert!(link.is_symlink() && !link.is_directory());
        assert_eq!(link.old_canonical_name_without_type_prefix(), "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn a_long_name_is_deflated_to_a_c9s_name() {
        let long = migration(&"A".repeat(8 * 40));   // 320 BASE32 characters -> 200 bytes -> 268 base64
        let inflated = long.new_inflated_name().unwrap();
        assert!(inflated.len() > SHORTENING_THRESHOLD);
        let deflated = long.new_deflated_name().unwrap();
        assert!(deflated.ends_with(".c9s") && deflated.len() == 28 + 4);   // base64(sha1)=28 + ".c9s"
        assert_ne!(inflated, deflated);
    }

    #[test]
    fn target_paths_follow_the_type() {
        assert!(migration("JBSWY3DPEHPK3PXP").target_path("").unwrap().ends_with("SGVsbG8h3q2-7w==.c9r"));
        assert!(migration("0JBSWY3DPEHPK3PXP").target_path("").unwrap().ends_with("SGVsbG8h3q2-7w==.c9r/dir.c9r"));
        assert!(migration("1SJBSWY3DPEHPK3PXP").target_path("").unwrap().ends_with("SGVsbG8h3q2-7w==.c9r/symlink.c9r"));
    }

    #[test]
    fn the_attempt_suffix_goes_before_the_extension() {
        let p = migration("JBSWY3DPEHPK3PXP").target_path("_1").unwrap();
        assert!(p.ends_with("SGVsbG8h3q2-7w==_1.c9r"), "{p:?}");
    }
}
```

The expected string `SGVsbG8h3q2-7w==.c9r` is to be verified with
`python3 -c "import base64;print(base64.urlsafe_b64encode(base64.b32decode('JBSWY3DPEHPK3PXP')).decode())"`
; if it deviates, the constant in the test is corrected.

- [ ] **Step 2: Run – must fail**

Run: `cargo test -p cryptomator-core migration::v7 --locked`
Expected: FAIL, module missing.

- [ ] **Step 3: `canonical` – the two patterns without a regex crate**

```rust
fn is_base32_char(c: char) -> bool { c.is_ascii_uppercase() && c != '0' && c != '1' || ('2'..='7').contains(&c) }

/// Java's `OLD_CANONICAL_FILENAME_PATTERN.matcher(name).find()`: the longest prefix from position 0
/// that satisfies `(0|1S)?([A-Z2-7]{8})*[A-Z2-7=]{8}`. Java searches with `find()` at *every*
/// position; for real v6 names the match is always at the start (conflict suffixes hang off the
/// end), and a match in the middle would be a name that Java too only migrates correctly by
/// accident. So we search from position 0 and document the restriction.
fn canonical(file_name: &str) -> Option<String> { … }
```
The algorithm: split off the prefix `1S` or `0` (check in that order, `1S` first – `1` on its own is not a BASE32 character, so there is no ambiguity). From the rest take as many full 8-character blocks of `[A-Z2-7]` as possible, then exactly one final 8-character block of `[A-Z2-7=]` must follow. The match is prefix + all consumed blocks; if there is none, `None`. The candidate must additionally have at least one block (Java's `*` allows zero repetitions, but the mandatory block at the end stays).

Careful, a Java detail with consequences: the last block may contain `=` **at any position** (`[A-Z2-7=]{8}`), not only at the end. `BASE32.decode` rejects such names later and yields `InvalidOldFilenameException`; we mirror that with `CoreError::InvalidArgument`.

`FilePathMigration::parse`:
```rust
pub fn parse(vault_root: &Path, old_path: &Path) -> Result<Option<Self>> {
    let name = old_path.file_name().unwrap_or_default().to_string_lossy().into_owned();
    // Already migrated? BASE32 is a subset of BASE64URL, a pure pattern match
    // would migrate `.c9r` names a second time.
    if name.ends_with(CRYPTOMATOR_FILE_SUFFIX) || name.ends_with(DEFLATED_FILE_SUFFIX) {
        return Ok(None);
    }
    let canonical_name = if name.ends_with(OLD_SHORTENED_FILENAME_SUFFIX) {
        match find_32_base32_chars(&name) {
            Some(hit) => inflate(vault_root, &format!("{hit}{OLD_SHORTENED_FILENAME_SUFFIX}"))?,
            None => return Ok(None),
        }
    } else {
        match canonical(&name) { Some(c) => c, None => return Ok(None) }
    };
    Ok(Some(Self { old_path: old_path.to_path_buf(), old_canonical_name: canonical_name }))
}
```
`find_32_base32_chars` is Java's `[A-Z2-7]{32}` `find()`: the first occurrence of 32 consecutive BASE32 characters anywhere in the name (for `.lng` names with a conflict suffix it sits at the start, but `find()` at every position is cheap here and stays faithful to Java).

`inflate` reads `<vault>/m/<n[0..2]>/<n[2..4]>/<n>` with the size limit `MAX_FILENAME_BUFFER_SIZE`; a file that is too large or missing yields `CoreError::MigrationBlocked(format!("failed to read metadata file {}", path.display()))` — Java's `UninflatableFileException`, which the visitors answer with `SKIP` (Step 5).

- [ ] **Step 4: `migrate()` of a single file**

```rust
pub fn migrate(&self) -> Result<PathBuf> {
    let inflated = self.new_inflated_name()?;
    let deflated = self.new_deflated_name()?;
    let shortened = inflated != deflated;
    let mut suffix = String::new();
    for attempt in 1..=MIGRATION_ATTEMPTS {
        let new_path = self.target_path(&suffix)?;
        let result = (|| -> std::io::Result<PathBuf> {
            if shortened || self.is_directory() || self.is_symlink() {
                std::fs::create_dir(new_path.parent().expect("has a parent"))?;
            }
            if shortened {
                let meta = new_path.with_file_name(INFLATED_FILE_NAME);
                std::fs::write(meta, inflated.as_bytes())?;
            }
            std::fs::rename(&self.old_path, &new_path)?;
            Ok(new_path)
        })();
        match result {
            Ok(path) => return Ok(path),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => { suffix = format!("_{attempt}"); }
            Err(e) => return Err(CoreError::Io(e)),
        }
    }
    Err(CoreError::MigrationBlocked(format!(
        "{} could not be migrated after {MIGRATION_ATTEMPTS} attempts", self.old_path.display())))
}
```
Exactly like Java: the suffix is set **after** the failure, so the three attempts are `""`, `"_1"`, `"_2"`. The suffix goes before the extension (`name_1.c9r`), so that the conflict resolver from M3 later recognizes it as " (1)".

`target_path`:
```rust
let inflated_named = format!("{}{suffix}{CRYPTOMATOR_FILE_SUFFIX}", &inflated[..inflated.len() - 4]);
let deflated_named = format!("{}{suffix}{DEFLATED_FILE_SUFFIX}", &deflated[..deflated.len() - 4]);
let parent = self.old_path.parent().expect("has a parent");
Ok(match (shortened, self.is_directory(), self.is_symlink()) {
    (true,  true,  _)     => parent.join(&deflated_named).join(DIR_FILE_NAME),
    (true,  _,     true)  => parent.join(&deflated_named).join(SYMLINK_FILE_NAME),
    (true,  _,     _)     => parent.join(&deflated_named).join(CONTENTS_FILE_NAME),
    (false, true,  _)     => parent.join(&inflated_named).join(DIR_FILE_NAME),
    (false, _,     true)  => parent.join(&inflated_named).join(SYMLINK_FILE_NAME),
    (false, _,     _)     => parent.join(&inflated_named),
})
```

- [ ] **Step 5: The pre-pass and the migration of the whole vault**

`migrate(vault_root, passphrase, full_scan_allowed, rng)` follows `Version7Migrator.migrate`:

1. `masterkey = access.load(vault_root/masterkey.cryptomator, passphrase)?`
2. `attempt_backup(&masterkey_file)?`
3. `let filename_limit = determine_supported_ciphertext_file_name_length(vault_root)?;` — our helper already uses `subPathLength = 46`, `min = 28`, `max = 220`, so the same arguments as Java's `determineSupportedCiphertextFileNameLength(vaultRoot.resolve("c"), 46, 28, 220)`. `let path_limit = filename_limit + 48;`
4. `let full_scan = if filename_limit >= 220 { false } else { if !full_scan_allowed { return Err(CoreError::MigrationBlocked("this storage supports only {filename_limit} characters per name (220 required); a full scan of the vault is needed to tell whether migration is possible -- rerun with --yes".into())) } else { true } };`
5. Pre-pass over `d/` with depth limit 3, files only:
   - name ends in `.icloud` → `CoreError::MigrationBlocked("migration impossible due to file: {name}")` (Java's `BLACKLISTED_NAMES`, "unsynced icloud content, user needs to download the vault first").
   - `total_files += 1`
   - with `full_scan`: `FilePathMigration::parse` and advance `max_name_length`/`max_path_length` for the target path; a `MigrationBlocked` from `inflate` is **skipped** here (Java: `LOG.warn("SKIP … because inflation failed")`), and so is an `InvalidArgument` from the BASE32 decoder.
   - without `full_scan` the values are fixed at `max_name = 220`, `max_path = 268` (Java's `PreMigrationVisitor` getters).
6. `if max_path > path_limit { return Err(CoreError::FileNameTooLong { path: longest_path, needed: max_path, allowed: path_limit }) }`, then the same for `max_name > filename_limit`.
7. If `total_files > 0`: a second walk over `d/` with depth limit 3. **Collect per directory first, then apply** (Java's `MigratingVisitor`: `visitFile` collects, `postVisitDirectory` migrates) – otherwise you walk over the `.c9r` directories you have just created. An `AlreadyExists` after three attempts is logged and skipped, not thrown (Java's `catch (FileAlreadyExistsException)` in the visitor); all other errors abort.
8. Delete `m/` recursively (`std::fs::remove_dir_all`, `NotFound` is fine — Java's `DeletingFileVisitor`).
9. `access.persist(&masterkey, &masterkey_file, passphrase, 7, rng)?`

`plan_renames(vault_root)` is the same first walk, but it collects `PlannedRename { from, to }` with vault-relative paths from `target_path("")` and writes nothing. Collisions (two sources onto the same target) are **not** resolved — the `--dry-run` text says "collisions get a `_1`/`_2` suffix at migration time" about that.

- [ ] **Step 6: Integration test over the whole path**

In `crates/cryptomator-core/tests/migration.rs`:

```rust
#[test]
fn six_to_seven_renames_every_node_and_drops_the_metadata_dir() {
    let (_tmp, vault) = common::copy_fixture("legacy_v6");
    let pass = manifest(&vault)["passphrase"].as_str().unwrap().to_string();
    let planned = cryptomator_core::migration::v7::plan_renames(&vault).unwrap();
    assert!(planned.len() >= 6, "{planned:#?}");
    assert!(planned.iter().all(|r| r.to.to_string_lossy().contains(".c9r")
                                || r.to.to_string_lossy().contains(".c9s")));

    cryptomator_core::migration::v7::migrate(&vault, &pass, true, &mut OsRng).unwrap();

    assert_eq!(cryptomator_core::determine_vault_version(&vault).unwrap(), 7);
    assert!(!vault.join("m").exists(), "the metadata directory is gone");
    // No BASE32 name under d/ any more.
    let mut names = Vec::new();
    collect_names(&vault.join("d"), &mut names);
    assert!(names.iter().all(|n| n.ends_with(".c9r") || n.ends_with(".c9s")
                               || n.len() == 2 || n.len() == 30), "{names:?}");
}

#[test]
fn the_whole_chain_from_five_to_eight_produces_a_readable_vault() {
    for (name, passphrase_key) in [("legacy_v5", "passphrase"), ("legacy_v6", "passphrase"), ("legacy_v7", "passphrase")] {
        let (_tmp, vault) = common::copy_fixture(name);
        let m = manifest(&vault);
        let pass = m[passphrase_key].as_str().unwrap().to_string();
        let final_pass = m.get("passphraseNfc").and_then(|v| v.as_str()).unwrap_or(&pass).to_string();

        let steps = Migrators::migrate(&vault, &pass, true, &mut |_| {}, &mut OsRng).unwrap();
        assert_eq!(cryptomator_core::determine_vault_version(&vault).unwrap(), 8, "{name}");
        assert!(!steps.is_empty(), "{name}");

        // The migrated vault can be opened and contains exactly what the manifest says.
        let opened = cryptomator_core::open_vault(
            &vault, &MasterkeyFileAccess::new(Vec::new()), &final_pass).unwrap();
        let fs = cryptomator_core::fs::CryptoFs::open(opened, Default::default()).unwrap();
        for entry in m["expected"].as_array().unwrap() {
            let path = entry["path"].as_str().unwrap();
            let cleartext = cryptomator_core::fs::CleartextPath::parse(path).unwrap();
            assert!(fs.metadata(&cleartext).is_ok(), "{name}: {path} is missing after migration");
        }
        // And the health checks find nothing.
        let opened = cryptomator_core::open_vault(
            &vault, &MasterkeyFileAccess::new(Vec::new()), &final_pass).unwrap();
        let ctx = cryptomator_core::CheckContext::new(opened);
        let results = cryptomator_core::run_checks(&cryptomator_core::all_checks(), &ctx);
        let bad: Vec<_> = results.iter()
            .filter(|r| r.severity > cryptomator_core::Severity::Good).collect();
        assert!(bad.is_empty(), "{name}: {bad:#?}");
    }
}
```

`CleartextPath::parse` and `CryptoFs::metadata` are from M3; the exact names are in `crates/cryptomator-core/tests/crypto_fs_fixtures.rs` and are taken from there. `collect_names` is a small recursive helper in the same test file.

- [ ] **Step 7: Wire up `mod.rs`**

`pub mod v7;`, the `SixToSeven` branch calls `v7::migrate(vault_path, &current, full_scan_allowed, rng)?`, and `Migrators::plan` fills `renames` with `v7::plan_renames(vault_path)?` when `steps` contains the `SixToSeven` step (otherwise the vector stays empty).

- [ ] **Step 8: Tests, gate, commit**

Run: `cargo test -p cryptomator-core --test migration --locked && cargo test -p cryptomator-core migration::v7 --locked`
Expected: all green. The test `the_whole_chain_…` is the most expensive one in the repo (three vaults, up to three scrypt runs each); if it takes more than 60 s, the implementer checks whether the release profile for `dev.package."*"` takes effect (`grep -n 'opt-level' Cargo.toml`) instead of shortening the test.

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked`

```bash
git add crates/cryptomator-core/src/migration crates/cryptomator-core/tests/migration.rs
git commit -m "feat(core): the 6->7 file name migration (BASE32 to base64url)

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 12: `crypto migrate`

**Files:**
- Create: `crates/crypto/src/commands/migrate.rs`, `crates/crypto/tests/cli_migrate.rs`
- Modify: `crates/crypto/src/cli.rs`, `crates/crypto/src/main.rs`, `crates/crypto/src/commands/mod.rs`

**Interfaces:**
- Consumes: `cryptomator_core::migration::{MigrationStep, Migrators}`, `cryptomator_core::{determine_vault_state, VaultState}`, `crypto::commands::{keychain_source, Ctx}`, `crypto::commands::password::update_keychain_entry_or_warn`, `cryptomator_app::{read_passphrase_with_keychain, PasswordArgs, SystemIo, AppError}`.
- Produces:
```rust
// crates/crypto/src/cli.rs
#[derive(Args, Debug)]
pub struct MigrateArgs {
    #[arg(allow_hyphen_values = true)]
    pub vault: String,
    /// Do not ask for confirmation
    #[arg(long)]
    pub yes: bool,
    /// Show what would change and exit without touching the vault
    #[arg(long)]
    pub dry_run: bool,
    #[command(flatten)]
    pub password: PasswordArgs,
}

// crates/crypto/src/commands/mod.rs
/// Like `locked_vault`, but `NEEDS_MIGRATION` is allowed -- that is the very reason for it.
pub fn migratable_vault(ctx: &Ctx, reference: &str) -> Result<(VaultSettingsJson, PathBuf)>;

// crates/crypto/src/commands/migrate.rs
pub fn run(ctx: &Ctx, args: MigrateArgs) -> anyhow::Result<u8>;
```

- [ ] **Step 1: Failing CLI tests**

`crates/crypto/tests/cli_migrate.rs`:

```rust
mod common;
use common::Sandbox;
use predicates::prelude::*;
use serde_json::Value;

fn passphrase(fixture: &str) -> String {
    let manifest = std::fs::read_to_string(
        common::fixtures_root().join(fixture).join("fixture.json")).unwrap();
    serde_json::from_str::<Value>(&manifest).unwrap()["passphrase"].as_str().unwrap().to_string()
}

#[test]
fn migrating_a_v7_vault_makes_it_a_format_8_vault() {
    let fx = Sandbox::new();
    let path = fx.add_fixture("legacy_v7");
    let out = fx
        .crypto(&["--json", "migrate", "legacy_v7", "--yes"])
        .env("CRYPTO_PASSWORD", passphrase("legacy_v7"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(value["fromVersion"], 7);
    assert_eq!(value["toVersion"], 8);
    assert_eq!(value["steps"], serde_json::json!(["7->8"]));
    assert!(path.join("vault.cryptomator").is_file());
    // After that the vault is a perfectly normal one: `crypto vault info` says LOCKED.
    fx.crypto(&["--json", "vault", "info", "legacy_v7"])
        .assert().success().stdout(predicate::str::contains("\"LOCKED\""));
}

#[test]
fn migrating_a_v5_vault_runs_all_three_steps_and_normalises_the_passphrase() {
    let fx = Sandbox::new();
    fx.add_fixture("legacy_v5");
    let manifest: Value = serde_json::from_str(
        &std::fs::read_to_string(common::fixtures_root().join("legacy_v5/fixture.json")).unwrap()).unwrap();
    let nfd = manifest["passphrase"].as_str().unwrap().to_string();
    let nfc = manifest["passphraseNfc"].as_str().unwrap().to_string();
    let out = fx
        .crypto(&["--json", "migrate", "legacy_v5", "--yes"])
        .env("CRYPTO_PASSWORD", &nfd)
        .assert().success().get_output().stdout.clone();
    let value: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(value["steps"], serde_json::json!(["5->6", "6->7", "7->8"]));
    // From now on the NFC form applies -- and the CLI normalizes input to NFC anyway, so
    // both spellings work when unlocking.
    fx.crypto(&["fs", "ls", "legacy_v5", "/"])
        .env("CRYPTO_PASSWORD", &nfc)
        .assert().success().stdout(predicate::str::contains("hello.txt"));
}

#[test]
fn a_vault_that_is_already_current_exits_zero() {
    let fx = Sandbox::new();
    fx.add_fixture("siv_gcm_basic");
    fx.crypto(&["migrate", "siv_gcm_basic", "--yes"])
        .env("CRYPTO_PASSWORD", "test-password-123")
        .assert()
        .success()
        .stdout(predicate::str::contains("already at version 8"));
}

#[test]
fn without_yes_and_without_a_terminal_it_is_a_usage_error() {
    let fx = Sandbox::new();
    let path = fx.add_fixture("legacy_v7");
    fx.crypto(&["migrate", "legacy_v7"])
        .env("CRYPTO_PASSWORD", passphrase("legacy_v7"))
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--yes"));
    assert!(!path.join("vault.cryptomator").exists(), "nothing was migrated");
}

#[test]
fn dry_run_lists_the_renames_and_changes_nothing() {
    let fx = Sandbox::new();
    let path = fx.add_fixture("legacy_v6");
    let before = std::fs::read(path.join("masterkey.cryptomator")).unwrap();
    let out = fx
        .crypto(&["--json", "migrate", "legacy_v6", "--dry-run"])
        .env("CRYPTO_PASSWORD", passphrase("legacy_v6"))
        .assert().success().get_output().stdout.clone();
    let value: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(value["dryRun"], true);
    assert_eq!(value["steps"], serde_json::json!(["6->7", "7->8"]));
    let renames = value["renames"].as_array().unwrap();
    assert!(renames.len() >= 6, "{renames:#?}");
    assert!(renames[0]["to"].as_str().unwrap().contains(".c9"));
    // Nothing touched -- not even a backup.
    assert_eq!(std::fs::read(path.join("masterkey.cryptomator")).unwrap(), before);
    assert!(path.join("m").is_dir());
    assert!(!path.join("vault.cryptomator").exists());
    assert!(std::fs::read_dir(&path).unwrap()
        .all(|e| !e.unwrap().file_name().to_string_lossy().ends_with(".bkup")));
}

#[test]
fn a_wrong_passphrase_is_exit_four_and_leaves_the_vault_alone() {
    let fx = Sandbox::new();
    let path = fx.add_fixture("legacy_v7");
    let before = std::fs::read(path.join("masterkey.cryptomator")).unwrap();
    fx.crypto(&["migrate", "legacy_v7", "--yes"])
        .env("CRYPTO_PASSWORD", "wrong")
        .assert()
        .code(4);
    assert_eq!(std::fs::read(path.join("masterkey.cryptomator")).unwrap(), before);
    assert!(!path.join("vault.cryptomator").exists());
}

#[test]
fn a_stored_password_follows_the_nfc_normalisation() {
    let fx = Sandbox::new();
    fx.add_fixture("legacy_v5");
    let manifest: Value = serde_json::from_str(
        &std::fs::read_to_string(common::fixtures_root().join("legacy_v5/fixture.json")).unwrap()).unwrap();
    let nfd = manifest["passphrase"].as_str().unwrap().to_string();
    let nfc = manifest["passphraseNfc"].as_str().unwrap().to_string();
    let id = fx.vault_id(0);
    fx.seed_keychain(&id, "legacy_v5", &nfd);
    fx.crypto_keychain(&["migrate", "legacy_v5", "--yes"])
        .env("CRYPTO_PASSWORD", &nfd)
        .assert().success();
    let stored = fx.fake_keychain_json();
    assert_eq!(stored[&id]["passphrase"], nfc, "the keychain entry followed the migration");
}
```

The last test uses `Sandbox::{seed_keychain, crypto_keychain, fake_keychain_json, vault_id}` from M6; the exact shape of `fake_keychain_json` (key name `passphrase` or something else) is to be checked with `sed -n '150,170p' crates/crypto/tests/common/mod.rs` and the assertion written accordingly.

- [ ] **Step 2: Run – must fail**

Run: `cargo test -p crypto --test cli_migrate --locked`
Expected: FAIL, `unrecognized subcommand 'migrate'`.

- [ ] **Step 3: `migratable_vault`**

```rust
/// Like [`locked_vault`], but `NEEDS_MIGRATION` is permitted -- that is the state
/// `crypto migrate` is meant to fix. The runtime part stays: a daemon serving the vault
/// holds files open, and the migration renames all of them.
pub fn migratable_vault(ctx: &Ctx, reference: &str) -> Result<(VaultSettingsJson, PathBuf)> {
    let settings = ctx.store.load()?;
    let index = resolve_vault_index(&settings, reference)?;
    let vault = settings.directories[index].clone();
    let path = vault.path_buf().ok_or_else(|| AppError::InvalidValue {
        key: "path".to_string(), message: format!("vault {} has no path", vault.id) })?;
    let state = determine_vault_state(&path)?;
    if !matches!(state, VaultState::Locked | VaultState::NeedsMigration) {
        return Err(AppError::WrongState {
            expected: "LOCKED or NEEDS_MIGRATION".to_string(),
            actual: state.as_str().to_string(),
        }.into());
    }
    ctx.registry().require_locked(&vault)?;
    Ok((vault, path))
}
```

- [ ] **Step 4: The command**

```rust
pub fn run(ctx: &Ctx, args: MigrateArgs) -> Result<u8> {
    let (vault, path) = migratable_vault(ctx, &args.vault)?;
    let plan = Migrators::plan(&path)?;
    if plan.steps.is_empty() {
        if plan.from_version >= VAULT_VERSION {
            ctx.out.emit(json!({ "path": path, "fromVersion": plan.from_version,
                                 "toVersion": plan.from_version, "steps": [] }),
                || format!("already at version {}; nothing to migrate", plan.from_version))?;
            return Ok(exit::OK);
        }
        return Err(CoreError::MigrationBlocked(format!(
            "vault format {} is older than this tool can migrate; open it once with \
             Cryptomator 1.4 or newer first", plan.from_version)).into());
    }
    // …
}
```

After that, in this order:
1. Get the password (`read_passphrase_with_keychain` with `keychain_source`, like `health`).
2. With `--dry-run`: `emit` with `dryRun: true`, `renames` (from `plan.renames`, each `{from, to}`) and the steps, then `Ok(exit::OK)` – **without** checking the passphrase at all? No: the passphrase is checked (`MasterkeyFileAccess::load` against `masterkey.cryptomator`), so that a `--dry-run` with a wrong password does not suggest that the migration will work. Nothing is written while doing so – `load` is pure reading. That is why `a_wrong_passphrase_…` and `dry_run_…` are both clean.
3. Confirmation: without `--yes` and with `std::io::stdin().is_terminal()`, a question on stderr
   ```
   Vault "legacy_v6" is in format 6 and will be migrated to format 8 (steps: 6->7, 7->8).
   This rewrites file names in the vault and cannot be undone; make sure you have a backup.
   Continue? [y/N]
   ```
   and read one line from stdin; anything other than `y`/`yes` (case-insensitive) aborts with exit 0 and the message `aborted`. Without a terminal and without `--yes`:
   ```rust
   return Err(AppError::InvalidValue {
       key: "--yes".to_string(),
       message: "migration needs a confirmation; pass --yes when there is no terminal".to_string(),
   }.into());
   ```
4. `Migrators::migrate(&path, &passphrase, /* full_scan_allowed = */ true, &mut |step| { if !ctx.out.json { eprintln!("migrating {} …", step.as_str()); } }, &mut OsRng)?`
   `full_scan_allowed` is `true` as soon as confirmation was given (or `--yes` was passed): the confirmation question above is our version of Java's `REQUIRES_FULL_VAULT_DIR_SCAN`, and a second dialog in the middle of the migration would be unusable for a CLI. Record as a comment.
5. For a chain that contained `FiveToSix`: `update_keychain_entry_or_warn(ctx, &vault, &nfc_passphrase, &args.vault, "migration")`, so that a stored password follows the normalization (ruling: the same mechanism as `password change`; the command computes the NFC form with `unicode_normalization`). If the chain contained no `5->6` step, the keychain stays untouched.
6. Output:
   ```json
   { "path": "/vaults/v", "fromVersion": 5, "toVersion": 8,
     "steps": ["5->6", "6->7", "7->8"], "dryRun": false, "keychainUpdated": true }
   ```
   Human-readable form: `migrated /vaults/v from format 5 to format 8 (5->6, 6->7, 7->8)`.

`cli.rs`: `Command::Migrate(MigrateArgs)` with `/// Bring a vault of format 5, 6 or 7 up to format 8`.
`main.rs`: `Command::Migrate(args) => commands::migrate::run(&ctx, args),`.

- [ ] **Step 5: Check the state error elsewhere**

`crypto unlock`/`fs`/`health` on a legacy vault must return exit **5** and point at `crypto migrate` in the text. `determine_vault_state` already returns `NEEDS_MIGRATION` for that, and `locked_vault` turns it into `AppError::WrongState`. Only the hint text is missing: in `AppError::WrongState`'s `Display` (`crates/cryptomator-app/src/error.rs`) the text stays unchanged; instead `locked_vault` in `commands/mod.rs` gets a special case:

```rust
if state == VaultState::NeedsMigration {
    return Err(AppError::WrongState {
        expected: VaultState::Locked.as_str().to_string(),
        actual: format!("{} (run `crypto migrate {reference}` first)", state.as_str()),
    }.into());
}
```

A test for it in `cli_migrate.rs`:
```rust
#[test]
fn a_legacy_vault_points_at_the_migrate_command() {
    let fx = Sandbox::new();
    fx.add_fixture("legacy_v7");
    fx.crypto(&["fs", "ls", "legacy_v7", "/"])
        .env("CRYPTO_PASSWORD", passphrase("legacy_v7"))
        .assert()
        .code(5)
        .stderr(predicate::str::contains("crypto migrate legacy_v7"));
}
```

- [ ] **Step 6: Tests, gate, commit**

Run: `cargo test -p crypto --test cli_migrate --locked`
Expected: 8 passed.

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked`

```bash
git add crates/crypto/src crates/crypto/tests/cli_migrate.rs
git commit -m "feat(cli): crypto migrate with confirmation, --yes and --dry-run

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 13: `recovery/restore.rs` and `crypto recovery-key restore`

**Files:**
- Create: `crates/cryptomator-core/src/recovery/restore.rs`
- Modify: `crates/cryptomator-core/src/recovery/mod.rs`, `crates/cryptomator-core/src/lib.rs`, `crates/cryptomator-core/src/error.rs`, `crates/crypto/src/cli.rs`, `crates/crypto/src/commands/recovery.rs`, `crates/crypto/src/main.rs`
- Test: `crates/cryptomator-core/tests/vault_lifecycle.rs` (core), `crates/crypto/tests/cli.rs` (CLI)

**Interfaces:**
- Consumes: `crate::vault::init::initialize`, `crate::masterkey_file::{MasterkeyFileAccess, DEFAULT_MASTERKEY_FILE_VERSION}`, `crate::recovery::key::decode_recovery_key`, `crate::recovery::words::WordEncoder`, `crate::crypto::{masterkey::Masterkey, cryptor::{CipherCombo, Cryptor}}`, `crate::constants::{MASTERKEY_FILENAME, VAULTCONFIG_FILENAME, DEFAULT_KEY_ID, DATA_DIR_NAME, CRYPTOMATOR_FILE_SUFFIX, DIR_FILE_NAME}`.
- Produces:
```rust
/// `common/recovery/RecoveryDirectory.java`: everything is written into a temp directory first and
/// then moved into the vault, so that a half-written restore never touches the vault.
#[derive(Debug)]
pub struct RecoveryDirectory { vault_path: PathBuf, temp: tempfile::TempDir }
impl RecoveryDirectory {
    pub fn create(vault_path: &Path) -> std::io::Result<Self>;
    pub fn path(&self) -> &Path;
    pub fn move_recovered_file(&self, file_name: &str) -> std::io::Result<()>;   // REPLACE_EXISTING
}

/// `MasterkeyService.detect`: the first regular `*.c9r` that is not called `dir.c9r` is tried with
/// both schemes -- in the order of the Java enum `CryptorProvider.Scheme`:
/// SIV_CTRMAC, then SIV_GCM.
pub fn detect_cipher_combo(masterkey: &Masterkey, vault_path: &Path) -> Option<CipherCombo>;

/// RESTORE_MASTERKEY: recovery key + new password -> `masterkey.cryptomator`.
pub fn restore_masterkey(
    encoder: &WordEncoder, access: &MasterkeyFileAccess, vault_path: &Path,
    recovery_key: &str, new_passphrase: &str, rng: &mut dyn Rng,
) -> Result<()>;

/// RESTORE_VAULT_CONFIG: existing masterkey file + vault password -> `vault.cryptomator`.
pub fn restore_config(
    access: &MasterkeyFileAccess, vault_path: &Path, passphrase: &str,
    cipher_combo: Option<CipherCombo>, shortening_threshold: u32, rng: &mut dyn Rng,
) -> Result<VaultConfig>;

/// RESTORE_ALL: recovery key + new password -> both files.
pub fn restore_all(
    encoder: &WordEncoder, access: &MasterkeyFileAccess, vault_path: &Path,
    recovery_key: &str, new_passphrase: &str,
    cipher_combo: Option<CipherCombo>, shortening_threshold: u32, rng: &mut dyn Rng,
) -> Result<VaultConfig>;
```
plus `CoreError::CipherComboUndetectable(PathBuf)` (→ `WRONG_STATE`, exit 5: the vault does not give away enough to decide that).

Grammar:
```rust
#[derive(Args, Debug)]
#[command(group = clap::ArgGroup::new("restore-what").required(true))]
pub struct RestoreArgs {
    #[arg(allow_hyphen_values = true)]
    pub vault: String,
    /// Recreate masterkey.cryptomator from the recovery key
    #[arg(long, group = "restore-what")]
    pub masterkey: bool,
    /// Recreate vault.cryptomator from the existing masterkey file and the vault password
    #[arg(long, group = "restore-what")]
    pub config: bool,
    /// Recreate both files from the recovery key
    #[arg(long, group = "restore-what")]
    pub all: bool,
    /// Cipher combo of the vault (default: detect it from the first encrypted file)
    #[arg(long, value_name = "auto|SIV_GCM|SIV_CTRMAC", default_value = "auto")]
    pub cipher_combo: String,
    /// Shortening threshold to write into the new vault config
    #[arg(long, value_name = "N", default_value_t = 220, value_parser = clap::value_parser!(u32).range(36..=220))]
    pub shortening_threshold: u32,
    /// Read the recovery key from the next line of standard input
    #[arg(long)]
    pub recovery_key_stdin: bool,
    /// Read the recovery key from a file
    #[arg(long, value_name = "FILE", conflicts_with = "recovery_key_stdin")]
    pub recovery_key_file: Option<PathBuf>,
    #[command(flatten)]
    pub password: PasswordArgs,
    #[command(flatten)]
    pub new_password: NewPasswordArgs,
}
```

**Java template.** `RecoveryKeyResetPasswordController.restorePassword` (RESTORE_ALL), `RecoveryKeyCreationController.restoreWithPassword` (RESTORE_VAULT_CONFIG), `ResetPasswordTask.call` (RESTORE_MASTERKEY = `newMasterkeyFileWithPassphrase`), `MasterkeyService.detect` + `determineScheme`, `CryptoFsInitializer.init`, `RecoveryDirectory`.

- [ ] **Step 1: Failing core tests**

In `crates/cryptomator-core/tests/vault_lifecycle.rs`:

```rust
#[test]
fn detect_cipher_combo_recognises_both_schemes() {
    for (name, expected) in [("siv_gcm_basic", CipherCombo::SivGcm), ("siv_ctrmac_basic", CipherCombo::SivCtrMac)] {
        let (_tmp, vault) = common::copy_fixture(name);
        let opened = open_vault(&vault, &MasterkeyFileAccess::new(Vec::new()), "test-password-123").unwrap();
        let detected = cryptomator_core::recovery::restore::detect_cipher_combo(&opened.masterkey, &vault);
        assert_eq!(detected, Some(expected), "{name}");
    }
}

#[test]
fn restoring_the_config_reproduces_an_equivalent_vault_config() {
    let (_tmp, vault) = common::copy_fixture("siv_gcm_basic");
    let before = cryptomator_core::read_vault_config(&vault).unwrap();
    let before_id = before.header_value("kid").unwrap().clone();
    std::fs::remove_file(vault.join("vault.cryptomator")).unwrap();
    for entry in std::fs::read_dir(&vault).unwrap().flatten() {
        if entry.file_name().to_string_lossy().starts_with("vault.cryptomator.") {
            std::fs::remove_file(entry.path()).unwrap();
        }
    }
    let config = cryptomator_core::recovery::restore::restore_config(
        &MasterkeyFileAccess::new(Vec::new()), &vault, "test-password-123", None, 220, &mut OsRng,
    ).unwrap();
    assert_eq!(config.cipher_combo, CipherCombo::SivGcm);
    assert_eq!(config.shortening_threshold, 220);
    // The vault can be opened and read again -- the jti is new, everything else the same.
    let opened = open_vault(&vault, &MasterkeyFileAccess::new(Vec::new()), "test-password-123").unwrap();
    assert_eq!(cryptomator_core::read_vault_config(&vault).unwrap().header_value("kid").unwrap(), &before_id);
    let fs = cryptomator_core::fs::CryptoFs::open(opened, Default::default()).unwrap();
    assert!(fs.metadata(&cryptomator_core::fs::CleartextPath::parse("/hello.txt").unwrap()).is_ok());
}

#[test]
fn restoring_the_masterkey_from_a_recovery_key_sets_a_new_password() {
    let (_tmp, vault) = common::copy_fixture("siv_gcm_basic");
    let opened = open_vault(&vault, &MasterkeyFileAccess::new(Vec::new()), "test-password-123").unwrap();
    let encoder = WordEncoder::new();
    let recovery_key = cryptomator_core::recovery::create_recovery_key(&encoder, opened.masterkey.raw());
    std::fs::remove_file(vault.join("masterkey.cryptomator")).unwrap();

    cryptomator_core::recovery::restore::restore_masterkey(
        &encoder, &MasterkeyFileAccess::new(Vec::new()), &vault, &recovery_key, "brand-new-pass", &mut OsRng,
    ).unwrap();

    let reopened = open_vault(&vault, &MasterkeyFileAccess::new(Vec::new()), "brand-new-pass").unwrap();
    assert_eq!(reopened.masterkey.raw(), opened.masterkey.raw());
}

#[test]
fn restoring_everything_rebuilds_both_files() {
    let (_tmp, vault) = common::copy_fixture("siv_ctrmac_basic");
    let opened = open_vault(&vault, &MasterkeyFileAccess::new(Vec::new()), "test-password-123").unwrap();
    let encoder = WordEncoder::new();
    let recovery_key = cryptomator_core::recovery::create_recovery_key(&encoder, opened.masterkey.raw());
    drop(opened);
    for name in ["masterkey.cryptomator", "vault.cryptomator"] {
        std::fs::remove_file(vault.join(name)).unwrap();
    }
    for entry in std::fs::read_dir(&vault).unwrap().flatten() {
        if entry.file_name().to_string_lossy().ends_with(".bkup") { std::fs::remove_file(entry.path()).unwrap(); }
    }

    let config = cryptomator_core::recovery::restore::restore_all(
        &encoder, &MasterkeyFileAccess::new(Vec::new()), &vault, &recovery_key, "brand-new-pass",
        None, 220, &mut OsRng,
    ).unwrap();
    assert_eq!(config.cipher_combo, CipherCombo::SivCtrMac, "the combo was detected, not guessed");
    let reopened = open_vault(&vault, &MasterkeyFileAccess::new(Vec::new()), "brand-new-pass").unwrap();
    let fs = cryptomator_core::fs::CryptoFs::open(reopened, Default::default()).unwrap();
    assert!(fs.metadata(&cryptomator_core::fs::CleartextPath::parse("/hello.txt").unwrap()).is_ok());
}

#[test]
fn an_empty_vault_cannot_have_its_combo_detected() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v");
    std::fs::create_dir_all(vault.join("d")).unwrap();
    let key = Masterkey::generate(&mut OsRng);
    assert_eq!(cryptomator_core::recovery::restore::detect_cipher_combo(&key, &vault), None);
    // restore_all reports this as its own error instead of silently guessing SIV_GCM.
    let encoder = WordEncoder::new();
    let recovery_key = cryptomator_core::recovery::create_recovery_key(&encoder, key.raw());
    let err = cryptomator_core::recovery::restore::restore_all(
        &encoder, &MasterkeyFileAccess::new(Vec::new()), &vault, &recovery_key, "pw", None, 220, &mut OsRng,
    ).unwrap_err();
    assert!(err.to_string().contains("cipher combo"), "{err}");
    assert!(!vault.join("vault.cryptomator").exists(), "nothing was written");
}

#[test]
fn a_failed_restore_leaves_the_vault_untouched() {
    let (_tmp, vault) = common::copy_fixture("siv_gcm_basic");
    let before = std::fs::read(vault.join("vault.cryptomator")).unwrap();
    // A recovery key with a wrong checksum never gets as far as writing.
    let err = cryptomator_core::recovery::restore::restore_all(
        &WordEncoder::new(), &MasterkeyFileAccess::new(Vec::new()), &vault,
        "not even words", "pw", None, 220, &mut OsRng,
    ).unwrap_err();
    assert!(matches!(err, cryptomator_core::CoreError::InvalidRecoveryKey(_)), "{err}");
    assert_eq!(std::fs::read(vault.join("vault.cryptomator")).unwrap(), before);
}
```

- [ ] **Step 2: Run – must fail**

Run: `cargo test -p cryptomator-core --test vault_lifecycle --locked restore`
Expected: FAIL, module `restore` is missing.

- [ ] **Step 3: `RecoveryDirectory` and `detect_cipher_combo`**

```rust
impl RecoveryDirectory {
    pub fn create(vault_path: &Path) -> std::io::Result<Self> {
        Ok(Self { vault_path: vault_path.to_path_buf(), temp: tempfile::Builder::new()
            .prefix("cryptomator").tempdir()? })
    }
    pub fn path(&self) -> &Path { self.temp.path() }
    pub fn move_recovered_file(&self, file_name: &str) -> std::io::Result<()> {
        let (from, to) = (self.temp.path().join(file_name), self.vault_path.join(file_name));
        // Java's Files.move(REPLACE_EXISTING). The temp directory lives in $TMPDIR and therefore
        // often on a different file system than the vault -- rename then fails.
        match std::fs::rename(&from, &to) {
            Ok(()) => Ok(()),
            Err(_) => { std::fs::copy(&from, &to)?; std::fs::remove_file(&from) }
        }
    }
}
```
`TempDir` deletes itself on drop – that is Java's `close()`/`deleteRecoveryDirectory`.

```rust
pub fn detect_cipher_combo(masterkey: &Masterkey, vault_path: &Path) -> Option<CipherCombo> {
    let candidate = first_encrypted_file(&vault_path.join(DATA_DIR_NAME))?;
    // Order as in Java's `CryptorProvider.Scheme.values()`.
    for combo in [CipherCombo::SivCtrMac, CipherCombo::SivGcm] {
        let cryptor = Cryptor::new(combo, masterkey);
        let size = cryptor.file_header_cryptor().header_size();
        let Ok(mut file) = std::fs::File::open(&candidate) else { continue };
        let mut buf = vec![0u8; size];
        if std::io::Read::read_exact(&mut file, &mut buf).is_err() { continue }
        if cryptor.file_header_cryptor().decrypt_header(&buf).is_ok() { return Some(combo); }
    }
    None
}
```
`first_encrypted_file` walks recursively over `d/` (sorted, so that the result is reproducible) and takes the first **regular file** whose name ends in `.c9r` and is **not** `dir.c9r`. Java's filter is word for word the same (`p.toString().endsWith(".c9r")`, `!p.endsWith("dir.c9r")`, `Files::isRegularFile`) and does **not** exclude `dirid.c9r`, `symlink.c9r` and `contents.c9r` – those are perfectly ordinary encrypted files with a header, so detection works on them just as well. Adopt verbatim.

- [ ] **Step 4: The three restore functions**

```rust
pub fn restore_masterkey(encoder, access, vault_path, recovery_key, new_passphrase, rng) -> Result<()> {
    let raw = decode_recovery_key(encoder, recovery_key)?;       // check first, then write
    let masterkey = Masterkey::from_raw(*raw);
    let target = vault_path.join(MASTERKEY_FILENAME);
    if target.exists() { crate::backup::attempt_backup(&target)?; }
    let dir = RecoveryDirectory::create(vault_path)?;
    access.persist(&masterkey, &dir.path().join(MASTERKEY_FILENAME), new_passphrase,
                   DEFAULT_MASTERKEY_FILE_VERSION, rng)?;
    dir.move_recovered_file(MASTERKEY_FILENAME)?;
    Ok(())
}
```
Unlike `recovery::key::reset_password` (M2), this does **not** read the `vault.cryptomator` to learn the file name: in a restore it may be missing. The name is `masterkey.cryptomator` — the same one Java hardwires in `RecoveryKeyFactory.newMasterkeyFileWithPassphrase`. Record as a comment so that the two functions are not merged later.

```rust
pub fn restore_config(access, vault_path, passphrase, cipher_combo, shortening_threshold, rng)
    -> Result<VaultConfig>
{
    let masterkey = access.load(&vault_path.join(MASTERKEY_FILENAME), passphrase)?;
    let combo = match cipher_combo {
        Some(c) => c,
        None => detect_cipher_combo(&masterkey, vault_path)
            .ok_or_else(|| CoreError::CipherComboUndetectable(vault_path.to_path_buf()))?,
    };
    write_config_via_recovery_dir(vault_path, &masterkey, combo, shortening_threshold, rng)
}

fn write_config_via_recovery_dir(vault_path, masterkey, combo, threshold, rng) -> Result<VaultConfig> {
    let dir = RecoveryDirectory::create(vault_path)?;
    // `initialize` creates the config, the root directory and its dirid.c9r -- Java's
    // CryptoFsInitializer.init. Only the config is taken over; the root directory in the
    // temp directory is waste, the real one is already in the vault.
    let config = crate::vault::init::initialize(
        dir.path(), masterkey, combo, threshold, DEFAULT_KEY_ID, rng)?;
    let target = vault_path.join(VAULTCONFIG_FILENAME);
    if target.exists() { crate::backup::attempt_backup(&target)?; }
    dir.move_recovered_file(VAULTCONFIG_FILENAME)?;
    Ok(config)
}

pub fn restore_all(encoder, access, vault_path, recovery_key, new_passphrase, cipher_combo,
                   shortening_threshold, rng) -> Result<VaultConfig>
{
    let raw = decode_recovery_key(encoder, recovery_key)?;
    let masterkey = Masterkey::from_raw(*raw);
    // Detection needs the key but not yet a written file -- hence here,
    // before anything touches the vault (test `an_empty_vault_cannot_have_its_combo_detected`).
    let combo = match cipher_combo {
        Some(c) => c,
        None => detect_cipher_combo(&masterkey, vault_path)
            .ok_or_else(|| CoreError::CipherComboUndetectable(vault_path.to_path_buf()))?,
    };
    let dir = RecoveryDirectory::create(vault_path)?;
    access.persist(&masterkey, &dir.path().join(MASTERKEY_FILENAME), new_passphrase,
                   DEFAULT_MASTERKEY_FILE_VERSION, rng)?;
    let config = crate::vault::init::initialize(
        dir.path(), &masterkey, combo, shortening_threshold, DEFAULT_KEY_ID, rng)?;
    for name in [MASTERKEY_FILENAME, VAULTCONFIG_FILENAME] {
        let target = vault_path.join(name);
        if target.exists() { crate::backup::attempt_backup(&target)?; }
        dir.move_recovered_file(name)?;
    }
    Ok(config)
}
```
`initialize` requires a directory and creates `d/<roothash>/dirid.c9r`; the temp directory satisfies both. Both files are moved only **after** they have been written completely – that is the point of the `RecoveryDirectory`, and the test `a_failed_restore_leaves_the_vault_untouched` checks exactly that.

- [ ] **Step 5: The command**

`cli.rs`: `RecoveryKeyCommand::Restore(RestoreArgs)`.
`main.rs`: `RecoveryKeyCommand::Restore(args) => commands::recovery::restore(&ctx, args),`.

`commands/recovery.rs`:
```rust
pub fn restore(ctx: &Ctx, args: RestoreArgs) -> Result<u8> {
    // Not `locked_vault`: a vault whose config is missing is VAULT_CONFIG_MISSING or
    // ALL_MISSING -- exactly the state this command is meant to fix.
    let (vault, path) = restorable_vault(ctx, &args.vault)?;
    let combo = match args.cipher_combo.as_str() {
        "auto" => None,
        other => Some(other.parse::<CipherCombo>()?),       // like `vault create --cipher-combo`
    };
    let mut io = SystemIo;
    if args.config {
        if args.recovery_key_stdin || args.recovery_key_file.is_some() {
            return Err(AppError::InvalidValue { key: "--config".into(),
                message: "restoring only the vault config uses the vault password, not the \
                          recovery key; drop --recovery-key-* or use --all".into() }.into());
        }
        let passphrase = read_passphrase_with_keychain(&args.password, "Password: ",
            || Ok(keychain_source(ctx.keychain()?.as_ref(), &vault)), &mut io)?;
        let config = restore::restore_config(&MasterkeyFileAccess::new(Vec::new()), &path,
            &passphrase, combo, args.shortening_threshold, &mut OsRng)?;
        emit(ctx, &path, &config, "vault.cryptomator")?;
    } else {
        if !args.recovery_key_stdin && args.recovery_key_file.is_none() {
            return Err(AppError::InvalidValue { key: "--recovery-key-stdin".into(),
                message: "a recovery key is required; pass --recovery-key-stdin or \
                          --recovery-key-file".into() }.into());
        }
        let recovery_key = read_recovery_key_from(&args, &mut io)?;   // like reset_password_cmd
        let new = read_new_passphrase(&PasswordArgs::from(&args.new_password),
            "New password: ", min_password_length(), &mut io)?;
        if args.masterkey {
            restore::restore_masterkey(&WordEncoder::new(), &MasterkeyFileAccess::new(Vec::new()),
                &path, &recovery_key, &new, &mut OsRng)?;
            emit_masterkey_only(ctx, &path)?;
        } else {
            let config = restore::restore_all(&WordEncoder::new(),
                &MasterkeyFileAccess::new(Vec::new()), &path, &recovery_key, &new,
                combo, args.shortening_threshold, &mut OsRng)?;
            emit(ctx, &path, &config, "masterkey.cryptomator and vault.cryptomator")?;
        }
    }
    Ok(exit::OK)
}
```
`read_recovery_key_from` is the existing `read_recovery_key` from `commands/recovery.rs`, whose parameter is changed from `&ResetPasswordArgs` to two `Option`s (`recovery_key_file: Option<&Path>`, `recovery_key_stdin: bool`), so that both commands share it — the body stays unchanged.

`restorable_vault` sits in `commands/mod.rs` right next to `migratable_vault` and permits `Locked`, `VaultConfigMissing` and `AllMissing`; `NeedsMigration` and `Missing` are exit 5 (for `NeedsMigration` with the pointer to `crypto migrate`).

Output (JSON): `{ "path": "…", "restored": ["masterkey.cryptomator","vault.cryptomator"], "cipherCombo": "SIV_GCM", "shorteningThreshold": 220 }`; human-readable form `restored masterkey.cryptomator and vault.cryptomator in /vaults/v (SIV_GCM, shortening threshold 220)`.

- [ ] **Step 6: CLI tests**

In `crates/crypto/tests/cli.rs` (new section at the end):

```rust
#[test]
fn recovery_key_restore_rebuilds_a_lost_vault_config() {
    let fx = Sandbox::new();
    let path = fx.add_fixture("siv_gcm_basic");
    std::fs::remove_file(path.join("vault.cryptomator")).unwrap();
    for entry in std::fs::read_dir(&path).unwrap().flatten() {
        if entry.file_name().to_string_lossy().starts_with("vault.cryptomator.") {
            std::fs::remove_file(entry.path()).unwrap();
        }
    }
    fx.crypto(&["--json", "recovery-key", "restore", "siv_gcm_basic", "--config"])
        .env("CRYPTO_PASSWORD", "test-password-123")
        .assert()
        .success()
        .stdout(predicates::str::contains("SIV_GCM"));
    fx.crypto(&["fs", "ls", "siv_gcm_basic", "/"])
        .env("CRYPTO_PASSWORD", "test-password-123")
        .assert().success().stdout(predicates::str::contains("hello.txt"));
}

#[test]
fn recovery_key_restore_all_takes_the_key_from_stdin() {
    let fx = Sandbox::new();
    let path = fx.add_fixture("siv_ctrmac_basic");
    let key = fx.crypto(&["recovery-key", "show", "siv_ctrmac_basic"])
        .env("CRYPTO_PASSWORD", "test-password-123")
        .assert().success().get_output().stdout.clone();
    let key = String::from_utf8(key).unwrap();
    for name in ["masterkey.cryptomator", "vault.cryptomator"] {
        std::fs::remove_file(path.join(name)).unwrap();
    }
    for entry in std::fs::read_dir(&path).unwrap().flatten() {
        if entry.file_name().to_string_lossy().ends_with(".bkup") {
            std::fs::remove_file(entry.path()).unwrap();
        }
    }
    fx.crypto(&["recovery-key", "restore", "siv_ctrmac_basic", "--all", "--recovery-key-stdin"])
        .write_stdin(key)
        .env("CRYPTO_NEW_PASSWORD", "brand-new-pass")     // check the name against NewPasswordArgs!
        .assert()
        .success();
    fx.crypto(&["fs", "cat", "siv_ctrmac_basic", "/hello.txt"])
        .env("CRYPTO_PASSWORD", "brand-new-pass")
        .assert().success().stdout(predicates::str::contains("Hello, Cryptomator!"));
}

#[test]
fn restore_config_with_a_recovery_key_flag_is_a_usage_error() {
    let fx = Sandbox::new();
    fx.add_fixture("siv_gcm_basic");
    fx.crypto(&["recovery-key", "restore", "siv_gcm_basic", "--config", "--recovery-key-stdin"])
        .write_stdin("x\n")
        .assert()
        .code(2)
        .stderr(predicates::str::contains("--all"));
}

#[test]
fn restore_needs_exactly_one_of_masterkey_config_all() {
    let fx = Sandbox::new();
    fx.add_fixture("siv_gcm_basic");
    fx.crypto(&["recovery-key", "restore", "siv_gcm_basic"]).assert().code(2);
    fx.crypto(&["recovery-key", "restore", "siv_gcm_basic", "--all", "--config"]).assert().code(2);
}
```

How the new password reaches a test without a terminal is decided by `NewPasswordArgs`: the implementer checks with `sed -n '50,80p' crates/cryptomator-app/src/password.rs` which flag or environment variable is provided there (it is already used in `recovery-key reset-password` in `crates/crypto/tests/cli.rs` – take the call form from there verbatim) and adapts the test accordingly instead of inventing a new one.

- [ ] **Step 7: Tests, gate, commit**

Run: `cargo test -p cryptomator-core --test vault_lifecycle --locked && cargo test -p crypto --test cli --locked restore`
Expected: all green.

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked`

```bash
git add crates/cryptomator-core/src crates/cryptomator-core/tests crates/crypto/src crates/crypto/tests/cli.rs
git commit -m "feat: recovery-key restore for masterkey, vault config or both

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 14: Addenda, documentation, CI and milestone wrap-up

**Files:**
- Modify: `crates/crypto/tests/cli_daemon.rs`, `crates/crypto/src/output.rs`, `crates/crypto/tests/java_interop.rs`, `.github/workflows/ci.yml`, `README.md`, `CHANGELOG.md`, `docs/superpowers/specs/2026-09-04-crypto-cli-design.md`

**Interfaces:**
- Consumes: everything from Tasks 1–13. New production code arises only in Step 2 (`output.rs` moves over to `health::report::civil_utc`).

- [ ] **Step 1: Addendum – the detached daemon writes its log**

`crates/crypto/tests/cli_daemon.rs` so far checks the log content only for `--foreground` (lines 273–281). The detached path is the normal case and unchecked. In `unlock_mounts_the_vault_and_lock_takes_it_down`, add after the `lock`:

```rust
    // The detached daemon writes into the same file as the foreground daemon; it stays around
    // after the lock, so that a failed mount can still be read up on.
    let log = std::fs::read_to_string(fx.state_file(".log")).expect("the detached daemon log");
    assert!(log.contains("INFO"), "the daemon installed its logger: {log:?}");
    assert!(log.contains("mounted at"), "the mount is in the log: {log:?}");
    assert!(log.contains("stopped"), "and so is the shutdown: {log:?}");
    assert!(!log.contains("test-password"), "no passphrase ever reaches the log");
```

Run: `cargo test -p crypto --test cli_daemon --locked unlock_mounts` (with `CRYPTO_ENABLE_NULL_MOUNTER=1`, which `Sandbox::crypto_daemon` sets itself).
Expected: PASS. If one of the three strings fails, the actual wording from the log is to be adopted (the messages are in `crates/cryptomator-app/src/daemon/server.rs`) – the assertion is adapted, not the daemon.

- [ ] **Step 2: Addendum – resolve the duplicated calendar algorithm**

`crates/crypto/src/output.rs::format_timestamp` and `cryptomator_core::health::report::civil_utc` (Task 7) compute the same thing. `format_timestamp` is switched over to the core helper:

```rust
/// `YYYY-MM-DD HH:MM:SS` in UTC.
pub fn format_timestamp(time: SystemTime) -> String {
    let (y, mo, d, h, m, s) = cryptomator_core::health::report::civil_utc(time);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02}:{s:02}")
}
```
The existing tests in `output.rs` stay unchanged and prove that nothing about the result changes.

- [ ] **Step 3: Addendum – re-wrap the README paragraph**

`README.md` lines 474–478 are broken mid-sentence (line 477 is 51 characters long and ends with "and the flags are mutually"). The paragraph is re-set to ~100 columns:

```markdown
`$CRYPTO_PASSWORD` deliberately outranks the implicit keychain step: it is a source a script sets on
purpose, and it can never make the operating system open a dialog. `--no-keychain` removes step 5
from the list for one run and turns step 0 into exit `8` (there is no keychain to read), whatever
`settings.json` says — and the flags are mutually exclusive, so `--password-keychain` together with
any other `--password-*` flag is a usage error.
```

- [ ] **Step 4: Java interop for the migrated legacy vaults**

`crates/crypto/tests/java_interop.rs` gets a test that closes the loop: Rust migrates, Java reads.

```rust
/// Legacy vaults that `crypto migrate` has lifted to format 8 must be openable with the real
/// cryptofs. That is the only proof that our migrators satisfy more than
/// just our own readers.
#[test]
#[ignore = "needs Java 21+ and Maven"]
fn java_reads_vaults_migrated_from_legacy_formats() {
    for name in ["legacy_v7", "legacy_v6", "legacy_v5"] {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join(name);
        copy_dir(&repo_root().join("tests/fixtures").join(name), &vault);
        let manifest: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(vault.join("fixture.json")).unwrap()).unwrap();
        let pass = manifest["passphrase"].as_str().unwrap().to_string();
        let final_pass = manifest.get("passphraseNfc").and_then(|v| v.as_str())
            .unwrap_or(&pass).to_string();

        cryptomator_core::migration::Migrators::migrate(
            &vault, &pass, true, &mut |_| {}, &mut cryptomator_core::OsRng).unwrap();

        verify_with_java(&vault, &final_pass);      // existing helper, checks exit 0 + manifest
    }
}
```
The helper `verify_with_java` already exists in this file (it calls `run_java_verify` and evaluates the exit code and the JSON output); its exact signature is to be checked with `grep -n "fn verify_with_java" -A 20 crates/crypto/tests/java_interop.rs`.

`crypto` needs `cryptomator-core` as a dev dependency for that – it already has it (the file uses `cryptomator_core::open_vault`).

- [ ] **Step 5: CI**

`.github/workflows/ci.yml`, job `interop-java`: nothing to add except a pre-build step, so that the three legacy artifacts are fetched once and the reactor compiles before the tests run:

```yaml
      - name: prime the fixture-gen reactor (downloads legacy cryptofs)
        run: mvn -q -B -f tools/fixture-gen/pom.xml compile
      - run: cargo test -p crypto --test java_interop --locked -- --ignored
```
`-B` (batch mode) suppresses the progress bars in the log. The `cache: maven` of the `setup-java` action is already set, so the artifacts are downloaded only once.

A new job is **not** necessary: the health and migration tests run along in `cargo test --workspace`, because they need no Java side.

- [ ] **Step 6: README – three new sections**

Extend the command table (around line 55):
```markdown
| `health` | Checks a vault for structural damage, optionally repairs it | `crypto health Secret --fix` |
| `migrate` | Brings a vault of format 5, 6 or 7 up to format 8 | `crypto migrate Old --yes` |
| `recovery-key restore` | Rebuilds a lost masterkey file and/or vault config | `crypto recovery-key restore V --all --recovery-key-stdin` |
```

New section `## Health checks` (after "Mount-less access", before "Password sources"):

```markdown
## Health checks

`crypto health <VAULT>` reads the ciphertext of a locked vault and reports everything that does not
fit the vault format. It is the same set of checks the desktop app runs in its "Vault Health"
window, with the same wording, so the two reports can be compared line by line.

| Check | `--check` name | What it looks at |
|---|---|---|
| Directory Check | `dirid` | every `dir.c9r`, whether its target directory exists, whether a directory id is used twice, and whether every content directory is reachable |
| Resource Type Check | `type` | whether each `.c9r`/`.c9s` directory says what it is (`dir.c9r`, `symlink.c9r`, `contents.c9r`) |
| Shortened Names Check | `shortened` | whether each `.c9s` directory has a `name.c9s` whose content hashes back to the directory's own name |

Findings have four severities: `GOOD` (nothing to say), `INFO` (worth knowing, no impact),
`WARN` (the structure is damaged, no data lost yet) and `CRITICAL` (data was lost — restore from a
backup if you can).

    crypto health Secret                       # report everything, exit 11 if anything is CRITICAL
    crypto health Secret --check dirid,type    # only two of the three checks
    crypto health Secret --fail-on WARN        # exit 11 for warnings too
    crypto health Secret --fix                 # repair what can be repaired, then check again
    crypto health Secret --no-report           # do not write the log file

`--fix` applies the repair of every finding of severity `WARN` or higher that has one
(`--fix-severity CRITICAL` narrows that to the critical ones), then runs the checks a second time
and prints both results; the exit code comes from the second run. Not every finding is fixable —
an empty `dir.c9r` or a `name.c9s` that is simply gone cannot be reconstructed from anything the
vault still contains. Orphaned directories are not deleted: their contents are adopted into a
`/LOST+FOUND` directory inside the vault, under a subdirectory named after the orphan, with the
original file names where they could still be decrypted and `file1`, `directory2`, `symlink3` …
where they could not.

Unless `--no-report` is given, a text report is written to the current directory as
`healthReport_<vault>_<YYYYMMDD-HHMMSS>.log` (the desktop app's file name, with a UTC timestamp);
`--report FILE` puts it somewhere else. The report contains ciphertext paths only — never a
cleartext file name and never the password.

The vault must be locked. `--json` prints one object with `findings` (or `before`/`after` with
`--fix`), each carrying `check`, `severity`, `message`, `paths`, `fixable` and `fixed`.
```

New section `## Migrating older vaults`:

```markdown
## Migrating older vaults

Vaults created before Cryptomator 1.6 use an older on-disk format. `crypto` reads format 8 only and
reports such a vault as `NEEDS_MIGRATION`; `crypto migrate` brings it forward, one format at a time,
until it is a format 8 vault:

| Step | What changes |
|---|---|
| 5 → 6 | the passphrase is re-encoded as Unicode NFC and the masterkey file is rewritten |
| 6 → 7 | every file in the vault is renamed from BASE32 to base64url, directories and symlinks become `.c9r` directories, long names move from `m/…lng` into `name.c9s`, and `m/` is deleted |
| 7 → 8 | `vault.cryptomator` is created (format 8, `SIV_CTRMAC`, shortening threshold 220) and the masterkey file loses its version |

    crypto migrate Old --dry-run     # list the renames, change nothing
    crypto migrate Old               # ask for confirmation, then migrate
    crypto migrate Old --yes         # no question (required when there is no terminal)

The migration happens in place. Before each step the file it is about to rewrite is backed up next
to itself as `masterkey.cryptomator.<checksum>.bkup`, exactly like the desktop app does — but the
6 → 7 step renames every file in the vault and there is no undo for that, so **make a backup of the
whole vault first**. Nothing is migrated if the password is wrong. A vault that is already at
format 8 is not an error: `crypto migrate` says so and exits `0`. A vault older than format 5 is
refused; open it once with Cryptomator 1.4 or newer first.

If the vault's password is stored in the keychain, the 5 → 6 step updates the stored entry to the
normalised form, so unlocking keeps working.
```

New section `### Restoring a lost masterkey or vault config` under "Recovery keys" (or after the `recovery-key validate` section):

```markdown
### `crypto recovery-key restore`

When `masterkey.cryptomator` or `vault.cryptomator` is gone and the `.bkup` files next to them are
gone too, they can be rebuilt:

| Flag | What it needs | What it writes |
|---|---|---|
| `--config` | the vault password (the masterkey file is still there) | `vault.cryptomator` |
| `--masterkey` | the recovery key and a new password | `masterkey.cryptomator` |
| `--all` | the recovery key and a new password | both files |

    crypto recovery-key restore Secret --config
    printf '%s' "$RECOVERY_KEY" | crypto recovery-key restore Secret --all --recovery-key-stdin

The cipher combo is detected by decrypting the header of the first encrypted file in the vault;
`--cipher-combo SIV_GCM|SIV_CTRMAC` sets it by hand, which is the only way for a vault that has no
encrypted file yet. `--shortening-threshold` (36–220, default 220) goes into the new vault config —
use the value the vault was created with, or long file names will be laid out differently from the
files already in it.

Both files are written into a temporary directory first and only moved into the vault once they are
complete, so a restore that fails leaves the vault exactly as it was. An existing file is backed up
before it is replaced.
```

Exit code table: the row for `11` replaces the sentence below it.
```markdown
| `11` | `crypto health` found at least one finding of the severity given by `--fail-on` (default `CRITICAL`) |
```
The paragraph "`11` (health findings) is reserved for M7 and is never returned today." is **deleted**. In the row for `5`, "needs migration" is extended by "(run `crypto migrate`)".

Section "Test fixtures": "eight reference vaults" → "twelve reference vaults" with a sentence about `broken_health` and `legacy_v{5,6,7}` and the four generator commands from Task 2, Step 5.

- [ ] **Step 7: CHANGELOG**

New section `### M7 – Health checks, restore and migration` after `### M6 – Keychain`, structured like the previous ones (list of deliverables, `#### Decisions taken along the way` with the eleven rulings of this plan, `#### Known limitations and follow-ups`). The limitations that demonstrably exist:

- `INFO` findings (`MissingDirIdBackup`, `LooseDirFile`) have fixes, but `--fix-severity` knows only `WARN` and `CRITICAL` — they cannot be applied with `crypto` (Ruling 3).
- The report timestamp is UTC, not the system time zone (no time zone database without a new dependency, Ruling 5).
- `crypto health` runs single-threaded; Java's `ExecutorService` streaming does not exist. For very large vaults that means: no intermediate output, no cancelling mid-run.
- The migration has not been tried on a real old vault, only on the generated fixtures; in particular the branch "storage supports fewer than 220 characters" (Java's `REQUIRES_FULL_VAULT_DIR_SCAN`) has never run under real conditions — on APFS and ext4 it does not trigger.
- `FilePathMigration::parse` looks for the canonical name pattern from position 0 instead of at every position like Java's `find()` (Task 11, Step 3).
- Everything from M4/M5/M6 that stayed open there: macFUSE unverified, `LinuxGioMounter` unverified, a keychain entry written by Cryptomator.app unchecked, the internet password before the AppleScript mount missing (→ M8).

- [ ] **Step 8: Spec**

In `docs/superpowers/specs/2026-09-04-crypto-cli-design.md`:
- Milestone table: the M7 row gets `✅` and a footnote `[^m7-scope]`.
- New footnote at the end of the footnote list, in the style of `[^m6-scope]`: what was delivered, the eleven rulings in short form, what was deliberately not implemented (the `INFO` fixes, the streaming, Java's `find()` semantics) and what stays open (M8).
- Test strategy point 1: `gen-legacy-v7/v6/v5` are there; add that 1.6.2 writes format **6** and that the v5 vault comes about by stamping the masterkey file over, and that the legacy artifacts are **not** in `~/.m2` (make finding 8 more precise: "available on Maven Central, not present locally – the first generator run needs network").
- Finding 9 ("Local environment"): unchanged.
- Risk 8 ("migration 6→7 is the single biggest item"): mark as done, with one sentence about the outcome.

- [ ] **Step 9: Manual acceptance run**

Against a real copy, not against a fixture, so that the commands run once the way they do for the user:

```bash
cd $(mktemp -d)
cp -R /Users/rfoerthe/work/cryptomator-cli/tests/fixtures/legacy_v6 ./v6
CRYPTO_SETTINGS_PATH=$PWD/settings.json cargo run -q -p crypto -- vault add ./v6 --name Alt
CRYPTO_SETTINGS_PATH=$PWD/settings.json CRYPTO_PASSWORD=test-password-123 \
    cargo run -q -p crypto -- migrate Alt --dry-run
CRYPTO_SETTINGS_PATH=$PWD/settings.json CRYPTO_PASSWORD=test-password-123 \
    cargo run -q -p crypto -- migrate Alt --yes
CRYPTO_SETTINGS_PATH=$PWD/settings.json CRYPTO_PASSWORD=test-password-123 \
    cargo run -q -p crypto -- health Alt
ls healthReport_Alt_*.log && head -8 healthReport_Alt_*.log
```
Expected: `--dry-run` lists renames and changes nothing, `migrate --yes` reports `6->7, 7->8`, `health` ends with 0 and writes a report whose head has the three asterisk lines. **Record in the report** what was actually printed – that is the only proof that the three commands work together.

- [ ] **Step 10: Gate and commit**

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked`
Run: `cargo test -p crypto --test java_interop --locked -- --ignored` (needs Java and Maven)
Expected: both green; the Java runs prove that cryptofs 2.10.0 opens all three migrated vaults.

```bash
git add README.md CHANGELOG.md docs .github crates
git commit -m "docs: health, migrate and restore; close milestone M7

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

## Self-check

**1. Spec coverage for M7.** Every commitment the spec makes for this milestone has a task:

| Spec location | Task |
|---|---|
| `health/mod.rs`: Trait `HealthCheck`, `DiagnosticResult{severity, details, fix}` | 3 |
| `health/dir_id.rs`: DirIdCheck, **8 result types**, fixes | 4 (7 types + 3 fixes), 5 (the 8th fix) |
| `health/dir_id.rs`: "fixes incl. LOST+FOUND adoption" | 5 |
| `health/file_type.rs`: CiphertextFileTypeCheck | 6 |
| `health/shortened.rs`: ShortenedNamesCheck, **6 types**, fixes | 6 |
| `health/report.rs`: "report format like `ReportWriter`" | 7 |
| Grammar `crypto health <VAULT> [--check …] [--report FILE\|--no-report] [--fail-on …]` | 8 |
| Grammar `crypto health … [--fix] [--fix-severity WARN\|CRITICAL]` | 9 |
| Exit code **11** "health findings ≥ `--fail-on`" | 8 (constant + trigger), 14 (README) |
| `migration/mod.rs`: version detection, `needs_migration`, `migrate(path, passphrase, progress)` | 10 |
| `migration/v6.rs`: "5→6 (NFC passphrase, `unicode-normalization`)" | 10 |
| `migration/v7.rs`: "capability check, PreMigrationVisitor, `FilePathMigration` base32→base64url, `0`/`1S` prefixes, `.lng` from `m/xx/yy/`, up to 3 `_n` attempts, delete `m/`" | 11 |
| `migration/v8.rs`: "JWT with `SIV_CTRMAC`, threshold 220, version 999" | 10 |
| Grammar `crypto migrate <VAULT> [--yes]` + Ruling `--dry-run` | 12 |
| Exit code **5** "needs migration" | 12 (Step 5: hint text on `locked_vault`) |
| `recovery/restore.rs`: "`detect_scheme` (first regular `.c9r`, try both header variants), restore masterkey/config/all via a temp `RecoveryDirectory`" | 13 |
| Grammar `crypto recovery-key restore <VAULT> (--masterkey\|--config\|--all) [--cipher-combo …] [--shortening-threshold N]` | 13 |
| Test strategy 1: `gen-legacy-v7/v6/v5` (cryptofs 1.9.15/1.8.9/1.6.2), "`.lng` names and an NFD umlaut passphrase", "< 200 KB each" | 2 |
| Test strategy 1: `verify` harness on migrated vaults | 14 (Step 4) |
| Test strategy 2: `migration.rs` | 10, 11 |
| M7 row "damaged fixtures (harness-generated: orphan dir, missing dirid, trailing bytes …)" | 1 |
| M7 row "migrate legacy fixtures and verify them in Java" | 11 (Rust side), 14 (Java side) |
| Finding 8 "legacy cryptofs on Maven Central" | 2 (verified: 1.9.15/1.8.9/1.6.2 answer with HTTP 200, but are **not** in `~/.m2`) |
| Verification "`crypto health` against intentionally damaged fixtures incl. `--fix`; `crypto migrate` against legacy fixtures" | 9, 12, 14 (Step 9) |
| Footnote `[^m6-scope]`: "M7 … and M8 stay open" | 14 (footnote `[^m7-scope]`) |
| Carry-over: check the detached daemon's log | 14 (Step 1) |
| Carry-over: re-wrap README line ~475 | 14 (Step 3) |

Not in M7 (the spec assigns them elsewhere): packaging, man pages, completions, `xtask`, the full CI matrix and the internet password before the AppleScript mount → **M8**. Windows is not in scope.

**Two spec formulations this plan deliberately reads differently.** First, the module table names a `detect_scheme` for `recovery/restore.rs`; the function is called `detect_cipher_combo` here, because the Rust type is called `CipherCombo` and `Scheme` occurs nowhere in the workspace. Second, the module table says `DiagnosticResult{severity, details, fix}` for `health/mod.rs`; the controller specification for this milestone reads `{severity, check, message, paths, fix}`, and that is the one that applies — Java's `details()` map has been absorbed into `paths` and `message`, because its values are exclusively paths, sizes and types, which both fields already carry.

**2. Placeholder scan.** No "TBD", no "implement later", no "see Task N" without repeating the content. Four places deliberately contain no finished body, and each says exactly what stands there and who replaces it:

- Task 3, Step 3: `struct Placeholder` in `all_checks()` — Task 4 replaces the first line, Task 6 the other two, and deletes the type.
- Task 8, Step 5: the `--fix` rejection block with the marker `not implemented yet`, which Task 9, Step 3 finds and replaces via `grep`.
- Task 10, Step 6: the `SixToSeven` branch, which returns `MigrationBlocked` until Task 11.
- Task 2, Step 3: the Java attempt at computing the `versionMac`, deliberately written out as a dead end — it is there so that nobody walks it a second time; the viable route is Step 4.

Plus six places where the implementer **looks it up instead of guessing**, each with the check command:
- Task 5, Step 1 and Task 11, Step 6: the M3 names `CryptoFs::open`, `CryptoFsOptions`, `CleartextPath::parse`, `CryptoFs::metadata`, `DirEntry::name` — `grep -n "CryptoFs::\|CleartextPath::" crates/cryptomator-core/tests/crypto_fs_fixtures.rs`.
- Task 6, Step 3: the declaration order of `CiphertextFileType` — `grep -n "enum CiphertextFileType" -A 6 crates/cryptomator-core/src/fs/ciphertext_path.rs`.
- Task 8, Step 1: whether `Sandbox::add_fixture` returns the vault path — `sed -n '160,190p' crates/crypto/tests/common/mod.rs`. **Also to be checked:** whether `add_fixture` registers a legacy vault without a `vault.cryptomator` at all (`vault add` goes through `assert_is_vault_directory`, which accepts `DirStructure::MaybeLegacy` — so it should work). If it does not, the tests in Task 12 register the vault with `crypto vault add <path>` instead and resolve it via the path.
- Task 10, Step 5: the variant name `CipherCombo::SivCtrMac` — `grep -n "enum CipherCombo" -A 6 crates/cryptomator-core/src/crypto/cryptor.rs`.
- Task 12, Step 1: the field names of `Sandbox::fake_keychain_json` — `sed -n '150,170p' crates/crypto/tests/common/mod.rs`.
- Task 13, Step 6: how a *new* password gets into a CLI test without a terminal — take the call form from the existing `recovery-key reset-password` test in `crates/crypto/tests/cli.rs` verbatim.

And two numeric constants in tests that are to be recomputed before committing, each with the command next to it: the timestamp in Task 7, Step 1 (`date -u -r 1788534245 +%Y%m%d-%H%M%S`) and the BASE32/BASE64 conversion in Task 11, Step 1 (`python3 -c "import base64;…"`).

**3. Type consistency across the tasks.**

- `Severity`, `DiagnosticResult`, `Fix`, `HealthCheck`, `CheckContext`, `run_checks`, `checks_by_ids`, `all_checks`, `CHECK_IDS` (3) → 4, 5, 6, 7, 8, 9, 11 (the health run at the end of the migration chain).
- `CheckContext::{vault_path, cryptor, config, data_dir, resolve, relativize, rng}` (3) → every check and every fix in 4, 5, 6. `config.shortening_threshold` (a field of `VaultConfig`, exists) is the only configuration value a fix needs (Task 5).
- `DIR_ID_CHECK_ID = "dirid"`, `TYPE_CHECK_ID = "type"`, `SHORTENED_CHECK_ID = "shortened"` (4, 6) are identical with the entries in `CHECK_IDS` (3) and with what `--check` accepts (8) and what appears in the JSON under `check` (8).
- `DIR_ID_CHECK_NAME = "Directory Check"`, `TYPE_CHECK_NAME = "Resource Type Check"`, `SHORTENED_CHECK_NAME = "Shortened Names Check"` (4, 6) are the `name()` values that the report inserts into `Check %s` (7, 8).
- `AdoptOrphan { content_dir }` (5) is created exclusively in `dir_id.rs` (5, Step 6) and nowhere else.
- `render_report`, `report_file_name`, `write_report`, `civil_utc` (7) → 8 (write the report), 9 (report from the second run), 14 (`output::format_timestamp` moves over to `civil_utc`).
- `exit::HEALTH_FINDINGS` (8) → 9 (the same return value), 14 (README table).
- `MigrationStep`, `MigrationPlan`, `PlannedRename`, `Migrators::{plan, migrate, needs_migration}`, `assert_all_capabilities` (10) → 11 (`plan_renames` fills `MigrationPlan::renames`), 12 (command), 14 (Java interop).
- `migration::v6::migrate(vault, passphrase, rng)`, `v8::migrate(vault, passphrase, rng)` (10) and `v7::migrate(vault, passphrase, full_scan_allowed, rng)` (11) — **v7 has one parameter more**, because only there can a query become necessary; `Migrators::migrate` passes `full_scan_allowed` straight through to it and ignores it for the other two.
- `FilePathMigration::{parse, migrate, target_path, new_inflated_name, new_deflated_name}` and `plan_renames` (11) → 12 (`--dry-run` reads `MigrationPlan::renames`).
- `migratable_vault` (12) and `restorable_vault` (13) both sit in `commands/mod.rs` next to `locked_vault`; all three return `(VaultSettingsJson, PathBuf)` and call `require_locked`. They differ **only** in the set of permitted `VaultState` values: `Locked` / `Locked|NeedsMigration` / `Locked|VaultConfigMissing|AllMissing`.
- `RecoveryDirectory::{create, path, move_recovered_file}`, `detect_cipher_combo`, `restore_masterkey`, `restore_config`, `restore_all` (13) → only the command in 13 and the tests there.
- `CoreError::{MissingCapability, FileNameTooLong, MigrationBlocked}` (10) and `CoreError::CipherComboUndetectable` (13) must **both** be sorted into `exit.rs::core_code`; `core_code` is deliberately written without a `_` arm, so the compiler enforces it. Assignment: `MissingCapability` and `FileNameTooLong` → `GENERAL` (1), `MigrationBlocked` and `CipherComboUndetectable` → `WRONG_STATE` (5).

Names that were called differently in two tasks and are resolved here: `detect_scheme` (spec) vs. `detect_cipher_combo` (binding, Task 13); `deflate` in `fs/long_names.rs` (takes a path) vs. `deflate_name` in the shortened check (takes a `&str`) — Task 6 pulls the shared arithmetic out into `fs::long_names::deflate_str` and points both at it instead of writing it twice.

**4. Exit code assignment.**

| Situation | Route | Code |
|---|---|---|
| health finding ≥ `--fail-on` | return value of `commands::health::run` | **11** |
| `--check bogus`, `--fail-on INFO`, `--fix-severity GOOD` | `CoreError::InvalidArgument` | 2 |
| `crypto migrate` without `--yes` and without a terminal | `AppError::InvalidValue { key: "--yes" }` | 2 |
| `crypto recovery-key restore --config --recovery-key-stdin` | `AppError::InvalidValue` | 2 |
| none or several of `--masterkey`/`--config`/`--all` | clap `ArgGroup` | 2 |
| wrong password for `health`, `migrate`, `restore --config` | `CoreError::InvalidPassphrase` | 4 |
| recovery key with a wrong checksum | `CoreError::InvalidRecoveryKey` | 4 |
| `health`/`migrate`/`restore` on a vault that a daemon is serving | `AppError::WrongState` via `require_locked` | 5 |
| `health` on a vault in state `NEEDS_MIGRATION` | `AppError::WrongState` with the pointer to `crypto migrate` | 5 |
| vault format < 5 | `CoreError::MigrationBlocked` | 5 |
| `vault.cryptomator` already exists at the 7→8 step | `CoreError::MigrationBlocked` | 5 |
| cipher combo not detectable and not given | `CoreError::CipherComboUndetectable` | 5 |
| storage cannot do 220-character names and `--yes` is missing | `CoreError::MigrationBlocked` | 5 |
| name too long for the storage after the migration | `CoreError::FileNameTooLong` | 1 |
| storage not readable or writable | `CoreError::MissingCapability` | 1 |
| hub vault with `health`/`migrate`/`restore` | `CoreError::HubVaultUnsupported` | 9 |
| `crypto migrate` on a format 8 vault | no error | **0** |
| `crypto migrate` aborted at the confirmation prompt | no error | **0** |
| `--fix` could not apply a fix | warning on stderr, `fixed: false` in the JSON | code of the second run |
| keychain refuses the update after `5→6` | warning on stderr | 0 |

The last two rows follow Ruling 5 from M6: what happens **after** the actual work becomes a warning, not an exit code — the vault is migrated, and an exit ≠ 0 would tempt a script into a wrong rollback.

## Execution

`superpowers:subagent-driven-development` with Opus 5 subagents, a fresh subagent per task, review between the tasks; order **1 → 14**.

**Dependencies.** Task 1 delivers the fixture without which Tasks 4, 6, 8 and 9 have nothing to check. Task 2 delivers the legacy fixtures for 10, 11, 12 and 14. Task 3 is the foundation for 4–9. Task 5 needs 4 (the fix is attached there), Task 6 needs 3 (it removes the last placeholders), Task 7 is independent of 4–6 and could run in parallel, Task 8 needs 3, 6 and 7, Task 9 needs 8. Task 10 needs only 2, Task 11 needs 10, Task 12 needs 11. Task 13 needs nothing from 3–12 and is the only real opportunity for parallelism: **Task 13 may run at any time after Task 2.** Task 14 builds on everything.

**Two tasks need network.** Task 2 downloads cryptofs 1.9.15, 1.8.9 and 1.6.2 from Maven Central into `~/.m2` (checked: all three answer with HTTP 200, none is present locally). Task 14, Step 10 needs the same artifacts plus cryptofs 2.10.0 (that one is local). Without network both are to be deferred; they are **not** to be replaced by other versions and **not** to be skipped — without legacy fixtures the migrators are unproven.

**Three tasks touch `tests/fixtures/`, and only these three:** Task 1 (`broken_health`), Task 2 (`legacy_v7`, `legacy_v6`, `legacy_v5` plus the `#[ignore]` stamping step) and — read-only — all the others. A subagent that writes a file under `tests/fixtures/` in any other task has made a mistake; the review between the tasks checks that with `git status --porcelain tests/fixtures/`.

**What must be in each task's report.** Besides the usual gate:
- Tasks 1 and 2: the `du -sh` output of the new fixtures (limit 200 KB per vault) and the `git status --porcelain tests/fixtures/` excerpt.
- Task 2: whether Maven could download the three legacy artifacts, and the evidence from Step 6 that `legacy_v6`/`legacy_v5` have BASE32 names and an `m/`.
- Task 5: the output of `crypto fs ls <vault> /LOST+FOUND`, or of the test output, showing which name the adopted file got.
- Task 9: the `--fix` run in plain text (before/after), so that the summary lines have been read by a human once.
- Task 11: the runtime of `the_whole_chain_from_five_to_eight_produces_a_readable_vault`.
- Task 14: the output of the manual acceptance run from Step 9 and the result of `cargo test -p crypto --test java_interop -- --ignored`.

**What must not happen.** No task sets `CRYPTO_E2E_KEYCHAIN=1`, calls `security` or mounts anything — M7 touches neither keychain dialogs nor FUSE. The only keychain contact is the fake in Task 12. No task changes `~/.m2` by hand or writes into the desktop checkout.
