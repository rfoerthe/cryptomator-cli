# M7: Health-Checks, `recovery-key restore` und die Migratoren v5→v6→v7→v8 – Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `crypto` findet, meldet und repariert die Schäden, die die Desktop-App im „Vault Health"-Fenster zeigt (`crypto health <VAULT> [--check …] [--fix] [--fix-severity …] [--report FILE|--no-report] [--fail-on …]`, Exit **11**), stellt eine verlorene `masterkey.cryptomator` und/oder `vault.cryptomator` aus einem Recovery-Key wieder her (`crypto recovery-key restore <VAULT> (--masterkey|--config|--all)`) und hebt Legacy-Vaults der Formate 5, 6 und 7 in einem Zug auf Format 8 (`crypto migrate <VAULT> [--yes] [--dry-run]`). Dazu kommen die Fixtures, die das prüfbar machen: ein absichtlich beschädigter Vault und je ein Legacy-Vault pro Altformat, beide vom Java-Harness erzeugt.

**Architecture:** Drei neue Modulbäume in `cryptomator-core`, dazu drei Kommandos im Binary. (1) `health/` – `mod.rs` trägt das Trait `HealthCheck`, den Ergebnistyp `DiagnosticResult` mit `Severity`, das Trait `Fix` und den `CheckContext` (Vault-Pfad, `Cryptor`, `VaultConfig`, RNG); `dir_id.rs`, `file_type.rs` und `shortened.rs` sind die drei Java-Checks eins zu eins, inklusive aller 8 + 3 + 6 Ergebnistypen und ihrer `fix()`-Implementierungen; `report.rs` schreibt den Textreport im Format von `ui/health/ReportWriter.java`. (2) `migration/` – `mod.rs` ist Javas `Migrators` (Version erkennen, Schritt für Schritt bis 8, Backups, Capability-Check), `v6.rs`/`v7.rs`/`v8.rs` sind die drei Migratoren, wobei `v7.rs` mit `FilePathMigration` (BASE32→BASE64URL, `0`/`1S`-Präfixe, `.lng`-Inflation aus `m/`, drei `_n`-Versuche) der größte Einzelposten ist. (3) `recovery/restore.rs` – `RecoveryDirectory` (Temp-Verzeichnis, in das erst geschrieben und aus dem dann verschoben wird), `restore_masterkey`, `restore_config`, `restore_all` und `detect_cipher_combo`. Im Binary sitzt jeweils eine dünne Kommandoschicht darüber, die Passwortquellen, Exit-Codes, `--json` und den Report-Pfad regelt. Die Fixtures entstehen im vorhandenen Maven-Harness `tools/fixture-gen/`, das dafür zu einem Reaktor mit drei zusätzlichen Modulen wird (cryptofs 1.9.15 / 1.8.9 / 1.6.2).

**Tech Stack:** Rust stable ≥ 1.89, keine neuen Crate-Abhängigkeiten – alles Nötige liegt schon im Workspace (`data-encoding` für BASE32/BASE64URL, `sha1`, `crc32fast`, `uuid`, `unicode-normalization` für die NFC-Normalisierung in v6, `zeroize`, `serde_json`, `clap` 4.6, `tempfile`, `assert_cmd` 2, `proptest` 1). Java-Seite: Maven-Reaktor, JDK ≥ 21, cryptofs 2.10.0 (aktuell) sowie 1.9.15 / 1.8.9 / 1.6.2 (Legacy, **von Maven Central, nicht im lokalen `~/.m2`** – der erste Lauf der Fixture-Tasks braucht Netz).

**Spec:** `docs/superpowers/specs/2026-09-04-crypto-cli-design.md` (Modultabelle `health/{mod,dir_id,file_type,shortened,report}.rs`, `migration/{mod,v6,v7,v8}.rs`, `recovery/restore.rs`; Kommandogrammatik `crypto health`, `crypto migrate`, `crypto recovery-key restore`; Exit-Codes **11** und **5**; Meilenstein **M7**; Teststrategie Punkt 1 (`gen-legacy-v7/v6/v5`, `verify`) und Punkt 2 (`migration.rs`); Befund 8 (Legacy-cryptofs auf Maven Central); Risiko 8 (Migration 6→7 ist der größte Einzelposten); Fußnoten `[^m4-scope]`, `[^m5-scope]`, `[^m6-scope]`).

## Global Constraints

- Arbeitsverzeichnis `/Users/rfoerthe/work/cryptomator-cli`, Branch `feature/m7-health-restore-migration` (von `main@be22e3c`). Niemals `.superpowers/` oder `.idea/` committen.
- Lizenz AGPL-3.0-only. `#![forbid(unsafe_code)]` gilt weiter in `cryptomator-core` **und** `cryptomator-app`; die neuen Module brauchen kein `unsafe`. Kein `unwrap()`/`expect()` auf Eingabedaten in Library-/Binary-Code (Tests dürfen). **MSRV 1.89** (`rust-version` im Workspace). **Keine neue Crate-Abhängigkeit** – wer eine braucht, hat den falschen Weg gewählt und soll im Report begründen, warum.
- `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo test --workspace --locked` vor **jedem** Commit sauber; Commit-Nachricht endet mit `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.
- `~/.m2` und der Desktop-Checkout (`/Users/rfoerthe/work/pro/cryptomator/…`) werden **nur gelesen** (`unzip -p`, `cat`) und nie verändert. Maven lädt die Legacy-Artefakte beim ersten Lauf nach `~/.m2` – das ist der einzige erlaubte Schreibzugriff dorthin und passiert durch Maven selbst, nicht durch Handarbeit.
- **`tests/fixtures/` ist für Implementierende read-only – mit genau zwei Ausnahmen: Task 1 und Task 2.** Diese beiden Tasks legen über den Generator neue Fixture-Verzeichnisse an (`broken_health/`, `legacy_v7/`, `legacy_v6/`, `legacy_v5/`). Kein anderer Task darf eine Datei unter `tests/fixtures/` anlegen, ändern oder löschen, und **niemand** editiert Fixture-Dateien von Hand: was der Generator nicht erzeugt, gehört nicht dorthin.
- **Jeder Test, der schreibt, arbeitet auf einer Kopie in einem Tempdir.** Health-Fixes, Migratoren und Restore verändern Vaults; kein Test darf ein eingechecktes Fixture anfassen. Der vorhandene Helfer `crates/crypto/tests/common/mod.rs::copy_recursively` bzw. ein gleichnamiger Helfer in `crates/cryptomator-core/tests/common/mod.rs` kopiert nach `tempfile::tempdir()`. Ein Test, der `tests/fixtures/**` direkt öffnet, darf das nur lesend tun.
- Passwörter und Recovery-Keys erscheinen nie in argv, Logs, Fehlermeldungen, Reports oder JSON. Jede Passphrase und jeder Recovery-Key wandert als `Zeroizing<String>` durch den Code. **Der Health-Report enthält keine Klartextnamen** – nur Ciphertext-Pfade, so wie Javas `ReportWriter` auch (die `details()`-Werte sind ausschließlich Pfade, Größen und Typen).
- Nie echte Keychain-E2E laufen lassen: kein `CRYPTO_E2E_KEYCHAIN=1`, kein `security`-Kommando unbeaufsichtigt. Alle Tests dieses Meilensteins, die eine Keychain berühren (nur Task 12 tut das, für das Nachziehen des Eintrags nach der NFC-Normalisierung), benutzen den Fake aus `CRYPTO_KEYCHAIN_FAKE` über `Sandbox::crypto_keychain`.
- Nie einen Mount oder Daemon zurücklassen. M7 mountet nichts; die einzige Berührung ist, dass `health`, `migrate` und `restore` einen laufenden Daemon **ablehnen** müssen (`VaultRegistry::require_locked`).
- Exit-Codes (`crates/crypto/src/exit.rs`): 0 ok, 1 allgemein, 2 Usage, 3 Vault nicht gefunden, 4 Passwort/Recovery-Key ungültig, 5 falscher Zustand, 6 Mount, 7 Unmount, 8 Keychain, 9 Hub, 10 Daemon, **11 Health-Befunde ≥ `--fail-on` (neu, war reserviert)**, 12 kein Vault-Verzeichnis.
- Java-Parität (cryptofs 2.10.0, Cryptomator 1.19.x). Die Konstanten, Severities, Meldungstexte und Reihenfolgen unten sind aus dem Quelltext abgeschrieben und in den Tasks wörtlich zitiert; wer davon abweicht, macht die Reports der beiden Programme unvergleichbar. Die vier bewussten Abweichungen stehen in den Rulings.

### Rulings dieses Meilensteins (im Code kommentieren, in Task 14 dokumentieren)

1. **Pfade in Ergebnissen sind vault-relativ.** Java ist hier uneinheitlich (`DirIdCheck` liefert absolute Pfade, `LooseDirFile.fix` macht darauf ein wirkungsloses `pathToVault.resolve(dirFile)`; `OrphanContentDir` liefert `d`-relative Pfade). Wir liefern **immer** vault-relativ (`d/AB/CDEF…/dir.c9r`), und jeder `Fix` löst gegen `ctx.vault_path` auf. Das macht Reports maschinenlesbar und reproduzierbar.
2. **`--fail-on` ist `CRITICAL` per Default.** Java kennt den Schalter nicht (das UI zeigt nur an). Ein CLI muss aber einen Exit-Code liefern, der in einem Cron-Job etwas bedeutet: `CRITICAL` = „Datenverlust ist bereits passiert" ist die Schwelle, die eine Meldung verdient. `--fail-on WARN` verschärft, mehr Werte gibt es nicht (`GOOD`/`INFO` als Fehlerschwelle wäre sinnlos, weil `GOOD` bei jedem gesunden Vault massenhaft auftritt).
3. **`--fix` repariert ab `WARN`, nicht ab `INFO`.** `--fix-severity` verschiebt die Schwelle auf `CRITICAL`. `INFO`-Befunde (`MissingDirIdBackup`, `LooseDirFile`) haben Fixes, aber sie sind Kosmetik; wer sie will, nimmt `--fix --fix-severity WARN` (der Default) — das schließt sie **nicht** ein. Wer *alles* will, gibt es nicht: die Schwelle kennt nur `WARN` und `CRITICAL`, weil die Grammatik in der Spec genau diese zwei Werte nennt. Dokumentiert als bewusste Lücke; `INFO`-Fixes bleiben über die Desktop-App erreichbar.
4. **Nach `--fix` wird neu geprüft.** Ein Fix kann neue Befunde erzeugen (die LOST+FOUND-Adoption legt Verzeichnisse an, die der nächste Lauf als `HealthyDir` sieht) und alte auflösen. `crypto health --fix` läuft deshalb zweimal und druckt beides („before"/„after"); der Exit-Code entscheidet sich am **zweiten** Lauf. Ohne diesen zweiten Lauf könnte `--fix` nie exit 0 liefern.
5. **Der Report-Pfad ist das aktuelle Verzeichnis.** Java schreibt nach `env.getLogDir().orElse(user.home)` als `healthReport_<displayName>_<yyyyMMdd-HHmmss>.log`. Das CLI hat für ein Vordergrundkommando kein Log-Verzeichnis (das State-Dir gehört den Daemons und liegt oft unter `/tmp`). Wir behalten Javas **Dateinamen** exakt und legen die Datei im **cwd** ab; der Pfad wird auf stderr genannt bzw. steht im JSON unter `report`. `--report FILE` überschreibt, `--no-report` unterdrückt. Der Zeitstempel ist **UTC** statt Systemzeitzone, weil der Workspace keine Zeitzonendatenbank hat und M7 keine neue Abhängigkeit bekommt.
6. **Migration läuft in place mit Backups, in einer Schleife bis Format 8.** Javas `Migrators.migrate` führt genau *einen* Migrator aus und überlässt der App die Wiederholung. `crypto migrate` schleift intern (5→6→7→8) und meldet die Kette. Vor jedem Schritt legen die Migratoren dieselben Backups an wie Java (`attempt_backup` auf `masterkey.cryptomator`, in v8 zusätzlich implizit über die neue `vault.cryptomator`, die `open_vault` beim ersten Öffnen sichert). Keine Kopie des ganzen Vaults – bei mehreren GB wäre das keine Sicherheit, sondern eine zweite Fehlerquelle. Der Hinweis „vorher sichern" steht in der Bestätigungsfrage.
7. **`--dry-run` ist Pflicht, nicht Komfort.** 6→7 benennt jede Datei im Vault um. `crypto migrate --dry-run` listet die geplanten Umbenennungen (alt → neu, inklusive der `_n`-Kollisionsauflösung, soweit ohne Schreiben bestimmbar) und die Schritte, die die Schlüsseldateien anfassen würden, und ändert nichts.
8. **Schon auf Format 8 ist kein Fehler.** `crypto migrate` auf einem aktuellen Vault meldet „already at version 8" und endet mit **0**. Exit **5** bleibt der Zustand „braucht Migration" bei allen *anderen* Kommandos (`unlock`, `fs`, `health`, …).
9. **Nicht-TTY ohne `--yes` ist Exit 2.** Sowohl die Bestätigungsfrage von `migrate` als auch Javas `REQUIRES_FULL_VAULT_DIR_SCAN`-Rückfrage in v7 werden ohne Terminal zu `AppError::NoPasswordSource`-artigen Usage-Fehlern — konkret `AppError::InvalidValue { key: "--yes", … }` → Exit 2. Ein Skript, das migrieren will, sagt das mit `--yes`.
10. **`recovery-key restore --config` nimmt das Vault-Passwort, nicht den Recovery-Key.** Das ist Javas `RecoveryKeyCreationController.restoreWithPassword`: die `masterkey.cryptomator` ist ja noch da, nur die `vault.cryptomator` fehlt. `--masterkey` und `--all` nehmen den Recovery-Key plus ein *neues* Passwort. Wer die Kombination verwechselt, bekommt einen Usage-Fehler mit dem richtigen Flag im Text.
11. **Der Check-Katalog ist fest, nicht plugin-fähig.** Java lädt `HealthCheck` über den `ServiceLoader`. Wir haben drei Checks, sie heißen `dirid`, `type`, `shortened`, und `--check` nimmt eine Komma-Liste davon (Default: alle drei, in dieser Reihenfolge). Ein unbekannter Name ist Exit 2 mit der Liste der gültigen.

---

## Dateistruktur

```
tools/fixture-gen/pom.xml                                   → Reaktor-POM (packaging pom, <modules>)
tools/fixture-gen/gen-current/pom.xml                       NEU: das bisherige Modul (cryptofs 2.10.0)
tools/fixture-gen/gen-current/src/main/java/.../Gen.java    verschoben, + `broken`-Kommando
tools/fixture-gen/gen-legacy-v7/pom.xml                     NEU: cryptofs 1.9.15 → Format 7
tools/fixture-gen/gen-legacy-v7/src/main/java/.../GenV7.java   NEU
tools/fixture-gen/gen-legacy-v6/pom.xml                     NEU: cryptofs 1.8.9  → Format 6
tools/fixture-gen/gen-legacy-v6/src/main/java/.../GenV6.java   NEU
tools/fixture-gen/gen-legacy-v5/pom.xml                     NEU: cryptofs 1.6.2  → Format 6, danach auf 5 zurückgestempelt
tools/fixture-gen/gen-legacy-v5/src/main/java/.../GenV5.java   NEU
tools/fixture-gen/README.md                                 Doku der neuen Kommandos
tests/fixtures/broken_health/                               NEU (Task 1, nur über den Generator)
tests/fixtures/legacy_v7/  legacy_v6/  legacy_v5/           NEU (Task 2, nur über den Generator)

crates/cryptomator-core/src/lib.rs                          + pub mod health; pub mod migration; Re-Exports
crates/cryptomator-core/src/health/mod.rs                   NEU: Severity, DiagnosticResult, Fix, HealthCheck, CheckContext, run_checks, CHECK_IDS
crates/cryptomator-core/src/health/dir_id.rs                NEU: DirIdCheck + 8 Ergebnistypen + Fixes
crates/cryptomator-core/src/health/orphan.rs                NEU: der LOST+FOUND-Fix von OrphanContentDir
crates/cryptomator-core/src/health/file_type.rs             NEU: CiphertextFileTypeCheck + 3 Ergebnistypen
crates/cryptomator-core/src/health/shortened.rs             NEU: ShortenedNamesCheck + 6 Ergebnistypen
crates/cryptomator-core/src/health/report.rs                NEU: ReportWriter-Format
crates/cryptomator-core/src/migration/mod.rs                NEU: Migrators, MigrationStep, MigrationPlan, assert_all_capabilities
crates/cryptomator-core/src/migration/v6.rs                 NEU: 5→6 (NFC)
crates/cryptomator-core/src/migration/v7.rs                 NEU: 6→7 (FilePathMigration, PreMigration, m/ löschen)
crates/cryptomator-core/src/migration/v8.rs                 NEU: 7→8 (vault.cryptomator)
crates/cryptomator-core/src/recovery/restore.rs             NEU: RecoveryDirectory, restore_*, detect_cipher_combo
crates/cryptomator-core/src/recovery/mod.rs                 + pub mod restore;
crates/cryptomator-core/src/error.rs                        + CoreError::{FileNameTooLong, MissingCapability, CipherComboUndetectable, MigrationBlocked}
crates/cryptomator-core/tests/common/mod.rs                 + fixture(), copy_fixture()
crates/cryptomator-core/tests/health.rs                     NEU: die drei Checks gegen broken_health
crates/cryptomator-core/tests/migration.rs                  NEU: die Migratoren gegen legacy_v{5,6,7}

crates/crypto/src/exit.rs                                   + HEALTH_FINDINGS = 11
crates/crypto/src/cli.rs                                    + Command::{Health, Migrate}, RecoveryKeyCommand::Restore
crates/crypto/src/commands/mod.rs                           + migratable_vault()
crates/crypto/src/commands/health.rs                        NEU: `crypto health`
crates/crypto/src/commands/migrate.rs                       NEU: `crypto migrate`
crates/crypto/src/commands/recovery.rs                      + restore()
crates/crypto/src/main.rs                                   + Dispatch
crates/crypto/src/output.rs                                 + format_compact_timestamp()
crates/crypto/tests/cli_health.rs                           NEU
crates/crypto/tests/cli_migrate.rs                          NEU
crates/crypto/tests/cli.rs                                  + recovery-key restore
crates/crypto/tests/cli_daemon.rs                           Log-Assertion für den detachten Daemon (Nachtrag)
crates/crypto/tests/java_interop.rs                         + migrierte Legacy-Vaults durch `verify`
.github/workflows/ci.yml                                    interop-java lädt die Legacy-Artefakte mit
README.md, CHANGELOG.md, Spec                               Doku
```

### Gemeinsame Typen (Details in den Tasks)

- `cryptomator_core::health::{Severity, DiagnosticResult, Fix, HealthCheck, CheckContext, run_checks, checks_by_ids, CHECK_IDS, ALL_CHECKS}` (Task 3).
- `cryptomator_core::health::dir_id::{DirIdCheck, DIR_ID_CHECK_NAME}` (Task 4), `health::orphan::AdoptOrphan` (Task 5).
- `cryptomator_core::health::file_type::{CiphertextFileTypeCheck, TYPE_CHECK_NAME}` und `health::shortened::{ShortenedNamesCheck, SHORTENED_CHECK_NAME}` (Task 6).
- `cryptomator_core::health::report::{write_report, report_file_name, REPORT_HEADER, CHECK_SEPARATOR}` (Task 7).
- `cryptomator_core::migration::{Migrators, MigrationStep, MigrationPlan, PlannedRename, assert_all_capabilities}` (Task 10, ergänzt in 11).
- `cryptomator_core::recovery::restore::{RecoveryDirectory, restore_masterkey, restore_config, restore_all, detect_cipher_combo}` (Task 13).
- `crypto::exit::HEALTH_FINDINGS` (Task 8), `crypto::commands::migratable_vault` (Task 12).

---

### Task 1: Beschädigtes Fixture `broken_health` aus dem Java-Harness

**Files:**
- Modify: `tools/fixture-gen/pom.xml` (Reaktor), `tools/fixture-gen/README.md`
- Create: `tools/fixture-gen/gen-current/pom.xml`
- Move: `tools/fixture-gen/src/main/java/org/cryptomator/cli/fixtures/Gen.java` → `tools/fixture-gen/gen-current/src/main/java/org/cryptomator/cli/fixtures/Gen.java`
- Create (Generator-Ausgabe, **einzige erlaubte Änderung unter `tests/fixtures/`**): `tests/fixtures/broken_health/`
- Test: `crates/cryptomator-core/tests/common/mod.rs`, `crates/cryptomator-core/tests/health.rs`

**Interfaces:**
- Consumes: das bestehende `Gen.java` (cryptofs 2.10.0), `Gen.PASSPHRASE = "test-password-123"`, `Gen.KEY_ID`.
- Produces:
  - Maven: `mvn -q -f tools/fixture-gen/pom.xml compile` baut den Reaktor; `mvn -q -f tools/fixture-gen/gen-current/pom.xml compile exec:exec -Dfixture.cmd=broken -Dfixture.arg1=<outDir>` erzeugt `<outDir>/broken_health`.
  - `tests/fixtures/broken_health/` – ein SIV_GCM-Vault, Threshold 220, Passphrase `test-password-123`, plus `fixture.json` (wie bisher) und `expected-findings.json`:
    ```json
    [ { "check": "dirid", "severity": "WARN",  "result": "OrphanContentDir", "path": "d/…/…" }, … ]
    ```
  - Rust: `cryptomator_core::tests::common::{fixture, copy_fixture}` (in `crates/cryptomator-core/tests/common/mod.rs`).

- [ ] **Step 1: Reaktor anlegen**

`tools/fixture-gen/pom.xml` wird zum Aggregator; der bisherige Inhalt (Dependencies, exec-Plugin) zieht nach `gen-current/pom.xml` um und bekommt dort `<parent>`. Neues Aggregator-POM:

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

`gen-current/pom.xml` erbt davon und behält alles Bisherige unverändert – Dependencies (cryptofs 2.10.0, gson 2.13.2, slf4j-simple 2.0.17), das `exec-maven-plugin` mit `exec:exec` und dem geforkten JVM-Aufruf, sowie `<exec.mainClass>org.cryptomator.cli.fixtures.Gen</exec.mainClass>`. Der Default von `fixture.arg1` wird zu `${project.basedir}/../../../tests/fixtures` (eine Ebene tiefer als vorher).

**Die Module `gen-legacy-*` legt Task 2 an.** Damit dieser Task für sich baut, stehen sie hier noch **nicht** in `<modules>`; Task 2 fügt die drei Zeilen hinzu. Der Reaktor hat in diesem Task also genau einen Modul-Eintrag `gen-current`.

- [ ] **Step 2: Prüfen, dass der Reaktor unverändert baut und die alten Fixtures reproduziert**

Run: `cd /Users/rfoerthe/work/cryptomator-cli && mvn -q -f tools/fixture-gen/pom.xml compile`
Expected: BUILD SUCCESS, keine Ausgabe.

Run: `cargo test -p crypto --test java_interop --locked -- --ignored`
Expected: alle Tests grün (der Interop-Test ruft `-f tools/fixture-gen/pom.xml`; er muss auf `gen-current/pom.xml` umgestellt werden – das ist Teil dieses Steps, `crates/crypto/tests/java_interop.rs::run_java_verify` bekommt `"tools/fixture-gen/gen-current/pom.xml"`).

- [ ] **Step 3: Das `broken`-Kommando in `Gen.java`**

`main` bekommt einen dritten Zweig; `argv.get(0).equals("broken")` mit einem Argument (Ausgabeverzeichnis). Der Ablauf: erst einen gesunden Vault `broken_health` mit einer bekannten Struktur erzeugen (dieselbe Mechanik wie `generate`, Masterkey = SHA-512("broken_health")), dann den Ciphertext gezielt beschädigen und die erwarteten Befunde protokollieren.

```java
static final String BROKEN_NAME = "broken_health";

static void broken(Path out) throws Exception {
    Path vault = out.resolve(BROKEN_NAME);
    Spec spec = new Spec(BROKEN_NAME, CryptorProvider.Scheme.SIV_GCM, 220, fs -> {
        write(fs, "/healthy.txt", "this file stays intact\n");
        Files.createDirectory(fs.getPath("/keep"));           // bleibt heil
        write(fs, "/keep/inside.txt", "kept\n");
        Files.createDirectory(fs.getPath("/orphaned"));       // wird zum Waisen-Verzeichnis
        write(fs, "/orphaned/adopted.txt", "adopt me\n");
        Files.createDirectory(fs.getPath("/nodirid"));        // verliert seine dirid.c9r
        Files.createDirectory(fs.getPath("/nocontent"));      // verliert sein Inhaltsverzeichnis
        write(fs, "/" + "L".repeat(200) + ".txt", "shortened\n");   // wird zu .c9s
        write(fs, "/" + "M".repeat(200) + ".txt", "mismatch\n");    // .c9s mit falschem Namen
        write(fs, "/" + "T".repeat(200) + ".txt", "trailing\n");    // .c9s mit Trailing Bytes
        write(fs, "/" + "N".repeat(200) + ".txt", "noname\n");      // .c9s ohne name.c9s
    });
    generate(vault, spec);                                    // schreibt auch fixture.json/expected.json
    List<Map<String, Object>> findings = damage(vault);
    var gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
    Files.writeString(vault.resolve("expected-findings.json"), gson.toJson(findings) + "\n", StandardCharsets.UTF_8);
    Files.delete(vault.resolve("expected.json"));  // der Klartext-Baum ist nach der Beschädigung sinnlos
}
```

- [ ] **Step 4: `damage(Path vault)` – die neun Schadensfälle**

`damage` öffnet den Vault mit cryptolib (Masterkey aus `fixture.json`), baut einen `Cryptor` für die Namensfunktionen und schreibt danach nur noch auf der Ciphertext-Ebene. Jeder Fall liefert eine Zeile in `expected-findings.json` mit `check`, `severity`, `result` und `path` (vault-relativ, mit `/` als Trenner – Ruling 1).

| # | Schaden | erwarteter Befund |
|---|---|---|
| 1 | im `.c9r`-Knoten von `/orphaned` die Datei `dir.c9r` löschen (das Inhaltsverzeichnis bleibt stehen) | `dirid` WARN `OrphanContentDir` auf `d/XX/YYY…` |
| 2 | im Inhaltsverzeichnis von `/nodirid` die `dirid.c9r` löschen | `dirid` INFO `MissingDirIdBackup` |
| 3 | das Inhaltsverzeichnis von `/nocontent` rekursiv löschen (das `dir.c9r` bleibt) | `dirid` WARN `MissingContentDir` |
| 4 | eine leere Datei `d/XX/YYY…/dir.c9r` neben dem Wurzelverzeichnis anlegen, wobei `XX/YYY…` das Wurzel-Inhaltsverzeichnis ist → Elternname endet nicht auf `.c9r`/`.c9s` | `dirid` INFO `LooseDirFile` |
| 5 | in einem neu angelegten `d/<root>/collide.c9r/dir.c9r` die dirId von `/keep` noch einmal schreiben | `dirid` CRITICAL `DirIdCollision` |
| 6 | ein neues `d/<root>/unknown.c9r/` anlegen, das weder `dir.c9r` noch `symlink.c9r` noch `contents.c9r` enthält (eine belanglose Datei `x` hinein, damit das Verzeichnis existiert und nicht leer ist) | `type` CRITICAL `UnknownType` |
| 7 | im `.c9s`-Knoten von `M…` die `name.c9s` mit dem Namen eines *anderen* Knotens überschreiben | `shortened` WARN `LongShortNamesMismatch` |
| 8 | an die `name.c9s` von `T…` den Text `garbage` anhängen | `shortened` WARN `TrailingBytesInNameFile` |
| 9 | im `.c9s`-Knoten von `N…` die `name.c9s` löschen | `shortened` CRITICAL `MissingLongName` |

Fall 4 braucht einen Elternnamen, der *kein* `.c9r`/`.c9s`-Suffix hat: Java prüft `parentDirName.endsWith(".c9r") || endsWith(".c9s")`. Das Wurzel-Inhaltsverzeichnis `d/XX/YYY…` heißt 30 BASE32-Zeichen — also `Files.writeString(rootContentDir.resolve("dir.c9r"), "")`. Es ist gleichzeitig leer, aber `EmptyDirFile` wird nicht gemeldet: der `LooseDirFile`-Zweig kommt **vor** der Größenprüfung und endet mit `CONTINUE`.

Zusätzlich zu den neun Zeilen enthält `expected-findings.json` **keine** `GOOD`-Befunde – die zählt der Rust-Test nur, er vergleicht sie nicht einzeln.

Hilfsfunktion für Fall 5/6, weil dort neue Ciphertext-Namen gebraucht werden:

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

- [ ] **Step 5: Fixture erzeugen und Größe prüfen**

Run:
```bash
cd /Users/rfoerthe/work/cryptomator-cli
mvn -q -f tools/fixture-gen/gen-current/pom.xml compile exec:exec \
    -Dfixture.cmd=broken -Dfixture.arg1=tests/fixtures
du -sh tests/fixtures/broken_health
```
Expected: das Verzeichnis existiert und ist **unter 200 KB**. Ist es größer, sind die Dateiinhalte zu lang – sie sind alle einzeilig, also darf das nicht passieren; sonst Inhalte kürzen und neu erzeugen.

Run: `cat tests/fixtures/broken_health/expected-findings.json`
Expected: neun Objekte, jedes mit `check` ∈ {`dirid`,`type`,`shortened`}, `severity` ∈ {`INFO`,`WARN`,`CRITICAL`} und einem vault-relativen `path`.

- [ ] **Step 6: Rust-Testhelfer und der erste (noch trivial grüne) Test**

`crates/cryptomator-core/tests/common/mod.rs` bekommt:

```rust
use std::path::{Path, PathBuf};

pub fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures").join(name)
}

/// Kopiert ein Fixture in ein Tempdir. Jeder Test, der schreibt (Health-Fixes, Migration,
/// Restore), arbeitet ausschliesslich auf so einer Kopie -- `tests/fixtures/` bleibt unberuehrt.
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

Neue Datei `crates/cryptomator-core/tests/health.rs` mit dem Manifest-Typ und einem Test, der nur belegt, dass das Fixture da und lesbar ist:

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
    // Der Vault laesst sich weiterhin oeffnen -- beschaedigt ist die Struktur, nicht der Schluessel.
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
Expected: alles grün.

```bash
git add tools/fixture-gen tests/fixtures/broken_health crates/cryptomator-core/tests crates/crypto/tests/java_interop.rs
git commit -m "test: damaged reference vault broken_health from the Java harness

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 2: Legacy-Fixtures v7, v6 und v5

**Files:**
- Modify: `tools/fixture-gen/pom.xml` (drei `<module>`-Einträge), `tools/fixture-gen/README.md`
- Create: `tools/fixture-gen/gen-legacy-v7/{pom.xml,src/main/java/org/cryptomator/cli/fixtures/GenV7.java}`
- Create: `tools/fixture-gen/gen-legacy-v6/{pom.xml,src/main/java/org/cryptomator/cli/fixtures/GenV6.java}`
- Create: `tools/fixture-gen/gen-legacy-v5/{pom.xml,src/main/java/org/cryptomator/cli/fixtures/GenV5.java}`
- Create (Generator-Ausgabe): `tests/fixtures/legacy_v7/`, `tests/fixtures/legacy_v6/`, `tests/fixtures/legacy_v5/`
- Test: `crates/cryptomator-core/tests/migration.rs`

**Interfaces:**
- Consumes: `common::{fixture, copy_fixture}` (Task 1), `cryptomator_core::{determine_vault_version, needs_migration, VaultState, determine_vault_state}`.
- Produces: drei Fixture-Verzeichnisse mit je `fixture.json`:
  ```json
  { "name": "legacy_v7", "vaultVersion": 7, "passphrase": "test-password-123",
    "masterkeyHex": "…", "expected": [ { "path": "/hello.txt", "type": "file", "sha256": "…" }, … ] }
  ```
  Für `legacy_v5` ist `"passphrase"` die **NFD**-Form von `"tästpaß-123"` (also `a` + U+0308 statt `ä`), zusätzlich als `"passphraseNfc"` die NFC-Form.

**Wichtig vorab (verifiziert):** In `~/.m2` liegt **nur** cryptofs 2.10.0. Die drei Legacy-Artefakte sind auf Maven Central vorhanden (`https://repo1.maven.org/maven2/org/cryptomator/cryptofs/{1.9.15,1.8.9,1.6.2}/` → HTTP 200, geprüft), werden aber beim ersten Bau heruntergeladen: **dieser Task braucht Netzzugang.** Ohne Netz bricht Maven mit `Could not resolve dependencies` ab; dann ist der Task zu vertagen, nicht zu umgehen.

**Zweiter Befund (verifiziert):** `Constants.VAULT_VERSION` ist in cryptofs **1.9.15 = 7**, **1.8.9 = 6** und **1.6.2 = 6** – es gibt keine Bibliothek, die Format 5 schreibt. Format 5 und 6 unterscheiden sich ausschließlich in der Passphrase-Normalisierung (der `Version6Migrator` schreibt nur die Masterkey-Datei mit NFC-Passphrase neu, die Verzeichnisstruktur bleibt gleich). `gen-legacy-v5` erzeugt deshalb mit **1.6.2** einen Vault mit einer **NFD**-Passphrase und stempelt anschließend die Masterkey-Datei auf `version: 5` um, inklusive neu berechnetem `versionMac` = HMAC-SHA256(hmacMasterKey, BE32(5)). Das ist genau das, was ein echter v5-Vault ist.

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

`GenV7.java` – cryptofs 1.x hat eine ganz andere API als 2.x: kein `Masterkey`-Objekt, kein `withKeyLoader`, stattdessen Passphrase-basiert.

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

/** Erzeugt einen Vault im Format 7 mit cryptofs 1.9.15 (Constants.VAULT_VERSION == 7). */
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

`LegacySupport` ist eine kleine Klasse, die in **jedem** der drei Legacy-Module als Kopie liegt (die Module teilen keinen Code, weil sie inkompatible cryptofs-Versionen auf dem Klassenpfad haben und `CryptoFileSystem` in 1.6.2/1.8.9/1.9.15 verschiedene Signaturen hat). Ihr Inhalt:

```java
static void recreate(Path vault) throws IOException {          // löscht rekursiv und legt neu an
static void populate(CryptoFileSystem fs) throws IOException {
    Files.writeString(fs.getPath("/hello.txt"), "Hello, legacy!\n", StandardCharsets.UTF_8);
    Files.createDirectory(fs.getPath("/docs"));
    Files.writeString(fs.getPath("/docs/notes.md"), "# Notes\n\nlegacy\n", StandardCharsets.UTF_8);
    Files.createDirectory(fs.getPath("/docs/deep"));
    Files.writeString(fs.getPath("/docs/deep/inner.txt"), "nested\n", StandardCharsets.UTF_8);
    // Ein Name, der laenger als 129 Zeichen wird und damit in v5/v6 als `.lng` in `m/` landet
    // (Constants.SHORT_NAMES_MAX_LENGTH == 129) bzw. in v7 als `.c9s`:
    Files.writeString(fs.getPath("/" + "l".repeat(150) + ".txt"), "long name\n", StandardCharsets.UTF_8);
    Files.createSymbolicLink(fs.getPath("/link.txt"), fs.getPath("hello.txt"));
}
static void walk(Path dir, List<Map<String, Object>> out) throws IOException {   // wie Gen.walk
static void writeManifest(Path vault, String name, int version, String passphrase,
                          String passphraseNfc, List<Map<String, Object>> expected) throws IOException
```

`walk` und `sha256` werden aus `gen-current/…/Gen.java` wörtlich übernommen (Pfad, Typ, Größe, SHA-256, Symlink-Ziel). `writeManifest` schreibt `fixture.json` mit `name`, `vaultVersion`, `passphrase`, optional `passphraseNfc`, `masterkeyHex` (aus der erzeugten Masterkey-Datei ist der Rohschlüssel nicht ablesbar – das Feld entfällt hier, anders als bei `Gen`) und `expected`.

- [ ] **Step 2: `gen-legacy-v6`**

Identisch zu Step 1, aber `<version>1.8.9</version>`, Klasse `GenV6`, `NAME = "legacy_v6"`, `vaultVersion = 6`. In 1.8.9 liegt `Constants` im Paket `org.cryptomator.cryptofs` (nicht `…cryptofs.common`) – das spielt für `GenV6` keine Rolle, weil nur die öffentliche Provider-API benutzt wird, die identisch ist (`initialize(Path, String, CharSequence)`, `newFileSystem(Path, CryptoFileSystemProperties)`, Builder mit `withPassphrase`/`withMasterkeyFilename`).

Der so erzeugte Vault hat die v6-Struktur: `d/XX/YYY…/BASE32==` für Dateien, `0BASE32==` für Verzeichnisse, `1SBASE32==` für Symlinks, und `m/xx/yy/<32 BASE32-Zeichen>.lng` für den 150-Zeichen-Namen.

- [ ] **Step 3: `gen-legacy-v5`**

`<version>1.6.2</version>`, Klasse `GenV5`, `NAME = "legacy_v5"`. Zwei Unterschiede zu Step 2:

1. Die Passphrase ist **NFD**: `String PASSPHRASE_NFD = "tästpaß-123";` (also `t`, `a`, U+0308 COMBINING DIAERESIS, `stpaß-123`) und `String PASSPHRASE_NFC = java.text.Normalizer.normalize(PASSPHRASE_NFD, java.text.Normalizer.Form.NFC);`. Der Vault wird mit **PASSPHRASE_NFD** initialisiert; cryptolib 1.x normalisiert nicht, also ist der KEK aus genau diesen Bytes abgeleitet. Ein `assert !PASSPHRASE_NFD.equals(PASSPHRASE_NFC)` im Generator stellt sicher, dass der Unterschied wirklich da ist.
2. Nach dem Schließen des Dateisystems wird die Masterkey-Datei auf Version 5 umgestempelt:

```java
static void stampVersion5(Path masterkeyFile) throws Exception {
    var gson = new com.google.gson.Gson();
    var obj = gson.fromJson(Files.readString(masterkeyFile), com.google.gson.JsonObject.class);
    obj.addProperty("version", 5);
    byte[] hmacKey = Base64.getDecoder().decode(obj.get("hmacMasterKey").getAsString());
    // Das ist der *gewrappte* HMAC-Schluessel -- der versionMac wird mit dem *entpackten*
    // gebildet. Deshalb ueber cryptolib gehen statt selbst zu rechnen:
    //   Cryptor c = Cryptors.version1(csprng).createFromKeyFile(KeyFile.parse(bytes), pass, 6);
    //   byte[] mac = c.fileHeaderCryptor() ...   -- gibt es in 1.x nicht oeffentlich.
    // Loesung: den versionMac auf die Bytes von cryptolib selbst schreiben lassen, indem der
    // Vault mit `CryptoFileSystemProvider.changePassphrase(vault, MASTERKEY, pass, pass)` neu
    // geschrieben wird -- das kann die Version aber nicht setzen.
    throw new UnsupportedOperationException("siehe Step 4");
}
```

Der obige Block ist **absichtlich** eine Sackgasse und steht hier, damit der Implementierende sie nicht selbst neu läuft: der `versionMac` braucht den entpackten HMAC-Schlüssel, den cryptolib 1.x nicht herausgibt. Der gangbare Weg steht in Step 4.

- [ ] **Step 4: Version 5 korrekt stempeln – über unser eigenes `MasterkeyFileAccess`**

Der `versionMac` wird **nicht** in Java berechnet, sondern in Rust, und zwar in einem `#[ignore]`-Test, der das Fixture fertigstellt. Grund: `crates/cryptomator-core/src/masterkey_file.rs` kann genau das schon (`MasterkeyFileAccess::{load, persist}` mit `vault_version`-Parameter, `lock()` schreibt `versionMac` = HMAC-SHA256 über `vault_version.to_be_bytes()` unter dem MAC-Key), und cryptolib 1.x und 2.x schreiben bitgleiche Masterkey-Dateien.

`GenV5.main` erzeugt also einen Vault mit `version: 6` und der NFD-Passphrase und meldet das im Manifest als `"vaultVersion": 5, "stampPending": true`. Danach läuft in `crates/cryptomator-core/tests/migration.rs`:

```rust
/// Stempelt `tests/fixtures/legacy_v5/masterkey.cryptomator` von Version 6 auf 5 um. Laeuft einmal
/// nach `mvn … GenV5` und schreibt als einziger Test in `tests/fixtures/` -- deshalb `#[ignore]`.
/// Aufruf: `cargo test -p cryptomator-core --test migration -- --ignored stamp_legacy_v5`
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

Der Testlauf ändert danach noch `stampPending` auf `false` — nein: einfacher und ohne Zustand, `writeManifest` lässt das Feld ganz weg und schreibt direkt `"vaultVersion": 5`; der Rust-Test ist der zweite Teil desselben Generatorschritts und in `tools/fixture-gen/README.md` als solcher dokumentiert. Nach dem Umstempeln ist die Datei fertig und wird eingecheckt.

- [ ] **Step 5: Alle drei Fixtures erzeugen**

Run:
```bash
cd /Users/rfoerthe/work/cryptomator-cli
mvn -q -f tools/fixture-gen/pom.xml compile                      # laedt 1.9.15/1.8.9/1.6.2 nach ~/.m2
mvn -q -f tools/fixture-gen/gen-legacy-v7/pom.xml exec:exec
mvn -q -f tools/fixture-gen/gen-legacy-v6/pom.xml exec:exec
mvn -q -f tools/fixture-gen/gen-legacy-v5/pom.xml exec:exec
cargo test -p cryptomator-core --test migration --locked -- --ignored stamp_legacy_v5
du -sh tests/fixtures/legacy_v*
```
Expected: drei Verzeichnisse, jedes **unter 200 KB**; `generated legacy_v7|v6|v5` auf stdout; der Rust-Test grün.

Schlägt der erste `mvn`-Aufruf mit `Could not resolve dependencies` fehl, fehlt Netz – im Report festhalten und den Task abbrechen, nicht die Versionen ändern.

- [ ] **Step 6: Die Struktur der drei Fixtures nachweisen**

Run:
```bash
ls tests/fixtures/legacy_v7/d/*/*/ | head
ls tests/fixtures/legacy_v6/ && ls tests/fixtures/legacy_v6/m/*/*/ | head
ls tests/fixtures/legacy_v5/ && head -c 200 tests/fixtures/legacy_v5/masterkey.cryptomator
```
Expected: `legacy_v7` hat `.c9r`/`.c9s`-Namen und **kein** `m/`; `legacy_v6` und `legacy_v5` haben BASE32-Namen mit `0`/`1S`-Präfixen und ein `m/xx/yy/…lng`; die v5-Masterkey-Datei beginnt mit `{"version": 5,` (bzw. `"version":5`).

- [ ] **Step 7: Rust-Test über die erkannten Versionen**

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
    // v6 und v5 haben das Metadatenverzeichnis, v7 nicht mehr.
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

- [ ] **Step 8: Doku, Gate, Commit**

`tools/fixture-gen/README.md` bekommt einen Abschnitt „Legacy fixtures" mit den vier Kommandos aus Step 5, dem Hinweis auf den Netzbedarf beim ersten Lauf und dem Satz, dass `legacy_v5` erst nach dem Rust-Stempelschritt fertig ist.

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked`
Expected: grün (der `stamp_legacy_v5`-Test läuft dabei nicht, er ist `#[ignore]`).

```bash
git add tools/fixture-gen tests/fixtures/legacy_v7 tests/fixtures/legacy_v6 tests/fixtures/legacy_v5 crates/cryptomator-core/tests/migration.rs
git commit -m "test: legacy reference vaults for formats 7, 6 and 5

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 3: Das Health-Gerüst – `Severity`, `DiagnosticResult`, `Fix`, `HealthCheck`, `CheckContext`

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
    pub fn parse_threshold(s: &str) -> Result<Severity>;  // nur "WARN" | "CRITICAL", case-insensitive
}

pub trait Fix: std::fmt::Debug + Send {
    fn apply(&self, ctx: &CheckContext) -> std::io::Result<()>;
}

#[derive(Debug)]
pub struct DiagnosticResult {
    pub severity: Severity,
    pub check: &'static str,        // eine der CHECK_IDS
    pub message: String,            // wortgleich mit Javas toString()
    pub paths: Vec<PathBuf>,        // vault-relativ (Ruling 1)
    pub fix: Option<Box<dyn Fix>>,
}
impl DiagnosticResult {
    pub fn new(check: &'static str, severity: Severity, message: String, paths: Vec<PathBuf>) -> Self;
    pub fn with_fix(self, fix: Box<dyn Fix>) -> Self;
    pub fn fixable(&self) -> bool;
}

pub trait HealthCheck: std::fmt::Debug {
    fn id(&self) -> &'static str;              // "dirid" | "type" | "shortened"
    fn name(&self) -> &'static str;            // Javas HealthCheck.name(), für den Report
    fn run(&self, ctx: &CheckContext, sink: &mut dyn FnMut(DiagnosticResult));
}

#[derive(Debug)]
pub struct CheckContext { pub vault_path: PathBuf, pub cryptor: Cryptor, pub config: VaultConfig, rng: Mutex<Box<dyn Rng + Send>> }
impl CheckContext {
    pub fn new(opened: OpenedVault) -> Self;                       // OsRng
    pub fn with_rng(opened: OpenedVault, rng: Box<dyn Rng + Send>) -> Self;
    pub fn data_dir(&self) -> PathBuf;                             // <vault>/d
    pub fn resolve(&self, relative: &Path) -> PathBuf;             // vault_path.join(relative)
    pub fn relativize(&self, absolute: &Path) -> PathBuf;          // strip_prefix(vault_path), sonst unveraendert
    pub fn rng<T>(&self, f: impl FnOnce(&mut dyn Rng) -> T) -> T;  // serialisiert ueber die Mutex
}

pub fn all_checks() -> Vec<Box<dyn HealthCheck>>;
pub fn checks_by_ids(ids: &[String]) -> Result<Vec<Box<dyn HealthCheck>>>;
pub fn run_checks(checks: &[Box<dyn HealthCheck>], ctx: &CheckContext) -> Vec<DiagnosticResult>;
```
und `CoreError::UnknownHealthCheck(String)` (→ Exit 2 über `CoreError::InvalidArgument`-Nachbarschaft; siehe Step 3).

- [ ] **Step 1: Failing test für `Severity` und den Katalog**

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

- [ ] **Step 2: Lauf – muss fehlschlagen**

Run: `cargo test -p cryptomator-core health::tests --locked`
Expected: FAIL, `unresolved module` / `cannot find`.

- [ ] **Step 3: Implementieren**

`health/mod.rs` mit den Typen aus dem Interfaces-Block. Details, die nicht raten lassen:

- `Severity` leitet `PartialOrd, Ord` in der Deklarationsreihenfolge `Good, Info, Warn, Critical` ab – daran hängen `--fail-on` und `--fix-severity`.
- `parse_threshold` akzeptiert case-insensitiv `"warn"`/`"critical"` und liefert sonst
  `CoreError::InvalidArgument(format!("unknown severity {input:?}; expected WARN or CRITICAL"))`.
- `checks_by_ids` geht **über `CHECK_IDS` in Katalogreihenfolge** und nimmt jede ID auf, die in `ids` vorkommt (dadurch Dedup und stabile Reihenfolge, unabhängig davon, wie der Nutzer sie sortiert hat). Danach prüft es, ob jedes Element von `ids` in `CHECK_IDS` steht, und meldet sonst
  `CoreError::InvalidArgument(format!("unknown check {id:?}; valid checks are {}", CHECK_IDS.join(", ")))`.
- `all_checks()` gibt `vec![Box::new(DirIdCheck), Box::new(CiphertextFileTypeCheck), Box::new(ShortenedNamesCheck)]` zurück. **In diesem Task existieren die drei Typen noch nicht.** Bis Task 4/6 sie liefern, steht in `all_checks()` genau dies:
  ```rust
  pub fn all_checks() -> Vec<Box<dyn HealthCheck>> {
      // Task 4 ersetzt die erste, Task 6 die zweite und dritte Zeile durch die echten Checks.
      vec![
          Box::new(Placeholder { id: "dirid", name: "Directory Check" }),
          Box::new(Placeholder { id: "type", name: "Resource Type Check" }),
          Box::new(Placeholder { id: "shortened", name: "Shortened Names Check" }),
      ]
  }

  /// Nur bis Task 4/6: ein Check, der nichts findet. Steht hier, damit `run_checks`, `--check`
  /// und der Report schon in diesem Task getestet werden koennen.
  #[derive(Debug)]
  struct Placeholder { id: &'static str, name: &'static str }
  impl HealthCheck for Placeholder {
      fn id(&self) -> &'static str { self.id }
      fn name(&self) -> &'static str { self.name }
      fn run(&self, _ctx: &CheckContext, _sink: &mut dyn FnMut(DiagnosticResult)) {}
  }
  ```
- `run_checks` ruft jeden Check der Reihe nach auf, sammelt in einen `Vec` und gibt ihn **in der Reihenfolge Check → Fundzeitpunkt** zurück. Kein Nebenläufigkeit: Java streamt über einen Executor, wir brauchen das nicht und ein deterministischer Report ist mehr wert.
- Panics eines Checks werden **nicht** abgefangen; ein Panic ist ein Bug, kein Befund. Javas `CheckFailed` (CRITICAL) bilden wir für den einen Fall nach, den Java auch abfängt: ein `walkdir`-Fehler beim Traversieren – das machen die Checks selbst in Task 4/6.
- `CheckContext::relativize` benutzt `strip_prefix(&self.vault_path).unwrap_or(absolute)` und gibt einen `PathBuf` zurück.
- `CheckContext::rng` sperrt die `Mutex` mit `lock().unwrap_or_else(|e| e.into_inner())` (dasselbe Muster wie `Ctx::keychain`).

`lib.rs`: `pub mod health;` und
```rust
pub use health::{
    all_checks, checks_by_ids, run_checks, CheckContext, DiagnosticResult, Fix, HealthCheck,
    Severity, CHECK_IDS,
};
```

- [ ] **Step 4: Lauf – muss bestehen**

Run: `cargo test -p cryptomator-core health --locked`
Expected: 5 passed.

- [ ] **Step 5: Gate und Commit**

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked`

```bash
git add crates/cryptomator-core/src/health crates/cryptomator-core/src/lib.rs
git commit -m "feat(core): health check trait, diagnostic results and check context

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 4: `DirIdCheck` – acht Ergebnistypen und die Fixes ohne LOST+FOUND

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

// Fixes (jeweils `pub(crate)`, weil sie nur ueber `DiagnosticResult::fix` erreichbar sind):
#[derive(Debug)] struct DeleteLooseDirFile { dir_file: PathBuf }
#[derive(Debug)] struct WriteDirIdBackup   { dir_id: String, content_dir: PathBuf }
#[derive(Debug)] struct CreateContentDir   { dir_id: String }
```

**Java-Vorlage, wörtlich (cryptofs 2.10.0 `health/dirid/*`).** Die acht Ergebnisse, ihre Severity, ihr `toString()` und ihr Fix:

| Ergebnis | Severity | Meldung (Java-Formatstring) | Fix |
|---|---|---|---|
| `HealthyDir` | GOOD | `Good directory %s (%s) -> %s` (dirFile, dirId, dir) | – |
| `MissingDirIdBackup` | INFO | `Directory ID backup for directory %s is missing.` (contentDir) | `DirectoryIdBackup.write(cryptor, {dirId, absCipherDir})` |
| `LooseDirFile` | INFO | `A dir.c9r without proper parent found: (%s). .` (dirFile) | `Files.deleteIfExists(pathToVault.resolve(dirFile))` |
| `ObeseDirFile` | CRITICAL | `Unexpected file size of %s: %d should be ≤ %d` (dirFile, size, 36) | – |
| `EmptyDirFile` | CRITICAL | `File %s is empty, expected content` (dirFile) | – |
| `DirIdCollision` | CRITICAL | `Directory ID reused: %s found in %s and %s` (dirId, dirFile, otherDirFile) | – |
| `MissingContentDir` | WARN | `dir.c9r file (%s) points to non-existing directory.` (dirFile) | `createDirectories(d/h[0..2]/h[2..32])` + `DirectoryIdBackup.write` |
| `OrphanContentDir` | WARN | `Orphan directory: %s` (contentDir) | LOST+FOUND-Adoption → **Task 5** |

Die Meldung von `LooseDirFile` endet tatsächlich auf `". ."` – Tippfehler im Original, wird wörtlich übernommen, damit Reports vergleichbar bleiben.

- [ ] **Step 1: Failing test gegen `broken_health`**

In `crates/cryptomator-core/tests/health.rs` (die Helfer `expected_findings`/`ExpectedFinding` stehen dort schon aus Task 1):

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

/// Wie oft eine Meldung mit diesem Praefix vorkommt. Die Ergebnistypen selbst sind privat --
/// die Meldung ist ihre oeffentliche Identitaet, genau wie in Javas Report.
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
    // Ruling 1: jeder Pfad ist vault-relativ.
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
        // Der Waisen-Fix kommt erst mit Task 5; hier werden die drei anderen angewandt.
        if result.message.starts_with("Orphan directory:") { continue; }
        if let Some(fix) = &result.fix {
            fix.apply(&ctx).expect("the fix applies");
        }
    }
    let after = run("dirid", &ctx);
    assert_eq!(count(&after, "Directory ID backup for directory"), 0);
    assert_eq!(count(&after, "dir.c9r file ("), 0);
    assert_eq!(count(&after, "A dir.c9r without proper parent found:"), 0);
    // Der Waisenfund bleibt, weil sein Fix uebersprungen wurde.
    assert_eq!(count(&after, "Orphan directory:"), 1);
    // Idempotenz: ein zweiter Durchlauf derselben Fixes aendert nichts mehr.
    for result in &after {
        if result.message.starts_with("Orphan directory:") { continue; }
        if let Some(fix) = &result.fix { fix.apply(&ctx).expect("idempotent"); }
    }
    assert_eq!(run("dirid", &ctx).len(), after.len());
}
```

- [ ] **Step 2: Lauf – muss fehlschlagen**

Run: `cargo test -p cryptomator-core --test health --locked`
Expected: FAIL – der `Placeholder` aus Task 3 liefert nichts, also `assert_eq!(count(…), 1)` schlägt fehl.

- [ ] **Step 3: Der Scan**

`DirIdCheck::run` in zwei Phasen, exakt wie `DirIdCheck.check`:

**Phase 1 – Traversieren** (`walkdir` gibt es nicht im Workspace, also `std::fs::read_dir` rekursiv mit einer Tiefenbegrenzung von 4 ab `d/`, gemessen wie Javas `Files.walkFileTree(dataDirPath, Set.of(), 4, visitor)`: `d` = Tiefe 0, `d/XX` = 1, `d/XX/YYY…` = 2, `d/XX/YYY…/name.c9r` = 3, `d/XX/YYY…/name.c9r/dir.c9r` = 4). Gesammelt wird:
- `dir_ids: BTreeMap<String, Option<PathBuf>>` – vorbelegt mit `("".to_string(), None)` (Javas „wir haben immer die leere dirId für die Wurzel").
- `second_level_dirs: BTreeSet<PathBuf>` – jeder Pfad, der relativ zu `d/` genau zwei Namenskomponenten hat (also `XX/YYY…`).

`BTreeMap`/`BTreeSet` statt `HashMap`/`HashSet`: der Report soll bei gleichem Vault gleich aussehen.

Beim Besuch einer **Datei** namens `dir.c9r` (Javas `visitFile` → `visitDirFile`):
1. Elternname endet weder auf `.c9r` noch `.c9s` → `LooseDirFile` (INFO, Fix `DeleteLooseDirFile`), weiter mit dem nächsten Geschwisterknoten (`CONTINUE`).
2. Größe > `MAX_DIR_ID_LENGTH` (36) → `ObeseDirFile` (CRITICAL, kein Fix).
3. Größe == 0 → `EmptyDirFile` (CRITICAL, kein Fix).
4. sonst Inhalt als UTF-8 lesen (`String::from_utf8_lossy`, wie Javas `new String(bytes, UTF_8)`); ist die dirId schon in `dir_ids` → `DirIdCollision` (CRITICAL) mit dem *anderen* Pfad, sonst eintragen.
Nach Fall 2–4 folgt Java `SKIP_SIBLINGS` – innerhalb eines `.c9r`-Verzeichnisses gibt es nach `dir.c9r` nichts mehr zu sehen. Unsere rekursive Variante bricht die Schleife über die Geschwister an dieser Stelle ab.

**Phase 2 – Paare auflösen:**
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
Zwei Java-Eigenheiten, die mitkommen: die Wurzel hat `dir_file == None` (Java setzt `null`), und ihr `HealthyDir`-Text enthält dann `null`; wir schreiben stattdessen `-` und halten das im Doc-Kommentar fest (ein Rust-`None` als `"None"` zu drucken wäre schlechter lesbar als beides). Und: der `MissingContentDir`-Fund für die *Wurzel* (dirId `""`) kann nur auftreten, wenn `d/<roothash>` fehlt – dann steht in der Meldung `dir.c9r file (-) points to non-existing directory.`

- [ ] **Step 4: Die drei Fixes**

```rust
#[derive(Debug)] struct DeleteLooseDirFile { dir_file: PathBuf }
impl Fix for DeleteLooseDirFile {
    fn apply(&self, ctx: &CheckContext) -> std::io::Result<()> {
        match std::fs::remove_file(ctx.resolve(&self.dir_file)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),   // Javas deleteIfExists
            other => other,
        }
    }
}

#[derive(Debug)] struct WriteDirIdBackup { dir_id: String, content_dir: PathBuf }
impl Fix for WriteDirIdBackup {
    fn apply(&self, ctx: &CheckContext) -> std::io::Result<()> {
        let dir = CiphertextDirectory { dir_id: self.dir_id.clone(), path: ctx.resolve(&self.content_dir) };
        match ctx.rng(|rng| crate::fs::dir_id::write_dir_id_backup(&ctx.cryptor, &dir, rng)) {
            // CREATE_NEW: eine schon vorhandene dirid.c9r ist der Erfolgsfall eines zweiten Laufs.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            other => other,
        }
    }
}

#[derive(Debug)] struct CreateContentDir { dir_id: String }
impl Fix for CreateContentDir {
    fn apply(&self, ctx: &CheckContext) -> std::io::Result<()> {
        let hash = ctx.cryptor.file_name_cryptor().hash_directory_id(&self.dir_id);
        // Java: substring(2, 32) statt substring(2) -- der Hash ist genau 32 Zeichen lang, also
        // dasselbe; hier steht die kuerzere Form.
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

Die `AlreadyExists`-Toleranz ist unsere Zutat und der Grund, warum `--fix` idempotent ist: Java wirft dort (bis auf `prepareStepParent`, das den Fall selbst abfängt).

- [ ] **Step 5: `all_checks` verdrahten**

In `health/mod.rs` die erste `Placeholder`-Zeile durch `Box::new(dir_id::DirIdCheck)` ersetzen und `pub mod dir_id;` ergänzen. Die beiden anderen Placeholder bleiben bis Task 6 stehen.

- [ ] **Step 6: Tests, Gate, Commit**

Run: `cargo test -p cryptomator-core --test health --locked`
Expected: 5 passed (die vier neuen plus der Fixture-Test aus Task 1).

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked`

```bash
git add crates/cryptomator-core/src/health crates/cryptomator-core/tests/health.rs
git commit -m "feat(core): DirIdCheck with all eight diagnostic results

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 5: Der LOST+FOUND-Fix von `OrphanContentDir`

**Files:**
- Create: `crates/cryptomator-core/src/health/orphan.rs`
- Modify: `crates/cryptomator-core/src/health/dir_id.rs` (`orphan_content_dir` bekommt den Fix), `crates/cryptomator-core/src/health/mod.rs` (`pub mod orphan;`)
- Test: `crates/cryptomator-core/tests/health.rs`

**Interfaces:**
- Consumes: `health::{CheckContext, Fix}`, `crate::constants::{RECOVERY_DIR_NAME, RECOVERY_DIR_ID, ROOT_DIR_ID, DIR_FILE_NAME, DIR_ID_BACKUP_FILE_NAME, INFLATED_FILE_NAME, SYMLINK_FILE_NAME, CRYPTOMATOR_FILE_SUFFIX, DEFLATED_FILE_SUFFIX, MIN_CIPHER_NAME_LENGTH, DATA_DIR_NAME}`, `crate::fs::dir_id::{read_dir_id_backup, write_dir_id_backup}`, `crate::fs::CiphertextDirectory`, `crate::crypto::rng::Rng`.
- Produces:
```rust
pub(crate) const FILE_PREFIX: &str = "file";
pub(crate) const DIR_PREFIX: &str = "directory";
pub(crate) const SYMLINK_PREFIX: &str = "symlink";
pub(crate) const LONG_NAME_SUFFIX_BASE: &str = "_withVeryLongName";

#[derive(Debug)] pub(crate) struct AdoptOrphan { pub content_dir: PathBuf }   // vault-relativ, z. B. d/AB/CDE…
impl Fix for AdoptOrphan { fn apply(&self, ctx: &CheckContext) -> std::io::Result<()>; }

// visible for testing (crate-privat, in den Unit-Tests dieses Moduls geprueft):
pub(crate) fn prepare_recovery_dir(ctx: &CheckContext) -> std::io::Result<PathBuf>;
pub(crate) fn prepare_step_parent(ctx: &CheckContext, recovery_dir: &Path, clear_name: &str)
    -> std::io::Result<CiphertextDirectory>;
pub(crate) fn clear_name_to_be_shortened(threshold: u32) -> String;
pub(crate) fn run_id(rng: &mut dyn Rng) -> String;
```

**Java-Vorlage: `OrphanContentDir.fix` (cryptofs 2.10.0), Schritt für Schritt.**

- [ ] **Step 1: Failing test**

```rust
#[test]
fn the_orphan_fix_adopts_the_lost_files_into_lost_and_found() {
    let (_tmp, vault, ctx) = open_broken();
    let before = run("dirid", &ctx);
    let orphan = before.iter().find(|r| r.message.starts_with("Orphan directory:")).expect("an orphan");
    orphan.fix.as_ref().expect("the orphan is fixable").apply(&ctx).expect("adoption succeeds");

    // Das Waisenverzeichnis ist weg …
    assert!(!ctx.resolve(&orphan.paths[0]).exists(), "the orphaned content dir was removed");
    // … und ein LOST+FOUND-Knoten steht in der Vault-Wurzel.
    let root = cryptomator_core::root_content_dir(&vault, &ctx.cryptor);
    let lost_and_found = ctx.cryptor.file_name_cryptor().encrypt_filename("LOST+FOUND", &[b""]) + ".c9r";
    let dir_file = root.join(&lost_and_found).join("dir.c9r");
    assert_eq!(std::fs::read_to_string(&dir_file).unwrap(), "recovery");

    // Der Fund ist nach dem Fix verschwunden, und der Vault ist wieder vollstaendig gesund
    // in dem Sinne, dass kein Waisenverzeichnis mehr uebrig ist.
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
    // Der Waise hatte eine dirid.c9r, also konnten die echten Namen entschluesselt werden.
    assert!(adopted.iter().any(|e| e.name == "adopted.txt"), "{adopted:#?}");
}

#[test]
fn applying_the_orphan_fix_twice_is_harmless() {
    let (_tmp, _vault, ctx) = open_broken();
    let orphan = run("dirid", &ctx).into_iter().find(|r| r.message.starts_with("Orphan directory:")).unwrap();
    orphan.fix.as_ref().unwrap().apply(&ctx).unwrap();
    // Der zweite Aufruf trifft ein Verzeichnis, das es nicht mehr gibt: NotFound ist kein Fehler.
    orphan.fix.as_ref().unwrap().apply(&ctx).expect("second run is a no-op");
}
```

Die genauen Namen `CryptoFs::open`, `CryptoFsOptions::default`, `CleartextPath::root`, `fs.read_dir` und das Feld `DirEntry::name` sind aus M3 zu übernehmen; sie stehen in `crates/cryptomator-core/tests/crypto_fs_fixtures.rs` und werden dort schon genau so verwendet – der Implementierende liest die Signaturen dort nach, statt sie zu erraten (`grep -n "CryptoFs::" crates/cryptomator-core/tests/crypto_fs_fixtures.rs`).

- [ ] **Step 2: Lauf – muss fehlschlagen**

Run: `cargo test -p cryptomator-core --test health --locked orphan`
Expected: FAIL, `the orphan is fixable` panickt (in Task 4 hat `orphan_content_dir` noch keinen Fix).

- [ ] **Step 3: `prepare_recovery_dir`**

```rust
/// `OrphanContentDir.prepareRecoveryDir`: legt `/LOST+FOUND` an (dirId "recovery") und gibt das
/// zugehoerige Inhaltsverzeichnis zurueck -- absolut, weil die Adoption dorthin verschiebt.
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
`symlink_metadata` statt `exists()`, weil Java `Files.notExists(…, NOFOLLOW_LINKS)` prüft.

- [ ] **Step 4: `prepare_step_parent`, `clear_name_to_be_shortened`, `run_id`**

```rust
/// `OrphanContentDir.prepareStepParent`: ein Unterverzeichnis von LOST+FOUND, dessen Klarname der
/// Hash des Waisenverzeichnisses ist (`<2 Zeichen><30 Zeichen>`), damit man es wiederfindet.
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
    // FileAlreadyExists = ein frueherer Reparaturversuch war schon hier; Java faengt genau das ab.
    if let Err(e) = ctx.rng(|rng| crate::fs::dir_id::write_dir_id_backup(&ctx.cryptor, &ct, rng)) {
        if e.kind() != std::io::ErrorKind::AlreadyExists { return Err(e); }
    }
    Ok(ct)
}

/// `OrphanContentDir.createClearnameToBeShortened`. Die Rechnung stammt aus Java und ist dort
/// schief (`%` statt `/`), wird aber bewusst nachgebaut: sie erzeugt nur einen Namen, der lang
/// genug ist, um verkuerzt zu werden, und beide Programme sollen dieselben Namen vergeben.
pub(crate) fn clear_name_to_be_shortened(threshold: u32) -> String {
    let needed = (threshold as i64 - 4) / 4 * 3 - 16;
    let times = (needed.rem_euclid(LONG_NAME_SUFFIX_BASE.len() as i64) + 1) as usize;
    LONG_NAME_SUFFIX_BASE.repeat(times)
}

/// `Integer.toString((short) UUID.randomUUID().getMostSignificantBits(), 32)`: die unteren 16 Bit
/// als *vorzeichenbehaftete* Zahl zur Basis 32 mit den Ziffern 0-9a-v; negative Werte bekommen ein
/// fuehrendes '-'.
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

Unit-Tests im selben Modul: `clear_name_to_be_shortened(220)` ergibt `needed = 146`, `146 % 17 = 10`, also 11 Wiederholungen à 17 Zeichen = 187 Zeichen; `run_id` liefert für `[0x00, 0x00]` `"0"`, für `[0xff, 0xff]` `"-1"` und für `[0x00, 0x21]` `"11"` (33 = 1·32 + 1).

- [ ] **Step 5: `AdoptOrphan::apply`**

```rust
impl Fix for AdoptOrphan {
    fn apply(&self, ctx: &CheckContext) -> std::io::Result<()> {
        let orphan = ctx.resolve(&self.content_dir);
        if !orphan.is_dir() { return Ok(()); }            // schon adoptiert (Idempotenz)
        // Klarname des Stiefeltern-Verzeichnisses = der Hash des Waisen, also `<XX><YYY…>`.
        let hash_name = format!("{}{}",
            self.content_dir.parent().and_then(Path::file_name).unwrap_or_default().to_string_lossy(),
            self.content_dir.file_name().unwrap_or_default().to_string_lossy());

        let recovery_dir = prepare_recovery_dir(ctx)?;
        if recovery_dir == orphan { return Ok(()); }      // LOST+FOUND war selbst der Waise
        let step_parent = prepare_step_parent(ctx, &recovery_dir, &hash_name)?;

        let run = ctx.rng(run_id);
        let long_suffix = clear_name_to_be_shortened(ctx.config.shortening_threshold);
        let dir_id = crate::fs::dir_id::read_dir_id_backup(&ctx.cryptor, &orphan).ok();
        let (mut files, mut dirs, mut links) = (1u32, 1u32, 1u32);

        let mut entries: Vec<_> = std::fs::read_dir(&orphan)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);    // deterministische Nummerierung
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
        for entry in std::fs::read_dir(&orphan)? {           // alles, was nicht Cryptomator gehoert
            let entry = entry?;
            move_path(&entry.path(), &step_parent.path.join(entry.file_name()))?;
        }
        std::fs::remove_dir(&orphan)
    }
}
```

Die vier Helfer:
- `matches_encrypted_content_pattern(name)` = `name.chars().count() >= MIN_CIPHER_NAME_LENGTH && (name.ends_with(".c9r") || name.ends_with(".c9s"))` (Javas `DirectoryStreamFactory`-Filter).
- `determine_type(path)` = `dir.c9r` vorhanden → `Directory`, sonst `symlink.c9r` → `Symlink`, sonst `File` (`symlink_metadata`, kein Folgen).
- `decrypt_orphan_name(ctx, path, shortened, dir_id)` liest bei `shortened` die `name.c9s`, sonst den Dateinamen, schneidet die letzten 4 Zeichen (`.c9r`) ab und ruft `ctx.cryptor.file_name_cryptor().decrypt_filename(&name, &[dir_id])`; jeder Fehler ergibt `None` (Java loggt eine Warnung und fällt auf den Zählernamen zurück).
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
  `BASE64URL` ist `data_encoding::BASE64URL` (mit Padding) wie in `fs/long_names.rs::deflate`; `sha1` benutzt `sha1::Sha1` wie dort. Der Implementierende übernimmt beide Zeilen aus `crates/cryptomator-core/src/fs/long_names.rs`, damit die Deflation bitgleich zur restlichen Codebasis bleibt.
- `move_path(from, to)` ist `std::fs::rename` mit einem Fallback auf Kopieren-und-Löschen bei `ErrorKind::CrossesDevices` (der Waise und LOST+FOUND liegen beide unter `d/`, also praktisch nie – aber ein Vault kann über Mount-Grenzen zusammengesetzt sein).

- [ ] **Step 6: Den Fix an `orphan_content_dir` hängen**

In `dir_id.rs` bekommt der `OrphanContentDir`-Zweig
```rust
.with_fix(Box::new(crate::health::orphan::AdoptOrphan { content_dir: rel.clone() }))
```
wobei `rel` der vault-relative Pfad `d/XX/YYY…` ist.

- [ ] **Step 7: Tests, Gate, Commit**

Run: `cargo test -p cryptomator-core --test health --locked && cargo test -p cryptomator-core health::orphan --locked`
Expected: alle grün.

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked`

```bash
git add crates/cryptomator-core/src/health crates/cryptomator-core/tests/health.rs
git commit -m "feat(core): adopt orphaned content directories into LOST+FOUND

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 6: `CiphertextFileTypeCheck` und `ShortenedNamesCheck`

**Files:**
- Create: `crates/cryptomator-core/src/health/file_type.rs`, `crates/cryptomator-core/src/health/shortened.rs`
- Modify: `crates/cryptomator-core/src/health/mod.rs` (`all_checks` – die letzten beiden Placeholder verschwinden)
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

// crate-privat, `visible for testing` wie in Java:
pub(crate) enum SyntaxResult { Valid, Invalid, TrailingBytes }
pub(crate) fn check_syntax(long_name: &str) -> SyntaxResult;
pub(crate) fn deflate_name(long_name: &str) -> String;      // BASE64URL(SHA1(name)) + ".c9s"
```

**Java-Vorlage, wörtlich.** Beide Checks laufen mit Tiefenlimit **3** ab `d/` (also bis `d/XX/YYY…/name.c9r`) und betrachten nur **Verzeichnisse**.

`CiphertextFileTypeCheck` (Name „Resource Type Check"): für jedes Verzeichnis, dessen Name auf `.c9r` oder `.c9s` endet, wird die Menge der Typdateien bestimmt – `dir.c9r` → DIRECTORY, `symlink.c9r` → SYMLINK, und **nur bei `.c9s`** auch `contents.c9r` → FILE (jeweils `Files.isRegularFile(…, NOFOLLOW_LINKS)`):

| Größe der Menge | Ergebnis | Severity | Meldung | Fix |
|---|---|---|---|---|
| 0 | `UnknownType` | CRITICAL | `C9r dir %s of unknown type.` | `Files.delete(pathToVault.resolve(cipherDir))` |
| 1 | `KnownType` | GOOD | `Node %s with determined type %s.` (Typ als `DIRECTORY`/`SYMLINK`/`FILE`) | – |
| >1 | `AmbiguousType` | CRITICAL | `Node %s of ambiguous type. Possible types are: %s` | – |

Die Typmenge in `AmbiguousType` wird wie Javas `EnumSet.toString()` gedruckt: `[DIRECTORY, SYMLINK]` in **Enum-Deklarationsreihenfolge** – in `CiphertextFileType` (cryptofs `common/CiphertextFileType`) ist das `FILE, DIRECTORY, SYMLINK`. Unser `crate::fs::CiphertextFileType` hat dieselbe Reihenfolge; der Implementierende prüft das mit `grep -n "enum CiphertextFileType" -A 6 crates/cryptomator-core/src/fs/ciphertext_path.rs` und sortiert beim Formatieren danach.

`ShortenedNamesCheck` (Name „Shortened Names Check"): für jedes Verzeichnis, dessen Name auf `.c9s` endet:

| Bedingung | Ergebnis | Severity | Meldung | Fix |
|---|---|---|---|---|
| `name.c9s` fehlt oder ist keine reguläre Datei | `MissingLongName` | CRITICAL | `Shortened resource %s either misses name.c9s or the file has invalid content.` | – |
| Größe > 10240 | `ObeseNameFile` | CRITICAL | `Long filename file %s with size %d exceeds limit of %d for this type.` | – |
| Syntax `Invalid` | `NotDecodableLongName` | CRITICAL | `String "%s" stored in %s is not a valid Cryptomator filename.` (longName, nameFile) | – |
| Syntax `TrailingBytes` | `TrailingBytesInNameFile` | WARN | `Encrypted filename "%s" stored in %s contains trailing bytes.` | auf `…​.c9r` kürzen |
| Verzeichnisname ≠ `deflate(longName)` | `LongShortNamesMismatch` | WARN | `Name of %s is not a base64url encoded SHA1 hash of String inside name.c9s.` | `rename(c9sDir, sibling(expectedShortName))` |
| sonst | `ValidShortenedFile` | GOOD | `Found valid shortened resource at %s.` | – |

`check_syntax` (Javas `DirVisitor.checkSyntax`, Bug cryptofs#121):
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
Javas `BaseEncoding.base64Url().canDecode` akzeptiert padded und unpadded Eingaben; `data_encoding::BASE64URL` ist padded. Für echte Cryptomator-Namen (immer padded, Länge ≡ 0 mod 4) ist das identisch; der Unterschied betrifft nur kaputte Eingaben, wo beide „invalid" sagen sollen und wir es strenger tun. Als Kommentar festhalten.

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
    // Der Fund bleibt: Javas `Files.delete` raeumt nur *leere* Verzeichnisse, und das
    // Fixture-Verzeichnis enthaelt die Datei `x` (ein leeres Verzeichnis ueberlebt git nicht).
    assert_eq!(count(&after, "C9r dir "), 1, "a non-empty unknown node is not deleted");
}

#[test]
fn an_empty_unknown_node_is_deleted() {
    let (_tmp, _vault, ctx) = open_broken();
    // Dasselbe wie im Fixture, nur leer -- so wie es aussieht, wenn die Desktop-App es erzeugt.
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

Damit dieser Test kompiliert, sind `check_syntax`, `deflate_name` und `SyntaxResult` `pub` statt `pub(crate)` und das Modul `shortened` `pub` – das ist die Rust-Entsprechung von Javas „visible for testing".

- [ ] **Step 2: Lauf – muss fehlschlagen**

Run: `cargo test -p cryptomator-core --test health --locked`
Expected: FAIL (die Placeholder liefern nichts).

- [ ] **Step 3: `file_type.rs` implementieren**

Ein rekursiver Walk ab `d/` mit Tiefenlimit 3, der nur Verzeichnisse betrachtet. Ein I/O-Fehler beim Traversieren erzeugt – wie Javas `catch (IOException)` – **einen** Befund
`DiagnosticResult::new(TYPE_CHECK_ID, Severity::Critical, "Check failed: Traversal of data dir failed. See log for details.".into(), vec![])`
und beendet den Check. `UnknownType::fix` ist `std::fs::remove_dir(ctx.resolve(&cipher_dir))` mit `NotFound` als Erfolg; Java benutzt `Files.delete`, das an einem *nicht leeren* Verzeichnis scheitert – wir übernehmen das. Ein `remove_dir_all` wäre bequemer und falsch: in einem Knoten unbekannten Typs können Nutzdaten liegen (eine `contents.c9r` in einem `.c9r`- statt `.c9s`-Verzeichnis etwa), und ein Fix darf nie löschen, was er nicht versteht.

Das erklärt die zweigeteilte Zusicherung in Step 1: das eingecheckte Fixture enthält in `unknown.c9r/` die Datei `x` (ein leeres Verzeichnis überlebt git nicht), sein Fund bleibt also nach `--fix` bestehen; der Zusatztest `an_empty_unknown_node_is_deleted` legt einen wirklich leeren Knoten an und zeigt, dass der Fix dort greift.

- [ ] **Step 4: `shortened.rs` implementieren**

Derselbe Walk mit Tiefenlimit 3, nur `.c9s`-Verzeichnisse. Die Reihenfolge der Prüfungen ist die Java-Reihenfolge (fehlend → obese → Syntax → Deflation → gültig), jeder Zweig endet mit `return`. `deflate_name` ist wörtlich `crate::fs::long_names::deflate`s Rechnung, aber auf einem `&str` statt einem Pfad – der Implementierende zieht die drei Zeilen aus `fs/long_names.rs::deflate` heraus in eine gemeinsame `pub(crate) fn deflate_str(name: &str) -> String` und lässt beide Aufrufer darauf zeigen (DRY; `deflate` selbst bleibt in seiner Signatur unverändert, damit M3-Code nicht angefasst wird).

Die beiden Fixes:
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
        if to.exists() { return Ok(()); }        // schon umbenannt (Idempotenz)
        std::fs::rename(from, to)
    }
}
```

- [ ] **Step 5: `all_checks` fertigstellen**

`health/mod.rs`: die zwei restlichen `Placeholder`-Zeilen durch `Box::new(file_type::CiphertextFileTypeCheck)` und `Box::new(shortened::ShortenedNamesCheck)` ersetzen, `struct Placeholder` samt `impl` **löschen**, `pub mod file_type; pub mod shortened;` ergänzen.

- [ ] **Step 6: Tests, Gate, Commit**

Run: `cargo test -p cryptomator-core --test health --locked`
Expected: alle grün, inklusive `a_healthy_vault_passes_all_three_checks` über sieben Fixtures.

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked`

```bash
git add crates/cryptomator-core/src/health crates/cryptomator-core/tests/health.rs
git commit -m "feat(core): ciphertext file type and shortened names health checks

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 7: Der Textreport im Format von `ReportWriter`

**Files:**
- Create: `crates/cryptomator-core/src/health/report.rs`
- Modify: `crates/cryptomator-core/src/health/mod.rs` (`pub mod report;`), `crates/cryptomator-core/src/lib.rs` (Re-Export)
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
pub const CHECK_SEPARATOR: &str = "------------------------------";   // 30 Bindestriche

/// `healthReport_<vaultName>_<yyyyMMdd-HHmmss>.log` -- Javas Dateiname, aber UTC (Ruling 5).
pub fn report_file_name(vault_name: &str, at: std::time::SystemTime) -> String;

/// Schreibt den Report von `ReportWriter.writeReport`. `sections` ist eine Liste aus
/// (Check-Anzeigename, seine Ergebnisse in Fundreihenfolge).
pub fn render_report(
    vault_id: &str,
    vault_name: &str,
    vault_path: &std::path::Path,
    sections: &[(&str, Vec<&DiagnosticResult>)],
) -> String;

pub fn write_report(path: &std::path::Path, contents: &str) -> std::io::Result<()>;
```

**Java-Vorlage, wörtlich (`ui/health/ReportWriter.java`).** Drei Formatstrings, ein Zeitformat:

```java
REPORT_HEADER = """
    *******************************************
    *     Cryptomator Vault Health Report     *
    *******************************************
    Analyzed vault: %s (Current name "%s")
    Vault storage path: %s
    """;                                          // vaultConfig.getId(), displayName, path
REPORT_CHECK_HEADER = "\n\nCheck %s\n------------------------------\n";   // zwei Leerzeilen davor
REPORT_CHECK_RESULT = "%8s - %s\n";                                       // Severity rechtsbuendig auf 8
TIME_STAMP = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss");
```
(Im Original stehen in `REPORT_CHECK_HEADER` zwei Zeilen aus je drei Leerzeichen; Javas Text-Blocks entfernen abschließenden Leerraum je Zeile, es bleiben zwei Leerzeilen.)

Nach dem Check-Header folgt `"STATUS: SUCCESS\nRESULTS:\n"` und dann je Ergebnis eine Zeile aus `REPORT_CHECK_RESULT`. Die Zweige `CANCELED` und `FAILED` gibt es bei uns nicht: `crypto health` bricht nichts ab, und ein Check, der nicht laufen kann, meldet das als `CheckFailed`-Befund innerhalb von `SUCCESS`.

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

Die 1788534245 ist mit `date -u -r 1788534245 +%Y%m%d-%H%M%S` gegenzuprüfen; weicht sie ab, wird die Konstante im Test korrigiert, nicht die Formatierung.

- [ ] **Step 2: Lauf – muss fehlschlagen**

Run: `cargo test -p cryptomator-core health::report --locked`
Expected: FAIL, Modul fehlt.

- [ ] **Step 3: Implementieren**

`render_report` baut die Zeichenkette mit `write!` in einen `String`. Die Severity-Spalte ist `format!("{:>8}", severity.as_str())`. Der Dateiname:

```rust
pub fn report_file_name(vault_name: &str, at: std::time::SystemTime) -> String {
    // Alles, was einen Pfad aufspannen koennte, faellt raus -- der Anzeigename kommt aus
    // settings.json und ist damit Nutzereingabe.
    let safe: String = vault_name
        .chars()
        .map(|c| if c.is_alphanumeric() || matches!(c, '-' | '_' | '.') { c } else { '_' })
        .collect();
    format!("healthReport_{safe}_{}.log", compact_utc(at))
}
```
`compact_utc` ist derselbe Zivilkalender-Algorithmus wie in `crates/crypto/src/output.rs::format_timestamp`, nur mit dem Format `yyyyMMdd-HHmmss`. Damit er nicht zweimal existiert, wandert die Umrechnung „Sekunden seit Epoch → (y, m, d, h, min, s)" in `report.rs` als `pub fn civil_utc(at: SystemTime) -> (i64, u32, u32, u32, u32, u32)`, und Task 14 stellt `crypto::output::format_timestamp` darauf um. In diesem Task bleibt `output.rs` unverändert; der doppelte Algorithmus lebt eine Task lang.

`write_report` ist `std::fs::write` mit `CREATE | TRUNCATE` (Javas Optionen) – also schlicht `std::fs::write(path, contents)`.

- [ ] **Step 4: Lauf und Gate**

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

### Task 8: `crypto health` – Kommando, Exit 11, JSON und Report

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

**Dieser Task liefert `--fix` noch nicht.** `args.fix` wird geparst und in Step 5 mit einer klaren Meldung abgelehnt; Task 9 füllt ihn.

- [ ] **Step 1: Failing CLI-Tests**

`crates/crypto/tests/cli_health.rs`:

```rust
mod common;
use common::Sandbox;
use predicates::prelude::*;
use serde_json::Value;

/// Registriert ein Fixture unter seinem Namen und gibt den Vault-Pfad zurueck.
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
    // Nur der shortened-Check ohne CRITICAL-Fund: der Trailing-Bytes-Fall ist WARN …
    fx.crypto(&["health", "broken_health", "--check", "dirid", "--fail-on", "WARN", "--no-report"])
        .env("CRYPTO_PASSWORD", "test-password-123")
        .assert()
        .code(11);
    // … waehrend `dirid` auch einen CRITICAL-Fund hat, also beide Schwellen greifen. Der Beleg,
    // dass die Schwelle wirkt, kommt vom gesunden Vault: dort ist auch WARN folgenlos.
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
    // Ein Vault, dessen Zustand nicht LOCKED ist, ist Exit 5. Ohne Daemon laesst sich das mit
    // einem Vault nachstellen, dessen vault.cryptomator fehlt: dann ist der Zustand
    // VAULT_CONFIG_MISSING.
    let fx = Sandbox::new();
    let path = vault(&fx, "siv_gcm_basic");
    std::fs::remove_file(path.join("vault.cryptomator")).unwrap();
    for entry in std::fs::read_dir(&path).unwrap() {
        let entry = entry.unwrap();
        if entry.file_name().to_string_lossy().starts_with("vault.cryptomator.") {
            std::fs::remove_file(entry.path()).unwrap();     // sonst greift der bkup-Restore
        }
    }
    fx.crypto(&["health", "siv_gcm_basic", "--no-report"])
        .env("CRYPTO_PASSWORD", "test-password-123")
        .assert()
        .code(5);
}
```

`Sandbox::add_fixture` gibt es schon (`crates/crypto/tests/common/mod.rs:167`); es kopiert ein Fixture in die Sandbox und registriert es. Der Implementierende prüft mit `sed -n '160,190p' crates/crypto/tests/common/mod.rs`, ob es den Pfad zurückgibt, und passt die Hilfsfunktion `vault` an, falls nicht.

- [ ] **Step 2: Lauf – muss fehlschlagen**

Run: `cargo test -p crypto --test cli_health --locked`
Expected: FAIL, `unrecognized subcommand 'health'`.

- [ ] **Step 3: Grammatik und Exit-Code**

`exit.rs`: `pub const HEALTH_FINDINGS: u8 = 11;` (nur die Konstante; sie wird direkt vom Kommando zurückgegeben, nicht über einen Fehlertyp – ein Befund ist kein Fehler).
`cli.rs`: `HealthArgs` wie oben und `Command::Health(HealthArgs)` mit dem Doc-Kommentar `/// Check a vault for structural damage and optionally repair it`.
`main.rs`: `Command::Health(args) => commands::health::run(&ctx, args),`.

- [ ] **Step 4: Das Kommando**

```rust
pub fn run(ctx: &Ctx, args: HealthArgs) -> Result<u8> {
    let (vault, path) = locked_vault(ctx, &args.vault)?;         // Exit 5 fuer alles nicht-LOCKED
    let fail_on = Severity::parse_threshold(&args.fail_on)?;
    let ids = if args.check.is_empty() { CHECK_IDS.map(String::from).to_vec() } else { args.check.clone() };
    let checks = checks_by_ids(&ids)?;                            // Exit 2 bei unbekanntem Namen
    let passphrase = read_passphrase_with_keychain(
        &args.password, "Password: ",
        || Ok(keychain_source(ctx.keychain()?.as_ref(), &vault)),
        &mut SystemIo,
    )?;
    let opened = open_vault(&path, &MasterkeyFileAccess::new(Vec::new()), &passphrase)?;
    let vault_id = opened.config.id.clone();
    let check_ctx = CheckContext::new(opened);
    let results = run_checks(&checks, &check_ctx);
    // … Report, Ausgabe, Exit-Code (Steps 5-7)
}
```

Reihenfolge ist Absicht: `--fail-on`/`--check` werden **vor** der Passwortabfrage validiert, damit ein Tippfehler nicht erst nach einem Prompt auffällt.

- [ ] **Step 5: `--fix` vorerst ablehnen**

```rust
if args.fix {
    return Err(AppError::InvalidValue {
        key: "--fix".to_string(),
        message: "not implemented yet".to_string(),
    }.into());
}
```
Task 9 ersetzt diesen Block; bis dahin ist `--fix` ein sauberer Exit 2 statt einer Lüge. Der Marker `not implemented yet` ist der einzige im Repo und wird in Task 9 mit `grep -rn "not implemented yet" crates/` gefunden.

- [ ] **Step 6: Report schreiben**

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

- [ ] **Step 7: Ausgabe und Exit-Code**

```rust
pub(crate) fn to_json(result: &DiagnosticResult, fixed: Option<bool>) -> serde_json::Value {
    json!({
        "check": result.check,
        "severity": result.severity.as_str(),
        "message": result.message,
        "paths": result.paths,
        "fixable": result.fixable(),
        "fixed": fixed,            // ohne --fix immer null
    })
}
```
`--json` liefert **ein** Objekt (wie überall im CLI):
```json
{ "vault": "…id…", "path": "/vaults/Secret", "checks": ["dirid","type","shortened"],
  "report": "/…/healthReport_….log", "summary": {"GOOD": 12, "INFO": 1, "WARN": 2, "CRITICAL": 3},
  "failOn": "CRITICAL", "findings": [ … ] }
```
Die Menschenausgabe ist eine Zeile je Befund im Reportformat (`{:>8} - {message}`) **ohne** die `GOOD`-Zeilen (die sind Rauschen auf einem Terminal), dahinter eine Zusammenfassung
`12 good, 1 info, 2 warnings, 3 critical` und, wenn ein Report geschrieben wurde, dessen Pfad auf stderr.

```rust
let worst = results.iter().map(|r| r.severity).max().unwrap_or(Severity::Good);
Ok(if worst >= fail_on { exit::HEALTH_FINDINGS } else { exit::OK })
```

- [ ] **Step 8: Tests, Gate, Commit**

Run: `cargo test -p crypto --test cli_health --locked`
Expected: 7 passed.

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked`

```bash
git add crates/crypto/src crates/crypto/tests/cli_health.rs
git commit -m "feat(cli): crypto health with exit code 11, JSON output and a text report

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 9: `crypto health --fix` und `--fix-severity`

**Files:**
- Modify: `crates/crypto/src/commands/health.rs`, `crates/crypto/tests/cli_health.rs`

**Interfaces:**
- Consumes: alles aus Task 8, plus `DiagnosticResult::fix` und `Fix::apply`.
- Produces: keine neuen öffentlichen Namen; `commands::health::run` bekommt den `--fix`-Pfad.

**Ruling 4 im Detail.** `--fix` läuft so ab:
1. Erster Lauf: alle gewählten Checks.
2. Für jeden Befund mit `severity >= fix_severity` **und** `fix.is_some()`: `fix.apply(&check_ctx)`. Erfolg → `fixed: true`, Fehler → `fixed: false` plus eine Warnung auf stderr mit der Meldung des Befunds und dem I/O-Fehler. Ein fehlgeschlagener Fix bricht den Lauf **nicht** ab; der nächste Befund ist davon unabhängig.
3. Zweiter Lauf derselben Checks auf demselben `CheckContext`.
4. Ausgabe: beide Läufe; Exit-Code aus dem **zweiten**.

Die Reihenfolge der Fixes ist die Fundreihenfolge. Das ist wichtig für `dirid`: `CreateContentDir` (MissingContentDir) läuft vor `AdoptOrphan` (OrphanContentDir), weil Phase 2 des Checks erst die Paare auflöst und dann die Waisen meldet — ein Verzeichnis, das gerade erst angelegt wurde, kann also nicht im selben Durchgang als Waise adoptiert werden.

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
        .code(11)                       // die CRITICAL-Faelle ohne Fix bleiben
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&out).unwrap();
    let before = value["before"]["findings"].as_array().unwrap();
    let after = value["after"]["findings"].as_array().unwrap();
    // Vorher: die drei WARN-Faelle mit Fix wurden repariert …
    assert!(before.iter().any(|f| f["fixed"] == true));
    // … und tauchen nachher nicht mehr auf.
    for message in ["Orphan directory:", "dir.c9r file (", "Encrypted filename ", "Name of "] {
        assert!(
            !after.iter().any(|f| f["message"].as_str().unwrap().starts_with(message)),
            "{message} survived --fix: {after:#?}"
        );
    }
    // INFO bleibt: --fix-severity ist WARN.
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
    // Die heile Datei ist unveraendert, und die adoptierte taucht unter LOST+FOUND auf.
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

- [ ] **Step 2: Lauf – muss fehlschlagen**

Run: `cargo test -p crypto --test cli_health --locked fix`
Expected: FAIL mit Exit 2 (`--fix: not implemented yet`).

- [ ] **Step 3: Den Ablehnungsblock ersetzen**

`grep -n "not implemented yet" crates/crypto/src/commands/health.rs` findet den Block aus Task 8, Step 5. An seine Stelle kommt nach dem ersten `run_checks`:

```rust
let fix_severity = Severity::parse_threshold(&args.fix_severity)?;   // schon oben, vor dem Passwort
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

- [ ] **Step 4: Ausgabe für beide Läufe**

Ohne `--fix` bleibt das JSON von Task 8 unverändert (Rückwärtskompatibilität für Skripte). Mit `--fix` bekommt es die Form

```json
{ "vault": "…", "path": "…", "checks": [ … ], "report": "…", "failOn": "CRITICAL",
  "fixSeverity": "WARN",
  "before": { "summary": { … }, "findings": [ … mit "fixed": true|false|null … ] },
  "after":  { "summary": { … }, "findings": [ … "fixed": null … ] } }
```
Das Feld `findings` auf oberster Ebene fehlt dann; `before`/`after` fehlen ohne `--fix`. Ein Skript unterscheidet die beiden Formen an genau der Flagge, die es selbst gesetzt hat.

Menschenausgabe mit `--fix`:
```
before the fixes
    WARN - Orphan directory: d/AB/CDEF…            [fixed]
CRITICAL - File d/…/dir.c9r is empty, expected content
12 good, 1 info, 2 warnings, 3 critical

after the fixes
CRITICAL - File d/…/dir.c9r is empty, expected content
15 good, 1 info, 0 warnings, 1 critical
```
Das Suffix ist `[fixed]` bei `Some(true)` und `[fix failed]` bei `Some(false)`.

Der Report (Task 8, Step 6) wird mit den Ergebnissen des **zweiten** Laufs geschrieben – er soll den Zustand beschreiben, in dem der Vault jetzt ist.

Exit-Code: `worst` über `second.as_ref().unwrap_or(&first)`.

- [ ] **Step 5: Tests, Gate, Commit**

Run: `cargo test -p crypto --test cli_health --locked`
Expected: 12 passed.

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked`

```bash
git add crates/crypto/src/commands/health.rs crates/crypto/tests/cli_health.rs
git commit -m "feat(cli): crypto health --fix with a second pass and before/after output

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 10: `migration/{mod,v6,v8}.rs` – Versionserkennung, 5→6 und 7→8

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
    pub fn from_version(v: u32) -> Option<Self>;      // 5|6|7 -> Some, sonst None
    pub fn as_str(self) -> &'static str;              // "5->6" | "6->7" | "7->8"
}

#[derive(Debug, Clone)]
pub struct MigrationPlan {
    pub from_version: u32,
    pub steps: Vec<MigrationStep>,
    /// Nur fuer 6->7 gefuellt (Task 11); sonst leer.
    pub renames: Vec<PlannedRename>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedRename { pub from: PathBuf, pub to: PathBuf }   // beide vault-relativ

/// `FileSystemCapabilityChecker.assertAllCapabilities`
pub fn assert_all_capabilities(vault_path: &Path) -> Result<()>;

#[derive(Debug)]
pub struct Migrators;
impl Migrators {
    pub fn needs_migration(vault_path: &Path) -> Result<bool>;
    pub fn plan(vault_path: &Path) -> Result<MigrationPlan>;
    /// Migriert Schritt fuer Schritt bis Format 8. `progress` wird vor jedem Schritt gerufen.
    pub fn migrate(
        vault_path: &Path,
        passphrase: &str,
        full_scan_allowed: bool,
        progress: &mut dyn FnMut(MigrationStep),
        rng: &mut dyn Rng,
    ) -> Result<Vec<MigrationStep>>;
}
```
und die neuen Fehler:
```rust
// crates/cryptomator-core/src/error.rs
#[error("the storage does not support {capability}: {path}")]
MissingCapability { path: PathBuf, capability: &'static str },   // "read access" | "write access"
#[error("ciphertext name too long for this storage: {path} needs {needed} chars, the storage allows {allowed}")]
FileNameTooLong { path: PathBuf, needed: usize, allowed: usize },
#[error("migration cannot continue: {0}")]
MigrationBlocked(String),
```
Alle drei kommen in `exit.rs::core_code` in die `GENERAL`-Gruppe, bis auf `MigrationBlocked`, das nach `WRONG_STATE` (5) geht: „der Vault ist so, wie er ist, nicht migrierbar" ist genau der Zustandsfehler.

**Java-Vorlage.** `Migrators.determineVaultVersion` (haben wir schon als `determine_vault_version`), `Migration.isApplicable` (5→6, 6→7, 7→8), `Version6Migrator`, `Version8Migrator`, `FileSystemCapabilityChecker.assertAllCapabilities`.

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
    // Backup der alten Datei liegt daneben.
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
    // Die Masterkey-Datei traegt jetzt 999 und oeffnet mit derselben Passphrase.
    let raw = std::fs::read(vault.join("masterkey.cryptomator")).unwrap();
    assert_eq!(MasterkeyFileAccess::read_alleged_vault_version(&raw).unwrap(), 999);
    // Und das Ganze ist ein Vault, den open_vault akzeptiert.
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

- [ ] **Step 2: Lauf – muss fehlschlagen**

Run: `cargo test -p cryptomator-core --test migration --locked`
Expected: FAIL, Modul `migration` fehlt.

- [ ] **Step 3: `assert_all_capabilities`**

```rust
/// `FileSystemCapabilityChecker.assertAllCapabilities`: erst lesen, dann schreiben.
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
    let _ = std::fs::remove_dir_all(&check_dir);      // Java: deleteRecursivelySilently im finally
    result.map_err(|_| CoreError::MissingCapability {
        path: check_dir, capability: "write access",
    })?;
    Ok(())
}
```
Java benutzt `Files.createTempDirectory(checkDir, "write-access")`; ein fester Name reicht und macht den Test deterministisch, weil das Verzeichnis unmittelbar wieder verschwindet.

- [ ] **Step 4: `v6.rs`**

```rust
//! 5 -> 6, Port von `migration/v6/Version6Migrator.java`. Version 6 kodiert die Passphrase in
//! Unicode NFC; der Schluessel selbst bleibt derselbe.
pub fn migrate(vault_path: &Path, passphrase: &str, rng: &mut dyn Rng) -> Result<()> {
    let masterkey_file = vault_path.join(MASTERKEY_FILENAME);
    let access = MasterkeyFileAccess::new(Vec::new());
    let masterkey = access.load(&masterkey_file, passphrase)?;    // erst pruefen …
    attempt_backup(&masterkey_file)?;                             // … dann sichern (Java-Reihenfolge)
    let normalized: Zeroizing<String> = Zeroizing::new(passphrase.nfc().collect());
    access.persist(&masterkey, &masterkey_file, &normalized, 6, rng)
}
```
Die Reihenfolge „laden, dann Backup" ist Javas und wichtig: eine falsche Passphrase darf kein Backup und keine Änderung hinterlassen. `attempt_backup` ist derselbe Helfer, den `open_vault` benutzt (`.bkup`-Suffix aus SHA-256).

- [ ] **Step 5: `v8.rs`**

```rust
//! 7 -> 8, Port von `migration/v8/Version8Migrator.java`: die Masterkey-Datei wird in
//! `masterkey.cryptomator` (nur noch KDF-Parameter) und `vault.cryptomator` (Format und
//! vault-spezifische Metadaten) aufgeteilt.
pub fn migrate(vault_path: &Path, passphrase: &str, rng: &mut dyn Rng) -> Result<()> {
    let masterkey_file = vault_path.join(MASTERKEY_FILENAME);
    let config_file = vault_path.join(VAULTCONFIG_FILENAME);
    let access = MasterkeyFileAccess::new(Vec::new());
    let masterkey = access.load(&masterkey_file, passphrase)?;
    attempt_backup(&masterkey_file)?;
    // Java: SIV_CTRMAC und Threshold 220 fest -- Format 7 kannte nichts anderes.
    let config = VaultConfig::create_new(CipherCombo::SivCtrMac, 220);
    let token = config.to_token(DEFAULT_KEY_ID, masterkey.raw());
    // CREATE_NEW: eine schon vorhandene vault.cryptomator ist ein Fehler, kein Ueberschreiben.
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
`VaultConfig::create_new` setzt `vault_version = VAULT_VERSION` (8) und ein zufälliges `jti` – genau wie Javas `withJWTId(UUID.randomUUID())`. `DEFAULT_MASTERKEY_FILE_VERSION` ist 999, Javas `persist(…, 999)`.

`CipherCombo::SivCtrMac` ist der Variantenname aus `crypto/cryptor.rs`; der Implementierende prüft ihn mit `grep -n "enum CipherCombo" -A 6 crates/cryptomator-core/src/crypto/cryptor.rs`.

- [ ] **Step 6: `mod.rs` – Plan und Schleife**

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
        // Die Passphrase aendert sich in 5->6 (NFC); die folgenden Schritte brauchen die neue Form.
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
`MigrationStep::from_version` liefert für `0..=4` und `>= 8` `None`. Ein Vault mit Version 4 oder kleiner ist damit **kein Migrationsziel**; `plan()` gibt eine leere Schrittliste zurück und `migrate` tut nichts. Das Kommando in Task 12 fängt diesen Fall ab und meldet `MigrationBlocked("vault format 4 is older than this tool can migrate; use Cryptomator 1.4 or newer first")`. Java wirft dort `NoApplicableMigratorException`.

**In diesem Task existiert `v7` noch nicht.** Der `SixToSeven`-Zweig lautet bis Task 11:
```rust
MigrationStep::SixToSeven => return Err(CoreError::MigrationBlocked(
    "the 6->7 migrator arrives with the next task".to_string())),
```
Der Test `the_plan_lists_every_step_up_to_format_eight` läuft trotzdem (er migriert nicht), und `five_to_six_…`/`seven_to_eight_…` rufen die Migratoren direkt.

`lib.rs`: `pub mod migration;` plus `pub use migration::{MigrationPlan, MigrationStep, Migrators, PlannedRename};`.

- [ ] **Step 7: Tests, Gate, Commit**

Run: `cargo test -p cryptomator-core --test migration --locked`
Expected: 8 passed (die zwei aus Task 2 plus sechs neue; `stamp_legacy_v5` bleibt `#[ignore]`).

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked`

```bash
git add crates/cryptomator-core/src crates/cryptomator-core/tests/migration.rs
git commit -m "feat(core): vault migrators 5->6 and 7->8 with version detection

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 11: `migration/v7.rs` – die Namensmigration 6→7

**Files:**
- Create: `crates/cryptomator-core/src/migration/v7.rs`
- Modify: `crates/cryptomator-core/src/migration/mod.rs` (`pub mod v7;`, der `SixToSeven`-Zweig, `MigrationPlan::renames`)
- Test: `crates/cryptomator-core/tests/migration.rs`, Unit-Tests in `v7.rs`

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

/// Ein einzelner Dateiname vor der Migration. Port von `migration/v7/FilePathMigration.java`.
#[derive(Debug, Clone)]
pub struct FilePathMigration { old_path: PathBuf, old_canonical_name: String }

impl FilePathMigration {
    /// `None`, wenn der Name schon migriert ist oder gar kein Cryptomator-Name.
    pub fn parse(vault_root: &Path, old_path: &Path) -> Result<Option<Self>>;
    pub fn old_path(&self) -> &Path;
    pub fn is_directory(&self) -> bool;                       // beginnt mit "0"
    pub fn is_symlink(&self) -> bool;                         // beginnt mit "1S"
    pub fn old_canonical_name_without_type_prefix(&self) -> &str;
    pub fn decoded_ciphertext(&self) -> Result<Vec<u8>>;      // BASE32-Dekodierung
    pub fn new_inflated_name(&self) -> Result<String>;        // BASE64URL(…) + ".c9r"
    pub fn new_deflated_name(&self) -> Result<String>;        // ggf. BASE64URL(SHA1(…)) + ".c9s"
    pub fn target_path(&self, attempt_suffix: &str) -> Result<PathBuf>;
    pub fn migrate(&self) -> Result<PathBuf>;
}

pub fn inflate(vault_root: &Path, long_file_name: &str) -> Result<String>;
pub fn plan_renames(vault_root: &Path) -> Result<Vec<PlannedRename>>;
pub fn migrate(vault_root: &Path, passphrase: &str, full_scan_allowed: bool, rng: &mut dyn Rng) -> Result<()>;
```

**Java-Vorlage, wörtlich.** Die vier regulären Ausdrücke und Konstanten aus `FilePathMigration.java`:
```java
OLD_SHORTENED_FILENAME_SUFFIX = ".lng";
OLD_SHORTENED_FILENAME_PATTERN = "[A-Z2-7]{32}";
OLD_CANONICAL_FILENAME_PATTERN = "(0|1S)?([A-Z2-7]{8})*[A-Z2-7=]{8}";
BASE32 = BaseEncoding.base32();            // RFC 4648, Grossbuchstaben, '='-Padding
BASE64 = BaseEncoding.base64Url();         // mit Padding
SHORTENING_THRESHOLD = 220;
MAX_FILENAME_BUFFER_SIZE = 10 * 1024;
```
Beide Muster werden mit `find()` benutzt, **nicht** mit `matches()`: ein Name mit Konfliktsuffix wie `ABCDEFGH (1)` liefert die Gruppe `ABCDEFGH`. Ohne Regex-Crate bauen wir das von Hand nach – Step 3.

- [ ] **Step 1: Failing Unit-Tests für die Namensarithmetik**

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
        // Padding ist nur im letzten Block erlaubt.
        assert_eq!(canonical("MFRGGZDFMZTWQ2L=").as_deref(), Some("MFRGGZDFMZTWQ2L="));
        assert_eq!(canonical("nope").as_deref(), None);
        assert_eq!(canonical("SHORT").as_deref(), None);          // weniger als 8 Zeichen
    }

    #[test]
    fn base32_becomes_base64url_with_a_c9r_suffix() {
        // BASE32("Hello!!!") -> die Bytes -> BASE64URL
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
        let long = migration(&"A".repeat(8 * 40));   // 320 BASE32-Zeichen -> 200 Bytes -> 268 base64
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

Die erwartete Zeichenkette `SGVsbG8h3q2-7w==.c9r` ist mit
`python3 -c "import base64;print(base64.urlsafe_b64encode(base64.b32decode('JBSWY3DPEHPK3PXP')).decode())"`
gegenzuprüfen; weicht sie ab, wird die Konstante im Test korrigiert.

- [ ] **Step 2: Lauf – muss fehlschlagen**

Run: `cargo test -p cryptomator-core migration::v7 --locked`
Expected: FAIL, Modul fehlt.

- [ ] **Step 3: `canonical` – die beiden Muster ohne Regex-Crate**

```rust
fn is_base32_char(c: char) -> bool { c.is_ascii_uppercase() && c != '0' && c != '1' || ('2'..='7').contains(&c) }

/// Javas `OLD_CANONICAL_FILENAME_PATTERN.matcher(name).find()`: der laengste Praefix ab Position 0,
/// der `(0|1S)?([A-Z2-7]{8})*[A-Z2-7=]{8}` erfuellt. Java sucht mit `find()` an *jeder* Position;
/// bei echten v6-Namen steht der Treffer immer am Anfang (Konfliktsuffixe haengen hinten), und ein
/// Treffer in der Mitte waere ein Name, den auch Java nur zufaellig richtig migriert. Wir suchen
/// deshalb ab Position 0 und dokumentieren die Einschraenkung.
fn canonical(file_name: &str) -> Option<String> { … }
```
Der Algorithmus: Präfix `1S` oder `0` abtrennen (in dieser Reihenfolge prüfen, `1S` zuerst – `1` allein ist kein BASE32-Zeichen, also gibt es keine Mehrdeutigkeit). Vom Rest so viele volle 8er-Blöcke aus `[A-Z2-7]` nehmen wie möglich, dann muss genau ein letzter 8er-Block aus `[A-Z2-7=]` folgen. Der Treffer ist Präfix + alle konsumierten Blöcke; ist keiner vorhanden, `None`. Der Kandidat muss zusätzlich mindestens einen Block haben (Javas `*` erlaubt null Wiederholungen, aber der Pflichtblock am Ende bleibt).

Achtung, ein Java-Detail mit Folgen: der letzte Block darf `=` **an jeder Stelle** enthalten (`[A-Z2-7=]{8}`), nicht nur am Ende. `BASE32.decode` weist solche Namen später ab und liefert `InvalidOldFilenameException`; wir spiegeln das mit `CoreError::InvalidArgument`.

`FilePathMigration::parse`:
```rust
pub fn parse(vault_root: &Path, old_path: &Path) -> Result<Option<Self>> {
    let name = old_path.file_name().unwrap_or_default().to_string_lossy().into_owned();
    // Schon migriert? BASE32 ist eine Teilmenge von BASE64URL, ein reiner Mustervergleich
    // wuerde `.c9r`-Namen erneut migrieren.
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
`find_32_base32_chars` ist Javas `[A-Z2-7]{32}`-`find()`: das erste Vorkommen von 32 aufeinanderfolgenden BASE32-Zeichen irgendwo im Namen (bei `.lng`-Namen mit Konfliktsuffix steht es am Anfang, aber `find()` an jeder Position ist hier billig und bleibt Java-treu).

`inflate` liest `<vault>/m/<n[0..2]>/<n[2..4]>/<n>` mit Größenlimit `MAX_FILENAME_BUFFER_SIZE`; eine zu große oder fehlende Datei ergibt `CoreError::MigrationBlocked(format!("failed to read metadata file {}", path.display()))` — Javas `UninflatableFileException`, die die Visitors mit `SKIP` beantworten (Step 5).

- [ ] **Step 4: `migrate()` einer einzelnen Datei**

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
Genau wie Java: der Suffix wird **nach** dem Fehlschlag gesetzt, also sind die drei Versuche `""`, `"_1"`, `"_2"`. Der Suffix steht vor der Endung (`name_1.c9r`), damit der Konfliktauflöser aus M3 ihn später als „ (1)" wiedererkennt.

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

- [ ] **Step 5: Der Vorlauf und die Migration des ganzen Vaults**

`migrate(vault_root, passphrase, full_scan_allowed, rng)` folgt `Version7Migrator.migrate`:

1. `masterkey = access.load(vault_root/masterkey.cryptomator, passphrase)?`
2. `attempt_backup(&masterkey_file)?`
3. `let filename_limit = determine_supported_ciphertext_file_name_length(vault_root)?;` — unser Helfer benutzt schon `subPathLength = 46`, `min = 28`, `max = 220`, also dieselben Argumente wie Javas `determineSupportedCiphertextFileNameLength(vaultRoot.resolve("c"), 46, 28, 220)`. `let path_limit = filename_limit + 48;`
4. `let full_scan = if filename_limit >= 220 { false } else { if !full_scan_allowed { return Err(CoreError::MigrationBlocked("this storage supports only {filename_limit} characters per name (220 required); a full scan of the vault is needed to tell whether migration is possible -- rerun with --yes".into())) } else { true } };`
5. Vorlauf über `d/` mit Tiefenlimit 3, nur Dateien:
   - Name endet auf `.icloud` → `CoreError::MigrationBlocked("migration impossible due to file: {name}")` (Javas `BLACKLISTED_NAMES`, „unsynced icloud content, user needs to download the vault first").
   - `total_files += 1`
   - bei `full_scan`: `FilePathMigration::parse` und für den Zielpfad `max_name_length`/`max_path_length` fortschreiben; ein `MigrationBlocked` aus `inflate` wird hier **übersprungen** (Java: `LOG.warn("SKIP … because inflation failed")`), ein `InvalidArgument` aus dem BASE32-Dekoder ebenso.
   - ohne `full_scan` sind die Werte fest `max_name = 220`, `max_path = 268` (Javas `PreMigrationVisitor`-Getter).
6. `if max_path > path_limit { return Err(CoreError::FileNameTooLong { path: longest_path, needed: max_path, allowed: path_limit }) }`, danach dasselbe für `max_name > filename_limit`.
7. Wenn `total_files > 0`: zweiter Walk über `d/` mit Tiefenlimit 3. **Pro Verzeichnis erst sammeln, dann anwenden** (Javas `MigratingVisitor`: `visitFile` sammelt, `postVisitDirectory` migriert) – sonst läuft man über die gerade erzeugten `.c9r`-Verzeichnisse. Ein `AlreadyExists` nach drei Versuchen wird geloggt und übersprungen, nicht geworfen (Javas `catch (FileAlreadyExistsException)` im Visitor); alle anderen Fehler brechen ab.
8. `m/` rekursiv löschen (`std::fs::remove_dir_all`, `NotFound` ist ok — Javas `DeletingFileVisitor`).
9. `access.persist(&masterkey, &masterkey_file, passphrase, 7, rng)?`

`plan_renames(vault_root)` ist derselbe erste Walk, sammelt aber `PlannedRename { from, to }` mit vault-relativen Pfaden aus `target_path("")` und schreibt nichts. Kollisionen (zwei Quellen auf dasselbe Ziel) werden **nicht** aufgelöst — der `--dry-run`-Text sagt dazu „collisions get a `_1`/`_2` suffix at migration time".

- [ ] **Step 6: Integrationstest über den ganzen Weg**

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
    // Kein BASE32-Name mehr unter d/.
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

        // Der migrierte Vault laesst sich oeffnen und enthaelt genau das, was das Manifest sagt.
        let opened = cryptomator_core::open_vault(
            &vault, &MasterkeyFileAccess::new(Vec::new()), &final_pass).unwrap();
        let fs = cryptomator_core::fs::CryptoFs::open(opened, Default::default()).unwrap();
        for entry in m["expected"].as_array().unwrap() {
            let path = entry["path"].as_str().unwrap();
            let cleartext = cryptomator_core::fs::CleartextPath::parse(path).unwrap();
            assert!(fs.metadata(&cleartext).is_ok(), "{name}: {path} is missing after migration");
        }
        // Und die Health-Checks finden nichts.
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

`CleartextPath::parse` und `CryptoFs::metadata` sind aus M3; die genauen Namen stehen in `crates/cryptomator-core/tests/crypto_fs_fixtures.rs` und werden von dort übernommen. `collect_names` ist ein kleiner rekursiver Helfer in derselben Testdatei.

- [ ] **Step 7: `mod.rs` verdrahten**

`pub mod v7;`, der `SixToSeven`-Zweig ruft `v7::migrate(vault_path, &current, full_scan_allowed, rng)?`, und `Migrators::plan` füllt `renames` mit `v7::plan_renames(vault_path)?`, wenn `steps` den Schritt `SixToSeven` enthält (sonst bleibt der Vektor leer).

- [ ] **Step 8: Tests, Gate, Commit**

Run: `cargo test -p cryptomator-core --test migration --locked && cargo test -p cryptomator-core migration::v7 --locked`
Expected: alle grün. Der Test `the_whole_chain_…` ist der teuerste im Repo (drei Vaults, je bis zu drei scrypt-Läufe); wenn er über 60 s braucht, prüft der Implementierende, ob das Release-Profil für `dev.package."*"` greift (`grep -n 'opt-level' Cargo.toml`), statt den Test zu kürzen.

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
/// Wie `locked_vault`, aber `NEEDS_MIGRATION` ist erlaubt -- das ist ja der Anlass.
pub fn migratable_vault(ctx: &Ctx, reference: &str) -> Result<(VaultSettingsJson, PathBuf)>;

// crates/crypto/src/commands/migrate.rs
pub fn run(ctx: &Ctx, args: MigrateArgs) -> anyhow::Result<u8>;
```

- [ ] **Step 1: Failing CLI-Tests**

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
    // Danach ist der Vault ein ganz normaler: `crypto vault info` sagt LOCKED.
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
    // Ab jetzt gilt die NFC-Form -- und das CLI normalisiert Eingaben ohnehin nach NFC, also
    // funktionieren beide Schreibweisen beim Entsperren.
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
    // Nichts angefasst -- auch kein Backup.
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

Der letzte Test benutzt `Sandbox::{seed_keychain, crypto_keychain, fake_keychain_json, vault_id}` aus M6; die genaue Form von `fake_keychain_json` (Schlüsselname `passphrase` oder anders) ist mit `sed -n '150,170p' crates/crypto/tests/common/mod.rs` zu prüfen und die Zusicherung entsprechend zu schreiben.

- [ ] **Step 2: Lauf – muss fehlschlagen**

Run: `cargo test -p crypto --test cli_migrate --locked`
Expected: FAIL, `unrecognized subcommand 'migrate'`.

- [ ] **Step 3: `migratable_vault`**

```rust
/// Wie [`locked_vault`], aber `NEEDS_MIGRATION` ist zugelassen -- das ist der Zustand, den
/// `crypto migrate` beheben soll. Der Laufzeitteil bleibt: ein Daemon, der den Vault bedient,
/// haelt Dateien offen, und die Migration benennt sie alle um.
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

- [ ] **Step 4: Das Kommando**

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

Danach in dieser Reihenfolge:
1. Passwort holen (`read_passphrase_with_keychain` mit `keychain_source`, wie `health`).
2. Bei `--dry-run`: `emit` mit `dryRun: true`, `renames` (aus `plan.renames`, jeweils `{from, to}`) und den Schritten, dann `Ok(exit::OK)` – **ohne** die Passphrase überhaupt zu prüfen? Nein: die Passphrase wird geprüft (`MasterkeyFileAccess::load` gegen `masterkey.cryptomator`), damit ein `--dry-run` mit falschem Passwort nicht suggeriert, die Migration werde klappen. Geschrieben wird dabei nichts – `load` ist reines Lesen. Das ist der Grund, warum `a_wrong_passphrase_…` und `dry_run_…` beide sauber sind.
3. Bestätigung: ohne `--yes` und mit `std::io::stdin().is_terminal()` eine Frage auf stderr
   ```
   Vault "legacy_v6" is in format 6 and will be migrated to format 8 (steps: 6->7, 7->8).
   This rewrites file names in the vault and cannot be undone; make sure you have a backup.
   Continue? [y/N]
   ```
   und eine Zeile von stdin lesen; alles außer `y`/`yes` (case-insensitiv) ist Abbruch mit Exit 0 und der Meldung `aborted`. Ohne Terminal und ohne `--yes`:
   ```rust
   return Err(AppError::InvalidValue {
       key: "--yes".to_string(),
       message: "migration needs a confirmation; pass --yes when there is no terminal".to_string(),
   }.into());
   ```
4. `Migrators::migrate(&path, &passphrase, /* full_scan_allowed = */ true, &mut |step| { if !ctx.out.json { eprintln!("migrating {} …", step.as_str()); } }, &mut OsRng)?`
   `full_scan_allowed` ist `true`, sobald bestätigt wurde (oder `--yes` gegeben war): die Bestätigungsfrage oben ist unsere Fassung von Javas `REQUIRES_FULL_VAULT_DIR_SCAN`, und ein zweiter Dialog mitten in der Migration wäre für ein CLI unbrauchbar. Als Kommentar festhalten.
5. Bei einer Kette, die `FiveToSix` enthielt: `update_keychain_entry_or_warn(ctx, &vault, &nfc_passphrase, &args.vault, "migration")`, damit ein gespeichertes Passwort der Normalisierung folgt (Ruling: derselbe Mechanismus wie `password change`; die NFC-Form berechnet das Kommando mit `unicode_normalization`). Enthielt die Kette keinen `5->6`-Schritt, bleibt die Keychain unangetastet.
6. Ausgabe:
   ```json
   { "path": "/vaults/v", "fromVersion": 5, "toVersion": 8,
     "steps": ["5->6", "6->7", "7->8"], "dryRun": false, "keychainUpdated": true }
   ```
   Menschenform: `migrated /vaults/v from format 5 to format 8 (5->6, 6->7, 7->8)`.

`cli.rs`: `Command::Migrate(MigrateArgs)` mit `/// Bring a vault of format 5, 6 or 7 up to format 8`.
`main.rs`: `Command::Migrate(args) => commands::migrate::run(&ctx, args),`.

- [ ] **Step 5: Der Zustandsfehler an anderer Stelle prüfen**

`crypto unlock`/`fs`/`health` auf einem Legacy-Vault müssen Exit **5** liefern und im Text auf `crypto migrate` verweisen. `determine_vault_state` liefert dafür schon `NEEDS_MIGRATION`, und `locked_vault` macht daraus `AppError::WrongState`. Nur der Hinweistext fehlt: in `AppError::WrongState`s `Display` (`crates/cryptomator-app/src/error.rs`) bleibt der Text unverändert; stattdessen bekommt `locked_vault` in `commands/mod.rs` einen Sonderfall:

```rust
if state == VaultState::NeedsMigration {
    return Err(AppError::WrongState {
        expected: VaultState::Locked.as_str().to_string(),
        actual: format!("{} (run `crypto migrate {reference}` first)", state.as_str()),
    }.into());
}
```

Ein Test dafür in `cli_migrate.rs`:
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

- [ ] **Step 6: Tests, Gate, Commit**

Run: `cargo test -p crypto --test cli_migrate --locked`
Expected: 8 passed.

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked`

```bash
git add crates/crypto/src crates/crypto/tests/cli_migrate.rs
git commit -m "feat(cli): crypto migrate with confirmation, --yes and --dry-run

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 13: `recovery/restore.rs` und `crypto recovery-key restore`

**Files:**
- Create: `crates/cryptomator-core/src/recovery/restore.rs`
- Modify: `crates/cryptomator-core/src/recovery/mod.rs`, `crates/cryptomator-core/src/lib.rs`, `crates/cryptomator-core/src/error.rs`, `crates/crypto/src/cli.rs`, `crates/crypto/src/commands/recovery.rs`, `crates/crypto/src/main.rs`
- Test: `crates/cryptomator-core/tests/vault_lifecycle.rs` (Kern), `crates/crypto/tests/cli.rs` (CLI)

**Interfaces:**
- Consumes: `crate::vault::init::initialize`, `crate::masterkey_file::{MasterkeyFileAccess, DEFAULT_MASTERKEY_FILE_VERSION}`, `crate::recovery::key::decode_recovery_key`, `crate::recovery::words::WordEncoder`, `crate::crypto::{masterkey::Masterkey, cryptor::{CipherCombo, Cryptor}}`, `crate::constants::{MASTERKEY_FILENAME, VAULTCONFIG_FILENAME, DEFAULT_KEY_ID, DATA_DIR_NAME, CRYPTOMATOR_FILE_SUFFIX, DIR_FILE_NAME}`.
- Produces:
```rust
/// `common/recovery/RecoveryDirectory.java`: es wird erst in ein Temp-Verzeichnis geschrieben und
/// dann in den Vault verschoben, damit ein halb geschriebener Restore den Vault nie beruehrt.
#[derive(Debug)]
pub struct RecoveryDirectory { vault_path: PathBuf, temp: tempfile::TempDir }
impl RecoveryDirectory {
    pub fn create(vault_path: &Path) -> std::io::Result<Self>;
    pub fn path(&self) -> &Path;
    pub fn move_recovered_file(&self, file_name: &str) -> std::io::Result<()>;   // REPLACE_EXISTING
}

/// `MasterkeyService.detect`: der erste regulaere `*.c9r`, der nicht `dir.c9r` heisst, wird mit
/// beiden Schemata probiert -- in der Reihenfolge der Java-Enum `CryptorProvider.Scheme`:
/// SIV_CTRMAC, dann SIV_GCM.
pub fn detect_cipher_combo(masterkey: &Masterkey, vault_path: &Path) -> Option<CipherCombo>;

/// RESTORE_MASTERKEY: Recovery-Key + neues Passwort -> `masterkey.cryptomator`.
pub fn restore_masterkey(
    encoder: &WordEncoder, access: &MasterkeyFileAccess, vault_path: &Path,
    recovery_key: &str, new_passphrase: &str, rng: &mut dyn Rng,
) -> Result<()>;

/// RESTORE_VAULT_CONFIG: vorhandene Masterkey-Datei + Vault-Passwort -> `vault.cryptomator`.
pub fn restore_config(
    access: &MasterkeyFileAccess, vault_path: &Path, passphrase: &str,
    cipher_combo: Option<CipherCombo>, shortening_threshold: u32, rng: &mut dyn Rng,
) -> Result<VaultConfig>;

/// RESTORE_ALL: Recovery-Key + neues Passwort -> beide Dateien.
pub fn restore_all(
    encoder: &WordEncoder, access: &MasterkeyFileAccess, vault_path: &Path,
    recovery_key: &str, new_passphrase: &str,
    cipher_combo: Option<CipherCombo>, shortening_threshold: u32, rng: &mut dyn Rng,
) -> Result<VaultConfig>;
```
und `CoreError::CipherComboUndetectable(PathBuf)` (→ `WRONG_STATE`, Exit 5: der Vault gibt nicht genug her, um das zu entscheiden).

Grammatik:
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

**Java-Vorlage.** `RecoveryKeyResetPasswordController.restorePassword` (RESTORE_ALL), `RecoveryKeyCreationController.restoreWithPassword` (RESTORE_VAULT_CONFIG), `ResetPasswordTask.call` (RESTORE_MASTERKEY = `newMasterkeyFileWithPassphrase`), `MasterkeyService.detect` + `determineScheme`, `CryptoFsInitializer.init`, `RecoveryDirectory`.

- [ ] **Step 1: Failing Kern-Tests**

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
    // Der Vault laesst sich wieder oeffnen und lesen -- die jti ist neu, alles andere gleich.
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
    // restore_all meldet das als eigener Fehler, statt still SIV_GCM zu raten.
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
    // Ein Recovery-Key mit falscher Pruefsumme kommt gar nicht bis zum Schreiben.
    let err = cryptomator_core::recovery::restore::restore_all(
        &WordEncoder::new(), &MasterkeyFileAccess::new(Vec::new()), &vault,
        "not even words", "pw", None, 220, &mut OsRng,
    ).unwrap_err();
    assert!(matches!(err, cryptomator_core::CoreError::InvalidRecoveryKey(_)), "{err}");
    assert_eq!(std::fs::read(vault.join("vault.cryptomator")).unwrap(), before);
}
```

- [ ] **Step 2: Lauf – muss fehlschlagen**

Run: `cargo test -p cryptomator-core --test vault_lifecycle --locked restore`
Expected: FAIL, Modul `restore` fehlt.

- [ ] **Step 3: `RecoveryDirectory` und `detect_cipher_combo`**

```rust
impl RecoveryDirectory {
    pub fn create(vault_path: &Path) -> std::io::Result<Self> {
        Ok(Self { vault_path: vault_path.to_path_buf(), temp: tempfile::Builder::new()
            .prefix("cryptomator").tempdir()? })
    }
    pub fn path(&self) -> &Path { self.temp.path() }
    pub fn move_recovered_file(&self, file_name: &str) -> std::io::Result<()> {
        let (from, to) = (self.temp.path().join(file_name), self.vault_path.join(file_name));
        // Javas Files.move(REPLACE_EXISTING). Das Temp-Verzeichnis liegt in $TMPDIR und damit oft
        // auf einem anderen Dateisystem als der Vault -- rename schlaegt dann fehl.
        match std::fs::rename(&from, &to) {
            Ok(()) => Ok(()),
            Err(_) => { std::fs::copy(&from, &to)?; std::fs::remove_file(&from) }
        }
    }
}
```
`TempDir` löscht sich beim Drop – das ist Javas `close()`/`deleteRecoveryDirectory`.

```rust
pub fn detect_cipher_combo(masterkey: &Masterkey, vault_path: &Path) -> Option<CipherCombo> {
    let candidate = first_encrypted_file(&vault_path.join(DATA_DIR_NAME))?;
    // Reihenfolge wie Javas `CryptorProvider.Scheme.values()`.
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
`first_encrypted_file` läuft rekursiv über `d/` (sortiert, damit das Ergebnis reproduzierbar ist) und nimmt die erste **reguläre Datei**, deren Name auf `.c9r` endet und **nicht** `dir.c9r` ist. Javas Filter ist wortgleich (`p.toString().endsWith(".c9r")`, `!p.endsWith("dir.c9r")`, `Files::isRegularFile`) und schließt `dirid.c9r`, `symlink.c9r` und `contents.c9r` **nicht** aus – die sind ganz normale verschlüsselte Dateien mit Header, also funktioniert die Erkennung an ihnen genauso. Wörtlich übernehmen.

- [ ] **Step 4: Die drei Restore-Funktionen**

```rust
pub fn restore_masterkey(encoder, access, vault_path, recovery_key, new_passphrase, rng) -> Result<()> {
    let raw = decode_recovery_key(encoder, recovery_key)?;       // erst pruefen, dann schreiben
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
Anders als `recovery::key::reset_password` (M2) liest das hier **nicht** die `vault.cryptomator`, um den Dateinamen zu erfahren: bei einem Restore kann sie fehlen. Der Name ist `masterkey.cryptomator` — derselbe, den Java in `RecoveryKeyFactory.newMasterkeyFileWithPassphrase` fest verdrahtet. Als Kommentar festhalten, damit die beiden Funktionen nicht später zusammengelegt werden.

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
    // `initialize` legt Config, Wurzelverzeichnis und dessen dirid.c9r an -- Javas
    // CryptoFsInitializer.init. Uebernommen wird nur die Config; das Wurzelverzeichnis im
    // Temp-Verzeichnis ist Abfall, das echte steht schon im Vault.
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
    // Die Erkennung braucht den Schluessel, aber noch keine geschriebene Datei -- deshalb hier,
    // bevor irgendetwas den Vault beruehrt (Test `an_empty_vault_cannot_have_its_combo_detected`).
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
`initialize` verlangt ein Verzeichnis und legt `d/<roothash>/dirid.c9r` an; das Temp-Verzeichnis erfüllt beides. Beide Dateien werden erst **nach** dem vollständigen Schreiben verschoben – das ist der Sinn der `RecoveryDirectory`, und der Test `a_failed_restore_leaves_the_vault_untouched` prüft genau das.

- [ ] **Step 5: Das Kommando**

`cli.rs`: `RecoveryKeyCommand::Restore(RestoreArgs)`.
`main.rs`: `RecoveryKeyCommand::Restore(args) => commands::recovery::restore(&ctx, args),`.

`commands/recovery.rs`:
```rust
pub fn restore(ctx: &Ctx, args: RestoreArgs) -> Result<u8> {
    // Nicht `locked_vault`: ein Vault, dem die Config fehlt, ist VAULT_CONFIG_MISSING oder
    // ALL_MISSING -- genau der Zustand, den dieses Kommando beheben soll.
    let (vault, path) = restorable_vault(ctx, &args.vault)?;
    let combo = match args.cipher_combo.as_str() {
        "auto" => None,
        other => Some(other.parse::<CipherCombo>()?),       // wie `vault create --cipher-combo`
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
        let recovery_key = read_recovery_key_from(&args, &mut io)?;   // wie reset_password_cmd
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
`read_recovery_key_from` ist die vorhandene `read_recovery_key` aus `commands/recovery.rs`, deren Parameter von `&ResetPasswordArgs` auf zwei `Option`s umgestellt wird (`recovery_key_file: Option<&Path>`, `recovery_key_stdin: bool`), damit beide Kommandos sie teilen — der Rumpf bleibt unverändert.

`restorable_vault` steht in `commands/mod.rs` direkt neben `migratable_vault` und lässt `Locked`, `VaultConfigMissing` und `AllMissing` zu; `NeedsMigration` und `Missing` sind Exit 5 (bei `NeedsMigration` mit dem Hinweis auf `crypto migrate`).

Ausgabe (JSON): `{ "path": "…", "restored": ["masterkey.cryptomator","vault.cryptomator"], "cipherCombo": "SIV_GCM", "shorteningThreshold": 220 }`; Menschenform `restored masterkey.cryptomator and vault.cryptomator in /vaults/v (SIV_GCM, shortening threshold 220)`.

- [ ] **Step 6: CLI-Tests**

In `crates/crypto/tests/cli.rs` (neuer Abschnitt am Ende):

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
        .env("CRYPTO_NEW_PASSWORD", "brand-new-pass")     // Name laut NewPasswordArgs pruefen!
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

Wie das neue Passwort in einem Test ohne Terminal ankommt, entscheidet `NewPasswordArgs`: der Implementierende prüft mit `sed -n '50,80p' crates/cryptomator-app/src/password.rs`, welche Flagge bzw. Umgebungsvariable dort vorgesehen ist (in `recovery-key reset-password` wird sie in `crates/crypto/tests/cli.rs` schon benutzt – die Aufrufform von dort wörtlich übernehmen), und passt den Test entsprechend an, statt eine neue zu erfinden.

- [ ] **Step 7: Tests, Gate, Commit**

Run: `cargo test -p cryptomator-core --test vault_lifecycle --locked && cargo test -p crypto --test cli --locked restore`
Expected: alle grün.

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked`

```bash
git add crates/cryptomator-core/src crates/cryptomator-core/tests crates/crypto/src crates/crypto/tests/cli.rs
git commit -m "feat: recovery-key restore for masterkey, vault config or both

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 14: Nachträge, Dokumentation, CI und Meilensteinabschluss

**Files:**
- Modify: `crates/crypto/tests/cli_daemon.rs`, `crates/crypto/src/output.rs`, `crates/crypto/tests/java_interop.rs`, `.github/workflows/ci.yml`, `README.md`, `CHANGELOG.md`, `docs/superpowers/specs/2026-09-04-crypto-cli-design.md`

**Interfaces:**
- Consumes: alles aus den Tasks 1–13. Neuer Produktionscode entsteht nur in Step 2 (`output.rs` zieht auf `health::report::civil_utc` um).

- [ ] **Step 1: Nachtrag – der detachte Daemon schreibt sein Log**

`crates/crypto/tests/cli_daemon.rs` prüft den Loginhalt bisher nur für `--foreground` (Zeilen 273–281). Der detachte Pfad ist der Normalfall und ungeprüft. In `unlock_mounts_the_vault_and_lock_takes_it_down` nach dem `lock` ergänzen:

```rust
    // Der detachte Daemon schreibt in dieselbe Datei wie der Vordergrund-Daemon; sie bleibt nach
    // dem Lock liegen, damit man einen fehlgeschlagenen Mount noch nachlesen kann.
    let log = std::fs::read_to_string(fx.state_file(".log")).expect("the detached daemon log");
    assert!(log.contains("INFO"), "the daemon installed its logger: {log:?}");
    assert!(log.contains("mounted at"), "the mount is in the log: {log:?}");
    assert!(log.contains("stopped"), "and so is the shutdown: {log:?}");
    assert!(!log.contains("test-password"), "no passphrase ever reaches the log");
```

Run: `cargo test -p crypto --test cli_daemon --locked unlock_mounts` (mit `CRYPTO_ENABLE_NULL_MOUNTER=1`, das `Sandbox::crypto_daemon` selbst setzt).
Expected: PASS. Schlägt eine der drei Zeichenketten fehl, ist der tatsächliche Wortlaut aus dem Log zu übernehmen (die Meldungen stehen in `crates/cryptomator-app/src/daemon/server.rs`) – die Zusicherung wird angepasst, nicht der Daemon.

- [ ] **Step 2: Nachtrag – den doppelten Kalenderalgorithmus auflösen**

`crates/crypto/src/output.rs::format_timestamp` und `cryptomator_core::health::report::civil_utc` (Task 7) rechnen dasselbe. `format_timestamp` wird auf den Core-Helfer umgestellt:

```rust
/// `YYYY-MM-DD HH:MM:SS` in UTC.
pub fn format_timestamp(time: SystemTime) -> String {
    let (y, mo, d, h, m, s) = cryptomator_core::health::report::civil_utc(time);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02}:{s:02}")
}
```
Die vorhandenen Tests in `output.rs` bleiben unverändert und belegen, dass sich nichts am Ergebnis ändert.

- [ ] **Step 3: Nachtrag – README-Absatz neu umbrechen**

`README.md` Zeilen 474–478 sind mitten im Satz umgebrochen (Zeile 477 ist 51 Zeichen lang und endet auf „and the flags are mutually"). Der Absatz wird auf ~100 Spalten neu gesetzt:

```markdown
`$CRYPTO_PASSWORD` deliberately outranks the implicit keychain step: it is a source a script sets on
purpose, and it can never make the operating system open a dialog. `--no-keychain` removes step 5
from the list for one run and turns step 0 into exit `8` (there is no keychain to read), whatever
`settings.json` says — and the flags are mutually exclusive, so `--password-keychain` together with
any other `--password-*` flag is a usage error.
```

- [ ] **Step 4: Java-Interop für die migrierten Legacy-Vaults**

`crates/crypto/tests/java_interop.rs` bekommt einen Test, der die Kette schließt: Rust migriert, Java liest.

```rust
/// Legacy-Vaults, die `crypto migrate` auf Format 8 gehoben hat, muessen sich mit dem echten
/// cryptofs oeffnen lassen. Das ist der einzige Beleg dafuer, dass unsere Migratoren nicht nur
/// unsere eigenen Leser zufriedenstellen.
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

        verify_with_java(&vault, &final_pass);      // vorhandener Helfer, prueft Exit 0 + Manifest
    }
}
```
Der Helfer `verify_with_java` existiert in dieser Datei bereits (er ruft `run_java_verify` und wertet Exit-Code und JSON-Ausgabe aus); seine genaue Signatur ist mit `grep -n "fn verify_with_java" -A 20 crates/crypto/tests/java_interop.rs` zu prüfen.

`crypto` braucht dafür `cryptomator-core` als Dev-Dependency – das ist schon so (die Datei benutzt `cryptomator_core::open_vault`).

- [ ] **Step 5: CI**

`.github/workflows/ci.yml`, Job `interop-java`: nichts hinzuzufügen außer einem Vorbau-Schritt, damit die drei Legacy-Artefakte einmal geladen werden und der Reaktor kompiliert, bevor die Tests laufen:

```yaml
      - name: prime the fixture-gen reactor (downloads legacy cryptofs)
        run: mvn -q -B -f tools/fixture-gen/pom.xml compile
      - run: cargo test -p crypto --test java_interop --locked -- --ignored
```
`-B` (batch mode) unterdrückt die Fortschrittsbalken im Log. Der `cache: maven` der `setup-java`-Action ist schon gesetzt, die Artefakte werden also nur einmal geladen.

Ein neuer Job ist **nicht** nötig: die Health- und Migrationstests laufen in `cargo test --workspace` mit, weil sie keine Java-Seite brauchen.

- [ ] **Step 6: README – drei neue Abschnitte**

Kommandotabelle (um Zeile 55) ergänzen:
```markdown
| `health` | Checks a vault for structural damage, optionally repairs it | `crypto health Secret --fix` |
| `migrate` | Brings a vault of format 5, 6 or 7 up to format 8 | `crypto migrate Old --yes` |
| `recovery-key restore` | Rebuilds a lost masterkey file and/or vault config | `crypto recovery-key restore V --all --recovery-key-stdin` |
```

Neuer Abschnitt `## Health checks` (nach „Mount-less access", vor „Password sources"):

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

Neuer Abschnitt `## Migrating older vaults`:

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

Neuer Abschnitt `### Restoring a lost masterkey or vault config` unter „Recovery keys" (bzw. hinter dem `recovery-key validate`-Abschnitt):

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

Exit-Code-Tabelle: die Zeile für `11` ersetzt den Satz darunter.
```markdown
| `11` | `crypto health` found at least one finding of the severity given by `--fail-on` (default `CRITICAL`) |
```
Der Absatz „`11` (health findings) is reserved for M7 and is never returned today." wird **gelöscht**. In der Zeile für `5` wird „needs migration" um „(run `crypto migrate`)" ergänzt.

Abschnitt „Test fixtures": „eight reference vaults" → „twelve reference vaults" mit einem Satz zu `broken_health` und `legacy_v{5,6,7}` und den vier Generatorkommandos aus Task 2, Step 5.

- [ ] **Step 7: CHANGELOG**

Neuer Abschnitt `### M7 – Health checks, restore and migration` nach `### M6 – Keychain`, gegliedert wie die vorherigen (Aufzählung der Lieferungen, `#### Decisions taken along the way` mit den elf Rulings dieses Plans, `#### Known limitations and follow-ups`). Die Limitierungen, die nachweislich bestehen:

- `INFO`-Befunde (`MissingDirIdBackup`, `LooseDirFile`) haben Fixes, aber `--fix-severity` kennt nur `WARN` und `CRITICAL` — sie lassen sich mit `crypto` nicht anwenden (Ruling 3).
- Der Report-Zeitstempel ist UTC, nicht die Systemzeitzone (keine Zeitzonendatenbank ohne neue Abhängigkeit, Ruling 5).
- `crypto health` läuft einfädig; Javas `ExecutorService`-Streaming gibt es nicht. Für sehr große Vaults heißt das: keine Zwischenausgabe, kein Abbrechen mitten im Lauf.
- Die Migration ist an keinem echten Alt-Vault erprobt worden, nur an den erzeugten Fixtures; insbesondere ist der Zweig „Speicher unterstützt weniger als 220 Zeichen" (Javas `REQUIRES_FULL_VAULT_DIR_SCAN`) nie unter echten Bedingungen gelaufen — auf APFS und ext4 greift er nicht.
- `FilePathMigration::parse` sucht das kanonische Namensmuster ab Position 0 statt wie Javas `find()` an jeder Position (Task 11, Step 3).
- Alles aus M4/M5/M6, was dort offen blieb: macFUSE unverifiziert, `LinuxGioMounter` unverifiziert, ein von Cryptomator.app geschriebener Keychain-Eintrag ungeprüft, das Internet-Password vor dem AppleScript-Mount fehlt (→ M8).

- [ ] **Step 8: Spec**

In `docs/superpowers/specs/2026-09-04-crypto-cli-design.md`:
- Meilensteintabelle: die M7-Zeile bekommt `✅` und eine Fußnote `[^m7-scope]`.
- Neue Fußnote am Ende der Fußnotenliste, im Stil von `[^m6-scope]`: was geliefert wurde, die elf Rulings in Kurzform, was bewusst nicht umgesetzt wurde (die `INFO`-Fixes, das Streaming, Javas `find()`-Semantik) und was offen bleibt (M8).
- Teststrategie Punkt 1: `gen-legacy-v7/v6/v5` sind da; ergänzen, dass 1.6.2 Format **6** schreibt und der v5-Vault durch Umstempeln der Masterkey-Datei entsteht, und dass die Legacy-Artefakte **nicht** in `~/.m2` liegen (Befund 8 präzisieren: „auf Maven Central verfügbar, lokal nicht vorhanden – der erste Generatorlauf braucht Netz").
- Befund 9 („Lokale Umgebung"): unverändert.
- Risiko 8 („Migration 6→7 ist der größte Einzelposten"): als erledigt markieren, mit einem Satz zum Ergebnis.

- [ ] **Step 9: Manueller Abnahmelauf**

Gegen eine echte Kopie, nicht gegen ein Fixture, damit die Kommandos einmal so laufen wie beim Nutzer:

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
Erwartet: `--dry-run` listet Umbenennungen und ändert nichts, `migrate --yes` meldet `6->7, 7->8`, `health` endet mit 0 und schreibt einen Report, dessen Kopf die drei Sternchenzeilen hat. **Im Report festhalten**, was tatsächlich ausgegeben wurde – das ist der einzige Beleg dafür, dass die drei Kommandos zusammen funktionieren.

- [ ] **Step 10: Gate und Commit**

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked`
Run: `cargo test -p crypto --test java_interop --locked -- --ignored` (braucht Java und Maven)
Expected: beides grün; die Java-Läufe belegen, dass cryptofs 2.10.0 alle drei migrierten Vaults öffnet.

```bash
git add README.md CHANGELOG.md docs .github crates
git commit -m "docs: health, migrate and restore; close milestone M7

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

## Selbstprüfung

**1. Spec-Abdeckung M7.** Jede Zusage der Spec zu diesem Meilenstein hat einen Task:

| Spec-Stelle | Task |
|---|---|
| `health/mod.rs`: Trait `HealthCheck`, `DiagnosticResult{severity, details, fix}` | 3 |
| `health/dir_id.rs`: DirIdCheck, **8 Ergebnistypen**, Fixes | 4 (7 Typen + 3 Fixes), 5 (der 8. Fix) |
| `health/dir_id.rs`: „Fixes inkl. LOST+FOUND-Adoption" | 5 |
| `health/file_type.rs`: CiphertextFileTypeCheck | 6 |
| `health/shortened.rs`: ShortenedNamesCheck, **6 Typen**, Fixes | 6 |
| `health/report.rs`: „Report-Format wie `ReportWriter`" | 7 |
| Grammatik `crypto health <VAULT> [--check …] [--report FILE\|--no-report] [--fail-on …]` | 8 |
| Grammatik `crypto health … [--fix] [--fix-severity WARN\|CRITICAL]` | 9 |
| Exit-Code **11** „Health-Befunde ≥ `--fail-on`" | 8 (Konstante + Auslöser), 14 (README) |
| `migration/mod.rs`: Versionserkennung, `needs_migration`, `migrate(path, passphrase, progress)` | 10 |
| `migration/v6.rs`: „5→6 (NFC-Passphrase, `unicode-normalization`)" | 10 |
| `migration/v7.rs`: „Capability-Check, PreMigrationVisitor, `FilePathMigration` base32→base64url, `0`/`1S`-Präfixe, `.lng` aus `m/xx/yy/`, bis 3 `_n`-Versuche, `m/` löschen" | 11 |
| `migration/v8.rs`: „JWT mit `SIV_CTRMAC`, Threshold 220, version 999" | 10 |
| Grammatik `crypto migrate <VAULT> [--yes]` + Ruling `--dry-run` | 12 |
| Exit-Code **5** „braucht Migration" | 12 (Step 5: Hinweistext an `locked_vault`) |
| `recovery/restore.rs`: „`detect_scheme` (erster regulärer `.c9r`, beide Header-Varianten probieren), Restore masterkey/config/all über Temp-`RecoveryDirectory`" | 13 |
| Grammatik `crypto recovery-key restore <VAULT> (--masterkey\|--config\|--all) [--cipher-combo …] [--shortening-threshold N]` | 13 |
| Teststrategie 1: `gen-legacy-v7/v6/v5` (cryptofs 1.9.15/1.8.9/1.6.2), „`.lng`-Namen und NFD-Umlaut-Passphrase", „je < 200 KB" | 2 |
| Teststrategie 1: `verify`-Harness auf migrierten Vaults | 14 (Step 4) |
| Teststrategie 2: `migration.rs` | 10, 11 |
| M7-Zeile „beschädigte Fixtures (Harness erzeugt: Orphan-Dir, fehlende dirid, Trailing Bytes …)" | 1 |
| M7-Zeile „Legacy-Fixtures migrieren und in Java verifizieren" | 11 (Rust-Seite), 14 (Java-Seite) |
| Befund 8 „Legacy-cryptofs auf Maven Central" | 2 (verifiziert: 1.9.15/1.8.9/1.6.2 antworten mit HTTP 200, liegen aber **nicht** in `~/.m2`) |
| Verifikation „`crypto health` gegen absichtlich beschädigte Fixtures inkl. `--fix`; `crypto migrate` gegen Legacy-Fixtures" | 9, 12, 14 (Step 9) |
| Fußnote `[^m6-scope]`: „Offen bleiben M7 … und M8" | 14 (Fußnote `[^m7-scope]`) |
| Carry-over: Log des detachten Daemons prüfen | 14 (Step 1) |
| Carry-over: README-Zeile ~475 neu umbrechen | 14 (Step 3) |

Nicht in M7 (Spec ordnet zu): Packaging, Manpages, Completions, `xtask`, die vollständige CI-Matrix und das Internet-Password vor dem AppleScript-Mount → **M8**. Windows ist nicht im Scope.

**Zwei Spec-Formulierungen, die dieser Plan bewusst anders auslegt.** Erstens nennt die Modultabelle für `recovery/restore.rs` ein `detect_scheme`; die Funktion heißt hier `detect_cipher_combo`, weil der Rust-Typ `CipherCombo` heißt und `Scheme` im Workspace nirgends vorkommt. Zweitens sagt die Modultabelle zu `health/mod.rs` `DiagnosticResult{severity, details, fix}`; die Controller-Vorgabe für diesen Meilenstein lautet `{severity, check, message, paths, fix}`, und die gilt — Javas `details()`-Map ist in `paths` und `message` aufgegangen, weil ihre Werte ausschließlich Pfade, Größen und Typen sind, die beide Felder schon tragen.

**2. Platzhalter-Scan.** Kein „TBD", kein „implement later", kein „siehe Task N" ohne den Inhalt zu wiederholen. Vier Stellen enthalten bewusst keinen fertigen Rumpf, und jede sagt genau, was dort steht und wer sie ersetzt:

- Task 3, Step 3: `struct Placeholder` in `all_checks()` — Task 4 ersetzt die erste, Task 6 die beiden anderen Zeilen und löscht den Typ.
- Task 8, Step 5: der `--fix`-Ablehnungsblock mit dem Marker `not implemented yet`, den Task 9, Step 3 per `grep` findet und ersetzt.
- Task 10, Step 6: der `SixToSeven`-Zweig, der bis Task 11 `MigrationBlocked` liefert.
- Task 2, Step 3: der absichtlich als Sackgasse ausgeschriebene Java-Versuch, den `versionMac` zu berechnen — er steht da, damit ihn niemand ein zweites Mal geht; der gangbare Weg ist Step 4.

Dazu sechs Stellen, an denen der Ausführende **nachsieht statt zu raten**, jeweils mit dem Prüfbefehl:
- Task 5, Step 1 und Task 11, Step 6: die M3-Namen `CryptoFs::open`, `CryptoFsOptions`, `CleartextPath::parse`, `CryptoFs::metadata`, `DirEntry::name` — `grep -n "CryptoFs::\|CleartextPath::" crates/cryptomator-core/tests/crypto_fs_fixtures.rs`.
- Task 6, Step 3: die Deklarationsreihenfolge von `CiphertextFileType` — `grep -n "enum CiphertextFileType" -A 6 crates/cryptomator-core/src/fs/ciphertext_path.rs`.
- Task 8, Step 1: ob `Sandbox::add_fixture` den Vault-Pfad zurückgibt — `sed -n '160,190p' crates/crypto/tests/common/mod.rs`. **Zusätzlich zu prüfen:** ob `add_fixture` einen Legacy-Vault ohne `vault.cryptomator` überhaupt registriert (`vault add` geht über `assert_is_vault_directory`, das `DirStructure::MaybeLegacy` akzeptiert — es sollte also gehen). Tut es das nicht, registrieren die Tests in Task 12 den Vault stattdessen mit `crypto vault add <pfad>` und lösen ihn über den Pfad auf.
- Task 10, Step 5: der Variantenname `CipherCombo::SivCtrMac` — `grep -n "enum CipherCombo" -A 6 crates/cryptomator-core/src/crypto/cryptor.rs`.
- Task 12, Step 1: die Feldnamen von `Sandbox::fake_keychain_json` — `sed -n '150,170p' crates/crypto/tests/common/mod.rs`.
- Task 13, Step 6: wie ein *neues* Passwort ohne Terminal in einen CLI-Test kommt — die Aufrufform aus dem vorhandenen `recovery-key reset-password`-Test in `crates/crypto/tests/cli.rs` wörtlich übernehmen.

Und zwei Zahlenkonstanten in Tests, die vor dem Committen gegenzurechnen sind, jeweils mit dem Befehl daneben: der Zeitstempel in Task 7, Step 1 (`date -u -r 1788534245 +%Y%m%d-%H%M%S`) und die BASE32/BASE64-Umrechnung in Task 11, Step 1 (`python3 -c "import base64;…"`).

**3. Typkonsistenz über die Tasks hinweg.**

- `Severity`, `DiagnosticResult`, `Fix`, `HealthCheck`, `CheckContext`, `run_checks`, `checks_by_ids`, `all_checks`, `CHECK_IDS` (3) → 4, 5, 6, 7, 8, 9, 11 (der Health-Lauf am Ende der Migrationskette).
- `CheckContext::{vault_path, cryptor, config, data_dir, resolve, relativize, rng}` (3) → jeder Check und jeder Fix in 4, 5, 6. `config.shortening_threshold` (Feld von `VaultConfig`, existiert) ist der einzige Konfigurationswert, den ein Fix braucht (Task 5).
- `DIR_ID_CHECK_ID = "dirid"`, `TYPE_CHECK_ID = "type"`, `SHORTENED_CHECK_ID = "shortened"` (4, 6) sind identisch mit den Einträgen in `CHECK_IDS` (3) und mit dem, was `--check` annimmt (8) und was im JSON unter `check` steht (8).
- `DIR_ID_CHECK_NAME = "Directory Check"`, `TYPE_CHECK_NAME = "Resource Type Check"`, `SHORTENED_CHECK_NAME = "Shortened Names Check"` (4, 6) sind die `name()`-Werte, die der Report in `Check %s` einsetzt (7, 8).
- `AdoptOrphan { content_dir }` (5) wird ausschließlich in `dir_id.rs` erzeugt (5, Step 6) und nirgends sonst.
- `render_report`, `report_file_name`, `write_report`, `civil_utc` (7) → 8 (Report schreiben), 9 (Report aus dem zweiten Lauf), 14 (`output::format_timestamp` zieht auf `civil_utc` um).
- `exit::HEALTH_FINDINGS` (8) → 9 (derselbe Rückgabewert), 14 (README-Tabelle).
- `MigrationStep`, `MigrationPlan`, `PlannedRename`, `Migrators::{plan, migrate, needs_migration}`, `assert_all_capabilities` (10) → 11 (`plan_renames` füllt `MigrationPlan::renames`), 12 (Kommando), 14 (Java-Interop).
- `migration::v6::migrate(vault, passphrase, rng)`, `v8::migrate(vault, passphrase, rng)` (10) und `v7::migrate(vault, passphrase, full_scan_allowed, rng)` (11) — **v7 hat einen Parameter mehr**, weil nur dort eine Rückfrage nötig werden kann; `Migrators::migrate` reicht `full_scan_allowed` genau dorthin durch und ignoriert es für die anderen beiden.
- `FilePathMigration::{parse, migrate, target_path, new_inflated_name, new_deflated_name}` und `plan_renames` (11) → 12 (`--dry-run` liest `MigrationPlan::renames`).
- `migratable_vault` (12) und `restorable_vault` (13) stehen beide in `commands/mod.rs` neben `locked_vault`; alle drei geben `(VaultSettingsJson, PathBuf)` zurück und rufen `require_locked`. Sie unterscheiden sich **nur** in der Menge der zugelassenen `VaultState`-Werte: `Locked` / `Locked|NeedsMigration` / `Locked|VaultConfigMissing|AllMissing`.
- `RecoveryDirectory::{create, path, move_recovered_file}`, `detect_cipher_combo`, `restore_masterkey`, `restore_config`, `restore_all` (13) → nur das Kommando in 13 und die Tests dort.
- `CoreError::{MissingCapability, FileNameTooLong, MigrationBlocked}` (10) und `CoreError::CipherComboUndetectable` (13) müssen **beide** in `exit.rs::core_code` einsortiert werden; `core_code` ist absichtlich ohne `_`-Arm geschrieben, der Compiler erzwingt das also. Zuordnung: `MissingCapability` und `FileNameTooLong` → `GENERAL` (1), `MigrationBlocked` und `CipherComboUndetectable` → `WRONG_STATE` (5).

Namen, die in zwei Tasks unterschiedlich hießen und hier aufgelöst sind: `detect_scheme` (Spec) vs. `detect_cipher_combo` (verbindlich, Task 13); `deflate` in `fs/long_names.rs` (nimmt einen Pfad) vs. `deflate_name` im Shortened-Check (nimmt einen `&str`) — Task 6 zieht die gemeinsame Rechnung in `fs::long_names::deflate_str` heraus und lässt beide darauf zeigen, statt sie zweimal zu schreiben.

**4. Exit-Code-Zuordnung.**

| Situation | Weg | Code |
|---|---|---|
| Health-Befund ≥ `--fail-on` | Rückgabewert von `commands::health::run` | **11** |
| `--check bogus`, `--fail-on INFO`, `--fix-severity GOOD` | `CoreError::InvalidArgument` | 2 |
| `crypto migrate` ohne `--yes` und ohne Terminal | `AppError::InvalidValue { key: "--yes" }` | 2 |
| `crypto recovery-key restore --config --recovery-key-stdin` | `AppError::InvalidValue` | 2 |
| kein `--masterkey`/`--config`/`--all` oder mehrere | clap `ArgGroup` | 2 |
| falsches Passwort bei `health`, `migrate`, `restore --config` | `CoreError::InvalidPassphrase` | 4 |
| Recovery-Key mit falscher Prüfsumme | `CoreError::InvalidRecoveryKey` | 4 |
| `health`/`migrate`/`restore` auf einem Vault, den ein Daemon bedient | `AppError::WrongState` über `require_locked` | 5 |
| `health` auf einem Vault im Zustand `NEEDS_MIGRATION` | `AppError::WrongState` mit dem Hinweis auf `crypto migrate` | 5 |
| Vault-Format < 5 | `CoreError::MigrationBlocked` | 5 |
| `vault.cryptomator` existiert schon beim 7→8-Schritt | `CoreError::MigrationBlocked` | 5 |
| Cipher-Combo nicht erkennbar und nicht angegeben | `CoreError::CipherComboUndetectable` | 5 |
| Speicher kann keine 220-Zeichen-Namen und `--yes` fehlt | `CoreError::MigrationBlocked` | 5 |
| Name nach der Migration zu lang für den Speicher | `CoreError::FileNameTooLong` | 1 |
| Speicher nicht les- oder beschreibbar | `CoreError::MissingCapability` | 1 |
| Hub-Vault bei `health`/`migrate`/`restore` | `CoreError::HubVaultUnsupported` | 9 |
| `crypto migrate` auf einem Format-8-Vault | kein Fehler | **0** |
| `crypto migrate` an der Bestätigungsfrage abgebrochen | kein Fehler | **0** |
| `--fix` konnte einen Fix nicht anwenden | Warnung auf stderr, `fixed: false` im JSON | Code des zweiten Laufs |
| Keychain lehnt das Nachziehen nach `5→6` ab | Warnung auf stderr | 0 |

Die letzten beiden Zeilen folgen Ruling 5 aus M6: was **nach** der eigentlichen Leistung passiert, wird zur Warnung, nicht zum Exit-Code — der Vault ist migriert, ein Exit ≠ 0 würde ein Skript zu einem falschen Rollback verleiten.

## Ausführung

`superpowers:subagent-driven-development` mit Opus-5-Subagenten, ein frischer Subagent je Task, Review zwischen den Tasks; Reihenfolge **1 → 14**.

**Abhängigkeiten.** Task 1 liefert das Fixture, ohne das die Tasks 4, 6, 8 und 9 nichts zu prüfen haben. Task 2 liefert die Legacy-Fixtures für 10, 11, 12 und 14. Task 3 ist das Fundament für 4–9. Task 5 braucht 4 (der Fix wird dort angehängt), Task 6 braucht 3 (es entfernt die letzten Placeholder), Task 7 ist unabhängig von 4–6 und könnte parallel laufen, Task 8 braucht 3, 6 und 7, Task 9 braucht 8. Task 10 braucht nur 2, Task 11 braucht 10, Task 12 braucht 11. Task 13 braucht nichts aus 3–12 und ist die einzige echte Parallelisierungsmöglichkeit: **Task 13 darf jederzeit nach Task 2 laufen.** Task 14 setzt auf allem auf.

**Zwei Tasks brauchen Netz.** Task 2 lädt cryptofs 1.9.15, 1.8.9 und 1.6.2 von Maven Central nach `~/.m2` (geprüft: alle drei antworten mit HTTP 200, keine liegt lokal vor). Task 14, Step 10 braucht dieselben Artefakte plus cryptofs 2.10.0 (das liegt lokal). Ohne Netz sind beide zu vertagen; sie sind **nicht** durch andere Versionen zu ersetzen und **nicht** zu überspringen — ohne Legacy-Fixtures sind die Migratoren unbelegt.

**Drei Tasks fassen `tests/fixtures/` an, und nur diese drei:** Task 1 (`broken_health`), Task 2 (`legacy_v7`, `legacy_v6`, `legacy_v5` plus der `#[ignore]`-Stempelschritt) und — lesend — alle anderen. Ein Subagent, der in einem anderen Task eine Datei unter `tests/fixtures/` schreibt, hat einen Fehler gemacht; der Review zwischen den Tasks prüft das mit `git status --porcelain tests/fixtures/`.

**Was im Report jedes Tasks stehen muss.** Neben dem üblichen Gate:
- Task 1 und 2: die `du -sh`-Ausgabe der neuen Fixtures (Grenze 200 KB je Vault) und der `git status --porcelain tests/fixtures/`-Auszug.
- Task 2: ob Maven die drei Legacy-Artefakte laden konnte, und der Beleg aus Step 6, dass `legacy_v6`/`legacy_v5` BASE32-Namen und ein `m/` haben.
- Task 5: die Ausgabe von `crypto fs ls <vault> /LOST+FOUND` bzw. der Testausgabe, die zeigt, welchen Namen die adoptierte Datei bekommen hat.
- Task 9: der `--fix`-Lauf im Klartext (before/after), damit die Zusammenfassungszeilen einmal von einem Menschen gelesen worden sind.
- Task 11: die Laufzeit von `the_whole_chain_from_five_to_eight_produces_a_readable_vault`.
- Task 14: die Ausgabe des manuellen Abnahmelaufs aus Step 9 und das Ergebnis von `cargo test -p crypto --test java_interop -- --ignored`.

**Was nicht passieren darf.** Kein Task setzt `CRYPTO_E2E_KEYCHAIN=1`, ruft `security` auf oder mountet etwas — M7 berührt weder Keychain-Dialoge noch FUSE. Der einzige Keychain-Kontakt ist der Fake in Task 12. Kein Task ändert `~/.m2` von Hand oder schreibt in den Desktop-Checkout.
