# Design-Spec: `crypto` – Rust-CLI-Port von Cryptomator

_Stand: 2026-09-04. Abgeleitet aus dem freigegebenen Planungsdokument; dient als Referenz für alle Implementierungspläne._


## Context

Cryptomator (JavaFX, GPLv3) hat kein vollwertiges CLI; das offizielle `cryptomator/cli` (Java) kann nur `unlock` + `list-mounters` und braucht eine JVM. Ziel ist ein neues, eigenständiges Rust-Tool **`crypto`** im Ordner **`/Users/rfoerthe/work/cryptomator-cli`** (derzeit leer, wird eigenes Git-Repo), das alle Funktionen der Desktop-App als CLI anbietet, für macOS und Linux gebaut wird und mit den Vaults, der `settings.json` und den Keychain-Einträgen der Desktop-App kompatibel bleibt.

Das Vault-Format steckt **nicht** im Cryptomator-Repo, sondern in `cryptolib 2.2.2` und `cryptofs 2.10.0`. Die Sources-JARs liegen lokal vor und sind die Portierungsvorlage (Lesen ohne Entpacken: `unzip -l <jar>` / `unzip -p <jar> <pfad>`):

- `~/.m2/repository/org/cryptomator/cryptolib/2.2.2/cryptolib-2.2.2-sources.jar`
- `~/.m2/repository/org/cryptomator/cryptofs/2.10.0/cryptofs-2.10.0-sources.jar`
- `~/.m2/repository/org/cryptomator/siv-mode/1.6.1/siv-mode-1.6.1-sources.jar`
- `~/.m2/repository/org/cryptomator/fuse-nio-adapter/6.0.1/fuse-nio-adapter-6.0.1-sources.jar` (Mount-Provider: Capabilities, Default-Flags, Erkennung, Unmount)
- `~/.m2/repository/org/cryptomator/integrations-mac/1.5.0/integrations-mac-1.5.0-sources.jar` (Keychain)
- Desktop-App: `/Users/rfoerthe/work/pro/cryptomator/.claude/worktrees/cryptomator-cli-rust-be5387/src/main/java/org/cryptomator/…`

## Getroffene Entscheidungen (mit dem User geklärt, Design freigegeben)

| Thema | Entscheidung |
|---|---|
| Ansatz | Eigener Port mit RustCrypto-Crates, keine Abhängigkeit von oxcrypt/cryptomator-rs |
| Lizenz | AGPL-3.0 (cryptolib/cryptofs sind AGPLv3) |
| Mount | FUSE via `fuser` (Linux libfuse3; macOS macFUSE **oder** FUSE-T, Laufzeitwahl) + WebDAV-Loopback-Fallback (Port 42427) + mountlose `fs`-Kommandos |
| Konfiguration | Desktop-`settings.json` schemakompatibel mitbenutzen |
| Prozessmodell | Hintergrund-Daemon pro Vault mit Unix-Socket; `--foreground` optional |
| Hub-Vaults | Erkennen (`kid` beginnt mit `hub+`) und mit klarer Fehlermeldung ablehnen (Exit 9) |
| Nicht im Scope | Theme, Fenster, Sprache, Tray, Kompaktmodus, Update-Check, Supporter-Zertifikat, Autostart/Auto-Unlock beim Login (Felder werden in settings.json nur erhalten) |

## Zentrale technische Befunde (verifiziert gegen Sources)

1. **FUSE-T ist mit `fuser` nicht direkt ansteuerbar.** FUSE-T hat kein `/dev/fuse`; `libfuse-t.dylib` ist eine libfuse-2.9-API-kompatible Bibliothek mit NFS/SMB-Userspace-Server. `fuser` spricht das Kernel-FUSE-Protokoll über einen fd. Einziger Weg für ein Binary mit Laufzeitwahl: `dlopen` der Vendor-Dylib (`/usr/local/lib/libfuse.2.dylib` macFUSE, `/usr/local/lib/libfuse-t.dylib` FUSE-T; genau diese Pfade prüfen `MacFuseMountProvider`/`FuseTMountProvider`), `fuse_mount_compat25(mountpoint, &fuse_args) -> fd` aufrufen (das Symbol nutzt fusers eigenes `src/mnt/fuse2.rs`) und den fd an `fuser::Session::from_fd` übergeben. Für macFUSE sicher, für FUSE-T **Spike (M0) mit Go/No-Go**; Fallback: `fuse_lowlevel_ops`-FFI-Backend nur für FUSE-T (wie jfuse).
   **Spike-A-Ergebnis (M0, [`docs/superpowers/spikes/2026-09-04-spike-a-fuse-t.md`](../spikes/2026-09-04-spike-a-fuse-t.md)): FUSE-T 1.2.7 ist mit unverändertem fuser 0.18 ein NO-GO.**
   Transport und Handshake funktionieren (`dlopen` → `fuse_mount_compat25` → `fuser::Session::from_fd`, `proto=7.19` ausgehandelt, echte Kernel-FUSE-Requests fließen); das Hindernis ist ausschließlich das Struct-ABI:
   fuser schreibt unter `target_os = "macos"` das macFUSE-`fuse_attr`-Layout (104 B, mit `crtime`/`crtimensec`, `flags` vor `blksize`), während FUSE-T das Linux-Layout (88 B) parst — dadurch kommt `mode` als 0 an und FUSE-T bricht den Mount ab.
   **Entscheidung für M4:** weiter mit `fuser`, aber mit einem Linux-ABI-Feature (Fork/Patch von `fuse_abi.rs`, das die `#[cfg(target_os = "macos")]`-Felder abschaltbar macht; als Feature-Flag upstream-tauglich), verifiziert durch einen Folge-Spike vor der Umsetzung. macFUSE ist **ungetestet** (nicht installiert) und vom Root Cause nicht betroffen.
2. **`keyring`-Crate ungeeignet** (sucht nach `service`/`username`). Desktop-Schema: macOS Generic Password in der Login-Keychain, Service `"Cryptomator"`, Account = Vault-ID, Passwort UTF-8 → `security-framework` direkt. Linux Secret Service: Login-Collection, Label `"Cryptomator"`, Attribute `{"Vault": id, "Name": displayName}`, Suche nur über `{"Vault": id}` → `secret-service`-Crate direkt. KWallet (Ordner `Cryptomator`, Key = ID) optional/später.
3. **settings.json-Asymmetrie**: Die Desktop-App ignoriert unbekannte Keys beim Lesen und **verwirft sie beim nächsten Speichern**. Das CLI muss unbekannte Keys erhalten (serde `flatten`), darf aber **keinen CLI-eigenen Zustand in settings.json ablegen** → separate `cli.json` neben settings.json. Lokal geprüft: `~/Library/Application Support/Cryptomator/settings.json` (geschrieben von 1.19.3) entspricht exakt `SettingsJson`.
4. **AES-SIV-Schlüsselreihenfolge**: cryptolib ruft `siv.encrypt(encKey /*CTR*/, macKey /*S2V*/)`. RFC 5297/RustCrypto `Aes256Siv`: erste Hälfte = S2V-Key, zweite = CTR-Key → **Rust-Key = macKey ‖ encKey**.
5. **Java-Streaming-Writer-Eigenheit**: `EncryptingWritableByteChannel.close()` schreibt immer einen letzten Chunk, auch leer. `dirid.c9r` des Root-Verzeichnisses (dirId `""`) = Header + leerer Chunk (SIV_GCM: 68 + 28 = 96 Bytes); `cleartextSize()` wirft für diese Größe. Unser Stream-Writer muss das spiegeln; der Chunk-Cache-Pfad schreibt nie leere Chunks.
6. **Mount-Provider-Fakten** (fuse-nio-adapter 6.0.1) müssen exakt reproduziert werden, damit `mountFlags` in settings.json gültig bleibt (siehe `cryptomator-mount`).
7. **mountPointsDir**: Linux `~/.local/share/Cryptomator/mnt`; im macOS-Build-Skript fehlt ein Slash (Upstream-Tippfehler). Wir nutzen `~/Library/Application Support/Cryptomator/mnt` und dokumentieren die Abweichung.
8. **Legacy-cryptofs auf Maven Central**: 1.9.15 (Format 7), 1.8.9 (Format 6), 1.6.2 (Format 5) für Legacy-Fixtures verfügbar.
9. **Lokale Umgebung**: macOS 26.6.2, cargo 1.98, pkg-config, Java 26 + jshell + Maven. **Kein FUSE installiert** (weder macFUSE noch FUSE-T). Für Spike A und FUSE-Tests muss der User FUSE-T (`brew install --cask macos-fuse-t/homebrew-cask/fuse-t`) oder macFUSE installieren; bis dahin WebDAV-Feature bauen/testen. Da die Dylib per `dlopen` geladen wird, braucht der Build selbst kein FUSE.
10. **Spike B (Desktop-Keychain lesen) ist BLOCKED, kein NO-GO** ([`docs/superpowers/spikes/2026-09-04-spike-b-keychain.md`](../spikes/2026-09-04-spike-b-keychain.md)):
    Die Desktop-App hatte nie eine Passphrase gespeichert, es existierte also kein echter Eintrag; gegen einen Wegwerf-Eintrag zeigt macOS für jeden Zugriff einen modalen ACL-Dialog, den eine nicht-interaktive Session nicht beantworten kann. Der Ansatz (`security-framework`, Generic Password, Service `Cryptomator`, Account = Vault-ID) ist damit weder bestätigt noch widerlegt — **vor M6 mit einem Menschen am Rechner wiederholen**.

## Zielarchitektur

Cargo-Workspace `/Users/rfoerthe/work/cryptomator-cli` (Verfeinerung des freigegebenen Designs: Settings, Keychain, Daemon-Protokoll und Mount-Orchestrierung liegen zusammen in `cryptomator-app`, da sie dieselben Settings-Typen teilen):

```
Cargo.toml                 workspace, [workspace.dependencies], profiles (release: lto fat, codegen-units 1, strip, panic=unwind)
LICENSE (AGPL-3.0)  README.md  CHANGELOG.md  rust-toolchain.toml (stable)
docs/superpowers/specs/2026-09-04-crypto-cli-design.md   Spec (aus diesem Plan)
docs/{cli.md, daemon-protocol.md, compat.md}
crates/
  cryptomator-core/        Vault-Format 8, Krypto, FS-Logik, Health, Migration, Recovery (std only, kein tokio)
  cryptomator-mount/       MountService-API + Backends (Features: fuse, webdav; default beide)
  cryptomator-app/         settings.json, cli.json, State-Dir, Keychain, Vault-Registry, Mounter-Orchestrierung, Daemon-Protokoll/Client/Server
  crypto/                  Binary (clap): dünne Kommandoschicht, Ausgabe (human/--json), Exit-Codes
xtask/                     lipo (Universal Binary), deb, Fixture-Regenerierung (M8-Deliverable, noch nicht angelegt)
tools/fixture-gen/         Maven-Harness (Java) zum Erzeugen/Verifizieren von Referenz-Vaults
tests/fixtures/            eingecheckte Referenz-Vaults + Manifeste + KAT-Vektoren
packaging/{homebrew/crypto.rb, deb/, man/}
.github/workflows/{ci.yml, release.yml}
```

### `cryptomator-core` – Module und Java-Vorlagen

| Rust-Modul | Verantwortung | Vorlage (Pfad im Sources-JAR bzw. App) |
|---|---|---|
| `crypto/masterkey.rs` | `Masterkey(Zeroizing<[u8;64]>)`, enc = [0..32], mac = [32..64] | cryptolib `api/Masterkey.java` |
| `crypto/kdf.rs`, `crypto/keywrap.rs` | scrypt (N=2^15, r=8, p=1, dkLen 32, Salt‖Pepper, Pepper leer), RFC3394 Wrap/Unwrap | `common/Scrypt.java`, `common/AesKeyWrap.java` |
| `crypto/siv.rs` | `FileNameCryptor`: `hash_directory_id` = BASE32(SHA1(SIV(dirId))), `encrypt_filename`/`decrypt_filename` (base64url mit Padding, AD = [dirId]) | `v2/FileNameCryptorImpl.java`, siv-mode `SivMode.java` |
| `crypto/header.rs`, `crypto/gcm.rs`, `crypto/ctrmac.rs`, `crypto/cryptor.rs` | `FileHeader{nonce, reserved=-1, content_key}`; `ContentCryptor` enum SivGcm (Header 68 B, Chunk 12+32768+16, AAD = BE64(chunkNo)‖headerNonce) / SivCtrMac (Header 88 B, Chunk 16+32768+32, HMAC mit macKey); `cleartext_size/ciphertext_size` exakt wie Java inkl. Fehlerfälle | `v1/*`, `v2/*` (`FileHeaderImpl`, `FileHeaderCryptorImpl`, `FileContentCryptorImpl`, `Constants`) |
| `crypto/stream.rs` | `EncryptingWriter`/`DecryptingReader` mit Leer-Chunk-Semantik (Befund 5) | `common/EncryptingWritableByteChannel.java`, `DecryptingReadableByteChannel.java` |
| `masterkey_file.rs` | JSON (Feldreihenfolge version, scryptSalt, scryptCostParam, scryptBlockSize, primaryMasterKey, hmacMasterKey, versionMac; Std-Base64), `load/persist(.tmp+rename)/change_passphrase/read_alleged_vault_version` | `common/MasterkeyFile.java`, `common/MasterkeyFileAccess.java` |
| `vault_config.rs` | JWT selbst implementiert: `UnverifiedVaultConfig` (kid, alleged format/threshold), `verify(raw_key, 8)` (HS256/384/512 akzeptieren), `to_token` (HS256), `KeyId` → `HubVaultUnsupported` | cryptofs `VaultConfig.java` |
| `constants.rs`, `backup.rs` | Namen/Limits; `.bkup`-Suffix = "." + HEXUPPER(SHA256[0..4]), `attempt_backup` (CREATE_NEW, sonst Vergleich) | `common/Constants.java`, `common/BackupHelper.java` |
| `fs/dir_id.rs`, `fs/long_names.rs` | `dir.c9r` (leer/übergroß → BrokenDirFile, fehlend → zufällige UUID), `dirid.c9r`; Shortening `deflate/inflate` (10 KiB Cap) | `DirectoryIdLoader.java`, `DirectoryIdBackup.java`, `LongFileNameProvider.java` |
| `fs/path_mapper.rs` | `CryptoPathMapper` mit Cache (Präfix-Invalidierung), `CiphertextFilePath`, Typ-Erkennung | `CryptoPathMapper.java`, `CiphertextFilePath.java`, `CiphertextDirCache.java` |
| `fs/dir_stream.rs` | Listing-Pipeline: Filter → `C9rDecryptor` (BASE64-Regex + Delimiter-Narrowing) → `C9rConflictResolver` (" (n)"-Umbenennung) → `C9sInflator` → `.c9u` überspringen → `BrokenDirectoryFilter` | `dir/*.java` |
| `fs/open_file.rs`, `fs/open_files.rs` | `OpenCryptoFile` (Header-Holder, `ChunkCache` 5 Chunks, dirty flags, read_at/write_at/truncate/flush, Sparse-Zero-Fill), Registry pro Ciphertext-Pfad, Two-Phase-Move | `fh/*.java`, `ch/CleartextFileChannel.java` |
| `fs/symlinks.rs`, `fs/attrs.rs`, `fs/crypto_fs.rs`, `fs/stats.rs`, `fs/events.rs`, `fs/capabilities.rs`, `fs/name_decryptor.rs` | Cleartext-FS-Fassade `CryptoFs` (open/read_dir/metadata/create_dir/delete/rename/copy/symlink/read_link/set_times), Statistik-Zähler, Events (DecryptionFailed, ConflictResolved, ConflictResolutionFailed, BrokenDirFile, BrokenFileNode), Capability-Probing (Name-Länge 28..220 in `c/`), `decrypt_filename` mit Pfadvalidierung | `CryptoFileSystemImpl.java`, `MoveOperation.java`, `CopyOperation.java`, `Symlinks.java`, `attr/*`, `CryptoFileSystemStats.java`, `event/*`, `common/FileSystemCapabilityChecker.java`, `FileNameDecryptor.java` |
| `vault/init.rs`, `vault/readme.rs`, `vault/state.rs`, `vault/unlock.rs`, `vault/password.rs` | `initialize` (Config, Root-Dir, dirid.c9r), `create_vault` (WELCOME.rtf innen, IMPORTANT.rtf außen; Texte aus `i18n/strings.properties` `addvault.new.readme.*`), `DirStructure`/`VaultState` mit `.bkup`-Auto-Restore, `UnlockedVault::open` (Masterkey-Backup bei Erfolg), `change_password` | cryptofs `CryptoFileSystemProvider.java`, `CryptoFileSystems.java`, `DirStructure.java`; App `ReadmeGenerator.java`, `VaultListManager.java`, `BackupRestorer.java`, `ChangePasswordController.java` |
| `recovery/words.rs`, `recovery/key.rs`, `recovery/restore.rs` | 12-Bit-Wortkodierung (`include_str!` der kopierten `4096words_en.txt`), 64 B + 2 Low-Bytes CRC32 (LE) → 44 Wörter, Validierung, `new_masterkey_file_with_passphrase`, `detect_scheme` (erster regulärer `.c9r`, beide Header-Varianten probieren), Restore masterkey/config/all über Temp-`RecoveryDirectory` | App `ui/recoverykey/{WordEncoder,RecoveryKeyFactory}.java`, `common/recovery/*.java` |
| `health/{mod,dir_id,file_type,shortened,report}.rs` | Trait `HealthCheck`, `DiagnosticResult{severity, details, fix}`; DirIdCheck (8 Ergebnistypen, Fixes inkl. LOST+FOUND-Adoption), CiphertextFileTypeCheck, ShortenedNamesCheck (6 Typen, Fixes); Report-Format wie `ReportWriter` | cryptofs `health/**`; App `ui/health/ReportWriter.java` |
| `migration/{mod,v6,v7,v8}.rs` | Versionserkennung, 5→6 (NFC-Passphrase, `unicode-normalization`), 6→7 (Capability-Check, PreMigrationVisitor, `FilePathMigration` base32→base64url, `0`/`1S`-Präfixe, `.lng` aus `m/xx/yy/`, bis 3 `_n`-Versuche, `m/` löschen), 7→8 (JWT mit `SIV_CTRMAC`, Threshold 220, version 999) | cryptofs `migration/**` |
| `error.rs` | thiserror `CoreError`: InvalidPassphrase, AuthenticationFailed, VaultVersionMismatch, HubVaultUnsupported, NeedsMigration, FileNameTooLong, NotAVault(reason), ContentRootMissing, Io | diverse Exceptions |

### `cryptomator-app`

- `settings/model.rs`: `SettingsJson`/`VaultSettingsJson` mit nur den genutzten Feldern + `#[serde(flatten)] extra: Map` auf beiden Ebenen; Java-Defaults (port 42427, useKeychain true, revealAfterMount true, autoLockIdleSeconds 1800, actionAfterUnlock ASK, maxCleartextFilenameLength -1, keychainProvider/mountService per OS); `Option`-Felder mit `skip_serializing_if` (entspricht `NON_NULL`); Legacy-Keys (`preferredVolumeImpl`, `useCustomMountPath`/`customMountPath`, `winDriveLetter`) lesen, migrieren und beim Schreiben entfernen. Neue Einträge mit vollem Java-Default-Satz schreiben. Golden-Tests aus `src/test/java/org/cryptomator/common/settings/SettingsJsonTest.java` übernehmen.
- `settings/store.rs`: Pfade macOS `~/Library/Application Support/Cryptomator/settings.json`; Linux `~/.config/Cryptomator/settings.json`, dann `~/.Cryptomator/settings.json`; Override `--settings`/`CRYPTO_SETTINGS_PATH`. Laden tolerant; Speichern pretty JSON → `settings.json.<pid>.tmp` → rename; `writtenByVersion` erhalten (nur bei Neuanlage `crypto-<semver>`). Eine unparsebare settings.json führt zu einem Fehler (Abweichung von Java, das sie stillschweigend ersetzt).
  **M2 liefert ausschließlich das atomare tmp+rename.** `flock` auf `settings.json.lock` und die Warnung bei erreichbarem Desktop-IPC-Socket sind **auf M4 verschoben**, wo der Daemon die Koordination der Settings-Schreiber ohnehin besitzt (siehe Risiko 3). Bis dahin gilt: Desktop-App vor `vault add/remove/set` und `config set` schließen.
- `settings/vault_ref.rs`, `settings/ids.rs`: Auflösung per ID / Anzeigename (eindeutig, erst case-sensitive) / Pfad (kanonisiert); Ad-hoc-Vault per Pfad mit `--no-register`; ID = base64url(9 Zufallsbytes); `normalize_display_name` (mountName-Regeln).
- `cli_config.rs`: `cli.json` neben settings.json (`mountPointsDir`, `defaultMounter`, `logLevel`, `forceUnmountOnSignalAfterSecs`, `webdavBind`).
- `state_dir.rs`: Linux `$XDG_RUNTIME_DIR/crypto` (Fallback `/tmp/crypto-<uid>`, 0700), macOS `~/Library/Application Support/Cryptomator/cli-run`; je Vault `<id>.sock/.pid/.json/.log`.
- `keychain/{mod,macos,linux}.rs`: Trait `Keychain{store, load, delete, change, is_supported, is_locked, java_class_name}`; Mapping Java-Klassennamen ↔ Backend; macOS `security_framework::passwords::*_generic_password("Cryptomator", id)` (Override `CRYPTO_KEYCHAIN_SERVICE`; `TouchIdKeychainAccess` als Lesen best effort); Linux `secret-service` (Default-Collection, Fallback `login`; `search_items({"Vault": id})`; `create_item("Cryptomator", {"Vault","Name"}, replace=true)`), `GnomeKeyringKeychainAccess` gleiches Backend ohne `Name`, KDEWallet → „nicht unterstützt“ mit Hinweis. Async-zbus in Blocking-Helper kapseln.
- `password.rs`: Reihenfolge `--password-stdin` / `--password-file` (≤ 5000 B, ein trailing Newline strippen) / `--password-env` / `CRYPTO_PASSWORD` / Keychain (wenn `useKeychain` und Eintrag vorhanden) / TTY-Prompt (`rpassword`, nur bei Terminal). Neue Passwörter: min. 8 Zeichen, Bestätigung, NFC-Normalisierung.
- `registry.rs`: `VaultRegistry` = settings + state dir → `VaultInfo{id, name, path, state}` inkl. `UNLOCKED@mountpoint` und `STALE_MOUNT`.
- `mounting/mounter.rs`: Port von `Mounter.SettledMounter`: Service-Wahl (vault.mountService → settings.mountService → erster unterstützter), Capabilities anwenden (FILE_SYSTEM_NAME="cryptoFs", LOOPBACK_PORT: vault.mountService null → settings.port sonst vault.port, MOUNT_FLAGS: leer → Default, VOLUME_ID=id, VOLUME_NAME=mountName, READ_ONLY), Mount-Point-Policy (User-Pfad validieren; sonst system-chosen bzw. `mountPointsDir/<mountName>` anlegen und beim Lock wieder entfernen).
- `daemon/{protocol,client,server}.rs`: siehe Daemon-Design.

### `cryptomator-mount`

- `api.rs`: `MountCapability` (12 Varianten, Java-Namen), Traits `MountService{java_class_name, display_name, is_supported, capabilities, default_mount_flags, default_loopback_port, for_file_system}`, `MountBuilder`, `Mount{mountpoint, unmount, unmount_forced}`, `Mountpoint::{Path, Uri}`.
- `registry.rs`: Reihenfolge wie Java-Priority: macOS `[MacFuse(100), FuseT(90), FallbackWebDav]`, Linux `[LinuxFuse(100), FallbackWebDav]`; Lookup per Klassenname; CLI-Aliase `macfuse`, `fuse-t`, `fuse`, `webdav`.
- `flags.rs`: Parser wie `AbstractMountBuilder.setMountFlags` (`\s+-` split, Set-Semantik), `-o` → `fuser::MountOption` (typisiert, sonst `CUSTOM`), `-r` → RO.
- `transcoder.rs`: macOS FUSE-Seite NFD ↔ Vault NFC; Linux Identität.
- `fuse/adapter.rs`: `impl fuser::Filesystem` (Inode-/Handle-Tabellen, readdir, getattr/setattr, create/open/read/write/flush/release/fsync, mkdir/rmdir/unlink/rename inkl. NOREPLACE, symlink/readlink, statfs, xattr = ENOTSUP, errno-Mapping, Aktivitäts-Ticks in Stats).
- `fuse/linux.rs`: Klasse `…LinuxFuseMountProvider`; supported wenn `fusermount3 -V` (2 s Timeout); Caps `{MOUNT_FLAGS, MOUNT_TO_EXISTING_DIR}`; Default-Flags `-oauto_unmount -ouid=<uid> -ogid=<gid> -oattr_timeout=5`; Mount via `fuser::Session::new` (ohne `libfuse`-Feature, fuser ruft `fusermount3`); Unmount `fusermount3 -u -- <name>` (cwd Parent), forced `fusermount3 -uz` (nur wir, Cap `UNMOUNT_FORCED`).
- `fuse/macos_dl.rs`: `libloading` von `fuse_mount_compat25`, `fuse_unmount_compat22`, `struct fuse_args`; argv `["cryptomator-cli", "-o", …]`; liefert `OwnedFd` → `fuser::Session::from_fd`.
- `fuse/macfuse.rs`: Klasse `…MacFuseMountProvider`; supported wenn `/usr/local/lib/libfuse.2.dylib` oder `libosxfuse.2.dylib`; Caps `{MOUNT_FLAGS, UNMOUNT_FORCED, READ_ONLY, MOUNT_TO_EXISTING_DIR, MOUNT_TO_SYSTEM_CHOSEN_PATH, VOLUME_ID, VOLUME_NAME}`; Defaults `-ouid=<uid> -ogid=<gid> -oatomic_o_trunc -oauto_xattr -oauto_cache -onoappledouble -odefault_permissions`; `-ovolname=<name>`, `-r` bei readonly; `-obackend=fskit` ablehnen; ohne Mountpoint `/Volumes/<volumeId>`; Unmount `umount -- <p>` / `umount -f -- <p>`.
- `fuse/fuset.rs`: Klasse `…FuseTMountProvider`; supported wenn `/usr/local/lib/libfuse-t.dylib`; Caps `{MOUNT_FLAGS, UNMOUNT_FORCED, READ_ONLY, MOUNT_TO_EXISTING_DIR, VOLUME_NAME}`; Defaults `-ononamedattr -obackend=smb -orwsize=262144 -ouid=<uid> -ogid=<gid>`; `-ononamedattr` immer anhängen; gleicher dlopen-Pfad. Laut Spike A reicht dieser Pfad mit unverändertem fuser 0.18 **nicht** (macFUSE- statt Linux-`fuse_attr`-Layout) — M4 setzt fuser mit einem Linux-ABI-Feature (Fork/Patch von `fuse_abi.rs`, upstream-tauglich) ein, verifiziert durch einen Folge-Spike. Ebenfalls aus Spike A: `-obackend=smb` ist auf FUSE-T 1.2.7 unbrauchbar (nur der NFS-Helper `go-nfsv4` wird ausgeliefert, `mount -t smbfs` scheitert mit Exit 64) — Default-Backend NFS verwenden.
- `webdav/{fs,server,fallback}.rs`: `impl dav_server::fs::DavFileSystem` über `CryptoFs` (Symlinks verborgen wie Java); hyper 1 + tokio auf `127.0.0.1:<port>` (Port 0 → ephemer), Kontextpfad `"/" + normalize(volumeId)`; `FallbackMounter` (Klasse `org.cryptomator.frontend.webdav.mount.FallbackMounter`, Caps `{LOOPBACK_PORT, VOLUME_ID}`), Werte `MacAppleScriptMounter`/`LinuxGioMounter` aus settings.json akzeptieren und auf Fallback mit Hinweis abbilden (OS-Mount via `open`/`gio mount` als spätere Komfortfunktion).

### `crypto` (Binary) – Kommandogrammatur (freigegeben, Details ergänzt)

```
crypto [--settings PATH] [--json] [-v|-q] [--no-keychain] [--state-dir PATH] [--color auto|always|never] <COMMAND>
Vault-Referenz <VAULT>: ID | Anzeigename | Pfad. Passwortoptionen (max. eine): --password-stdin | --password-file P | --password-env VAR | --password-keychain; sonst CRYPTO_PASSWORD, dann TTY-Prompt.

crypto vault create <path> [--name N] [--shortening-threshold 36..220 (220)] [--show-recovery-key] [--no-register] [--store-password]
crypto vault add <path> [--name N] | remove <VAULT> [--forget-password] | list | info <VAULT>
crypto vault set <VAULT> [--name] [--mount-point P|--no-mount-point] [--read-only true|false] [--mount-flags=S|--default-mount-flags] [--mounter X] [--port N] [--auto-lock-idle SECS|--no-auto-lock] [--max-filename-length N|auto]
crypto unlock <VAULT> [--mounter X] [--mount-point P] [--mount-option -o…]* [--read-only] [--volume-name N] [--port N] [--foreground] [--store-password|--no-store-password] [--reveal]
crypto lock <VAULT>... | --all [--force]
crypto status [<VAULT>] ; crypto stats <VAULT> [--follow] [--interval S] ; crypto events <VAULT> [--follow] [--since N]
crypto fs ls|tree|cat|get|put|rm|mkdir|mv <VAULT> …            (mountlos, arbeitet direkt auf dem Ciphertext)
crypto password change|store|forget <VAULT>
crypto recovery-key show <VAULT> | reset-password <VAULT> (--recovery-key-stdin|--recovery-key-file) | restore <VAULT> (--masterkey|--config|--all) [--cipher-combo auto|SIV_GCM|SIV_CTRMAC] [--shortening-threshold N] | validate
crypto health <VAULT> [--check dirid,type,shortened] [--fix] [--fix-severity WARN|CRITICAL] [--report FILE|--no-report] [--fail-on WARN|CRITICAL]
crypto migrate <VAULT> [--yes]
crypto name decrypt <VAULT> <ciphertext-path>... ; crypto name locate <VAULT> <cleartext-path> [--contents]
crypto config get [key] | set <key> <value>      (mountService, port, useKeychain, keychainProvider, debugMode; mountPointsDir → cli.json)
crypto mounters [--all] ; crypto keychain test ; crypto completions <shell> ; crypto --version
crypto __daemon --vault-id ID --socket P --key-fd N …            (versteckt)
```

Exit-Codes: 0 ok · 1 allgemein · 2 Usage · 3 Vault nicht gefunden/mehrdeutig · 4 Passwort/Recovery-Key ungültig · 5 falscher Vault-Zustand (schon entsperrt, braucht Migration, Config fehlt) · 6 Mount fehlgeschlagen · 7 Unmount fehlgeschlagen (Hinweis `--force`) · 8 Keychain nicht verfügbar · 9 Hub-Vault · 10 Daemon nicht erreichbar · 11 Health-Befunde ≥ `--fail-on` · 12 kein Vault-Verzeichnis. `--json`: ein Objekt (NDJSON bei `--follow`), Feldnamen wie settings.json/VaultState.

### Daemon-Design

1. `crypto unlock` (Elternprozess) löst Vault auf, holt Passwort, führt scrypt + Config-Verifikation selbst aus (Fehler synchron), ermittelt bei `maxCleartextFilenameLength == -1` und nicht read-only die Namenslänge per Capability-Probe und persistiert sie.
2. Erzeugt State-Dir und `pipe()`, schreibt den 64-Byte-Rohkey in das Schreibende; startet `current_exe() __daemon …` mit `pre_exec(setsid)`, cwd `/`, stdin `/dev/null`, stdout/stderr → `<id>.log`, fd 3 = Pipe-Leseende, Env ohne `CRYPTO_PASSWORD`.
3. Verbindet sich mit dem Socket (Retry ≤ 30 s), wartet auf `{"event":"ready","mountpoint":…}` oder `failed`, gibt Mountpoint aus, zeroized den Key. `--foreground`: derselbe Codepfad im Prozess; SIGINT/SIGTERM → sauberer Lock, Eskalation zu forced nach N s (cli.json).
4. State-Dateien: `<id>.sock` (0600), `<id>.pid`, `<id>.json` (`vaultId, path, mounter, mountpoint, pid, startedAt, readOnly`), `<id>.log`. Stale-Erkennung: Socket tot → `kill(pid, 0)`; tot → Dateien löschen; Mountpoint laut `mount`/`/proc/self/mountinfo` noch gemountet → `STALE_MOUNT`, `lock` führt Unmount-Kommando direkt aus.
5. Protokoll (newline-JSON, Daemon grüßt zuerst): `{"hello":"crypto-daemon","protocol":1,"vaultId":…,"pid":…}`; Requests `{"id":n,"op":"status"|"stats"|"lock","force":bool|"events","follow":bool,"since":seq|"ping"|"shutdown"}`; Antworten `{"id":n,"ok":true,"result":{…}}` bzw. `{"ok":false,"error":{"code":"UNMOUNT_FAILED","message":…}}`; Events mit `seq`, Ringpuffer 1000.
6. Lebenszyklus: Key aus fd → `Cryptor` → `CryptoFs` (readonly, Event-Sink) → `Mounter` → mount → `<id>.json` → `ready`; tokio-Runtime für Socket/Timer, FUSE-Session auf fuser-Thread (`BackgroundSession`) bzw. WebDAV als tokio-Task. Timer: Stats-Sampler 1 s (`lastActivity` bei Zugriffszuwachs), Auto-Lock-Tick 60 s (Settings je Tick neu lesen). Shutdown: unmount (graceful, `force` → `umount -f`/`fusermount3 -uz`) → `umount_and_join` → `CryptoFs::close` (flush, zeroize) → State-Dateien löschen → exit. Bei Unmount-Fehler weiterlaufen und Fehler melden (wie `Vault.lock`).
7. WebDAV-Portregel (ein Daemon pro Vault): `vault.port`, wenn `vault.mountService` gesetzt, sonst `settings.port`; bei `EADDRINUSE` Exit 6 mit Hinweis `--port 0`/`vault set --port`. Gemeinsamer WebDAV-Host-Daemon = spätere Erweiterung.

## Crate-Auswahl (Versionen auf crates.io geprüft, Stand 09/2026)

| Zweck | Crate | Hinweis |
|---|---|---|
| CLI | `clap` 4.6 (derive, env, wrap_help), `clap_complete` | |
| AES-SIV | `aes-siv` 0.8 | `siv::Aes256Siv`, Key = mac‖enc, Header-Slices als AD |
| AES-GCM | `aes-gcm` 0.11 | 12-B-Nonce, 16-B-Tag, AAD als ein Slice |
| AES-CTR | `aes` 0.9 + `ctr` 0.10 (`Ctr128BE<Aes256>`) | Java `AES/CTR/NoPadding` = BE-128-Bit-Zähler |
| HMAC/SHA | `hmac` 0.13, `sha2` 0.11, `sha1` 0.11, `cmac` 0.8 | **alle auf der digest-0.11-Generation**; bei M0 `cargo tree -d` prüfen, sonst geschlossen auf die Vorgängergeneration pinnen (aes 0.8/ctr 0.9/aes-gcm 0.10/aes-siv 0.7/hmac 0.12/sha* 0.10/scrypt 0.11/aes-kw 0.2) |
| scrypt / Key-Wrap | `scrypt` 0.12 (log_n 15, r 8, p 1, len 32), `aes-kw` 0.3 (`KekAes256`) | |
| Encodings | `data-encoding` 2.11 | BASE64URL (padded, Namen), BASE64URL_NOPAD (JWT), BASE64 (Masterkey-Datei), BASE32 (Dir-Hash), HEXUPPER (.bkup) |
| JSON/UUID | `serde` 1, `serde_json` 1 (`preserve_order`), `uuid` 1 (v4) | Pretty-Print weicht kosmetisch von Jackson ab (ok) |
| Secrets/RNG/CRC | `zeroize` 1.9, `secrecy` 0.10, `getrandom` 0.3, `crc32fast` 1.5 | |
| Passwort-Prompt | `rpassword` 7.5 + `std::io::IsTerminal` | |
| FUSE | `fuser` 0.18 (ohne `libfuse`-Feature) + `libloading` 0.9 | `Filesystem` mit `&self`, `Session::from_fd`, `MountOption::CUSTOM`; kein pkg-config nötig |
| WebDAV | `dav-server` 0.11 (`hyper`) + `hyper` 1 + `hyper-util` + `http-body-util` | |
| Async/Unix | `tokio` 1 (rt-multi-thread, net, signal, io-util, time, macros), `nix` 0.31 (process, signal, unistd, fcntl) | |
| Keychain | `security-framework` 3.7 (macOS), `secret-service` 5.2 (`rt-tokio-crypto-rust`, Linux) | |
| Logging/Fehler/Temp | `tracing` 0.1 + `tracing-subscriber` 0.3 (env-filter, json), `thiserror` 2, `anyhow` 1, `tempfile` 3, `unicode-normalization` | |
| Tests/Packaging | `assert_cmd` 2, `predicates`, `proptest` 1, `cargo-deb` | |

## Teststrategie

1. **Fixture-Generator** `tools/fixture-gen/` (Maven-Reaktor, JDK ≥ 22, Artefakte aus `~/.m2` bzw. Maven Central):
   - `gen-current` (cryptofs 2.10.0): `gen <outDir>` erzeugt mit Passwort `test-password-123` die Vaults `siv_gcm_basic`, `siv_ctrmac_basic`, `long_names` (146/147/200/1000 Zeichen → `.c9s`), `symlinks` (relativ/absolut/auf Dir/dangling), `nested` (5 Ebenen), `sizes` (0, 1, 32767, 32768, 32769, 65536, 100000 Bytes, deterministischer Inhalt), `unicode` (NFC/NFD, Emoji), `conflicts` (`X (1).c9r`, konfligierendes `dir.c9r`), `threshold_36`; dazu `expected/<vault>.json` (Baum, Größen, SHA-256, Linkziele, dirIds) und `vectors.json` (KATs: scrypt-KEK, gewrappte Keys, `hashDirectoryId("")`, Filename-Samples mit AD, Header/Chunk-Vektoren, Recovery-Key für festen Masterkey, `.bkup`-Suffixe).
   - `verify <vault> <manifest>`: öffnet von Rust erzeugte Vaults mit cryptofs, vergleicht, prüft `FileNameDecryptor`, `DirectoryIdBackup.read`, Health-Checks (alle GOOD/INFO).
   - `gen-legacy-v7/v6/v5` (cryptofs 1.9.15/1.8.9/1.6.2) mit `.lng`-Namen und NFD-Umlaut-Passphrase. Alles unter `tests/fixtures/` (je < 200 KB).
2. **Rust-Tests**: `kat.rs` (vectors.json), `fixtures_read.rs` (alle Fixtures listen/lesen/Symlinks/Namen/Health clean), `fixtures_write.rs` (Vaults aus demselben Manifest nach `target/interop/` → Java `verify`), `migration.rs`; `proptest` für size-Inversen, Chunk-Grenzen, BASE64-Pattern, Flag-Parser, settings-Roundtrip (unbekannte Keys bytegleich als JSON-Werte).
3. **CLI-E2E** mit `assert_cmd` und `HOME`/`--settings` im Tempdir; Exit-Codes; `--json`-Schemas. Mount-E2E hinter `CRYPTO_E2E_MOUNT=1` (Linux CI mit fuse3; macOS CI mit FUSE-T-Cask ohne Kext). Keychain-E2E: Linux `gnome-keyring` unter `dbus-run-session`; macOS `security add-generic-password -s Cryptomator -a <id>` und zurücklesen.

## Build & Packaging

- macOS: `aarch64-apple-darwin` + `x86_64-apple-darwin` → `xtask lipo` Universal Binary; kein Link gegen libfuse (dlopen), läuft ohne FUSE (WebDAV). `MACOSX_DEPLOYMENT_TARGET=12.0`. Optional Developer-ID-Signatur/Notarisierung (stabile Code-Identität reduziert Keychain-Prompts).
- Linux: `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`; kein libfuse zur Build-/Linkzeit (`fusermount3` zur Laufzeit aus `fuse3`); musl-Static als Extra-Artefakt möglich.
- CI (`ci.yml`): **aktuell umgesetzt** ubuntu-22.04 und macos-15 (arm64) mit `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo test --workspace --locked`. macos-13 (x86_64) und ubuntu-22.04-arm sowie die Jobs interop-java (Temurin + Maven-Cache), Mount-E2E und Keychain-E2E sind für **M8** geplant. `release.yml` bei Tag: Build, lipo, `cargo-deb` (`Depends: fuse3`, `Recommends: gnome-keyring`), tar.gz + sha256, GitHub-Release, Homebrew-Formel (`packaging/homebrew/crypto.rb`, Caveats: macfuse oder fuse-t).
- README-Voraussetzungen: macOS macFUSE (Kext) oder FUSE-T (`brew install --cask macos-fuse-t/homebrew-cask/fuse-t`), sonst WebDAV; Linux `fuse3`, ggf. `user_allow_other`, Secret-Service-Daemon für Keychain.

## Phasen und Meilensteine

| M | Umfang | Testbar am Ende |
|---|---|---|
| **M0 Gerüst + Spikes** ✅ | Workspace, Lizenz, CI-Skelett, Spec ins Repo (`xtask` nach M8 verschoben); **Spike A**: dlopen `libfuse-t.dylib`/`libfuse.2.dylib` → `fuse_mount_compat25` → `fuser::Session::from_fd` mit Hello-World-FS (braucht FUSE-T-Installation durch den User); **Spike B**: Desktop-Keychain-Eintrag auf macOS lesen; `cargo tree -d` für RustCrypto-Generationen | Go/No-Go FUSE-T-via-fuser (sonst lowlevel-FFI-Backend einplanen); Keychain-Ansatz bestätigt |
| **M1 Core-Krypto** ✅ | masterkey, scrypt, keywrap, SIV-Namen, Header/Content beide Schemata, Streams, Masterkey-Datei, Vault-Config-JWT, Recovery-Wörter/Key; Fixture-Generator + `vectors.json` | KATs; `recovery-key validate`; Masterkey-Load aller Fixtures |
| **M2 Vault-Metadaten** ✅ [^m2-lock] | Settings-Modell/Store, Vault-Refs, Zustandserkennung + bkup-Restore, `vault create/add/remove/list/info/set`, `password change`, `recovery-key show/reset-password`, `config`, Readme-Erzeugung | Java `verify` akzeptiert Rust-erzeugte leere Vaults; Settings-Roundtrip; Desktop-App öffnet CLI-Vault |
| **M3 Dateisystem + mountlose Ops** | path mapper, dir stream + Konflikte, open files/chunk cache, symlinks, attrs, `fs *`, `name decrypt/locate` | bidirektionaler Interop auf allen Fixtures; proptests |
| **M4 FUSE + Daemon** | fuser-Adapter, Linux-/macFUSE-/FUSE-T-Provider, `Mounter`, Daemon/Protokoll, `unlock/lock/status/stats/events`, Auto-Lock, `mounters` | Mount-E2E Linux-CI + FUSE-T macOS; Koexistenz mit Desktop-App |
| **M5 WebDAV** | dav-server-FS, Server, FallbackMounter, Portregeln | Finder/`gio`/`curl`-E2E |
| **M6 Keychain** | macOS/Linux-Provider, `password store/forget`, Keychain-Unlock, `--store-password` | Keychain-E2E; Einträge mit Desktop-App austauschbar |
| **M7 Health, Restore, Migration** | 3 Checks + Fixes + Report, `recovery-key restore`, Migratoren v6/v7/v8 | beschädigte Fixtures (Harness erzeugt: Orphan-Dir, fehlende dirid, Trailing Bytes …); Legacy-Fixtures migrieren und in Java verifizieren |
| **M8 Release** | Packaging, Docs, Manpages, Completions, Homebrew/deb, `xtask` (lipo/deb/Fixture-Regenerierung), vollständige CI-Matrix (macos-13, ubuntu-22.04-arm, interop-java, Mount-/Keychain-E2E) | Release-Artefakte auf sauberen VMs installierbar |

[^m2-lock]: M2 ist abgeschlossen **ohne** `flock` auf `settings.json.lock` und ohne die Warnung bei laufender Desktop-App; beides ist nach M4 verschoben (Daemon besitzt die Schreiber-Koordination, siehe `settings/store.rs` oben und Risiko 3). Bis dahin: Desktop-App vor `vault add/remove/set` und `config set` schließen.

✅ = abgeschlossen. Jede Phase: TDD, Commit pro Task, Kompatibilitätslauf gegen Fixtures am Ende.

## Erster Umsetzungsschritt nach Freigabe

1. `git init` in `/Users/rfoerthe/work/cryptomator-cli`; Spec aus diesem Plan nach `docs/superpowers/specs/2026-09-04-crypto-cli-design.md` schreiben und committen (Brainstorming-Workflow).
2. Mit dem `writing-plans`-Skill den detaillierten Implementierungsplan für M0+M1 als `docs/superpowers/plans/…` ausarbeiten; Umsetzung per `executing-plans`/`subagent-driven-development`.
3. User-Schritt parallel: FUSE-T oder macFUSE installieren, damit Spike A laufen kann.

## Verifikation (End-to-End)

- `cargo build --workspace --all-features`, `cargo test --workspace`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check` (macOS lokal, Linux CI).
- Interop: `cargo test -p cryptomator-core --test fixtures_read` liest alle Java-Fixtures; `tools/fixture-gen verify` liest Rust-Vaults.
- Manuell auf macOS: `crypto vault create /tmp/v1`, `crypto unlock v1 --mounter fuse-t` (bzw. `webdav` ohne FUSE), Dateien im Finder anlegen, `crypto stats v1`, `crypto lock v1`; Vault in der Desktop-App öffnen und Inhalte prüfen; Desktop-Vault mit `crypto unlock` über Keychain-Passwort öffnen.
- `crypto health` gegen absichtlich beschädigte Fixtures inkl. `--fix`; `crypto migrate` gegen Legacy-Fixtures.

## Offene Risiken

1. **FUSE-T über fuser** (Top-Risiko): Spike A; Fallback lowlevel-FFI-Backend (+ Aufwand). Selbst bei funktionierendem fd können FUSE-T-Protokolldetails (`fuse_init`-Flags, `renamex_np`, `setvolname`) fuser-Anpassungen erfordern.
2. **macOS-Keychain-ACLs**: von Cryptomator.app erzeugte Einträge lösen beim CLI Zugriffs-Prompts aus und umgekehrt; Touch-ID-Einträge ggf. headless nicht lesbar. Signatur mit stabiler Identität und Doku.
3. **Gleichzeitige settings.json-Schreiber**: Desktop-App schreibt die ganze Datei aus dem Speicher (1 s Debounce) → CLI-Änderungen bei laufender App können verloren gehen. M2 liefert nur das kurze RMW-Fenster mit atomarem tmp+rename; flock und die Warnung bei erreichbarem IPC-Socket kommen mit M4 (Daemon). Empfehlung bis dahin: App für `vault add/remove/set` und `config set` schließen.
4. **`.c9u`-In-Use-Marker** (nur mit Hub-Owner aktiv): beim Listing ignorieren, nie erzeugen.
5. **Namensnormalisierung macOS** (NFD FUSE-seitig, NFC im Vault), Finder-`._*`-Dateien (werden normale verschlüsselte Dateien, wie bei Java-WebDAV).
6. **Java-`cleartextSize`-Fehlerfälle** (Größe 0 bei fehlerhaftem letztem Chunk) exakt nachbilden, damit `ls -l` mit der Desktop-App übereinstimmt.
7. **RustCrypto-Versionsabgleich** (digest 0.11) bei M0 prüfen.
8. **Migration 6→7** ist der größte Einzelposten (FilePathMigration, Capability-Probing in `c/`); bewusst spät.
9. **`fusermount3` fehlt in Sandboxes** (Flatpak/snap) → Provider nicht unterstützt, WebDAV-Fallback.
