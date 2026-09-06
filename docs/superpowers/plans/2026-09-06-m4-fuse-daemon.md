# M4: FUSE-Mount + Daemon – Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `crypto unlock <VAULT>` mountet einen Vault per FUSE (Linux libfuse3/`fusermount3`, macOS FUSE-T; macFUSE-Pfad implementiert, aber unverifiziert) in einem Hintergrund-Daemon; `crypto lock|status|stats|events|mounters` sprechen über einen Unix-Socket mit dem Daemon. Dateien, die über den Mount geschrieben werden, liest cryptofs (Java) unverändert.

**Architecture:** Drei Schichten. (1) `cryptomator-mount`: `MountService`/`MountBuilder`/`Mount`-API (Port der `integrations-api`), Flag-Parser, Name-Transcoder, ein von fuser unabhängiger, testbarer Operationskern `fuse/ops.rs` über `Arc<CryptoFs>` (Inode-/Handle-Tabellen, Errno-Mapping) und der dünne `impl fuser::Filesystem` in `fuse/adapter.rs`; Provider für Linux (`fuser::Session::new`, pure-rust/fusermount3), FUSE-T und macFUSE (dlopen `fuse_mount_compat25` → `Session::from_fd`). (2) `cryptomator-app`: State-Dir, `cli.json`, Vault-Registry (UNLOCKED/STALE_MOUNT), `Mounter` (Port von `Mounter.SettledMounter`), Daemon-Protokoll/-Client/-Server (std-Threads + `UnixListener`, kein tokio). (3) `crypto`: `unlock` (Passwort + scrypt im Elternprozess, Namenslängen-Probe, Daemon spawnen, Ready abwarten), `lock`, `status`, `stats`, `events`, `mounters`, verstecktes `__daemon`. fuser 0.18.0 wird als `vendor/fuser` mit einem **Laufzeit-ABI-Schalter** (`KernelAbi::{Native, Linux}`) gepatcht, weil FUSE-T die Linux-Struct-Layouts erwartet (Spike A).

**Tech Stack:** Rust stable ≥ 1.85; `fuser` 0.18.0 (vendored, MIT, `[patch.crates-io]`), `libloading` 0.9, `nix` 0.31 (features `process`, `signal`, `user`, `fs`), `libc` 0.2 (nur im Binary für `setsid`), `signal-hook` 0.3, `log` 0.4 (+ eigener Datei-Logger), `serde`/`serde_json`, `data-encoding`; Tests mit `tempfile`, `assert_cmd`. Java 21+/Maven für Interop.

**Spec:** `docs/superpowers/specs/2026-09-04-crypto-cli-design.md` (Abschnitte `cryptomator-mount`, `cryptomator-app` → `cli_config.rs`, `state_dir.rs`, `registry.rs`, `mounting/mounter.rs`, `daemon/*`, Kommandogrammatur `unlock/lock/status/stats/events/mounters/__daemon`, Daemon-Design, Exit-Codes, Meilenstein M4, Spike A)

## Global Constraints

- Arbeitsverzeichnis `/Users/rfoerthe/work/cryptomator-cli`, Branch `feature/m4-fuse-daemon` (von `main@dd5c038`).
- Lizenz AGPL-3.0-only; `vendor/fuser` behält seine MIT-`LICENSE` und einen `README-VENDORED.md` mit der Patch-Liste. `#![forbid(unsafe_code)]` bleibt in `cryptomator-core` und `cryptomator-app`; `cryptomator-mount` (dlopen/FFI) und das Binary (`pre_exec`) dürfen `unsafe` mit `// SAFETY:`-Kommentar. Kein `unwrap()`/`expect()` auf Eingabedaten in Library-/Binary-Code (Tests dürfen). MSRV 1.85 (keine `io::ErrorKind`-Varianten jünger als 1.85).
- `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo test --workspace --locked` vor jedem Commit sauber; Commit-Nachricht endet mit `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`. Nach Dependency-Änderungen einmal `cargo build` ohne `--locked`, `Cargo.lock` committen.
- `tests/fixtures/` read-only; nichts unter `~/.m2` oder im Desktop-Checkout ändern; **keine** FUSE-Software installieren (FUSE-T 1.2.7 ist installiert: `/usr/local/lib/libfuse-t.dylib`; macFUSE ist NICHT installiert; `fusermount3` fehlt auf dem Mac). Tests dürfen nur unter `CRYPTO_E2E_MOUNT=1` (und `#[ignore]`) wirklich mounten; alle anderen Tests laufen ohne FUSE, ohne Root, ohne Netzwerk.
- Java-Parität (Desktop 1.19 / fuse-nio-adapter 6.0.1 / integrations-api 1.9): Klassennamen `org.cryptomator.frontend.fuse.mount.{LinuxFuseMountProvider,MacFuseMountProvider,FuseTMountProvider}`; Capabilities exakt wie Java (Linux `{MOUNT_FLAGS, MOUNT_TO_EXISTING_DIR}`; macFUSE `{MOUNT_FLAGS, UNMOUNT_FORCED, READ_ONLY, MOUNT_TO_EXISTING_DIR, MOUNT_TO_SYSTEM_CHOSEN_PATH, VOLUME_ID, VOLUME_NAME}`; FUSE-T `{MOUNT_FLAGS, UNMOUNT_FORCED, READ_ONLY, MOUNT_TO_EXISTING_DIR, VOLUME_NAME}`); Default-Flags Linux `-oauto_unmount -ouid=<uid> -ogid=<gid> -oattr_timeout=5`, macFUSE `-ouid=<uid> -ogid=<gid> -oatomic_o_trunc -oauto_xattr -oauto_cache -onoappledouble -odefault_permissions`, FUSE-T `-ononamedattr -orwsize=262144 -ouid=<uid> -ogid=<gid>` (**ohne** `-obackend=smb`, Spike A); `-ononamedattr` wird bei FUSE-T immer angehängt; Flag-Parsing wie `AbstractMountBuilder.setMountFlags` (Split an `\s+-`, Set-Semantik); `-r` bei read-only, `-ovolname=<name>` bei VOLUME_NAME; `-obackend=fskit` bei macFUSE abgelehnt; Mount-Point-Policy wie `Mounter.prepareMountPoint`; Service-Wahl `vault.mountService` → `settings.mountService` → erster unterstützter in Prioritätsreihenfolge (macOS `[MacFuse(100), FuseT(90)]`, Linux `[LinuxFuse(100)]`); macFUSE und FUSE-T schließen sich gegenseitig aus (`CONFLICTING_MOUNT_SERVICES`); Unmount Linux `fusermount3 -u -- <name>` (cwd = Parent), forced `-uz`; macOS `umount -- <p>` / `umount -f -- <p>`; `uid`/`gid`/`attr_timeout`/`entry_timeout` werden vom Adapter interpretiert (Java: libfuse-High-Level), `attr_timeout` Default 1 s wenn nicht gesetzt; Verzeichnislisting liefert `.`/`..`; `chown` no-op (Java), `chmod` no-op mit Erfolg (Ruling, s. u.); xattr → `ENOTSUP`; `rmdir` löscht auf macOS zuerst `._*`/`.DS_Store`-Kinder (Java `deleteAppleDoubleFiles`); Namen FUSE-seitig NFD (macOS) ↔ Vault NFC.
- Daemon-Design (Spec, mit Abweichungen per Ruling): Elternprozess macht scrypt + Config-Verifikation + Namenslängen-Probe (`maxCleartextFilenameLength == -1` und nicht read-only: `ciphertextLimit < shorteningThreshold ? cleartextLimit : i32::MAX`, persistiert wie `Vault.createCryptoFileSystem`), startet `current_exe() __daemon --vault-id ID --socket P --state-dir D [--settings …]` detached (`setsid`, cwd `/`, stdin `/dev/null`, stdout/stderr → `<id>.log`, Env ohne `CRYPTO_PASSWORD`), verbindet sich (Retry ≤ 30 s) und **schickt den 64-Byte-Rohkey als erste Nachricht über den Socket** (`{"op":"unlock","key":<base64>,…}`, Ruling: kein fd 3), wartet auf `ready`/`failed`, zeroized den Key. State-Dateien `<id>.sock` (0600), `<id>.pid`, `<id>.json`, `<id>.log` im State-Dir (0700; macOS `~/Library/Application Support/Cryptomator/cli-run`, Linux `$XDG_RUNTIME_DIR/crypto` sonst `/tmp/crypto-<uid>`; Override `--state-dir`/`CRYPTO_STATE_DIR`). Protokoll newline-JSON, Daemon grüßt zuerst `{"hello":"crypto-daemon","protocol":1,"vaultId":…,"pid":…}`; Requests `{"id":n,"op":…}`; Antworten `{"id":n,"ok":true,"result":{…}}` / `{"id":n,"ok":false,"error":{"code":…,"message":…}}`; Events mit `seq`, Ringpuffer 1000; Stats-Sampler 1 s (`lastActivity`), Auto-Lock-Tick 60 s (Settings je Tick neu lesen); Shutdown: unmount → join → `CryptoFs::close` → State-Dateien löschen → exit; Unmount-Fehler → weiterlaufen und melden.
- Exit-Codes: 0 ok, 1 allgemein, 2 Usage, 3 Vault nicht gefunden, 4 Passwort ungültig, 5 falscher Zustand (auch „schon entsperrt“/„nicht entsperrt“), **6 Mount fehlgeschlagen, 7 Unmount fehlgeschlagen (Hinweis `--force`), 10 Daemon nicht erreichbar**, 9 Hub, 12 kein Vault-Verzeichnis. `--json`: ein Objekt, NDJSON bei `--follow`.
- Passwörter/Keys nie in argv, Logs, Fehlermeldungen oder JSON; Rohkey nur `Zeroizing`; Socket-Nachricht mit Key wird nach dem Parsen gewischt; Log-Datei 0600.
- Rulings (im Code kommentieren, in Task 16 dokumentieren): (1) fuser-Fork mit Laufzeit-`KernelAbi` statt Compile-Feature, damit ein Binary macFUSE (nativ) und FUSE-T (Linux-Layout) bedient; (2) Daemon mit std-Threads/`UnixListener` statt tokio (tokio kommt mit WebDAV in M5); (3) Key-Übergabe über den Socket statt fd 3; (4) `chmod` ist ein erfolgreicher No-op (cryptofs-Rechte kommen aus den Ciphertext-Dateien; Java setzt POSIX-Rechte auf dem Ciphertext, was den Vault nicht verändert); (5) `--port`, `--store-password`, `--no-store-password` erscheinen erst mit M5/M6; (6) ein eingebauter **Null-Mounter** (`org.cryptomator.cli.NullMountProvider`, nur aktiv bei `CRYPTO_ENABLE_NULL_MOUNTER=1`, in `mounters` nur mit `--all` sichtbar) macht Daemon- und CLI-Lebenszyklus ohne FUSE testbar; (7) macFUSE-Provider ist implementiert, aber unverifiziert (nicht installiert) und wird so dokumentiert; (8) FUSE-T ohne `backend=smb`.
- M3-Zusagen, die M4 einlöst: `fs`-Schreibkommandos verweigern bei laufendem Daemon (Exit 5); `fs_loop` → `ELOOP`; Verzeichnis-Cache (20 s) und `DirIdLoader`-Cache mit Expiry; `CryptoFs` bekommt `Drop` → `close_all`.

---

## Dateistruktur

```
Cargo.toml                                          + [patch.crates-io] fuser = { path = "vendor/fuser" }; deps nix, libc, signal-hook, log
vendor/fuser/                                       Kopie von fuser 0.18.0 (src, Cargo.toml, LICENSE, build.rs) + README-VENDORED.md
vendor/fuser/src/mnt/mount_options.rs               + `KernelAbi`, Feld `Config.abi`
vendor/fuser/src/ll/fuse_abi.rs                     + Linux-Layouts unter macOS: fuse_attr_linux, fuse_setattr_in_linux, fuse_getxattr_in_linux, fuse_setxattr_in_linux
vendor/fuser/src/ll/reply.rs, src/reply.rs          ABI-bewusste Antworten (entry/attr/create/readdirplus)
vendor/fuser/src/ll/request.rs, src/request.rs      ABI-bewusstes Parsen (setattr/getxattr/setxattr)
vendor/fuser/src/session.rs                         `abi` durchreichen (from_fd/new → event loop → requests/replies)
crates/cryptomator-core/src/fs/mod.rs               + `FilesystemLoop` Marker-Fehler (für ELOOP)
crates/cryptomator-core/src/fs/path_mapper.rs       + 20-s-Expiry im dir_cache
crates/cryptomator-core/src/fs/dir_id.rs            + 20-s-Expiry im DirIdLoader-Cache
crates/cryptomator-core/src/fs/crypto_fs.rs         + impl Drop (close_all)
crates/cryptomator-mount/Cargo.toml                 features: fuse (default), null-mounter (immer kompiliert, Aktivierung per Env)
crates/cryptomator-mount/src/lib.rs
crates/cryptomator-mount/src/api.rs                 MountCapability, MountService, MountBuilder, Mount, Mountpoint, MountError, UnmountError
crates/cryptomator-mount/src/flags.rs               parse_mount_flags, MountFlags (adapter options + passthrough)
crates/cryptomator-mount/src/transcoder.rs          NameTranscoder (NFC/NFD)
crates/cryptomator-mount/src/mounttab.rs            is_mountpoint (mount / /proc/self/mountinfo)
crates/cryptomator-mount/src/registry.rs            services(), lookup(class), aliases, conflicts, NullMountProvider
crates/cryptomator-mount/src/fuse/mod.rs
crates/cryptomator-mount/src/fuse/errno.rs          io::Error → Errno
crates/cryptomator-mount/src/fuse/inodes.rs         InodeTable
crates/cryptomator-mount/src/fuse/handles.rs        FileHandles, DirHandles
crates/cryptomator-mount/src/fuse/ops.rs            VaultOps (fuser-frei, testbar)
crates/cryptomator-mount/src/fuse/adapter.rs        CryptoFuse: impl fuser::Filesystem
crates/cryptomator-mount/src/fuse/session.rs        FuseSessionHandle (BackgroundSession + unmount)
crates/cryptomator-mount/src/fuse/linux.rs          LinuxFuseMountProvider
crates/cryptomator-mount/src/fuse/macos_dl.rs       LibFuse (dlopen), fuse_mount/unmount
crates/cryptomator-mount/src/fuse/fuset.rs          FuseTMountProvider
crates/cryptomator-mount/src/fuse/macfuse.rs        MacFuseMountProvider
crates/cryptomator-mount/examples/spike_macos_dlopen.rs  Spike C (KernelAbi::Linux für FUSE-T)
crates/cryptomator-mount/tests/mount_e2e.rs         #[ignore], CRYPTO_E2E_MOUNT=1
docs/superpowers/spikes/2026-09-06-spike-c-fuse-t-linux-abi.md
crates/cryptomator-app/Cargo.toml                   + cryptomator-mount, log, nix, signal-hook, data-encoding
crates/cryptomator-app/src/state_dir.rs             StateDir, VaultStateFiles, RunInfo
crates/cryptomator-app/src/cli_config.rs            CliConfig (cli.json)
crates/cryptomator-app/src/registry.rs              VaultRegistry, VaultInfo, RuntimeState
crates/cryptomator-app/src/mounting/mod.rs, mounter.rs   Mounter (SettledMounter-Port), MountHandle
crates/cryptomator-app/src/daemon/mod.rs, protocol.rs, client.rs, server.rs, logging.rs
crates/cryptomator-app/src/error.rs                 + MountFailed, UnmountFailed, DaemonUnreachable, DaemonError
crates/crypto/src/cli.rs                            + unlock/lock/status/stats/events/mounters/__daemon, --state-dir
crates/crypto/src/commands/{unlock,lock,status,stats,events,mounters,daemon}.rs
crates/crypto/src/commands/fs.rs                    + Verweigerung bei UNLOCKED
crates/crypto/src/exit.rs                           + 6/7/10
crates/crypto/tests/cli_daemon.rs                   Lebenszyklus mit Null-Mounter
.github/workflows/ci.yml                            + Jobs mount-e2e-linux (fuse3), mount-e2e-macos (FUSE-T, continue-on-error)
README.md, CHANGELOG.md, Spec                       aktualisiert
```

Gemeinsame Typen (Übersicht; Details in den Tasks):

- `fuser::KernelAbi::{Native, Linux}` in `fuser::Config.abi` (Task 1).
- `cryptomator_mount::api::{MountCapability, MountService, MountBuilder, Mount, Mountpoint, MountError, UnmountError, ServiceInfo}` (Task 3); `flags::{MountFlags, parse_mount_flags, AdapterOptions}` (Task 3); `transcoder::NameTranscoder` (Task 3); `mounttab::is_mountpoint` (Task 3).
- `cryptomator_mount::fuse::{VaultOps, CryptoFuse, FuseSessionHandle}` (Tasks 4–6); Provider (Task 7); `registry::{services, all_services, service_by_class, NULL_MOUNTER_CLASS}` (Task 7).
- `cryptomator_app::{state_dir::StateDir, cli_config::CliConfig, registry::{VaultRegistry, VaultInfo, RuntimeState}, mounting::{Mounter, MountHandle}, daemon::{protocol::*, client::DaemonClient, server::{DaemonConfig, run_daemon}}}` (Tasks 9–11).

---

### Task 1: fuser vendoren und Laufzeit-ABI-Schalter

**Files:**
- Create: `vendor/fuser/**` (Kopie von `~/.cargo/registry/src/index.crates.io-*/fuser-0.18.0/`: `Cargo.toml`, `build.rs`, `LICENSE`, `README.md`, `src/**`; **ohne** `examples/`, `docs/`, `tests/`, `.github/`), `vendor/fuser/README-VENDORED.md`
- Modify: `Cargo.toml` (Workspace), `vendor/fuser/src/mnt/mount_options.rs`, `vendor/fuser/src/ll/fuse_abi.rs`, `vendor/fuser/src/ll/reply.rs`, `vendor/fuser/src/reply.rs`, `vendor/fuser/src/ll/request.rs`, `vendor/fuser/src/request.rs`, `vendor/fuser/src/session.rs`

**Interfaces:**
- Produces: `fuser::KernelAbi { Native, Linux }` (`Copy`, `Default = Native`), `fuser::Config { …, pub abi: KernelAbi }`; `Session::from_fd(fs, fd, acl, config)` und `Session::new` respektieren `config.abi`. Auf Linux sind `Native` und `Linux` identisch.

Hintergrund (Spike A): FUSE-T erkennt unseren Client als `libfuse3` und liest die **Linux**-Layouts; fuser schreibt unter `target_os = "macos"` die macFUSE-Layouts. Betroffen (alle `#[cfg(target_os = "macos")]`-Felder in `fuse_abi.rs`): Antworten `fuse_attr` (in `fuse_entry_out`, `fuse_attr_out`, `fuse_create`-Antwort = entry_out + open_out, `readdirplus`-Einträge); Anfragen `fuse_setattr_in` (macOS hängt `bkuptime, chgtime, crtime, bkuptimensec, chgtimensec, crtimensec, flags` an), `fuse_getxattr_in` / `fuse_setxattr_in` (macOS: `position`, `padding`). Die macOS-only-Operationen `FUSE_SETVOLNAME/GETXTIMES/EXCHANGE` schickt FUSE-T nicht. `FUSE_KERNEL_MINOR_VERSION = 19` bleibt (Handshake im Spike ok).

- [ ] **Step 1: Vendoren und einbinden**

```bash
SRC=$(ls -d ~/.cargo/registry/src/index.crates.io-*/fuser-0.18.0 | head -1)
mkdir -p vendor/fuser && cp -R "$SRC"/{Cargo.toml,build.rs,LICENSE,README.md,src} vendor/fuser/
rm -rf vendor/fuser/src/../examples  # (nur falls mitkopiert)
```

`Cargo.toml` (Workspace) ergänzen:

```toml
[patch.crates-io]
fuser = { path = "vendor/fuser" }
```

und in `[workspace.dependencies]`: `nix = { version = "0.31", features = ["process", "signal", "user", "fs"] }`, `libc = "0.2"`, `signal-hook = "0.3"`, `log = "0.4"`. `vendor/fuser/Cargo.toml`: `[package] publish = false` ergänzen; `[[example]]`-Blöcke und `[dev-dependencies]`, die nur Beispiele/Tests brauchen, entfernen, damit `--locked`-Builds keine unnötigen Crates ziehen (behalten: alles, was `src/` braucht; `cargo build -p fuser` muss durchlaufen).

`vendor/fuser/README-VENDORED.md`:

```markdown
# Vendored fuser 0.18.0

Upstream: https://github.com/cberner/fuser (MIT, see LICENSE). Vendored because FUSE-T on macOS
speaks the Linux struct layouts while fuser hard-codes the macFUSE layouts under `target_os = "macos"`.

Patches (all under `#[cfg(target_os = "macos")]`, no behaviour change on Linux):
- `Config.abi: KernelAbi` (`Native` = upstream behaviour, `Linux` = Linux struct layouts).
- Linux-layout twins `fuse_attr_linux`, `fuse_setattr_in_linux`, `fuse_getxattr_in_linux`,
  `fuse_setxattr_in_linux` in `src/ll/fuse_abi.rs`.
- Replies (`entry`, `attr`, `create`, `readdirplus`) serialise the twin when `abi == Linux`.
- Requests (`setattr`, `getxattr`, `setxattr`) parse the twin when `abi == Linux`.
- `examples/`, `docs/`, `tests/` dropped.
Upstream-worthy as a feature-less runtime switch; see docs/superpowers/spikes/2026-09-04-spike-a-fuse-t.md.
```

- [ ] **Step 2: Failing test im Fork**

In `vendor/fuser/src/ll/reply.rs` (Testmodul, nur macOS):

```rust
#[cfg(all(test, target_os = "macos"))]
mod abi_tests {
    use super::*;
    use crate::{FileAttr, FileType, INodeNo, KernelAbi};
    use std::time::{Duration, UNIX_EPOCH};

    fn attr() -> FileAttr {
        FileAttr {
            ino: INodeNo(1), size: 0, blocks: 1, atime: UNIX_EPOCH, mtime: UNIX_EPOCH, ctime: UNIX_EPOCH,
            crtime: UNIX_EPOCH, kind: FileType::Directory, perm: 0o755, nlink: 1, uid: 501, gid: 20,
            rdev: 0, flags: 0, blksize: 512,
        }
    }

    #[test]
    fn linux_abi_attr_out_is_88_byte_layout() {
        let native = ResponseStruct::new_attr(&Duration::from_secs(1), &(&attr()).into(), KernelAbi::Native).to_bytes();
        let linux = ResponseStruct::new_attr(&Duration::from_secs(1), &(&attr()).into(), KernelAbi::Linux).to_bytes();
        assert_eq!(native.len(), 16 + 104);
        assert_eq!(linux.len(), 16 + 88);
        // Linux layout: mode at attr offset 60, nlink 64, uid 68, gid 72, rdev 76, blksize 80, flags 84
        let a = &linux[16..];
        let u32_at = |o: usize| u32::from_ne_bytes(a[o..o + 4].try_into().unwrap());
        assert_eq!(u32_at(60), 0o040755);
        assert_eq!(u32_at(64), 1);
        assert_eq!(u32_at(68), 501);
        assert_eq!(u32_at(72), 20);
        assert_eq!(u32_at(80), 512);
    }
}
```

(Die konkreten Konstruktor-Namen/-Signaturen sind an fusers vorhandene `ResponseStruct::new_attr/new_entry/new_create` anzupassen; der Test muss die Byte-Layouts prüfen, nicht Namen.)

- [ ] **Step 3: Patch**

`mount_options.rs`:

```rust
/// Which kernel struct layouts the peer expects. macFUSE uses the Darwin layouts fuser ships under
/// `target_os = "macos"`; FUSE-T (a userspace NFS/SMB server) expects the Linux ones.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub enum KernelAbi {
    #[default]
    Native,
    Linux,
}
```

`Config` bekommt `pub abi: KernelAbi` (Default `Native`; `#[non_exhaustive]` bleibt, Konstruktion über `Config::default()` + Feldzuweisung). `lib.rs`: `pub use crate::mnt::mount_options::KernelAbi;`.

`fuse_abi.rs` (macOS): Zwillinge ohne die macOS-Felder:

```rust
#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Debug, IntoBytes, Clone, Copy, KnownLayout, Immutable)]
pub(crate) struct fuse_attr_linux {
    pub(crate) ino: u64, pub(crate) size: u64, pub(crate) blocks: u64,
    pub(crate) atime: i64, pub(crate) mtime: i64, pub(crate) ctime: i64,
    pub(crate) atimensec: u32, pub(crate) mtimensec: u32, pub(crate) ctimensec: u32,
    pub(crate) mode: u32, pub(crate) nlink: u32, pub(crate) uid: u32, pub(crate) gid: u32,
    pub(crate) rdev: u32, pub(crate) blksize: u32, pub(crate) flags: u32,
}
#[cfg(target_os = "macos")]
impl From<&fuse_attr> for fuse_attr_linux { /* Feld für Feld, flags = 0 */ }
```

analog `fuse_entry_out_linux { nodeid, generation, entry_valid, attr_valid, entry_valid_nsec, attr_valid_nsec, attr: fuse_attr_linux }`, `fuse_attr_out_linux { attr_valid, attr_valid_nsec, dummy, attr: fuse_attr_linux }`, `fuse_setattr_in_linux` (= die Felder bis einschließlich `unused5`), `fuse_getxattr_in_linux { size, padding }`, `fuse_setxattr_in_linux { size, flags }`.

Antwortpfad: Die `Reply*`-Objekte (`src/reply.rs`) erhalten ein Feld `abi: KernelAbi`, gesetzt vom Request-Dispatcher (`src/request.rs` `reply::<T>()` → `Reply::new(unique, sender, abi)`); `ll::ResponseStruct::new_entry/new_attr/new_create` und `DirEntryPlus::new` bekommen den `abi`-Parameter und serialisieren unter macOS bei `Linux` die Zwillinge. Anfragepfad: `ll::request::AnyRequest`/`Operation`-Parsing bekommt `abi`; bei `Linux` werden `setattr/getxattr/setxattr` über die Zwillinge geparst und in dieselben `Operation`-Varianten überführt (`crtime/chgtime/bkuptime/flags` = `None`, `position` = 0). `session.rs`: `Session` speichert `abi` aus `config`, `SessionEventLoop` reicht es an `RequestWithSender::new` durch. Auf Linux (`not(target_os = "macos")`) sind alle Verzweigungen `Native`-Pfade (`let _ = abi;`), damit kein `dead_code` entsteht.

- [ ] **Step 4: Tests**

Run: `cargo test -p fuser --locked` (macOS) und `cargo build --workspace --locked`
Expected: PASS inkl. `abi_tests`; Workspace baut mit `fuser (path+vendor/fuser)` im `Cargo.lock`.

- [ ] **Step 5: Gate + Commit** („Vendor fuser 0.18.0 with a runtime Linux-ABI switch for FUSE-T“)

---

### Task 2: Spike C – FUSE-T mit Linux-ABI verifizieren

**Files:**
- Modify: `crates/cryptomator-mount/examples/spike_macos_dlopen.rs`
- Create: `docs/superpowers/spikes/2026-09-06-spike-c-fuse-t-linux-abi.md`

**Interfaces:** keine neuen; Gate für Task 6/7.

- [ ] **Step 1: Beispiel anpassen**

Im Beispiel: für `fuse-t` die Optionen auf `["-o", "nonamedattr"]` reduzieren (kein `backend=smb`) und `config.abi = KernelAbi::Linux`; für `macfuse` `KernelAbi::Native`. `attr()` liefert `nlink: 2` für das Root-Verzeichnis; `statfs` mit `reply.statfs(1_000_000, 500_000, 500_000, 1000, 500, 4096, 255, 4096)` implementieren (FUSE-T fragt STATFS zuerst).

- [ ] **Step 2: Ausführen (macOS, FUSE-T installiert)**

```bash
mkdir -p /tmp/spike-c-mnt
cargo run -p cryptomator-mount --example spike_macos_dlopen -- fuse-t /tmp/spike-c-mnt &
sleep 3; mount | grep spike-c-mnt; cat /tmp/spike-c-mnt/hello.txt; ls -la /tmp/spike-c-mnt; umount /tmp/spike-c-mnt; wait
```

Expected: Mount erscheint in der mount-Tabelle, `cat` gibt `Hello from crypto spike A!`, `umount` beendet das Programm mit `session ended (unmounted)`. Bei Fehlschlag: FUSE-T-Log `~/Library/Logs/fuse-t/fuse-t.log` auswerten, Struct-Offsets nachrechnen (Spike-A-Tabelle), Fork nachbessern — **Task 2 endet erst, wenn der Mount funktioniert** (Root-Cause-Analyse im Spike-Dokument, ggf. ist `fuse_open_out`/`fuse_statfs_out`/`fuse_init_out` ebenfalls betroffen; alle Layouts gegen `fuse_kernel.h` von libfuse 3 prüfen).

- [ ] **Step 3: Spike-Dokument** nach dem Muster von Spike A (Setup, Tabelle Backend/Ergebnis, Beobachtungen, Konsequenz), plus manueller Befund zu `ls -la` (Attribute korrekt: `drwxr-xr-x`, uid/gid).

- [ ] **Step 4: Gate + Commit** („Spike C: FUSE-T mounts with the Linux-ABI fuser session“)

---

### Task 3: Mount-API, Flag-Parser, Transcoder, Mount-Tabelle

**Files:**
- Modify: `crates/cryptomator-mount/Cargo.toml`, `crates/cryptomator-mount/src/lib.rs`
- Create: `crates/cryptomator-mount/src/api.rs`, `flags.rs`, `transcoder.rs`, `mounttab.rs`

**Interfaces:**
- Produces (`api.rs`):

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum MountCapability { FileSystemName, LoopbackHostName, LoopbackPort, MountFlags, MountToExistingDir, MountWithinExistingParent, MountAsDriveLetter, MountToSystemChosenPath, ReadOnly, UnmountForced, VolumeId, VolumeName }
impl MountCapability { pub fn java_name(self) -> &'static str /* "FILE_SYSTEM_NAME" … */ }

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum Mountpoint { Path(PathBuf), Uri(String) }

#[derive(Debug, thiserror::Error)]
pub enum MountError { #[error("mount point {0}: {1}")] MountPoint(PathBuf, String), #[error("unsupported mount flag {0}")] UnsupportedFlag(String), #[error("{0}")] Failed(String), #[error(transparent)] Io(#[from] std::io::Error) }
#[derive(Debug, thiserror::Error)]
pub enum UnmountError { #[error("unmount failed: {0}")] Failed(String), #[error("filesystem busy")] Busy, #[error(transparent)] Io(#[from] std::io::Error) }

pub trait Mount: Send {
    fn mountpoint(&self) -> Mountpoint;
    fn unmount(&mut self) -> Result<(), UnmountError>;          // graceful
    fn unmount_forced(&mut self) -> Result<(), UnmountError>;   // only if UnmountForced capability
    fn close(self: Box<Self>) -> Result<(), UnmountError>;      // join session; unmount first if still mounted
}
pub trait MountBuilder: Send {
    fn set_file_system_name(&mut self, _: &str) -> Result<(), MountError> { Err(unsupported()) }
    fn set_loopback_port(&mut self, _: u16) -> Result<(), MountError> { Err(unsupported()) }
    fn set_mountpoint(&mut self, _: &Path) -> Result<(), MountError> { Err(unsupported()) }
    fn set_mount_flags(&mut self, _: &str) -> Result<(), MountError> { Err(unsupported()) }
    fn set_read_only(&mut self, _: bool) -> Result<(), MountError> { Err(unsupported()) }
    fn set_volume_id(&mut self, _: &str) -> Result<(), MountError> { Err(unsupported()) }
    fn set_volume_name(&mut self, _: &str) -> Result<(), MountError> { Err(unsupported()) }
    fn mount(self: Box<Self>) -> Result<Box<dyn Mount>, MountError>;
}
pub trait MountService: Send + Sync {
    fn java_class_name(&self) -> &'static str;
    fn display_name(&self) -> &'static str;
    fn priority(&self) -> u32;
    fn is_supported(&self) -> bool;
    fn capabilities(&self) -> &'static [MountCapability];
    fn has_capability(&self, c: MountCapability) -> bool { self.capabilities().contains(&c) }
    fn default_mount_flags(&self) -> String;
    fn default_loopback_port(&self) -> Option<u16> { None }
    fn for_file_system(&self, fs: Arc<CryptoFs>) -> Box<dyn MountBuilder>;
}
#[derive(Debug, Clone, serde::Serialize)] #[serde(rename_all = "camelCase")]
pub struct ServiceInfo { pub class_name: String, pub display_name: String, pub alias: Option<String>, pub supported: bool, pub priority: u32, pub capabilities: Vec<String>, pub default_mount_flags: String }
```

- Produces (`flags.rs`): `parse_mount_flags(&str) -> Vec<String>` (Java-Split, Set-Semantik: Reihenfolge der ersten Nennung, Duplikate entfernt); `struct MountFlags { pub read_only: bool, pub adapter: AdapterOptions, pub passthrough: Vec<String> /* "-o…"-Strings ohne Präfix, z. B. "volname=X" */ }`; `struct AdapterOptions { pub uid: u32, pub gid: u32, pub attr_timeout: Duration /* 1 s */, pub entry_timeout: Duration /* = attr_timeout wenn nicht gesetzt */, pub volname: Option<String>, pub no_apple_double: bool, pub default_permissions: bool, pub allow_other: bool, pub allow_root: bool, pub auto_unmount: bool }`; `MountFlags::from_flags(flags: &[String], current_uid: u32, current_gid: u32) -> Result<MountFlags, MountError>` (erkennt `-r`/`-oro` → read_only; `-ouid=`/`-ogid=` (u32), `-oattr_timeout=`/`-oentry_timeout=` (Sekunden, auch Dezimal), `-ovolname=`, `-onoappledouble`, `-odefault_permissions`, `-oallow_other`, `-oallow_root`, `-oauto_unmount`; alles andere landet in `passthrough`; Flags, die nicht mit `-o` oder `-r` beginnen → `UnsupportedFlag`); `MountFlags::linux_mount_options(&self) -> Vec<fuser::MountOption>` (typisiert: `ro`, `default_permissions`, `auto_unmount`, `fsname=`, `subtype=`, `dev/nodev/suid/nosuid/exec/noexec/atime/noatime/sync/async/dirsync`; **nicht** weitergegeben: `uid/gid/attr_timeout/entry_timeout/volname/noappledouble` (Adapter); Rest `CUSTOM`).
- Produces (`transcoder.rs`): `#[derive(Clone, Copy)] pub enum FuseNormalization { Nfc, Nfd }`, `pub struct NameTranscoder { fuse: FuseNormalization }` mit `fuse_to_vault(&OsStr) -> Option<String>` (UTF-8 + NFC), `vault_to_fuse(&str) -> OsString` (NFD auf macOS-Providern), `for_platform_default()` (Linux Nfc, macOS Nfd).
- Produces (`mounttab.rs`): `pub fn is_mountpoint(path: &Path) -> bool` (Linux `/proc/self/mountinfo` Feld 5 mit `\040`-Unescape; macOS `mount`-Kommando: Zeilen `… on <path> (…)`), `pub fn mounted_paths() -> Vec<PathBuf>`.

- [ ] **Step 1: Failing tests** (Unit-Tests je Modul)

`flags.rs`:

```rust
#[test]
fn splits_like_java_and_dedups() {
    assert_eq!(parse_mount_flags(" -ouid=501 -ogid=20   -ouid=501 -r"), vec!["-ouid=501", "-ogid=20", "-r"]);
    assert_eq!(parse_mount_flags(""), Vec::<String>::new());
    assert_eq!(parse_mount_flags("-ovolname=My Vault -oattr_timeout=5"), vec!["-ovolname=My Vault", "-oattr_timeout=5"]);
}
#[test]
fn classifies_adapter_and_passthrough_options() {
    let f = MountFlags::from_flags(&parse_mount_flags("-oauto_unmount -ouid=501 -ogid=20 -oattr_timeout=5 -ovolname=Secret -r -ononamedattr -orwsize=262144"), 1000, 1000).unwrap();
    assert!(f.read_only);
    assert_eq!((f.adapter.uid, f.adapter.gid), (501, 20));
    assert_eq!(f.adapter.attr_timeout, Duration::from_secs(5));
    assert_eq!(f.adapter.entry_timeout, Duration::from_secs(5));
    assert_eq!(f.adapter.volname.as_deref(), Some("Secret"));
    assert!(f.adapter.auto_unmount);
    assert_eq!(f.passthrough, vec!["nonamedattr", "rwsize=262144"]);
    let opts = f.linux_mount_options();
    assert!(opts.contains(&fuser::MountOption::RO) && opts.contains(&fuser::MountOption::AutoUnmount));
    assert!(opts.contains(&fuser::MountOption::CUSTOM("nonamedattr".into())));
    assert!(!opts.iter().any(|o| matches!(o, fuser::MountOption::CUSTOM(s) if s.starts_with("uid="))));
    let d = MountFlags::from_flags(&[], 7, 8).unwrap();
    assert_eq!((d.adapter.uid, d.adapter.gid, d.adapter.attr_timeout), (7, 8, Duration::from_secs(1)));
    assert!(matches!(MountFlags::from_flags(&parse_mount_flags("--weird"), 0, 0), Err(MountError::UnsupportedFlag(_))));
    assert!(matches!(MountFlags::from_flags(&parse_mount_flags("-ouid=abc"), 0, 0), Err(MountError::UnsupportedFlag(_))));
}
```

`transcoder.rs`:

```rust
#[test]
fn nfd_on_fuse_side_nfc_in_vault() {
    let t = NameTranscoder::new(FuseNormalization::Nfd);
    assert_eq!(t.fuse_to_vault(OsStr::new("cafe\u{301}.txt")).unwrap(), "caf\u{e9}.txt");
    assert_eq!(t.vault_to_fuse("caf\u{e9}.txt"), OsString::from("cafe\u{301}.txt"));
    let id = NameTranscoder::new(FuseNormalization::Nfc);
    assert_eq!(id.vault_to_fuse("caf\u{e9}.txt"), OsString::from("caf\u{e9}.txt"));
    assert!(t.fuse_to_vault(OsStr::from_bytes(&[0xff, 0xfe])).is_none());
}
```

`mounttab.rs`:

```rust
#[test]
fn parses_linux_mountinfo_and_macos_mount_output() {
    let mi = "36 35 98:0 /mnt1 /mnt/my\\040vault rw,relatime - fuse cryptoFs rw\n37 35 0:1 / /proc rw - proc proc rw\n";
    assert_eq!(parse_mountinfo(mi), vec![PathBuf::from("/mnt/my vault"), PathBuf::from("/proc")]);
    let mo = "/dev/disk3s1s1 on / (apfs, sealed, local)\nfuse-t:/vault on /Users/x/mnt/Vault (nfs, nodev)\n";
    assert_eq!(parse_macos_mount(mo), vec![PathBuf::from("/"), PathBuf::from("/Users/x/mnt/Vault")]);
    assert!(is_mountpoint(Path::new("/")));
    assert!(!is_mountpoint(Path::new("/definitely/not/mounted")));
}
```

`api.rs`: `capabilities` Java-Namen (`MountCapability::MountToExistingDir.java_name() == "MOUNT_TO_EXISTING_DIR"`), `Mountpoint` serialisiert als `{"path": …}` / `{"uri": …}`.

- [ ] **Step 2: Implementierung** gemäß Interfaces; `Cargo.toml` der Mount-Crate: `serde`, `serde_json`, `thiserror`, `unicode-normalization`, `nix` (features `fs`, `user`), `log`; `fuser`/`libloading` unter Feature `fuse` (default).

- [ ] **Step 3: Tests** `cargo test -p cryptomator-mount` → PASS

- [ ] **Step 4: Gate + Commit** („Add mount service API, flag parser, name transcoder and mount table probe“)

---

### Task 4: Errno-Mapping, Inode- und Handle-Tabellen (+ `FilesystemLoop`-Marker im Core)

**Files:**
- Create: `crates/cryptomator-mount/src/fuse/mod.rs`, `fuse/errno.rs`, `fuse/inodes.rs`, `fuse/handles.rs`
- Modify: `crates/cryptomator-core/src/fs/mod.rs` (`FilesystemLoop`), `crates/cryptomator-core/src/fs/symlinks.rs` (nutzt ihn)

**Interfaces:**
- Core: `pub struct FilesystemLoop(pub String)` (`Display` „…: too many levels of symbolic links“, `std::error::Error`); `fs_loop(path)` erzeugt `io::Error::new(Other, FilesystemLoop(path.to_string()))`; Test: `err.get_ref().and_then(|e| e.downcast_ref::<FilesystemLoop>()).is_some()`.
- `errno.rs`: `pub fn errno_for(err: &io::Error) -> fuser::Errno`: `raw_os_error()` → `Errno::from_i32`; sonst Kind: NotFound→ENOENT, AlreadyExists→EEXIST, NotADirectory→ENOTDIR, IsADirectory→EISDIR, DirectoryNotEmpty→ENOTEMPTY, PermissionDenied→EACCES, ReadOnlyFilesystem→EROFS, InvalidInput→EINVAL, InvalidData→EIO, UnexpectedEof→EIO, Unsupported→ENOTSUP, `Other` mit `FilesystemLoop` → ELOOP, sonst EIO.
- `inodes.rs`:

```rust
pub struct InodeTable { /* Mutex<Inner> */ }
struct Inner { by_ino: HashMap<u64, Entry>, by_path: HashMap<CleartextPath, u64>, next: u64 }
struct Entry { path: CleartextPath, lookups: u64 }
impl InodeTable {
    pub fn new() -> Self;                                            // ino 1 = root, lookups = u64::MAX/2 (never forgotten)
    pub fn path(&self, ino: u64) -> Option<CleartextPath>;
    pub fn lookup(&self, path: &CleartextPath) -> u64;               // get-or-insert, lookups += 1
    pub fn forget(&self, ino: u64, n: u64);                          // remove when lookups reaches 0 (never ino 1)
    pub fn rename(&self, from: &CleartextPath, to: &CleartextPath);  // re-keys `from` and every descendant (rebase)
    pub fn remove_path(&self, path: &CleartextPath);                 // after unlink/rmdir: drop the path→ino mapping but keep ino→path until forget (like libfuse: open handles keep working)
    pub fn len(&self) -> usize;
}
```

- `handles.rs`: `pub struct FileHandles { … }` mit `insert(OpenFileEntry) -> u64` (ab 1, monoton), `get(u64) -> Option<Arc<OpenFileEntry>>`, `remove(u64) -> Option<OpenFileEntry>`; `pub struct OpenFileEntry { pub handle: cryptomator_core::fs::FileHandle, pub path: CleartextPath, pub append: bool, pub writable: bool }`; `pub struct DirHandles` analog mit `DirSnapshot { pub entries: Vec<DirListing> }`, `DirListing { pub name: OsString, pub ino: u64, pub kind: fuser::FileType }` (inkl. `.`/`..`).

- [ ] **Step 1: Failing tests** (`inodes.rs`)

```rust
#[test]
fn lookup_forget_rename_and_remove() {
    let t = InodeTable::new();
    assert_eq!(t.path(1).unwrap(), CleartextPath::root());
    let a = t.lookup(&CleartextPath::parse("/a"));
    let ab = t.lookup(&CleartextPath::parse("/a/b"));
    assert_eq!(t.lookup(&CleartextPath::parse("/a")), a, "stable");
    assert!(a >= 2 && ab > a);
    t.rename(&CleartextPath::parse("/a"), &CleartextPath::parse("/x"));
    assert_eq!(t.path(ab).unwrap().to_string(), "/x/b");
    assert_eq!(t.lookup(&CleartextPath::parse("/x")), a);
    t.remove_path(&CleartextPath::parse("/x/b"));
    assert_eq!(t.path(ab).unwrap().to_string(), "/x/b", "ino survives until forget");
    assert_ne!(t.lookup(&CleartextPath::parse("/x/b")), ab, "a re-created path gets a fresh ino");
    t.forget(a, 1);
    assert!(t.path(a).is_some(), "two lookups, one forget");
    t.forget(a, 1);
    assert!(t.path(a).is_none());
    t.forget(1, u64::MAX);
    assert!(t.path(1).is_some(), "root is never forgotten");
}
```

`errno.rs`: Tabelle aller Kinds oben + `raw_os_error(libc::ENOSPC)` → `Errno::ENOSPC` + `FilesystemLoop` → `ELOOP`.

- [ ] **Step 2: Implementierung** (Mutex via `lock`-Helfer wie im Core, kein Poison-Panic).

- [ ] **Step 3: Tests** `cargo test -p cryptomator-mount fuse:: && cargo test -p cryptomator-core fs::symlinks` → PASS

- [ ] **Step 4: Gate + Commit** („Add errno mapping, inode and handle tables for the FUSE adapter“)

---

### Task 5: `VaultOps` – der fuser-freie Operationskern

**Files:**
- Create: `crates/cryptomator-mount/src/fuse/ops.rs`

**Interfaces:**

```rust
pub struct VaultOpsConfig { pub transcoder: NameTranscoder, pub options: AdapterOptions, pub read_only: bool, pub delete_apple_double: bool /* macOS providers */, pub max_name_length: u32 /* statfs namelen = max_cleartext_name_length */ }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attr { pub ino: u64, pub size: u64, pub blocks: u64, pub atime: SystemTime, pub mtime: SystemTime, pub ctime: SystemTime, pub crtime: SystemTime, pub kind: fuser::FileType, pub perm: u16, pub nlink: u32, pub uid: u32, pub gid: u32, pub blksize: u32 }
pub struct Statfs { pub blocks: u64, pub bfree: u64, pub bavail: u64, pub files: u64, pub ffree: u64, pub bsize: u32, pub namelen: u32, pub frsize: u32 }
pub struct Created { pub attr: Attr, pub fh: u64 }
pub struct VaultOps { fs: Arc<CryptoFs>, inodes: InodeTable, files: FileHandles, dirs: DirHandles, cfg: VaultOpsConfig, vault_path: PathBuf }
impl VaultOps {
    pub fn new(fs: Arc<CryptoFs>, cfg: VaultOpsConfig) -> Self;
    pub fn lookup(&self, parent: u64, name: &OsStr) -> Result<Attr, Errno>;
    pub fn forget(&self, ino: u64, n: u64);
    pub fn getattr(&self, ino: u64, fh: Option<u64>) -> Result<Attr, Errno>;
    pub fn setattr(&self, ino: u64, fh: Option<u64>, size: Option<u64>, atime: Option<TimeOrNow>, mtime: Option<TimeOrNow>) -> Result<Attr, Errno>;  // mode/uid/gid ignored (ruling)
    pub fn readlink(&self, ino: u64) -> Result<Vec<u8>, Errno>;
    pub fn mkdir(&self, parent: u64, name: &OsStr) -> Result<Attr, Errno>;
    pub fn unlink(&self, parent: u64, name: &OsStr) -> Result<(), Errno>;   // EISDIR for directories
    pub fn rmdir(&self, parent: u64, name: &OsStr) -> Result<(), Errno>;    // ENOTDIR for non-dirs; AppleDouble sweep when configured
    pub fn symlink(&self, parent: u64, link_name: &OsStr, target: &Path) -> Result<Attr, Errno>;
    pub fn rename(&self, parent: u64, name: &OsStr, newparent: u64, newname: &OsStr, noreplace: bool, exchange: bool) -> Result<(), Errno>;  // exchange → EINVAL
    pub fn open(&self, ino: u64, flags: OpenFlags) -> Result<u64, Errno>;   // acc_mode + O_TRUNC + O_APPEND; write on read-only vault → EROFS; directory → EISDIR
    pub fn create(&self, parent: u64, name: &OsStr, flags: OpenFlags) -> Result<Created, Errno>;  // O_EXCL → create_new else create; EEXIST
    pub fn read(&self, fh: u64, offset: u64, size: u32) -> Result<Vec<u8>, Errno>;
    pub fn write(&self, fh: u64, offset: u64, data: &[u8]) -> Result<u32, Errno>;  // append → at current size
    pub fn flush(&self, fh: u64) -> Result<(), Errno>;
    pub fn release(&self, fh: u64) -> Result<(), Errno>;                     // close(); EBADF if unknown
    pub fn fsync(&self, fh: u64, datasync: bool) -> Result<(), Errno>;
    pub fn opendir(&self, ino: u64) -> Result<u64, Errno>;                   // snapshot listing incl. "." and ".." with inos
    pub fn readdir(&self, fh: u64, offset: u64) -> Result<Vec<(DirListing, u64 /* next offset */)>, Errno>;
    pub fn releasedir(&self, fh: u64) -> Result<(), Errno>;
    pub fn statfs(&self) -> Result<Statfs, Errno>;                           // nix::sys::statvfs on vault_path; namelen = cfg.max_name_length
    pub fn access(&self, ino: u64, mask: AccessFlags) -> Result<(), Errno>; // exists + (write && read_only → EROFS)
    pub fn is_in_use(&self) -> bool;                                         // any open file handle
}
```

Regeln: Klartextnamen über `transcoder.fuse_to_vault` (None → `EINVAL`); `Attr` aus `FileAttributes`: `kind` aus `file_type`, `perm = mode & 0o7777` (read-only: Schreibbits gelöscht durch CryptoFs), `nlink = 1` (Root 2), `uid/gid = cfg.options`, `blksize = 4096`, `blocks = size.div_ceil(512)`, Zeiten aus Attributen (`created`/`crtime` fällt auf `modified` zurück); `setattr` mit `size`: über `fh` (wenn gegeben) oder temporär `open_file(read_write)` + `truncate` + `close`; `atime/mtime`: `TimeOrNow::Now` → `SystemTime::now()`, dann `fs.set_times`; `readlink`: `read_link` → `vault_to_fuse` bytes; `rename`: `noreplace` → `replace_existing=false`, sonst `true`; danach `inodes.rename`; `unlink/rmdir`: `fs.delete` (rmdir: vorher `symlink_metadata` muss `is_dir` sein) → `inodes.remove_path`; `open`: `OpenAccMode::O_RDONLY` → `read_only()`, `O_WRONLY|O_RDWR` → `read_write()` (+ `truncate` bei `O_TRUNC`), `append` bei `O_APPEND`; Statistik-Zähler bleiben in `CryptoFs`.

- [ ] **Step 1: Failing tests** (Testvault via `cryptomator_core` — die Mount-Crate braucht dafür `cryptomator-core` mit Feature `det-rng` als dev-dependency; Helfer `test_fs()` legt mit `initialize` + `open_vault_with_key` ein Vault an, wie `crates/cryptomator-core/src/fs/crypto_fs.rs::tests::test_fs`, aber über die öffentliche API: `initialize(dir, &key, SivGcm, 220, DEFAULT_KEY_ID, &mut DetRng::default())`, `open_vault_with_key`, `CryptoFs::open(opened, CryptoFsOptions::default())`)

```rust
#[test]
fn full_file_lifecycle_through_ops() {
    let (_dir, ops) = test_ops(false);
    let root = ops.getattr(1, None).unwrap();
    assert_eq!(root.kind, fuser::FileType::Directory);
    let d = ops.mkdir(1, OsStr::new("docs")).unwrap();
    let c = ops.create(d.ino, OsStr::new("a.txt"), OpenFlags(libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL)).unwrap();
    assert_eq!(ops.write(c.fh, 0, b"hello").unwrap(), 5);
    assert_eq!(ops.write(c.fh, 5, b" world").unwrap(), 6);
    ops.flush(c.fh).unwrap();
    ops.release(c.fh).unwrap();
    let a = ops.lookup(d.ino, OsStr::new("a.txt")).unwrap();
    assert_eq!(a.size, 11);
    let fh = ops.open(a.ino, OpenFlags(libc::O_RDONLY)).unwrap();
    assert_eq!(ops.read(fh, 6, 100).unwrap(), b"world");
    assert_eq!(ops.read(fh, 11, 10).unwrap(), b"");
    assert_eq!(ops.write(fh, 0, b"x").unwrap_err(), Errno::EBADF, "read-only handle");
    ops.release(fh).unwrap();
    let fh = ops.open(a.ino, OpenFlags(libc::O_WRONLY | libc::O_APPEND)).unwrap();
    ops.write(fh, 0, b"!").unwrap();
    ops.release(fh).unwrap();
    assert_eq!(ops.getattr(a.ino, None).unwrap().size, 12);
    let t = ops.setattr(a.ino, None, Some(5), None, None).unwrap();
    assert_eq!(t.size, 5);
    let fh = ops.open(a.ino, OpenFlags(libc::O_RDWR | libc::O_TRUNC)).unwrap();
    assert_eq!(ops.getattr(a.ino, Some(fh)).unwrap().size, 0);
    ops.release(fh).unwrap();
    // directory listing with . and ..
    let dh = ops.opendir(d.ino).unwrap();
    let names: Vec<String> = ops.readdir(dh, 0).unwrap().into_iter().map(|(e, _)| e.name.to_string_lossy().into_owned()).collect();
    assert_eq!(names, vec![".", "..", "a.txt"]);
    assert!(ops.readdir(dh, 3).unwrap().is_empty());
    ops.releasedir(dh).unwrap();
    // rename keeps inode, unlink/rmdir
    ops.rename(d.ino, OsStr::new("a.txt"), 1, OsStr::new("b.txt"), false, false).unwrap();
    assert_eq!(ops.lookup(1, OsStr::new("b.txt")).unwrap().ino, a.ino);
    assert_eq!(ops.lookup(d.ino, OsStr::new("a.txt")).unwrap_err(), Errno::ENOENT);
    assert_eq!(ops.rename(1, OsStr::new("b.txt"), 1, OsStr::new("docs"), true, false).unwrap_err(), Errno::EEXIST);
    assert_eq!(ops.rmdir(1, OsStr::new("b.txt")).unwrap_err(), Errno::ENOTDIR);
    assert_eq!(ops.unlink(1, OsStr::new("docs")).unwrap_err(), Errno::EISDIR);
    ops.unlink(1, OsStr::new("b.txt")).unwrap();
    ops.rmdir(1, OsStr::new("docs")).unwrap();
    assert_eq!(ops.lookup(1, OsStr::new("docs")).unwrap_err(), Errno::ENOENT);
    assert!(!ops.is_in_use());
}

#[test]
fn symlinks_transcoding_and_read_only() {
    let (_dir, ops) = test_ops(false);
    let l = ops.symlink(1, OsStr::new("link"), Path::new("docs/a.txt")).unwrap();
    assert_eq!(l.kind, fuser::FileType::Symlink);
    assert_eq!(ops.readlink(l.ino).unwrap(), b"docs/a.txt");
    // NFD name from FUSE is stored NFC and served back NFD
    let f = ops.create(1, OsStr::new("cafe\u{301}.txt"), OpenFlags(libc::O_WRONLY | libc::O_CREAT)).unwrap();
    ops.release(f.fh).unwrap();
    assert!(ops.lookup(1, OsStr::new("caf\u{e9}.txt")).is_ok(), "NFC lookup also works after transcoding");
    let dh = ops.opendir(1).unwrap();
    let names: Vec<OsString> = ops.readdir(dh, 0).unwrap().into_iter().map(|(e, _)| e.name).collect();
    assert!(names.contains(&OsString::from("cafe\u{301}.txt")));
    let (_dir, ro) = test_ops(true);
    assert_eq!(ro.mkdir(1, OsStr::new("d")).unwrap_err(), Errno::EROFS);
    assert_eq!(ro.access(1, AccessFlags::W_OK).unwrap_err(), Errno::EROFS);
    assert!(ro.access(1, AccessFlags::R_OK).is_ok());
    let s = ro.statfs().unwrap();
    assert!(s.bsize > 0 && s.namelen == 10 * 1024);
}

#[test]
fn rmdir_sweeps_apple_double_files_when_configured() { /* create "._x" and ".DS_Store" inside a dir via ops with delete_apple_double = true; rmdir succeeds; with false → ENOTEMPTY */ }
```

(`test_ops(read_only)` konfiguriert `NameTranscoder::new(FuseNormalization::Nfd)` und `uid/gid` 501/20.)

- [ ] **Step 2: Implementierung** gemäß Regeln.

- [ ] **Step 3: Tests** `cargo test -p cryptomator-mount fuse::ops` → PASS (3 Tests)

- [ ] **Step 4: Gate + Commit** („Add the fuser-independent FUSE operation core over CryptoFs“)

---

### Task 6: `impl fuser::Filesystem` und Session-Handle

**Files:**
- Create: `crates/cryptomator-mount/src/fuse/adapter.rs`, `fuse/session.rs`

**Interfaces:**
- `pub struct CryptoFuse { ops: Arc<VaultOps> }` mit `impl fuser::Filesystem`: jede Methode ruft `ops` und übersetzt `Result<_, Errno>` in `reply.*`/`reply.error`; TTLs aus `AdapterOptions` (`attr_timeout`, `entry_timeout`), `Generation(0)`; `init` setzt `KernelConfig` unverändert (Rückgabe `Ok(())`); `destroy` = no-op; `readdir` iteriert `ops.readdir(fh, offset)` und bricht bei `reply.add(..) == true` ab; `readdirplus` → `ENOSYS` (FUSE-T/libfuse fallen auf readdir zurück); `setattr` reicht `size/atime/mtime/fh` durch; `mknod` → `ENOSYS`; `link` → `EPERM`; `getxattr/listxattr/setxattr/removexattr` → `ENOTSUP`; `getlk/setlk/bmap/ioctl/poll/fallocate/lseek/copy_file_range` → Defaults (ENOSYS); macOS: `setvolname` → `reply.ok()`, `getxtimes` → `xtimes(UNIX_EPOCH, crtime)`, `exchange` → `EINVAL`.
- `session.rs`: `pub struct FuseSessionHandle { bg: Option<fuser::BackgroundSession>, ops: Arc<VaultOps>, mountpoint: PathBuf, unmounter: Box<dyn Fn(bool /*forced*/) -> Result<(), UnmountError> + Send> }` mit `spawn_from_fd(ops, fd: OwnedFd, abi: KernelAbi, unmounter) -> io::Result<Self>` (`Session::from_fd(CryptoFuse, fd, SessionACL::Owner, config)` → `spawn()`), `spawn_mounted(ops, mountpoint, options: Vec<MountOption>, acl, unmounter)` (Linux: `Session::new`), `unmount(&mut self, forced: bool) -> Result<(), UnmountError>` (ruft `unmounter`, wartet bis zu 10 s auf das Ende des Session-Threads (`guard` via `join` in einem Hilfsthread mit Timeout — oder `is_mountpoint`-Polling), bei Timeout ohne `forced` → `UnmountError::Busy`), `join(self) -> io::Result<()>`, `is_in_use()`.

- [ ] **Step 1: Failing test** (Compile-/Typtest ohne Mount): `fn assert_filesystem<T: fuser::Filesystem>() {}` mit `CryptoFuse`; plus `errno`-Roundtrip in `reply`-freien Helfern (`ttl()` liefert `attr_timeout`).

- [ ] **Step 2: Implementierung**; Achtung: `Filesystem: Send + Sync + 'static`; `CryptoFuse` hält nur `Arc<VaultOps>` (`VaultOps: Send + Sync` — compile-time assert wie in M3).

- [ ] **Step 3: Tests + Gate + Commit** („Add fuser Filesystem adapter and session handle“)

---

### Task 7: Provider (Linux, FUSE-T, macFUSE, Null) und Registry

**Files:**
- Create: `crates/cryptomator-mount/src/fuse/macos_dl.rs`, `fuse/linux.rs`, `fuse/fuset.rs`, `fuse/macfuse.rs`, `crates/cryptomator-mount/src/registry.rs`
- Modify: `crates/cryptomator-mount/src/lib.rs`, `crates/cryptomator-app/src/mounters.rs` (Alias `null` → `org.cryptomator.cli.NullMountProvider`)

**Interfaces:**
- `macos_dl.rs` (macOS only): `pub struct LibFuse { lib: libloading::Library, path: PathBuf }` mit `load(path) -> Result<Self, MountError>`, `mount(&self, mountpoint: &Path, opts: &[String] /* "-o" values */) -> Result<OwnedFd, MountError>` (argv `["cryptomator-cli", "-o", opt, …]`, `fuse_mount_compat25`), `unmount(&self, mountpoint)` (`fuse_unmount_compat22`). `// SAFETY:`-Kommentare wie im Spike-Beispiel.
- `fuset.rs`: `pub struct FuseTMountProvider` (`FUSE_T_DYLIB = "/usr/local/lib/libfuse-t.dylib"`, Env-Override `CRYPTO_FUSE_T_LIB` für Tests), `priority 90`, `display_name "FUSE-T (Experimental)"`, Caps/Defaults wie Global Constraints, Builder: `set_mountpoint` verlangt existierendes Verzeichnis, `combined_flags` = flags ∪ `-r` ∪ `-ovolname=` ∪ `-ononamedattr`; `mount()`: `LibFuse::load` → `MountFlags::from_flags` → `LibFuse::mount(mountpoint, passthrough ∪ ["uid=", "gid=" bleiben enthalten? NEIN: uid/gid werden NICHT weitergereicht, sie gelten dem Adapter; `volname`, `nonamedattr`, `rwsize` etc. werden weitergereicht])` → `FuseSessionHandle::spawn_from_fd(.., KernelAbi::Linux, umount-Kommando)` → `Box<dyn Mount>` (`FuseMount { session, mountpoint, forced_supported: true }`); Unmount: `umount -- <p>` (10 s), forced `umount -f -- <p>`; „not currently mounted“ im stderr → ok.
- `macfuse.rs`: `MacFuseMountProvider` (`/usr/local/lib/libosxfuse.2.dylib`, `/usr/local/lib/libfuse.2.dylib`; Env `CRYPTO_MACFUSE_LIB`), `priority 100`, `display_name "macFUSE"`, `set_mountpoint` erlaubt `/Volumes/<x>` (nicht existent) oder existierendes Verzeichnis; ohne Mountpoint `/Volumes/<volumeId>`; `-obackend=fskit` → `UnsupportedFlag`; `KernelAbi::Native`; Transcoder Nfd; **im Doc-Kommentar und in `ServiceInfo.display_name` als „(unverified)“ markiert**.
- `linux.rs`: `LinuxFuseMountProvider`, `priority 100`, `display_name "FUSE"`, supported wenn `fusermount3 -V` (2 s Timeout, `std::process::Command` + Thread mit `wait_timeout` via Polling); `mount()`: `FuseSessionHandle::spawn_mounted(ops, mountpoint, flags.linux_mount_options(), acl)` mit `acl` = `All` bei `allow_other`, `RootAndOwner` bei `allow_root`, sonst `Owner` — **`auto_unmount` verlangt in fuser `acl != Owner`**: Ruling: wenn `auto_unmount` ohne `allow_*` gesetzt ist (Java-Default!), wird `AutoUnmount` NICHT an fuser übergeben (wir unmounten selbst beim Lock; Kommentar). Unmount `fusermount3 -u -- <name>` mit cwd Parent (10 s), forced `-uz`; „not mounted“/„entry for … not found“ → ok.
- `registry.rs`: `pub const NULL_MOUNTER_CLASS: &str = "org.cryptomator.cli.NullMountProvider"`; `pub struct NullMountProvider` (`is_supported()` ⇔ Env `CRYPTO_ENABLE_NULL_MOUNTER=1`; Caps `{MOUNT_FLAGS, MOUNT_TO_EXISTING_DIR, READ_ONLY, VOLUME_NAME, UNMOUNT_FORCED}`; `mount()` legt im Mountpoint eine Datei `.crypto-null-mount` mit dem Volume-Namen an und entfernt sie beim Unmount; `unmount` schlägt fehl (`Busy`), solange die Env-Variable `CRYPTO_NULL_MOUNT_BUSY=1` gesetzt ist — für Lock-Tests); `pub fn all_services() -> Vec<Box<dyn MountService>>` (Plattform-Reihenfolge nach Priorität, Null zuletzt), `pub fn services() -> Vec<Box<dyn MountService>>` (nur `is_supported`), `pub fn service_by_class(class: &str) -> Option<Box<dyn MountService>>`, `pub fn conflicting_classes(class: &str) -> &'static [&'static str]`, `pub fn service_infos(all: bool) -> Vec<ServiceInfo>`.

- [ ] **Step 1: Failing tests**: Capability-Sets und Default-Flags je Provider (uid/gid aus `nix::unistd::geteuid/getegid`), `FuseT` `combined_flags` enthält `-ononamedattr` genau einmal und `-r` bei read-only, macFUSE lehnt `-obackend=fskit` ab, `is_supported` per Env-Override auf eine Temp-Datei; Null-Mounter: `all_services()` enthält ihn, `services()` nur mit Env; ein vollständiger Null-Mount (mount → `.crypto-null-mount` existiert → unmount → weg; `CRYPTO_NULL_MOUNT_BUSY=1` → `Busy`, forced → ok).

- [ ] **Step 2: Implementierung**; `mounters.rs` (app) Alias `null` ergänzen.

- [ ] **Step 3: Tests + Gate + Commit** („Add FUSE mount providers for Linux, FUSE-T, macFUSE and a null mounter for tests“)

---

### Task 8: Mount-E2E-Test (FUSE-T auf diesem Mac) + Java-Gegenprobe

**Files:**
- Create: `crates/cryptomator-mount/tests/mount_e2e.rs`
- Modify: `crates/crypto/tests/java_interop.rs` (Test `java_reads_files_written_through_the_mount`, `#[ignore]`, nur mit `CRYPTO_E2E_MOUNT=1`)

- [ ] **Step 1: Test** (`#[ignore = "mounts a real FUSE filesystem; CRYPTO_E2E_MOUNT=1"]`): Vault per `initialize` in Tempdir, bester unterstützter Service (`registry::services()[0]`, Null-Mounter ausgeschlossen; ohne FUSE → Test meldet „skipped“ und endet ok), Mountpoint = Tempdir, `set_mount_flags(default)`, `set_volume_name("e2e")`, `mount()`; dann über `std::fs` auf dem Mountpoint: `create_dir`, `write` 100 000 Bytes (Muster), `read` zurück, `metadata().len()`, `rename`, `symlink` + `read_link`, `remove_file`, Listing enthält `.`-lose Namen, NFD-Name `cafe\u{301}.txt` → erscheint im Vault als NFC (per `CryptoFs::read_dir` nach dem Unmount prüfen), `unmount()` + `close()`; danach `is_mountpoint == false` und `CryptoFs` liest den Baum. Timeout-Schutz: alle Zugriffe in einem Thread mit 30-s-Limit.
- [ ] **Step 2: Java-Gegenprobe**: derselbe Baum, danach `verify_with_java` → Manifest gleicht `crypto fs tree --json --hash`.
- [ ] **Step 3: Lokal ausführen**: `CRYPTO_E2E_MOUNT=1 cargo test -p cryptomator-mount --test mount_e2e -- --ignored --nocapture` und der Interop-Test; Ergebnis (inkl. `mount`-Zeile) in den Report; Abweichungen (z. B. FUSE-T-Eigenheiten wie zusätzliche `._`-Dateien) dokumentieren und ggf. im Adapter behandeln.
- [ ] **Step 4: Gate + Commit** („Add end-to-end mount test and Java verification of mount-written files“)

---

### Task 9: State-Dir, `cli.json`, Vault-Registry, `Mounter`

**Files:**
- Modify: `crates/cryptomator-app/Cargo.toml` (+ `cryptomator-mount`, `log`, `nix`, `data-encoding`), `crates/cryptomator-app/src/lib.rs`, `src/error.rs`
- Create: `crates/cryptomator-app/src/state_dir.rs`, `src/cli_config.rs`, `src/registry.rs`, `src/mounting/mod.rs`, `src/mounting/mounter.rs`

**Interfaces:**
- `error.rs`: `AppError::{MountFailed(String), UnmountFailed(String), DaemonUnreachable(String), DaemonError { code: String, message: String }, MountPointInvalid(PathBuf, String)}`.
- `state_dir.rs`:

```rust
pub const STATE_DIR_ENV: &str = "CRYPTO_STATE_DIR";
#[derive(Debug, Clone)] pub struct StateDir { root: PathBuf }
impl StateDir {
    pub fn from_env_or_default() -> Result<Self>;   // env → macOS ~/Library/Application Support/Cryptomator/cli-run → Linux $XDG_RUNTIME_DIR/crypto → /tmp/crypto-<uid>
    pub fn at(root: PathBuf) -> Self;
    pub fn ensure(&self) -> Result<()>;              // create_dir_all + chmod 0700 (only when we created it or it is ours)
    pub fn files(&self, vault_id: &str) -> VaultStateFiles;
    pub fn list_run_infos(&self) -> Result<Vec<RunInfo>>;
}
#[derive(Debug, Clone)] pub struct VaultStateFiles { pub socket: PathBuf, pub pid: PathBuf, pub info: PathBuf, pub log: PathBuf }
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)] #[serde(rename_all = "camelCase")]
pub struct RunInfo { pub vault_id: String, pub path: String, pub mounter: String, pub mountpoint: Option<String>, pub pid: u32, pub started_at: u64 /* epoch secs */, pub read_only: bool }
impl VaultStateFiles {
    pub fn write_pid(&self, pid: u32) -> Result<()>; pub fn read_pid(&self) -> Option<u32>;
    pub fn write_info(&self, info: &RunInfo) -> Result<()>; pub fn read_info(&self) -> Option<RunInfo>;
    pub fn remove_all(&self) -> Result<()>;          // sock/pid/info (log stays)
}
pub fn process_alive(pid: u32) -> bool;              // nix::sys::signal::kill(pid, None)
```

- `cli_config.rs`: `cli.json` neben `settings.json` (`SettingsStore::preferred_path().with_file_name("cli.json")`):

```rust
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)] #[serde(rename_all = "camelCase", default)]
pub struct CliConfig { pub mount_points_dir: Option<String>, pub default_mounter: Option<String>, pub log_level: String /* "info" */, pub force_unmount_on_signal_after_secs: u32 /* 10 */, #[serde(flatten)] pub extra: Map<String, Value> }
impl CliConfig { pub fn load(path: &Path) -> Result<Self> /* missing → default */; pub fn save(&self, path: &Path) -> Result<()> /* tmp+rename */; pub fn mount_points_dir(&self, home: &Path) -> PathBuf /* macOS ~/Library/Application Support/Cryptomator/mnt, Linux ~/.local/share/Cryptomator/mnt */ }
```

- `registry.rs`:

```rust
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)] #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuntimeState { Locked, Unlocked, StaleMount, Missing, VaultConfigMissing, AllMissing, NeedsMigration, Error }
#[derive(Debug, Clone, serde::Serialize)] #[serde(rename_all = "camelCase")]
pub struct VaultInfo { pub id: String, pub display_name: Option<String>, pub path: Option<String>, pub state: RuntimeState, pub mountpoint: Option<String>, pub mounter: Option<String>, pub pid: Option<u32>, pub read_only: Option<bool> }
pub struct VaultRegistry { store: SettingsStore, state_dir: StateDir }
impl VaultRegistry {
    pub fn new(store: SettingsStore, state_dir: StateDir) -> Self;
    pub fn runtime_state(&self, vault_id: &str) -> Result<(RuntimeState, Option<RunInfo>)>;  // socket connectable → Unlocked; else pid alive → Unlocked (daemon starting); else info.mountpoint still mounted (is_mountpoint) → StaleMount; else stale files removed → disk state (determine_vault_state)
    pub fn infos(&self) -> Result<Vec<VaultInfo>>;
    pub fn info(&self, reference: &str) -> Result<VaultInfo>;
}
```

- `mounting/mounter.rs` (Port `Mounter` + `SettledMounter`):

```rust
pub struct MountRequest<'a> { pub vault: &'a VaultSettingsJson, pub settings: &'a SettingsJson, pub cli: &'a CliConfig, pub home: &'a Path, pub overrides: MountOverrides }
#[derive(Debug, Default, Clone)] pub struct MountOverrides { pub mounter: Option<String> /* class */, pub mount_point: Option<PathBuf>, pub mount_options: Vec<String> /* "-o…" appended */, pub read_only: Option<bool>, pub volume_name: Option<String> }
pub struct MountHandle { pub mount: Box<dyn Mount>, pub supports_forced: bool, pub cleanup: Option<PathBuf> /* created mount dir to remove after unmount */, pub service_class: String }
pub fn choose_service(req: &MountRequest, services: &[Box<dyn MountService>]) -> Result<Box<dyn MountService>>;   // overrides.mounter → vault.mount_service → cli.default_mounter → settings.mount_service → first supported; unknown/unsupported → MountFailed
pub fn mount(req: &MountRequest, fs: Arc<CryptoFs>) -> Result<MountHandle>;
```

Mount-Point-Policy exakt wie `Mounter.prepareMountPoint`: user path (`overrides.mount_point` → `vault.mount_point`) → validieren (existierendes Verzeichnis für `MountToExistingDir`; `/Volumes/…` nicht existent für `MountToSystemChosenPath`), sonst `MountPointInvalid`; ohne user path: `MountToSystemChosenPath` → kein Mountpoint; `MountToExistingDir` → `mountPointsDir/<mountName>` anlegen (`cleanup = Some(dir)`); Capabilities anwenden wie `SettledMounter.prepare` (`FILE_SYSTEM_NAME="cryptoFs"`, `READ_ONLY`, `MOUNT_FLAGS` (leer → Default) + `overrides.mount_options` angehängt, `VOLUME_ID=id`, `VOLUME_NAME=mount_name`; `LOOPBACK_PORT` erst M5).

- [ ] **Step 1: Failing tests**: State-Dir Defaults je OS (mit `HOME`/`XDG_RUNTIME_DIR`-Overrides über Parameter, nicht globale Env), `ensure` setzt 0700, `RunInfo` Roundtrip, `process_alive(std::process::id())`; `CliConfig` Default/Load/Save/unknown keys preserved; `runtime_state`: kein State → `Locked` (Disk); Info+PID eines beendeten Prozesses + nicht gemounteter Pfad → Dateien entfernt, `Locked`; Info mit `mountpoint = "/"` (immer gemountet) + toter PID → `StaleMount`; `choose_service` Reihenfolge mit Fake-Services (`is_supported` per Konstruktor); `mount` mit `NullMountProvider`: Mountpoint-Policy legt `mountPointsDir/<mountName>` an, `cleanup` gesetzt, `.crypto-null-mount` existiert; user path, der nicht existiert → `MountPointInvalid`.

- [ ] **Step 2: Implementierung**; `lib.rs` re-exportiert `state_dir::*`, `cli_config::CliConfig`, `registry::*`, `mounting::*`.

- [ ] **Step 3: Tests + Gate + Commit** („Add state dir, cli.json, vault registry and the mounter port“)

---

### Task 10: Daemon-Protokoll und Client

**Files:**
- Create: `crates/cryptomator-app/src/daemon/mod.rs`, `daemon/protocol.rs`, `daemon/client.rs`

**Interfaces (`protocol.rs`, alles `serde` + `Serialize/Deserialize`, camelCase):**

```rust
pub const PROTOCOL_VERSION: u32 = 1;
pub struct Hello { pub hello: String /* "crypto-daemon" */, pub protocol: u32, pub vault_id: String, pub pid: u32 }
#[serde(tag = "op", rename_all = "camelCase")]
pub enum Request {
    Unlock { id: u64, key: String /* base64 of 64 raw bytes */, mounter: Option<String>, mount_point: Option<String>, mount_options: Vec<String>, read_only: Option<bool>, volume_name: Option<String>, max_cleartext_name_length: usize },
    Status { id: u64 }, Stats { id: u64 }, Lock { id: u64, force: bool }, Events { id: u64, follow: bool, since: u64 }, Ping { id: u64 }, Shutdown { id: u64 },
}
pub struct Response { pub id: u64, pub ok: bool, #[serde(skip_serializing_if = "Option::is_none")] pub result: Option<serde_json::Value>, #[serde(skip_serializing_if = "Option::is_none")] pub error: Option<ErrorBody> }
pub struct ErrorBody { pub code: String /* "MOUNT_FAILED" | "UNMOUNT_FAILED" | "ALREADY_UNLOCKED" | "NOT_UNLOCKED" | "BAD_REQUEST" | "INTERNAL" */, pub message: String }
pub struct StatusResult { pub vault_id: String, pub state: String /* "STARTING" | "UNLOCKED" | "LOCKING" */, pub mountpoint: Option<String>, pub mounter: String, pub read_only: bool, pub started_at: u64, pub uptime_secs: u64, pub last_activity: u64, pub in_use: bool }
pub struct StatsResult { pub bytes_per_second_read: u64, pub bytes_per_second_written: u64, pub bytes_per_second_encrypted: u64, pub bytes_per_second_decrypted: u64, pub cache_hit_rate: f64, pub total_bytes_read: u64, pub total_bytes_written: u64, pub total_bytes_encrypted: u64, pub total_bytes_decrypted: u64, pub files_read: u64, pub files_written: u64, pub total_files_accessed: u64, pub last_activity: u64 }
pub struct EventRecord { pub seq: u64, pub timestamp: u64, pub kind: String, pub message: String, pub cleartext_path: Option<String>, pub ciphertext_path: Option<String> }
pub struct EventsResult { pub events: Vec<EventRecord>, pub next_seq: u64 }
pub struct StreamItem { pub id: u64, pub event: EventRecord }   // for follow streams: one line per event, terminated by a final Response
pub fn write_line<W: Write>(w: &mut W, value: &impl Serialize) -> io::Result<()>;
pub fn read_line<R: BufRead>(r: &mut R) -> io::Result<Option<String>>;  // None on EOF; max 1 MiB
```

Der Key in `Request::Unlock` ist ein `String` — nach dem Decodieren wird die Zeile/das Struct via `zeroize` gewischt (`Zeroizing<String>` für die Rohzeile; `key` in `Zeroizing<String>` via `#[serde(with = …)]`-freiem Umweg: `Request::Unlock` hält `key: Zeroizing<String>`? `serde` für `Zeroizing<String>` ist nicht verfügbar → Ruling: Feld `key: String`, `impl Drop for Request` wischt (`key.zeroize()`) — plus explizites `zeroize` nach dem Decodieren).

**`client.rs`:**

```rust
pub struct DaemonClient { stream: BufReader<UnixStream>, writer: UnixStream, next_id: u64, pub hello: Hello }
impl DaemonClient {
    pub fn connect(socket: &Path) -> Result<Self>;                        // one attempt; reads Hello; NotFound/ConnectionRefused → DaemonUnreachable
    pub fn connect_with_retry(socket: &Path, deadline: Duration) -> Result<Self>;  // 100 ms backoff
    pub fn call(&mut self, request: Request) -> Result<serde_json::Value>;   // sends, reads until a Response with the same id; error → AppError::DaemonError; sets `id` from next_id
    pub fn stream(&mut self, request: Request, mut on_item: impl FnMut(EventRecord) -> bool /* continue? */) -> Result<()>;  // for follow
    pub fn status(&mut self) -> Result<StatusResult>; pub fn stats(&mut self) -> Result<StatsResult>; pub fn lock(&mut self, force: bool) -> Result<()>; pub fn events(&mut self, since: u64) -> Result<EventsResult>; pub fn ping(&mut self) -> Result<()>;
}
```

- [ ] **Step 1: Failing tests**: Serialisierung exakt (`{"op":"lock","id":3,"force":true}`; `Response` ohne `result`-Feld bei Fehler; `StreamItem`); `read_line` EOF/Limit; `DaemonClient` gegen einen In-Prozess-Fake-Server (Thread mit `UnixListener` in Tempdir: schreibt Hello, beantwortet `Ping` mit `ok`, `Lock{force:false}` mit Fehler `UNMOUNT_FAILED`, `Events{follow:true}` mit zwei `StreamItem`s + abschließender Response); `connect` auf nicht existierenden Socket → `DaemonUnreachable`; `connect_with_retry` findet einen Socket, der 300 ms später erscheint.

- [ ] **Step 2: Implementierung**

- [ ] **Step 3: Tests + Gate + Commit** („Add daemon protocol and client“)

---

### Task 11: Daemon-Server

**Files:**
- Create: `crates/cryptomator-app/src/daemon/server.rs`, `daemon/logging.rs`

**Interfaces:**

```rust
pub struct DaemonConfig { pub vault_id: String, pub state_dir: StateDir, pub store: SettingsStore, pub cli: CliConfig, pub home: PathBuf, pub services: Vec<Box<dyn MountService>>, pub unlock_timeout: Duration /* 60 s */, pub stats_interval: Duration /* 1 s */, pub autolock_tick: Duration /* 60 s; env CRYPTO_AUTOLOCK_TICK_SECS overrides for tests */, pub force_unmount_after: Duration /* cli.force_unmount_on_signal_after_secs */ }
pub fn run_daemon(config: DaemonConfig, shutdown: Arc<AtomicBool> /* set by signal handler */) -> Result<()>;
```

Ablauf (`run_daemon`): `state_dir.ensure()`; Socket-Datei entfernen falls Reste; `UnixListener::bind` + chmod 0600; PID schreiben; Logger (`logging.rs`: `log::Log`-Impl in `<id>.log`, 0600, Level aus `cli.log_level`, Format `2026-09-06T10:00:00Z INFO target: msg`); **Phase 1 (STARTING)**: Verbindungen annehmen (jede in eigenem Thread), Hello senden; nur `Ping`/`Status`/`Shutdown` sowie genau ein `Unlock` erlaubt; ohne `Unlock` binnen `unlock_timeout` → Cleanup + Exit 1. `Unlock`: Key base64 → `[u8;64]` (`Zeroizing`) → `Masterkey::from_raw` → `open_vault_with_key(path, key)` → `CryptoFs::open(opened, CryptoFsOptions { read_only, max_cleartext_name_length, events: sink → Ringpuffer })` → `mounting::mount(MountRequest{… overrides aus Unlock}, Arc<CryptoFs>)` → `RunInfo` schreiben → Antwort `ok` mit `{"mountpoint": …}`; Fehler → Antwort `MOUNT_FAILED` + Cleanup + Exit 6. **Phase 2 (UNLOCKED)**: Requests `Status/Stats/Lock/Events/Ping/Shutdown`; Stats-Sampler-Thread (1 s): Snapshot-Deltas → `StatsResult`-Felder (`bytes_per_second_*`, `cache_hit_rate = hits/accesses` des Intervalls), `last_activity` bei Zuwachs von `accesses_read + accesses_written`; Auto-Lock-Thread (Tick): Settings neu laden (`store.load()`), `auto_lock_when_idle && idle >= auto_lock_idle_seconds` → graceful lock (Fehler loggen, weiter); `Lock{force}`: `handle.mount.unmount()`/`unmount_forced()` (nur wenn `supports_forced`, sonst Fehler `UNMOUNT_FAILED` mit Hinweis) → bei Erfolg `close()`, `cleanup`-Dir entfernen, `fs.close()`, Antwort `ok`, dann Shutdown; bei Fehler Antwort `UNMOUNT_FAILED` und weiterlaufen; `Events{follow}`: Ringpuffer (`VecDeque<EventRecord>` max 1000, `seq` ab 1) ab `since`; bei `follow` bleibt die Verbindung offen und bekommt neue Events (Condvar) bis Client trennt oder Shutdown; `shutdown` (Signal/Request): wie Lock graceful, nach `force_unmount_after` forced; am Ende `remove_all()`, Exit 0.

Daemon-`Status.state`: `STARTING` bis Mount fertig, `UNLOCKED`, `LOCKING` während des Unmounts. Der Daemon verweigert einen zweiten `Unlock` (`ALREADY_UNLOCKED`).

- [ ] **Step 1: Failing tests** (In-Prozess, Null-Mounter, Tempdir, `DaemonConfig` mit `services = vec![Box::new(NullMountProvider)]`, `CRYPTO_ENABLE_NULL_MOUNTER=1` per Konstruktor-Flag statt Env, kleine Intervalle): Thread startet `run_daemon`; `DaemonClient::connect_with_retry`; `Status` → `STARTING`; `Unlock` mit Key eines per `initialize` erzeugten Vaults (Settings-Eintrag in einer Tempdir-`settings.json`) → `ok`, Mountpoint = `mountPointsDir/<mountName>`, `.crypto-null-mount` existiert, `RunInfo` geschrieben; zweiter `Unlock` → `ALREADY_UNLOCKED`; `Stats` liefert Felder; Events: Sink-Event (über `fs`-Zugriff auf eine kaputte `dir.c9r` ausgelöst, oder einfacher: der Server bietet in Tests `inject_event`) → `Events{since:0}` liefert es; `Lock{force:false}` mit `CRYPTO_NULL_MOUNT_BUSY=1` (Konstruktor-Flag) → `UNMOUNT_FAILED`, Daemon lebt (`Ping` ok); `Lock{force:true}` → ok, Thread endet, State-Dateien weg, Mount-Dir entfernt. Zweiter Test: Auto-Lock mit `autoLockWhenIdle=true`, `autoLockIdleSeconds=1`, Tick 1 s → Daemon beendet sich binnen 5 s. Dritter Test: Unlock-Timeout (200 ms) ohne Unlock → Exit-Result Err, Dateien weg. Vierter: falscher Key (`open_vault_with_key` → `VaultKeyInvalid`) → `MOUNT_FAILED` … Ruling: Code `MOUNT_FAILED` mit Message `vault key does not match` (Exit 6 im CLI).

- [ ] **Step 2: Implementierung** (Threads: accept-loop, pro Verbindung, stats, autolock; gemeinsamer `Arc<Mutex<DaemonState>>`; `shutdown: Arc<AtomicBool>` + Condvar; keine Busy-Loops).

- [ ] **Step 3: Tests + Gate + Commit** („Add the vault daemon server“)

---

### Task 12: CLI `unlock`, `lock`, `__daemon`, `--state-dir`, `fs`-Verweigerung

**Files:**
- Modify: `crates/crypto/Cargo.toml` (+ `libc`, `signal-hook`, `cryptomator-mount`), `src/cli.rs`, `src/main.rs`, `src/exit.rs`, `src/commands/mod.rs`, `src/commands/fs.rs`
- Create: `src/commands/unlock.rs`, `src/commands/lock.rs`, `src/commands/daemon.rs`, `crates/crypto/tests/cli_daemon.rs`

**Grammatik:**

```rust
/// Unlock and mount a vault in a background daemon
Unlock(UnlockArgs),   // vault; --mounter <ALIAS|CLASS>; --mount-point <PATH>; --mount-option=<-o…> (repeatable, require_equals, allow_hyphen_values); --read-only; --volume-name <N>; --foreground; --reveal; PasswordArgs
/// Unmount and lock vaults
Lock(LockArgs),       // vaults: Vec<String> (allow_hyphen_values) | --all; --force
#[command(name = "__daemon", hide = true)] Daemon(DaemonArgs),  // --vault-id, --socket, --state-dir
```

Global: `#[arg(long, global = true, value_name = "PATH", env = "CRYPTO_STATE_DIR")] state_dir: Option<PathBuf>` → `Ctx.state_dir: StateDir`. `exit.rs`: `MOUNT_FAILED = 6`, `UNMOUNT_FAILED = 7`, `DAEMON_UNREACHABLE = 10`; Mapping `AppError::MountFailed/MountPointInvalid → 6`, `UnmountFailed → 7`, `DaemonUnreachable → 10`, `DaemonError{code}`: `UNMOUNT_FAILED → 7`, `MOUNT_FAILED → 6`, `ALREADY_UNLOCKED/NOT_UNLOCKED → 5`, sonst 1.

`unlock` (`commands/unlock.rs`): Registry-Zustand prüfen (`Unlocked` → Exit 5 „already unlocked at <mp>“; `StaleMount` → Exit 5 mit Hinweis `crypto lock --force`); `locked_vault`; Hub-Check; Passwort; `open_vault` (scrypt) → Namenslängen-Probe/Persistenz wie in den Global Constraints (nur wenn nicht read-only und `max_cleartext_filename_length == -1`; Ergebnis via `store.update`) → `max_cleartext_name_length` bestimmen; `masterkey.raw()` base64 in `Zeroizing<String>`; Daemon-Spawn (`current_exe()`, Args `__daemon --vault-id … --socket … --state-dir …` + `--settings` wenn gesetzt; `env_remove("CRYPTO_PASSWORD")`; `stdin(null)`, stdout/stderr → Log-Datei (append, 0600); `// SAFETY` `pre_exec(|| { libc::setsid(); Ok(()) })`; `current_dir("/")`); `--foreground`: stattdessen `run_daemon` im Prozess in einem Thread + Client im Hauptthread, Signale (`signal_hook::flag::register(SIGINT/SIGTERM, shutdown)`); Client `connect_with_retry(30 s)` → `Unlock{…}` → Ergebnis: Human `Unlocked <name> at <mountpoint>` / JSON `{ "id", "mountpoint", "mounter", "pid" }`; `--reveal` oder `actionAfterUnlock == REVEAL` → `open <mp>` (macOS) / `xdg-open <mp>` (Linux), Fehler ignorieren; bei `failed` → Log-Tail (letzte 20 Zeilen) auf stderr, Exit 6.

`lock`: für jede Referenz (oder alle `Unlocked/StaleMount` bei `--all`): `Unlocked` → Client `Lock{force}` → Erfolg/Fehler (7); `StaleMount` → Unmount-Kommando direkt (`registry`/Provider `unmount_stale(mountpoint, forced)` → `cryptomator_mount::registry::service_by_class(info.mounter).unmount_path(...)` — ergänze der `MountService`-Trait um `fn unmount_path(&self, mountpoint: &Path, forced: bool) -> Result<(), UnmountError>` in Task 7 (Default `Err`) → **Nachtrag zu Task 7 in diesem Task erlaubt**), danach State-Dateien entfernen; `Locked` → Exit 5 „not unlocked“. JSON `{ "locked": [ids] }`. `--all` ohne unlocked Vaults → ok, „nothing to lock“.

`fs`-Kommandos (M3-Zusage): `open_fs` prüft `registry.runtime_state` → `Unlocked|StaleMount` → `WrongState { expected: "LOCKED", actual: "UNLOCKED (mounted at …)" }` (Exit 5), auch für Lesekommandos (Ruling: einfacher und sicher).

- [ ] **Step 1: Failing tests (`tests/cli_daemon.rs`)** mit `Sandbox` (+ `--state-dir <sandbox>/state`, Env `CRYPTO_ENABLE_NULL_MOUNTER=1`, `CRYPTO_AUTOLOCK_TICK_SECS=1`): `vault create v` → `unlock v --mounter null --json` → Felder, `mountpoint` = `<sandbox>/home/…/mnt/v`? (`HOME` auf Sandbox setzen; `cli.json` mit `mountPointsDir=<sandbox>/mnt` schreiben) → `.crypto-null-mount` existiert; `status v --json` → `UNLOCKED`; zweites `unlock v` → Exit 5; `fs ls v` → Exit 5; `lock v` → ok, Datei weg, `status` → `LOCKED`; `lock v` erneut → Exit 5; `unlock` mit `CRYPTO_NULL_MOUNT_BUSY=1` dann `lock v` → Exit 7, `lock v --force` → ok; `unlock v --foreground` in einem Hintergrundprozess (`std::process::Command` spawn) + `lock v` beendet ihn (Exit 0 binnen 10 s); Stale: nach `unlock`, Daemon mit `kill -9 <pid>` beenden, `status` → `STALE_MOUNT` … mit Null-Mounter ist nichts wirklich gemountet → `is_mountpoint` false → Registry räumt auf → `LOCKED` (Test prüft genau das). Wrong password → Exit 4 ohne Daemon; `unlock nope` → Exit 3; `--mounter bogus` → Exit 2.

- [ ] **Step 2: Implementierung**

- [ ] **Step 3: Tests + Gate + Commit** („Add crypto unlock and lock with a detached vault daemon“)

---

### Task 13: CLI `status`, `stats`, `events`, `mounters`, `config` für `cli.json`

**Files:**
- Modify: `src/cli.rs`, `src/main.rs`, `src/commands/config.rs`
- Create: `src/commands/{status,stats,events,mounters}.rs`; Tests in `tests/cli_daemon.rs` ergänzen

**Grammatik:** `Status { vault: Option<String> }`; `Stats(StatsArgs { vault, --follow, --interval <SECS=1> })`; `Events(EventsArgs { vault, --follow, --since <SEQ=0> })`; `Mounters { --all }`.

Ausgabe: `status` human Tabelle `ID  NAME  STATE  MOUNTPOINT` (alle Vaults; mit Argument nur einer), JSON `VaultInfo`(-Array); `stats` human `read 0 B/s  write 0 B/s  cache 0%  total read …  files …  last activity …`, JSON `StatsResult`, `--follow` → NDJSON pro Intervall bis Ctrl-C; `events` human `seq  time  KIND  message`, JSON `EventRecord`-Array / NDJSON bei `--follow`; `mounters` human `ALIAS  CLASS  SUPPORTED  CAPABILITIES`, JSON `ServiceInfo`-Array (ohne `--all` nur unterstützte; Null-Mounter nur mit `--all`). `config get|set` Keys `mountPointsDir`, `defaultMounter` (Alias oder Klasse), `logLevel` (`error|warn|info|debug|trace`), `forceUnmountOnSignalAfterSecs` → `cli.json`.

- [ ] **Step 1: Failing tests**: `status --json` vor/nach Unlock; `stats v --json` Felder; `events v --json` leer → `[]`; `mounters --json` enthält den Null-Mounter nur mit `--all` und `supported=true` nur mit Env; `config set mountPointsDir <dir>` wirkt beim nächsten `unlock`; `config get logLevel` → `info`.

- [ ] **Step 2: Implementierung + Tests + Gate + Commit** („Add status, stats, events, mounters and cli.json settings“)

---

### Task 14: Signale, forced-Unmount-Eskalation, Auto-Lock im Foreground-Modus, Reveal

**Files:**
- Modify: `src/commands/unlock.rs`, `crates/cryptomator-app/src/daemon/server.rs`

- SIGINT/SIGTERM/SIGHUP im Daemon (detached und foreground) → `shutdown` → graceful unmount; nach `force_unmount_on_signal_after_secs` forced; danach Exit 0 (bzw. 7 wenn auch forced scheitert, Mount bleibt bestehen → Log + State-Dateien bleiben, damit `status` `STALE_MOUNT` zeigt).
- Auto-Lock-Test über CLI: `vault set v --auto-lock-idle 1` + `unlock` (Tick 1 s) → binnen 5 s `status` → `LOCKED`.
- Reveal: `--reveal` ruft `open`/`xdg-open`; im Test per Env `CRYPTO_REVEAL_CMD=<script>` überschreibbar (schreibt den Pfad in eine Datei).

- [ ] **Step 1/2/3**: Tests (`tests/cli_daemon.rs`: `--foreground` + SIGTERM → Prozess endet mit 0 und Null-Mount ist weg; Busy + SIGTERM → forced nach 1 s (`config set forceUnmountOnSignalAfterSecs 1`)), Implementierung, Gate + Commit („Handle signals, forced unmount escalation, auto-lock and reveal“)

---

### Task 15: M3-Nachträge für den Daemon-Betrieb

**Files:**
- Modify: `crates/cryptomator-core/src/fs/path_mapper.rs`, `fs/dir_id.rs`, `fs/crypto_fs.rs`, `fs/open_files.rs`

- `CryptoPathMapper::dir_cache`: Einträge mit `Instant`; Treffer älter als 20 s werden verworfen und neu geladen (Java `CiphertextDirCache` `expireAfterWrite(20 s)`); `DirIdLoader`: gleiches Expiry (Java hat keins, aber ohne Expiry sieht ein langlebiger Daemon Fremdänderungen an `dir.c9r` nie — Ruling); `CryptoFs`: `impl Drop` → `open_files.close_all()` (Fehler ignoriert, geloggt via `log::warn`); `FileHandle::release`: Flush **außerhalb** des Registry-Locks (Datei-Lock halten, Registry-Lock nur für das Entfernen) — Lock-Reihenfolge bleibt Registry → Datei, indem `release` zuerst den Datei-Lock nimmt, flusht, freigibt, dann Registry+Datei sperrt und die Handle-Zählung prüft; Tests: Expiry über einen injizierbaren Clock-Offset (`#[cfg(test)] fn advance(&self, d: Duration)`), Drop schließt Handles (Datei ist danach flushed), `release` unter Nebenläufigkeit (zwei Threads schreiben zwei Dateien parallel ohne Deadlock).

- [ ] **Step 1/2/3**: Tests, Implementierung, Gate + Commit („Add cache expiry, Drop-close and lock-free flush for long-running mounts“)

---

### Task 16: CI, Dokumentation, Spec

**Files:**
- Modify: `.github/workflows/ci.yml`, `README.md`, `CHANGELOG.md`, `docs/superpowers/specs/2026-09-04-crypto-cli-design.md`, `docs/superpowers/spikes/2026-09-04-spike-a-fuse-t.md` (Verweis auf Spike C)

- CI: Job `mount-e2e-linux` (ubuntu-22.04: `sudo apt-get install -y fuse3`, `CRYPTO_E2E_MOUNT=1 cargo test -p cryptomator-mount --test mount_e2e --locked -- --ignored`), Job `mount-e2e-macos` (macos-15: `brew install --cask macos-fuse-t/homebrew-cask/fuse-t`, gleicher Test, `continue-on-error: true` — FUSE-T braucht ggf. eine Freigabe), `test`-Job setzt `CRYPTO_ENABLE_NULL_MOUNTER=1` für `cli_daemon`.
- README: Abschnitte „Mounting“ (Voraussetzungen macOS FUSE-T/macFUSE, Linux `fuse3`; `unlock/lock/status/stats/events/mounters`; State-Dir; `cli.json`-Keys; Signale; `--foreground`), Kommandotabelle ergänzen, Exit-Codes 6/7/10, Hinweis macFUSE unverifiziert, FUSE-T-Einschränkungen (kein xattr, NFS-Backend).
- CHANGELOG `### M4 – FUSE mount and daemon` inkl. der acht Rulings und der M3-Nachträge; Spec: M4 ✅ (Fußnote: WebDAV/Port M5, Keychain M6), `cryptomator-mount`-Abschnitt an die Implementierung angleichen (`ops.rs`, Null-Mounter, `KernelAbi`, kein `backend=smb`, Key über Socket, std-Threads), Daemon-Design entsprechend korrigieren.

- [ ] **Step 1/2/3**: Änderungen, Gate (inkl. `cargo test -p crypto --test java_interop --locked -- --ignored` und lokal `CRYPTO_E2E_MOUNT=1 … mount_e2e`), Commit („Document M4 and add mount end-to-end CI jobs“)

---

## Selbstprüfung

- **Spec-Abdeckung M4:** `api.rs`/`registry.rs`/`flags.rs`/`transcoder.rs` (3, 7); `fuse/adapter.rs` + Inode-/Handle-Tabellen + Errno-Mapping (4–6); `fuse/linux.rs`, `macos_dl.rs`, `macfuse.rs`, `fuset.rs` (7) mit fuser-Linux-ABI (1) und Folge-Spike (2); `Mounter` (9); `daemon/{protocol,client,server}` (10, 11); `state_dir.rs`, `cli_config.rs`, `registry.rs` (9); CLI `unlock/lock/status/stats/events/mounters/__daemon` (12–14); Auto-Lock (11, 14); Mount-E2E Linux-CI + FUSE-T macOS (8, 16); Koexistenz mit Desktop-App = manueller Schritt. Nicht in M4 (Spec ordnet zu): WebDAV/`--port` (M5), Keychain/`--store-password` (M6), `fs`-Zugriff auf gemountete Vaults (bleibt verweigert).
- **Typkonsistenz:** `KernelAbi` (1) in 2, 6, 7; `MountService/MountBuilder/Mount/MountCapability/MountError/UnmountError/ServiceInfo` (3) in 7, 9, 11, 12, 13; `MountFlags/AdapterOptions/parse_mount_flags` (3) in 5, 7; `NameTranscoder` (3) in 5, 7; `is_mountpoint` (3) in 6, 9, 12; `FilesystemLoop`/`errno_for` (4) in 5, 6; `InodeTable/FileHandles/DirHandles/DirListing` (4) in 5; `VaultOps/VaultOpsConfig/Attr` (5) in 6, 7; `CryptoFuse/FuseSessionHandle` (6) in 7; `NullMountProvider/services/all_services/service_by_class/conflicting_classes/service_infos` (7) in 9, 11, 12, 13; `StateDir/VaultStateFiles/RunInfo/process_alive`, `CliConfig`, `VaultRegistry/VaultInfo/RuntimeState`, `Mounter::{choose_service, mount}/MountRequest/MountOverrides/MountHandle` (9) in 11, 12, 13; `protocol::*`, `DaemonClient` (10) in 11, 12, 13; `DaemonConfig/run_daemon` (11) in 12, 14; `unmount_path` (Nachtrag 12→7) in 12.
- **Platzhalter:** keine; wo Signaturen an fuser-Interna anzupassen sind (Task 1), ist das Zielverhalten byte-genau vorgegeben.
- **Exit-Code-Mapping:** `MountFailed/MountPointInvalid` → 6, `UnmountFailed`/Daemon `UNMOUNT_FAILED` → 7, `DaemonUnreachable` → 10, `ALREADY_UNLOCKED/NOT_UNLOCKED`/`WrongState` → 5, `MountFailed` beim falschen Key im Daemon → 6 (Passwortfehler werden bereits im Elternprozess mit 4 abgefangen).

## Ausführung

`superpowers:subagent-driven-development` mit Opus-5-Subagenten; Reihenfolge 1 → 16. Task 2 und 8 laufen echte FUSE-T-Mounts auf diesem Mac (kein Root nötig); der Implementierer muss die Ergebnisse (mount-Tabelle, `cat`, `umount`) im Report belegen. Tasks 12–14 setzen `CRYPTO_ENABLE_NULL_MOUNTER=1` in den Tests.
