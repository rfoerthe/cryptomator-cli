# M0 + M1: Gerüst, Spikes und Core-Krypto – Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cargo-Workspace für `crypto` aufsetzen, die beiden Go/No-Go-Spikes (FUSE-T via dlopen, Desktop-Keychain lesen) durchführen und `cryptomator-core` mit dem vollständigen Vault-Format-8-Kryptokern (Masterkey-Datei, Vault-Config-JWT, Dateinamen, Header/Chunks beider Cipher-Combos, Streams, Backups, Recovery-Key) als 1:1-Port von cryptolib 2.2.2 / cryptofs 2.10.0 liefern, verifiziert gegen Known-Answer-Vektoren aus der echten Java-Bibliothek.

**Architecture:** Workspace mit vier Crates (`cryptomator-core` reine Logik, `cryptomator-mount`, `cryptomator-app`, Binary `crypto`). In M1 wird nur `cryptomator-core` gefüllt; alle Zufallswerte laufen über ein `Rng`-Trait, damit Tests mit einem deterministischen RNG byte-genau die Java-Ausgaben reproduzieren. Java-Tests existieren nicht in den Sources-JARs; alle KAT-Vektoren unten wurden am 2026-09-04 per jshell aus cryptolib 2.2.2 / cryptofs 2.10.0 erzeugt (Masterkey = Bytes 00..3f, deterministischer RNG `byte n = 0xA0 + (n & 0x3F)`).

**Tech Stack:** Rust stable ≥ 1.85 (cargo 1.98 lokal), RustCrypto-Generation digest 0.11: aes-siv 0.8, aes-gcm 0.11, aes 0.9, ctr 0.10, hmac 0.13, sha1 0.11, sha2 0.11, scrypt 0.12, aes-kw 0.3; data-encoding 2.11, serde/serde_json (preserve_order), uuid 1 (v4), zeroize 1.9, getrandom 0.4, crc32fast 1.5, thiserror 2, clap 4.6, fuser 0.18 (ohne libfuse-Feature), libloading 0.9, security-framework 3.7, tempfile 3, assert_cmd 2. Java 21+ mit Maven für den Fixture-Generator.

**Spec:** `docs/superpowers/specs/2026-09-04-crypto-cli-design.md`

## Global Constraints

- Lizenz AGPL-3.0-only; jede Crate trägt `license = "AGPL-3.0-only"`.
- Arbeitsverzeichnis für alle Befehle: `/Users/rfoerthe/work/cryptomator-cli` (eigenes Git-Repo, Branch `main`).
- Java-Vorlagen: `~/.m2/repository/org/cryptomator/cryptolib/2.2.2/cryptolib-2.2.2-sources.jar`, `~/.m2/repository/org/cryptomator/cryptofs/2.10.0/cryptofs-2.10.0-sources.jar` (lesen mit `unzip -p <jar> <pfad>`).
- AES-SIV-Schlüssel für RustCrypto = `macKey ‖ encKey` (cryptolib übergibt encKey als CTR-Key und macKey als S2V-Key).
- Masterkey-Layout: `raw[0..32]` = encKey, `raw[32..64]` = macKey.
- Passphrasen als `&str` (UTF-8); NFC-Normalisierung ist Aufgabe der App-Schicht (nicht M1).
- Alle Fehler in `cryptomator-core` sind `CoreError` (thiserror); keine `unwrap()` auf Eingabedaten.
- Commits: pro Task ein Commit, Nachricht endet mit `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.
- `cargo fmt` und `cargo clippy --workspace --all-targets -- -D warnings` müssen vor jedem Commit sauber sein.
- Kein FUSE ist auf dem Mac installiert. Spike A (Task 3) ist nur ausführbar, nachdem der User `brew install --cask macos-fuse-t/homebrew-cask/fuse-t` (oder macFUSE) installiert hat; der Spike-Code wird trotzdem geschrieben und kompiliert.

---

## Dateistruktur (M0 + M1)

```
Cargo.toml                                   Workspace, gemeinsame Dependency-Versionen, Release-Profil
rust-toolchain.toml                          stable
README.md, CHANGELOG.md
.github/workflows/ci.yml                     fmt, clippy, test auf ubuntu-22.04 + macos-15
crates/crypto/src/main.rs                    clap-Einstieg, Exit-Codes
crates/crypto/src/cli.rs                     Kommandogrammatik (in M1: nur `recovery-key validate`)
crates/crypto/tests/cli.rs                   assert_cmd-Tests
crates/cryptomator-app/src/lib.rs            (leer in M1)
crates/cryptomator-app/examples/spike_keychain.rs      Spike B
crates/cryptomator-mount/src/lib.rs          (leer in M1)
crates/cryptomator-mount/examples/spike_macos_dlopen.rs Spike A
crates/cryptomator-core/src/lib.rs           Modulbaum + Re-Exports
crates/cryptomator-core/src/error.rs         CoreError
crates/cryptomator-core/src/constants.rs     cryptofs Constants
crates/cryptomator-core/src/crypto/mod.rs
crates/cryptomator-core/src/crypto/rng.rs    Rng-Trait, OsRng, DetRng
crates/cryptomator-core/src/crypto/masterkey.rs
crates/cryptomator-core/src/crypto/kdf.rs    scrypt-KEK
crates/cryptomator-core/src/crypto/keywrap.rs RFC 3394
crates/cryptomator-core/src/crypto/siv.rs    FileNameCryptor
crates/cryptomator-core/src/crypto/header.rs FileHeader
crates/cryptomator-core/src/crypto/gcm.rs    SIV_GCM Header/Content
crates/cryptomator-core/src/crypto/ctrmac.rs SIV_CTRMAC Header/Content
crates/cryptomator-core/src/crypto/cryptor.rs CipherCombo, HeaderCryptor, ContentCryptor, Cryptor, Größenmathematik
crates/cryptomator-core/src/crypto/stream.rs EncryptingWriter, DecryptingReader
crates/cryptomator-core/src/masterkey_file.rs
crates/cryptomator-core/src/vault_config.rs
crates/cryptomator-core/src/backup.rs
crates/cryptomator-core/src/recovery/mod.rs
crates/cryptomator-core/src/recovery/words.rs + 4096words_en.txt
crates/cryptomator-core/src/recovery/key.rs
crates/cryptomator-core/tests/fixtures_masterkey.rs   liest alle Java-Fixtures
tools/fixture-gen/pom.xml, src/main/java/org/cryptomator/cli/fixtures/Gen.java
tests/fixtures/<name>/{vault.cryptomator,masterkey.cryptomator,d/…,fixture.json,expected.json}
docs/superpowers/spikes/2026-09-04-spike-a-fuse-t.md, 2026-09-04-spike-b-keychain.md
```

---

### Task 1: Workspace-Gerüst mit vier Crates, CI und `crypto --version`

**Files:**
- Create: `Cargo.toml`, `rust-toolchain.toml`, `README.md`, `CHANGELOG.md`, `.github/workflows/ci.yml`
- Create: `crates/cryptomator-core/Cargo.toml`, `crates/cryptomator-core/src/lib.rs`
- Create: `crates/cryptomator-app/Cargo.toml`, `crates/cryptomator-app/src/lib.rs`
- Create: `crates/cryptomator-mount/Cargo.toml`, `crates/cryptomator-mount/src/lib.rs`
- Create: `crates/crypto/Cargo.toml`, `crates/crypto/src/main.rs`, `crates/crypto/tests/cli.rs`

**Interfaces:**
- Produces: Workspace-Dependency-Tabelle (`[workspace.dependencies]`), von allen späteren Tasks per `{ workspace = true }` genutzt. Binary `crypto` mit `--version`.

- [ ] **Step 1: Workspace-Manifest schreiben**

```toml
# Cargo.toml
[workspace]
resolver = "2"
members = [
    "crates/cryptomator-core",
    "crates/cryptomator-app",
    "crates/cryptomator-mount",
    "crates/crypto",
]

[workspace.package]
version = "0.1.0"
edition = "2021"
license = "AGPL-3.0-only"
repository = "https://github.com/rfoerthe/cryptomator-cli"
rust-version = "1.85"

[workspace.dependencies]
aes-siv = "0.8"
aes-gcm = "0.11"
aes = "0.9"
ctr = "0.10"
hmac = "0.13"
sha1 = "0.11"
sha2 = "0.11"
scrypt = "0.12"
aes-kw = "0.3"
data-encoding = "2.11"
serde = { version = "1", features = ["derive"] }
serde_json = { version = "1", features = ["preserve_order"] }
uuid = { version = "1", features = ["v4"] }
zeroize = { version = "1.9", features = ["derive"] }
getrandom = "0.4"
crc32fast = "1.5"
thiserror = "2"
anyhow = "1"
clap = { version = "4.6", features = ["derive", "env", "wrap_help"] }
fuser = { version = "0.18", default-features = false }
libloading = "0.9"
tempfile = "3"
assert_cmd = "2"
predicates = "3"

[profile.release]
lto = "fat"
codegen-units = 1
strip = "symbols"
panic = "unwind"
```

```toml
# rust-toolchain.toml
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
```

- [ ] **Step 2: Crate-Manifeste und leere Libraries schreiben**

```toml
# crates/cryptomator-core/Cargo.toml
[package]
name = "cryptomator-core"
description = "Cryptomator vault format 8 (port of cryptolib/cryptofs)"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true

[dependencies]
aes-siv.workspace = true
aes-gcm.workspace = true
aes.workspace = true
ctr.workspace = true
hmac.workspace = true
sha1.workspace = true
sha2.workspace = true
scrypt.workspace = true
aes-kw.workspace = true
data-encoding.workspace = true
serde.workspace = true
serde_json.workspace = true
uuid.workspace = true
zeroize.workspace = true
getrandom.workspace = true
crc32fast.workspace = true
thiserror.workspace = true

[dev-dependencies]
tempfile.workspace = true
```

```rust
// crates/cryptomator-core/src/lib.rs
//! Cryptomator vault format 8, ported from cryptolib 2.2.2 and cryptofs 2.10.0.
#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
```

```toml
# crates/cryptomator-app/Cargo.toml
[package]
name = "cryptomator-app"
description = "Settings, keychain, daemon and vault registry for the crypto CLI"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true

[dependencies]
cryptomator-core = { path = "../cryptomator-core" }

[target.'cfg(target_os = "macos")'.dependencies]
security-framework = "3.7"
```

```rust
// crates/cryptomator-app/src/lib.rs
//! Application layer: settings.json, keychain, daemon protocol, vault registry.
```

```toml
# crates/cryptomator-mount/Cargo.toml
[package]
name = "cryptomator-mount"
description = "Mount services (FUSE, WebDAV) for the crypto CLI"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true

[features]
default = ["fuse"]
fuse = ["dep:fuser", "dep:libloading"]

[dependencies]
cryptomator-core = { path = "../cryptomator-core" }
fuser = { workspace = true, optional = true }
libloading = { workspace = true, optional = true }
```

```rust
// crates/cryptomator-mount/src/lib.rs
//! Mount services: FUSE (Linux libfuse3, macOS macFUSE/FUSE-T via dlopen) and WebDAV.
```

```toml
# crates/crypto/Cargo.toml
[package]
name = "crypto"
description = "Cryptomator command line interface"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true

[[bin]]
name = "crypto"
path = "src/main.rs"

[dependencies]
cryptomator-core = { path = "../cryptomator-core" }
cryptomator-app = { path = "../cryptomator-app" }
cryptomator-mount = { path = "../cryptomator-mount" }
clap.workspace = true
anyhow.workspace = true

[dev-dependencies]
assert_cmd.workspace = true
predicates.workspace = true
```

- [ ] **Step 3: Fehlschlagenden CLI-Test schreiben**

```rust
// crates/crypto/tests/cli.rs
use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn version_flag_prints_name_and_version() {
    Command::cargo_bin("crypto")
        .unwrap()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::starts_with("crypto 0.1.0"));
}

#[test]
fn no_arguments_prints_help_and_exits_with_usage_code() {
    Command::cargo_bin("crypto")
        .unwrap()
        .assert()
        .code(2)
        .stderr(predicate::str::contains("Usage: crypto"));
}
```

- [ ] **Step 4: Test laufen lassen, Fehlschlag bestätigen**

Run: `cargo test -p crypto`
Expected: FAIL (Binary `crypto` existiert noch nicht / `main.rs` fehlt)

- [ ] **Step 5: Binary-Einstieg schreiben**

```rust
// crates/crypto/src/main.rs
//! `crypto` – Cryptomator command line interface.
use clap::Parser;
use std::process::ExitCode;

/// Exit codes as defined in the design spec.
pub mod exit {
    pub const OK: u8 = 0;
    pub const GENERAL: u8 = 1;
    pub const USAGE: u8 = 2;
    pub const INVALID_PASSPHRASE: u8 = 4;
}

#[derive(Parser, Debug)]
#[command(name = "crypto", version, about = "Cryptomator vaults from the command line", arg_required_else_help = true)]
struct Cli {}

fn main() -> ExitCode {
    match Cli::try_parse() {
        Ok(_cli) => ExitCode::from(exit::OK),
        Err(err) => {
            // clap's own --help/--version output goes to stdout with exit 0; usage errors to stderr with exit 2.
            let _ = err.print();
            match err.kind() {
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion => ExitCode::from(exit::OK),
                _ => ExitCode::from(exit::USAGE),
            }
        }
    }
}
```

Hinweis: `arg_required_else_help` erzeugt bei fehlenden Argumenten einen Fehler vom Kind `DisplayHelpOnMissingArgumentOrSubcommand`, der auf stderr gedruckt wird und hier Exit 2 liefert.

- [ ] **Step 6: Tests laufen lassen**

Run: `cargo test -p crypto`
Expected: PASS (2 Tests)

- [ ] **Step 7: README, CHANGELOG und CI schreiben**

```markdown
<!-- README.md -->
# crypto – Cryptomator on the command line

`crypto` is a Rust command line client for [Cryptomator](https://cryptomator.org) vaults (vault format 8)
for macOS and Linux. It shares the desktop app's `settings.json` and keychain entries.

Status: early development. See `docs/superpowers/specs/2026-09-04-crypto-cli-design.md`.

## Build

    cargo build --release

## License

AGPL-3.0-only. The vault format implementation is a port of
[cryptolib](https://github.com/cryptomator/cryptolib) and [cryptofs](https://github.com/cryptomator/cryptofs) (AGPL-3.0).
```

```markdown
<!-- CHANGELOG.md -->
# Changelog

## Unreleased

- Workspace scaffold.
```

```yaml
# .github/workflows/ci.yml
name: CI
on:
  push:
    branches: [main]
  pull_request:
jobs:
  test:
    strategy:
      matrix:
        os: [ubuntu-22.04, macos-15]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy
      - uses: Swatinem/rust-cache@v2
      - run: cargo fmt --all --check
      - run: cargo clippy --workspace --all-targets -- -D warnings
      - run: cargo test --workspace
```

- [ ] **Step 8: Gesamtes Workspace prüfen und committen**

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
Expected: PASS

```bash
git add -A
git commit -m "Scaffold workspace with core, app, mount crates and crypto binary

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 2: Spike B – Desktop-Keychain-Eintrag auf macOS lesen

**Files:**
- Create: `crates/cryptomator-app/examples/spike_keychain.rs`
- Create: `docs/superpowers/spikes/2026-09-04-spike-b-keychain.md`

**Interfaces:**
- Produces: Nachweis, dass `security_framework::passwords::get_generic_password("Cryptomator", <vault-id>)` die von Cryptomator.app gespeicherten Passwörter liest. Ergebnis fließt in M6.

- [ ] **Step 1: Vault-IDs der Desktop-App ermitteln (nur lesen)**

Run: `python3 -c 'import json,os; d=json.load(open(os.path.expanduser("~/Library/Application Support/Cryptomator/settings.json"))); [print(v["id"], v.get("displayName"), v.get("path")) for v in d.get("directories",[])]'`
Expected: Liste von Vault-IDs (12 Zeichen base64url). Eine davon wird für Step 3 gewählt. Dann `security find-generic-password -s Cryptomator -a <id>` (ohne `-w`): Expected: Eintrag gefunden (Exit 0). Ist kein Eintrag vorhanden, in Step 3 zuerst `security add-generic-password -s Cryptomator -a spike-test-id -w spike-password` anlegen und `spike-test-id` nutzen.

- [ ] **Step 2: Beispielprogramm schreiben**

```rust
// crates/cryptomator-app/examples/spike_keychain.rs
//! Spike B: read a Cryptomator desktop keychain entry.
//! Usage: cargo run -p cryptomator-app --example spike_keychain -- <vault-id>
//! Prints only the byte length and UTF-8 validity of the stored passphrase, never the passphrase.

#[cfg(target_os = "macos")]
fn main() {
    let account = std::env::args().nth(1).expect("usage: spike_keychain <vault-id>");
    match security_framework::passwords::get_generic_password("Cryptomator", &account) {
        Ok(bytes) => {
            println!(
                "found entry for account {account}: {} bytes, valid utf-8: {}",
                bytes.len(),
                std::str::from_utf8(&bytes).is_ok()
            );
        }
        Err(err) => {
            eprintln!("keychain lookup failed: {err} (code {})", err.code());
            std::process::exit(1);
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("this spike only runs on macOS");
    std::process::exit(2);
}
```

- [ ] **Step 3: Spike ausführen**

Run: `cargo run -p cryptomator-app --example spike_keychain -- <vault-id>`
Expected: `found entry for account <id>: N bytes, valid utf-8: true` (macOS zeigt ggf. einen Keychain-Zugriffsdialog; „Erlauben“ wählen). Zusätzlich Gegenprobe: `security find-generic-password -s Cryptomator -a <id> -w | wc -c` liefert N+1 (Newline).

- [ ] **Step 4: Ergebnis dokumentieren**

```markdown
<!-- docs/superpowers/spikes/2026-09-04-spike-b-keychain.md -->
# Spike B: Desktop-Keychain-Eintrag lesen (macOS)

Frage: Kann `security-framework` (Generic Password, Service `Cryptomator`, Account = Vault-ID) die Einträge von Cryptomator.app lesen?

Durchführung: `cargo run -p cryptomator-app --example spike_keychain -- <vault-id>` gegen einen Eintrag der installierten Desktop-App (Version aus `writtenByVersion` in settings.json).

Ergebnis: <GO | NO-GO>. Beobachtungen: <Dialog erschienen? Länge korrekt? Fehlercode?>

Konsequenz für M6: <security-framework direkt verwenden | Alternative>.
```

- [ ] **Step 5: Commit**

```bash
git add crates/cryptomator-app/examples/spike_keychain.rs docs/superpowers/spikes/2026-09-04-spike-b-keychain.md
git commit -m "Add spike B: read Cryptomator desktop keychain entry on macOS

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 3: Spike A – FUSE-T/macFUSE per dlopen mit `fuser::Session::from_fd`

**Files:**
- Create: `crates/cryptomator-mount/examples/spike_macos_dlopen.rs`
- Create: `docs/superpowers/spikes/2026-09-04-spike-a-fuse-t.md`

**Interfaces:**
- Produces: Go/No-Go für den macOS-FUSE-Pfad aus der Spec (dlopen `libfuse-t.dylib`/`libfuse.2.dylib` → `fuse_mount_compat25` → `Session::from_fd`). Bei No-Go plant M4 ein `fuse_lowlevel_ops`-FFI-Backend für FUSE-T.

- [ ] **Step 1: Beispielprogramm schreiben**

```rust
// crates/cryptomator-mount/examples/spike_macos_dlopen.rs
//! Spike A: mount a hello-world filesystem on macOS by dlopen-ing the vendor libfuse
//! (macFUSE or FUSE-T), calling `fuse_mount_compat25` and handing the fd to fuser.
//! Usage: cargo run -p cryptomator-mount --example spike_macos_dlopen -- <fuse-t|macfuse> <empty-mountpoint-dir>
//! Unmount from another shell with `umount <mountpoint>`; the program then exits.

#[cfg(all(target_os = "macos", feature = "fuse"))]
mod spike {
    use fuser::{
        Config, Errno, FileAttr, FileHandle, FileType, Filesystem, Generation, INodeNo, LockOwner, OpenFlags,
        ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, Request, Session, SessionACL,
    };
    use std::ffi::{c_char, c_int, CString, OsStr};
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::path::Path;
    use std::time::{Duration, UNIX_EPOCH};

    #[repr(C)]
    struct FuseArgs {
        argc: c_int,
        argv: *const *const c_char,
        allocated: c_int,
    }

    const TTL: Duration = Duration::from_secs(1);
    const CONTENT: &[u8] = b"Hello from crypto spike A!\n";

    fn attr(ino: u64, kind: FileType, size: u64, perm: u16) -> FileAttr {
        FileAttr {
            ino: INodeNo(ino),
            size,
            blocks: 1,
            atime: UNIX_EPOCH,
            mtime: UNIX_EPOCH,
            ctime: UNIX_EPOCH,
            crtime: UNIX_EPOCH,
            kind,
            perm,
            nlink: 1,
            uid: unsafe { libc_geteuid() },
            gid: unsafe { libc_getegid() },
            rdev: 0,
            flags: 0,
            blksize: 512,
        }
    }

    extern "C" {
        #[link_name = "geteuid"]
        fn libc_geteuid() -> u32;
        #[link_name = "getegid"]
        fn libc_getegid() -> u32;
    }

    struct HelloFs;

    impl Filesystem for HelloFs {
        fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
            if parent == INodeNo::ROOT && name == "hello.txt" {
                reply.entry(&TTL, &attr(2, FileType::RegularFile, CONTENT.len() as u64, 0o444), Generation(0));
            } else {
                reply.error(Errno::ENOENT);
            }
        }

        fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
            match u64::from(ino) {
                1 => reply.attr(&TTL, &attr(1, FileType::Directory, 0, 0o755)),
                2 => reply.attr(&TTL, &attr(2, FileType::RegularFile, CONTENT.len() as u64, 0o444)),
                _ => reply.error(Errno::ENOENT),
            }
        }

        fn read(
            &self,
            _req: &Request,
            ino: INodeNo,
            _fh: FileHandle,
            offset: u64,
            size: u32,
            _flags: OpenFlags,
            _lock_owner: Option<LockOwner>,
            reply: ReplyData,
        ) {
            if u64::from(ino) != 2 {
                reply.error(Errno::ENOENT);
                return;
            }
            let start = (offset as usize).min(CONTENT.len());
            let end = (start + size as usize).min(CONTENT.len());
            reply.data(&CONTENT[start..end]);
        }

        fn readdir(&self, _req: &Request, ino: INodeNo, _fh: FileHandle, offset: u64, mut reply: ReplyDirectory) {
            if ino != INodeNo::ROOT {
                reply.error(Errno::ENOENT);
                return;
            }
            let entries = [(1u64, FileType::Directory, "."), (1, FileType::Directory, ".."), (2, FileType::RegularFile, "hello.txt")];
            for (i, (ino, kind, name)) in entries.iter().enumerate().skip(offset as usize) {
                if reply.add(INodeNo(*ino), (i + 1) as u64, *kind, name) {
                    break;
                }
            }
            reply.ok();
        }
    }

    pub fn run() -> Result<(), Box<dyn std::error::Error>> {
        let args: Vec<String> = std::env::args().collect();
        if args.len() != 3 {
            eprintln!("usage: spike_macos_dlopen <fuse-t|macfuse> <mountpoint>");
            std::process::exit(2);
        }
        let (lib_path, extra_opts): (&str, &[&str]) = match args[1].as_str() {
            "fuse-t" => ("/usr/local/lib/libfuse-t.dylib", &["-o", "nonamedattr", "-o", "backend=smb"]),
            "macfuse" => ("/usr/local/lib/libfuse.2.dylib", &["-o", "noappledouble"]),
            other => {
                eprintln!("unknown backend {other}");
                std::process::exit(2);
            }
        };
        if !Path::new(lib_path).exists() {
            eprintln!("{lib_path} not found – install FUSE-T (brew install --cask macos-fuse-t/homebrew-cask/fuse-t) or macFUSE");
            std::process::exit(2);
        }
        let mountpoint = &args[2];

        // SAFETY: loading a vendor library; symbols are called with the documented libfuse 2.x C signatures.
        let lib = unsafe { libloading::Library::new(lib_path)? };
        let fuse_mount: libloading::Symbol<unsafe extern "C" fn(*const c_char, *const FuseArgs) -> c_int> =
            unsafe { lib.get(b"fuse_mount_compat25\0")? };

        let mut argv_owned: Vec<CString> = vec![CString::new("crypto-spike")?, CString::new("-o")?, CString::new("volname=crypto-spike")?];
        for opt in extra_opts {
            argv_owned.push(CString::new(*opt)?);
        }
        let argv: Vec<*const c_char> = argv_owned.iter().map(|s| s.as_ptr()).collect();
        let fuse_args = FuseArgs { argc: argv.len() as c_int, argv: argv.as_ptr(), allocated: 0 };
        let mp = CString::new(mountpoint.as_str())?;

        let raw_fd = unsafe { fuse_mount(mp.as_ptr(), &fuse_args) };
        if raw_fd < 0 {
            return Err(format!("fuse_mount_compat25 failed: {}", std::io::Error::last_os_error()).into());
        }
        // SAFETY: raw_fd is a freshly returned, owned file descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        let config = Config::default();
        let session = Session::from_fd(HelloFs, fd, SessionACL::Owner, config)?;
        println!("mounted at {mountpoint}; in another shell run: cat {mountpoint}/hello.txt && umount {mountpoint}");
        session.run()?;
        println!("session ended (unmounted)");
        Ok(())
    }
}

#[cfg(all(target_os = "macos", feature = "fuse"))]
fn main() {
    if let Err(err) = spike::run() {
        eprintln!("spike failed: {err}");
        std::process::exit(1);
    }
}

#[cfg(not(all(target_os = "macos", feature = "fuse")))]
fn main() {
    eprintln!("this spike only runs on macOS with the `fuse` feature");
    std::process::exit(2);
}
```

- [ ] **Step 2: Kompilieren (ohne FUSE-Installation möglich)**

Run: `cargo build -p cryptomator-mount --example spike_macos_dlopen`
Expected: Build ok. Falls fuser 0.18 andere Signaturen meldet (z. B. `readdir`-Parameter), die Fehlermeldung mit `~/.cargo/registry/src/*/fuser-0.18.0/examples/hello.rs` abgleichen und anpassen.

- [ ] **Step 3: Spike gegen FUSE-T ausführen (nur wenn installiert)**

Run: `ls /usr/local/lib/libfuse-t.dylib` — falls fehlt: Ergebnis „blocked, FUSE-T nicht installiert“ dokumentieren und Task abschließen; M1 hängt nicht davon ab.
Sonst: `mkdir -p /tmp/spike-mnt && cargo run -p cryptomator-mount --example spike_macos_dlopen -- fuse-t /tmp/spike-mnt` und in einer zweiten Shell `cat /tmp/spike-mnt/hello.txt; umount /tmp/spike-mnt`.
Expected GO: `Hello from crypto spike A!` erscheint, Programm endet mit „session ended“. NO-GO: `fuse_mount_compat25` liefert fd < 0, oder `Session::from_fd` scheitert im Handshake (Fehler notieren).
Danach dasselbe mit `macfuse`, falls installiert.

- [ ] **Step 4: Ergebnis dokumentieren**

```markdown
<!-- docs/superpowers/spikes/2026-09-04-spike-a-fuse-t.md -->
# Spike A: FUSE-T / macFUSE über dlopen + fuser::Session::from_fd

Frage: Liefert `fuse_mount_compat25` aus `libfuse-t.dylib` einen fd, über den fuser 0.18 das Kernel-FUSE-Protokoll sprechen kann?

Setup: `cargo run -p cryptomator-mount --example spike_macos_dlopen -- <fuse-t|macfuse> /tmp/spike-mnt`

| Backend | Installiert (Version) | fuse_mount fd | Handshake | cat hello.txt | umount | Ergebnis |
|---|---|---|---|---|---|---|
| FUSE-T | <ja/nein> | <ok/fehler> | <ok/fehler> | <ok/fehler> | <ok/fehler> | <GO/NO-GO/BLOCKED> |
| macFUSE | <ja/nein> | | | | | |

Beobachtungen: <Fehlermeldungen, Protokolldetails>

Konsequenz für M4: <dlopen-Pfad wie geplant | lowlevel-FFI-Backend für FUSE-T einplanen>.
```

- [ ] **Step 5: Commit**

```bash
git add crates/cryptomator-mount/examples/spike_macos_dlopen.rs docs/superpowers/spikes/2026-09-04-spike-a-fuse-t.md
git commit -m "Add spike A: mount via dlopen'd libfuse and fuser::Session::from_fd

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 4: Core-Fundament – Fehler, Konstanten, RNG-Trait, `Masterkey`

**Files:**
- Create: `crates/cryptomator-core/src/error.rs`, `src/constants.rs`, `src/crypto/mod.rs`, `src/crypto/rng.rs`, `src/crypto/masterkey.rs`
- Modify: `crates/cryptomator-core/src/lib.rs`

**Interfaces:**
- Produces: `CoreError`, `Result<T>`; `trait Rng { fn fill(&mut self, buf: &mut [u8]); }`, `OsRng`, `DetRng` (`DetRng::default()`, `DetRng::starting_at(u64)`); `Masterkey::{from_raw([u8;64]), from_slice(&[u8]), generate(&mut dyn Rng), enc_key() -> &[u8;32], mac_key() -> &[u8;32], raw() -> &[u8;64]}`; Konstanten aus cryptofs `Constants.java`.

- [ ] **Step 1: Fehlschlagende Tests schreiben**

```rust
// am Ende von crates/cryptomator-core/src/crypto/rng.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn det_rng_matches_java_det_random_sequence() {
        let mut rng = DetRng::default();
        let mut buf = [0u8; 70];
        rng.fill(&mut buf);
        assert_eq!(&buf[..4], &[0xa0, 0xa1, 0xa2, 0xa3]);
        assert_eq!(buf[63], 0xdf);
        assert_eq!(buf[64], 0xa0, "counter wraps after 64 bytes");
        assert_eq!(buf[69], 0xa5);
    }

    #[test]
    fn det_rng_starting_at_continues_the_counter() {
        let mut rng = DetRng::starting_at(8);
        let mut buf = [0u8; 8];
        rng.fill(&mut buf);
        assert_eq!(buf, [0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf]);
    }

    #[test]
    fn os_rng_produces_different_outputs() {
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        OsRng.fill(&mut a);
        OsRng.fill(&mut b);
        assert_ne!(a, b);
    }
}
```

```rust
// am Ende von crates/cryptomator-core/src/crypto/masterkey.rs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rng::DetRng;

    fn sequential_key() -> [u8; 64] {
        let mut raw = [0u8; 64];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = i as u8;
        }
        raw
    }

    #[test]
    fn enc_and_mac_key_are_first_and_second_half() {
        let key = Masterkey::from_raw(sequential_key());
        assert_eq!(key.enc_key()[0], 0x00);
        assert_eq!(key.enc_key()[31], 0x1f);
        assert_eq!(key.mac_key()[0], 0x20);
        assert_eq!(key.mac_key()[31], 0x3f);
        assert_eq!(key.raw(), &sequential_key());
    }

    #[test]
    fn from_slice_rejects_wrong_length() {
        assert!(matches!(Masterkey::from_slice(&[0u8; 63]), Err(CoreError::InvalidArgument(_))));
        assert!(Masterkey::from_slice(&[0u8; 64]).is_ok());
    }

    #[test]
    fn generate_uses_rng() {
        let key = Masterkey::generate(&mut DetRng::default());
        assert_eq!(key.raw()[0], 0xa0);
        assert_eq!(key.raw()[63], 0xdf);
    }

    #[test]
    fn debug_output_is_redacted() {
        let key = Masterkey::from_raw(sequential_key());
        assert_eq!(format!("{key:?}"), "Masterkey(<redacted>)");
    }
}
```

- [ ] **Step 2: Tests laufen lassen, Fehlschlag bestätigen**

Run: `cargo test -p cryptomator-core`
Expected: FAIL (Module existieren nicht)

- [ ] **Step 3: Implementieren**

```rust
// crates/cryptomator-core/src/error.rs
//! Error type of the core crate. Variants mirror the cryptolib/cryptofs exceptions.
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("invalid passphrase")]
    InvalidPassphrase,
    #[error("authentication failed: {0}")]
    AuthenticationFailed(String),
    #[error("invalid masterkey file: {0}")]
    InvalidMasterkeyFile(String),
    #[error("failed to load vault config: {0}")]
    VaultConfigLoad(String),
    #[error("vault key does not match the vault config signature")]
    VaultKeyInvalid,
    #[error("vault config is for format {actual}, expected {expected}")]
    VaultVersionMismatch { expected: u32, actual: u32 },
    #[error("Cryptomator Hub vaults are not supported (key id: {0})")]
    HubVaultUnsupported(String),
    #[error("unsupported key id: {0}")]
    UnsupportedKeyId(String),
    #[error("invalid recovery key: {0}")]
    InvalidRecoveryKey(String),
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, CoreError>;
```

```rust
// crates/cryptomator-core/src/constants.rs
//! Vault layout constants, ported from cryptofs `common/Constants.java`.
pub const VAULT_VERSION: u32 = 8;
pub const BACKUP_SUFFIX: &str = ".bkup";
pub const DATA_DIR_NAME: &str = "d";
pub const ROOT_DIR_ID: &str = "";
pub const RECOVERY_DIR_ID: &str = "recovery";
pub const CRYPTOMATOR_FILE_SUFFIX: &str = ".c9r";
pub const DEFLATED_FILE_SUFFIX: &str = ".c9s";
pub const INUSE_FILE_SUFFIX: &str = ".c9u";
pub const DIR_FILE_NAME: &str = "dir.c9r";
pub const SYMLINK_FILE_NAME: &str = "symlink.c9r";
pub const CONTENTS_FILE_NAME: &str = "contents.c9r";
pub const INFLATED_FILE_NAME: &str = "name.c9s";
pub const DIR_ID_BACKUP_FILE_NAME: &str = "dirid.c9r";
pub const MAX_SYMLINK_LENGTH: usize = 32767;
pub const MAX_DIR_ID_LENGTH: usize = 36;
pub const MAX_CIPHER_NAME_LENGTH: usize = 220;
pub const MIN_CIPHER_NAME_LENGTH: usize = 28;
pub const MAX_ADDITIONAL_PATH_LENGTH: usize = 48;
pub const RECOVERY_DIR_NAME: &str = "LOST+FOUND";
pub const INUSE_CLEARTEXT_SIZE: usize = 1000;
/// File names used by the desktop app (`common/Constants.java`).
pub const MASTERKEY_FILENAME: &str = "masterkey.cryptomator";
pub const VAULTCONFIG_FILENAME: &str = "vault.cryptomator";
pub const DEFAULT_KEY_ID: &str = "masterkeyfile:masterkey.cryptomator";
```

```rust
// crates/cryptomator-core/src/crypto/rng.rs
//! Random number source abstraction so tests can reproduce Java's deterministic vectors.

/// Fills buffers with random bytes.
pub trait Rng {
    fn fill(&mut self, buf: &mut [u8]);
}

/// Operating system CSPRNG.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsRng;

impl Rng for OsRng {
    fn fill(&mut self, buf: &mut [u8]) {
        getrandom::fill(buf).expect("operating system random number generator unavailable");
    }
}

/// Deterministic RNG reproducing the Java `DetRandom` used to create the known-answer vectors:
/// byte number `n` (counting from 0 over the lifetime of the instance) is `0xA0 + (n & 0x3F)`.
/// Never use outside tests and fixture generation.
#[derive(Debug, Default, Clone)]
pub struct DetRng {
    counter: u64,
}

impl DetRng {
    pub fn starting_at(counter: u64) -> Self {
        Self { counter }
    }
}

impl Rng for DetRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = 0xA0 + (self.counter & 0x3F) as u8;
            self.counter += 1;
        }
    }
}
```

```rust
// crates/cryptomator-core/src/crypto/masterkey.rs
//! 512-bit vault masterkey (`api/Masterkey.java`): encryption key || MAC key.
use crate::crypto::rng::Rng;
use crate::error::{CoreError, Result};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const SUBKEY_LEN: usize = 32;
pub const MASTERKEY_LEN: usize = 64;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Masterkey {
    raw: [u8; MASTERKEY_LEN],
}

impl Masterkey {
    pub fn from_raw(raw: [u8; MASTERKEY_LEN]) -> Self {
        Self { raw }
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let raw: [u8; MASTERKEY_LEN] = bytes
            .try_into()
            .map_err(|_| CoreError::InvalidArgument(format!("masterkey must be {MASTERKEY_LEN} bytes, got {}", bytes.len())))?;
        Ok(Self { raw })
    }

    pub fn from_parts(enc_key: &[u8; SUBKEY_LEN], mac_key: &[u8; SUBKEY_LEN]) -> Self {
        let mut raw = [0u8; MASTERKEY_LEN];
        raw[..SUBKEY_LEN].copy_from_slice(enc_key);
        raw[SUBKEY_LEN..].copy_from_slice(mac_key);
        Self { raw }
    }

    pub fn generate(rng: &mut dyn Rng) -> Self {
        let mut raw = [0u8; MASTERKEY_LEN];
        rng.fill(&mut raw);
        Self { raw }
    }

    pub fn enc_key(&self) -> &[u8; SUBKEY_LEN] {
        self.raw[..SUBKEY_LEN].try_into().expect("slice has fixed length")
    }

    pub fn mac_key(&self) -> &[u8; SUBKEY_LEN] {
        self.raw[SUBKEY_LEN..].try_into().expect("slice has fixed length")
    }

    pub fn raw(&self) -> &[u8; MASTERKEY_LEN] {
        &self.raw
    }
}

impl std::fmt::Debug for Masterkey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Masterkey(<redacted>)")
    }
}
```

```rust
// crates/cryptomator-core/src/crypto/mod.rs
//! Cryptographic primitives of vault format 8.
pub mod masterkey;
pub mod rng;
```

```rust
// crates/cryptomator-core/src/lib.rs
//! Cryptomator vault format 8, ported from cryptolib 2.2.2 and cryptofs 2.10.0.
#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod constants;
pub mod crypto;
pub mod error;

pub use crypto::masterkey::Masterkey;
pub use crypto::rng::{DetRng, OsRng, Rng};
pub use error::{CoreError, Result};
```

- [ ] **Step 4: Tests laufen lassen**

Run: `cargo test -p cryptomator-core`
Expected: PASS (7 Tests)

- [ ] **Step 5: Commit**

```bash
git add crates/cryptomator-core
git commit -m "Add core error type, vault constants, Rng trait and Masterkey

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 5: scrypt-KEK und RFC-3394-Key-Wrap

**Files:**
- Create: `crates/cryptomator-core/src/crypto/kdf.rs`, `src/crypto/keywrap.rs`
- Modify: `crates/cryptomator-core/src/crypto/mod.rs`

**Interfaces:**
- Produces: `kdf::scrypt_kek(passphrase: &str, salt: &[u8], pepper: &[u8], cost_param: u32, block_size: u32) -> Result<Zeroizing<[u8; 32]>>`; `keywrap::wrap_key(kek: &[u8;32], key: &[u8;32]) -> [u8; 40]`; `keywrap::unwrap_key(kek: &[u8;32], wrapped: &[u8]) -> Result<Zeroizing<[u8;32]>>` (Fehler: `CoreError::AuthenticationFailed`).

- [ ] **Step 1: Fehlschlagende Tests schreiben**

```rust
// am Ende von crates/cryptomator-core/src/crypto/kdf.rs
#[cfg(test)]
mod tests {
    use super::*;
    use data_encoding::HEXLOWER;

    #[test]
    fn rfc7914_vector_1_first_32_bytes() {
        // RFC 7914 §12, scrypt("", "", N=16, r=1, p=1, dkLen=64) – dkLen 32 is the prefix.
        let kek = scrypt_kek("", b"", b"", 16, 1).unwrap();
        assert_eq!(HEXLOWER.encode(&*kek), "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442");
    }

    #[test]
    fn pepper_is_appended_to_salt() {
        let with_pepper = scrypt_kek("pw", b"sa", b"lt", 16, 1).unwrap();
        let joined = scrypt_kek("pw", b"salt", b"", 16, 1).unwrap();
        assert_eq!(*with_pepper, *joined);
    }

    #[test]
    fn rejects_cost_param_that_is_not_a_power_of_two() {
        assert!(matches!(scrypt_kek("pw", b"salt", b"", 1000, 8), Err(CoreError::InvalidArgument(_))));
        assert!(matches!(scrypt_kek("pw", b"salt", b"", 1, 8), Err(CoreError::InvalidArgument(_))));
    }
}
```

```rust
// am Ende von crates/cryptomator-core/src/crypto/keywrap.rs
#[cfg(test)]
mod tests {
    use super::*;
    use data_encoding::HEXUPPER;

    // RFC 3394 §4.6: wrap 256 bits of key data with a 256-bit KEK.
    const KEK: &str = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
    const KEY: &str = "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F";
    const WRAPPED: &str = "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21";

    fn arr32(hex: &str) -> [u8; 32] {
        HEXUPPER.decode(hex.as_bytes()).unwrap().try_into().unwrap()
    }

    #[test]
    fn wraps_like_rfc3394() {
        let wrapped = wrap_key(&arr32(KEK), &arr32(KEY));
        assert_eq!(HEXUPPER.encode(&wrapped), WRAPPED);
    }

    #[test]
    fn unwraps_like_rfc3394() {
        let wrapped = HEXUPPER.decode(WRAPPED.as_bytes()).unwrap();
        let key = unwrap_key(&arr32(KEK), &wrapped).unwrap();
        assert_eq!(*key, arr32(KEY));
    }

    #[test]
    fn unwrap_with_wrong_kek_fails_authentication() {
        let wrapped = HEXUPPER.decode(WRAPPED.as_bytes()).unwrap();
        let mut kek = arr32(KEK);
        kek[0] ^= 1;
        assert!(matches!(unwrap_key(&kek, &wrapped), Err(CoreError::AuthenticationFailed(_))));
    }

    #[test]
    fn unwrap_rejects_wrong_length() {
        assert!(matches!(unwrap_key(&arr32(KEK), &[0u8; 39]), Err(CoreError::AuthenticationFailed(_))));
    }
}
```

- [ ] **Step 2: Tests laufen lassen, Fehlschlag bestätigen**

Run: `cargo test -p cryptomator-core kdf keywrap`
Expected: FAIL (Module fehlen)

- [ ] **Step 3: Implementieren**

```rust
// crates/cryptomator-core/src/crypto/kdf.rs
//! scrypt key derivation for the masterkey file (`common/Scrypt.java`, `MasterkeyFileAccess.scrypt`).
//! p is fixed to 1 and the derived key is always 32 bytes, exactly like cryptolib.
use crate::error::{CoreError, Result};
use zeroize::Zeroizing;

pub const KEK_LEN: usize = 32;

pub fn scrypt_kek(passphrase: &str, salt: &[u8], pepper: &[u8], cost_param: u32, block_size: u32) -> Result<Zeroizing<[u8; KEK_LEN]>> {
    if cost_param < 2 || !cost_param.is_power_of_two() {
        return Err(CoreError::InvalidArgument("scrypt N must be a power of 2 greater than 1".into()));
    }
    let log_n = cost_param.trailing_zeros() as u8;
    let params = scrypt::Params::new(log_n, block_size, 1).map_err(|e| CoreError::InvalidArgument(format!("invalid scrypt parameters: {e}")))?;
    let mut salt_and_pepper = Zeroizing::new(Vec::with_capacity(salt.len() + pepper.len()));
    salt_and_pepper.extend_from_slice(salt);
    salt_and_pepper.extend_from_slice(pepper);
    let mut kek = Zeroizing::new([0u8; KEK_LEN]);
    scrypt::scrypt(passphrase.as_bytes(), &salt_and_pepper, &params, kek.as_mut())
        .map_err(|e| CoreError::InvalidArgument(format!("scrypt failed: {e}")))?;
    Ok(kek)
}
```

```rust
// crates/cryptomator-core/src/crypto/keywrap.rs
//! AES key wrap (RFC 3394) as used by `common/AesKeyWrap.java` (JCE "AESWrap").
use crate::error::{CoreError, Result};
use aes_kw::KwAes256;
use aes_kw::cipher::KeyInit;
use zeroize::Zeroizing;

pub const WRAPPED_LEN: usize = 40;

pub fn wrap_key(kek: &[u8; 32], key: &[u8; 32]) -> [u8; WRAPPED_LEN] {
    let kw = KwAes256::new_from_slice(kek).expect("32-byte KEK");
    let mut out = [0u8; WRAPPED_LEN];
    kw.wrap_key(key, &mut out).expect("output buffer sized for 32-byte key");
    out
}

pub fn unwrap_key(kek: &[u8; 32], wrapped: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    if wrapped.len() != WRAPPED_LEN {
        return Err(CoreError::AuthenticationFailed(format!("wrapped key must be {WRAPPED_LEN} bytes, got {}", wrapped.len())));
    }
    let kw = KwAes256::new_from_slice(kek).expect("32-byte KEK");
    let mut out = Zeroizing::new([0u8; 32]);
    kw.unwrap_key(wrapped, out.as_mut())
        .map_err(|_| CoreError::AuthenticationFailed("key unwrap integrity check failed".into()))?;
    Ok(out)
}
```

```rust
// crates/cryptomator-core/src/crypto/mod.rs
pub mod kdf;
pub mod keywrap;
pub mod masterkey;
pub mod rng;
```

Falls `aes_kw::cipher::KeyInit` nicht existiert: `use aes_kw::KeyInit;` bzw. den Pfad mit `grep -rn "pub use" ~/.cargo/registry/src/*/aes-kw-0.3.1/src/lib.rs` nachschlagen (im Kompiliertest vom 2026-09-04 funktionierte `KwAes256::new_from_slice` mit `use aes_gcm::aead::KeyInit` im Scope; jeder Re-Export des `crypto_common::KeyInit`-Traits genügt).

- [ ] **Step 4: Tests laufen lassen**

Run: `cargo test -p cryptomator-core kdf keywrap`
Expected: PASS (7 Tests)

- [ ] **Step 5: Commit**

```bash
git add crates/cryptomator-core
git commit -m "Add scrypt KEK derivation and RFC 3394 key wrap

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 6: `masterkey.cryptomator` lesen, entsperren, schreiben, Passwort ändern

**Files:**
- Create: `crates/cryptomator-core/src/masterkey_file.rs`
- Modify: `crates/cryptomator-core/src/lib.rs`

**Interfaces:**
- Consumes: `kdf::scrypt_kek`, `keywrap::{wrap_key, unwrap_key}`, `Masterkey`, `Rng`.
- Produces: `MasterkeyFile` (serde, Felder wie Java), `MasterkeyFileAccess::new(pepper: Vec<u8>)`, `MasterkeyFileAccess::{load(&Path, &str) -> Result<Masterkey>, load_bytes(&[u8], &str), unlock(&MasterkeyFile, &str), lock(&Masterkey, &str, vault_version: u32, cost_param: u32, &mut dyn Rng) -> Result<MasterkeyFile>, persist(&Masterkey, &Path, &str, vault_version: u32, &mut dyn Rng) -> Result<()>, persist_bytes(...) -> Result<Vec<u8>>, change_passphrase(&[u8], old: &str, new: &str, &mut dyn Rng) -> Result<Vec<u8>>, read_alleged_vault_version(&[u8]) -> Result<u32>}`; Konstanten `DEFAULT_MASTERKEY_FILE_VERSION = 999`, `DEFAULT_SCRYPT_COST_PARAM = 32768`, `DEFAULT_SCRYPT_BLOCK_SIZE = 8`, `DEFAULT_SCRYPT_SALT_LENGTH = 8`.

- [ ] **Step 1: Fehlschlagende Tests schreiben**

```rust
// am Ende von crates/cryptomator-core/src/masterkey_file.rs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rng::DetRng;

    const PASSPHRASE: &str = "test-password-123";

    /// Written by cryptolib 2.2.2 `MasterkeyFileAccess.persist(masterkey 00..3f, out, "test-password-123", 999, 1024)`
    /// with the deterministic RNG at counter 8 (salt a8..af).
    const JAVA_FILE_N1024: &str = "{\n  \"version\": 999,\n  \"scryptSalt\": \"qKmqq6ytrq8=\",\n  \"scryptCostParam\": 1024,\n  \"scryptBlockSize\": 8,\n  \"primaryMasterKey\": \"LA//cCFKBRjcCgISzMSIjL0Fn2YQATOR/IVnzFFkaOx24s0tLAXCEw==\",\n  \"hmacMasterKey\": \"E1kytsBb50pNsNR2Oh0a/bQFJ7fozm9WK571i2SfVKRw0m/p0cR9Ew==\",\n  \"versionMac\": \"te38NaywQwzDL8JpI/7fH4rBjoqfEz4JpdlYujCZlz8=\"\n}";

    /// Same masterkey and passphrase, default cost 32768, RNG at counter 0 (salt a0..a7).
    const JAVA_FILE_DEFAULT: &str = "{\n  \"version\": 999,\n  \"scryptSalt\": \"oKGio6Slpqc=\",\n  \"scryptCostParam\": 32768,\n  \"scryptBlockSize\": 8,\n  \"primaryMasterKey\": \"HF3Q2cbpzZVISNl7oZ7XSwt3RAIcWNXco3Vs4LEJFqC1m0153R2tAQ==\",\n  \"hmacMasterKey\": \"kWEWMRWW1WZb43j0RF5AYFN9G43uDEo8Pq8xYmv8W3eU9x0SBpnu7A==\",\n  \"versionMac\": \"te38NaywQwzDL8JpI/7fH4rBjoqfEz4JpdlYujCZlz8=\"\n}";

    fn sequential_key() -> Masterkey {
        let mut raw = [0u8; 64];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = i as u8;
        }
        Masterkey::from_raw(raw)
    }

    #[test]
    fn parses_java_file() {
        let file = MasterkeyFile::parse(JAVA_FILE_N1024.as_bytes()).unwrap();
        assert_eq!(file.version, 999);
        assert_eq!(file.scrypt_salt, vec![0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf]);
        assert_eq!(file.scrypt_cost_param, 1024);
        assert_eq!(file.scrypt_block_size, 8);
        assert_eq!(file.primary_master_key.len(), 40);
        assert!(file.is_valid());
    }

    #[test]
    fn unlocks_java_file_with_correct_passphrase() {
        let access = MasterkeyFileAccess::new(Vec::new());
        let key = access.load_bytes(JAVA_FILE_N1024.as_bytes(), PASSPHRASE).unwrap();
        assert_eq!(key.raw(), sequential_key().raw());
    }

    #[test]
    fn wrong_passphrase_is_reported_as_invalid_passphrase() {
        let access = MasterkeyFileAccess::new(Vec::new());
        assert!(matches!(access.load_bytes(JAVA_FILE_N1024.as_bytes(), "wrong"), Err(CoreError::InvalidPassphrase)));
    }

    #[test]
    fn persist_bytes_is_byte_identical_to_java_output() {
        let access = MasterkeyFileAccess::new(Vec::new());
        let bytes = access.persist_bytes(&sequential_key(), PASSPHRASE, 999, 1024, &mut DetRng::starting_at(8)).unwrap();
        assert_eq!(String::from_utf8(bytes).unwrap(), JAVA_FILE_N1024);
    }

    #[test]
    fn persist_with_default_cost_matches_java() {
        let access = MasterkeyFileAccess::new(Vec::new());
        let bytes = access.persist_bytes(&sequential_key(), PASSPHRASE, DEFAULT_MASTERKEY_FILE_VERSION, DEFAULT_SCRYPT_COST_PARAM, &mut DetRng::default()).unwrap();
        assert_eq!(String::from_utf8(bytes).unwrap(), JAVA_FILE_DEFAULT);
    }

    #[test]
    fn read_alleged_vault_version_reads_version_field() {
        assert_eq!(MasterkeyFileAccess::read_alleged_vault_version(JAVA_FILE_N1024.as_bytes()).unwrap(), 999);
    }

    #[test]
    fn invalid_json_is_invalid_masterkey_file() {
        assert!(matches!(MasterkeyFile::parse(b"{\"version\": 7}"), Err(CoreError::InvalidMasterkeyFile(_))));
        assert!(matches!(MasterkeyFile::parse(b"not json"), Err(CoreError::InvalidMasterkeyFile(_))));
    }

    #[test]
    fn change_passphrase_keeps_key_version_and_cost() {
        let access = MasterkeyFileAccess::new(Vec::new());
        let changed = access.change_passphrase(JAVA_FILE_N1024.as_bytes(), PASSPHRASE, "new-pass", &mut DetRng::default()).unwrap();
        let file = MasterkeyFile::parse(&changed).unwrap();
        assert_eq!(file.scrypt_cost_param, 1024);
        assert_eq!(file.version, 999);
        assert_eq!(access.load_bytes(&changed, "new-pass").unwrap().raw(), sequential_key().raw());
        assert!(matches!(access.load_bytes(&changed, PASSPHRASE), Err(CoreError::InvalidPassphrase)));
    }

    #[test]
    fn persist_writes_via_tmp_file_and_replaces_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("masterkey.cryptomator");
        std::fs::write(&path, b"old").unwrap();
        let access = MasterkeyFileAccess::new(Vec::new());
        access.persist(&sequential_key(), &path, PASSPHRASE, 999, &mut DetRng::default()).unwrap();
        assert!(!dir.path().join("masterkey.cryptomator.tmp").exists());
        let key = access.load(&path, PASSPHRASE).unwrap();
        assert_eq!(key.raw(), sequential_key().raw());
    }
}
```

- [ ] **Step 2: Tests laufen lassen, Fehlschlag bestätigen**

Run: `cargo test -p cryptomator-core masterkey_file`
Expected: FAIL (Modul fehlt)

- [ ] **Step 3: Implementieren**

```rust
// crates/cryptomator-core/src/masterkey_file.rs
//! `masterkey.cryptomator` (`common/MasterkeyFile.java`, `common/MasterkeyFileAccess.java`).
use crate::crypto::kdf::scrypt_kek;
use crate::crypto::keywrap::{unwrap_key, wrap_key};
use crate::crypto::masterkey::Masterkey;
use crate::crypto::rng::Rng;
use crate::error::{CoreError, Result};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::Path;

pub const DEFAULT_MASTERKEY_FILE_VERSION: u32 = 999;
pub const DEFAULT_SCRYPT_SALT_LENGTH: usize = 8;
pub const DEFAULT_SCRYPT_COST_PARAM: u32 = 1 << 15;
pub const DEFAULT_SCRYPT_BLOCK_SIZE: u32 = 8;

mod base64_bytes {
    use data_encoding::BASE64;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> std::result::Result<S::Ok, S::Error> {
        BASE64.encode(bytes).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        BASE64.decode(text.as_bytes()).map_err(serde::de::Error::custom)
    }
}

/// JSON schema of the masterkey file. Field order matches Gson's output so re-serialization is byte-identical.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MasterkeyFile {
    pub version: u32,
    #[serde(rename = "scryptSalt", with = "base64_bytes")]
    pub scrypt_salt: Vec<u8>,
    #[serde(rename = "scryptCostParam")]
    pub scrypt_cost_param: u32,
    #[serde(rename = "scryptBlockSize")]
    pub scrypt_block_size: u32,
    #[serde(rename = "primaryMasterKey", with = "base64_bytes")]
    pub primary_master_key: Vec<u8>,
    #[serde(rename = "hmacMasterKey", with = "base64_bytes")]
    pub hmac_master_key: Vec<u8>,
    #[serde(rename = "versionMac", with = "base64_bytes")]
    pub version_mac: Vec<u8>,
}

impl MasterkeyFile {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(|e| CoreError::InvalidMasterkeyFile(format!("unreadable JSON: {e}")))
    }

    /// Pretty-printed JSON, identical to Gson's `setPrettyPrinting()` output (2-space indent, no trailing newline).
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("MasterkeyFile serializes")
    }

    pub fn is_valid(&self) -> bool {
        self.version != 0
            && self.scrypt_cost_param > 1
            && self.scrypt_block_size > 0
            && !self.primary_master_key.is_empty()
            && !self.hmac_master_key.is_empty()
            && !self.version_mac.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct MasterkeyFileAccess {
    pepper: Vec<u8>,
}

impl MasterkeyFileAccess {
    pub fn new(pepper: Vec<u8>) -> Self {
        Self { pepper }
    }

    pub fn read_alleged_vault_version(bytes: &[u8]) -> Result<u32> {
        Ok(MasterkeyFile::parse(bytes)?.version)
    }

    pub fn load(&self, path: &Path, passphrase: &str) -> Result<Masterkey> {
        let bytes = std::fs::read(path)?;
        self.load_bytes(&bytes, passphrase)
    }

    pub fn load_bytes(&self, bytes: &[u8], passphrase: &str) -> Result<Masterkey> {
        let file = MasterkeyFile::parse(bytes)?;
        if !file.is_valid() {
            return Err(CoreError::InvalidMasterkeyFile("invalid key file".into()));
        }
        self.unlock(&file, passphrase)
    }

    pub fn unlock(&self, file: &MasterkeyFile, passphrase: &str) -> Result<Masterkey> {
        let kek = scrypt_kek(passphrase, &file.scrypt_salt, &self.pepper, file.scrypt_cost_param, file.scrypt_block_size)?;
        let enc_key = unwrap_key(&kek, &file.primary_master_key).map_err(|_| CoreError::InvalidPassphrase)?;
        let mac_key = unwrap_key(&kek, &file.hmac_master_key).map_err(|_| CoreError::InvalidPassphrase)?;
        Ok(Masterkey::from_parts(&enc_key, &mac_key))
    }

    pub fn lock(&self, masterkey: &Masterkey, passphrase: &str, vault_version: u32, cost_param: u32, rng: &mut dyn Rng) -> Result<MasterkeyFile> {
        let mut salt = vec![0u8; DEFAULT_SCRYPT_SALT_LENGTH];
        rng.fill(&mut salt);
        let kek = scrypt_kek(passphrase, &salt, &self.pepper, cost_param, DEFAULT_SCRYPT_BLOCK_SIZE)?;
        let mut mac = Hmac::<Sha256>::new_from_slice(masterkey.mac_key()).expect("HMAC accepts any key length");
        mac.update(&vault_version.to_be_bytes());
        let version_mac = mac.finalize().into_bytes().to_vec();
        Ok(MasterkeyFile {
            version: vault_version,
            scrypt_salt: salt,
            scrypt_cost_param: cost_param,
            scrypt_block_size: DEFAULT_SCRYPT_BLOCK_SIZE,
            primary_master_key: wrap_key(&kek, masterkey.enc_key()).to_vec(),
            hmac_master_key: wrap_key(&kek, masterkey.mac_key()).to_vec(),
            version_mac,
        })
    }

    pub fn persist_bytes(&self, masterkey: &Masterkey, passphrase: &str, vault_version: u32, cost_param: u32, rng: &mut dyn Rng) -> Result<Vec<u8>> {
        Ok(self.lock(masterkey, passphrase, vault_version, cost_param, rng)?.to_json().into_bytes())
    }

    /// Writes `<path>.tmp` (must not exist) and atomically renames it over `path`.
    pub fn persist(&self, masterkey: &Masterkey, path: &Path, passphrase: &str, vault_version: u32, rng: &mut dyn Rng) -> Result<()> {
        let bytes = self.persist_bytes(masterkey, passphrase, vault_version, DEFAULT_SCRYPT_COST_PARAM, rng)?;
        let file_name = path.file_name().and_then(|n| n.to_str()).ok_or_else(|| CoreError::InvalidArgument(format!("not a file path: {}", path.display())))?;
        let tmp_path = path.with_file_name(format!("{file_name}.tmp"));
        {
            use std::io::Write;
            let mut tmp = std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp_path)?;
            tmp.write_all(&bytes)?;
            tmp.sync_all()?;
        }
        std::fs::rename(&tmp_path, path)?;
        Ok(())
    }

    pub fn change_passphrase(&self, bytes: &[u8], old_passphrase: &str, new_passphrase: &str, rng: &mut dyn Rng) -> Result<Vec<u8>> {
        let original = MasterkeyFile::parse(bytes)?;
        if !original.is_valid() {
            return Err(CoreError::InvalidMasterkeyFile("invalid key file".into()));
        }
        let key = self.unlock(&original, old_passphrase)?;
        let updated = self.lock(&key, new_passphrase, original.version, original.scrypt_cost_param, rng)?;
        Ok(updated.to_json().into_bytes())
    }
}
```

In `lib.rs` ergänzen: `pub mod masterkey_file;` und `pub use masterkey_file::{MasterkeyFile, MasterkeyFileAccess};`.

- [ ] **Step 4: Tests laufen lassen**

Run: `cargo test -p cryptomator-core masterkey_file`
Expected: PASS (9 Tests; `persist_with_default_cost_matches_java` braucht wegen N=32768 etwa 0,2 s)

- [ ] **Step 5: Commit**

```bash
git add crates/cryptomator-core
git commit -m "Add masterkey.cryptomator parsing, unlock, persist and passphrase change

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 7: Dateinamen-Verschlüsselung und Verzeichnis-ID-Hash (AES-SIV)

**Files:**
- Create: `crates/cryptomator-core/src/crypto/siv.rs`
- Modify: `crates/cryptomator-core/src/crypto/mod.rs`

**Interfaces:**
- Consumes: `Masterkey`.
- Produces: `FileNameCryptor::new(&Masterkey)`, `hash_directory_id(&self, dir_id: &str) -> String` (BASE32, 32 Zeichen), `encrypt_filename(&self, cleartext: &str, associated_data: &[&[u8]]) -> String` (base64url mit Padding, ohne `.c9r`), `decrypt_filename(&self, ciphertext: &str, associated_data: &[&[u8]]) -> Result<String>` (Fehler `AuthenticationFailed`).

- [ ] **Step 1: Fehlschlagende Tests schreiben**

```rust
// am Ende von crates/cryptomator-core/src/crypto/siv.rs
#[cfg(test)]
mod tests {
    use super::*;

    const DIR_ID: &str = "2f3a8f2e-0b8a-4e6f-9c5d-1a2b3c4d5e6f";

    fn cryptor() -> FileNameCryptor {
        let mut raw = [0u8; 64];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = i as u8;
        }
        FileNameCryptor::new(&Masterkey::from_raw(raw))
    }

    // Vectors from cryptolib 2.2.2 FileNameCryptorImpl (identical for SIV_CTRMAC and SIV_GCM).
    #[test]
    fn hashes_root_directory_id() {
        assert_eq!(cryptor().hash_directory_id(""), "MN53XCQH5RFQJPKAFCMWDGELQHPPW2YQ");
    }

    #[test]
    fn hashes_uuid_directory_id() {
        assert_eq!(cryptor().hash_directory_id(DIR_ID), "CMKXWDS23EJDGI6W6QGYTCABGFDYURNB");
    }

    #[test]
    fn encrypts_filename_in_root_directory() {
        assert_eq!(cryptor().encrypt_filename("hello.txt", &[b""]), "9ovGh03FYi0-jGCbRkIA80k29tJKo9BfgA==");
    }

    #[test]
    fn encrypts_unicode_filename_with_directory_id_as_associated_data() {
        assert_eq!(cryptor().encrypt_filename("Grüße 🚀.txt", &[DIR_ID.as_bytes()]), "ATbLUpvuQpUbOMmcUnUNBnNuMYP-j40I9efry_VkIiU=");
    }

    #[test]
    fn decrypts_filenames() {
        let c = cryptor();
        assert_eq!(c.decrypt_filename("9ovGh03FYi0-jGCbRkIA80k29tJKo9BfgA==", &[b""]).unwrap(), "hello.txt");
        assert_eq!(c.decrypt_filename("ATbLUpvuQpUbOMmcUnUNBnNuMYP-j40I9efry_VkIiU=", &[DIR_ID.as_bytes()]).unwrap(), "Grüße 🚀.txt");
    }

    #[test]
    fn wrong_associated_data_fails_authentication() {
        let c = cryptor();
        assert!(matches!(c.decrypt_filename("9ovGh03FYi0-jGCbRkIA80k29tJKo9BfgA==", &[DIR_ID.as_bytes()]), Err(CoreError::AuthenticationFailed(_))));
    }

    #[test]
    fn invalid_base64_fails_authentication() {
        assert!(matches!(cryptor().decrypt_filename("not*base64", &[b""]), Err(CoreError::AuthenticationFailed(_))));
    }

    #[test]
    fn encryption_is_deterministic_and_round_trips() {
        let c = cryptor();
        let name = "some file (1).pdf";
        let ct = c.encrypt_filename(name, &[DIR_ID.as_bytes()]);
        assert_eq!(ct, c.encrypt_filename(name, &[DIR_ID.as_bytes()]));
        assert_eq!(c.decrypt_filename(&ct, &[DIR_ID.as_bytes()]).unwrap(), name);
    }
}
```

- [ ] **Step 2: Tests laufen lassen, Fehlschlag bestätigen**

Run: `cargo test -p cryptomator-core siv`
Expected: FAIL (Modul fehlt)

- [ ] **Step 3: Implementieren**

```rust
// crates/cryptomator-core/src/crypto/siv.rs
//! Filename encryption (`v2/FileNameCryptorImpl.java`, RFC 5297 AES-SIV via siv-mode).
//! cryptolib calls `siv.encrypt(encKey, macKey, ...)` where the first key is the CTR key and the
//! second the S2V key. RustCrypto expects `S2V key || CTR key`, hence the key is `macKey || encKey`.
use crate::crypto::masterkey::Masterkey;
use crate::error::{CoreError, Result};
use aes_siv::aead::KeyInit;
use aes_siv::siv::Aes256Siv;
use data_encoding::{BASE32, BASE64URL};
use sha1::{Digest, Sha1};
use zeroize::Zeroizing;

pub struct FileNameCryptor {
    /// `macKey || encKey`
    siv_key: Zeroizing<[u8; 64]>,
}

impl std::fmt::Debug for FileNameCryptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FileNameCryptor(<redacted>)")
    }
}

impl FileNameCryptor {
    pub fn new(masterkey: &Masterkey) -> Self {
        let mut siv_key = Zeroizing::new([0u8; 64]);
        siv_key[..32].copy_from_slice(masterkey.mac_key());
        siv_key[32..].copy_from_slice(masterkey.enc_key());
        Self { siv_key }
    }

    fn siv(&self) -> Aes256Siv {
        Aes256Siv::new((&*self.siv_key).into())
    }

    /// `BASE32(SHA1(AES-SIV(dirId)))` – the ciphertext directory name; root uses `""`.
    pub fn hash_directory_id(&self, cleartext_directory_id: &str) -> String {
        let encrypted = self
            .siv()
            .encrypt(std::iter::empty::<&[u8]>(), cleartext_directory_id.as_bytes())
            .expect("directory id fits in memory");
        BASE32.encode(&Sha1::digest(&encrypted))
    }

    pub fn encrypt_filename(&self, cleartext_name: &str, associated_data: &[&[u8]]) -> String {
        let encrypted = self
            .siv()
            .encrypt(associated_data.iter().copied(), cleartext_name.as_bytes())
            .expect("file name fits in memory");
        BASE64URL.encode(&encrypted)
    }

    pub fn decrypt_filename(&self, ciphertext_name: &str, associated_data: &[&[u8]]) -> Result<String> {
        let encrypted = BASE64URL
            .decode(ciphertext_name.as_bytes())
            .map_err(|_| CoreError::AuthenticationFailed("Invalid Ciphertext.".into()))?;
        let cleartext = self
            .siv()
            .decrypt(associated_data.iter().copied(), &encrypted)
            .map_err(|_| CoreError::AuthenticationFailed("Invalid Ciphertext.".into()))?;
        String::from_utf8(cleartext).map_err(|_| CoreError::AuthenticationFailed("Invalid Ciphertext.".into()))
    }
}
```

In `crypto/mod.rs` ergänzen: `pub mod siv;`.

- [ ] **Step 4: Tests laufen lassen**

Run: `cargo test -p cryptomator-core siv`
Expected: PASS (8 Tests)

- [ ] **Step 5: Commit**

```bash
git add crates/cryptomator-core
git commit -m "Add AES-SIV filename encryption and directory id hashing

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 8: Datei-Header und Inhalts-Chunks für SIV_GCM

**Files:**
- Create: `crates/cryptomator-core/src/crypto/header.rs`, `src/crypto/gcm.rs`
- Modify: `crates/cryptomator-core/src/crypto/mod.rs`

**Interfaces:**
- Consumes: `Masterkey`, `Rng`.
- Produces: `FileHeader::{new(nonce: Vec<u8>, reserved: i64, content_key: [u8;32]), nonce() -> &[u8], reserved() -> i64, content_key() -> &[u8;32], encode_payload() -> Zeroizing<[u8;40]>, decode_payload(nonce: Vec<u8>, payload: &[u8]) -> Result<FileHeader>}`; `gcm::{GCM_NONCE_SIZE=12, PAYLOAD_SIZE=32768, GCM_TAG_SIZE=16, CHUNK_SIZE=32796, HEADER_SIZE=68}`; `GcmHeaderCryptor::new(&Masterkey)` mit `create(&mut dyn Rng) -> FileHeader`, `header_size() -> usize`, `encrypt_header(&FileHeader) -> Vec<u8>`, `decrypt_header(&[u8]) -> Result<FileHeader>`; `GcmContentCryptor` (unit struct) mit `cleartext_chunk_size()`, `ciphertext_chunk_size()`, `encrypt_chunk(cleartext: &[u8], chunk_number: u64, header: &FileHeader, rng: &mut dyn Rng) -> Vec<u8>`, `decrypt_chunk(ciphertext: &[u8], chunk_number: u64, header: &FileHeader) -> Result<Vec<u8>>`.

- [ ] **Step 1: Fehlschlagende Tests schreiben**

```rust
// am Ende von crates/cryptomator-core/src/crypto/gcm.rs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rng::DetRng;
    use data_encoding::HEXLOWER;
    use sha2::{Digest, Sha256};

    // cryptolib 2.2.2 v2.CryptorImpl(masterkey 00..3f, DetRandom): header create() draws 12-byte nonce (a0..ab)
    // then 32-byte content key (ac..cb); each encryptChunk draws a fresh 12-byte nonce.
    const ENC_HEADER: &str = "a0a1a2a3a4a5a6a7a8a9aaab19e783d2ba34fd40cec8297cb7cb726dc419efa72a0ef8d720b39839bf6ab7c216b3813867eb99f6a8d57bbc501ceb787b03fa91363626a6";
    const CHUNK0_HELLO_WORLD: &str = "cccdcecfd0d1d2d3d4d5d6d7f8dc799de0dfabbf41fe6f59efd689d8af72ab071b366dcabdff36";
    const CHUNK1_EMPTY: &str = "d8d9dadbdcdddedfa0a1a2a389d46c02b523fb8a3877bbf295d9547a";
    const CHUNK7_FULL_SHA256: &str = "d2455024dcaf35935ed35ef3bb040eb9c5d3b3492a415a4bfecbc9e6d8f8f93e";

    fn masterkey() -> Masterkey {
        let mut raw = [0u8; 64];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = i as u8;
        }
        Masterkey::from_raw(raw)
    }

    fn hex(s: &str) -> Vec<u8> {
        HEXLOWER.decode(s.as_bytes()).unwrap()
    }

    fn full_chunk() -> Vec<u8> {
        (0..PAYLOAD_SIZE).map(|i| (i * 7) as u8).collect()
    }

    #[test]
    fn created_header_uses_rng_for_nonce_and_content_key() {
        let hc = GcmHeaderCryptor::new(&masterkey());
        let header = hc.create(&mut DetRng::default());
        assert_eq!(header.nonce(), &hex("a0a1a2a3a4a5a6a7a8a9aaab")[..]);
        assert_eq!(header.content_key()[0], 0xac);
        assert_eq!(header.content_key()[31], 0xcb);
        assert_eq!(header.reserved(), -1);
        assert_eq!(hc.header_size(), 68);
    }

    #[test]
    fn encrypts_header_like_java() {
        let hc = GcmHeaderCryptor::new(&masterkey());
        let header = hc.create(&mut DetRng::default());
        assert_eq!(HEXLOWER.encode(&hc.encrypt_header(&header)), ENC_HEADER);
    }

    #[test]
    fn decrypts_java_header() {
        let hc = GcmHeaderCryptor::new(&masterkey());
        let header = hc.decrypt_header(&hex(ENC_HEADER)).unwrap();
        assert_eq!(header.nonce(), &hex("a0a1a2a3a4a5a6a7a8a9aaab")[..]);
        assert_eq!(header.content_key()[0], 0xac);
        assert_eq!(header.reserved(), -1);
    }

    #[test]
    fn tampered_header_fails_authentication() {
        let hc = GcmHeaderCryptor::new(&masterkey());
        let mut bytes = hex(ENC_HEADER);
        bytes[20] ^= 1;
        assert!(matches!(hc.decrypt_header(&bytes), Err(CoreError::AuthenticationFailed(_))));
        assert!(matches!(hc.decrypt_header(&bytes[..67]), Err(CoreError::InvalidArgument(_))));
    }

    #[test]
    fn encrypts_chunks_like_java() {
        let hc = GcmHeaderCryptor::new(&masterkey());
        let mut rng = DetRng::default();
        let header = hc.create(&mut rng);
        let cc = GcmContentCryptor;
        assert_eq!(HEXLOWER.encode(&cc.encrypt_chunk(b"hello world", 0, &header, &mut rng)), CHUNK0_HELLO_WORLD);
        assert_eq!(HEXLOWER.encode(&cc.encrypt_chunk(b"", 1, &header, &mut rng)), CHUNK1_EMPTY);
        let chunk7 = cc.encrypt_chunk(&full_chunk(), 7, &header, &mut rng);
        assert_eq!(chunk7.len(), CHUNK_SIZE);
        assert_eq!(HEXLOWER.encode(&Sha256::digest(&chunk7)), CHUNK7_FULL_SHA256);
    }

    #[test]
    fn decrypts_java_chunks() {
        let hc = GcmHeaderCryptor::new(&masterkey());
        let header = hc.decrypt_header(&hex(ENC_HEADER)).unwrap();
        let cc = GcmContentCryptor;
        assert_eq!(cc.decrypt_chunk(&hex(CHUNK0_HELLO_WORLD), 0, &header).unwrap(), b"hello world");
        assert_eq!(cc.decrypt_chunk(&hex(CHUNK1_EMPTY), 1, &header).unwrap(), b"");
    }

    #[test]
    fn wrong_chunk_number_or_tampering_fails_authentication() {
        let hc = GcmHeaderCryptor::new(&masterkey());
        let header = hc.decrypt_header(&hex(ENC_HEADER)).unwrap();
        let cc = GcmContentCryptor;
        assert!(matches!(cc.decrypt_chunk(&hex(CHUNK0_HELLO_WORLD), 1, &header), Err(CoreError::AuthenticationFailed(_))));
        let mut tampered = hex(CHUNK0_HELLO_WORLD);
        tampered[15] ^= 1;
        assert!(matches!(cc.decrypt_chunk(&tampered, 0, &header), Err(CoreError::AuthenticationFailed(_))));
        assert!(matches!(cc.decrypt_chunk(&[0u8; 27], 0, &header), Err(CoreError::InvalidArgument(_))));
    }

    #[test]
    fn full_chunk_round_trips() {
        let hc = GcmHeaderCryptor::new(&masterkey());
        let mut rng = DetRng::default();
        let header = hc.create(&mut rng);
        let cc = GcmContentCryptor;
        let ct = cc.encrypt_chunk(&full_chunk(), 42, &header, &mut rng);
        assert_eq!(cc.decrypt_chunk(&ct, 42, &header).unwrap(), full_chunk());
    }
}
```

- [ ] **Step 2: Tests laufen lassen, Fehlschlag bestätigen**

Run: `cargo test -p cryptomator-core gcm`
Expected: FAIL (Module fehlen)

- [ ] **Step 3: Implementieren**

```rust
// crates/cryptomator-core/src/crypto/header.rs
//! Cleartext file header (`v1/FileHeaderImpl.java`, `v2/FileHeaderImpl.java`): nonce + payload(reserved i64, content key).
use crate::error::{CoreError, Result};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const CONTENT_KEY_LEN: usize = 32;
pub const RESERVED_LEN: usize = 8;
pub const PAYLOAD_LEN: usize = RESERVED_LEN + CONTENT_KEY_LEN;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct FileHeader {
    nonce: Vec<u8>,
    reserved: i64,
    content_key: [u8; CONTENT_KEY_LEN],
}

impl std::fmt::Debug for FileHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileHeader").field("nonce_len", &self.nonce.len()).field("reserved", &self.reserved).finish_non_exhaustive()
    }
}

impl FileHeader {
    pub fn new(nonce: Vec<u8>, reserved: i64, content_key: [u8; CONTENT_KEY_LEN]) -> Self {
        Self { nonce, reserved, content_key }
    }

    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    pub fn reserved(&self) -> i64 {
        self.reserved
    }

    pub fn content_key(&self) -> &[u8; CONTENT_KEY_LEN] {
        &self.content_key
    }

    /// `BE-int64(reserved) || contentKey`
    pub fn encode_payload(&self) -> Zeroizing<[u8; PAYLOAD_LEN]> {
        let mut out = Zeroizing::new([0u8; PAYLOAD_LEN]);
        out[..RESERVED_LEN].copy_from_slice(&self.reserved.to_be_bytes());
        out[RESERVED_LEN..].copy_from_slice(&self.content_key);
        out
    }

    pub fn decode_payload(nonce: Vec<u8>, payload: &[u8]) -> Result<Self> {
        if payload.len() != PAYLOAD_LEN {
            return Err(CoreError::InvalidArgument(format!("invalid payload buffer length {}", payload.len())));
        }
        let reserved = i64::from_be_bytes(payload[..RESERVED_LEN].try_into().expect("8 bytes"));
        let mut content_key = [0u8; CONTENT_KEY_LEN];
        content_key.copy_from_slice(&payload[RESERVED_LEN..]);
        Ok(Self { nonce, reserved, content_key })
    }
}
```

```rust
// crates/cryptomator-core/src/crypto/gcm.rs
//! SIV_GCM content encryption (`v2/FileHeaderCryptorImpl.java`, `v2/FileContentCryptorImpl.java`, `v2/Constants.java`).
use crate::crypto::header::{FileHeader, CONTENT_KEY_LEN, PAYLOAD_LEN};
use crate::crypto::masterkey::Masterkey;
use crate::crypto::rng::Rng;
use crate::error::{CoreError, Result};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use zeroize::Zeroizing;

pub const GCM_NONCE_SIZE: usize = 12;
pub const PAYLOAD_SIZE: usize = 32 * 1024;
pub const GCM_TAG_SIZE: usize = 16;
pub const CHUNK_SIZE: usize = GCM_NONCE_SIZE + PAYLOAD_SIZE + GCM_TAG_SIZE;
pub const HEADER_SIZE: usize = GCM_NONCE_SIZE + PAYLOAD_LEN + GCM_TAG_SIZE;

fn nonce(bytes: &[u8]) -> Nonce {
    Nonce::try_from(bytes).expect("12-byte nonce")
}

pub struct GcmHeaderCryptor {
    enc_key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for GcmHeaderCryptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GcmHeaderCryptor(<redacted>)")
    }
}

impl GcmHeaderCryptor {
    pub fn new(masterkey: &Masterkey) -> Self {
        Self { enc_key: Zeroizing::new(*masterkey.enc_key()) }
    }

    pub fn create(&self, rng: &mut dyn Rng) -> FileHeader {
        let mut nonce = vec![0u8; GCM_NONCE_SIZE];
        rng.fill(&mut nonce);
        let mut content_key = [0u8; CONTENT_KEY_LEN];
        rng.fill(&mut content_key);
        FileHeader::new(nonce, -1, content_key)
    }

    pub fn header_size(&self) -> usize {
        HEADER_SIZE
    }

    pub fn encrypt_header(&self, header: &FileHeader) -> Vec<u8> {
        let cipher = Aes256Gcm::new_from_slice(&*self.enc_key).expect("32-byte key");
        let payload = header.encode_payload();
        let ciphertext_and_tag = cipher.encrypt(&nonce(header.nonce()), Payload { msg: &*payload, aad: b"" }).expect("GCM encryption");
        let mut out = Vec::with_capacity(HEADER_SIZE);
        out.extend_from_slice(header.nonce());
        out.extend_from_slice(&ciphertext_and_tag);
        out
    }

    pub fn decrypt_header(&self, ciphertext_header: &[u8]) -> Result<FileHeader> {
        if ciphertext_header.len() < HEADER_SIZE {
            return Err(CoreError::InvalidArgument("Malformed ciphertext header".into()));
        }
        let header_nonce = &ciphertext_header[..GCM_NONCE_SIZE];
        let ciphertext_and_tag = &ciphertext_header[GCM_NONCE_SIZE..HEADER_SIZE];
        let cipher = Aes256Gcm::new_from_slice(&*self.enc_key).expect("32-byte key");
        let payload = Zeroizing::new(
            cipher
                .decrypt(&nonce(header_nonce), Payload { msg: ciphertext_and_tag, aad: b"" })
                .map_err(|_| CoreError::AuthenticationFailed("Header tag mismatch.".into()))?,
        );
        FileHeader::decode_payload(header_nonce.to_vec(), &payload)
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct GcmContentCryptor;

impl GcmContentCryptor {
    pub fn cleartext_chunk_size(&self) -> usize {
        PAYLOAD_SIZE
    }

    pub fn ciphertext_chunk_size(&self) -> usize {
        CHUNK_SIZE
    }

    fn aad(chunk_number: u64, header: &FileHeader) -> Vec<u8> {
        let mut aad = Vec::with_capacity(8 + header.nonce().len());
        aad.extend_from_slice(&chunk_number.to_be_bytes());
        aad.extend_from_slice(header.nonce());
        aad
    }

    /// `nonce || AES-GCM(contentKey, nonce, AAD = BE64(chunkNumber) || headerNonce)(cleartext) || tag`
    pub fn encrypt_chunk(&self, cleartext_chunk: &[u8], chunk_number: u64, header: &FileHeader, rng: &mut dyn Rng) -> Vec<u8> {
        assert!(cleartext_chunk.len() <= PAYLOAD_SIZE, "Invalid cleartext chunk size: {}", cleartext_chunk.len());
        let mut chunk_nonce = [0u8; GCM_NONCE_SIZE];
        rng.fill(&mut chunk_nonce);
        let cipher = Aes256Gcm::new_from_slice(header.content_key()).expect("32-byte key");
        let ciphertext_and_tag = cipher
            .encrypt(&nonce(&chunk_nonce), Payload { msg: cleartext_chunk, aad: &Self::aad(chunk_number, header) })
            .expect("GCM encryption");
        let mut out = Vec::with_capacity(GCM_NONCE_SIZE + ciphertext_and_tag.len());
        out.extend_from_slice(&chunk_nonce);
        out.extend_from_slice(&ciphertext_and_tag);
        out
    }

    pub fn decrypt_chunk(&self, ciphertext_chunk: &[u8], chunk_number: u64, header: &FileHeader) -> Result<Vec<u8>> {
        if ciphertext_chunk.len() < GCM_NONCE_SIZE + GCM_TAG_SIZE || ciphertext_chunk.len() > CHUNK_SIZE {
            return Err(CoreError::InvalidArgument(format!(
                "Invalid ciphertext chunk size: {}, expected range [{}, {}]",
                ciphertext_chunk.len(),
                GCM_NONCE_SIZE + GCM_TAG_SIZE,
                CHUNK_SIZE
            )));
        }
        let (chunk_nonce, ciphertext_and_tag) = ciphertext_chunk.split_at(GCM_NONCE_SIZE);
        let cipher = Aes256Gcm::new_from_slice(header.content_key()).expect("32-byte key");
        cipher
            .decrypt(&nonce(chunk_nonce), Payload { msg: ciphertext_and_tag, aad: &Self::aad(chunk_number, header) })
            .map_err(|_| CoreError::AuthenticationFailed("Content tag mismatch.".into()))
    }
}
```

In `crypto/mod.rs` ergänzen: `pub mod gcm;` und `pub mod header;`.

- [ ] **Step 4: Tests laufen lassen**

Run: `cargo test -p cryptomator-core gcm`
Expected: PASS (8 Tests)

- [ ] **Step 5: Commit**

```bash
git add crates/cryptomator-core
git commit -m "Add file header type and SIV_GCM header/content encryption

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 9: Datei-Header und Inhalts-Chunks für SIV_CTRMAC

**Files:**
- Create: `crates/cryptomator-core/src/crypto/ctrmac.rs`
- Modify: `crates/cryptomator-core/src/crypto/mod.rs`

**Interfaces:**
- Consumes: `FileHeader`, `Masterkey`, `Rng`.
- Produces: `ctrmac::{NONCE_SIZE=16, PAYLOAD_SIZE=32768, MAC_SIZE=32, CHUNK_SIZE=32816, HEADER_SIZE=88}`; `CtrMacHeaderCryptor::new(&Masterkey)` und `CtrMacContentCryptor::new(&Masterkey)` mit denselben Methodensignaturen wie die GCM-Typen aus Task 8 (`create`, `header_size`, `encrypt_header`, `decrypt_header`; `cleartext_chunk_size`, `ciphertext_chunk_size`, `encrypt_chunk`, `decrypt_chunk`).

- [ ] **Step 1: Fehlschlagende Tests schreiben**

```rust
// am Ende von crates/cryptomator-core/src/crypto/ctrmac.rs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rng::DetRng;
    use data_encoding::HEXLOWER;
    use sha2::{Digest, Sha256};

    // cryptolib 2.2.2 v1.CryptorImpl(masterkey 00..3f, DetRandom): header nonce a0..af, content key b0..cf,
    // chunk 0 nonce d0..df, chunk 1 nonce a0..af (counter wrapped at 64).
    const ENC_HEADER: &str = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf2360fe02894783f2bffa5a36bfbe5a57596851aac0fc2b972c4b3a49a3f5155851222e6924aa57c5a12c9850de5595b2e1a07a8fb733a48864582784ef3c2c0dd39f245236529acc";
    const CHUNK0_HELLO_WORLD: &str = "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf07bc829afb3ef90b0c483749798b267733ee79939d12d6ddf38ca30e7d6008344a2e2bb3cd8289df268ad4";
    const CHUNK1_EMPTY: &str = "a0a1a2a3a4a5a6a7a8a9aaabacadaeafbce25e58d844216c94d19cc661b42e587eb94d34f0308748c7ba61dffc6b4f34";
    const CHUNK7_FULL_SHA256: &str = "e65c9046e7ff61828986c3d8e47e17cbc7dd623677ee89bfd150cc9a304100fb";

    fn masterkey() -> Masterkey {
        let mut raw = [0u8; 64];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = i as u8;
        }
        Masterkey::from_raw(raw)
    }

    fn hex(s: &str) -> Vec<u8> {
        HEXLOWER.decode(s.as_bytes()).unwrap()
    }

    fn full_chunk() -> Vec<u8> {
        (0..PAYLOAD_SIZE).map(|i| (i * 7) as u8).collect()
    }

    #[test]
    fn encrypts_header_like_java() {
        let hc = CtrMacHeaderCryptor::new(&masterkey());
        let header = hc.create(&mut DetRng::default());
        assert_eq!(header.nonce().len(), 16);
        assert_eq!(hc.header_size(), 88);
        assert_eq!(HEXLOWER.encode(&hc.encrypt_header(&header)), ENC_HEADER);
    }

    #[test]
    fn decrypts_java_header() {
        let hc = CtrMacHeaderCryptor::new(&masterkey());
        let header = hc.decrypt_header(&hex(ENC_HEADER)).unwrap();
        assert_eq!(header.nonce(), &hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")[..]);
        assert_eq!(header.content_key()[0], 0xb0);
        assert_eq!(header.content_key()[31], 0xcf);
        assert_eq!(header.reserved(), -1);
    }

    #[test]
    fn tampered_header_fails_authentication() {
        let hc = CtrMacHeaderCryptor::new(&masterkey());
        let mut bytes = hex(ENC_HEADER);
        bytes[30] ^= 1;
        assert!(matches!(hc.decrypt_header(&bytes), Err(CoreError::AuthenticationFailed(_))));
        assert!(matches!(hc.decrypt_header(&bytes[..87]), Err(CoreError::InvalidArgument(_))));
    }

    #[test]
    fn encrypts_chunks_like_java() {
        let hc = CtrMacHeaderCryptor::new(&masterkey());
        let mut rng = DetRng::default();
        let header = hc.create(&mut rng);
        let cc = CtrMacContentCryptor::new(&masterkey());
        assert_eq!(HEXLOWER.encode(&cc.encrypt_chunk(b"hello world", 0, &header, &mut rng)), CHUNK0_HELLO_WORLD);
        assert_eq!(HEXLOWER.encode(&cc.encrypt_chunk(b"", 1, &header, &mut rng)), CHUNK1_EMPTY);
        let chunk7 = cc.encrypt_chunk(&full_chunk(), 7, &header, &mut rng);
        assert_eq!(chunk7.len(), CHUNK_SIZE);
        assert_eq!(HEXLOWER.encode(&Sha256::digest(&chunk7)), CHUNK7_FULL_SHA256);
    }

    #[test]
    fn decrypts_java_chunks() {
        let hc = CtrMacHeaderCryptor::new(&masterkey());
        let header = hc.decrypt_header(&hex(ENC_HEADER)).unwrap();
        let cc = CtrMacContentCryptor::new(&masterkey());
        assert_eq!(cc.decrypt_chunk(&hex(CHUNK0_HELLO_WORLD), 0, &header).unwrap(), b"hello world");
        assert_eq!(cc.decrypt_chunk(&hex(CHUNK1_EMPTY), 1, &header).unwrap(), b"");
    }

    #[test]
    fn wrong_chunk_number_or_tampering_fails_authentication() {
        let hc = CtrMacHeaderCryptor::new(&masterkey());
        let header = hc.decrypt_header(&hex(ENC_HEADER)).unwrap();
        let cc = CtrMacContentCryptor::new(&masterkey());
        assert!(matches!(cc.decrypt_chunk(&hex(CHUNK0_HELLO_WORLD), 1, &header), Err(CoreError::AuthenticationFailed(_))));
        let mut tampered = hex(CHUNK0_HELLO_WORLD);
        tampered[20] ^= 1;
        assert!(matches!(cc.decrypt_chunk(&tampered, 0, &header), Err(CoreError::AuthenticationFailed(_))));
        assert!(matches!(cc.decrypt_chunk(&[0u8; 47], 0, &header), Err(CoreError::InvalidArgument(_))));
    }

    #[test]
    fn full_chunk_round_trips() {
        let hc = CtrMacHeaderCryptor::new(&masterkey());
        let mut rng = DetRng::default();
        let header = hc.create(&mut rng);
        let cc = CtrMacContentCryptor::new(&masterkey());
        let ct = cc.encrypt_chunk(&full_chunk(), 42, &header, &mut rng);
        assert_eq!(cc.decrypt_chunk(&ct, 42, &header).unwrap(), full_chunk());
    }
}
```

- [ ] **Step 2: Tests laufen lassen, Fehlschlag bestätigen**

Run: `cargo test -p cryptomator-core ctrmac`
Expected: FAIL (Modul fehlt)

- [ ] **Step 3: Implementieren**

```rust
// crates/cryptomator-core/src/crypto/ctrmac.rs
//! SIV_CTRMAC content encryption (`v1/FileHeaderCryptorImpl.java`, `v1/FileContentCryptorImpl.java`, `v1/Constants.java`).
//! AES-CTR with a big-endian 128-bit counter (JCE "AES/CTR/NoPadding") + HMAC-SHA256 with the masterkey's MAC key.
use crate::crypto::header::{FileHeader, CONTENT_KEY_LEN, PAYLOAD_LEN};
use crate::crypto::masterkey::Masterkey;
use crate::crypto::rng::Rng;
use crate::error::{CoreError, Result};
use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

pub const NONCE_SIZE: usize = 16;
pub const PAYLOAD_SIZE: usize = 32 * 1024;
pub const MAC_SIZE: usize = 32;
pub const CHUNK_SIZE: usize = NONCE_SIZE + PAYLOAD_SIZE + MAC_SIZE;
pub const HEADER_SIZE: usize = NONCE_SIZE + PAYLOAD_LEN + MAC_SIZE;

type Aes256Ctr = ctr::Ctr128BE<Aes256>;
type HmacSha256 = Hmac<Sha256>;

fn apply_ctr(key: &[u8; 32], iv: &[u8], data: &mut [u8]) {
    let mut cipher = Aes256Ctr::new_from_slices(key, iv).expect("32-byte key, 16-byte IV");
    cipher.apply_keystream(data);
}

fn hmac(mac_key: &[u8; 32]) -> HmacSha256 {
    HmacSha256::new_from_slice(mac_key).expect("HMAC accepts any key length")
}

pub struct CtrMacHeaderCryptor {
    enc_key: Zeroizing<[u8; 32]>,
    mac_key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for CtrMacHeaderCryptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CtrMacHeaderCryptor(<redacted>)")
    }
}

impl CtrMacHeaderCryptor {
    pub fn new(masterkey: &Masterkey) -> Self {
        Self { enc_key: Zeroizing::new(*masterkey.enc_key()), mac_key: Zeroizing::new(*masterkey.mac_key()) }
    }

    pub fn create(&self, rng: &mut dyn Rng) -> FileHeader {
        let mut nonce = vec![0u8; NONCE_SIZE];
        rng.fill(&mut nonce);
        let mut content_key = [0u8; CONTENT_KEY_LEN];
        rng.fill(&mut content_key);
        FileHeader::new(nonce, -1, content_key)
    }

    pub fn header_size(&self) -> usize {
        HEADER_SIZE
    }

    /// `nonce || AES-CTR(encKey, iv=nonce)(payload) || HMAC-SHA256(macKey, nonce || encryptedPayload)`
    pub fn encrypt_header(&self, header: &FileHeader) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_SIZE);
        out.extend_from_slice(header.nonce());
        let mut payload = header.encode_payload();
        apply_ctr(&self.enc_key, header.nonce(), payload.as_mut());
        out.extend_from_slice(&*payload);
        let mut mac = hmac(&self.mac_key);
        mac.update(&out);
        out.extend_from_slice(&mac.finalize().into_bytes());
        out
    }

    pub fn decrypt_header(&self, ciphertext_header: &[u8]) -> Result<FileHeader> {
        if ciphertext_header.len() < HEADER_SIZE {
            return Err(CoreError::InvalidArgument("Malformed ciphertext header".into()));
        }
        let nonce_and_payload = &ciphertext_header[..NONCE_SIZE + PAYLOAD_LEN];
        let expected_mac = &ciphertext_header[NONCE_SIZE + PAYLOAD_LEN..HEADER_SIZE];
        let mut mac = hmac(&self.mac_key);
        mac.update(nonce_and_payload);
        mac.verify_slice(expected_mac).map_err(|_| CoreError::AuthenticationFailed("Header MAC doesn't match.".into()))?;
        let nonce = &ciphertext_header[..NONCE_SIZE];
        let mut payload = Zeroizing::new(ciphertext_header[NONCE_SIZE..NONCE_SIZE + PAYLOAD_LEN].to_vec());
        apply_ctr(&self.enc_key, nonce, payload.as_mut_slice());
        FileHeader::decode_payload(nonce.to_vec(), &payload)
    }
}

pub struct CtrMacContentCryptor {
    mac_key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for CtrMacContentCryptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CtrMacContentCryptor(<redacted>)")
    }
}

impl CtrMacContentCryptor {
    pub fn new(masterkey: &Masterkey) -> Self {
        Self { mac_key: Zeroizing::new(*masterkey.mac_key()) }
    }

    pub fn cleartext_chunk_size(&self) -> usize {
        PAYLOAD_SIZE
    }

    pub fn ciphertext_chunk_size(&self) -> usize {
        CHUNK_SIZE
    }

    /// `HMAC-SHA256(macKey, headerNonce || BE64(chunkNumber) || chunkNonce || ciphertext)`
    fn chunk_mac(&self, header_nonce: &[u8], chunk_number: u64, nonce_and_ciphertext: &[u8]) -> HmacSha256 {
        let mut mac = hmac(&self.mac_key);
        mac.update(header_nonce);
        mac.update(&chunk_number.to_be_bytes());
        mac.update(nonce_and_ciphertext);
        mac
    }

    /// `nonce || AES-CTR(contentKey, iv=nonce)(cleartext) || chunkMac`
    pub fn encrypt_chunk(&self, cleartext_chunk: &[u8], chunk_number: u64, header: &FileHeader, rng: &mut dyn Rng) -> Vec<u8> {
        assert!(cleartext_chunk.len() <= PAYLOAD_SIZE, "Invalid cleartext chunk size: {}", cleartext_chunk.len());
        let mut out = Vec::with_capacity(NONCE_SIZE + cleartext_chunk.len() + MAC_SIZE);
        let mut chunk_nonce = [0u8; NONCE_SIZE];
        rng.fill(&mut chunk_nonce);
        out.extend_from_slice(&chunk_nonce);
        let mut ciphertext = cleartext_chunk.to_vec();
        apply_ctr(header.content_key(), &chunk_nonce, &mut ciphertext);
        out.extend_from_slice(&ciphertext);
        let mac = self.chunk_mac(header.nonce(), chunk_number, &out);
        out.extend_from_slice(&mac.finalize().into_bytes());
        out
    }

    pub fn decrypt_chunk(&self, ciphertext_chunk: &[u8], chunk_number: u64, header: &FileHeader) -> Result<Vec<u8>> {
        if ciphertext_chunk.len() < NONCE_SIZE + MAC_SIZE || ciphertext_chunk.len() > CHUNK_SIZE {
            return Err(CoreError::InvalidArgument(format!(
                "Invalid ciphertext chunk size: {}, expected range [{}, {}]",
                ciphertext_chunk.len(),
                NONCE_SIZE + MAC_SIZE,
                CHUNK_SIZE
            )));
        }
        let (nonce_and_ciphertext, expected_mac) = ciphertext_chunk.split_at(ciphertext_chunk.len() - MAC_SIZE);
        self.chunk_mac(header.nonce(), chunk_number, nonce_and_ciphertext)
            .verify_slice(expected_mac)
            .map_err(|_| CoreError::AuthenticationFailed(format!("Authentication of chunk {chunk_number} failed.")))?;
        let (chunk_nonce, ciphertext) = nonce_and_ciphertext.split_at(NONCE_SIZE);
        let mut cleartext = ciphertext.to_vec();
        apply_ctr(header.content_key(), chunk_nonce, &mut cleartext);
        Ok(cleartext)
    }
}
```

In `crypto/mod.rs` ergänzen: `pub mod ctrmac;`.

- [ ] **Step 4: Tests laufen lassen**

Run: `cargo test -p cryptomator-core ctrmac`
Expected: PASS (7 Tests)

- [ ] **Step 5: Commit**

```bash
git add crates/cryptomator-core
git commit -m "Add SIV_CTRMAC header/content encryption

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 10: `CipherCombo`, `Cryptor`-Fassade und Größenmathematik

**Files:**
- Create: `crates/cryptomator-core/src/crypto/cryptor.rs`
- Modify: `crates/cryptomator-core/src/crypto/mod.rs`, `src/lib.rs`

**Interfaces:**
- Consumes: Task 7–9.
- Produces: `CipherCombo { SivCtrMac, SivGcm }` (serde-Namen `SIV_CTRMAC`/`SIV_GCM`, `as_str()`, `FromStr`, `Display`); `HeaderCryptor` (enum über Gcm/CtrMac) mit `create`, `header_size`, `encrypt_header`, `decrypt_header`; `ContentCryptor` (enum) mit `cleartext_chunk_size`, `ciphertext_chunk_size`, `encrypt_chunk`, `decrypt_chunk`, `cleartext_size(ciphertext_size: u64) -> Result<u64>`, `ciphertext_size(cleartext_size: u64) -> u64`; `Cryptor::new(CipherCombo, &Masterkey)` mit `cipher_combo()`, `file_name_cryptor()`, `file_header_cryptor()`, `file_content_cryptor()`.

- [ ] **Step 1: Fehlschlagende Tests schreiben**

```rust
// am Ende von crates/cryptomator-core/src/crypto/cryptor.rs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rng::DetRng;

    fn masterkey() -> Masterkey {
        let mut raw = [0u8; 64];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = i as u8;
        }
        Masterkey::from_raw(raw)
    }

    #[test]
    fn cipher_combo_names_match_java_enum() {
        assert_eq!(CipherCombo::SivGcm.as_str(), "SIV_GCM");
        assert_eq!(CipherCombo::SivCtrMac.as_str(), "SIV_CTRMAC");
        assert_eq!("SIV_GCM".parse::<CipherCombo>().unwrap(), CipherCombo::SivGcm);
        assert!("AES_GCM".parse::<CipherCombo>().is_err());
        assert_eq!(serde_json::to_string(&CipherCombo::SivCtrMac).unwrap(), "\"SIV_CTRMAC\"");
        assert_eq!(serde_json::from_str::<CipherCombo>("\"SIV_GCM\"").unwrap(), CipherCombo::SivGcm);
    }

    #[test]
    fn cryptor_dispatches_to_scheme() {
        let gcm = Cryptor::new(CipherCombo::SivGcm, &masterkey());
        let ctr = Cryptor::new(CipherCombo::SivCtrMac, &masterkey());
        assert_eq!(gcm.file_header_cryptor().header_size(), 68);
        assert_eq!(ctr.file_header_cryptor().header_size(), 88);
        assert_eq!(gcm.file_content_cryptor().ciphertext_chunk_size(), 32796);
        assert_eq!(ctr.file_content_cryptor().ciphertext_chunk_size(), 32816);
        assert_eq!(gcm.file_name_cryptor().hash_directory_id(""), "MN53XCQH5RFQJPKAFCMWDGELQHPPW2YQ");
    }

    #[test]
    fn header_and_chunk_round_trip_through_facade() {
        for combo in [CipherCombo::SivGcm, CipherCombo::SivCtrMac] {
            let cryptor = Cryptor::new(combo, &masterkey());
            let mut rng = DetRng::default();
            let header = cryptor.file_header_cryptor().create(&mut rng);
            let enc = cryptor.file_header_cryptor().encrypt_header(&header);
            let dec = cryptor.file_header_cryptor().decrypt_header(&enc).unwrap();
            assert_eq!(dec.content_key(), header.content_key());
            let chunk = cryptor.file_content_cryptor().encrypt_chunk(b"payload", 3, &header, &mut rng);
            assert_eq!(cryptor.file_content_cryptor().decrypt_chunk(&chunk, 3, &header).unwrap(), b"payload");
        }
    }

    // Values from FileContentCryptor.cleartextSize/ciphertextSize (Java defaults) and jshell runs.
    #[test]
    fn size_math_matches_java() {
        let gcm = Cryptor::new(CipherCombo::SivGcm, &masterkey());
        let cc = gcm.file_content_cryptor();
        assert_eq!(cc.ciphertext_size(0), 0);
        assert_eq!(cc.ciphertext_size(1), 29);
        assert_eq!(cc.ciphertext_size(32768), 32796);
        assert_eq!(cc.ciphertext_size(32769), 32796 + 29);
        assert_eq!(cc.cleartext_size(0).unwrap(), 0);
        assert_eq!(cc.cleartext_size(29).unwrap(), 1);
        assert_eq!(cc.cleartext_size(32796).unwrap(), 32768);
        assert_eq!(cc.cleartext_size(40124 - 68).unwrap(), 40000, "40124-byte GCM file from the jshell run holds 40000 cleartext bytes");
        assert!(matches!(cc.cleartext_size(28), Err(CoreError::InvalidArgument(_))), "trailing bytes <= overhead are undefined");
        assert!(matches!(cc.cleartext_size(32796 + 5), Err(CoreError::InvalidArgument(_))));

        let ctr = Cryptor::new(CipherCombo::SivCtrMac, &masterkey());
        let cc = ctr.file_content_cryptor();
        assert_eq!(cc.ciphertext_size(1), 49);
        assert_eq!(cc.cleartext_size(40184 - 88).unwrap(), 40000);
        assert!(cc.cleartext_size(48).is_err());
    }
}
```

- [ ] **Step 2: Tests laufen lassen, Fehlschlag bestätigen**

Run: `cargo test -p cryptomator-core cryptor`
Expected: FAIL (Modul fehlt)

- [ ] **Step 3: Implementieren**

```rust
// crates/cryptomator-core/src/crypto/cryptor.rs
//! Scheme selection (`api/CryptorProvider.Scheme`) and the `Cryptor` facade (`api/Cryptor.java`).
use crate::crypto::ctrmac::{CtrMacContentCryptor, CtrMacHeaderCryptor};
use crate::crypto::gcm::{GcmContentCryptor, GcmHeaderCryptor};
use crate::crypto::header::FileHeader;
use crate::crypto::masterkey::Masterkey;
use crate::crypto::rng::Rng;
use crate::crypto::siv::FileNameCryptor;
use crate::error::{CoreError, Result};
use serde::{Deserialize, Serialize};

/// `cipherCombo` claim of `vault.cryptomator`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CipherCombo {
    #[serde(rename = "SIV_CTRMAC")]
    SivCtrMac,
    #[serde(rename = "SIV_GCM")]
    SivGcm,
}

impl CipherCombo {
    pub const ALL: [CipherCombo; 2] = [CipherCombo::SivCtrMac, CipherCombo::SivGcm];

    pub fn as_str(&self) -> &'static str {
        match self {
            CipherCombo::SivCtrMac => "SIV_CTRMAC",
            CipherCombo::SivGcm => "SIV_GCM",
        }
    }
}

impl std::fmt::Display for CipherCombo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for CipherCombo {
    type Err = CoreError;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "SIV_CTRMAC" => Ok(CipherCombo::SivCtrMac),
            "SIV_GCM" => Ok(CipherCombo::SivGcm),
            other => Err(CoreError::InvalidArgument(format!("unknown cipher combo {other}"))),
        }
    }
}

#[derive(Debug)]
pub enum HeaderCryptor {
    Gcm(GcmHeaderCryptor),
    CtrMac(CtrMacHeaderCryptor),
}

impl HeaderCryptor {
    pub fn create(&self, rng: &mut dyn Rng) -> FileHeader {
        match self {
            HeaderCryptor::Gcm(h) => h.create(rng),
            HeaderCryptor::CtrMac(h) => h.create(rng),
        }
    }

    pub fn header_size(&self) -> usize {
        match self {
            HeaderCryptor::Gcm(h) => h.header_size(),
            HeaderCryptor::CtrMac(h) => h.header_size(),
        }
    }

    pub fn encrypt_header(&self, header: &FileHeader) -> Vec<u8> {
        match self {
            HeaderCryptor::Gcm(h) => h.encrypt_header(header),
            HeaderCryptor::CtrMac(h) => h.encrypt_header(header),
        }
    }

    pub fn decrypt_header(&self, ciphertext_header: &[u8]) -> Result<FileHeader> {
        match self {
            HeaderCryptor::Gcm(h) => h.decrypt_header(ciphertext_header),
            HeaderCryptor::CtrMac(h) => h.decrypt_header(ciphertext_header),
        }
    }
}

#[derive(Debug)]
pub enum ContentCryptor {
    Gcm(GcmContentCryptor),
    CtrMac(CtrMacContentCryptor),
}

impl ContentCryptor {
    pub fn cleartext_chunk_size(&self) -> usize {
        match self {
            ContentCryptor::Gcm(c) => c.cleartext_chunk_size(),
            ContentCryptor::CtrMac(c) => c.cleartext_chunk_size(),
        }
    }

    pub fn ciphertext_chunk_size(&self) -> usize {
        match self {
            ContentCryptor::Gcm(c) => c.ciphertext_chunk_size(),
            ContentCryptor::CtrMac(c) => c.ciphertext_chunk_size(),
        }
    }

    pub fn encrypt_chunk(&self, cleartext_chunk: &[u8], chunk_number: u64, header: &FileHeader, rng: &mut dyn Rng) -> Vec<u8> {
        match self {
            ContentCryptor::Gcm(c) => c.encrypt_chunk(cleartext_chunk, chunk_number, header, rng),
            ContentCryptor::CtrMac(c) => c.encrypt_chunk(cleartext_chunk, chunk_number, header, rng),
        }
    }

    pub fn decrypt_chunk(&self, ciphertext_chunk: &[u8], chunk_number: u64, header: &FileHeader) -> Result<Vec<u8>> {
        match self {
            ContentCryptor::Gcm(c) => c.decrypt_chunk(ciphertext_chunk, chunk_number, header),
            ContentCryptor::CtrMac(c) => c.decrypt_chunk(ciphertext_chunk, chunk_number, header),
        }
    }

    /// Cleartext size of a file body (ciphertext size WITHOUT the header). Mirrors `FileContentCryptor.cleartextSize`,
    /// including the undefined case where trailing bytes are not larger than the per-chunk overhead.
    pub fn cleartext_size(&self, ciphertext_size: u64) -> Result<u64> {
        let cleartext_chunk = self.cleartext_chunk_size() as u64;
        let ciphertext_chunk = self.ciphertext_chunk_size() as u64;
        let overhead = ciphertext_chunk - cleartext_chunk;
        let full_chunks = ciphertext_size / ciphertext_chunk;
        let additional_ciphertext = ciphertext_size % ciphertext_chunk;
        if additional_ciphertext > 0 && additional_ciphertext <= overhead {
            return Err(CoreError::InvalidArgument(format!("Method not defined for input value {ciphertext_size}")));
        }
        let additional_cleartext = if additional_ciphertext == 0 { 0 } else { additional_ciphertext - overhead };
        Ok(cleartext_chunk * full_chunks + additional_cleartext)
    }

    /// Ciphertext size of a file body (WITHOUT the header). Mirrors `FileContentCryptor.ciphertextSize`.
    pub fn ciphertext_size(&self, cleartext_size: u64) -> u64 {
        let cleartext_chunk = self.cleartext_chunk_size() as u64;
        let ciphertext_chunk = self.ciphertext_chunk_size() as u64;
        let overhead = ciphertext_chunk - cleartext_chunk;
        let full_chunks = cleartext_size / cleartext_chunk;
        let additional_cleartext = cleartext_size % cleartext_chunk;
        let additional_ciphertext = if additional_cleartext == 0 { 0 } else { additional_cleartext + overhead };
        ciphertext_chunk * full_chunks + additional_ciphertext
    }
}

/// Bundle of all cryptographic operations for one vault (`api/Cryptor.java`).
#[derive(Debug)]
pub struct Cryptor {
    cipher_combo: CipherCombo,
    file_name_cryptor: FileNameCryptor,
    header_cryptor: HeaderCryptor,
    content_cryptor: ContentCryptor,
}

impl Cryptor {
    pub fn new(cipher_combo: CipherCombo, masterkey: &Masterkey) -> Self {
        let (header_cryptor, content_cryptor) = match cipher_combo {
            CipherCombo::SivGcm => (HeaderCryptor::Gcm(GcmHeaderCryptor::new(masterkey)), ContentCryptor::Gcm(GcmContentCryptor)),
            CipherCombo::SivCtrMac => (
                HeaderCryptor::CtrMac(CtrMacHeaderCryptor::new(masterkey)),
                ContentCryptor::CtrMac(CtrMacContentCryptor::new(masterkey)),
            ),
        };
        Self { cipher_combo, file_name_cryptor: FileNameCryptor::new(masterkey), header_cryptor, content_cryptor }
    }

    pub fn cipher_combo(&self) -> CipherCombo {
        self.cipher_combo
    }

    pub fn file_name_cryptor(&self) -> &FileNameCryptor {
        &self.file_name_cryptor
    }

    pub fn file_header_cryptor(&self) -> &HeaderCryptor {
        &self.header_cryptor
    }

    pub fn file_content_cryptor(&self) -> &ContentCryptor {
        &self.content_cryptor
    }
}
```

In `crypto/mod.rs` ergänzen: `pub mod cryptor;`. In `lib.rs` ergänzen: `pub use crypto::cryptor::{CipherCombo, ContentCryptor, Cryptor, HeaderCryptor};` und `pub use crypto::header::FileHeader;`.

- [ ] **Step 4: Tests laufen lassen**

Run: `cargo test -p cryptomator-core cryptor`
Expected: PASS (4 Tests)

- [ ] **Step 5: Commit**

```bash
git add crates/cryptomator-core
git commit -m "Add CipherCombo, Cryptor facade and chunk size math

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 11: Streams – `EncryptingWriter` und `DecryptingReader`

**Files:**
- Create: `crates/cryptomator-core/src/crypto/stream.rs`
- Modify: `crates/cryptomator-core/src/crypto/mod.rs`, `src/lib.rs`

**Interfaces:**
- Consumes: `Cryptor`, `Rng`.
- Produces: `EncryptingWriter<'a, W: Write>::new(dest: W, cryptor: &'a Cryptor, rng: &'a mut dyn Rng)`, `impl Write`, `finish(self) -> io::Result<W>` (schreibt immer Header + letzten, ggf. leeren Chunk – wie `EncryptingWritableByteChannel.close()`); `DecryptingReader<'a, R: Read>::new(src: R, cryptor: &'a Cryptor)`, `impl Read` (Authentifizierungsfehler → `io::ErrorKind::InvalidData`, fehlender Header → `UnexpectedEof`); Helfer `encrypt_all(cryptor, rng, cleartext) -> io::Result<Vec<u8>>`, `decrypt_all(cryptor, ciphertext) -> io::Result<Vec<u8>>`.

- [ ] **Step 1: Fehlschlagende Tests schreiben**

```rust
// am Ende von crates/cryptomator-core/src/crypto/stream.rs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::cryptor::{CipherCombo, Cryptor};
    use crate::crypto::masterkey::Masterkey;
    use crate::crypto::rng::DetRng;
    use data_encoding::HEXLOWER;
    use sha2::{Digest, Sha256};

    // cryptolib 2.2.2 EncryptingWritableByteChannel with a fresh deterministic CryptorImpl per stream.
    const GCM_STREAM_EMPTY: &str = "a0a1a2a3a4a5a6a7a8a9aaab19e783d2ba34fd40cec8297cb7cb726dc419efa72a0ef8d720b39839bf6ab7c216b3813867eb99f6a8d57bbc501ceb787b03fa91363626a6cccdcecfd0d1d2d3d4d5d6d739cd8eb4a54f66cd826f0381487942a4";
    const GCM_DIRID_UUID: &str = "a0a1a2a3a4a5a6a7a8a9aaab19e783d2ba34fd40cec8297cb7cb726dc419efa72a0ef8d720b39839bf6ab7c216b3813867eb99f6a8d57bbc501ceb787b03fa91363626a6cccdcecfd0d1d2d3d4d5d6d7a2df2690b799eeb51ea269f50546f6f049df5670afc00da82d04a938442fc7b39f8e0be99b3cada7d91cbee0ff263c10e6b0debf";
    const GCM_STREAM_40000_SHA256: &str = "d8cff2ee78a481ed855805e9ef095f8d593b223cc5dd4325c8b3fbf2e0584dfa";
    const CTRMAC_STREAM_EMPTY: &str = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf2360fe02894783f2bffa5a36bfbe5a57596851aac0fc2b972c4b3a49a3f5155851222e6924aa57c5a12c9850de5595b2e1a07a8fb733a48864582784ef3c2c0dd39f245236529accd0d1d2d3d4d5d6d7d8d9dadbdcdddedf70d82713a3f441f675b5b8c0c348e1d981285c7907cdf92b9b56d65c65e8c5f2";
    const CTRMAC_STREAM_40000_SHA256: &str = "85ac051a68fd5a1811046347a521d317e9355c464f6f3cb8cf6e8723845136fe";
    const DIR_ID: &str = "2f3a8f2e-0b8a-4e6f-9c5d-1a2b3c4d5e6f";

    fn cryptor(combo: CipherCombo) -> Cryptor {
        let mut raw = [0u8; 64];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = i as u8;
        }
        Cryptor::new(combo, &Masterkey::from_raw(raw))
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 7) as u8).collect()
    }

    #[test]
    fn empty_stream_writes_header_and_one_empty_chunk() {
        for (combo, expected) in [(CipherCombo::SivGcm, GCM_STREAM_EMPTY), (CipherCombo::SivCtrMac, CTRMAC_STREAM_EMPTY)] {
            let c = cryptor(combo);
            let out = encrypt_all(&c, &mut DetRng::default(), b"").unwrap();
            assert_eq!(HEXLOWER.encode(&out), expected, "{combo}");
            assert_eq!(decrypt_all(&c, &out).unwrap(), b"");
        }
    }

    #[test]
    fn dirid_backup_of_uuid_matches_java() {
        let c = cryptor(CipherCombo::SivGcm);
        let out = encrypt_all(&c, &mut DetRng::default(), DIR_ID.as_bytes()).unwrap();
        assert_eq!(HEXLOWER.encode(&out), GCM_DIRID_UUID);
        assert_eq!(decrypt_all(&c, &out).unwrap(), DIR_ID.as_bytes());
    }

    #[test]
    fn multi_chunk_stream_matches_java_and_round_trips() {
        for (combo, expected_sha, expected_len) in [
            (CipherCombo::SivGcm, GCM_STREAM_40000_SHA256, 40124usize),
            (CipherCombo::SivCtrMac, CTRMAC_STREAM_40000_SHA256, 40184usize),
        ] {
            let c = cryptor(combo);
            let data = pattern(40000);
            let mut writer = EncryptingWriter::new(Vec::new(), &c, &mut DetRng::default());
            // write in odd-sized pieces to exercise buffering across chunk boundaries
            for piece in data.chunks(12345) {
                writer.write_all(piece).unwrap();
            }
            let out = writer.finish().unwrap();
            assert_eq!(out.len(), expected_len, "{combo}");
            assert_eq!(HEXLOWER.encode(&Sha256::digest(&out)), expected_sha, "{combo}");
            let mut reader = DecryptingReader::new(&out[..], &c);
            let mut got = Vec::new();
            reader.read_to_end(&mut got).unwrap();
            assert_eq!(got, data);
        }
    }

    #[test]
    fn small_reads_return_all_data() {
        let c = cryptor(CipherCombo::SivGcm);
        let data = pattern(70000);
        let out = encrypt_all(&c, &mut DetRng::default(), &data).unwrap();
        let mut reader = DecryptingReader::new(&out[..], &c);
        let mut got = Vec::new();
        let mut buf = [0u8; 1000];
        loop {
            let n = reader.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got, data);
    }

    #[test]
    fn truncated_header_is_unexpected_eof() {
        let c = cryptor(CipherCombo::SivGcm);
        let out = encrypt_all(&c, &mut DetRng::default(), b"abc").unwrap();
        let err = decrypt_all(&c, &out[..40]).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn tampered_chunk_is_invalid_data() {
        let c = cryptor(CipherCombo::SivGcm);
        let mut out = encrypt_all(&c, &mut DetRng::default(), b"abc").unwrap();
        let last = out.len() - 1;
        out[last] ^= 1;
        let err = decrypt_all(&c, &out).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}
```

- [ ] **Step 2: Tests laufen lassen, Fehlschlag bestätigen**

Run: `cargo test -p cryptomator-core stream`
Expected: FAIL (Modul fehlt)

- [ ] **Step 3: Implementieren**

```rust
// crates/cryptomator-core/src/crypto/stream.rs
//! Whole-file streaming encryption (`common/EncryptingWritableByteChannel.java`, `common/DecryptingReadableByteChannel.java`).
//! Java always flushes a final chunk on close, even an empty one; `finish()` reproduces that.
use crate::crypto::cryptor::Cryptor;
use crate::crypto::header::FileHeader;
use crate::crypto::rng::Rng;
use std::io::{self, Read, Write};

pub struct EncryptingWriter<'a, W: Write> {
    dest: W,
    cryptor: &'a Cryptor,
    rng: &'a mut dyn Rng,
    header: FileHeader,
    buffer: Vec<u8>,
    header_written: bool,
    chunk_number: u64,
}

impl<W: Write> std::fmt::Debug for EncryptingWriter<'_, W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptingWriter").field("chunk_number", &self.chunk_number).finish_non_exhaustive()
    }
}

impl<'a, W: Write> EncryptingWriter<'a, W> {
    pub fn new(dest: W, cryptor: &'a Cryptor, rng: &'a mut dyn Rng) -> Self {
        let header = cryptor.file_header_cryptor().create(rng);
        let capacity = cryptor.file_content_cryptor().cleartext_chunk_size();
        Self { dest, cryptor, rng, header, buffer: Vec::with_capacity(capacity), header_written: false, chunk_number: 0 }
    }

    fn write_header_on_first_write(&mut self) -> io::Result<()> {
        if !self.header_written {
            let encrypted = self.cryptor.file_header_cryptor().encrypt_header(&self.header);
            self.dest.write_all(&encrypted)?;
            self.header_written = true;
        }
        Ok(())
    }

    fn encrypt_and_flush_buffer(&mut self) -> io::Result<()> {
        let chunk = self.cryptor.file_content_cryptor().encrypt_chunk(&self.buffer, self.chunk_number, &self.header, self.rng);
        self.chunk_number += 1;
        self.dest.write_all(&chunk)?;
        self.buffer.clear();
        Ok(())
    }

    /// Writes the header (if nothing was written yet) and the final chunk, then returns the destination.
    pub fn finish(mut self) -> io::Result<W> {
        self.write_header_on_first_write()?;
        self.encrypt_and_flush_buffer()?;
        self.dest.flush()?;
        Ok(self.dest)
    }
}

impl<W: Write> Write for EncryptingWriter<'_, W> {
    fn write(&mut self, src: &[u8]) -> io::Result<usize> {
        self.write_header_on_first_write()?;
        let chunk_size = self.cryptor.file_content_cryptor().cleartext_chunk_size();
        let mut written = 0;
        while written < src.len() {
            let room = chunk_size - self.buffer.len();
            let take = room.min(src.len() - written);
            self.buffer.extend_from_slice(&src[written..written + take]);
            written += take;
            if self.buffer.len() == chunk_size {
                self.encrypt_and_flush_buffer()?;
            }
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.dest.flush()
    }
}

pub struct DecryptingReader<'a, R: Read> {
    src: R,
    cryptor: &'a Cryptor,
    header: Option<FileHeader>,
    cleartext: Vec<u8>,
    position: usize,
    reached_eof: bool,
    chunk_number: u64,
}

impl<R: Read> std::fmt::Debug for DecryptingReader<'_, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptingReader").field("chunk_number", &self.chunk_number).finish_non_exhaustive()
    }
}

impl<'a, R: Read> DecryptingReader<'a, R> {
    pub fn new(src: R, cryptor: &'a Cryptor) -> Self {
        Self { src, cryptor, header: None, cleartext: Vec::new(), position: 0, reached_eof: false, chunk_number: 0 }
    }

    /// Reads until `buf` is full or the source hits EOF; returns the number of bytes read.
    fn fill(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut total = 0;
        while total < buf.len() {
            match self.src.read(&mut buf[total..]) {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(total)
    }

    fn load_header_if_necessary(&mut self) -> io::Result<()> {
        if self.header.is_none() {
            let mut header_buf = vec![0u8; self.cryptor.file_header_cryptor().header_size()];
            let read = self.fill(&mut header_buf)?;
            if read != header_buf.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Unable to read header from channel."));
            }
            let header = self
                .cryptor
                .file_header_cryptor()
                .decrypt_header(&header_buf)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Unauthentic ciphertext: {e}")))?;
            self.header = Some(header);
        }
        Ok(())
    }

    /// Returns false at EOF.
    fn load_next_cleartext_chunk(&mut self) -> io::Result<bool> {
        let mut ciphertext_chunk = vec![0u8; self.cryptor.file_content_cryptor().ciphertext_chunk_size()];
        let read = self.fill(&mut ciphertext_chunk)?;
        if read == 0 {
            self.reached_eof = true;
            return Ok(false);
        }
        let header = self.header.as_ref().expect("header loaded before chunks");
        self.cleartext = self
            .cryptor
            .file_content_cryptor()
            .decrypt_chunk(&ciphertext_chunk[..read], self.chunk_number, header)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Unauthentic ciphertext: {e}")))?;
        self.chunk_number += 1;
        self.position = 0;
        Ok(true)
    }
}

impl<R: Read> Read for DecryptingReader<'_, R> {
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        self.load_header_if_necessary()?;
        let mut result = 0;
        while result < dst.len() && !self.reached_eof {
            if self.position < self.cleartext.len() || self.load_next_cleartext_chunk()? {
                let available = &self.cleartext[self.position..];
                let take = available.len().min(dst.len() - result);
                dst[result..result + take].copy_from_slice(&available[..take]);
                self.position += take;
                result += take;
            }
        }
        Ok(result)
    }
}

pub fn encrypt_all(cryptor: &Cryptor, rng: &mut dyn Rng, cleartext: &[u8]) -> io::Result<Vec<u8>> {
    let mut writer = EncryptingWriter::new(Vec::new(), cryptor, rng);
    writer.write_all(cleartext)?;
    writer.finish()
}

pub fn decrypt_all(cryptor: &Cryptor, ciphertext: &[u8]) -> io::Result<Vec<u8>> {
    let mut reader = DecryptingReader::new(ciphertext, cryptor);
    let mut out = Vec::new();
    reader.read_to_end(&mut out)?;
    Ok(out)
}
```

In `crypto/mod.rs` ergänzen: `pub mod stream;`. In `lib.rs`: `pub use crypto::stream::{decrypt_all, encrypt_all, DecryptingReader, EncryptingWriter};`.

- [ ] **Step 4: Tests laufen lassen**

Run: `cargo test -p cryptomator-core stream`
Expected: PASS (6 Tests)

- [ ] **Step 5: Commit**

```bash
git add crates/cryptomator-core
git commit -m "Add streaming file encryption and decryption

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 12: `vault.cryptomator` – JWT dekodieren, verifizieren, erzeugen

**Files:**
- Create: `crates/cryptomator-core/src/vault_config.rs`
- Modify: `crates/cryptomator-core/src/lib.rs`

**Interfaces:**
- Consumes: `CipherCombo`, `constants::VAULT_VERSION`.
- Produces: `KeyId::{MasterkeyFile { file_name: String }, Hub { uri: String }, Other(String)}` mit `KeyId::parse(&str)` und `Display` (Original-String); `JwtAlgorithm::{Hs256, Hs384, Hs512}`; `UnverifiedVaultConfig::decode(token: &str) -> Result<Self>` mit `key_id() -> Result<KeyId>`, `algorithm() -> Result<JwtAlgorithm>`, `alleged_vault_version() -> Option<u32>`, `alleged_shortening_threshold() -> Option<u32>`, `header_value(key: &str) -> Option<&serde_json::Value>`, `token() -> &str`, `verify(&self, raw_key: &[u8; 64], expected_vault_version: u32) -> Result<VaultConfig>` (Fehler: `VaultKeyInvalid`, `VaultVersionMismatch`, `VaultConfigLoad`); `VaultConfig { id: String, vault_version: u32, cipher_combo: CipherCombo, shortening_threshold: u32 }` mit `VaultConfig::create_new(cipher_combo, shortening_threshold)` (jti = UUIDv4, Version 8) und `to_token(&self, key_id: &str, raw_key: &[u8; 64]) -> String` (HS256, Header-Reihenfolge `kid, alg, typ`, Claims `jti, format, cipherCombo, shorteningThreshold`).

- [ ] **Step 1: Fehlschlagende Tests schreiben**

```rust
// am Ende von crates/cryptomator-core/src/vault_config.rs
#[cfg(test)]
mod tests {
    use super::*;

    // cryptofs 2.10.0: VaultConfig.createNew().cipherCombo(SIV_GCM).shorteningThreshold(220).build().toToken("masterkeyfile:masterkey.cryptomator", key 00..3f)
    const TOKEN: &str = "eyJraWQiOiJtYXN0ZXJrZXlmaWxlOm1hc3RlcmtleS5jcnlwdG9tYXRvciIsImFsZyI6IkhTMjU2IiwidHlwIjoiSldUIn0.eyJqdGkiOiI1YmMwMzg0Yi0xNGFjLTRmZGMtYWVkMC02MmU3YmMwOGZkNWEiLCJmb3JtYXQiOjgsImNpcGhlckNvbWJvIjoiU0lWX0dDTSIsInNob3J0ZW5pbmdUaHJlc2hvbGQiOjIyMH0.0DdfRRefLZici0eI0jDe6lS4sU7H8ZGp9eTqESy29Cg";
    const ID: &str = "5bc0384b-14ac-4fdc-aed0-62e7bc08fd5a";

    fn raw_key() -> [u8; 64] {
        let mut raw = [0u8; 64];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = i as u8;
        }
        raw
    }

    #[test]
    fn decodes_unverified_claims() {
        let cfg = UnverifiedVaultConfig::decode(TOKEN).unwrap();
        assert_eq!(cfg.key_id().unwrap(), KeyId::MasterkeyFile { file_name: "masterkey.cryptomator".into() });
        assert_eq!(cfg.algorithm().unwrap(), JwtAlgorithm::Hs256);
        assert_eq!(cfg.alleged_vault_version(), Some(8));
        assert_eq!(cfg.alleged_shortening_threshold(), Some(220));
        assert!(cfg.header_value("hub").is_none());
        assert_eq!(cfg.token(), TOKEN);
    }

    #[test]
    fn verifies_with_correct_key() {
        let cfg = UnverifiedVaultConfig::decode(TOKEN).unwrap().verify(&raw_key(), 8).unwrap();
        assert_eq!(cfg.id, ID);
        assert_eq!(cfg.vault_version, 8);
        assert_eq!(cfg.cipher_combo, CipherCombo::SivGcm);
        assert_eq!(cfg.shortening_threshold, 220);
    }

    #[test]
    fn wrong_key_is_vault_key_invalid() {
        let mut wrong = raw_key();
        wrong[0] ^= 1;
        assert!(matches!(UnverifiedVaultConfig::decode(TOKEN).unwrap().verify(&wrong, 8), Err(CoreError::VaultKeyInvalid)));
    }

    #[test]
    fn wrong_expected_version_is_version_mismatch() {
        assert!(matches!(
            UnverifiedVaultConfig::decode(TOKEN).unwrap().verify(&raw_key(), 7),
            Err(CoreError::VaultVersionMismatch { expected: 7, actual: 8 })
        ));
    }

    #[test]
    fn to_token_is_byte_identical_to_java() {
        let cfg = VaultConfig { id: ID.into(), vault_version: 8, cipher_combo: CipherCombo::SivGcm, shortening_threshold: 220 };
        assert_eq!(cfg.to_token("masterkeyfile:masterkey.cryptomator", &raw_key()), TOKEN);
    }

    #[test]
    fn create_new_round_trips() {
        let cfg = VaultConfig::create_new(CipherCombo::SivCtrMac, 36);
        assert_eq!(cfg.vault_version, 8);
        assert_eq!(cfg.id.len(), 36);
        let token = cfg.to_token("masterkeyfile:masterkey.cryptomator", &raw_key());
        let verified = UnverifiedVaultConfig::decode(&token).unwrap().verify(&raw_key(), 8).unwrap();
        assert_eq!(verified, cfg);
    }

    #[test]
    fn hub_key_id_is_detected() {
        let cfg = VaultConfig { id: ID.into(), vault_version: 8, cipher_combo: CipherCombo::SivGcm, shortening_threshold: 220 };
        let token = cfg.to_token("hub+https://hub.example.com/api/vaults/123", &raw_key());
        let key_id = UnverifiedVaultConfig::decode(&token).unwrap().key_id().unwrap();
        assert_eq!(key_id, KeyId::Hub { uri: "hub+https://hub.example.com/api/vaults/123".into() });
        assert_eq!(key_id.to_string(), "hub+https://hub.example.com/api/vaults/123");
        assert_eq!(KeyId::parse("hub+http://x/api/vaults/1"), KeyId::Hub { uri: "hub+http://x/api/vaults/1".into() });
        assert_eq!(KeyId::parse("unknown:thing"), KeyId::Other("unknown:thing".into()));
    }

    #[test]
    fn garbage_is_vault_config_load_error() {
        assert!(matches!(UnverifiedVaultConfig::decode("not.a.jwt"), Err(CoreError::VaultConfigLoad(_))));
        assert!(matches!(UnverifiedVaultConfig::decode("onlyonepart"), Err(CoreError::VaultConfigLoad(_))));
    }

    #[test]
    fn accepts_hs512_signatures() {
        let cfg = VaultConfig { id: ID.into(), vault_version: 8, cipher_combo: CipherCombo::SivGcm, shortening_threshold: 220 };
        let token = cfg.to_token_with_algorithm("masterkeyfile:masterkey.cryptomator", &raw_key(), JwtAlgorithm::Hs512);
        let unverified = UnverifiedVaultConfig::decode(&token).unwrap();
        assert_eq!(unverified.algorithm().unwrap(), JwtAlgorithm::Hs512);
        assert_eq!(unverified.verify(&raw_key(), 8).unwrap(), cfg);
    }
}
```

- [ ] **Step 2: Tests laufen lassen, Fehlschlag bestätigen**

Run: `cargo test -p cryptomator-core vault_config`
Expected: FAIL (Modul fehlt)

- [ ] **Step 3: Implementieren**

```rust
// crates/cryptomator-core/src/vault_config.rs
//! `vault.cryptomator` (`cryptofs/VaultConfig.java`): a JWT signed with HMAC over the raw 64-byte masterkey.
//! Implemented by hand (base64url header.payload.signature) to control claim order and the accepted algorithms.
use crate::constants::VAULT_VERSION;
use crate::crypto::cryptor::CipherCombo;
use crate::error::{CoreError, Result};
use data_encoding::BASE64URL_NOPAD;
use hmac::{Hmac, Mac};
use serde_json::{json, Map, Value};
use sha2::{Sha256, Sha384, Sha512};

const CLAIM_FORMAT: &str = "format";
const CLAIM_CIPHER_COMBO: &str = "cipherCombo";
const CLAIM_SHORTENING_THRESHOLD: &str = "shorteningThreshold";
const CLAIM_ID: &str = "jti";
const HEADER_KEY_ID: &str = "kid";
const HEADER_ALGORITHM: &str = "alg";

/// `kid` header of the vault config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyId {
    /// `masterkeyfile:<file name>` – password based vault.
    MasterkeyFile { file_name: String },
    /// `hub+http(s)://…` – Cryptomator Hub vault (unsupported by crypto).
    Hub { uri: String },
    Other(String),
}

impl KeyId {
    pub fn parse(raw: &str) -> Self {
        if let Some(file_name) = raw.strip_prefix("masterkeyfile:") {
            KeyId::MasterkeyFile { file_name: file_name.to_string() }
        } else if raw.starts_with("hub+http://") || raw.starts_with("hub+https://") {
            KeyId::Hub { uri: raw.to_string() }
        } else {
            KeyId::Other(raw.to_string())
        }
    }
}

impl std::fmt::Display for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyId::MasterkeyFile { file_name } => write!(f, "masterkeyfile:{file_name}"),
            KeyId::Hub { uri } => f.write_str(uri),
            KeyId::Other(raw) => f.write_str(raw),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwtAlgorithm {
    Hs256,
    Hs384,
    Hs512,
}

impl JwtAlgorithm {
    fn name(&self) -> &'static str {
        match self {
            JwtAlgorithm::Hs256 => "HS256",
            JwtAlgorithm::Hs384 => "HS384",
            JwtAlgorithm::Hs512 => "HS512",
        }
    }

    fn from_name(name: &str) -> Result<Self> {
        match name {
            "HS256" => Ok(JwtAlgorithm::Hs256),
            "HS384" => Ok(JwtAlgorithm::Hs384),
            "HS512" => Ok(JwtAlgorithm::Hs512),
            other => Err(CoreError::VaultConfigLoad(format!("Unsupported signature algorithm: {other}"))),
        }
    }

    fn sign(&self, key: &[u8], signing_input: &[u8]) -> Vec<u8> {
        match self {
            JwtAlgorithm::Hs256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("any key length");
                mac.update(signing_input);
                mac.finalize().into_bytes().to_vec()
            }
            JwtAlgorithm::Hs384 => {
                let mut mac = Hmac::<Sha384>::new_from_slice(key).expect("any key length");
                mac.update(signing_input);
                mac.finalize().into_bytes().to_vec()
            }
            JwtAlgorithm::Hs512 => {
                let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("any key length");
                mac.update(signing_input);
                mac.finalize().into_bytes().to_vec()
            }
        }
    }

    fn verify(&self, key: &[u8], signing_input: &[u8], signature: &[u8]) -> bool {
        match self {
            JwtAlgorithm::Hs256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("any key length");
                mac.update(signing_input);
                mac.verify_slice(signature).is_ok()
            }
            JwtAlgorithm::Hs384 => {
                let mut mac = Hmac::<Sha384>::new_from_slice(key).expect("any key length");
                mac.update(signing_input);
                mac.verify_slice(signature).is_ok()
            }
            JwtAlgorithm::Hs512 => {
                let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("any key length");
                mac.update(signing_input);
                mac.verify_slice(signature).is_ok()
            }
        }
    }
}

/// Decoded but not yet signature-checked vault config.
#[derive(Debug, Clone)]
pub struct UnverifiedVaultConfig {
    token: String,
    signing_input_len: usize,
    header: Map<String, Value>,
    claims: Map<String, Value>,
    signature: Vec<u8>,
}

impl UnverifiedVaultConfig {
    pub fn decode(token: &str) -> Result<Self> {
        let load_err = || CoreError::VaultConfigLoad(format!("Failed to parse config: {token}"));
        let mut parts = token.split('.');
        let (header_b64, claims_b64, signature_b64) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(h), Some(c), Some(s), None) => (h, c, s),
            _ => return Err(load_err()),
        };
        let decode_json = |part: &str| -> Result<Map<String, Value>> {
            let bytes = BASE64URL_NOPAD.decode(part.as_bytes()).map_err(|_| load_err())?;
            match serde_json::from_slice::<Value>(&bytes).map_err(|_| load_err())? {
                Value::Object(map) => Ok(map),
                _ => Err(load_err()),
            }
        };
        let header = decode_json(header_b64)?;
        let claims = decode_json(claims_b64)?;
        let signature = BASE64URL_NOPAD.decode(signature_b64.as_bytes()).map_err(|_| load_err())?;
        Ok(Self { token: token.to_string(), signing_input_len: header_b64.len() + 1 + claims_b64.len(), header, claims, signature })
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    pub fn header_value(&self, key: &str) -> Option<&Value> {
        self.header.get(key)
    }

    pub fn key_id(&self) -> Result<KeyId> {
        self.header
            .get(HEADER_KEY_ID)
            .and_then(Value::as_str)
            .map(KeyId::parse)
            .ok_or_else(|| CoreError::VaultConfigLoad("vault config has no key id".into()))
    }

    pub fn algorithm(&self) -> Result<JwtAlgorithm> {
        let name = self
            .header
            .get(HEADER_ALGORITHM)
            .and_then(Value::as_str)
            .ok_or_else(|| CoreError::VaultConfigLoad("vault config has no signature algorithm".into()))?;
        JwtAlgorithm::from_name(name)
    }

    pub fn alleged_vault_version(&self) -> Option<u32> {
        self.claims.get(CLAIM_FORMAT).and_then(Value::as_u64).map(|v| v as u32)
    }

    pub fn alleged_shortening_threshold(&self) -> Option<u32> {
        self.claims.get(CLAIM_SHORTENING_THRESHOLD).and_then(Value::as_u64).map(|v| v as u32)
    }

    /// Checks the signature with the raw masterkey, then the `format` claim, then parses the remaining claims.
    pub fn verify(&self, raw_key: &[u8; 64], expected_vault_version: u32) -> Result<VaultConfig> {
        let algorithm = self.algorithm()?;
        let signing_input = &self.token.as_bytes()[..self.signing_input_len];
        if !algorithm.verify(raw_key, signing_input, &self.signature) {
            return Err(CoreError::VaultKeyInvalid);
        }
        let actual = self
            .alleged_vault_version()
            .ok_or_else(|| CoreError::VaultConfigLoad(format!("Failed to verify vault config: {}", self.token)))?;
        if actual != expected_vault_version {
            return Err(CoreError::VaultVersionMismatch { expected: expected_vault_version, actual });
        }
        let load_err = || CoreError::VaultConfigLoad(format!("Failed to verify vault config: {}", self.token));
        let id = self.claims.get(CLAIM_ID).and_then(Value::as_str).ok_or_else(load_err)?.to_string();
        let cipher_combo = self
            .claims
            .get(CLAIM_CIPHER_COMBO)
            .and_then(Value::as_str)
            .ok_or_else(load_err)?
            .parse::<CipherCombo>()
            .map_err(|_| load_err())?;
        let shortening_threshold = self.alleged_shortening_threshold().ok_or_else(load_err)?;
        Ok(VaultConfig { id, vault_version: actual, cipher_combo, shortening_threshold })
    }
}

/// Verified vault configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultConfig {
    pub id: String,
    pub vault_version: u32,
    pub cipher_combo: CipherCombo,
    pub shortening_threshold: u32,
}

impl VaultConfig {
    pub fn create_new(cipher_combo: CipherCombo, shortening_threshold: u32) -> Self {
        Self { id: uuid::Uuid::new_v4().to_string(), vault_version: VAULT_VERSION, cipher_combo, shortening_threshold }
    }

    /// HS256 token exactly like `VaultConfig.toToken` (java-jwt claim order: kid, alg, typ / jti, format, cipherCombo, shorteningThreshold).
    pub fn to_token(&self, key_id: &str, raw_key: &[u8; 64]) -> String {
        self.to_token_with_algorithm(key_id, raw_key, JwtAlgorithm::Hs256)
    }

    pub fn to_token_with_algorithm(&self, key_id: &str, raw_key: &[u8; 64], algorithm: JwtAlgorithm) -> String {
        let header = json!({ "kid": key_id, "alg": algorithm.name(), "typ": "JWT" });
        let claims = json!({
            "jti": self.id,
            "format": self.vault_version,
            "cipherCombo": self.cipher_combo.as_str(),
            "shorteningThreshold": self.shortening_threshold,
        });
        let header_b64 = BASE64URL_NOPAD.encode(header.to_string().as_bytes());
        let claims_b64 = BASE64URL_NOPAD.encode(claims.to_string().as_bytes());
        let signing_input = format!("{header_b64}.{claims_b64}");
        let signature = algorithm.sign(raw_key, signing_input.as_bytes());
        format!("{signing_input}.{}", BASE64URL_NOPAD.encode(&signature))
    }
}
```

`serde_json` mit Feature `preserve_order` hält die Einfügereihenfolge von `json!` bei; ohne dieses Feature würden die Claims alphabetisch sortiert und `to_token_is_byte_identical_to_java` fehlschlagen. In `lib.rs` ergänzen: `pub mod vault_config;` und `pub use vault_config::{JwtAlgorithm, KeyId, UnverifiedVaultConfig, VaultConfig};`.

- [ ] **Step 4: Tests laufen lassen**

Run: `cargo test -p cryptomator-core vault_config`
Expected: PASS (9 Tests)

- [ ] **Step 5: Commit**

```bash
git add crates/cryptomator-core
git commit -m "Add vault.cryptomator JWT decoding, verification and creation

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 13: Backup-Dateien (`<name>.<HEX8>.bkup`)

**Files:**
- Create: `crates/cryptomator-core/src/backup.rs`
- Modify: `crates/cryptomator-core/src/lib.rs`

**Interfaces:**
- Produces: `generate_file_id_suffix(bytes: &[u8]) -> String` (`"." + HEXUPPER(SHA-256[0..4])`), `backup_file_name(original_file_name: &str, bytes: &[u8]) -> String`, `attempt_backup(path: &Path) -> Result<BackupOutcome>` mit `BackupOutcome { path: PathBuf, status: BackupStatus }`, `BackupStatus::{Created, VerifiedExisting, MismatchExisting, Failed(String)}`.

- [ ] **Step 1: Fehlschlagende Tests schreiben**

```rust
// am Ende von crates/cryptomator-core/src/backup.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffix_is_upper_hex_of_first_four_sha256_bytes() {
        // sha256("hello\n") = 5891b5b5…; cryptofs BackupHelper.generateFileIdSuffix → ".5891B5B5"
        assert_eq!(generate_file_id_suffix(b"hello\n"), ".5891B5B5");
        assert_eq!(backup_file_name("masterkey.cryptomator", b"hello\n"), "masterkey.cryptomator.5891B5B5.bkup");
    }

    #[test]
    fn creates_backup_next_to_original() {
        let dir = tempfile::tempdir().unwrap();
        let original = dir.path().join("vault.cryptomator");
        std::fs::write(&original, b"hello\n").unwrap();
        let outcome = attempt_backup(&original).unwrap();
        assert_eq!(outcome.path, dir.path().join("vault.cryptomator.5891B5B5.bkup"));
        assert_eq!(outcome.status, BackupStatus::Created);
        assert_eq!(std::fs::read(&outcome.path).unwrap(), b"hello\n");
    }

    #[test]
    fn existing_identical_backup_is_verified() {
        let dir = tempfile::tempdir().unwrap();
        let original = dir.path().join("vault.cryptomator");
        std::fs::write(&original, b"hello\n").unwrap();
        attempt_backup(&original).unwrap();
        assert_eq!(attempt_backup(&original).unwrap().status, BackupStatus::VerifiedExisting);
    }

    #[test]
    fn existing_different_backup_is_reported_as_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let original = dir.path().join("vault.cryptomator");
        std::fs::write(&original, b"hello\n").unwrap();
        std::fs::write(dir.path().join("vault.cryptomator.5891B5B5.bkup"), b"corrupt").unwrap();
        assert_eq!(attempt_backup(&original).unwrap().status, BackupStatus::MismatchExisting);
    }

    #[test]
    fn missing_original_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(attempt_backup(&dir.path().join("nope")), Err(CoreError::Io(_))));
    }
}
```

- [ ] **Step 2: Tests laufen lassen, Fehlschlag bestätigen**

Run: `cargo test -p cryptomator-core backup`
Expected: FAIL (Modul fehlt)

- [ ] **Step 3: Implementieren**

```rust
// crates/cryptomator-core/src/backup.rs
//! Backup copies of `vault.cryptomator` / `masterkey.cryptomator` (`cryptofs/common/BackupHelper.java`).
use crate::constants::BACKUP_SUFFIX;
use crate::error::{CoreError, Result};
use data_encoding::HEXUPPER;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};

pub fn generate_file_id_suffix(file_bytes: &[u8]) -> String {
    let digest = Sha256::digest(file_bytes);
    format!(".{}", HEXUPPER.encode(&digest[..4]))
}

pub fn backup_file_name(original_file_name: &str, file_bytes: &[u8]) -> String {
    format!("{original_file_name}{}{BACKUP_SUFFIX}", generate_file_id_suffix(file_bytes))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackupStatus {
    Created,
    VerifiedExisting,
    MismatchExisting,
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupOutcome {
    pub path: PathBuf,
    pub status: BackupStatus,
}

/// Best-effort backup like Java: `CREATE_NEW`; if the backup exists (or is not writable) compare contents;
/// other I/O failures while writing are reported as `Failed` rather than propagated.
pub fn attempt_backup(path: &Path) -> Result<BackupOutcome> {
    let file_bytes = std::fs::read(path)?;
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| CoreError::InvalidArgument(format!("not a file path: {}", path.display())))?;
    let backup_path = path.with_file_name(backup_file_name(file_name, &file_bytes));
    let status = match std::fs::OpenOptions::new().write(true).create_new(true).open(&backup_path) {
        Ok(mut file) => match file.write_all(&file_bytes) {
            Ok(()) => BackupStatus::Created,
            Err(e) => BackupStatus::Failed(e.to_string()),
        },
        Err(e) if matches!(e.kind(), std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::PermissionDenied) => {
            match std::fs::read(&backup_path) {
                Ok(existing) if existing == file_bytes => BackupStatus::VerifiedExisting,
                Ok(_) => BackupStatus::MismatchExisting,
                Err(e) => BackupStatus::Failed(e.to_string()),
            }
        }
        Err(e) => BackupStatus::Failed(e.to_string()),
    };
    Ok(BackupOutcome { path: backup_path, status })
}
```

In `lib.rs` ergänzen: `pub mod backup;`.

- [ ] **Step 4: Tests laufen lassen**

Run: `cargo test -p cryptomator-core backup`
Expected: PASS (5 Tests)

- [ ] **Step 5: Commit**

```bash
git add crates/cryptomator-core
git commit -m "Add .bkup backup helper

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 14: Recovery-Key – Wortkodierung, Erzeugung, Validierung, Passwort-Reset

**Files:**
- Create: `crates/cryptomator-core/src/recovery/mod.rs`, `src/recovery/words.rs`, `src/recovery/key.rs`, `src/recovery/4096words_en.txt` (Kopie)
- Modify: `crates/cryptomator-core/src/lib.rs`

**Interfaces:**
- Consumes: `MasterkeyFileAccess`, `backup::backup_file_name`, `Masterkey`, `Rng`.
- Produces: `WordEncoder::new()`, `words() -> &[&'static str]`, `encode_padded(&[u8]) -> Result<String>`, `decode(&str) -> Result<Vec<u8>>`; `create_recovery_key(&WordEncoder, raw: &[u8; 64]) -> String` (44 Wörter), `decode_recovery_key(&WordEncoder, &str) -> Result<Zeroizing<[u8; 64]>>`, `validate_recovery_key(&WordEncoder, &str) -> bool`, `reset_password(vault_path: &Path, recovery_key: &str, new_passphrase: &str, rng: &mut dyn Rng) -> Result<()>` (verschiebt vorhandene Masterkey-Datei nach `masterkey.cryptomator.<HEX8>.bkup`, schreibt neue Datei mit Version 999).

- [ ] **Step 1: Wortliste kopieren**

Run: `cp /Users/rfoerthe/work/pro/cryptomator/.claude/worktrees/cryptomator-cli-rust-be5387/src/main/resources/i18n/4096words_en.txt crates/cryptomator-core/src/recovery/4096words_en.txt && awk 'END{print NR}' crates/cryptomator-core/src/recovery/4096words_en.txt && head -1 crates/cryptomator-core/src/recovery/4096words_en.txt && tail -1 crates/cryptomator-core/src/recovery/4096words_en.txt`
Expected: `4096` (die Datei hat kein abschließendes Newline, `wc -l` zeigt 4095), erstes Wort `ad`, letztes Wort `residence`.

- [ ] **Step 2: Fehlschlagende Tests schreiben**

```rust
// am Ende von crates/cryptomator-core/src/recovery/words.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dictionary_has_4096_words() {
        let enc = WordEncoder::new();
        assert_eq!(enc.words().len(), 4096);
        assert_eq!(enc.words()[0], "ad");
        assert_eq!(enc.words()[4095], "residence");
    }

    #[test]
    fn encode_then_decode_round_trips_for_all_multiples_of_three() {
        let enc = WordEncoder::new();
        let mut seed = 42u64;
        for i in 0..30 {
            let input: Vec<u8> = (0..i * 3)
                .map(|_| {
                    seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                    (seed >> 33) as u8
                })
                .collect();
            let encoded = enc.encode_padded(&input).unwrap();
            assert_eq!(enc.decode(&encoded).unwrap(), input, "length {}", input.len());
        }
    }

    #[test]
    fn encode_rejects_length_not_multiple_of_three() {
        assert!(matches!(WordEncoder::new().encode_padded(&[1, 2]), Err(CoreError::InvalidArgument(_))));
    }

    #[test]
    fn decode_rejects_odd_word_count_and_unknown_words() {
        let enc = WordEncoder::new();
        assert!(matches!(enc.decode("pathway"), Err(CoreError::InvalidRecoveryKey(_))));
        assert!(matches!(enc.decode("Backpfeifengesicht Schweinehund"), Err(CoreError::InvalidRecoveryKey(_))));
        assert_eq!(enc.decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn decode_ignores_extra_whitespace() {
        let enc = WordEncoder::new();
        assert_eq!(enc.decode("  ad   ad ").unwrap(), vec![0, 0, 0]);
    }
}
```

```rust
// am Ende von crates/cryptomator-core/src/recovery/key.rs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rng::DetRng;
    use crate::masterkey_file::MasterkeyFileAccess;

    // RecoveryKeyFactory.createRecoveryKey(key 00..3f): crc32 = 0x100ece8c → trailing bytes 8c ce.
    const RECOVERY_KEY_SEQUENTIAL: &str = "ad back bin enter gym gentle own intense van resident sin oh boot dumb debt stake flag tenure hers worship life similarly nail open pray thick shoe visual tend counter warn scenario cave cash jury grass shed league allow obvious build transfer dream normally";
    // From RecoveryKeyFactoryTest in the desktop app.
    const VALID_KEY: &str = "pathway lift abuse plenty export texture gentleman landscape beyond ceiling around leaf cafe charity border breakdown victory surely computer cat linger restrict infer crowd live computer true written amazed investor boot depth left theory snow whereby terminal weekly reject happiness circuit partial cup ad";
    const INVALID_CRC_KEY: &str = "pathway lift abuse plenty export texture gentleman landscape beyond ceiling around leaf cafe charity border breakdown victory surely computer cat linger restrict infer crowd live computer true written amazed investor boot depth left theory snow whereby terminal weekly reject happiness circuit partial cup wrong";

    fn sequential() -> [u8; 64] {
        let mut raw = [0u8; 64];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = i as u8;
        }
        raw
    }

    #[test]
    fn creates_44_word_key_like_java() {
        let enc = WordEncoder::new();
        let key = create_recovery_key(&enc, &sequential());
        assert_eq!(key.split(' ').count(), 44);
        assert_eq!(key, RECOVERY_KEY_SEQUENTIAL);
    }

    #[test]
    fn decodes_own_key_back_to_raw_masterkey() {
        let enc = WordEncoder::new();
        assert_eq!(*decode_recovery_key(&enc, RECOVERY_KEY_SEQUENTIAL).unwrap(), sequential());
    }

    #[test]
    fn validates_like_java_tests() {
        let enc = WordEncoder::new();
        assert!(validate_recovery_key(&enc, VALID_KEY));
        assert!(!validate_recovery_key(&enc, INVALID_CRC_KEY));
        assert!(!validate_recovery_key(&enc, "pathway"));
        assert!(!validate_recovery_key(&enc, "Backpfeifengesicht Schweinehund"));
        assert!(!validate_recovery_key(&enc, "pathway lift"));
    }

    #[test]
    fn reset_password_backs_up_old_file_and_writes_new_one() {
        let dir = tempfile::tempdir().unwrap();
        let masterkey_path = dir.path().join("masterkey.cryptomator");
        std::fs::write(&masterkey_path, b"old masterkey file\n").unwrap();
        let enc = WordEncoder::new();
        reset_password(&enc, dir.path(), RECOVERY_KEY_SEQUENTIAL, "new-pass", &mut DetRng::default()).unwrap();
        let expected_backup = dir.path().join(format!("masterkey.cryptomator{}.bkup", crate::backup::generate_file_id_suffix(b"old masterkey file\n")));
        assert_eq!(std::fs::read(&expected_backup).unwrap(), b"old masterkey file\n");
        let key = MasterkeyFileAccess::new(Vec::new()).load(&masterkey_path, "new-pass").unwrap();
        assert_eq!(key.raw(), &sequential());
    }

    #[test]
    fn reset_password_with_invalid_key_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let enc = WordEncoder::new();
        assert!(matches!(reset_password(&enc, dir.path(), INVALID_CRC_KEY, "x", &mut DetRng::default()), Err(CoreError::InvalidRecoveryKey(_))));
        assert!(!dir.path().join("masterkey.cryptomator").exists());
    }
}
```

- [ ] **Step 3: Tests laufen lassen, Fehlschlag bestätigen**

Run: `cargo test -p cryptomator-core recovery`
Expected: FAIL (Module fehlen)

- [ ] **Step 4: Implementieren**

```rust
// crates/cryptomator-core/src/recovery/mod.rs
//! Recovery key handling (desktop app `ui/recoverykey/{WordEncoder,RecoveryKeyFactory}.java`).
pub mod key;
pub mod words;

pub use key::{create_recovery_key, decode_recovery_key, reset_password, validate_recovery_key, RECOVERY_KEY_WORDS};
pub use words::{WordEncoder, WORD_COUNT};
```

```rust
// crates/cryptomator-core/src/recovery/words.rs
//! 12-bit word encoding: every 3 bytes become 2 words of a 4096-word dictionary.
use crate::error::{CoreError, Result};
use std::collections::HashMap;

pub const WORD_COUNT: usize = 4096;
const DELIMITER: char = ' ';
/// English word list shipped with the Cryptomator desktop app (`i18n/4096words_en.txt`).
const WORD_FILE: &str = include_str!("4096words_en.txt");

#[derive(Debug, Clone)]
pub struct WordEncoder {
    words: Vec<&'static str>,
    indices: HashMap<&'static str, u16>,
}

impl Default for WordEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl WordEncoder {
    pub fn new() -> Self {
        let words: Vec<&'static str> = WORD_FILE.lines().take(WORD_COUNT).collect();
        assert_eq!(words.len(), WORD_COUNT, "word list must contain {WORD_COUNT} words");
        let indices = words.iter().enumerate().map(|(i, w)| (*w, i as u16)).collect();
        Self { words, indices }
    }

    pub fn words(&self) -> &[&'static str] {
        &self.words
    }

    pub fn encode_padded(&self, input: &[u8]) -> Result<String> {
        if input.len() % 3 != 0 {
            return Err(CoreError::InvalidArgument("input needs to be padded to a multiple of three".into()));
        }
        let mut out = Vec::with_capacity(input.len() / 3 * 2);
        for triple in input.chunks_exact(3) {
            let (b1, b2, b3) = (triple[0] as u32, triple[1] as u32, triple[2] as u32);
            let first = ((b1 << 4) & 0xFF0) | ((b2 >> 4) & 0x00F);
            let second = ((b2 << 8) & 0xF00) | (b3 & 0x0FF);
            out.push(self.words[first as usize]);
            out.push(self.words[second as usize]);
        }
        Ok(out.join(&DELIMITER.to_string()))
    }

    pub fn decode(&self, encoded: &str) -> Result<Vec<u8>> {
        let split: Vec<&str> = encoded.split(DELIMITER).filter(|w| !w.is_empty()).collect();
        if split.len() % 2 != 0 {
            return Err(CoreError::InvalidRecoveryKey(format!("{encoded} needs to be a multiple of two words")));
        }
        let mut out = Vec::with_capacity(split.len() / 2 * 3);
        for pair in split.chunks_exact(2) {
            let first = *self.indices.get(pair[0]).ok_or_else(|| CoreError::InvalidRecoveryKey(format!("{} not in dictionary", pair[0])))? as u32;
            let second = *self.indices.get(pair[1]).ok_or_else(|| CoreError::InvalidRecoveryKey(format!("{} not in dictionary", pair[1])))? as u32;
            out.push((first >> 4) as u8);
            out.push((((first << 4) & 0xF0) | ((second >> 8) & 0x0F)) as u8);
            out.push((second & 0xFF) as u8);
        }
        Ok(out)
    }
}
```

```rust
// crates/cryptomator-core/src/recovery/key.rs
//! Recovery key = 64-byte masterkey + 2 low-order bytes (little-endian) of CRC32 → 66 bytes → 44 words.
use crate::backup::backup_file_name;
use crate::constants::MASTERKEY_FILENAME;
use crate::crypto::masterkey::Masterkey;
use crate::crypto::rng::Rng;
use crate::error::{CoreError, Result};
use crate::masterkey_file::{MasterkeyFileAccess, DEFAULT_MASTERKEY_FILE_VERSION};
use crate::recovery::words::WordEncoder;
use std::path::Path;
use zeroize::Zeroizing;

pub const RECOVERY_KEY_WORDS: usize = 44;
const PADDED_LEN: usize = 66;

fn crc_suffix(raw_key: &[u8; 64]) -> [u8; 2] {
    // Guava's HashCode.asBytes() is little-endian; Java copies its first two bytes.
    let crc = crc32fast::hash(raw_key).to_le_bytes();
    [crc[0], crc[1]]
}

pub fn create_recovery_key(encoder: &WordEncoder, raw_key: &[u8; 64]) -> String {
    let mut padded = Zeroizing::new([0u8; PADDED_LEN]);
    padded[..64].copy_from_slice(raw_key);
    padded[64..].copy_from_slice(&crc_suffix(raw_key));
    encoder.encode_padded(&*padded).expect("66 is a multiple of 3")
}

pub fn decode_recovery_key(encoder: &WordEncoder, recovery_key: &str) -> Result<Zeroizing<[u8; 64]>> {
    let padded = Zeroizing::new(encoder.decode(recovery_key)?);
    if padded.len() != PADDED_LEN {
        return Err(CoreError::InvalidRecoveryKey("Recovery key doesn't consist of 66 bytes.".into()));
    }
    let mut raw = Zeroizing::new([0u8; 64]);
    raw.copy_from_slice(&padded[..64]);
    if padded[64..] != crc_suffix(&raw) {
        return Err(CoreError::InvalidRecoveryKey("Recovery key has invalid CRC.".into()));
    }
    Ok(raw)
}

pub fn validate_recovery_key(encoder: &WordEncoder, recovery_key: &str) -> bool {
    decode_recovery_key(encoder, recovery_key).is_ok()
}

/// `RecoveryKeyFactory.newMasterkeyFileWithPassphrase`: back up an existing masterkey file, then write a new one.
pub fn reset_password(encoder: &WordEncoder, vault_path: &Path, recovery_key: &str, new_passphrase: &str, rng: &mut dyn Rng) -> Result<()> {
    let raw = decode_recovery_key(encoder, recovery_key)?;
    let masterkey = Masterkey::from_raw(*raw);
    let masterkey_path = vault_path.join(MASTERKEY_FILENAME);
    if masterkey_path.exists() {
        let old_bytes = std::fs::read(&masterkey_path)?;
        let backup_path = vault_path.join(backup_file_name(MASTERKEY_FILENAME, &old_bytes));
        std::fs::rename(&masterkey_path, &backup_path)?;
    }
    MasterkeyFileAccess::new(Vec::new()).persist(&masterkey, &masterkey_path, new_passphrase, DEFAULT_MASTERKEY_FILE_VERSION, rng)
}
```

In `lib.rs` ergänzen: `pub mod recovery;`.

- [ ] **Step 5: Tests laufen lassen**

Run: `cargo test -p cryptomator-core recovery`
Expected: PASS (10 Tests)

- [ ] **Step 6: Commit**

```bash
git add crates/cryptomator-core
git commit -m "Add recovery key word encoding, validation and password reset

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 15: CLI-Kommando `crypto recovery-key validate`

**Files:**
- Create: `crates/crypto/src/cli.rs`
- Modify: `crates/crypto/src/main.rs`, `crates/crypto/tests/cli.rs`

**Interfaces:**
- Consumes: `cryptomator_core::recovery::{WordEncoder, validate_recovery_key}`.
- Produces: `crypto recovery-key validate --recovery-key-stdin` (liest stdin, trimmt, druckt `valid` / `invalid`; Exit 0 bzw. 4). Exit-Code-Konstanten in `main.rs` (`exit::INVALID_PASSPHRASE = 4`) werden von späteren Kommandos wiederverwendet.

- [ ] **Step 1: Fehlschlagende Tests schreiben**

```rust
// an crates/crypto/tests/cli.rs anhängen
const VALID_KEY: &str = "pathway lift abuse plenty export texture gentleman landscape beyond ceiling around leaf cafe charity border breakdown victory surely computer cat linger restrict infer crowd live computer true written amazed investor boot depth left theory snow whereby terminal weekly reject happiness circuit partial cup ad";

#[test]
fn recovery_key_validate_accepts_valid_key_from_stdin() {
    Command::cargo_bin("crypto")
        .unwrap()
        .args(["recovery-key", "validate", "--recovery-key-stdin"])
        .write_stdin(format!("{VALID_KEY}\n"))
        .assert()
        .success()
        .stdout("valid\n");
}

#[test]
fn recovery_key_validate_rejects_invalid_key_with_exit_code_4() {
    Command::cargo_bin("crypto")
        .unwrap()
        .args(["recovery-key", "validate", "--recovery-key-stdin"])
        .write_stdin("pathway lift\n")
        .assert()
        .code(4)
        .stdout("invalid\n");
}

#[test]
fn recovery_key_validate_requires_a_source() {
    Command::cargo_bin("crypto")
        .unwrap()
        .args(["recovery-key", "validate"])
        .assert()
        .code(2);
}
```

- [ ] **Step 2: Tests laufen lassen, Fehlschlag bestätigen**

Run: `cargo test -p crypto`
Expected: FAIL (Subcommand unbekannt)

- [ ] **Step 3: Implementieren**

```rust
// crates/crypto/src/cli.rs
//! Command grammar of `crypto`. Only the subcommands implemented so far are declared here.
use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "crypto", version, about = "Cryptomator vaults from the command line", arg_required_else_help = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Show, validate or use recovery keys
    #[command(name = "recovery-key")]
    RecoveryKey {
        #[command(subcommand)]
        command: RecoveryKeyCommand,
    },
}

#[derive(Subcommand, Debug)]
pub enum RecoveryKeyCommand {
    /// Check whether a recovery key is well-formed (dictionary words, length, checksum)
    Validate(ValidateArgs),
}

#[derive(Args, Debug)]
pub struct ValidateArgs {
    /// Read the recovery key from standard input
    #[arg(long, required = true)]
    pub recovery_key_stdin: bool,
}
```

```rust
// crates/crypto/src/main.rs
//! `crypto` – Cryptomator command line interface.
mod cli;

use clap::Parser;
use cli::{Cli, Command, RecoveryKeyCommand};
use cryptomator_core::recovery::{validate_recovery_key, WordEncoder};
use std::io::Read;
use std::process::ExitCode;

/// Exit codes as defined in the design spec.
pub mod exit {
    pub const OK: u8 = 0;
    pub const GENERAL: u8 = 1;
    pub const USAGE: u8 = 2;
    pub const INVALID_PASSPHRASE: u8 = 4;
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            let _ = err.print();
            return match err.kind() {
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion => ExitCode::from(exit::OK),
                _ => ExitCode::from(exit::USAGE),
            };
        }
    };
    match run(cli) {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(exit::GENERAL)
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<u8> {
    match cli.command {
        Command::RecoveryKey { command: RecoveryKeyCommand::Validate(args) } => {
            debug_assert!(args.recovery_key_stdin);
            let mut input = String::new();
            std::io::stdin().read_to_string(&mut input)?;
            let encoder = WordEncoder::new();
            if validate_recovery_key(&encoder, input.trim()) {
                println!("valid");
                Ok(exit::OK)
            } else {
                println!("invalid");
                Ok(exit::INVALID_PASSPHRASE)
            }
        }
    }
}
```

- [ ] **Step 4: Tests laufen lassen**

Run: `cargo test -p crypto`
Expected: PASS (5 Tests; der Test `no_arguments_prints_help_and_exits_with_usage_code` aus Task 1 bleibt gültig)

- [ ] **Step 5: Commit**

```bash
git add crates/crypto
git commit -m "Add crypto recovery-key validate command

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 16: Java-Fixture-Generator und Fixture-Lesetest

**Files:**
- Create: `tools/fixture-gen/pom.xml`, `tools/fixture-gen/src/main/java/org/cryptomator/cli/fixtures/Gen.java`, `tools/fixture-gen/README.md`
- Create: `tests/fixtures/<name>/…` (generiert, eingecheckt)
- Create: `crates/cryptomator-core/tests/fixtures_masterkey.rs`
- Modify: `.gitignore`

**Interfaces:**
- Produces: Referenz-Vaults, je mit `fixture.json` (`{"name","cipherCombo","shorteningThreshold","passphrase":"test-password-123","masterkeyHex"}`) und `expected.json` (Liste `{"path","type":"file|dir|symlink","size","sha256","target"}`); Rust-Test, der für jedes Fixture Masterkey lädt, Vault-Config verifiziert und `masterkeyHex` sowie Cipher-Combo vergleicht (Meilenstein M1).

- [ ] **Step 1: Maven-Projekt schreiben**

```xml
<!-- tools/fixture-gen/pom.xml -->
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.cryptomator.cli</groupId>
  <artifactId>fixture-gen</artifactId>
  <version>0.1.0</version>
  <properties>
    <maven.compiler.release>21</maven.compiler.release>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    <exec.mainClass>org.cryptomator.cli.fixtures.Gen</exec.mainClass>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.cryptomator</groupId>
      <artifactId>cryptofs</artifactId>
      <version>2.10.0</version>
    </dependency>
    <dependency>
      <groupId>com.google.code.gson</groupId>
      <artifactId>gson</artifactId>
      <version>2.13.2</version>
    </dependency>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-simple</artifactId>
      <version>2.0.17</version>
    </dependency>
  </dependencies>
  <build>
    <plugins>
      <plugin>
        <groupId>org.codehaus.mojo</groupId>
        <artifactId>exec-maven-plugin</artifactId>
        <version>3.5.0</version>
      </plugin>
    </plugins>
  </build>
</project>
```

```java
// tools/fixture-gen/src/main/java/org/cryptomator/cli/fixtures/Gen.java
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
 * Generates reference vaults with cryptofs 2.10.0. Usage: Gen gen <outputDir>
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
        if (args.length != 2 || !args[0].equals("gen")) {
            System.err.println("usage: Gen gen <outputDir>");
            System.exit(2);
        }
        Path out = Path.of(args[1]);
        Files.createDirectories(out);
        for (Spec spec : specs()) {
            generate(out.resolve(spec.name()), spec);
            System.out.println("generated " + spec.name());
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
```

```markdown
<!-- tools/fixture-gen/README.md -->
# fixture-gen

Java harness that creates reference vaults with the real cryptofs 2.10.0 / cryptolib 2.2.2 under `tests/fixtures/`.

Regenerate (JDK 21+, Maven):

    mvn -q -f tools/fixture-gen/pom.xml compile exec:java -Dexec.args="gen $(pwd)/tests/fixtures"

Regeneration changes nonces and salts but keeps each vault's masterkey (SHA-512 of the fixture name) and passphrase
`test-password-123`. Commit the result; Rust tests read the fixtures without Java.
```

`.gitignore` ergänzen: `/tools/fixture-gen/target`.

- [ ] **Step 2: Fixtures erzeugen**

Run: `mvn -q -f tools/fixture-gen/pom.xml compile exec:java -Dexec.args="gen $(pwd)/tests/fixtures" && ls tests/fixtures && cat tests/fixtures/siv_gcm_basic/fixture.json && du -sh tests/fixtures`
Expected: acht Fixture-Verzeichnisse (`siv_gcm_basic`, `siv_ctrmac_basic`, `long_names`, `threshold_36`, `symlinks`, `nested`, `sizes`, `unicode`), je mit `vault.cryptomator`, `masterkey.cryptomator`, `d/`, `fixture.json`, `expected.json`; Gesamtgröße unter 1 MB. Falls `Files.createSymbolicLink` in cryptofs eine `UnsupportedOperationException` wirft, die Symlink-Zeilen im Populator auf `fs.provider().createSymbolicLink(...)` umstellen; falls der Fehler bleibt, Symlink-Fixture auskommentieren und im README notieren.

- [ ] **Step 3: Fehlschlagenden Rust-Test schreiben**

```rust
// crates/cryptomator-core/tests/fixtures_masterkey.rs
//! Loads every Java-generated fixture: masterkey file + vault config must verify with our implementation.
use cryptomator_core::constants::{MASTERKEY_FILENAME, VAULTCONFIG_FILENAME, VAULT_VERSION};
use cryptomator_core::{CipherCombo, KeyId, MasterkeyFileAccess, UnverifiedVaultConfig};
use data_encoding::HEXLOWER;
use std::path::PathBuf;

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureMeta {
    name: String,
    cipher_combo: String,
    shortening_threshold: u32,
    passphrase: String,
    masterkey_hex: String,
}

fn fixture_dirs() -> Vec<PathBuf> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(&root)
        .expect("tests/fixtures exists (run tools/fixture-gen)")
        .map(|e| e.unwrap().path())
        .filter(|p| p.join("fixture.json").exists())
        .collect();
    dirs.sort();
    assert!(dirs.len() >= 8, "expected at least 8 fixtures, found {}", dirs.len());
    dirs
}

#[test]
fn every_fixture_unlocks_and_verifies() {
    for dir in fixture_dirs() {
        let meta: FixtureMeta = serde_json::from_slice(&std::fs::read(dir.join("fixture.json")).unwrap()).unwrap();
        let access = MasterkeyFileAccess::new(Vec::new());
        let masterkey = access.load(&dir.join(MASTERKEY_FILENAME), &meta.passphrase).unwrap_or_else(|e| panic!("{}: {e}", meta.name));
        assert_eq!(HEXLOWER.encode(masterkey.raw()), meta.masterkey_hex, "{}", meta.name);

        let token = std::fs::read_to_string(dir.join(VAULTCONFIG_FILENAME)).unwrap();
        let unverified = UnverifiedVaultConfig::decode(token.trim()).unwrap();
        assert_eq!(unverified.key_id().unwrap(), KeyId::MasterkeyFile { file_name: MASTERKEY_FILENAME.into() });
        let config = unverified.verify(masterkey.raw(), VAULT_VERSION).unwrap_or_else(|e| panic!("{}: {e}", meta.name));
        assert_eq!(config.cipher_combo, meta.cipher_combo.parse::<CipherCombo>().unwrap(), "{}", meta.name);
        assert_eq!(config.shortening_threshold, meta.shortening_threshold, "{}", meta.name);

        let wrong = access.load(&dir.join(MASTERKEY_FILENAME), "wrong password");
        assert!(matches!(wrong, Err(cryptomator_core::CoreError::InvalidPassphrase)), "{}", meta.name);
    }
}

#[test]
fn root_directory_of_every_fixture_exists_under_hashed_name() {
    use cryptomator_core::crypto::siv::FileNameCryptor;
    for dir in fixture_dirs() {
        let meta: FixtureMeta = serde_json::from_slice(&std::fs::read(dir.join("fixture.json")).unwrap()).unwrap();
        let masterkey = MasterkeyFileAccess::new(Vec::new()).load(&dir.join(MASTERKEY_FILENAME), &meta.passphrase).unwrap();
        let hash = FileNameCryptor::new(&masterkey).hash_directory_id("");
        let root = dir.join("d").join(&hash[..2]).join(&hash[2..]);
        assert!(root.is_dir(), "{}: root content dir {} missing", meta.name, root.display());
        assert!(root.join("dirid.c9r").is_file(), "{}: dirid.c9r missing", meta.name);
    }
}
```

`crates/cryptomator-core/Cargo.toml` unter `[dev-dependencies]` ergänzen: `serde.workspace = true`, `serde_json.workspace = true`, `data-encoding.workspace = true` (serde/serde_json/data-encoding sind bereits normale Dependencies; Integrationstests sehen sie nur, wenn sie explizit auch als dev-dependency oder über die Crate re-exportiert sind – am einfachsten die drei Zeilen zusätzlich unter `[dev-dependencies]` eintragen).

- [ ] **Step 4: Test laufen lassen, Fehlschlag bestätigen**

Run: `cargo test -p cryptomator-core --test fixtures_masterkey`
Expected: FAIL, falls Fixtures fehlen oder ein Modul nicht exportiert ist; sonst PASS (dann ist Step 5 der Nachweis).

- [ ] **Step 5: Test laufen lassen (alle Fixtures verifizieren)**

Run: `cargo test -p cryptomator-core --test fixtures_masterkey`
Expected: PASS (2 Tests, 8 Fixtures). Ein Fehlschlag hier bedeutet eine Abweichung vom Java-Format und muss im betroffenen Modul (Task 6, 7 oder 12) behoben werden, nicht im Test.

- [ ] **Step 6: Gesamtlauf und Commit**

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
Expected: PASS

```bash
git add tools/fixture-gen tests/fixtures crates/cryptomator-core .gitignore
git commit -m "Add Java fixture generator and fixture-based masterkey/config verification

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

## Selbstprüfung (durchgeführt beim Schreiben)

- **Spec-Abdeckung M0:** Workspace/Lizenz/CI (Task 1), Spike B (Task 2), Spike A (Task 3), `cargo tree -d` wurde am 2026-09-04 bereits mit exakt der Dependency-Menge aus Task 1 geprüft: keine doppelten Crate-Generationen. Spec ins Repo: erledigt (Commit e988c7c).
- **Spec-Abdeckung M1:** masterkey (4), scrypt/keywrap (5), Masterkey-Datei (6), SIV-Namen (7), Header/Content beider Schemata (8, 9), Cryptor + Größenmathematik (10), Streams (11), Vault-Config-JWT (12), Backups (13), Recovery-Wörter/Key (14), `recovery-key validate` (15), Fixture-Generator + Masterkey-Load aller Fixtures (16). `vectors.json` aus der Spec ist durch die eingebetteten Konstanten in den Modultests ersetzt; die Rohdaten liegen in diesem Plan.
- **Typkonsistenz:** `Masterkey::{raw, enc_key, mac_key}` (Task 4) werden in 6, 7, 8, 9, 12, 14, 16 identisch verwendet; `FileHeader::{nonce, content_key, reserved, encode_payload, decode_payload}` (8) in 9–11; `Rng`/`DetRng::{default, starting_at}` (4) überall; `CipherCombo::{as_str, FromStr}` (10) in 12 und 16; `backup_file_name`/`generate_file_id_suffix` (13) in 14; `MasterkeyFileAccess::{load, persist}` (6) in 14 und 16; `KeyId::MasterkeyFile { file_name }` (12) in 16.
- **Platzhalter:** keine; die Spike-Dokumente enthalten bewusst auszufüllende Ergebnisfelder in spitzen Klammern, die beim Durchführen ersetzt werden.

## Ausführung

Empfohlen: `superpowers:subagent-driven-development` – ein frischer Subagent pro Task, Review zwischen den Tasks. Alternative: `superpowers:executing-plans` in dieser Session. Task 3 (Spike A) kann erst nach Installation von FUSE-T oder macFUSE vollständig ausgeführt werden; die übrigen Tasks sind davon unabhängig.
