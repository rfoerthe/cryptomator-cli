# Spike A: FUSE-T / macFUSE über dlopen + fuser::Session::from_fd

> **Nachtrag (M4):** Option 1 der Konsequenz unten wurde umgesetzt und bewiesen —
> `docs/superpowers/spikes/2026-09-06-spike-c-fuse-t-linux-abi.md` (**Spike C**) mountet FUSE-T
> erfolgreich mit `KernelAbi::Linux` aus dem Fork `vendor/fuser`. Der Schalter ist eine
> Laufzeit-Entscheidung (`Config::abi`) statt eines Features, damit ein Binary macFUSE und FUSE-T
> bedient. macFUSE bleibt unverifiziert (nach wie vor nicht installiert). Das
> Ergebnis „NO-GO“ unten gilt also für **unverändertes** fuser 0.18 und ist mit dem Fork überholt.

Frage: Liefert `fuse_mount_compat25` aus `libfuse-t.dylib` einen fd, über den fuser 0.18 das Kernel-FUSE-Protokoll sprechen kann?

Setup: `cargo run -p cryptomator-mount --example spike_macos_dlopen -- <fuse-t|macfuse> /tmp/spike-mnt`

Umgebung: macOS 26.6.2 (Build 25G83), Apple Silicon, Rust-Workspace `crypto`, fuser 0.18.0 (`macos-no-mount`), libloading 0.9.

| Backend | Installiert (Version) | fuse_mount fd | Handshake | cat hello.txt | umount | Ergebnis |
|---|---|---|---|---|---|---|
| FUSE-T | ja (1.2.7, `/usr/local/lib/libfuse-t.dylib` → `libfuse-t-1.2.7.dylib`) | ok (fd = 4) | ok (`proto=7.19`, von FUSE-T als `client=libfuse3` erkannt) | fehler (Mount erscheint nie in der mount-Tabelle) | entfällt (nie gemountet) | **NO-GO** |
| macFUSE | nein (`/usr/local/lib/libfuse.2.dylib` fehlt) | — | — | — | — | **BLOCKED** |

## Beobachtungen

### macFUSE — BLOCKED

macFUSE ist nicht installiert; der Spike bricht wie vorgesehen ab:

```
$ ./target/debug/examples/spike_macos_dlopen macfuse /tmp/spike-mnt-macfuse
/usr/local/lib/libfuse.2.dylib not found – install FUSE-T (brew install --cask macos-fuse-t/homebrew-cask/fuse-t) or macFUSE
EXIT=2
```

Nachzuholen, sobald macFUSE installiert ist (Installation ist eine Nutzerentscheidung, Kext/System-Extension war für diesen Spike out of scope):

```bash
# macFUSE installieren (Nutzerentscheidung, erfordert System-Extension-Freigabe)
brew install --cask macfuse
mkdir -p /tmp/spike-mnt
cargo run -p cryptomator-mount --example spike_macos_dlopen -- macfuse /tmp/spike-mnt
# zweite Shell:
cat /tmp/spike-mnt/hello.txt; umount /tmp/spike-mnt
```

### FUSE-T — NO-GO, aber nicht am Transportweg

Der dlopen-Pfad selbst funktioniert vollständig:

```
$ ./target/debug/examples/spike_macos_dlopen fuse-t /tmp/spike-mnt
mounted at /tmp/spike-mnt; in another shell run: cat /tmp/spike-mnt/hello.txt && umount /tmp/spike-mnt
spike failed: Invalid request
EXIT=1
```

Reproduzierbar über alle Läufe. Im Detail (mit einem temporären Diagnose-Beispiel und aktiviertem `log`-Logger ermittelt, nicht eingecheckt):

1. `fuse_mount_compat25` liefert einen gültigen fd (`fd = 4`).
2. `Session::from_fd` schließt den Handshake **erfolgreich** ab. FUSE-T bestätigt das in seinem eigenen Log (`~/Library/Logs/fuse-t/fuse-t.log`):
   `fuse session negotiated profile=v3 client=libfuse3 proto=7.19 max_write=16777216 flags=0xe0000001`
3. FUSE-T startet seinen NFS-Server (`Server version 1.2.7 running at 127.0.0.1:52100`) und schickt echte Kernel-FUSE-Requests über den fd, die fuser korrekt zustellt: `STATFS`, `GETATTR` (jeweils zweimal auf Inode 1).
4. Direkt nach der `GETATTR`-Antwort bricht FUSE-T die Verbindung ab (`Connection closed`); der fd liefert EOF. fuser meldet das als `Short read of FUSE request header (0 < 40)` und daraus resultierend `Invalid request` — die Fehlermeldung ist also irreführend, es ist ein **EOF**, kein Parse-Fehler auf unserer Seite.

Der eigentliche Grund steht in FUSE-Ts Debug-Log — FUSE-T dekodiert unsere `GETATTR`-Antwort falsch:

```
Getattr reply: {136 0 6}, {AttrValid:1 AttrValidNsec:0 Dummy:0 Attr:{Ino:1 Size:0 Blocks:1
  Atime:0 Mtime:0 Ctime:0 Crtime:0 Atimensec:0 Mtimensec:0 Ctimensec:0 Crtimensec:0
  Mode:0 Nlink:0 Uid:0 Gid:16877 Rdev:1 Flags:20 Blksize:501 Padding:0}}
```

Gesendet hatte der Spike `mode=0o40755 (=16877)`, `nlink=1`, `uid=501`, `gid=20`, `rdev=0`, `flags=0`, `blksize=512`. Die Werte landen um genau drei `u32`-Felder verschoben in FUSE-Ts Struktur.

**Root Cause: `fuse_attr`-Layout-Mismatch.** fuser aktiviert unter `#[cfg(target_os = "macos")]` die macFUSE-Variante von `fuse_attr` (`src/ll/fuse_abi.rs`) mit den Zusatzfeldern `crtime: u64`, `crtimensec: u32` und `flags: u32` **vor** `blksize` — insgesamt 104 Bytes. FUSE-T liest dagegen das **Linux**-Layout (88 Bytes, ohne `crtime`/`crtimensec`, `blksize` vor `flags`), passend dazu, dass es unseren Client als `libfuse3` erkennt. Rechnet man unseren Puffer gegen die Linux-Offsets, stimmen alle beobachtbaren Felder exakt:

| FUSE-T-Feld | Linux-Offset | Wert an diesem Offset in fusers macOS-Layout | von FUSE-T gemeldet |
|---|---|---|---|
| Mode | 60 | `mtimensec` = 0 | 0 |
| Nlink | 64 | `ctimensec` = 0 | 0 |
| Uid | 68 | `crtimensec` = 0 | 0 |
| Gid | 72 | `mode` = 16877 | 16877 |
| Rdev | 76 | `nlink` = 1 | 1 |
| Blksize | 80 | `uid` = 501 | 501 |
| Flags | 84 | `gid` = 20 | 20 |

Weil `Mode` dadurch als `0` ankommt, ist die Root-Inode für FUSE-T weder Verzeichnis noch sonst ein gültiger Typ — FUSE-T bricht den Mount ab. In der mount-Tabelle erscheint nie etwas, `cat`/`umount` sind entsprechend nicht durchführbar.

Ausgeschlossene Nebenursachen (jeweils einzeln getestet):

- **Nicht** die ausgehandelte Minor-Version: FUSE-T bietet 7.23 an; INIT-Antworten mit Minor 19/23 und Länge 40/80 Bytes führen alle zu identischem, sauberem Nachrichtenfluss.
- **Nicht** `statfs`: Auch mit realistischen Werten statt fusers Default (0 Blöcke) bricht FUSE-T an derselben Stelle ab.
- **Nicht** der Mountpoint: `/tmp/spike-mnt` und `$HOME/spike-mnt` verhalten sich gleich.
- **Nicht** die Sandbox der Entwicklungsumgebung: identisches Ergebnis mit deaktivierter Sandbox.
- **Nicht** fehlende Mount-Rechte: ein manueller `mount -t nfs` als normaler Nutzer scheitert mit `Connection refused` (also erlaubt), nicht mit `Operation not permitted`.
- **Anmerkung zum Brief:** die vorgegebene Option `-o backend=smb` ist auf diesem System ohnehin unbrauchbar — FUSE-T 1.2.7 liefert nur den NFS-Helper (`/Library/Application Support/fuse-t/bin/go-nfsv4`), kein SMB-Backend. Mit `backend=smb` scheitert schon FUSE-Ts eigener Mount-Aufruf (`mount -t smbfs …`, `exit status 64`). Der Spike-Code behält die Option laut Brief bei; die Diagnose oben wurde zusätzlich mit dem Default-Backend (NFS) durchgeführt, das weiter kommt (`STATFS`+`GETATTR` statt nur `GETATTR`) und den Root Cause offenlegt.

## Konsequenz für M4

**Lowlevel-/ABI-Anpassung für FUSE-T einplanen — der reine dlopen-Pfad mit unverändertem fuser 0.18 reicht nicht.**

Wichtige Nuance für die Planung: Transport und Handshake sind *nicht* das Problem. `dlopen` → `fuse_mount_compat25` → `fuser::Session::from_fd` funktioniert, und über den fd fließt echtes Kernel-FUSE-Protokoll in beide Richtungen. Das Hindernis ist ausschließlich das **Struct-ABI der Antworten**: FUSE-T erwartet die Linux-Varianten, fuser erzeugt unter macOS die macFUSE-Varianten. Optionen:

1. **fuser mit Linux-ABI unter macOS** (bevorzugt, kleinster Eingriff): Fork/Patch, der die `#[cfg(target_os = "macos")]`-Felder in `fuse_abi.rs` abschaltbar macht, damit `Session::from_fd` gegen FUSE-T das Linux-Layout schreibt. Betrifft mindestens `fuse_attr`; die übrigen `#[cfg(target_os = "macos")]`-Strukturen sind vor der Umsetzung durchzusehen. Upstream-tauglich als Feature-Flag (z. B. `abi-linux`).
2. **Eigenes `fuse_lowlevel_ops`-FFI-Backend** für FUSE-T, wie in der Spec als Fallback vorgesehen — deutlich mehr Aufwand, dafür unabhängig von fusers ABI-Entscheidungen.
3. **macFUSE-Pfad** bleibt vom Root Cause unberührt und ist mit fuser wie geplant plausibel (macFUSE nutzt genau das ABI, das fuser unter macOS erzeugt) — **noch nicht verifiziert**, da macFUSE nicht installiert ist. Das ist der nächste Spike-Schritt, sobald der Nutzer macFUSE installiert.

## Reproduktion

```bash
mkdir -p /tmp/spike-mnt
cargo run -p cryptomator-mount --example spike_macos_dlopen -- fuse-t /tmp/spike-mnt
tail -f ~/Library/Logs/fuse-t/fuse-t.log   # FUSE-Ts Sicht; mit -o debug deutlich gesprächiger
```
