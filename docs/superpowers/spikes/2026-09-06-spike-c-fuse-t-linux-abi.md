# Spike C: FUSE-T mit dem Linux-ABI der fuser-Session

Frage: Mountet FUSE-T, wenn `fuser::Session::from_fd` mit `Config { abi: KernelAbi::Linux, .. }`
läuft — also mit den Linux-Struct-Layouts statt der macFUSE-Layouts? Spike A hatte das
`fuse_attr`-Layout als Root Cause des gescheiterten Mounts identifiziert (NO-GO); Task 1 hat den
Laufzeit-Schalter in den Fork `vendor/fuser` eingebaut. Spike C ist der End-to-End-Beweis.

## Setup

Umgebung: macOS 26.6.2 (Build 25G83), Apple Silicon, rustc 1.98.0, Workspace `crypto`,
`vendor/fuser` (fuser 0.18.0 + Linux-ABI-Patch), libloading 0.9.
FUSE-T 1.2.7 (`/usr/local/lib/libfuse-t.dylib`), macFUSE **nicht** installiert.

Änderungen am Spike-Beispiel gegenüber Spike A
(`crates/cryptomator-mount/examples/spike_macos_dlopen.rs`):

- `fuse-t`: Optionen nur noch `["-o", "nonamedattr"]` — `-o backend=smb` ist raus (FUSE-T 1.2.7
  liefert auf diesem System kein SMB-Backend, siehe Spike A), `config.abi = KernelAbi::Linux`.
- `macfuse`: unverändert `["-o", "noappledouble"]` und `KernelAbi::Native`.
- Root-Inode meldet `nlink: 2` (`.` plus der Eintrag im Elternverzeichnis).
- `statfs` implementiert: `reply.statfs(1_000_000, 500_000, 500_000, 1000, 500, 4096, 255, 4096)`.
  FUSE-T schickt STATFS als allererste Operation und vor **jedem** GETATTR.

```bash
mkdir -p /tmp/spike-c-mnt
cargo run -p cryptomator-mount --example spike_macos_dlopen -- fuse-t /tmp/spike-c-mnt &
sleep 5
mount | grep spike-c-mnt
cat /tmp/spike-c-mnt/hello.txt
ls -la /tmp/spike-c-mnt
umount /tmp/spike-c-mnt
```

## Ergebnis

| Backend | Version | mount fd | Handshake | mount-Tabelle | `cat` | `ls -la` | `umount` | Ergebnis |
|---|---|---|---|---|---|---|---|---|
| FUSE-T (`KernelAbi::Linux`) | 1.2.7 | ok | ok (`proto=7.19`, `client=libfuse3`) | ok (`fuse-t:/crypto-spike … (nfs, nodev, nosuid, mounted by rfoerthe)`) | ok (`Hello from crypto spike A!`) | ok (`drwxr-xr-x`, uid/gid 501/20, `nlink 2`) | ok, Programm endet mit `session ended (unmounted)` | **GO** |
| FUSE-T (`KernelAbi::Native`) | 1.2.7 | ok | ok | — | — | — | — | NO-GO (Spike A) |
| macFUSE | nicht installiert | — | — | — | — | — | — | BLOCKED (unverändert) |

## Beobachtungen

### Verbatim-Ausgaben des GO-Laufs

```
$ mount | grep spike-c-mnt
fuse-t:/crypto-spike on /private/tmp/spike-c-mnt (nfs, nodev, nosuid, mounted by rfoerthe)

$ cat /tmp/spike-c-mnt/hello.txt
Hello from crypto spike A!

$ ls -la /tmp/spike-c-mnt
total 4000001
drwxr-xr-x   2 rfoerthe  staff     0 Jan  1  1970 .
drwxrwxrwt  57 root      wheel  1824 Sep  6 10:01 ..
-r--r--r--   1 rfoerthe  staff    27 Jan  1  1970 hello.txt

$ ls -lan /tmp/spike-c-mnt
total 4000001
drwxr-xr-x   2 501  20     0 Jan  1  1970 .
drwxrwxrwt  57 0    0   1824 Sep  6 09:59 ..
-r--r--r--   1 501  20    27 Jan  1  1970 hello.txt

$ stat -f '%N mode=%Sp uid=%u gid=%g nlink=%l size=%z' /tmp/spike-c-mnt /tmp/spike-c-mnt/hello.txt
/tmp/spike-c-mnt mode=drwxr-xr-x uid=501 gid=20 nlink=2 size=0
/tmp/spike-c-mnt/hello.txt mode=-r--r--r-- uid=501 gid=20 nlink=1 size=27

$ df -h /tmp/spike-c-mnt
Filesystem              Size    Used   Avail Capacity iused ifree %iused  Mounted on
fuse-t:/crypto-spike   3.8Gi   1.9Gi   1.9Gi    50%     500   500   50%   /private/tmp/spike-c-mnt

$ umount /tmp/spike-c-mnt        # rc=0

# Ausgabe des Spike-Programms:
mounted at /tmp/spike-c-mnt; in another shell run: cat /tmp/spike-c-mnt/hello.txt && umount /tmp/spike-c-mnt
session ended (unmounted)

$ mount | grep spike             # leer, rc=1
```

Attribute sind vollständig korrekt: `drwxr-xr-x` für das Root-Verzeichnis, `-r--r--r--` für
`hello.txt`, uid 501 / gid 20 (die realen Werte aus `geteuid`/`getegid`), `nlink` 2 bzw. 1,
Größe 27 = `len("Hello from crypto spike A!\n")`. `df` spiegelt die `statfs`-Antwort:
1 000 000 × 4096 = 3,8 GiB, 500 000 frei, 500 von 1000 Inodes belegt.

### Der Beweis im FUSE-T-Log

Mit `-o debug` (nur für die Diagnose ergänzt, nicht eingecheckt) protokolliert FUSE-T jede
Antwort. Dieselbe GETATTR-Antwort, die in Spike A um drei `u32` verschoben ankam, wird jetzt
korrekt dekodiert:

```
# Spike A (KernelAbi::Native), FALSCH:
wire: recv body unique=6 payload=120
Getattr reply: … Mode:0 Nlink:0 Uid:0 Gid:16877 Rdev:1 Flags:20 Blksize:501 Padding:0

# Spike C (KernelAbi::Linux), RICHTIG:
wire: recv body unique=4 payload=104
Getattr reply: {120 0 4}, {AttrValid:1 AttrValidNsec:0 Dummy:0 Attr:{Ino:1 Size:0 Blocks:1
  Atime:0 Mtime:0 Ctime:0 Crtime:0 Atimensec:0 Mtimensec:0 Ctimensec:0 Crtimensec:0
  Mode:16877 Nlink:2 Uid:501 Gid:20 Rdev:0 Flags:0 Blksize:512 Padding:0}}
```

`payload` 120 → 104 ist die Nutzlast von `fuse_attr_out` (16 Byte Präfix + `fuse_attr`): 104 Byte
macFUSE-Layout vs. 88 Byte Linux-Layout. `Mode:16877` ist `0o40755`, also endlich ein
Verzeichnis — genau der Wert, an dem FUSE-T in Spike A gescheitert ist.

### Was FUSE-T mountet und schickt

```
Mounting: /tmp/spike-c-mnt
mount [-o port=52100,mountport=52100,vers=4 -t nfs fuse-t:/crypto-spike /tmp/spike-c-mnt]
```

FUSE-T übersetzt FUSE nach NFSv4 und mountet per `mount -t nfs` gegen seinen eigenen
Loopback-Server. Daher taucht der Mount als `nfs` in der `mount`-Tabelle auf, nicht als `fusefs`,
und `umount` ist ein ganz normaler NFS-`umount` — kein `umount -f`, keine Root-Rechte.

Opcode-Statistik eines vollständigen Laufs (Mount + `cat` + `ls -la` + `umount`):

| Opcode | Name | Anzahl |
|---|---|---|
| 3 | GETATTR | 33 |
| 17 | STATFS | 22 |
| 1 | LOOKUP | 11 |
| 28 | READDIR | 2 |
| 27 / 29 | OPENDIR / RELEASEDIR | je 1 |
| 14 / 15 / 25 / 18 | OPEN / READ / FLUSH / RELEASE | je 1 |

Bemerkenswert:

- **STATFS + GETATTR vor fast jeder NFS-Operation.** FUSE-T holt sich `StatFS 1` und `GetAttr 1`
  vor jedem NFSv4-COMPOUND (`mount`, `secinfo`, `statfs`, `pathconf`, `lookup`, `access`, …).
  Deshalb ist `statfs` kein „nice to have": fusers Default meldet 0 Blöcke, und das sieht für den
  NFS-Client wie ein volles/kaputtes Dateisystem aus.
- **macOS-Metadaten-Rauschen.** LOOKUPs, die es nie geben wird, aber beantwortet werden müssen
  (alle mit `ENOENT`): `._.` (2×), `.DS_Store`, `.hidden`, `.Spotlight-V100`,
  `.metadata_never_index`, `.metadata_never_index_unless_rootfs`,
  `.metadata_direct_scope_only`, `Applications`, `DCIM`. Die `._`-Anfragen kommen trotz
  `-o nonamedattr` — die Option unterdrückt Named Streams (AppleDouble als Extended Attributes),
  nicht die Suche des Finders/`ls` nach AppleDouble-Sidecar-Dateien.
- **Kein READDIRPLUS (44), kein GETXATTR (22)** in diesem Lauf — der Adapter darf sich darauf
  aber nicht verlassen; beide Pfade sind im Fork bereits umgestellt.
- `umount` erzeugt **kein** FUSE_DESTROY: FUSE-T schließt schlicht die Verbindung
  (`Connection closed`).

### Zusätzlicher Fork-Patch: EOF beendet die Session sauber

Der Mount und `cat` funktionierten sofort mit dem Task-1-Fork; nur der Ausstieg nicht. Beim ersten
Lauf endete das Programm mit

```
spike failed: Invalid request
```

statt mit `session ended (unmounted)`. Ursache ist kein ABI-Problem, sondern der Transport:
`/dev/fuse` liefert beim Unmount `ENODEV`, und genau das behandelt fuser als sauberes Ende
(`session.rs`, `Err(Errno::ENODEV) => return Ok(())`). FUSE-Ts Kanal ist dagegen ein Socket, das
beim Unmount einfach geschlossen wird — `read()` liefert **0**. fuser reichte diese 0 Bytes an
`RequestWithSender::new` weiter, das erwartungsgemäß `None` liefert, woraus der Event-Loop
`io::ErrorKind::InvalidData` / „Invalid request" machte. (Dieselbe irreführende Meldung wie in
Spike A, dort aber mit dem `fuse_attr`-Mismatch als eigentlicher Ursache.)

Patch in `vendor/fuser/src/session.rs`: `Ok(0)` beendet `SessionEventLoop::event_loop` mit
`Ok(())`; im Handshake führt `Ok(0)` zum bestehenden `NotConnected`-Fehler. Ein Read von 0 Byte
kann nie eine gültige FUSE-Anfrage sein, auf Linux tritt der Fall nicht auf — der Patch ist dort
also ein No-op.

Abgesichert durch einen End-to-End-Test über ein `socketpair`
(`vendor/fuser/src/session.rs::abi_session_test::linux_abi_session_answers_getattr_and_ends_cleanly_on_eof`):
INIT → GETATTR (Antwort muss 88-Byte-`fuse_attr` mit `mode` @60, `nlink` @64, `uid` @68, `gid` @72,
`blksize` @80 sein) → Peer schließen → `Session::run()` muss `Ok(())` liefern. Ohne den Patch
schlägt der Test mit exakt `Err(Custom { kind: InvalidData, error: "Invalid request" })` fehl.

Weitere `#[cfg(target_os = "macos")]`-Abweichungen mussten **nicht** angefasst werden. Geprüft
wurden alle in diesem Lauf benutzten Strukturen gegen `fuse_kernel.h` von libfuse 3:
`fuse_init_out` (identisch), `fuse_statfs_out`/`fuse_kstatfs` (identisch — FUSE-T dekodiert die
Antwort verbatim, siehe `Statfs reply` oben), `fuse_open_out` (identisch), `fuse_read_in`,
`fuse_write_in`, `fuse_dirent` (alle identisch). In `fuse_abi.rs` bleiben als macOS-Sonderfälle nur
die Strukturen, die Task 1 bereits mit Linux-Zwillingen versehen hat (`fuse_attr` und alles, was
sie einbettet, sowie `fuse_setattr_in`, `fuse_getxattr_in`, `fuse_setxattr_in`), plus die
Darwin-only-Opcodes `FUSE_SETVOLNAME`/`FUSE_GETXTIMES`/`FUSE_EXCHANGE`, die FUSE-T nie schickt.

## Konsequenz für M4

**Der Weg ist frei: `dlopen(libfuse-t.dylib)` → `fuse_mount_compat25` → `Session::from_fd` mit
`KernelAbi::Linux` ist ein tragfähiges FUSE-T-Backend.** Ein eigenes `fuse_lowlevel_ops`-FFI-Backend
(Fallback-Option 2 aus Spike A) wird nicht gebraucht.

Für die Adapter-Task (Task 6/7) daraus:

1. **`abi` gehört ans Backend, nicht an die Plattform.** FUSE-T ⇒ `KernelAbi::Linux`,
   macFUSE ⇒ `KernelAbi::Native`. Der Wert muss aus derselben Stelle kommen, die entscheidet,
   welche `.dylib` geladen wird.
2. **Umgestellte Strukturen** (aus Task 1, hier bestätigt): `fuse_attr` und alles, was sie
   einbettet — `fuse_entry_out`, `fuse_attr_out`, `fuse_create_out`, `fuse_direntplus` — sowie
   auf der Anfrageseite `fuse_setattr_in`, `fuse_getxattr_in` (auch für LISTXATTR) und
   `fuse_setxattr_in`. Alles andere ist zwischen macFUSE und Linux gleich.
3. **`statfs` ist Pflicht.** FUSE-T fragt STATFS vor praktisch jeder Operation; die Default-Antwort
   von fuser (0 Blöcke) reicht nicht. Der Vault-Adapter sollte echte Werte des Backing-Store
   melden.
4. **`nlink` für Verzeichnisse.** Root mit `nlink: 1` war in der Spike-A-Fassung mit drin; der
   NFSv4-Pfad ist damit zwar nicht gescheitert, korrekt ist aber `2 + Anzahl Unterverzeichnisse`.
5. **AppleDouble-/Spotlight-Rauschen abfangen.** `._*`, `.DS_Store`, `.hidden`, `.Spotlight-V100`,
   `.metadata_*` werden bei jedem Verzeichniszugriff angefragt. `-o nonamedattr` verhindert das
   nicht. Für einen verschlüsselten Vault heißt das: diese Namen müssen entweder schnell mit
   `ENOENT` beantwortet werden (kein Roundtrip in die Verschlüsselung) oder — falls sie erlaubt
   sein sollen — ganz normal als Dateien im Vault landen. Ein negativer Lookup-Cache im Adapter
   wäre hier lohnend.
6. **Unmount = EOF.** Kein FUSE_DESTROY. Der Daemon muss ein `Ok(())` aus `Session::run()` als
   „sauber unmountet" werten und darf nicht auf `Destroy` warten. Der Fork-Patch oben stellt das
   sicher.
7. **Der Mount ist ein NFS-Mount.** In der `mount`-Tabelle steht `nfs`, der Mountpoint erscheint
   unter `/private/tmp/...`. Wer den Mount-Status per `mount`/`statfs` prüft, darf nicht auf
   `fusefs` als Dateisystemtyp testen. `umount` ohne Sonderrechte genügt.

## E2E-Befunde (Task 8, echter Mount eines Vaults)

Task 8 mountet erstmals einen echten Vault durch den fertigen Provider
(`crates/cryptomator-mount/tests/mount_e2e.rs`, FUSE-T 1.2.7, macOS 26.6.2). Was dabei über die
Spike-Beobachtungen hinaus auffiel:

1. **Der Kanal ist ein Stream-Socket — Message-Framing muss der Leser machen.** `SO_TYPE` des von
   `fuse_mount_compat25` gelieferten Deskriptors ist `SOCK_STREAM` (RCVBUF/SNDBUF je 4 MiB).
   fuser behandelt jeden `read` als genau einen Request; auf einem Stream-Socket stimmt das in
   **beide** Richtungen nicht:
   * **Zu wenig:** FUSE-T schickt einen WRITE als **zwei** `write()`s (`wire: send unique=31
     opcode=16 … bytes=80` + `wire: send data bytes=4096`). Ein einzelner `read` lieferte nur die
     ersten 80 Bytes; der Parser sah einen Request ohne Nutzdaten, die Antwort blieb aus, der
     NFS-Client wartete ~40 s pro Schreibvorgang und die Session war danach tot. Intermittierend,
     weil die beiden `write()`s meist im Socket-Puffer verschmelzen — bei 10 KiB Nutzlast fiel es
     nie auf, bei 100 KiB immer.
   * **Zu viel:** genau dieses Verschmelzen trifft auch **zwei aufeinanderfolgende Requests**. Der
     Event-Loop beantwortete den ersten und verwarf den zweiten stillschweigend; auf dessen Antwort
     wartete der Client ewig, der Mount stand. Symptom im E2E-Test: „the mount stopped answering:
     no result within 30 s“, danach hing der Testprozess in einem unterbrechbaren `U`-State auf dem
     Mountpoint. Trat in ~1 von 5 Läufen auf und wurde erst durch Wiederholungsläufe sichtbar.
   Fix im Fork: `Channel::receive_retrying` liefert **genau einen** Request — es liest weiter, bis
   der Puffer die im `fuse_in_header` angekündigte `len` enthält, und hebt alles darüber hinaus
   Gelesene in `Channel::spill` für den nächsten Aufruf auf (`vendor/fuser/src/channel.rs`, Tests
   `session::abi_session_test::a_request_split_across_two_writes_is_read_as_one` und
   `…::two_requests_that_arrive_in_one_read_are_both_answered`). Auf `/dev/fuse` ist beides ein
   No-op: dort liefert jeder `read` genau einen vollständigen Request, der Spill-Puffer bleibt leer.
   **Konsequenz für jeden weiteren Socket-Transport: Message-Framing ist Pflicht — in beide
   Richtungen.**
2. **macOS' NFS-Client legt zu jedem neuen Knoten eine AppleDouble-Sidecar-Datei `._<name>` an.**
   Nach `mkdir docs` folgt sofort ein `Create` von `._docs`, nach jeder Datei ein `._datei`, auch
   für Symlinks. Ohne Gegenmaßnahme landet für jeden Knoten ein zusätzlicher verschlüsselter
   Eintrag im Vault. `-ononamedattr` ändert daran nichts (mit **und** ohne die Option identisch);
   macFUSE verhindert das mit `-onoappledouble` im Kernel, FUSE-T hat kein Gegenstück.
   Fix im Adapter: `VaultOpsConfig::refuse_apple_double` (bei FUSE-T an) beantwortet
   `create`/`mkdir`/`symlink`/`rename` auf `._*` mit `EPERM` — derselbe Errno, den macFUSEs
   Kernel-Extension liefert. Der Client verwirft die Sidecar-Datei und die eigentliche Operation
   des Nutzers bleibt erfolgreich; der Vault bleibt sauber. `.DS_Store` ist bewusst **nicht**
   betroffen (das schreibt der Finder für den Nutzer; dafür gibt es den `rmdir`-Sweep).
   Die Sidecar-Datei wird vom Client übrigens mitgelöscht, wenn ihr Knoten verschwindet — ein
   `rmdir` eines gerade angelegten Verzeichnisses scheitert also nicht daran.
3. **`ro` wird akzeptiert.** Ein read-only-Mount (`-o ro` an `fuse_mount_compat25`) erscheint als
   `fuse-t:/e2e-ro on … (nfs, nodev, nosuid, read-only, mounted by rfoerthe)`; `write(2)` und
   `mkdir(2)` scheitern mit **EROFS (30)**, Lesen funktioniert. Der Adapter-EROFS bleibt als
   zweite Verteidigungslinie erhalten.
4. **Der Mount erscheint asynchron in der Mount-Tabelle.** `fuse_mount_compat25` kehrt zurück,
   sobald der Server lauscht; das `mount -t nfs` läuft danach. Wer sofort `umount` ruft, bekommt
   „not currently mounted", die Session läuft weiter und der Mount taucht danach auf. Der E2E-Test
   wartet deshalb (bis 20 s) auf `is_mountpoint`. Für Task 9/10 heißt das: nach `mount()` erst auf
   die Mount-Tabelle warten, bevor der Zustand als „gemountet" gemeldet wird.
5. **Mountpoint-Pfade sind kanonisiert.** Ein Tempdir unter `/var/folders/...` steht als
   `/private/var/folders/...` in der Tabelle; `mounttab::is_mountpoint` kanonisiert beide Seiten
   und trifft deshalb.
6. **NFSv4-Locking wird von FUSE-T nicht implementiert** (`Implement txLockCommon`,
   `Implement txLocku`, `opReleaseLockowner: implement` im Log, bei jedem Schreibvorgang). Der
   Client kommt trotzdem klar; Byte-Range-Locks über den Mount sind also nicht zu erwarten.
7. **Restrauschen wie in Spike C:** `._.`, `.DS_Store`, `.hidden`, `.Spotlight-V100`, `Applications`,
   `DCIM` werden weiter angefragt und mit `ENOENT` beantwortet; STATFS läuft weiter vor fast jeder
   Operation. Nach beiden Fixes braucht der komplette E2E-Baum (100 000 Bytes schreiben, lesen,
   anhängen, umbenennen, Symlink, NFD-Name, unlink, rmdir, zwei Listings, `stat`) **~130 ms**.
8. **`umount` ohne `-f` genügt weiterhin**, und die Session endet per EOF; `close()` ist seit
   Task 8 auf zehn Sekunden begrenzt und meldet danach `Busy` statt zu blockieren.
9. **`umount` direkt nach dem letzten Schreibzugriff meldet sporadisch „filesystem busy“**, obwohl
   nichts mehr offen ist — der NFS-Client hält den Mount noch einen Moment. Ein paar hundert
   Millisekunden später klappt derselbe Aufruf. `umount_macos` wiederholt einen `Busy` deshalb bis
   zu 5 s lang (`UNMOUNT_BUSY_RETRY`), bevor es aufgibt; ein wirklich belegter Mount wird weiterhin
   als `Busy` gemeldet, nur eben 5 s später.
10. **Ein `umount` kann im Kernel festhängen** (Prozess-State `U`, nicht per `SIGKILL` zu beenden),
   wenn der NFS-Server unter dem Mount weg ist — beobachtet als Folgeschaden des stehenden Mounts
   aus Punkt 1, einmal über zehn Minuten lang. `run_unmount_command` wartet nach dem `kill` deshalb
   nicht mehr selbst auf das Kind, sondern übergibt es einem Wegwerf-Thread (`reap`); der Aufrufer
   ist damit auch in diesem Fall nach `UNMOUNT_COMMAND_TIMEOUT` wieder frei.

## Reproduktion

```bash
mkdir -p /tmp/spike-c-mnt
cargo run -p cryptomator-mount --example spike_macos_dlopen -- fuse-t /tmp/spike-c-mnt &
sleep 5; mount | grep spike-c-mnt; cat /tmp/spike-c-mnt/hello.txt; ls -la /tmp/spike-c-mnt
umount /tmp/spike-c-mnt; wait
tail -f ~/Library/Logs/fuse-t/fuse-t.log   # mit "-o", "debug" in den extra_opts deutlich gesprächiger
```
