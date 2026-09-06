# The `crypto` daemon protocol

`crypto unlock` mounts a vault in a **daemon process of its own** and talks to it over a Unix
domain socket in the state directory. Every later command for that vault — `lock`, `stats`,
`events` — is a round trip over the same socket; `status` is the exception, it reads the state
files and never connects.

This document describes the protocol as it is implemented in
`crates/cryptomator-app/src/daemon/` (`protocol.rs` for the message types, `client.rs` for the
client the CLI commands use, `server.rs` for the daemon). It is an internal interface between two
copies of the same binary: there is no compatibility promise across releases beyond the version
check below.

## Transport

- One **Unix stream socket** per vault: `<state-dir>/<vault-id>.sock`, mode `0600`, inside a
  directory that is `0700` and must belong to the calling user.
- **Newline-delimited JSON**, UTF-8, one object per line, `\n`-terminated. `\r\n` is accepted on
  read. Nothing is pretty-printed on the wire.
- The trust boundary is the file system: the socket may only be opened by its owner, and the
  daemon serves whoever gets through. There is no authentication beyond that, and none is needed —
  a peer that can open the socket runs as the user whose vault it is.
- A line longer than **1 MiB** (`protocol::MAX_LINE_LEN`, the terminator not counted) is refused
  with `InvalidData` and the connection is unusable afterwards. That is what keeps a peer that
  never sends a newline from growing the read buffer without bound; the largest legitimate message,
  `unlock`, is a base64 key plus a few paths.
- Several clients may be connected at once. Each connection is served by its own thread, requests
  on one connection are answered in order, and the daemon answers exactly one `Response` per
  request.

## The handshake

The **daemon speaks first**: immediately after `accept` it writes one line and then waits.

```json
{"hello":"crypto-daemon","protocol":1,"vaultId":"UARWQsp1etRW","pid":89958}
```

The client checks `hello == "crypto-daemon"` and `protocol == 1` before it sends anything, so a
socket some other program left behind is never fed a vault key. A wrong magic or a protocol
version this build does not speak is fatal at once — retrying cannot fix it — while a missing
socket or nobody listening is transient and `DaemonClient::connect_with_retry` keeps trying every
100 ms until its deadline. Both failures reach the user as exit code **10**.

## Requests

A request is a JSON object tagged by `"op"` and carrying an `id` the response echoes. Ids are
per connection and chosen by the client (`DaemonClient` counts up from 1).

| `op` | Fields besides `id` | Answer |
|---|---|---|
| `unlock` | `key`, `mounter`, `mountPoint`, `mountOptions`, `readOnly`, `volumeName`, `maxCleartextNameLength` | `{"mountpoint": "<path>"}` |
| `status` | — | [`StatusResult`](#status) |
| `stats` | — | [`StatsResult`](#stats) |
| `lock` | `force` | `null` |
| `events` | `follow`, `since` | [`EventsResult`](#eventsresult), or a stream |
| `ping` | — | `null` |
| `shutdown` | — | `null` |

### `unlock`

Sent **once**, by the process that spawned the daemon, before anything is mounted. A second
`unlock` on a daemon that already serves a mount is answered with `ALREADY_UNLOCKED`; every other
request before the first `unlock` is answered with `NOT_UNLOCKED`.

```json
{"op":"unlock","id":1,"key":"<base64 of the 64 raw key bytes>","mounter":"org.cryptomator.frontend.fuse.mount.FuseTMountProvider","mountPoint":"/Users/me/mnt/secret","mountOptions":["-ovolname=Secret"],"readOnly":null,"volumeName":"Secret","maxCleartextNameLength":220}
```

- `key` — base64 of the 64 raw key bytes (the unwrapped masterkey). See
  [The key](#the-key-never-touches-argv) below.
- `mounter` — the mount service's Java class name, or `null` for "pick the best available one".
- `mountPoint` — an **absolute** path, or `null` for the configured default. The daemon's working
  directory is `/`, so a relative path would mean something different to it than to the shell.
- `mountOptions` — extra flags, handed to the mount service verbatim (`-o…`, `-r`).
- `readOnly` — `true`/`false`, or `null` for "whatever the vault's `usesReadOnlyMode` says".
- `volumeName` — the name the operating system shows, or `null`.
- `maxCleartextNameLength` — the longest cleartext file name this vault accepts; the parent process
  probes it (and persists it in `settings.json`) before it spawns the daemon, so the daemon never
  writes into a vault to find out.

The response arrives once the volume is really usable -- the mount call has returned **and** the
mount point has appeared in the system mount table (checked every 50 ms, for at most 10 s). FUSE-T
mounts asynchronously, so answering earlier would let a caller write into the bare directory
underneath the mount point. A volume that never becomes visible is `MOUNT_FAILED` like any other
mount failure, with the mount released before the answer:

```json
{"id":1,"ok":true,"result":{"mountpoint":"/Users/me/mnt/secret"}}
```

A failure is `MOUNT_FAILED`, and the daemon stops itself afterwards.

### `lock` and `shutdown`

`lock` unmounts and then ends the daemon; `force` takes a volume down that is still in use.
`shutdown` ends the daemon **without** unmounting, for a caller that already knows the volume is
gone — the daemon serves it, but no CLI command sends it today (a stale mount has no daemon left to
ask, so `crypto lock --force` unmounts it by path instead). Both answer *before* the process exits,
so the client sees a result rather than a closed socket. A `lock` whose unmount fails answers
`UNMOUNT_FAILED` and the daemon keeps running.

### `events`

Without `follow`, one batch and one response (see [`EventsResult`](#eventsresult)). With `follow`, the
daemon keeps the connection open and writes **stream items** until the client stops reading:

```json
{"id":4,"event":{"seq":7,"timestamp":1788722000,"kind":"DECRYPTION_FAILED","message":"…","cleartextPath":"/a.txt","ciphertextPath":"d/AB/CD…/x.c9r"}}
```

A stream item carries the `id` of the request that opened the stream, so a reader can tell it from
the closing `Response`, which has the same `id`:

```json
{"id":4,"ok":true,"result":{"nextSeq":7}}
```

The stream ends when the daemon shuts down (the closing response is written first), or when the
client shuts its socket down — `DaemonClient::stream_until` does that on Ctrl-C, and the daemon
takes the closed connection as the end of the stream. `DaemonClient::call` skips stream items, so
a `call` issued while a stream is running would block until the stream ends; use `stream` /
`stream_until` for those.

## Responses

Exactly one per request, echoing its `id`. Exactly one of `result` and `error` is present; the
other is left off the wire.

```json
{"id":2,"ok":true,"result":{ … }}
{"id":2,"ok":false,"error":{"code":"UNMOUNT_FAILED","message":"volume is in use"}}
```

`code` is stable and drives the CLI's exit code; `message` is for humans and never quotes a key or
a password.

| `code` | Meaning | CLI exit code |
|---|---|---|
| `MOUNT_FAILED` | the mount service refused to mount | 6 |
| `UNMOUNT_FAILED` | the volume could not be taken down (usually still in use) | 7 |
| `ALREADY_UNLOCKED` | an `unlock` reached a daemon that already serves a mount | 5 |
| `NOT_UNLOCKED` | a request arrived before the vault was unlocked | 5 |
| `BAD_REQUEST` | the line did not decode, or its fields make no sense | 1 |
| `INTERNAL` | anything the daemon did not expect | 1 |

A daemon that cannot be reached at all — no socket, nobody listening, a stranger on the other end,
a protocol version mismatch, or a connection that breaks mid-request — is exit code **10**, not an
error body.

### `status`

```json
{"vaultId":"UARWQsp1etRW","state":"UNLOCKED","mountpoint":"/Users/me/mnt/secret","mounter":"org.cryptomator.frontend.fuse.mount.FuseTMountProvider","readOnly":false,"startedAt":1788722000,"uptimeSecs":42,"lastActivity":1788722030,"inUse":true}
```

`state` is `STARTING` (no `unlock` yet — `mountpoint` is `null` and `mounter` is empty),
`UNLOCKED` or `LOCKING`. `inUse` says whether the access counters grew during the last sampling
interval. This is the *daemon's* view; the `crypto status` command answers from the state files
instead and reports `UNLOCKED`, `STALE_MOUNT` or one of the on-disk vault states.

### `stats`

```json
{"bytesPerSecondRead":0,"bytesPerSecondWritten":0,"bytesPerSecondEncrypted":0,"bytesPerSecondDecrypted":0,"cacheHitRate":0.0,"totalBytesRead":62,"totalBytesWritten":62,"totalBytesEncrypted":62,"totalBytesDecrypted":62,"filesRead":1,"filesWritten":2,"totalFilesAccessed":65,"lastActivity":1788722030}
```

The per-second values are the deltas of the last sampling interval (one second); the totals are
read at request time.

### EventsResult

```json
{"events":[{"seq":1,"timestamp":1788722000,"kind":"CONFLICT_RESOLVED","message":"…","cleartextPath":"/a (1).txt","ciphertextPath":null}],"nextSeq":1}
```

`kind` is the event type, `cleartextPath` and `ciphertextPath` are `null` when the event names
none. The log lives in the daemon — it starts empty with every unlock and keeps the newest 1000
entries.

**`nextSeq` is the newest event's own `seq`**, not one past it (and `0` while the log is empty).
Pass it back as `since`, which the daemon reads **exclusively** (`seq > since`), and you continue
exactly after the last event you saw. The closing response of a follow stream carries the same
value under the same name, so a reader that is interrupted can resume from it.

## The key never touches `argv`

The vault key is derived in the `crypto unlock` process — the password is read, NFC-normalised and
run through scrypt there, so a wrong password fails synchronously and never reaches a background
process. The daemon is then spawned with `setsid(2)`, working directory `/`, stdin `/dev/null`,
stdout and stderr appended to `<state-dir>/<vault-id>.log` and `$CRYPTO_PASSWORD` removed from its
environment. The key follows over the socket as the **first message**, the `unlock` request.

That means it never appears in the process list, in the environment, or in a file. Both ends know
this line is special:

- the client serialises it through a `Zeroizing` buffer and wipes it after the write;
- `Request` has a hand-written `Debug` that prints `key: "<redacted>"`, and a `Drop` that wipes the
  string, so no log line and no panic message can carry it;
- the server wipes the raw line it decoded from.

**Known limitation:** the daemon reads its socket through a `BufReader`, and the `unlock` line
passes through that internal buffer before it is decoded. The decoded copies are wiped, the
`BufReader`'s buffer is not — it holds the base64 key until later traffic on the same connection
overwrites it. Same-uid access is the trust boundary anyway (an attacker who can read the daemon's
memory can read the key itself), so this is a follow-up for M5, not a hole in the design.

## State files and their order

Four files per vault in the state directory (`--state-dir`, `$CRYPTO_STATE_DIR`, else a platform
default), all `0600`:

| File | Contents |
|---|---|
| `<id>.pid` | the daemon's process id, as text |
| `<id>.sock` | the control socket |
| `<id>.json` | the run info: `vaultId`, `path`, `mounter`, `mountpoint`, `pid`, `startedAt`, `readOnly` |
| `<id>.log` | the daemon's log; **kept** when the other three are removed |

They are published in exactly this order:

1. **pid**, before anything else — but only after a connect probe has shown that nobody is already
   serving on the socket, because overwriting a running daemon's pid file would leave it
   unreachable and still mounted;
2. **socket**, bound and narrowed to `0600` (a leftover socket file from a crashed daemon is
   removed first, guarded by the same probe);
3. **run info**, after the mount succeeded — it names the mount point, which only exists then.

The order is what makes the detection below safe: a bound socket accepts connections before
`accept` runs, so from the moment step 2 finishes the daemon answers, and step 1 has already put a
live pid in place for anyone who looks in between. The run info is written last and is therefore
the one file that says "this vault really is mounted, and here".

`<id>.json` and `<id>.pid` are written through a process-unique temporary file that is renamed over
the target, so a reader never sees a half-written file.

## Stale detection

A daemon that was killed with `SIGKILL` (or died with its machine) leaves its files behind and, on
macOS and Linux alike, its volume mounted. `crypto status` and every command that resolves a vault
therefore ask, in this order:

1. Read `<id>.json`, if it is there — it is what the answer is built from.
2. Does somebody answer on the socket (connect, then hang up)? Yes → **`UNLOCKED`**. A socket file
   nobody listens on proves nothing; only a successful connect does.
3. Is the pid still alive (`kill(pid, 0)`; `EPERM` counts as alive)? Yes → **`UNLOCKED`**. This is
   the window between step 1 and step 2 of the write order above, where a daemon has a pid file but
   not yet a socket.
4. Otherwise the daemon is gone. Is the run info's `mountpoint` still in the mount table? Yes →
   **`STALE_MOUNT`**; `crypto lock <VAULT> --force` takes it down by mount point, through the mount
   service the run info names, and removes the leftover files.
5. Nothing mounted either → any leftover files are removed on the spot and the vault falls back to
   its on-disk state (`LOCKED`, `MISSING`, …).

A daemon whose *own* unmount failed on shutdown deliberately keeps its run info and exits `7`, so
the volume it left behind stays addressable through exactly this path.

## Why threads and not tokio

The daemon is plain `std`: a `UnixListener` polled in an accept loop, one thread per connection,
one thread for the stats sampler (one second), one for the auto-lock tick, and the FUSE session on
its own thread. Waiting is always `Condvar::wait_timeout` with a 100 ms cap — the condvar makes an
internal stop immediate, the cap bounds how long a flag that a signal handler can only *set* stays
unnoticed. There is no busy loop and no async runtime. tokio arrives with WebDAV in M5, which needs
one for hyper; until then it would be a dependency without a job.
