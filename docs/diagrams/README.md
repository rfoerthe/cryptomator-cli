# Diagrams

Four views of `crypto`, each one a small JSON source plus the standalone HTML rendered from it.
The HTML needs no server and no network: the viewer — dark/light, pan and zoom, search, focus,
relationship tracing, guided chapters, presentation mode and PNG/SVG/WebM export — is inlined,
which is also why every file is around 800 KB.

| Source | Artefact | What it shows |
|---|---|---|
| `architecture.json` | [`architecture.html`](architecture.html) | The four crates, the per-vault daemon, and the three surfaces shared with the desktop app |
| `unlock-sequence.json` | [`unlock-sequence.html`](unlock-sequence.html) | `crypto unlock`: passphrase, scrypt, daemon spawn, handshake, mount, report |
| `ciphertext-pipeline.json` | [`ciphertext-pipeline.html`](ciphertext-pipeline.html) | How a cleartext path and its bytes become a `.c9r` file under `d/` |
| `vault-states.json` | [`vault-states.html`](vault-states.html) | `RuntimeState`: how LOCKED, UNLOCKED and STALE\_MOUNT are decided, and the way back from each |

The facts come from the code, not from the spec: `architecture.json` carries `sources` entries, so
every component in that diagram links to the file it was read from. The design spec is
[`../superpowers/specs/2026-09-04-crypto-cli-design.md`](../superpowers/specs/2026-09-04-crypto-cli-design.md),
the daemon's wire format is in [`../daemon-protocol.md`](../daemon-protocol.md).

## Regenerating

The diagrams are produced by the `archify` agent skill; `$ARCHIFY` below is `bin/archify.mjs`
inside the installed skill directory (`~/.claude/skills/archify/` on the machine these were made
on). `deliver` renders, validates at the `showcase` profile and only then writes the HTML, so a
non-zero exit leaves the previous artefact in place.

    ARCHIFY=~/.claude/skills/archify/bin/archify.mjs

    # from the repository root — the architecture diagram verifies its `sources`
    # entries against the working tree, which is what --repo-root points at
    node $ARCHIFY deliver architecture docs/diagrams/architecture.json \
        docs/diagrams/architecture.html --quality showcase --repo-root .

    node $ARCHIFY deliver sequence docs/diagrams/unlock-sequence.json \
        docs/diagrams/unlock-sequence.html --quality showcase

    node $ARCHIFY deliver dataflow docs/diagrams/ciphertext-pipeline.json \
        docs/diagrams/ciphertext-pipeline.html --quality showcase

    node $ARCHIFY deliver lifecycle docs/diagrams/vault-states.json \
        docs/diagrams/vault-states.html --quality showcase

`node $ARCHIFY visual-check <file>.html` afterwards opens the delivered file in a real Chrome at
1440x900, 1600x1000, 1920x1080 and 2048x1320 in both themes and checks containment and projected
text size. It writes `*.visual-check.*` sidecars (screenshots and a JSON receipt) next to the
artefact — **delete them again**, they do not belong in the repository.

## Two things that go stale

1. **`architecture.json` pins a revision.** `meta.repository.revision` is a full commit SHA, and
   the source links in that diagram point at exactly that commit. After a change to the files it
   names, bump the revision — otherwise the diagram links at a tree that no longer matches its own
   boxes. The other three carry no repository evidence and are unaffected.

2. **The layout is authored, not solved.** Node positions, channel coordinates and label offsets
   are literal numbers in the JSON, tuned until `--quality showcase` passed with no errors and no
   warnings. Adding a node or lengthening a label will usually break a clearance rule; the
   validator names the offending element, the measured distance and the supported fixes, and that
   diagnostic is the thing to act on rather than the coordinates directly.

## Deliberate omissions

`vault-states` draws `NEEDS_MIGRATION` and `STALE_MOUNT` as their own states but folds
`VAULT_CONFIG_MISSING` and `ALL_MISSING` into a card line instead: both are recovered the same way
(`crypto recovery-key restore`), and two more boxes in that band cost more legibility than they
bought. `MISSING` and `ERROR` are not drawn at all — they say the path is not a vault, which is the
absence of the lifecycle rather than a state in it.

`unlock-sequence` shows the detached path only. `--foreground` runs the same code in-process
(`serve_in_foreground` in `crates/crypto/src/commands/unlock.rs`) and would add a branch without
adding a fact.
