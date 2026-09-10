# Spike B: reading a desktop keychain entry (macOS)

Question: can `security-framework` (generic password, service `Cryptomator`, account = vault ID) read the entries written by Cryptomator.app?

Execution: the plan was a run of `cargo run -p cryptomator-app --example spike_keychain -- <vault-id>`
against an entry of the installed desktop app. No such entry existed (see observation 1),
so the spike ran against the throwaway entry `spike-test-id` foreseen in the brief, created by
`/usr/bin/security` — plus one run against the real vault ID `OefwgtaX5vsy`, which returned
`errSecItemNotFound` as expected. The cross-check the brief asked for (`security find-generic-password ... -w | wc -c`
= N+1) could **not** be completed, because the Rust program never printed an N; the
human-accompanied repeat run has to supply that N.

Environment: macOS 26.6.2 (25G83), Apple Silicon, Cryptomator Desktop `writtenByVersion` = `1.19.3-dmg-6495`,
`keychainProvider` = `org.cryptomator.macos.keychain.MacSystemKeychainAccess`, `useKeychain` = `true`,
`security-framework` 3.7, debug build (`target/debug/examples/spike_keychain`), non-interactive session.

## Result: BLOCKED

A successful read could **not** be observed — not because of the API, but because for every access macOS
shows a modal keychain confirmation dialog that nobody in this session could
answer. This is explicitly **not a NO-GO**: the entry was found and a
decryption request reached securityd, which is now waiting for the ACL approval. The decryption
itself has therefore been requested, but not completed.

## Observations

1. **No real desktop entry present.** `settings.json` lists exactly one vault
   (`OefwgtaX5vsy`, "Tresor"). Neither for that ID nor for the service as a whole does an entry exist:
   `security find-generic-password -s Cryptomator [-a OefwgtaX5vsy]` → exit 44 (`errSecItemNotFound`).
   So the desktop app has never stored a passphrase. The spike could therefore **not** run against an
   entry written by Cryptomator.app; what was tested is the throwaway entry
   `spike-test-id` foreseen in the brief.
2. **Lookup path and error mapping are correct.** Against the real vault ID the example reports
   `keychain lookup failed: The specified item could not be found in the keychain. (code -25300)`
   — `errSecItemNotFound`, identical to the `security` CLI. Service/account resolution and `Error::code()`
   therefore work as expected.
3. **The entry itself is readable.** Cross-check via the CLI:
   `security find-generic-password -s Cryptomator -a spike-test-id -w | wc -c` → `15`
   (14 bytes of password + newline). The `security` tool is in the ACL of the item it created itself and
   therefore does not ask.
4. **The Rust call blocks in the ACL dialog.** `sample` on the hanging process shows the main thread in
   `security_framework::passwords::get_generic_password` → `SecItemCopyMatching` →
   `SecItemCopyMatching_osx` → `AddItemResults` → `SecKeychainItemCopyContent` → `ItemImpl::getContent` →
   `SSDbUniqueRecordImpl::get` → `SSGroupImpl::decodeDataBlob` → `CSSM_DecryptDataFinal` →
   `ClientSession::decrypt` → `mach_msg`. The entry was therefore found and a decryption request
   reached securityd; securityd is waiting for the user confirmation, the decryption is
   **not** complete. A `SecurityAgent` process is running alongside.
5. **No timeout in the API.** The call hangs indefinitely. After 180 s it was aborted
   (no retry loop). The variants with `-A` (allow all programs) and
   `-T <path-to-binary>` (register the binary as a trusted app) did **not** suppress the dialog
   either; both ran into the same timeout. For `-T`, an insufficient signature of the
   ad-hoc-signed debug binary would be a plausible explanation — for `-A` (ACL "allow any", with no
   program list at all) it explains **nothing**. The `-A` result therefore remains **unexplained**. An obvious
   confounder: from the first hanging run an unanswered `SecurityAgent` dialog was still open;
   whether it was closed and the hanging process killed before the additional variants is not
   documented — a blocked authorisation context could have held up the subsequent runs regardless of
   the ACL. The variants have to be repeated in the accompanied repeat run, cleanly separated (dialog
   answered each time, hanging process killed).
6. **Cleanup done.** `spike-test-id` was deleted; the login keychain again contains no entry
   with service `Cryptomator` (the initial state). Existing entries were never modified.

## Consequence for M6

**Use `security-framework` directly** — the path `SecItemCopyMatching` via service `Cryptomator` +
account = vault ID is the expected correct way in (**expected, not measured**: a successful
read was never observed in this spike; only the lookup and the error mapping are proven). Switching
to another crate or to FFI would change nothing about the core problem. The ACL dialog is with high
probability a macOS property of the item and not an API problem: an entry written by
Cryptomator.app belongs, ACL-wise, to Cryptomator.app, `crypto` is a different program and should
therefore prompt on first access. That is **plausible, but untested** — the only entry used in the
spike was created by `/usr/bin/security`, not by Cryptomator.app.

For the implementation this means:

- Keychain access is **interactive and must never block indefinitely**: run it on a worker thread with a
  timeout and, when it expires, fall back cleanly to the remaining password sources (`--password-stdin`,
  `--password-file`, `--password-env`, `CRYPTO_PASSWORD`, TTY prompt).
- Headless/SSH without a GUI session **cannot** rely on the keychain; that has to be documented and
  named in the error message ("choose 'Always Allow' in the dialog").
- For "Always Allow" to survive updates, a **stable code-signing identity** for the release binary is
  to be **recommended** (otherwise the dialog should reappear after every newly signed build). The spike
  did not prove this — how strongly the signature affects the dialog at all is open (observation 5).
- `errSecItemNotFound` (-25300) is the normal case "no passphrase stored" and has to be
  treated as such, not as an error.

**Open / to be made up before M6:** the spike has to be repeated once against a real entry written by
Cryptomator.app, with a human confirming the dialog with "Always Allow". Only
then is it proven that the length and UTF-8 encoding of the desktop passphrase arrive as expected. The same
run has to make up the cross-check `wc -c` = N+1 required by the brief and re-check the ACL variants (`-A`, `-T`)
individually, each with the dialog closed beforehand.
