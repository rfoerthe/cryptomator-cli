# Spike B: Desktop-Keychain-Eintrag lesen (macOS)

Frage: Kann `security-framework` (Generic Password, Service `Cryptomator`, Account = Vault-ID) die Einträge von Cryptomator.app lesen?

Durchführung: `cargo run -p cryptomator-app --example spike_keychain -- <vault-id>` gegen einen Eintrag der installierten Desktop-App (Version aus `writtenByVersion` in settings.json).

Umgebung: macOS 26.6.2 (25G83), Apple Silicon, Cryptomator Desktop `writtenByVersion` = `1.19.3-dmg-6495`,
`keychainProvider` = `org.cryptomator.macos.keychain.MacSystemKeychainAccess`, `useKeychain` = `true`,
`security-framework` 3.7, Debug-Build (`target/debug/examples/spike_keychain`), nicht-interaktive Session.

## Ergebnis: BLOCKED

Ein erfolgreicher Lesevorgang konnte **nicht** beobachtet werden — nicht wegen der API, sondern weil macOS
für jeden Zugriff einen modalen Keychain-Bestätigungsdialog anzeigt, den in dieser Session niemand
beantworten konnte. Das ist ausdrücklich **kein NO-GO**: der Aufruf erreicht securityd und entschlüsselt
bereits den richtigen Eintrag, er wartet nur auf die ACL-Freigabe.

## Beobachtungen

1. **Kein echter Desktop-Eintrag vorhanden.** `settings.json` listet genau einen Vault
   (`OefwgtaX5vsy`, „Tresor"). Weder für diese ID noch für den Service insgesamt existiert ein Eintrag:
   `security find-generic-password -s Cryptomator [-a OefwgtaX5vsy]` → Exit 44 (`errSecItemNotFound`).
   Die Desktop-App hat also nie eine Passphrase gespeichert. Der Spike konnte deshalb **nicht** gegen einen
   von Cryptomator.app geschriebenen Eintrag laufen; getestet wurde mit dem im Brief vorgesehenen
   Wegwerf-Eintrag `spike-test-id`.
2. **Lookup-Pfad und Fehler-Mapping stimmen.** Gegen die echte Vault-ID meldet das Beispiel
   `keychain lookup failed: The specified item could not be found in the keychain. (code -25300)`
   — `errSecItemNotFound`, identisch zum `security`-CLI. Service/Account-Auflösung und `Error::code()`
   funktionieren also wie erwartet.
3. **Der Eintrag selbst ist lesbar.** Gegenprobe über das CLI:
   `security find-generic-password -s Cryptomator -a spike-test-id -w | wc -c` → `15`
   (14 Bytes Passwort + Newline). Das `security`-Tool steht in der ACL des von ihm angelegten Items und
   fragt daher nicht nach.
4. **Der Rust-Aufruf blockiert im ACL-Dialog.** `sample` auf den hängenden Prozess zeigt den Main-Thread in
   `security_framework::passwords::get_generic_password` → `SecItemCopyMatching` →
   `SecItemCopyMatching_osx` → `AddItemResults` → `SecKeychainItemCopyContent` → `ItemImpl::getContent` →
   `SSDbUniqueRecordImpl::get` → `SSGroupImpl::decodeDataBlob` → `CSSM_DecryptDataFinal` →
   `ClientSession::decrypt` → `mach_msg`. Der Eintrag wurde also gefunden, securityd entschlüsselt ihn und
   wartet auf die Benutzerbestätigung; parallel läuft ein `SecurityAgent`-Prozess.
5. **Kein Timeout in der API.** Der Aufruf hängt unbegrenzt. Nach 180 s wurde er abgebrochen
   (kein Retry-Loop). Auch die Varianten mit `-A` (alle Programme erlauben) und
   `-T <pfad-zum-binary>` (Binary als vertrauenswürdige App eintragen) haben den Dialog **nicht**
   unterdrückt — ein nur ad-hoc signiertes Debug-Binary erfüllt die ACL-Requirement offenbar nicht stabil.
6. **Aufräumen erfolgt.** `spike-test-id` wurde gelöscht; die Login-Keychain enthält wieder keinen Eintrag
   mit Service `Cryptomator` (Ausgangszustand). Bestehende Einträge wurden zu keinem Zeitpunkt verändert.

## Konsequenz für M6

`security-framework` **direkt verwenden** — der Pfad `SecItemCopyMatching` über Service `Cryptomator` +
Account = Vault-ID ist nachweislich der richtige, ein Wechsel auf eine andere Crate oder auf FFI würde am
Kernproblem nichts ändern. Der ACL-Dialog ist eine macOS-Eigenschaft des Items, kein API-Problem: Der
Eintrag gehört ACL-seitig Cryptomator.app, `crypto` ist ein anderes Programm und wird deshalb beim ersten
Zugriff immer nachfragen.

Daraus folgt für die Implementierung:

- Keychain-Zugriff ist **interaktiv und darf niemals unbegrenzt blockieren**: in einem Worker-Thread mit
  Timeout ausführen und bei Ablauf sauber auf die übrigen Passwort-Quellen (`--password-stdin`,
  `--password-file`, `--password-env`, `CRYPTO_PASSWORD`, TTY-Prompt) zurückfallen.
- Headless/SSH ohne GUI-Session kann sich **nicht** auf die Keychain verlassen; das muss dokumentiert und
  in der Fehlermeldung benannt werden („im Dialog ‚Immer erlauben' wählen").
- Damit „Immer erlauben" über Updates hinweg hält, braucht das Release-Binary eine **stabile Code-Signing-
  Identität**; bei jedem neu signierten Build erscheint der Dialog sonst erneut.
- `errSecItemNotFound` (-25300) ist der Normalfall „keine Passphrase gespeichert" und muss als solcher
  behandelt werden, nicht als Fehler.

**Offen / vor M6 nachzuholen:** Der Spike muss einmal gegen einen echten, von Cryptomator.app
geschriebenen Eintrag wiederholt werden, wobei ein Mensch den Dialog mit „Immer erlauben" bestätigt. Erst
dann ist belegt, dass Länge und UTF-8-Kodierung der Desktop-Passphrase wie erwartet ankommen.
