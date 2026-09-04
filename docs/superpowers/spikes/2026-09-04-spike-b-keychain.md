# Spike B: Desktop-Keychain-Eintrag lesen (macOS)

Frage: Kann `security-framework` (Generic Password, Service `Cryptomator`, Account = Vault-ID) die Einträge von Cryptomator.app lesen?

Durchführung: Geplant war ein Lauf `cargo run -p cryptomator-app --example spike_keychain -- <vault-id>`
gegen einen Eintrag der installierten Desktop-App. Ein solcher Eintrag existierte nicht (siehe Beobachtung 1),
daher lief der Spike gegen den im Brief vorgesehenen Wegwerf-Eintrag `spike-test-id`, den `/usr/bin/security`
angelegt hat — zusätzlich einmal gegen die echte Vault-ID `OefwgtaX5vsy`, die erwartungsgemäß
`errSecItemNotFound` lieferte. Die im Brief geforderte Gegenprobe (`security find-generic-password ... -w | wc -c`
= N+1) konnte **nicht** abgeschlossen werden, weil das Rust-Programm nie ein N ausgegeben hat; der
menschlich begleitete Wiederholungslauf muss dieses N nachliefern.

Umgebung: macOS 26.6.2 (25G83), Apple Silicon, Cryptomator Desktop `writtenByVersion` = `1.19.3-dmg-6495`,
`keychainProvider` = `org.cryptomator.macos.keychain.MacSystemKeychainAccess`, `useKeychain` = `true`,
`security-framework` 3.7, Debug-Build (`target/debug/examples/spike_keychain`), nicht-interaktive Session.

## Ergebnis: BLOCKED

Ein erfolgreicher Lesevorgang konnte **nicht** beobachtet werden — nicht wegen der API, sondern weil macOS
für jeden Zugriff einen modalen Keychain-Bestätigungsdialog anzeigt, den in dieser Session niemand
beantworten konnte. Das ist ausdrücklich **kein NO-GO**: Der Eintrag wurde gefunden und eine
Entschlüsselungsanfrage hat securityd erreicht, das nun auf die ACL-Freigabe wartet. Die Entschlüsselung
selbst ist damit angefordert, aber nicht abgeschlossen.

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
   `ClientSession::decrypt` → `mach_msg`. Der Eintrag wurde also gefunden und eine Entschlüsselungsanfrage
   hat securityd erreicht; securityd wartet auf die Benutzerbestätigung, die Entschlüsselung ist noch
   **nicht** abgeschlossen. Parallel läuft ein `SecurityAgent`-Prozess.
5. **Kein Timeout in der API.** Der Aufruf hängt unbegrenzt. Nach 180 s wurde er abgebrochen
   (kein Retry-Loop). Auch die Varianten mit `-A` (alle Programme erlauben) und
   `-T <pfad-zum-binary>` (Binary als vertrauenswürdige App eintragen) haben den Dialog **nicht**
   unterdrückt; beide liefen in denselben Timeout. Für `-T` wäre eine unzureichende Signatur des
   ad-hoc signierten Debug-Binarys eine plausible Erklärung — für `-A` (ACL „allow any", ganz ohne
   Programmliste) erklärt sie **nichts**. Das `-A`-Ergebnis bleibt daher **ungeklärt**. Naheliegender
   Störfaktor: Aus dem ersten hängenden Lauf stand noch ein unbeantworteter `SecurityAgent`-Dialog offen;
   ob er vor den Zusatzvarianten geschlossen und der hängende Prozess beendet wurde, ist nicht
   dokumentiert — ein blockierter Autorisierungs-Kontext könnte die Folgeläufe unabhängig von der ACL
   aufgehalten haben. Die Varianten müssen im begleiteten Wiederholungslauf sauber getrennt (Dialog
   jeweils beantwortet, hängender Prozess beendet) wiederholt werden.
6. **Aufräumen erfolgt.** `spike-test-id` wurde gelöscht; die Login-Keychain enthält wieder keinen Eintrag
   mit Service `Cryptomator` (Ausgangszustand). Bestehende Einträge wurden zu keinem Zeitpunkt verändert.

## Konsequenz für M6

`security-framework` **direkt verwenden** — der Pfad `SecItemCopyMatching` über Service `Cryptomator` +
Account = Vault-ID ist der erwartete richtige Zugriffsweg (**erwartet, nicht gemessen**: ein erfolgreicher
Lesevorgang wurde in diesem Spike nie beobachtet; belegt sind nur Lookup und Fehler-Mapping). Ein Wechsel
auf eine andere Crate oder auf FFI würde am Kernproblem nichts ändern. Der ACL-Dialog ist mit hoher
Wahrscheinlichkeit eine macOS-Eigenschaft des Items und kein API-Problem: Ein von Cryptomator.app
geschriebener Eintrag gehört ACL-seitig Cryptomator.app, `crypto` ist ein anderes Programm und dürfte
deshalb beim ersten Zugriff nachfragen. Das ist **plausibel, aber ungetestet** — der einzige im Spike
verwendete Eintrag wurde von `/usr/bin/security` angelegt, nicht von Cryptomator.app.

Daraus folgt für die Implementierung:

- Keychain-Zugriff ist **interaktiv und darf niemals unbegrenzt blockieren**: in einem Worker-Thread mit
  Timeout ausführen und bei Ablauf sauber auf die übrigen Passwort-Quellen (`--password-stdin`,
  `--password-file`, `--password-env`, `CRYPTO_PASSWORD`, TTY-Prompt) zurückfallen.
- Headless/SSH ohne GUI-Session kann sich **nicht** auf die Keychain verlassen; das muss dokumentiert und
  in der Fehlermeldung benannt werden („im Dialog ‚Immer erlauben' wählen").
- Für „Immer erlauben" über Updates hinweg ist eine **stabile Code-Signing-Identität** des Release-Binarys
  zu **empfehlen** (sonst dürfte der Dialog nach jedem neu signierten Build erneut erscheinen). Der Spike
  hat das nicht belegt — wie stark die Signatur den Dialog überhaupt beeinflusst, ist offen (Beobachtung 5).
- `errSecItemNotFound` (-25300) ist der Normalfall „keine Passphrase gespeichert" und muss als solcher
  behandelt werden, nicht als Fehler.

**Offen / vor M6 nachzuholen:** Der Spike muss einmal gegen einen echten, von Cryptomator.app
geschriebenen Eintrag wiederholt werden, wobei ein Mensch den Dialog mit „Immer erlauben" bestätigt. Erst
dann ist belegt, dass Länge und UTF-8-Kodierung der Desktop-Passphrase wie erwartet ankommen. Derselbe
Lauf muss die im Brief geforderte Gegenprobe `wc -c` = N+1 nachholen und die ACL-Varianten (`-A`, `-T`)
einzeln und mit jeweils zuvor geschlossenem Dialog erneut prüfen.
