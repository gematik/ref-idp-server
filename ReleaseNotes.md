# Release 11.0.0
* Accept header werden vom IDP-Client benutzt sowie vom Server validiert
* Erstes Set von Testszenarien mit Anforderungen verlinkt
* NBF entfernt
* Endpunkt pairing in pairings umbenannt
* Korrekte Werte für not_after in Pairing-Data in der Testsuite
* Discoverydocument an neue Spezifikation angepasst
* IDP PUK_ENC ohne X5C in JWKS_URI Response
* Testsuite um Testfall für Primärsystem ohne SSO_TOKEN erweitert

# Release 10.0.0
* Fehlermeldungen spezifikationskonform im Basisflow
* CLAIMS ACR/NBF/AT_HASH/EXP/CTY spezifikationskonform
* Discovery Document überarbeitet
* AFO Reporter in Testsuite integriert

# Release 9.0.0
- Korrigierte redirect_uri
- Renaming ssotoken => sso_token
- kid in Header-Token enthalten
- kid-Werte im JWKS-Endpunkt und in einzelnen Schlüssel-Endpunkten vereinheitlicht
- Testfälle zur alternativen Authentisierung enthalten
- ACR-Wert angepasst
- jti im ID-Token ergänzt
- Versionranges für GemLibPki korrigiert

# Release 8.1.0
- User consent angepasst
- Validierung von device und pairing Daten implementiert
- Testsuite um Token Verschlüsselung für den Pairing Endpunkt erweitert
- gemlibPKI Version update 
-- fix https://github.com/gematik/ref-idp-server/issues/2

# Release 8.0.0
- Versionsnummer in den Response-Headern ersichtlich
- Aktuelles Bespiel für den TokenFlow unter /tokenFlow.html abrufbar
- Fix für lokales Discovery Document
- Biometrie Kommunikation verschlüsselt
- Draft Set Testfälle für Biometrie Registrierungsendpunkt
- Umstellung Schlüssel AUTH/TOKEN auf SIGN/ENC
- Einbindung der gemLibPKI
- ID-Token enthält nonce
- Fix für lokales Disc Doc in der Testsuite

# Release 7.0.0
RELEASE 7.0.0
IDP
- Es gibt einen TokenLoggerTest der die Tokens des Workflows in ein Dokument speichert (siehe idp-server/target)
- Prüfungen Tokengültigkeit
- diverse Tokenclaims angepasst
- Tokenverschlüsselung umgesetzt
Testsuite 
- Tokenverschlüsslung wird in der Testsuite geprüft (konfigurierbar)
- Beide Flows weitestgehend positiv und negativ getestet
- erste Testfälle zur Biometrie enthalten (Registrierung)
- Korrekturen zum Flow
- Abweichungen in der API konsolidiert

# Release 6.0.0
RELEASE 6.0.0

# Release 5.1.0
RELEASE 5.1.0 Zulassungstest Version 1.1.0

# Release 5.0.0
RELEASE 5.0.0 Zulassungstest Stufe 1

# Release 4.0.0
RELEASE 4.0.0

