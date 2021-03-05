# Gematik IDP Zulassungstestsuite v8.2.0

Die Gematik IDP Zulassungstestsuite dient zur Pr&uuml;fung externer IDP Dienst Drittanbieter. Sie ist derzeit in
Entwicklung und noch **NICHT** fertiggestellt. Ziel der Suite ist es sowohl externe IDP Dienste, als auch die Gematik
interne Referenzimplementierung bez&uuml;glich ihrer Eignung als IDP Dienst in der TI Umgebung zu testen.

#### Informationen zum IDP Dienst

[Produkt&uuml;bersicht (intern)](https://confluence.int.gematik.de/display/DEV/IDP+-+Aufbau)

Folgende Endpunkte sind von einem IDP Dienst zur Verf&uuml;gung zu stellen:

* Discovery-Endpunkte (TI und Internet) ("OAuth 2.0 Authorization Server Metadata" [RFC8414])
* Authorization-Endpunkt(e) (Teil des "The OAuth 2.0 Authorization Framework" [RFC6749])
* Token-Endpunkt(e) [RFC6749 # section-3.2] mit
    * "ID_TOKEN" [openid-connect-core 1.0 # IDToken],
    * "ACCESS_TOKEN" [RFC6749 # section-1.4 & RFC6749 # section-5],
    * "REFRESH_TOKEN/SSO_TOKEN" [RFC6749 # section-1.5 & RFC6749 # section-6]
* Pairing-Endpunkt für die Registrierung von Endgeräte zur alternativen Authentisierung
* Authorization-Endpunkt für alternative Authentisierung

Weiterf&uuml;hrende interne Dokumente

* [gemSpec_IDP_Dienst](https://polarion.int.gematik.de/polarion/#/project/Mainline_OPB1/wiki/Spezifikation/gemSpec_IDP_Dienst)
* [Testkonzept](https://confluence.int.gematik.de/display/DEV/IDP+Testkonzept?src=contextnavpagetreemode)
* [Testspezifikation](https://confluence.int.gematik.de/display/DEV/IDP+Testspezifikation?src=contextnavpagetreemode)

#### Relevante RFCs

* [RFC6749](https://tools.ietf.org/html/rfc6749) ist der allgemeine OAuth 2.0 RFC. Hier werden die Endpunkte
  (Authorization-Endpoint, Token-Endpoint, …) beschrieben.
* [RFC7636](https://tools.ietf.org/html/rfc7636) beschreibt einen Schutzmechanismus gegen das Abfangen von Authorization
  Codes. Es wird mit code_verifier gearbeitet und die damit verbundenen &Auml;nderungen am Authorization-Request finden
  sich in diesem RFC
* [RFC8252](https://tools.ietf.org/html/rfc8252) beschreibt, wie Native Apps OAuth 2.0 machen sollen.
* [RFC8414](https://tools.ietf.org/html/rfc8414) beschreibt, wie man &uuml;ber einen Discovery-Endpunkt die relevanten
  Endpunkte ermittelt.
* [RFC7519 Appendix A.2](https://tools.ietf.org/html/rfc7519#appendix-A.2) beschreibt, wie das Challenge-Token zu
  signieren und verschl&uuml;sseln ist (Nested JWT).
* [RFC7515 Ssection 3](https://tools.ietf.org/html/rfc7515#section-3) beschreibt die zu verwendende Form der Signatur (
  JSON Web Signature)
* [RFC7516 Section 3](https://tools.ietf.org/html/rfc7516#section-3) beschreibt die zu verwendende Form der
  Verschl&uuml;sselung (JSON Web Encryption)
