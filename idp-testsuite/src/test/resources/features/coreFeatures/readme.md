Kernfunktionalität

Folgende Endpunkte sind von einem IDP Dienst zur Verfügung zu stellen:

Discovery-Endpunkte (TI und Internet) ("OAuth 2.0 Authorization Server Metadata" [RFC8414])

* Liefert das Discovery Dokument aus.

Authorization-Endpunkt (Teil des "The OAuth 2.0 Authorization Framework" [RFC6749])

* Liefert den TOKEN_CODE aus, mit dessen Hilfe am Token Endpunkt ein Access Token angefordert werden kann.

Token-Endpunkt [RFC6749 # section-3.2] mit

* "ID_TOKEN" [openid-connect-core 1.0 # IDToken],
* "ACCESS_TOKEN" [RFC6749 # section-1.4 & RFC6749 # section-5],
* "REFRESH_TOKEN/SSO_TOKEN" [RFC6749 # section-1.5 & RFC6749 # section-6]