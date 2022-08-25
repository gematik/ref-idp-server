## Übersicht

Das Projekt **IDP-Global** setzt sich aus verschiedenen Teilprojekten zusammen. Diese sind

* **IDP-Server:** Referenzentwicklung des zentralen IDPs
* **IDP-Client:** Client zur Beantragung von ACCESS_TOKEN mit SMC-B-Aut- oder HBA-Aut-Schlüsseln beim zentralen IDP
* **IDP-Testsuite:** Zulassungstestsuite für einen zentralen IDP, enthält auch Tests für Fast Track und föderierte IDPs

  <br>

* **IDP-Sektoral:** PoC für einen sektoralen IDP im Kontext Fast Track/föderierte IDPs
* **IDP-Fedmaster:** PoC für einen Föderationsmaster im Kontext föderierte IDPs
* **IDP-Fachdienst:** PoC für den Auth Server eines Fachdienstes im Kontext föderierte IDPs

Die letzten 3 Teilprojekte in o.s. Liste sind nicht Teil der Referenzimplementierung/Veröffentlichung auf github.

### Verwendung des Idp-Server im Docker image

in project root:

#### build image of Idp-Server

```console 
$ mvn clean install -pl idp-server -am
```

#### start container

```console 
$ docker run --rm -it -p 8571:8080 eu.gcr.io/gematik-all-infra-prod/idp/idp-server:20.0.9
```

#### smoke test: get discovery document

```console 
$ curl http://localhost:8571/auth/realms/idp/.well-known/openid-configuration
```

### Unittests

Unittests können mit `-Dskip.unittests` deaktiviert werden.

### Integrationstests/Zulassungstests

Integrationstests stellen die Tests in der Idp-Testsuite dar.<br>
Basierend auf der Integrationstestsuite können auch Zulassungstests durchgeführt werden. Mehr Informationen hierzu
finden sich im [README im submodule idp-testsuite](idp-testsuite/README.md)

Integrationstests können mit `-Dskip.inttests` deaktiviert werden.

## Caveats

Sämtliche Targets müssen aus dem **Basisverzeichnis idp-global** aufgerufen werden!

## Tokenflow Seiten

* [TokenFlow EGK](https://gematik.github.io/ref-idp-server/tokenFlowEgk.html)
* [TokenFlow PS](https://gematik.github.io/ref-idp-server/tokenFlowPs.html)
* [TokenFlow SSO](https://gematik.github.io/ref-idp-server/tokenFlowSso.html)
   
