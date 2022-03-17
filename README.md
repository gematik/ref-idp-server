# ![Logo](./doc/images/IDPLogo-64.png) IDP-Global

<div>Icons made by <a href="https://www.flaticon.com/authors/freepik" title="Freepik">Freepik</a> from <a href="https://www.flaticon.com/" title="Flaticon">www.flaticon.com</a></div>

## Übersicht

Das Projekt **IDP-Global** setzt sich aus verschiedenen Teilprojekten zusammen. Diese sind

* **IDP-Server:** Referenzentwicklung des zentralen IDPs
* **IDP-Client:** Client zur Beantragung von ACCESS_TOKEN mit SMC-B-Aut- oder HBA-Aut-Schlüsseln beim zentralen IDP
* **IDP-Testsuite:** Zulassungstestsuite für einen zentralen IDP
* **IDP-Sektoral:** PoC für einen sektoralen IDP im Kontext Fast Track/föderierte IDPs
* **IDP-Fedmaster:** PoC für einen Föderationsmaster im Kontext föderierte IDPs
* **IDP-Fachdienst:** PoC für den Auth Server eines Fachdienstes im Kontext föderierte IDPs

## Tests

### Unittests

Unittests können mit `-Dskip.unittests=true` deaktiviert werden.

### Integrationstests

Der Integrationstest kann entweder mit einer lokalen Instanz des IDP Servers oder gegen einen remote verfügbaren Server
durchgeführt werden. Durch Setzen der Umgebungsvariable `IDP_SERVER` wird die test suite angewiesen gegen den in der
Variable definierten Host/URL zu testen. Existiert diese Umgebungsvariable nicht, so wird eine lokale Instanz für die
Integrationstests gestartet.

Ein Beispiel für die lokale Instanz wäre:

```
http://localhost:8080/auth/realms/idp/.well-known/openid-configuration
```

Integrationstests können mit dem property `-Dskip.inttests=true` disabled werden.

### Tests gegen Docker image

Docker container online bringen, dann:

```
docker ps
docker inspect $CONTAINERID | grep IPAddress
```

Diese IP-Adresse für IDP_SERVER Variable verwenden oder einfach untige Kommandos ausführen

```
mvn clean install
docker-compose up &
# wait for docker startup to complete
export CONTAINERID=`docker ps | grep "idp-" | cut -f 1 -d \ `
export CONTAINERIP=`docker inspect $CONTAINERID | grep -v \"\" | grep \"IPAddress\"\: | head -1 | cut -d \" -f 4`
export IDP_SERVER=http://$CONTAINERIP:8080/auth/realms/idp/.well-known/openid-configuration
mvn verify -Dskip.unittests=true
```

### Zulassungstests

Basierend auf der Integrationstestsuite können auch Zulassungstests durchgeführt werden. Mehr Informationen hierzu
finden sich im [README im submodule idp-testsuite](idp-testsuite/README.md)

## Cheatsheet

```
mvn clean
mvn compile
mvn package # runs unit tests and creates jar artefacts
mvn install # runs unit and integration test against temporary lokal instance and creates docker image 
mvn XXXX -Dskip.unittests # skip unit tests
mvn XXXX -Dskip.inttests # skip integration tests
cd idp-server && mvn docker:remove && cd ..

docker-compose build # creates a docker image after running all tests
docker-compose build --build-args mode=untested # creates a docker image without running any tests
```

## Caveats

Sämtliche Targets müssen aus dem **Basisverzeichnis idp-global** aufgerufen werden!

Um docker images zu entfernen, hilft mvn docker:remove, leider geht dies nur aus dem idp-server Verzeichnis. Auf top
Ebene wird das docker plugin nicht gefunden. Mehr Details dazu
gibts [auf dieser Seite](http://dmp.fabric8.io/#docker:remove))

## Tokenflow Seiten

* [TokenFlow EGK](https://gematik.github.io/ref-idp-server/tokenFlowEgk.html)
* [TokenFlow PS](https://gematik.github.io/ref-idp-server/tokenFlowPs.html)
* [TokenFlow SSO](https://gematik.github.io/ref-idp-server/tokenFlowSso.html)
   
