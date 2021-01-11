# ![Logo](./doc/images/IDPLogo-64.png) IDP-Server

<div>Icons made by <a href="https://www.flaticon.com/authors/freepik" title="Freepik">Freepik</a> from <a href="https://www.flaticon.com/" title="Flaticon">www.flaticon.com</a></div>

## Build

### Docker Container über docker-compose bauen

Dies ist vor allem für den Server relevant (konstante, saubere Umgebung). Im idp-global root-Verzeichnis bauen mit:

```
docker-compose build --build-args mode=[un]tested
```

### Docker Container über Maven bauen

```
mvn clean compile
mvn install # builds docker image and runs integration test suite
```

Sollte **kein** Docker auf dem Buildrechner installiert sein, so kann über -Ddocker.skip dieser Teil deaktiviert werden.
Naturgemäß wird aber dann auch kein Docker image gebaut.

## Tests

### Unittests

Unittests können mit dem property `-Dskip.unittests=true` disabled werden. In the idp-server submodule unit tests will
temporarily also set up the server but this is based on Junit runners and should not be mixed up with the integration
test server instance. Later runs in a separate fork.

### Integrationstests

Der Integrationstest kann entweder mit einer lokalen Instanz des IDP servers oder gegen einen remote verfügbaren Server
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
docker-compose build --nuild-args mode=untested # creates a docker image without running any tests
```

## Caveats

Aufgrund von ungeklärten Phänomenen im Lifecycle, empfiehlt es sich vor dem Ausführen von package, verify oder install
zuerst ein `mvn clean compile` auszuführen. Anschließend können Tests und Install targets aufgerufen werden. Sämtliche
Targets müssen aus dem **Basisverzeichnis idp-global** aufgerufen werden!

Ein wiederholtes mvn clean kann zu einer Fehlermeldung führen.

Um docker images zu entfernen, hilft mvn docker:remove, leider geht dies nur aus dem idp-server Verzeichnis. Auf top
Ebene wird das docker plugin nicht gefunden. Mehr Details dazu
gibts [auf dieser Seite](http://dmp.fabric8.io/#docker:remove))
   
