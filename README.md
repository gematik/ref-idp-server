## Overview

Das Projekt **IDP-Global** setzt sich aus verschiedenen Teilprojekten zusammen. Diese sind

* **IDP-Server:** Referenzentwicklung des zentralen IDPs
* **IDP-Client:** Client zur Beantragung von ACCESS_TOKEN mit SMC-B-Aut- oder HBA-Aut-Schlüsseln
  beim zentralen IDP
* **IDP-Testsuite:** Zulassungstestsuite für einen zentralen IDP, enthält auch Tests für Fast Track
  und föderierte IDPs

  <br>

* **IDP-Sektoral:** PoC für einen sektoralen IDP im Kontext Fast Track/föderierte IDPs
* **IDP-Fedmaster:** PoC für einen Föderationsmaster im Kontext föderierte IDPs
* **IDP-Fachdienst:** PoC für den Auth Server eines Fachdienstes im Kontext föderierte IDPs

Die letzten 3 Teilprojekte in o.s. Liste sind nicht Teil der
Referenzimplementierung/Veröffentlichung auf github.

### Idp-Server as docker image

#### Use existing image from docker hub

https://hub.docker.com/repository/docker/gematik1/idp-server

#### Build image of Idp-Server, 2 examples

in project root:

###### Example 1: build with all tests

```console 
$ mvn clean install -pl idp-server -am
```

###### Example 2: build without unit/int tests, set parameter commit_hash for dockerfile

```console 
$ mvn clean install -pl idp-server -am -Dskip.unittests -Dskip.inttests -Dcommit_hash=`git log --pretty=format:'%H' -n 1`
```

#### Start container

```console 
$ docker run --rm -it -p 8571:8080 gematik1/idp-server
```

or use docker compose:

```console
$ mvn clean install -pl idp-server -am -Dskip.unittests -Dskip.inttests
$ export appVersion=21.0.33
$ docker-compose --project-name myidp -f docker-compose-ref.yml up -d
```

#### Smoke test: get discovery document

```console 
$ curl http://localhost:8571/auth/realms/idp/.well-known/openid-configuration
```

### Scope Configuration via application.yaml

You can modify the scopes that are supported by the IDP Server. All you have to is add, remove or
modify entries in the scopesConfiguration section of the idp-server's application.yml.

### Unittests

disable: `-Dskip.unittests`

### Integrationstests/Zulassungstests

disable: `-Dskip.inttests`

Tests of the Idp-Testsuite are integration tests as well.<br>
Based on integration tests, approval tests are poosible. Please refer to
[README im submodule idp-testsuite](idp-testsuite/README.md).

## Caveats

Call all build targets always from project root ("idp-global").

## Tokenflow sites

* [TokenFlow EGK](https://gematik.github.io/ref-idp-server/tokenFlowEgk.html)
* [TokenFlow PS](https://gematik.github.io/ref-idp-server/tokenFlowPs.html)
* [TokenFlow SSO](https://gematik.github.io/ref-idp-server/tokenFlowSso.html)
   
