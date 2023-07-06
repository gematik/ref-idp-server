## Disclaimer

This software is not developed for productive use. It was developed to check the feasibility of the
specification.

## Overview

The **IDP-Global** project consists of various sub-projects. These are

* **IDP-Server:** Reference development of the central IDP
* **IDP-Client:** Client to request ACCESS_TOKEN with SMC-B-Aut or HBA-Aut keys
  at the central IDP
* **IDP-Testsuite:** Approval test suite for a central IDP, also includes tests for Fast Track
  and federated IDPs

  <br>

* **IDP-Sektoral:** PoC for a sectoral IDP in the Fast Track context
* **IDP-Fedmaster:** PoC for a federation master in the context of federated IDPs

The last 2 sub-projects in the list above are not part of the reference implementation published on
github.

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
$ export appVersion=24.1.0
$ export serverLoglevel=info (default)
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

### Integration Testing/Approval Testing

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

## Swagger

find generated API at: /swagger-ui/index.html
