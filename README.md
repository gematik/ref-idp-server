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
$ mvn clean install -pl idp-server -am -Dskip.unittests -Dskip.inttests -Dskip.dockerbuild=false
$ export appVersion=<...> # e.g. 29.1.6
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

### Configuration of Server URL

The URL of the idp-server is required for many fields inside the discovery document of the server.
For example, the
authorization endpoint:

```
{
"authorization_endpoint": "https://server42/sign_response",
...
```

The idp-server determines the URL in the following priority order if it exists:

1. jvm arg: --idp.serverUrl=https://myServerUrlAsJvmArgument.de
2. environment variable: IDP_SERVER_URL=myServerUrlFromEnv:8080
3. spring boot configuration (application.yml):

```
idp:
   serverUrl: "https://urlPreConfiguredUrl"
```

During development, it is recommended to set "severUrl" not in application.yml as some unit tests
will fail then.
Background: serverUrl will be set several times in the discovery document and used from there in
unit tests.
In unit tests, random (free) ports are used, and with that they are part of the serverUrl.

4. precompiled value: IdpConstants.DEFAULT_SERVER_URL

### Unittests

disable: `-Dskip.unittests`

All keys and p12 containers inside this repository were intentionally published. They allow the
project to be built ootb after a clean checkout and run the testsuite.

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
