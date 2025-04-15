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

### idp-server logging

Logs are written via log4j2 to console.

Export `LOG_LEVEL_GEMATIK=<YOUR LOG LEVEL>` to set the log level.
Export REQUEST_LOGGING_ENABLED=true to enable request logging.
See also [idp-server application.yml](idp-server/src/main/resources/application.yml) for
configuration.

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

## License

Copyright 2025 gematik GmbH

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.

See the [LICENSE](./LICENSE) for the specific language governing permissions and limitations under the License.

## Additional Notes and Disclaimer from gematik GmbH

1. Copyright notice: Each published work result is accompanied by an explicit statement of the license conditions for use. These are regularly typical conditions in connection with open source or free software. Programs described/provided/linked here are free software, unless otherwise stated.
2. Permission notice: Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions::
    1. The copyright notice (Item 1) and the permission notice (Item 2) shall be included in all copies or substantial portions of the Software.
    2. The software is provided "as is" without warranty of any kind, either express or implied, including, but not limited to, the warranties of fitness for a particular purpose, merchantability, and/or non-infringement. The authors or copyright holders shall not be liable in any manner whatsoever for any damages or other claims arising from, out of or in connection with the software or the use or other dealings with the software, whether in an action of contract, tort, or otherwise.
    3. The software is the result of research and development activities, therefore not necessarily quality assured and without the character of a liable product. For this reason, gematik does not provide any support or other user assistance (unless otherwise stated in individual cases and without justification of a legal obligation). Furthermore, there is no claim to further development and adaptation of the results to a more current state of the art.
3. Gematik may remove published results temporarily or permanently from the place of publication at any time without prior notice or justification.
4. Please note: Parts of this code may have been generated using AI-supported technology.’ Please take this into account, especially when troubleshooting, for security analyses and possible adjustments.
