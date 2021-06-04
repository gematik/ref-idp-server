# how to use

```
IDP_SERVER=https://idp-ref.zentral.idp.splitdns.ti-dienste.de/.well-known/openid-configuration
java -Dhttps.proxyHost=192.168.230.85 -Dhttps.proxyPort=3128 -jar target/idp-operations-18.0.0-SNAPSHOT-min.jar discdoc
```

Use cases:

* discdoc
* signedchallenge
* ssotoken
* altauth

## how to build

to avoid creating the fat jar on every build run of idp the fat jar is only built if profile "operations" is used

```
mvn package -P operations
```

To reduce the jar size to a halfway reasonable size use the minify.sh script
(for windows, expects 7z to be installed in default folder)

## exit codes

* 127 if the use case failed
* 128 if the cmd line params or env variables are not set/correct
* 129 if the use case is not implemented
