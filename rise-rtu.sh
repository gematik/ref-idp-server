#!/bin/bash

export IDP_SERVER=https://idp-test.zentral.idp.splitdns.ti-dienste.de/.well-known/openid-configuration
export GEMATIK_TESTCONFIG=rise-rtu

mvn clean verify -Dskip.unittests=true -Dhttps.proxyHost=192.168.230.85 -Dhttps.proxyPort=3128 \
  -Dcucumber.filter.tags="@Approval and not @OpenBug and not @WiP and not @LongRunning and not @Biometrics and not @RefImplOnly"

echo ""
echo ""
echo "Copying serenity report to "idp-testsuite/reports/serenity-$GEMATIK_TESTCONFIG" ..."
rm -rf idp-testsuite/reports/serenity-$GEMATIK_TESTCONFIG
cp -r idp-testsuite/target/site/serenity idp-testsuite/reports/serenity-$GEMATIK_TESTCONFIG

# and not @RefImplOnly
#"@TCID:IDP_REF_AUTH_052"
#"@Approval and not @OpenBug and not @WiP and not @LongRunning and not @Biometrics"
