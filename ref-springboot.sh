#!/bin/bash

unset IDP_SERVER
export GEMATIK_TESTCONFIG=default

mvn clean verify -Dskip.unittests=true \
  -Dcucumber.filter.tags="@Approval and not @OpenBug and not @WiP and not @LongRunning"

echo ""
echo ""
echo "Copying serenity report to "idp-testsuite/reports/serenity-$GEMATIK_TESTCONFIG" ..."
rm -rf idp-testsuite/reports/serenity-$GEMATIK_TESTCONFIG
cp -r idp-testsuite/target/site/serenity idp-testsuite/reports/serenity-$GEMATIK_TESTCONFIG

# and not @RefImplOnly
#"@TCID:IDP_REF_AUTH_052"
#"@Approval and not @OpenBug and not @WiP and not @LongRunning and not @Biometrics"
