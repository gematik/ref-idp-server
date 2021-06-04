#!/bin/bash
VERSION=18.0.3
NEWJAR=idp-operations-$VERSION-min.jar

echo "-------------------------------------------"
echo "Copying shaded to min jar..."
rm -f target/idp-operations-$VERSION*.jar.tmp
cp target/idp-operations-$VERSION.jar target/$NEWJAR

echo "-------------------------------------------"
echo "Removing obsolete packages/folders..."
/c/Program\ Files/7-Zip/7z.exe d target/$NEWJAR BOOT-INF/* org/spring* org/glassfish* org/jruby* org/hibernate* org/h2* org/pcap4j* org/selenium* assets/* com/ibm/* wiremock/* META-INF/jruby* com/mysql* firefox/* liquibase/* native/* org/apache/pdfbox/* org/apache/catalina/* org/openqa/* org/thymeleaf/* org/eclipse/* META-INF/native/* META-INF/maven/* net/sourceforge/* org/jnetpcap/* org/apache/fontbox/* www.liquibase.org/* resources/* io/appium/* kotlin/* gems/* report-resources/* com/gargoylesoftware/* com/openhtmltopdf/*

echo "-------------------------------------------"
echo "DONE"
echo "-------------------------------------------"
ls -al target/$NEWJAR
