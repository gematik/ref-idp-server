#!/bin/bash

export IDP_SERVER=1
export IDP_LOCAL_DISCDOC_PKEY_PWD=00
export IDP_LOCAL_DISCDOC=discovery_document

mvn clean verify -Dskip.unittests=true -Dhttps.proxyHost=192.168.230.85 -Dhttps.proxyPort=3128
