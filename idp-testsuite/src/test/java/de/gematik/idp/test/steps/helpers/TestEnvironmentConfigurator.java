/*
 * Copyright (c) 2020 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.idp.test.steps.helpers;

import de.gematik.idp.brainPoolExtension.BrainpoolCurves;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

@Slf4j
public class TestEnvironmentConfigurator {

    private static final String DISCOVERY_URL_TEMPLATE = "http://localhost:%d/auth/realms/idp/.well-known/openid-configuration";
    private static String DISCOVERY_URL = null;

    public static synchronized String getDiscoveryDocumentURL() {
        // To allow IDE to simply call features/scenarios we do check for missing initialization in this call
        // neither EventListener nor Before did work as expected for both scenarios out of the box: mvn, IDE
        if (DISCOVERY_URL == null) {
            initializeTestEnvironment();
        }
        return DISCOVERY_URL;
    }

    public static void initializeTestEnvironment() {
        // initialize Jose4j to support Gematik specific brainpool curves
        BrainpoolCurves.init();

        if (System.getenv().containsKey("IDP_SERVER")) {
            DISCOVERY_URL = System.getenv("IDP_SERVER");
        } else {
            final int serverPort;
            final String s = System.getProperty("IDP_SERVER_PORT");
            if (StringUtils.isBlank(s)) {
                serverPort = 8080;
            } else {
                serverPort = Integer.parseInt(s);
            }
            DISCOVERY_URL = String.format(DISCOVERY_URL_TEMPLATE, serverPort);
        }
        log.info("======================================\n\n"
            + "Running Test against IDPSERVER " + DISCOVERY_URL
            + "\n\n======================================");
    }
}
