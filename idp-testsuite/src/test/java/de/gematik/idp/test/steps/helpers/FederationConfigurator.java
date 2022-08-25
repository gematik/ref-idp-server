/*
 * Copyright (c) 2022 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.idp.test.steps.helpers;

import static de.gematik.idp.EnvHelper.getSystemProperty;
import de.gematik.idp.brainPoolExtension.BrainpoolCurves;
import de.gematik.test.bdd.TestEnvironmentConfigurator;
import de.gematik.test.tiger.common.config.TigerGlobalConfiguration;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class FederationConfigurator extends TestEnvironmentConfigurator {

    private static String FEDMASTER_URL = "IDP_FEDMASTER";
    private static String IDP_FACHDIENST_URL = "IDP_FACHDIENST";
    private static String IDP_SEKTORAL = "IDP_SEKTORAL";

    static {
        initializeFederation();
    }

    public static synchronized String getFedmasterURL() {
        return FEDMASTER_URL;
    }

    public static synchronized String getFachdienstURL() {
        return IDP_FACHDIENST_URL;
    }

    public static synchronized String getIdpSektoralURL() {
        return IDP_SEKTORAL;
    }

    public static synchronized boolean isRbelLoggerActive() {
        return getTestEnvProperty("logging.rbel.active", "0").equals("1");
    }

    public static void initializeFederation() {

        // initialize Jose4j to support Gematik specific brainpool curves
        BrainpoolCurves.init();

        log.info("  initializing IDP Federation...");

        IDP_SEKTORAL = getServerUrl(IDP_SEKTORAL, getTigerPort("tiger.ports.idpsektoral"));
        FEDMASTER_URL = getServerUrl(FEDMASTER_URL, getTigerPort("tiger.ports.idpfedmaster"));
        IDP_FACHDIENST_URL = getServerUrl(IDP_FACHDIENST_URL, getTigerPort("tiger.ports.idpfachdienst"));

        log.info("FEDMASTER_URL         : {}", FEDMASTER_URL);
        log.info("FACHDIENST_URL         : {}", IDP_FACHDIENST_URL);
        log.info("IDP_SEKTORAL_URL         : {}", IDP_SEKTORAL);
    }

    private static String getTigerPort(final String cfgPort) {
        return TigerGlobalConfiguration.resolvePlaceholders(TigerGlobalConfiguration.readString(cfgPort));
    }

    private static String getServerUrl(final String serverEnvName, final String fallbackPort) {
        final StringBuilder strBuilder = new StringBuilder();
        strBuilder.append(getSystemProperty(serverEnvName).orElse("http://127.0.0.1"));
        strBuilder.append(":");
        strBuilder.append(getSystemProperty(serverEnvName + "_PORT").orElse(fallbackPort));
        return strBuilder.toString();
    }
}
