/*
 * Copyright (c) 2021 gematik GmbH
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

import static org.assertj.core.api.Assertions.assertThat;
import de.gematik.idp.brainPoolExtension.BrainpoolCurves;
import de.gematik.idp.test.steps.model.CodeAuthType;
import de.gematik.test.bdd.TestEnvironmentConfigurator;
import java.net.MalformedURLException;
import java.nio.file.Path;
import java.security.Key;
import javax.crypto.spec.SecretKeySpec;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;
import org.assertj.core.api.Assertions;

@Slf4j
public class IdpTestEnvironmentConfigurator extends TestEnvironmentConfigurator {

    private static final String IDP_LOCAL_DISCDOC = "IDP_LOCAL_DISCDOC";
    private static final String IDP_SERVER_PORT = "IDP_SERVER_PORT";
    private static final String DISCOVERY_URL_TEMPLATE = "http://localhost:%d/auth/realms/idp/.well-known/openid-configuration";
    public static final String IDP_SERVER = "IDP_SERVER";
    private static String DISCOVERY_URL = null;

    static {
        initializeIDPTestEnvironment();
    }

    public static synchronized String getDiscoveryDocumentURL() {
        return DISCOVERY_URL;
    }

    public static synchronized boolean isRbelLoggerActive() {
        return getTestEnvProperty("logging.rbel.active", "0").equals("1");
    }

    public static synchronized Key getSymmetricEncryptionKey(final CodeAuthType flowType) {
        assertThat(flowType)
            .isIn(CodeAuthType.SSO_TOKEN, CodeAuthType.SIGNED_CHALLENGE, CodeAuthType.ALTERNATIVE_AUTHENTICATION);
        return new SecretKeySpec(DigestUtils.sha256(
            getTestEnvProperty(
                "encryption." +
                    flowType.toString().toLowerCase().replace(" ", "") +
                    ".symmetric.key", "")),
            "AES");
    }

    public static void initializeIDPTestEnvironment() {

        // initialize Jose4j to support Gematik specific brainpool curves
        BrainpoolCurves.init();

        final String idpLocalDiscdoc = System.getenv(IDP_LOCAL_DISCDOC);
        final String idpServerPort = System.getenv(IDP_SERVER_PORT);

        log.info("  initializing IDP Testenvironment...");
        if (idpLocalDiscdoc == null || idpLocalDiscdoc.isBlank()) {
            if (System.getenv().containsKey(IDP_SERVER)) {
                DISCOVERY_URL = System.getenv(IDP_SERVER);
            } else {
                final int serverPort;
                final String s = System.getProperty(IDP_SERVER_PORT);
                if (StringUtils.isBlank(s)) {
                    serverPort = 8080;
                } else {
                    serverPort = Integer.parseInt(s);
                }
                DISCOVERY_URL = String.format(DISCOVERY_URL_TEMPLATE, serverPort);
            }
        } else {
            try {
                DISCOVERY_URL = Path.of(idpLocalDiscdoc).toUri().toURL().toExternalForm();
            } catch (final MalformedURLException e) {
                Assertions.fail("Unable to look up local discovery document", e);
            }
        }
        log.info("IDP_LOCAL_DISCODOC       : {}", getSystemEnvString(IDP_LOCAL_DISCDOC));
        log.info("IDP_SERVER               : {}", getSystemEnvString(IDP_SERVER));
        log.info("IDP_SERVER_PORT          : {}", getSystemEnvString(IDP_SERVER_PORT));
        log.info("IDP DISC DOC URI         : {}", DISCOVERY_URL);
    }
}
