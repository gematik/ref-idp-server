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

import de.gematik.idp.brainPoolExtension.BrainpoolCurves;
import java.io.FileInputStream;
import java.nio.file.Path;
import java.security.Key;
import java.util.Properties;
import javax.crypto.spec.SecretKeySpec;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;

@Slf4j
public class TestEnvironmentConfigurator {

    private static final String DISCOVERY_URL_TEMPLATE = "http://localhost:%d/auth/realms/idp/.well-known/openid-configuration";
    private static String DISCOVERY_URL = null;

    private static boolean TOKEN_ENCRYPTION_ACTIVE = false;
    private static String TOKEN_ENCRYPTION_KEY = "";

    public static synchronized String getDiscoveryDocumentURL() {
        // To allow IDE to simply call features/scenarios we do check for missing initialization in this call
        // neither EventListener nor Before did work as expected for both scenarios out of the box: mvn, IDE
        if (DISCOVERY_URL == null) {
            initializeTestEnvironment();
        }
        return DISCOVERY_URL;
    }

    public static synchronized boolean isTokenEncryptionActive() {
        if (DISCOVERY_URL == null) {
            initializeTestEnvironment();
        }
        return TOKEN_ENCRYPTION_ACTIVE;
    }

    public static synchronized Key getSymmetricEncryptionKey() {
        if (DISCOVERY_URL == null) {
            initializeTestEnvironment();
        }
        return new SecretKeySpec(DigestUtils.sha256(TOKEN_ENCRYPTION_KEY), "AES");
    }

    @SneakyThrows
    public static void initializeTestEnvironment() {
        // initialize Jose4j to support Gematik specific brainpool curves
        BrainpoolCurves.init();

        final String idpLocalDiscdoc = System.getenv("IDP_LOCAL_DISCDOC");
        final String idpServer = System.getenv("IDP_SERVER");
        final String idpServerPort = System.getenv("IDP_SERVER_PORT");

        log.info("Initializing Testenvironment...");
        log.info("Env IDP_LOCAL_DISCODOC {}", idpLocalDiscdoc);
        log.info("Env IDP_SERVER {}", idpServer);
        log.info("Env IDP_SERVER_PORT {}", idpServerPort);

        if (idpLocalDiscdoc == null || idpLocalDiscdoc.isBlank()) {
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
        } else {
            DISCOVERY_URL = Path.of(idpLocalDiscdoc).toUri().toURL().toExternalForm();
        }

        final Properties props = new Properties();
        props.load(new FileInputStream("testsuite_config.properties"));
        TOKEN_ENCRYPTION_ACTIVE = props.getProperty("encryption.token.active", "0").equals("1");
        TOKEN_ENCRYPTION_KEY = props.getProperty("encryption.symmetric.key", "");

        log.info("======================================\n\n"
            + "Running Test against Discovery Document " + DISCOVERY_URL
            + "\n\n======================================");
    }
}
