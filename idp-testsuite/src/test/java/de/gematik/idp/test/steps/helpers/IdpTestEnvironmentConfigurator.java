/*
 *  Copyright 2023 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.idp.test.steps.helpers;

import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.test.steps.model.CodeAuthType;
import de.gematik.test.bdd.TestEnvironmentConfigurator;
import de.gematik.test.tiger.common.config.TigerGlobalConfiguration;
import java.net.MalformedURLException;
import java.nio.file.Path;
import java.security.Key;
import javax.crypto.spec.SecretKeySpec;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.tomcat.util.buf.HexUtils;
import org.assertj.core.api.Assertions;

@Slf4j
public class IdpTestEnvironmentConfigurator extends TestEnvironmentConfigurator {

  public static final String IDP_SERVER = "IDP_SERVER";
  private static final String IDP_LOCAL_DISCDOC = "IDP_LOCAL_DISCDOC";
  private static final String DISCOVERY_URL_TEMPLATE =
      "http://idp" + /*127.0.0.1:%d*/ "/.well-known/openid-configuration";
  private static final String AUTHORIZATION_URL_SEKTORAL_IDP_TEMPLATE =
      "http://idpsektoral" + /*127.0.0.1:%d*/ "/authorization";
  private static final String ENV_AUTHORIZATION_URL_SEKTORAL_IDP = "AUTHORIZATION_URL_SEKTORAL_IDP";
  private static String DISCOVERY_URL = null;
  private static String AUTHORIZATION_URL_SEKTORAL_IDP;

  private static boolean initialized = false;

  public static synchronized String getDiscoveryDocumentURL() {
    return DISCOVERY_URL;
  }

  public static synchronized String getAuthorizationUrlSektoralIdpURL() {
    return AUTHORIZATION_URL_SEKTORAL_IDP;
  }

  public static synchronized boolean isRbelLoggerActive() {
    return getTestEnvProperty("logging.rbel.active", "0").equals("1");
  }

  public static synchronized String getFqdnInternet() {
    return getTestEnvProperty("TESTENV.fqdn_internet", "");
  }

  public static synchronized Key getSymmetricEncryptionKey(final CodeAuthType flowType) {
    assertThat(flowType)
        .isIn(
            CodeAuthType.SSO_TOKEN,
            CodeAuthType.SIGNED_CHALLENGE,
            CodeAuthType.ALTERNATIVE_AUTHENTICATION);

    final String propName =
        "encryption." + flowType.toString().toLowerCase().replace(" ", "") + ".symmetric.key";
    if (getTestEnvProperty(propName, null) != null) {
      return new SecretKeySpec(DigestUtils.sha256(getTestEnvProperty(propName, "")), "AES");
    } else {
      return new SecretKeySpec(
          HexUtils.fromHexString(getTestEnvProperty(propName + ".hex", "")), "AES");
    }
  }

  public static synchronized void initializeIDPTestEnvironment() {

    if (initialized) {
      return;
    }

    final String idpLocalDiscdoc = getProperty(IDP_LOCAL_DISCDOC);

    log.info("  initializing IDP Testenvironment...");
    final int serverPort =
        Integer.parseInt(
            TigerGlobalConfiguration.resolvePlaceholders(
                TigerGlobalConfiguration.readString("tiger.ports.idp")));
    final int sektoralIdpPort =
        Integer.parseInt(
            TigerGlobalConfiguration.resolvePlaceholders(
                TigerGlobalConfiguration.readString("tiger.ports.idpsektoral")));
    log.info("serverPort: {}", serverPort);
    log.info("sektoralIdpPort: {}", sektoralIdpPort);
    if (idpLocalDiscdoc == null || idpLocalDiscdoc.isBlank()) {
      if (getProperty(IDP_SERVER) != null) {
        log.info("Environment variable IDP_SERVER was set to: {}", getProperty(IDP_SERVER));
        DISCOVERY_URL = getProperty(IDP_SERVER);
        AUTHORIZATION_URL_SEKTORAL_IDP = getProperty(ENV_AUTHORIZATION_URL_SEKTORAL_IDP);
      } else {
        DISCOVERY_URL = String.format(DISCOVERY_URL_TEMPLATE, serverPort);
        AUTHORIZATION_URL_SEKTORAL_IDP =
            String.format(AUTHORIZATION_URL_SEKTORAL_IDP_TEMPLATE, sektoralIdpPort);
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
    log.info("IDP_SERVER_PORT          : {}", serverPort);
    log.info("IDP DISC DOC URI         : {}", DISCOVERY_URL);
    log.info("AUTHORIZATION_URL_SEKTORAL_IDP  : {}", AUTHORIZATION_URL_SEKTORAL_IDP);
    initialized = true;
  }
}
