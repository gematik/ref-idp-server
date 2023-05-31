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

package de.gematik.test.bdd;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.Security;
import java.util.Comparator;
import java.util.Optional;
import java.util.Properties;
import lombok.extern.slf4j.Slf4j;
import org.assertj.core.api.Assertions;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * ${ENV.xxxxx} in property values will be replaced with the value of the environment variable xxxxx
 * at test run startup. ${TESTENV.xxxxx} in feature files values/params/tables will be replaced with
 * the value of the property TESTENV.xxxxx in the configured testsuite config properties file.
 */
@Slf4j
public class TestEnvironmentConfigurator {

  private static Properties props;

  static {
    initialize();
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    Security.insertProviderAt(new BouncyCastleProvider(), 1);
  }

  public static String getTestEnvVar(final String varName) {
    assertThat(props).containsKey("TESTENV." + varName);
    return props.getProperty("TESTENV." + varName);
  }

  public static String getTestEnvProperty(final String propName) {
    assertThat(props).containsKey(propName);
    return props.getProperty(propName);
  }

  public static String getTestEnvProperty(final String varName, final String defaultValue) {
    if (props.containsKey(varName)) {
      return props.getProperty(varName);
    } else {
      return defaultValue;
    }
  }

  private static void initialize() {
    String testEnv = System.getProperty("GEMATIK_TESTCONFIG");
    if (testEnv == null) {
      log.warn("Environment variable GEMATIK_TESTCONFIG not set, using value 'default'");
      testEnv = "default";
    }
    final File configFile = new File("testsuite_config." + testEnv + ".properties");

    log.info(
        "-----------------------------------------------------------------------------------------------");
    log.info("- T E S T   E N V I R O N M E N T");
    log.info("");
    log.info(
        "HTTPS PROXY : " + getProperty("https.proxyHost") + ":" + getProperty("https.proxyPort"));
    log.info(
        "HTTP PROXY  : " + getProperty("http.proxyHost") + ":" + getProperty("http.proxyPort"));
    log.debug("  initializing Testenvironment '" + testEnv + "'...");
    log.info("-------------");
    log.info("CONFIG FILE : " + configFile.getAbsolutePath());
    log.debug("  reading properties from '" + configFile.getAbsolutePath() + "'...");
    props = new Properties();
    try (final FileInputStream fis = new FileInputStream(configFile)) {
      props.load(fis);
    } catch (final IOException e) {
      throw new AssertionError(
          "Unable to load test suite configuration for test environment '" + testEnv + "'", e);
    }
    log.debug("  substituting env variables referenced in properties...");
    props
        .entrySet()
        .forEach(
            entry -> entry.setValue(substituteEnvironmentVariables(entry.getValue().toString())));
    props.entrySet().stream()
        .sorted(Comparator.comparing(left -> left.getValue().toString()))
        .forEach(entry -> log.info("Property " + entry.getKey() + " = '" + entry.getValue() + "'"));
    log.info(
        "-----------------------------------------------------------------------------------------------");
  }

  protected static String substituteEnvironmentVariables(String str) {
    int varIdx = str.indexOf("${ENV.");
    while (varIdx != -1) {
      final int endVar = str.indexOf("}", varIdx);
      final String varName = str.substring(varIdx + "${ENV.".length(), endVar);
      if (System.getenv(varName) == null) {
        Assertions.fail("Referenced Environment variable '" + varName + "' not set!");
      }
      str = str.substring(0, varIdx) + System.getProperty(varName, "") + str.substring(endVar + 1);
      varIdx = str.indexOf("${ENV.");
    }
    return str;
  }

  protected static String getSystemEnvString(final String envName) {
    return Optional.ofNullable(getProperty(envName)).orElse("NOT SET");
  }

  public static String getProperty(final String key) {
    return System.getProperty(key, System.getenv(key)); // fallback
  }
}
