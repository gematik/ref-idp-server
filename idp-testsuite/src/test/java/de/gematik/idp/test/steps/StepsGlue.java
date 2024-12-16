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

package de.gematik.idp.test.steps;

import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.test.steps.helpers.ClaimsStepHelper;
import de.gematik.idp.test.steps.helpers.CucumberValuesConverter;
import de.gematik.idp.test.steps.helpers.IdpTestEnvironmentConfigurator;
import de.gematik.idp.test.steps.helpers.JsonChecker;
import de.gematik.idp.test.steps.helpers.KeyAndCertificateStepsHelper;
import de.gematik.idp.test.steps.helpers.SerenityJSONObject;
import de.gematik.idp.test.steps.model.AccessTokenType;
import de.gematik.idp.test.steps.model.ClaimLocation;
import de.gematik.idp.test.steps.model.CodeAuthType;
import de.gematik.idp.test.steps.model.DateCompareMode;
import de.gematik.idp.test.steps.model.HttpMethods;
import de.gematik.idp.test.steps.model.HttpStatus;
import de.gematik.idp.test.steps.model.IdpEndpointType;
import de.gematik.test.bdd.Context;
import de.gematik.test.bdd.ContextKey;
import de.gematik.test.bdd.Variables;
import de.gematik.test.tiger.common.config.TigerGlobalConfiguration;
import io.cucumber.datatable.DataTable;
import io.cucumber.java.Before;
import io.cucumber.java.DataTableType;
import io.cucumber.java.ParameterType;
import io.cucumber.java.de.Gegebensei;
import io.cucumber.java.de.Und;
import io.cucumber.java.en.And;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import net.serenitybdd.annotations.Steps;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.assertj.core.api.Assertions;
import org.json.JSONObject;

/**
 * TODO explain / reference to Context class for how to use the test context and test variables
 *
 * <p>TODO explain / reference to CucumberValuesConverter for how to use replacment / converter
 * tokens
 *
 * <ul>
 *   <li>$NULL setting the current parameter/entry to null
 *   <lI>$REMOVE removing the current entry from parameter tables, and also partly from the
 *       arguments of requests/steps
 *   <li>${TESTENV.xxxxx} to replace this token with the configure test environment variable in
 *       testsuite_config.XXXXXX.properties
 *   <lI>${VAR.xxxxx} to replace this token with the current value of the variable
 *   <lI>$FILL_FROM_CERT used in alt auth registration to populate pairing data from given
 *       certificate
 * </ul>
 *
 * <p>TODO explain / reference to JSONChecker for hwo to use the json comparison strings
 * ("${json-unit.ignore}" et al)
 */
@Slf4j
public class StepsGlue {

  @Steps IdpDiscoveryDocumentSteps disc;

  @Steps IdpAuthenticationSteps auth;

  @Steps IdpAuthorizationSteps author;

  @Steps IdpAccessTokenSteps access;

  @Steps JsonChecker jsoncheck;

  @Steps CucumberValuesConverter cucumberValuesConverter;

  @Steps KeyAndCertificateStepsHelper keyAndCertificateStepsHelper;

  @Steps ClaimsStepHelper claimStepHelper;

  // =================================================================================================================
  //
  // B A S I C F L O W S
  //
  // =================================================================================================================

  /**
   * convenience step to request an access token of given type via signed challenge, signing the
   * challenge with given certificate in a single step. This step needs a data table following the
   * step with the parameters to be used, when creating the token.
   *
   * @param accessType type of access token to request (erezept or pairing)
   * @param certFile certificate resource to use for signing the challenge (either looked up via
   *     getResource() or if the string starts with "file://" looked up via file system look up. The
   *     file name string is not expected to be a file URL, so you may use normal file system paths
   *     afterwards (either relative or absolute))
   * @param dataTable optional list of parameters (client_id, scope, code_challenge,
   *     code_challenge_method, redirect_uri, state, nonce, rsponse_type)
   * @testenv client_id, redirect_uri
   * @gematik.context.in USER_AGENT
   * @gematik.context.out RESPONSE, CLAIMS?, HEADER_CLAIMS?, DISC_DOC, CHALLENGE, USER_CONSENT,
   *     SIGNED_CHALLENGE, SSO_TOKEN, SSO_TOKEN_ENCRYPTED, TOKEN_REDIRECT_URL, CODE_VERIFIER,
   *     CLIENT_ID, STATE, TOKEN_CODE, TOKEN_CODE_ENCRYPTED, REDIRECT_URI, PUK_DISC, PUK_SIGN,
   *     PUK_ENC, ACCESS_TOKEN, ID_TOKEN
   * @see CucumberValuesConverter
   */
  @Given("IDP I request an {word} access token with eGK cert {string} and given values")
  public void iRequestAnAccessTokenWitheGKAndGivenValues(
      final String accessType, final String certFile, final DataTable dataTable) {
    requestAnAccessTokenWitheGK(
        accessType,
        CodeAuthType.SIGNED_CHALLENGE,
        cucumberValuesConverter.parseDocString(certFile),
        "00",
        cucumberValuesConverter.getMapFromDatatable(dataTable));
  }

  /**
   * convenience step to request an access token of given type via SSO token. For this first we need
   * to obtain an SSO Token via signed challenge, signing the challenge with given certificate. Then
   * we use this sso token to request another access token for given scope. This step needs a data
   * table following the step with the parameters to be used, when creating the token.
   *
   * @param accessType type of access token to request (erezept or pairing)
   * @param certFile certificate resource to use for signing the challenge (either looked up via
   *     getResource() or if the string starts with "file://" looked up via file system look up. The
   *     file name string is not expected to be a file URL, so you may use normal file system paths
   *     afterwards (either relative or absolute))
   * @param dataTable optional list of parameters (client_id, scope, code_challenge,
   *     code_challenge_method, redirect_uri, state, nonce, rsponse_type)
   * @testenv client_id, redirect_uri
   * @gematik.context.in USER_AGENT
   * @gematik.context.out RESPONSE, CLAIMS?, HEADER_CLAIMS?, DISC_DOC, CHALLENGE, USER_CONSENT,
   *     SIGNED_CHALLENGE, SSO_TOKEN, SSO_TOKEN_ENCRYPTED, TOKEN_REDIRECT_URL, CODE_VERIFIER,
   *     CLIENT_ID, STATE, TOKEN_CODE, TOKEN_CODE_ENCRYPTED, REDIRECT_URI, PUK_DISC, PUK_SIGN,
   *     PUK_ENC, ACCESS_TOKEN, ID_TOKEN
   * @see CucumberValuesConverter
   */
  @Given(
      "IDP I request an {word} access token via SSO token with eGK cert {string} and given values")
  public void iRequestAnAccessTokenViaSsoTokenWithGivenValues(
      final String accessType, final String certFile, final DataTable dataTable) {
    Map<String, String> data = cucumberValuesConverter.getMapFromDatatable(dataTable);
    requestAnAccessTokenWitheGK(
        accessType,
        CodeAuthType.SIGNED_CHALLENGE,
        cucumberValuesConverter.parseDocString(certFile),
        "00",
        data);
    data = cucumberValuesConverter.getMapFromDatatable(dataTable);
    requestAnAccessTokenWitheGK(
        accessType,
        CodeAuthType.SSO_TOKEN,
        cucumberValuesConverter.parseDocString(certFile),
        "00",
        data);
  }

  /**
   * convenience step to request an access token of given type via signed challenge with default
   * values, signing the challenge with given certificate in a single step.
   *
   * @param accessType type of access token to request
   * @param certFile certificate resource to use for signing the challenge (either looked up via
   *     getResource() or if the string starts with "file://" looked up via file system look up. The
   *     file name string is not expected to be a file URL, so you may use normal file system paths
   *     afterwards (either relative or absolute))
   * @testenv client_id, redirect_uri
   * @gematik.context.in USER_AGENT
   * @gematik.context.out RESPONSE, CLAIMS?, HEADER_CLAIMS?, DISC_DOC, CHALLENGE, USER_CONSENT,
   *     SIGNED_CHALLENGE, SSO_TOKEN, SSO_TOKEN_ENCRYPTED, TOKEN_REDIRECT_URL, CODE_VERIFIER,
   *     CLIENT_ID, STATE, TOKEN_CODE, TOKEN_CODE_ENCRYPTED, REDIRECT_URI, PUK_DISC, PUK_SIGN,
   *     PUK_ENC, ACCESS_TOKEN, ID_TOKEN
   * @see CucumberValuesConverter
   */
  @Given("IDP I request an {AccessTokenType} access token with eGK cert {string}")
  @SneakyThrows
  public void iRequestAnAccessTokenWitheGK(
      final AccessTokenType accessType, final String certFile) {
    final Map<String, String> data =
        new HashMap<>(Map.of("scope", accessType.toScope() + " openid"));
    requestAnAccessTokenWitheGK(
        accessType.toString(),
        CodeAuthType.SIGNED_CHALLENGE,
        cucumberValuesConverter.parseDocString(certFile),
        "00",
        data);
  }

  /**
   * convenience step to request an access token of given type via SSO token with default values.
   * For this first we need to obtain an SSO Token via signed challenge, signing the challenge with
   * given certificate. Then we use this sso token to request another access token for given scope.
   *
   * @param accessType type of access token to request
   * @param certFile certificate resource to use for signing the challenge (either looked up via
   *     getResource() or if the string starts with "file://" looked up via file system look up. The
   *     file name string is not expected to be a file URL, so you may use normal file system paths
   *     afterwards (either relative or absolute))
   * @testenv client_id, redirect_uri
   * @gematik.context.in USER_AGENT
   * @gematik.context.out RESPONSE, CLAIMS?, HEADER_CLAIMS?, DISC_DOC, CHALLENGE, USER_CONSENT,
   *     SIGNED_CHALLENGE, SSO_TOKEN, SSO_TOKEN_ENCRYPTED, TOKEN_REDIRECT_URL, CODE_VERIFIER,
   *     CLIENT_ID, STATE, TOKEN_CODE, TOKEN_CODE_ENCRYPTED, REDIRECT_URI, PUK_DISC, PUK_SIGN,
   *     PUK_ENC, ACCESS_TOKEN, ID_TOKEN
   * @see CucumberValuesConverter
   */
  @Given("IDP I request an {AccessTokenType} access token via SSO token with eGK cert {string}")
  @SneakyThrows
  public void iRequestAnAccessTokenViaSsoToken(
      final AccessTokenType accessType, final String certFile) {
    Map<String, String> data = new HashMap<>(Map.of("scope", accessType.toScope() + " openid"));
    requestAnAccessTokenWitheGK(
        accessType.toString(),
        CodeAuthType.SIGNED_CHALLENGE,
        cucumberValuesConverter.parseDocString(certFile),
        "00",
        data);
    data = new HashMap<>(Map.of("scope", accessType.toScope() + " openid"));
    requestAnAccessTokenWitheGK(
        accessType.toString(),
        CodeAuthType.SSO_TOKEN,
        cucumberValuesConverter.parseDocString(certFile),
        "00",
        data);
  }

  /**
   * convenience step to request an access token of given type via signed challenge, signing the
   * challenge with given certificate in a single step. This step needs a data table following the
   * step with the parameters to be used, when creating the token.
   *
   * @param accessType type of access token to request (erezept or pairing)
   * @param certFile certificate resource to use for signing the challenge (either looked up via
   *     getResource() or if the string starts with "file://" looked up via file system look up. The
   *     file name string is not expected to be a file URL, so you may use normal file system paths
   *     afterwards (either relative or absolute))
   * @param password password to access the p12 key store
   * @param dataTable optional list of parameters (client_id, scope, code_challenge,
   *     code_challenge_method, redirect_uri, state, nonce, rsponse_type)
   * @testenv client_id, redirect_uri
   * @gematik.context.in USER_AGENT
   * @gematik.context.out RESPONSE, CLAIMS?, HEADER_CLAIMS?, DISC_DOC, CHALLENGE, USER_CONSENT,
   *     SIGNED_CHALLENGE, SSO_TOKEN, SSO_TOKEN_ENCRYPTED, TOKEN_REDIRECT_URL, CODE_VERIFIER,
   *     CLIENT_ID, STATE, TOKEN_CODE, TOKEN_CODE_ENCRYPTED, REDIRECT_URI, PUK_DISC, PUK_SIGN,
   *     PUK_ENC, ACCESS_TOKEN, ID_TOKEN
   * @see CucumberValuesConverter
   */
  @Given(
      "IDP I request an {word} access token with eGK cert {string}, password {string} and given"
          + " values")
  public void iRequestAnAccessTokenWitheGKKeyStorePasswordAndGivenValues(
      final String accessType,
      final String certFile,
      final String password,
      final DataTable dataTable) {
    requestAnAccessTokenWitheGK(
        accessType,
        CodeAuthType.SIGNED_CHALLENGE,
        cucumberValuesConverter.parseDocString(certFile),
        password,
        cucumberValuesConverter.getMapFromDatatable(dataTable));
  }

  /**
   * convenience step to request an access token of given type via SSO token. For this first we need
   * to obtain an SSO Token via signed challenge, signing the challenge with given certificate. Then
   * we use this sso token to request another access token for given scope. This step needs a data
   * table following the step with the parameters to be used, when creating the token.
   *
   * @param accessType type of access token to request (erezept or pairing)
   * @param certFile certificate resource to use for signing the challenge (either looked up via
   *     getResource() or if the string starts with "file://" looked up via file system look up. The
   *     file name string is not expected to be a file URL, so you may use normal file system paths
   *     afterwards (either relative or absolute))
   * @param password password to access the p12 key store
   * @param dataTable optional list of parameters (client_id, scope, code_challenge,
   *     code_challenge_method, redirect_uri, state, nonce, rsponse_type)
   * @testenv client_id, redirect_uri
   * @gematik.context.in USER_AGENT
   * @gematik.context.out RESPONSE, CLAIMS?, HEADER_CLAIMS?, DISC_DOC, CHALLENGE, USER_CONSENT,
   *     SIGNED_CHALLENGE, SSO_TOKEN, SSO_TOKEN_ENCRYPTED, TOKEN_REDIRECT_URL, CODE_VERIFIER,
   *     CLIENT_ID, STATE, TOKEN_CODE, TOKEN_CODE_ENCRYPTED, REDIRECT_URI, PUK_DISC, PUK_SIGN,
   *     PUK_ENC, ACCESS_TOKEN, ID_TOKEN
   * @see CucumberValuesConverter
   */
  @Given(
      "IDP I request an {word} access token via SSO token with eGK cert {string}, password {string}"
          + " and given values")
  public void iRequestAnAccessTokenViaSsoTokenWithKeyStorePasswordAndGivenValues(
      final String accessType,
      final String certFile,
      final String password,
      final DataTable dataTable) {
    Map<String, String> data = cucumberValuesConverter.getMapFromDatatable(dataTable);
    requestAnAccessTokenWitheGK(
        accessType,
        CodeAuthType.SIGNED_CHALLENGE,
        cucumberValuesConverter.parseDocString(certFile),
        password,
        data);
    data = cucumberValuesConverter.getMapFromDatatable(dataTable);
    requestAnAccessTokenWitheGK(
        accessType,
        CodeAuthType.SSO_TOKEN,
        cucumberValuesConverter.parseDocString(certFile),
        password,
        data);
  }

  /**
   * convenience step to request an access token of given type via signed challenge with default
   * values, signing the challenge with given certificate in a single step.
   *
   * @param accessType type of access token to request
   * @param certFile certificate resource to use for signing the challenge (either looked up via
   *     getResource() or if the string starts with "file://" looked up via file system look up. The
   *     file name string is not expected to be a file URL, so you may use normal file system paths
   *     afterwards (either relative or absolute))
   * @param password password to access the p12 key store
   * @testenv client_id, redirect_uri
   * @gematik.context.in USER_AGENT
   * @gematik.context.out RESPONSE, CLAIMS?, HEADER_CLAIMS?, DISC_DOC, CHALLENGE, USER_CONSENT,
   *     SIGNED_CHALLENGE, SSO_TOKEN, SSO_TOKEN_ENCRYPTED, TOKEN_REDIRECT_URL, CODE_VERIFIER,
   *     CLIENT_ID, STATE, TOKEN_CODE, TOKEN_CODE_ENCRYPTED, REDIRECT_URI, PUK_DISC, PUK_SIGN,
   *     PUK_ENC, ACCESS_TOKEN, ID_TOKEN
   * @see CucumberValuesConverter
   */
  @Given(
      "IDP I request an {AccessTokenType} access token with eGK cert {string} and password"
          + " {string}")
  @SneakyThrows
  public void iRequestAnAccessTokenWitheGKAndKeyStorePassword(
      final AccessTokenType accessType, final String certFile, final String password) {
    final Map<String, String> data =
        new HashMap<>(Map.of("scope", accessType.toScope() + " openid"));
    requestAnAccessTokenWitheGK(
        accessType.toString(),
        CodeAuthType.SIGNED_CHALLENGE,
        cucumberValuesConverter.parseDocString(certFile),
        password,
        data);
  }

  /**
   * convenience step to request an access token of given type via SSO token with default values.
   * For this first we need to obtain an SSO Token via signed challenge, signing the challenge with
   * given certificate. Then we use this sso token to request another access token for given scope.
   *
   * @param accessType type of access token to request
   * @param certFile certificate resource to use for signing the challenge (either looked up via
   *     getResource() or if the string starts with "file://" looked up via file system look up. The
   *     file name string is not expected to be a file URL, so you may use normal file system paths
   *     afterwards (either relative or absolute))
   * @param password password to access the p12 key store
   * @testenv client_id, redirect_uri
   * @gematik.context.in USER_AGENT
   * @gematik.context.out RESPONSE, CLAIMS?, HEADER_CLAIMS?, DISC_DOC, CHALLENGE, USER_CONSENT,
   *     SIGNED_CHALLENGE, SSO_TOKEN, SSO_TOKEN_ENCRYPTED, TOKEN_REDIRECT_URL, CODE_VERIFIER,
   *     CLIENT_ID, STATE, TOKEN_CODE, TOKEN_CODE_ENCRYPTED, REDIRECT_URI, PUK_DISC, PUK_SIGN,
   *     PUK_ENC, ACCESS_TOKEN, ID_TOKEN
   * @see CucumberValuesConverter
   */
  @Given(
      "IDP I request an {AccessTokenType} access token via SSO token with eGK cert {string} and"
          + " password {string}")
  @SneakyThrows
  public void iRequestAnAccessTokenWithKeyStorePasswordViaSsoToken(
      final AccessTokenType accessType, final String certFile, final String password) {
    Map<String, String> data = new HashMap<>(Map.of("scope", accessType.toScope() + " openid"));
    requestAnAccessTokenWitheGK(
        accessType.toString(),
        CodeAuthType.SIGNED_CHALLENGE,
        cucumberValuesConverter.parseDocString(certFile),
        password,
        data);
    data = new HashMap<>(Map.of("scope", accessType.toScope() + " openid"));
    requestAnAccessTokenWitheGK(
        accessType.toString(),
        CodeAuthType.SSO_TOKEN,
        cucumberValuesConverter.parseDocString(certFile),
        password,
        data);
  }

  @SneakyThrows
  public void requestAnAccessTokenWitheGK(
      final String accessType,
      final CodeAuthType authType,
      final String certFile,
      final String password,
      final Map<String, String> data) {
    final String codeVerifier =
        data.getOrDefault("codeVerifier", RandomStringUtils.random(60, true, true));
    data.remove("codeVerifier");
    auth.setCodeVerifier(codeVerifier);

    data.putIfAbsent("client_id", IdpTestEnvironmentConfigurator.getTestEnvVar("client_id"));
    data.putIfAbsent("scope", AccessTokenType.fromString(accessType).toScope() + " openid");
    data.putIfAbsent("code_challenge", auth.generateCodeChallenge(codeVerifier));
    data.putIfAbsent("code_challenge_method", "S256");
    data.putIfAbsent("redirect_uri", IdpTestEnvironmentConfigurator.getTestEnvVar("redirect_uri"));
    data.putIfAbsent("state", RandomStringUtils.random(16, true, true));
    data.putIfAbsent("nonce", RandomStringUtils.random(20, true, true));
    data.putIfAbsent("response_type", "code");

    auth.getChallenge(data, HttpStatus.SUCCESS);
    author.signChallenge(cucumberValuesConverter.parseDocString(certFile), password);
    author.getCode(authType, HttpStatus.SUCCESS);
    Context.get().put(ContextKey.REDIRECT_URI, data.get("redirect_uri"));
    access.getToken(HttpStatus.SUCCESS, null);
  }

  // =================================================================================================================
  //
  // D I S C O V E R Y D O C U M E N T
  //
  // =================================================================================================================

  /**
   * download the discovery document.
   *
   * @gematik.context.in USER_AGENT
   * @gematik.context.out RESPONSE
   */
  @Given("IDP I request the discovery document")
  public void iRequestTheInternalDiscoveryDocument() {
    disc.iRequestTheInternalDiscoveryDocument(HttpStatus.NOCHECK);
  }

  /**
   * download discovery document and store it in test context.
   *
   * @gematik.context.in USER_AGENT
   * @gematik.context.out RESPONSE, DISC_DOC
   */
  @Given("IDP I initialize scenario from discovery document endpoint")
  @Gegebensei("IDP ich initialisiere das Szenario mit dem Discovery Dokument Endpunkt")
  @SneakyThrows
  public void iInitializeScenarioFromDiscoveryDocumentEndpoint() {
    disc.initializeFromDiscoveryDocument();
  }

  /**
   * retrieve puk_idp_enc and puk_idp_sig from the uris specified in the discovery document and
   * puk_disc from the x5c header claim.
   *
   * @gematik.context.in DISC_DOC, USER_AGENT
   * @gematik.context.out PUK_ENC, PUK_SIGN, PUK_DISC
   */
  @Given("IDP I retrieve public keys from URIs")
  @Gegebensei("IDP ich hole die öffentlichen Schlüssel von ihren URIs")
  @SneakyThrows
  public void iRetrievePublicKeysFromURIs() {
    Context.getDiscoveryDocument().readPublicKeysFromURIs();
  }

  // =================================================================================================================
  //
  // A U T H E N T I C A T I O N
  //

  // =================================================================================================================

  /**
   * Add given code verifier to test context.
   *
   * @param codeverifier code verifier to store
   * @gematik.context.out CODE_VERIFIER
   * @see CucumberValuesConverter
   */
  @Given("IDP I choose code verifier {string}")
  public void iChooseCodeVerifier(final String codeverifier) {
    auth.setCodeVerifier(cucumberValuesConverter.parseDocString(codeverifier));
  }

  /**
   * request a challenge from auth endpoint with given parameters.
   *
   * @param params list of params to be sent to the server
   * @gematik.context.in USER_AGENT
   * @gematik.context.out CLIENT_ID, RESPONSE, CHALLENGE, USER_CONSENT
   * @see CucumberValuesConverter
   */
  @When("IDP I request a challenge with")
  @SneakyThrows
  public void iRequestAChallengeWith(final DataTable params) {
    auth.getChallenge(cucumberValuesConverter.getMapFromDatatable(params), HttpStatus.NOCHECK);
  }

  // =================================================================================================================
  //
  // A U T H O R I Z A T I O N
  //
  // =================================================================================================================

  /**
   * sign the stored challenge with given certificate and default password "00"
   *
   * @param keyfile file to read the certificate from
   * @param password password to access the p12 key store
   * @gematik.context.in CHALLENGE
   * @gematik.context.out SIGNED_CHALLENGE
   * @see CucumberValuesConverter
   */
  @When("IDP I sign the challenge with {string} and password {string}")
  public void iSignTheChallengeWithAndPassword(final String keyfile, final String password) {
    author.signChallenge(cucumberValuesConverter.parseDocString(keyfile), password);
  }

  /**
   * sign the stored challenge with given certificate and default password "00"
   *
   * @param keyfile file to read the certificate from
   * @gematik.context.in CHALLENGE
   * @gematik.context.out SIGNED_CHALLENGE
   * @see CucumberValuesConverter
   */
  @When("IDP I sign the challenge with {string}")
  public void iSignTheChallengeWith(final String keyfile) {
    author.signChallenge(cucumberValuesConverter.parseDocString(keyfile), "00");
  }

  /**
   * sign the stored challenge with given certificate and default password "00"
   *
   * @param keyfile file to read the certificate from
   * @gematik.context.in CHALLENGE
   * @gematik.context.out SIGNED_CHALLENGE
   * @see CucumberValuesConverter
   */
  @When("IDP I sign the challenge with {string} and Header Claims")
  public void iSignTheChallengeWithCertAndHeaders(final String keyfile, final DataTable params) {
    author.signChallengeWithSignaturHeaders(
        cucumberValuesConverter.parseDocString(keyfile),
        "00",
        cucumberValuesConverter.getMapFromDatatable(params));
  }

  /**
   * request a code token with given flow specifier. Parameters depend on flow type.
   *
   * @param authType type of flow to apply, defines which end point url and which parameters to use
   *     <ul>
   *       <li>Signed challenge flow: SIGNED_CHALLENGE
   *       <li>SSO Token flow: CHALLENGE, SSO_TOKEN, SSO_TOKEN_ENCRYPTED
   *       <li>Alt auth flow: SIGNED_AUTHENTICATION_DATA
   *     </ul>
   *
   * @gematik.context.in DISC_DOC, PUK_ENC, CHALLENGE, SIGNED_CHALLENGE, SSO_TOKEN,
   *     SSO_TOKEN_ENCRYPTED, SIGEND_AUTHENTICATION_DATA, USER_AGENT
   * @gematik.context.out RESPONSE, STATE, TOKEN_CODE, TOKEN_CODE_ENCRYPTED, SSO_TOKEN,
   *     SSO_TOKEN_ENCRYPTED
   */
  @When("IDP I request a code token with {CodeAuthType}")
  @SneakyThrows
  public void iRequestACodeTokenWith(final CodeAuthType authType) {
    author.getCode(authType, HttpStatus.NOCHECK);
  }

  /**
   * request a code token with given flow specifier. Parameters depend on flow type.
   *
   * @param authType type of flow to apply, defines which end point url and which parameters to use
   *     <ul>
   *       <li>Signed challenge flow: SIGNED_CHALLENGE
   *       <li>SSO Token flow: CHALLENGE, SSO_TOKEN, SSO_TOKEN_ENCRYPTED
   *       <li>Alt auth flow: SIGNED_AUTHENTICATION_DATA
   *     </ul>
   *
   * @gematik.context.in DISC_DOC, PUK_ENC, CHALLENGE, SIGNED_CHALLENGE, SSO_TOKEN,
   *     SSO_TOKEN_ENCRYPTED, SIGEND_AUTHENTICATION_DATA, USER_AGENT
   * @gematik.context.out RESPONSE, STATE, TOKEN_CODE, TOKEN_CODE_ENCRYPTED, SSO_TOKEN,
   *     SSO_TOKEN_ENCRYPTED
   */
  @When("IDP I request a code token with {CodeAuthType} successfully")
  @SneakyThrows
  public void iRequestACodeTokenWithSuccessfully(final CodeAuthType authType) {
    author.getCode(authType, HttpStatus.SUCCESS);
  }

  // =================================================================================================================
  //
  // T O K E N E N D P O I N T
  //
  // =================================================================================================================

  /**
   * request an access and id token from the token endpoint with the parameters given in the
   * attached data table.
   *
   * @param params table of parameters to be sent with the request. These parameters will be stored
   *     in the test context.
   * @gematik.context.in TOKEN_CODE, CODE_VERIFIER, CLIENT_ID, TOKEN_CODE_ENCRYPTED, REDIRECT_URI,
   *     USER_AGENT
   * @gematik.context.out RESPONSE, ACCESS_TOKEN, ID_TOKEN, TOKEN_CODE, CODE_VERIFIER, CLIENT_ID,
   *     TOKEN_CODE_ENCRYPTED, REDIRECT_URI
   * @see CucumberValuesConverter
   */
  @And("IDP I request an access token with")
  public void iRequestAnAccessTokenWith(final DataTable params) {
    access.getToken(HttpStatus.NOCHECK, params);
  }

  /**
   * request an access and id token from the token endpoint with parameters filled from test
   * context.
   *
   * @gematik.context.in TOKEN_CODE, CODE_VERIFIER, CLIENT_ID, TOKEN_CODE_ENCRYPTED, REDIRECT_URI,
   *     USER_AGENT
   * @gematik.context.out RESPONSE, ACCESS_TOKEN, ID_TOKEN
   */
  @And("IDP I request an access token")
  public void iRequestAnAccessToken() {
    access.getToken(HttpStatus.NOCHECK, null);
  }

  // =================================================================================================================
  //
  // H E L P E R S T E P S
  //
  // =================================================================================================================

  /**
   * extract body or header claims from the current response body, assuming its a JWT or JWE.
   *
   * @param claimLocation whether to extract body or header claims
   * @gematik.context.in RESPONSE
   * @gematik.context.out CLAIMS or HEADER_CLAIMS
   */
  @When("IDP I extract the {ClaimLocation} claims")
  @SneakyThrows
  public void iExtractTheClaims(final ClaimLocation claimLocation) {
    claimStepHelper.iExtractTheClaims(claimLocation);
  }

  /**
   * extract body or header claims from the current response body's JSON attribute, assuming its a
   * JWT.
   *
   * @param claimLocation whether to extract body or header claims
   * @param jsonName name of the JSON attribute
   * @gematik.context.in RESPONSE
   * @gematik.context.out CLAIMS or HEADER_CLAIMS
   * @see CucumberValuesConverter
   */
  @When("IDP I extract the {ClaimLocation} claims from response field {word}")
  @SneakyThrows
  public void iExtractTheClaims(final ClaimLocation claimLocation, final String jsonName) {
    claimStepHelper.iExtractTheClaimsFromResponseJsonField(
        cucumberValuesConverter.parseDocString(jsonName), claimLocation);
  }

  /**
   * send HTTP request to the URI retrieved from body claim with given name and check its return
   * status.
   *
   * @param claimName name of the body claim to use as URI
   * @param method HTTP request method
   * @param result expected HTTP status
   * @gematik.context.in CLAIMS, USER_AGENT
   * @gematik.context.out RESPONSE
   * @see CucumberValuesConverter
   */
  @Given(
      "IDP I request the uri from claim {string} with method {HttpMethods} and status {HttpStatus}")
  @SneakyThrows
  public void iRequestTheUriFromClaimWithMethod(
      final String claimName, final HttpMethods method, final HttpStatus result) {
    disc.iRequestTheUriFromClaim(cucumberValuesConverter.parseDocString(claimName), method, result);
  }

  /**
   * assert the current response has the given HTTP status code.
   *
   * @param status expected HTTP status code
   * @gematik.context.in RESPONSE
   */
  @Then("the response status is {HttpStatus}")
  public void theResponseStatusIs(final HttpStatus status) {
    disc.assertResponseStatusIs(status);
  }

  /**
   * assert the current response has the given content type
   *
   * @param contentType expected content type
   * @gematik.context.in RESPONSE
   * @see CucumberValuesConverter
   */
  @Then("IDP the response content type matches {string}")
  public void theResponseContentTypeMatches(final String contentType) {
    disc.assertResponseContentTypeMatches(cucumberValuesConverter.parseDocString(contentType));
  }

  /**
   * assert the current response has at least the given headers, matching their values. Additional
   * headers in the response are not checked.
   *
   * @param kvps docstring containing key value pairs of the form key=value
   * @gematik.context.in RESPONSE
   * @see CucumberValuesConverter
   */
  @Then("IDP the response http headers match")
  public void theResponseHTTPHeadersMatch(final String kvps) {
    disc.assertThatHttpResponseHeadersMatch(cucumberValuesConverter.parseDocString(kvps));
  }

  /**
   * assert that the 302 location header contains an URI with a parameter with given name and given
   * value.
   *
   * @param param name of the parameter in the location URI
   * @param value expected value of the parameter
   * @gematik.context.in RESPONSE
   * @see CucumberValuesConverter
   */
  @Then("IDP the response URI exists with param {string} and value {string}")
  public void theResponseLocationContainsParamAndValue(final String param, final String value) {
    disc.assertThatHttpResponseUriParameterContains(
        cucumberValuesConverter.parseDocString(param),
        cucumberValuesConverter.parseDocString(value));
  }

  /**
   * assert the current response is signed with the certificate from test context with given
   * ContextKey. As of now only the PUK_DISC cert is available in the test context.
   *
   * @param certKey test context key of the cert
   * @gematik.context.in RESPONSE, PUK_DISC
   */
  @And("IDP the response must be signed with cert {ContextKey}")
  @SneakyThrows
  public void theResponseMustBeSignedWithCert(final String certKey) {
    disc.assertResponseIsSignedWithCert(certKey);
  }

  /**
   * assert the test context object with given key is signed by certificate with given test context
   * key. As of now only the PUK_DISC cert is available in the test context.
   *
   * @param tokenKey context key of the token to check
   * @param certKey context key of the certificate to check
   * @gematik.context.in ANY TOKEN, PUK_DISC
   */
  @And("IDP the context {ContextKey} must be signed with cert {ContextKey}")
  @SneakyThrows
  public void theContextMustBeSignedWithCert(final String tokenKey, final String certKey) {
    keyAndCertificateStepsHelper.assertContextIsSignedWithCertificate(tokenKey, certKey);
  }

  /**
   * assert the attribute with given name from body claims of current response contains an URI that
   * is reachable via given HTTP method and returns the given HTTP status code.
   *
   * @param claimName name of the body claim
   * @param method HTTP method to use
   * @param status expected HTTP status code
   * @gematik.context.in CLAIMS, USER_AGENT
   * @gematik.context.out RESPONSE
   * @see CucumberValuesConverter
   */
  @Then("IDP URI in claim {string} exists with method {HttpMethods} and status {HttpStatus}")
  @SneakyThrows
  public void uriInClaimExistsWithMethodAndStatus(
      final String claimName, final HttpMethods method, final HttpStatus status) {
    disc.assertUriInClaimExistsWithMethodAndStatus(
        cucumberValuesConverter.parseDocString(claimName), method, status);
  }

  /**
   * assert the current response body matches the given string. First check for equal then applies
   * given string as regex pattern.
   *
   * @param toMatch string to equal / match.
   * @gematik.context.in RESPONSE
   * @see CucumberValuesConverter
   */
  @And("IDP the response should match")
  public void theResponseShouldMatch(final String toMatch) {
    final String bodyStr = Context.getCurrentResponse().getBody().asString();
    if (!bodyStr.equals(cucumberValuesConverter.parseDocString(toMatch))) {
      assertThat(bodyStr).matches(cucumberValuesConverter.parseDocString(toMatch));
    }
  }

  /**
   * assert the current response body is a JSON object matching the given string (which must be a
   * JSON representation). The compare algorithm is rather complex and allows recursive checks. For
   * more Details check {@link JsonChecker}.
   *
   * @param toMatchJSON JSON string representation to match
   * @gematik.context.in RESPONSE
   * @see CucumberValuesConverter
   * @see JsonChecker
   */
  @Then("IDP the JSON response should match")
  @SneakyThrows
  public void theJSONResponseShouldMatch(final String toMatchJSON) {
    jsoncheck.assertJsonShouldMatchInAnyOrder(
        Context.getCurrentResponse().getBody().asString(),
        cucumberValuesConverter.parseDocString(toMatchJSON));
  }

  /**
   * assert the current response body is a JSON array matching the given string (which must be a
   * JSON representation). The compare algorithm is rather complex and allows recursive checks. For
   * more Details check {@link JsonChecker}.
   *
   * @param toMatchJSON JSON string representation to match
   * @gematik.context.in RESPONSE
   * @see CucumberValuesConverter
   * @see JsonChecker
   */
  @Then("IDP the JSON Array response should match")
  public void theJSONArrayResponseShouldMatch(final String toMatchJSON) {
    jsoncheck.assertJsonArrayShouldMatchInAnyOrder(
        Context.getCurrentResponse().getBody().asString(),
        cucumberValuesConverter.parseDocString(toMatchJSON));
  }

  /**
   * assert the current response body is a JSON object and has the given node. The node is a path
   * expression as used by {@link net.javacrumbs.jsonunit.assertj.JsonAssert}
   *
   * @param path path expression that should exist
   * @gematik.context.in RESPONSE
   * @see CucumberValuesConverter
   */
  @Then("IDP JSON response has node {string}")
  @SneakyThrows
  public void jSONResponseHasNode(final String path) {
    jsoncheck.assertJsonResponseHasNode(cucumberValuesConverter.parseDocString(path));
  }

  /**
   * assert the current response body is a JSON object and has exactly the given node at the given
   * path. The path is a path expression as used by {@link
   * net.javacrumbs.jsonunit.assertj.JsonAssert}
   *
   * @param node name of the single node
   * @param path path where the single node should exist
   * @gematik.context.in RESPONSE
   * @see CucumberValuesConverter
   */
  @Then("IDP JSON response has exactly one node {string} at {string}")
  @SneakyThrows
  public void jSONResponseHasExactlyOneNodeAt(final String node, final String path) {
    jsoncheck.assertJsonResponseHasExactlyOneNodeAt(
        cucumberValuesConverter.parseDocString(node), cucumberValuesConverter.parseDocString(path));
  }

  /**
   * assert the current body or header claims match the given string in any order.
   *
   * @param claimLocation body or header claims
   * @param toMatchJSON string to compare the claims with
   * @gematik.context.in CLAIMS, HEADER_CLAIMS
   * @see CucumberValuesConverter
   */
  @Then("IDP the {ClaimLocation} claims should match in any order")
  @SneakyThrows
  public void theClaimsShouldMatchInAnyOrder(
      final ClaimLocation claimLocation, final String toMatchJSON) {
    final JSONObject json =
        (JSONObject)
            (Context.get()
                .get(
                    (claimLocation == ClaimLocation.body)
                        ? ContextKey.CLAIMS
                        : ContextKey.HEADER_CLAIMS));
    jsoncheck.assertJsonShouldMatchInAnyOrder(
        json.toString(), cucumberValuesConverter.parseDocString(toMatchJSON));
  }

  /**
   * assert body or header claim with given name matches the given string.
   *
   * @param claimLocation body or header
   * @param claimName name of the claim to check
   * @param regex string to equal or match
   * @gematik.context.in CLAIMS, HEADER_CLAIMS
   * @see CucumberValuesConverter
   */
  @Then("IDP the {ClaimLocation} claim {string} should match {string}")
  @SneakyThrows
  public void theClaimShouldMatch(
      final ClaimLocation claimLocation, final String claimName, final String regex) {
    final JSONObject json =
        (JSONObject)
            (Context.get()
                .get(
                    (claimLocation == ClaimLocation.body)
                        ? ContextKey.CLAIMS
                        : ContextKey.HEADER_CLAIMS));
    jsoncheck.assertJsonShouldMatch(
        new SerenityJSONObject(json),
        cucumberValuesConverter.parseDocString(claimName),
        cucumberValuesConverter.parseDocString(regex));
  }

  /**
   * assert body or header claim with given name does not equals and not match the given string.
   *
   * @param claimLocation body or header
   * @param claimName name of the claim to check
   * @param regex string to not equal and not match
   * @gematik.context.in CLAIMS, HEADER_CLAIMS
   * @see CucumberValuesConverter
   */
  @Then("IDP the {ClaimLocation} claim {string} should not match {string}")
  @SneakyThrows
  public void theClaimShouldNotMatch(
      final ClaimLocation claimLocation, final String claimName, final String regex) {
    final JSONObject json =
        (JSONObject)
            (Context.get()
                .get(
                    (claimLocation == ClaimLocation.body)
                        ? ContextKey.CLAIMS
                        : ContextKey.HEADER_CLAIMS));
    jsoncheck.assertJsonShouldNotMatch(
        new SerenityJSONObject(json),
        cucumberValuesConverter.parseDocString(claimName),
        cucumberValuesConverter.parseDocString(regex));
  }

  /**
   * reset test context and empty all entries except the given ones.
   *
   * @param keys table of keys to keep
   * @gematik.context.out POTENTIALLY ALL KEYS REMOVED
   */
  @When("IDP I start new interaction keeping only")
  public void iStartNewInteractionKeepingOnly(final List<String> keys) {
    Context.get().purgeButKeep(keys);
  }

  /**
   * set the test context key entry with given key to the given value. Applicable only to string
   * entries.
   *
   * @param key key of the test context entry to modify
   * @param value new value
   * @gematik.context.out all but USER_CONSENT, RESPONSE, DISC_DOC, HEADER_CLAIMS, CLAIMS
   * @see CucumberValuesConverter
   */
  @When("IDP I set the context with key {ContextKey} to {string}")
  public void iSetTheContextWithKeyto(final String key, final String value) {
    Context.get().putString(key, cucumberValuesConverter.parseDocString(value));
  }

  /**
   * assert the context entry with given key matches the given string.
   *
   * @param key test context key
   * @param regex string to equal or match
   * @gematik.context.in all but USER_CONSENT, RESPONSE, DISC_DOC, HEADER_CLAIMS, CLAIMS
   * @see CucumberValuesConverter
   */
  @Then("IDP I expect the Context with key {ContextKey} to match {string}")
  public void iExpectTheContextWithKeyToMatch(final String key, final String regex) {
    Context.get().assertRegexMatches(key, cucumberValuesConverter.parseDocString(regex));
  }

  /**
   * flip the bit with given index of the test context entry with given key. Used to invalidate a
   * signature blob.
   *
   * @param bitidx index of the bit to flip
   * @param key test context key
   * @gematik.context.out ANY KEY
   */
  @And("IDP I flip bit {int} on context with key {ContextKey}")
  public void iFlipBitOnContextWithKey(final int bitidx, final String key) {
    Context.get().flipBitInContextValue(bitidx, key);
  }

  /**
   * assert the current body or header claim contains a claim with given name that satisfies the
   * given duration constraint.
   *
   * @param claimLocation body or header
   * @param claim name of the claim
   * @param compareMode mode of comparison
   * @param duration duration string in Java {@link Duration} notation.
   * @gematik.context.in one of HEADER_CLAIMS, CLAIMS
   * @see CucumberValuesConverter
   * @see Duration
   */
  @And("IDP the {ClaimLocation} claim {string} contains a date {DateCompareMode} {Duration}")
  @SneakyThrows
  public void theBodyClaimContainsADate(
      final ClaimLocation claimLocation,
      final String claim,
      final DateCompareMode compareMode,
      final Duration duration) {
    claimStepHelper.assertDateFromClaimMatches(
        claimLocation, cucumberValuesConverter.parseDocString(claim), compareMode, duration);
  }

  /**
   * extract body or header claim from token identified by given test context key. Both JWT and JWE
   * are supported.
   *
   * @param cType body or header
   * @param token test context key of the token
   * @gematik.context.in ANY OF TOKEN_CODE_ENCRYPTED, SSO_TOKEN_ENCRYPTED, TOKEN_CODE,
   *     SIGNED_CHALLENGE, ACCESS_TOKEN, ID_TOKEN
   * @gematik.context.out CLAIMS or HEADER_CLAIMS
   */
  @When("IDP I extract the {ClaimLocation} claims from token {ContextKey}")
  @SneakyThrows
  public void iExtractTheClaimsFromToken(final ClaimLocation cType, final String token) {
    claimStepHelper.extractClaimsFromToken(cType, token);
  }

  /**
   * assert the current response should be a valid certificate.
   *
   * @gematik.context.in RESPONSE
   */
  @And("IDP the JSON response should be a valid certificate")
  @SneakyThrows
  public void theJSONResponseShouldBeAValidCertificate() {
    keyAndCertificateStepsHelper.jsonObjectShouldBeValidCertificate(
        new JSONObject(Context.getCurrentResponse().getBody().asString()));
  }

  /**
   * assert the current response should be a valid public key.
   *
   * @gematik.context.in RESPONSE
   */
  @And("IDP the JSON response should be a valid public key")
  public void theJSONResponseShouldBeAValidPublicKey() {
    keyAndCertificateStepsHelper.jsonObjectShouldBeValidPublicKey(
        new JSONObject(Context.getCurrentResponse().getBody().asString()));
  }

  /**
   * assert the current response should be a JSON object with an attribute at given path, containing
   * an JSON array. The array must contain an entry with given key id and this entry must be with
   * valid certificate.
   *
   * @param jarray name of the attribute containing the key array
   * @param keyid id of the key to check
   * @gematik.context.in RESPONSE
   * @see CucumberValuesConverter
   */
  @And("IDP the JSON array {string} of response should contain valid certificates for {string}")
  @SneakyThrows
  public void theJSONArrayOfResponseShouldContainValidCertificatesWithKeyId(
      final String jarray, final String keyid) {
    keyAndCertificateStepsHelper.jsonArrayPathShouldContainValidCertificatesWithKeyId(
        cucumberValuesConverter.parseDocString(jarray),
        cucumberValuesConverter.parseDocString(keyid));
  }

  /**
   * assert IDP the response is an error message with given status (302 or 4XX). The error message
   * must contain the given gematik error id and the given oauth error code. For 302 error messages
   * the values are expected to be returned as parameters in the Location header. For 4XX messages
   * the response body should contain a JSON object.
   *
   * @param httpStatus expected HTTP status
   * @param errcode expected Gematik error id
   * @param errstr expected OAuth error code
   * @gematik.context.in RESPONSE
   * @see CucumberValuesConverter
   */
  @Then("IDP the response is an {int} error with gematik code {int} and error {string}")
  public void theResponseIsAnErrorWithMessageMatching(
      final int httpStatus, final int errcode, final String errstr) {
    author.responseIsErrorWithMessageMatching(
        httpStatus, errcode, cucumberValuesConverter.parseDocString(errstr));
  }

  /**
   * wait for the given duration. Useful for specific timeouts in test scenarios.
   *
   * @param timeout duration string as used in {@link Duration}
   * @see Duration
   */
  @When("IDP I wait {Duration}")
  @SneakyThrows
  public void iWait(final Duration timeout) {
    auth.wait(timeout);
  }

  /**
   * save test context entry with given key to file system. The file will be located under
   * testartefacts foilder in a dynamically created folder with pattern "yyyyMMdd_HH_mm" and will be
   * named as the string value of the given context key. This method can be used to save specific
   * test context entries for later analysis. The content of the file is the string representation
   * of the entry applying the object's toString() method.
   *
   * @param key key of the test context entry to save
   * @gematik.context.in ANY KEY
   */
  @Then("IDP I store {ContextKey} as text")
  @SneakyThrows
  public void iStoreContextKey(final String key) {
    final File f =
        new File(
            "testartefacts"
                + File.separatorChar
                + DateTimeFormatter.ofPattern("yyyyMMdd_HH_mm").format(ZonedDateTime.now()));

    if (!f.exists()) {
      assertThat(f.mkdirs())
          .withFailMessage("Unable to create testartefact folder " + f.getAbsolutePath())
          .isTrue();
    }
    try (final FileOutputStream fos =
        new FileOutputStream(f.getAbsolutePath() + File.separatorChar + key + ".txt")) {
      fos.write(Context.get().get(key).toString().getBytes(StandardCharsets.UTF_8));
    }
  }

  /**
   * load the test context entry with given key from given folder.
   *
   * @param key test context key to load from file
   * @param folder folder to laod from
   * @gematik.context.out SSO_TOKEN, SSO_TOKEN_ENCRYPTED, ACCESS_TOKEN, ID_TOKEN
   * @see #iStoreContextKey(String)
   */
  @When("IDP I load {ContextKey} from folder {string}")
  @SneakyThrows
  public void iLoadContextKeyFromFolder(final String key, final String folder) {
    final File f =
        new File(
            "testartefacts"
                + File.separatorChar
                + cucumberValuesConverter.parseDocString(folder)
                + File.separatorChar
                + key
                + ".txt");
    final String str = IOUtils.toString(new FileInputStream(f), StandardCharsets.UTF_8);
    switch (key) {
      case ContextKey.SSO_TOKEN:
      case ContextKey.SSO_TOKEN_ENCRYPTED:
      case ContextKey.ACCESS_TOKEN:
      case ContextKey.ID_TOKEN:
        Context.get().put(key, str);
        break;
        // TODO add support for all other keys
      default:
        Assertions.fail("Unsupported key (Feel free to implement)");
    }
  }

  /**
   * save body or header claim with given name as test variable with given name.
   *
   * @param claimLocation body or header
   * @param claimName name of the claim to save
   * @param varname name of the test variable to save the claim value to
   * @gematik.context.in ANY KEY
   * @see CucumberValuesConverter
   */
  @And("IDP I store {ClaimLocation} claim {string} to variable {string}")
  public void iStoreClaimSubToVariable(
      final ClaimLocation claimLocation, final String claimName, final String varname) {
    final JSONObject json =
        (JSONObject)
            (Context.get()
                .get(
                    (claimLocation == ClaimLocation.body)
                        ? ContextKey.CLAIMS
                        : ContextKey.HEADER_CLAIMS));
    Variables.get()
        .putString(
            cucumberValuesConverter.parseDocString(varname),
            json.getString(cucumberValuesConverter.parseDocString(claimName)));
  }

  /**
   * set the user agent string to be used for all subsequent HTTP requests.
   *
   * @param userAgent user agent string
   * @gematik.context.out USER_AGENT
   * @see CucumberValuesConverter
   */
  @And("IDP I set user agent to {string}")
  public void iSetUserAgent(final String userAgent) {
    Context.get().put(ContextKey.USER_AGENT, cucumberValuesConverter.parseDocString(userAgent));
  }

  @And("IDP I add the token key {string} to the key folder")
  @Und("IDP Ich füge den token key {string} meinem Schklüsselverzeichnis hinzu")
  @SneakyThrows
  public void iAddTokenKeyFromConfig(final String tokenKeyLocation) {
    access.addAesKeyToRbelKeyManager(
        TigerGlobalConfiguration.resolvePlaceholders(
            TigerGlobalConfiguration.readString(tokenKeyLocation)));
  }

  // =================================================================================================================
  //
  // Z E N T R A L E R   I D P   F A S T   T R A C K
  //
  // =================================================================================================================

  // =================================================================================================================
  //
  // C U S T O M P A R A M E T E R T Y P E S
  //
  // =================================================================================================================
  @DataTableType
  @SneakyThrows
  public String getContextKey(final List<String> row) {
    return row.get(0);
  }

  @ParameterType(HttpStatus.CUCUMBER_REGEX)
  public HttpStatus HttpStatus(final String httpStatusStr) {
    return new HttpStatus(httpStatusStr);
  }

  @ParameterType("P[-\\d\\.DTHMS]*")
  public Duration Duration(final String durationStr) {
    return Duration.parse(durationStr);
  }

  @ParameterType(ClaimLocation.CUCUMBER_REGEX)
  public ClaimLocation ClaimLocation(final String claimLocationStr) {
    return ClaimLocation.valueOf(claimLocationStr);
  }

  @ParameterType(DateCompareMode.CUCUMBER_REGEX)
  public DateCompareMode DateCompareMode(final String dateCompareModeStr) {
    return DateCompareMode.fromString(dateCompareModeStr);
  }

  @ParameterType(ContextKey.CUCUMBER_REGEX)
  public String ContextKey(final String contextKeyStr) {
    return contextKeyStr;
  }

  @ParameterType(CodeAuthType.CUCUMBER_REGEX)
  public CodeAuthType CodeAuthType(final String codeAuthTypeStr) {
    return CodeAuthType.fromString(codeAuthTypeStr);
  }

  @ParameterType(HttpMethods.CUCUMBER_REGEX)
  public HttpMethods HttpMethods(final String httpMethodsStr) {
    return HttpMethods.valueOf(httpMethodsStr);
  }

  @ParameterType(AccessTokenType.CUCUMBER_REGEX)
  public AccessTokenType AccessTokenType(final String accessTokenTypeStr) {
    return AccessTokenType.fromString(accessTokenTypeStr);
  }

  @ParameterType(IdpEndpointType.CUCUMBER_REGEX)
  public IdpEndpointType IdpEndpointType(final String idpEndpointTypeStr) {
    return IdpEndpointType.fromString(idpEndpointTypeStr);
  }

  @Before
  public void initializeIDPTestEnvironment() {
    IdpTestEnvironmentConfigurator.initializeIDPTestEnvironment();
  }
}
