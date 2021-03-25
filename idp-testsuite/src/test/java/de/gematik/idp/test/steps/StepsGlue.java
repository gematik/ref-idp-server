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

package de.gematik.idp.test.steps;

import static org.assertj.core.api.Assertions.assertThat;
import de.gematik.idp.test.steps.helpers.*;
import de.gematik.idp.test.steps.model.*;
import io.cucumber.datatable.DataTable;
import io.cucumber.java.*;
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
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import net.thucydides.core.annotations.Steps;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.assertj.core.api.Assertions;
import org.json.JSONObject;


/**
 * TODO explain / reference to Context class for how to use the test context and test variables
 * <p>
 * TODO explain / reference to CucumberValuesConverter for how to use replacment / converter tokens
 * <ul><li>$NULL setting the current parameter/entry to null</li>
 * <lI>$REMOVE removing the current entry from parameter tables, and also partly from the arguments of
 * requests/steps</lI>
 * <li>${TESTENV.xxxxx} to replace this token with the configure test environment variable in
 * testsuite_config.properties</li>
 * <lI>${VAR.xxxxx} to replace this token with the current value of the variable</lI>
 * <lI>$FILL_FROM_CERT used in alt auth registration to populate pairing data from given certificate</lI>
 * </ul>
 * <p>
 * TODO explain / reference to JSONChecker for hwo to use the json comparison strings ("${json-unit.ignore}" et al)
 */
@Slf4j
public class StepsGlue {

    @Steps
    IdpDiscoveryDocumentSteps disc;

    @Steps
    IdpAuthenticationSteps auth;

    @Steps
    IdpAuthorizationSteps author;

    @Steps
    IdpAccessTokenSteps access;

    @Steps
    Context context;

    @Steps
    JsonChecker jsoncheck;

    @Steps
    CucumberValuesConverter cucumberValuesConverter;

    @Steps
    KeyAndCertificateStepsHelper keyAndCertificateStepsHelper;

    @Steps
    ClaimsStepHelper claimStepHelper;

    // =================================================================================================================
    //
    // B A S I C F L O W S
    //
    // =================================================================================================================

    /**
     * convenience step to request an access token of given type via signed challenge, signing the challenge with given
     * certificate in a single step.
     *
     * @param accessType type of access token to request
     * @param certFile   certificate to use for signing the challenge
     * @testenv client_id, redirect_uri
     * @gematik.context.out RESPONSE, CLAIMS?, HEADER_CLAIMS?, DISC_DOC, CHALLENGE, USER_CONSENT, SIGNED_CHALLENGE,
     * SSO_TOKEN, SSO_TOKEN_ENCRYPTED, TOKEN_REDIRECT_URL, CODE_VERIFIER, CLIENT_ID, STATE, TOKEN_CODE,
     * TOKEN_CODE_ENCRYPTED, REDIRECT_URI, PUK_DISC, PUK_SIGN, PUK_ENC, ACCESS_TOKEN, ID_TOKEN
     * @see CucumberValuesConverter
     */
    @Given("I request an {AccessTokenType} access token with eGK cert {string}")
    @SneakyThrows
    public void iRequestAnAccessTokenWitheGK(final AccessTokenType accessType, final String certFile) {
        final String state = RandomStringUtils.random(16, true, true);
        final String nonce = RandomStringUtils.random(20, true, true);
        final String codeVerifier = RandomStringUtils.random(60, true, true);
        auth.setCodeVerifier(codeVerifier);
        final Map<String, String> data = Stream.of(new String[][]{
            {"client_id", TestEnvironmentConfigurator.getTestEnvVar("client_id")},
            {"scope", accessType.toScope() + " openid"},
            {"code_challenge", auth.generateCodeChallenge(codeVerifier)},
            {"code_challenge_method", "S256"},
            {"redirect_uri", TestEnvironmentConfigurator.getTestEnvVar("redirect_uri")},
            {"state", state},
            {"nonce", nonce},
            {"response_type", "code"}
        }).collect(Collectors.collectingAndThen(
            Collectors.toMap(d -> d[0], d -> d[1]),
            Collections::<String, String>unmodifiableMap));
        auth.getChallenge(data, HttpStatus.NOCHECK);
        author.signChallenge(cucumberValuesConverter.parseDocString(certFile));
        author.getCode(CodeAuthType.SIGNED_CHALLENGE, HttpStatus.NOCHECK);
        Context.getThreadContext()
            .put(ContextKey.REDIRECT_URI, TestEnvironmentConfigurator.getTestEnvVar("redirect_uri"));
        access.getToken(HttpStatus.NOCHECK, null);
    }

    /**
     * convenience step to request an access token of given type via SSO token. For this first we need to obtain an SSO
     * Token via signed challenge, signing the challenge with given certificate. Then we use this sso token to request
     * another access token for given scope.
     *
     * @param accessType type of access token to request
     * @param certFile   certificate to use for signing the challenge
     * @testenv client_id, redirect_uri
     * @gematik.context.out RESPONSE, CLAIMS?, HEADER_CLAIMS?, DISC_DOC, CHALLENGE, USER_CONSENT, SIGNED_CHALLENGE,
     * SSO_TOKEN, SSO_TOKEN_ENCRYPTED, TOKEN_REDIRECT_URL, CODE_VERIFIER, CLIENT_ID, STATE, TOKEN_CODE,
     * TOKEN_CODE_ENCRYPTED, REDIRECT_URI, PUK_DISC, PUK_SIGN, PUK_ENC, ACCESS_TOKEN, ID_TOKEN
     * @see CucumberValuesConverter
     */
    @Given("I request an {AccessTokenType} access token via SSO token with eGK cert {string}")
    @SneakyThrows
    public void iRequestAnAccessTokenViaSsoToken(final AccessTokenType accessType, final String certFile) {
        iRequestAnAccessTokenWitheGK(accessType, cucumberValuesConverter.parseDocString(certFile));
        final String state = RandomStringUtils.random(16, true, true);
        final String nonce = RandomStringUtils.random(20, true, true);
        final String codeVerifier = RandomStringUtils.random(60, true, true);
        auth.setCodeVerifier(codeVerifier);
        final Map<String, String> data = Stream.of(new String[][]{
            {"client_id", TestEnvironmentConfigurator.getTestEnvVar("client_id")},
            {"scope", accessType.toScope() + " openid"},
            {"code_challenge", auth.generateCodeChallenge(codeVerifier)},
            {"code_challenge_method", "S256"},
            {"redirect_uri", TestEnvironmentConfigurator.getTestEnvVar("redirect_uri")},
            {"state", state},
            {"nonce", nonce},
            {"response_type", "code"}
        }).collect(Collectors.collectingAndThen(
            Collectors.toMap(d -> d[0], d -> d[1]),
            Collections::<String, String>unmodifiableMap));
        auth.getChallenge(data, HttpStatus.NOCHECK);
        author.getCode(CodeAuthType.SSO_TOKEN, HttpStatus.NOCHECK);
        Context.getThreadContext()
            .put(ContextKey.REDIRECT_URI, TestEnvironmentConfigurator.getTestEnvVar("redirect_uri"));
        access.getToken(HttpStatus.NOCHECK, null);
    }

    // =================================================================================================================
    //
    // D I S C O V E R Y D O C U M E N T
    //
    // =================================================================================================================

    /**
     * download the discovery document.
     *
     * @gematik.context.out RESPONSE
     */
    @Given("I request the discovery document")
    public void iRequestTheInternalDiscoveryDocument() {
        disc.iRequestTheInternalDiscoveryDocument(HttpStatus.NOCHECK);
    }

    /**
     * download discovery document and store it in test context.
     *
     * @gematik.context.out RESPONSE, DISC_DOC
     */
    @Given("I initialize scenario from discovery document endpoint")
    @SneakyThrows
    public void iInitializeScenarioFromDiscoveryDocumentEndpoint() {
        disc.initializeFromDiscoveryDocument();
    }

    /**
     * retrieve puk_idp_enc and puk_idp_sig from the uris specified in the discovery document and puk_disc from the x5c
     * header claim.
     *
     * @gematik.context.in DISC_DOC
     * @gematik.context.out PUK_ENC, PUK_SIGN, PUK_DISC
     */
    @Given("I retrieve public keys from URIs")
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
    @Given("I choose code verifier {string}")
    public void iChooseCodeVerifier(final String codeverifier) {
        auth.setCodeVerifier(cucumberValuesConverter.parseDocString(codeverifier));
    }

    /**
     * request a challenge from auth endpoint with given parameters.
     *
     * @param params list of params to be sent to the server
     * @gematik.context.out CLIENT_ID, RESPONSE, CHALLENGE, USER_CONSENT
     * @see CucumberValuesConverter
     */
    @When("I request a challenge with")
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
     * sign the stored challenge with given certificate
     *
     * @param keyfile file to read the certificate from
     * @gematik.context.in CHALLENGE
     * @gematik.context.out SIGNED_CHALLENGE
     * @see CucumberValuesConverter
     */
    @When("I sign the challenge with {string}")
    public void iSignTheChallengeWith(final String keyfile) {
        author.signChallenge(cucumberValuesConverter.parseDocString(keyfile));
    }

    /**
     * request a code token with given flow specifier. Parameters depend on flow type.
     *
     * @param authType type of flow to apply, defines which end point url and which parameters to use
     *                 <ul>
     *                     <li>Signed challenge flow: SIGNED_CHALLENGE</li>
     *                     <li>SSO Token flow: CHALLENGE, SSO_TOKEN, SSO_TOKEN_ENCRYPTED</li>
     *                     <li>Alt auth flow: SIGNED_AUTHENTICATION_DATA</li>
     *                  </ul>
     * @gematik.context.in DISC_DOC, PUK_ENC, CHALLENGE, SIGNED_CHALLENGE, SSO_TOKEN, SSO_TOKEN_ENCRYPTED,
     * SIGEND_AUTHENTICATION_DATA
     * @gematik.context.out RESPONSE, STATE, TOKEN_CODE, TOKEN_CODE_ENCRYPTED, SSO_TOKEN, SSO_TOKEN_ENCRYPTED
     */
    @When("I request a code token with {CodeAuthType}")
    @SneakyThrows
    public void iRequestACodeTokenWith(final CodeAuthType authType) {
        author.getCode(authType, HttpStatus.NOCHECK);
    }

    // =================================================================================================================
    //
    // T O K E N E N D P O I N T
    //
    // =================================================================================================================

    /**
     * request an access and id token from the token endpoint with the parameters given in the attached data table.
     *
     * @param params table of parameters to be sent with the request. These parameters will be stored in the test
     *               context.
     * @gematik.context.in TOKEN_CODE, CODE_VERIFIER, CLIENT_ID, TOKEN_CODE_ENCRYPTED, REDIRECT_URI
     * @gematik.context.out RESPONSE, ACCESS_TOKEN, ID_TOKEN, TOKEN_CODE, CODE_VERIFIER, CLIENT_ID,
     * TOKEN_CODE_ENCRYPTED, REDIRECT_URI
     * @see CucumberValuesConverter
     */
    @And("I request an access token with")
    public void iRequestAnAccessTokenWith(final DataTable params) {
        access.getToken(HttpStatus.NOCHECK, params);
    }

    /**
     * request an access and id token from the token endpoint with parameters filled from test context.
     *
     * @gematik.context.in TOKEN_CODE, CODE_VERIFIER, CLIENT_ID, TOKEN_CODE_ENCRYPTED, REDIRECT_URI
     * @gematik.context.out RESPONSE, ACCESS_TOKEN, ID_TOKEN
     */
    @And("I request an access token")
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
    @When("I extract the {ClaimLocation} claims")
    @SneakyThrows
    public void iExtractTheClaims(final ClaimLocation claimLocation) {
        claimStepHelper.iExtractTheClaims(claimLocation);
    }

    /**
     * extract body or header claims from the current response body's JSON attribute, assuming its a JWT.
     *
     * @param claimLocation whether to extract body or header claims
     * @param jsonName      name of the JSON attribute
     * @gematik.context.in RESPONSE
     * @gematik.context.out CLAIMS or HEADER_CLAIMS
     * @see CucumberValuesConverter
     */
    @When("I extract the {ClaimLocation} claims from response field {word}")
    @SneakyThrows
    public void iExtractTheClaims(final ClaimLocation claimLocation, final String jsonName) {
        claimStepHelper.iExtractTheClaimsFromResponseJsonField(
            cucumberValuesConverter.parseDocString(jsonName), claimLocation);
    }

    /**
     * send HTTP request to the URI retrieved from body claim with given name and check its return status.
     *
     * @param claimName name of the body claim to use as URI
     * @param method    HTTP request method
     * @param result    expected HTTP status
     * @gematik.context.in CLAIMS
     * @gematik.context.out RESPONSE
     * @see CucumberValuesConverter
     */
    @Given("I request the uri from claim {string} with method {HttpMethods} and status {HttpStatus}")
    @SneakyThrows
    public void iRequestTheUriFromClaimWithMethod(final String claimName, final HttpMethods method,
        final HttpStatus result) {
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
    @Then("the response content type matches {string}")
    public void theResponseContentTypeMatches(final String contentType) {
        disc.assertResponseContentTypeMatches(cucumberValuesConverter.parseDocString(contentType));
    }

    /**
     * assert the current response has at least the given headers, matching their values. Additional headers in the
     * response are not checked.
     *
     * @param kvps docstring containing key value pairs of the form key=value
     * @gematik.context.in RESPONSE
     * @see CucumberValuesConverter
     */
    @Then("the response http headers match")
    public void theResponseHTTPHeadersMatch(final String kvps) {
        disc.assertThatHttpResponseHeadersMatch(cucumberValuesConverter.parseDocString(kvps));
    }

    /**
     * assert that the 302 location header contains an URI with a parameter with given name and given value.
     *
     * @param param name of the parameter in the location URI
     * @param value expected value of the parameter
     * @gematik.context.in RESPONSE
     * @see CucumberValuesConverter
     */
    @Then("the response URI exists with param {string} and value {string}")
    public void theResponseLocationContainsParamAndValue(final String param, final String value) {
        disc.assertThatHttpResponseUriParameterContains(cucumberValuesConverter.parseDocString(param),
            cucumberValuesConverter.parseDocString(value));
    }

    /**
     * assert the current response is signed with the certificate from test context with given ContextKey. As of now
     * only the PUK_DISC cert is available in the test context.
     *
     * @param certKey test context key of the cert
     * @gematik.context.in RESPONSE, PUK_DISC
     */
    @And("the response must be signed with cert {ContextKey}")
    @SneakyThrows
    public void theResponseMustBeSignedWithCert(final ContextKey certKey) {
        disc.assertResponseIsSignedWithCert(certKey);
    }

    /**
     * assert the current response body is empty.
     *
     * @gematik.context.in RESPONSE
     */
    @Then("the response is empty")
    public void theResponseIsEmpty() {
        assertThat(Context.getCurrentResponse().getBody().asString()).isEmpty();
    }


    /**
     * assert the test context object with given key is signed by certificate with given test context key. As of now
     * only the PUK_DISC cert is available in the test context.
     *
     * @param tokenKey context key of the token to check
     * @param certKey  context key of the certificate to check
     * @gematik.context.in ANY TOKEN, PUK_DISC
     */
    @And("the context {ContextKey} must be signed with cert {ContextKey}")
    @SneakyThrows
    public void theContextMustBeSignedWithCert(final ContextKey tokenKey, final ContextKey certKey) {
        keyAndCertificateStepsHelper.assertContextIsSignedWithCertificate(tokenKey, certKey);
    }

    /**
     * assert the attribute with given name from body claims of current response contains an URI that is reachable via
     * given HTTP method and returns the given HTTP status code.
     *
     * @param claimName name of the body claim
     * @param method    HTTP method to use
     * @param status    expected HTTP status code
     * @gematik.context.in CLAIMS
     * @gematik.context.out RESPONSE
     * @see CucumberValuesConverter
     */
    @Then("URI in claim {string} exists with method {HttpMethods} and status {HttpStatus}")
    @SneakyThrows
    public void uriInClaimExistsWithMethodAndStatus(final String claimName, final HttpMethods method,
        final HttpStatus status) {
        disc.assertUriInClaimExistsWithMethodAndStatus(
            cucumberValuesConverter.parseDocString(claimName), method, status);
    }

    /**
     * assert the current response body matches the given string. First check for equal then applies given string as
     * regex pattern.
     *
     * @param toMatch string to equal / match.
     * @gematik.context.in RESPONSE
     * @see CucumberValuesConverter
     */
    @And("the response should match")
    public void theResponseShouldMatch(final String toMatch) {
        final String bodyStr = Context.getCurrentResponse().getBody().asString();
        if (!bodyStr.equals(cucumberValuesConverter.parseDocString(toMatch))) {
            assertThat(bodyStr).matches(cucumberValuesConverter.parseDocString(toMatch));
        }
    }

    /**
     * assert the current response body is a JSON object matching the given string (which must be a JSON
     * representation). The compare algorithm is rather complex and allows recursive checks. For more Details check
     * {@link JsonChecker}.
     *
     * @param toMatchJSON JSON string representation to match
     * @gematik.context.in RESPONSE
     * @see CucumberValuesConverter
     * @see JsonChecker
     */
    @Then("the JSON response should match")
    @SneakyThrows
    public void theJSONResponseShouldMatch(final String toMatchJSON) {
        jsoncheck.assertJsonShouldMatchInAnyOrder(
            Context.getCurrentResponse().getBody().asString(), cucumberValuesConverter.parseDocString(toMatchJSON));
    }

    /**
     * assert the current response body is a JSON array matching the given string (which must be a JSON representation).
     * The compare algorithm is rather complex and allows recursive checks. For more Details check {@link JsonChecker}.
     *
     * @param toMatchJSON JSON string representation to match
     * @gematik.context.in RESPONSE
     * @see CucumberValuesConverter
     * @see JsonChecker
     */
    @Then("the JSON Array response should match")
    public void theJSONArrayResponseShouldMatch(final String toMatchJSON) {
        jsoncheck.assertJsonArrayShouldMatchInAnyOrder(
            Context.getCurrentResponse().getBody().asString(), cucumberValuesConverter.parseDocString(toMatchJSON));
    }

    /**
     * assert the current response body is a JSON object and has the given node. The node is a path expression as used
     * by {@link net.javacrumbs.jsonunit.assertj.JsonAssert}
     *
     * @param path path expression that should exist
     * @gematik.context.in RESPONSE
     * @see CucumberValuesConverter
     */
    @Then("JSON response has node {string}")
    @SneakyThrows
    public void jSONResponseHasNode(final String path) {
        jsoncheck.assertJsonResponseHasNode(cucumberValuesConverter.parseDocString(path));
    }


    /**
     * assert the current response body is a JSON object and has exactly the given node at the given path. The path is a
     * path expression as used by {@link net.javacrumbs.jsonunit.assertj.JsonAssert}
     *
     * @param node name of the single node
     * @param path path where the single node should exist
     * @gematik.context.in RESPONSE
     * @see CucumberValuesConverter
     */
    @Then("JSON response has exactly one node {string} at {string}")
    @SneakyThrows
    public void jSONResponseHasExactlyOneNodeAt(final String node, final String path) {
        jsoncheck.assertJsonResponseHasExactlyOneNodeAt(cucumberValuesConverter.parseDocString(node),
            cucumberValuesConverter.parseDocString(path));
    }

    /**
     * assert the current body or header claims match the given string in any order.
     *
     * @param claimLocation body or header claims
     * @param toMatchJSON   string to compare the claims with
     * @gematik.context.in CLAIMS, HEADER_CLAIMS
     * @see CucumberValuesConverter
     */
    @Then("the {ClaimLocation} claims should match in any order")
    @SneakyThrows
    public void theClaimsShouldMatchInAnyOrder(final ClaimLocation claimLocation, final String toMatchJSON) {
        final JSONObject json = (JSONObject) (
            (claimLocation == ClaimLocation.body) ? Context.getCurrentClaims() :
                Context.getThreadContext().get(ContextKey.HEADER_CLAIMS)
        );
        jsoncheck.assertJsonShouldMatchInAnyOrder(
            json.toString(), cucumberValuesConverter.parseDocString(toMatchJSON));
    }

    /**
     * assert body or header claim with given name matches the given string.
     *
     * @param claimLocation body or header
     * @param claimName     name of the claim to check
     * @param regex         string to equal or match
     * @gematik.context.in CLAIMS, HEADER_CLAIMS
     * @see CucumberValuesConverter
     */
    @Then("the {ClaimLocation} claim {string} should match {string}")
    @SneakyThrows
    public void theClaimShouldMatch(final ClaimLocation claimLocation, final String claimName, final String regex) {
        final JSONObject json = (JSONObject) (
            (claimLocation == ClaimLocation.body) ? Context.getCurrentClaims() :
                Context.getThreadContext().get(ContextKey.HEADER_CLAIMS)
        );
        jsoncheck.assertJsonShouldMatch(new SerenityJSONObject(json), cucumberValuesConverter.parseDocString(claimName),
            cucumberValuesConverter.parseDocString(regex));
    }


    /**
     * assert body or header claim with given name does not equals and not match the given string.
     *
     * @param claimLocation body or header
     * @param claimName     name of the claim to check
     * @param regex         string to not equal and not match
     * @gematik.context.in CLAIMS, HEADER_CLAIMS
     * @see CucumberValuesConverter
     */
    @Then("the {ClaimLocation} claim {string} should not match {string}")
    @SneakyThrows
    public void theClaimShouldNotMatch(final ClaimLocation claimLocation, final String claimName, final String regex) {
        final JSONObject json = (JSONObject) (
            (claimLocation == ClaimLocation.body) ? Context.getCurrentClaims() :
                Context.getThreadContext().get(ContextKey.HEADER_CLAIMS)
        );
        jsoncheck
            .assertJsonShouldNotMatch(new SerenityJSONObject(json), cucumberValuesConverter.parseDocString(claimName),
                cucumberValuesConverter.parseDocString(regex));
    }

    /**
     * reset test context and empty all entries except the given ones.
     *
     * @param keys table of keys to keep
     * @gematik.context.out POTENTIALLY ALL KEYS REMOVED
     */
    @When("I start new interaction keeping only")
    public void iStartNewInteractionKeepingOnly(final List<ContextKey> keys) {
        context.iStartNewInteractionKeepingOnly(keys);
    }

    /**
     * set the test context key entry with given key to the given value. Applicable only to string entries.
     *
     * @param key   key of the test context entry to modify
     * @param value new value
     * @gematik.context.out USER_CONSENT, RESPONSE, DISC_DOC, HEADER_CLAIMS, CLAIMS
     * @see CucumberValuesConverter
     */
    @When("I set the context with key {ContextKey} to {string}")
    public void iSetTheContextWithKeyto(final ContextKey key, final String value) {
        context.setValue(key, cucumberValuesConverter.parseDocString(value));
    }

    /**
     * assert the context entry with given key matches the given string.
     *
     * @param key   test context key
     * @param regex string to equal or match
     * @see CucumberValuesConverter
     */
    @Then("I expect the Context with key {ContextKey} to match {string}")
    public void iExpectTheContextWithKeyToMatch(final ContextKey key, final String regex) {
        context.assertRegexMatches(key, cucumberValuesConverter.parseDocString(regex));
    }

    /**
     * flip the bit with given index of the test context entry with given key. Used to invalidate a signature blob.
     *
     * @param bitidx index of the bit to flip
     * @param key    test context key
     * @gematik.context.out ANY KEY
     */
    @And("I flip bit {int} on context with key {ContextKey}")
    public void iFlipBitOnContextWithKey(final int bitidx, final ContextKey key) {
        context.flipBit(bitidx, key);
    }

    /**
     * assert the current body or header claim contains a claim with given name that satisfies the given duration
     * constraint.
     *
     * @param claimLocation body or header
     * @param claim         name of the claim
     * @param compareMode   mode of comparison
     * @param duration      duration string in Java {@link Duration} notation.
     * @see CucumberValuesConverter
     * @see Duration
     */
    @And("the {ClaimLocation} claim {string} contains a date {DateCompareMode} {Duration}")
    @SneakyThrows
    public void theBodyClaimContainsADate(final ClaimLocation claimLocation, final String claim,
        final DateCompareMode compareMode, final Duration duration) {
        claimStepHelper
            .assertDateFromClaimMatches(claimLocation, cucumberValuesConverter.parseDocString(claim), compareMode,
                duration);
    }

    /**
     * extract body or header claim from token identified by given test context key. Both JWT and JWE are supported.
     *
     * @param cType body or header
     * @param token test context key of the token
     * @gematik.context.in ANY OF TOKEN_CODE_ENCRYPTED, SSO_TOKEN_ENCRYPTED, TOKEN_CODE, SIGNED_CHALLENGE, ACCESS_TOKEN,
     * ID_TOKEN
     * @gematik.context.out CLAIMS or HEADER_CLAIMS
     */
    @When("I extract the {ClaimLocation} claims from token {ContextKey}")
    @SneakyThrows
    public void iExtractTheClaimsFromToken(final ClaimLocation cType, final ContextKey token) {
        claimStepHelper.extractClaimsFromToken(cType, token);
    }

    /**
     * assert the current response should be a valid certificate.
     *
     * @gematik.context.in RESPONSE
     */
    @And("the JSON response should be a valid certificate")
    @SneakyThrows
    public void theJSONResponseShouldBeAValidCertificate() {
        keyAndCertificateStepsHelper
            .jsonObjectShouldBeValidCertificate(new JSONObject(Context.getCurrentResponse().getBody().asString()));
    }

    /**
     * assert the current response should be a valid public key.
     *
     * @gematik.context.in RESPONSE
     */
    @And("the JSON response should be a valid public key")
    public void theJSONResponseShouldBeAValidPublicKey() {
        keyAndCertificateStepsHelper
            .jsonObjectShouldBeValidPublicKey(new JSONObject(Context.getCurrentResponse().getBody().asString()));

    }

    /**
     * assert the current response should be a JSON object with an attribute at given path, containing an JSON array.
     * The array must contain an entry with given key id and this entry must be with valid certificate.
     *
     * @param jarray name of the attribute containing the key array
     * @param keyid  id of the key to check
     * @gematik.context.in RESPONSE
     * @see CucumberValuesConverter
     */
    @And("the JSON array {string} of response should contain valid certificates for {string}")
    @SneakyThrows
    public void theJSONArrayOfResponseShouldContainValidCertificatesWithKeyId(final String jarray, final String keyid) {
        keyAndCertificateStepsHelper.jsonArrayPathShouldContainValidCertificatesWithKeyId(
            cucumberValuesConverter.parseDocString(jarray),
            cucumberValuesConverter.parseDocString(keyid));
    }

    /**
     * assert the response is an error message with given status (302 or 4XX). The error message must contain the given
     * gematik error id and the given oauth error code. For 302 error messages the values are expected to be returned as
     * parameters in the Location header. For 4XX messages the response body should contain a JSON object.
     *
     * @param httpStatus expected HTTP status
     * @param errcode    expected Gematik error id
     * @param errstr     expected OAuth error code
     * @gematik.context.in RESPONSE
     * @see CucumberValuesConverter
     */
    @Then("the response is an {int} error with gematik code {int} and error {string}")
    public void theResponseIsAnErrorWithMessageMatching(final int httpStatus, final int errcode, final String errstr) {
        author.responseIsErrorWithMessageMatching(httpStatus, errcode, cucumberValuesConverter.parseDocString(errstr));
    }

    /**
     * wait for the given duration. Useful for specific timeouts in test scenarios.
     *
     * @param timeout duration string as used in {@link Duration}
     * @see Duration
     */
    @When("I wait {Duration}")
    @SneakyThrows
    public void iWait(final Duration timeout) {
        auth.wait(timeout);
    }

    /**
     * save test context entry with given key to file system. The file will be located under testartefacts foilder in a
     * dynamically created folder with pattern "yyyyMMdd_HH_mm" and will be named as the string value of the given
     * context key. This method can be used to save specific test context entries for later analysis. The content of the
     * file is the string representation of the entry applying the object's toString() method.
     *
     * @param key key of the test context entry to save
     * @gematik.context.in ANY KEY
     */
    @Then("I store {ContextKey} as text")
    @SneakyThrows
    public void iStoreContextKey(final ContextKey key) {
        final File f = new File("testartefacts" + File.separatorChar +
            DateTimeFormatter.ofPattern("yyyyMMdd_HH_mm").format(ZonedDateTime.now()));

        if (!f.exists()) {
            assertThat(f.mkdirs())
                .withFailMessage("Unable to create testartefact folder " + f.getAbsolutePath())
                .isTrue();
        }
        try (final FileOutputStream fos = new FileOutputStream(
            f.getAbsolutePath() + File.separatorChar + key + ".txt")) {
            fos.write(Context.getThreadContext().get(key).toString().getBytes(StandardCharsets.UTF_8));
        }
    }

    /**
     * load the test context entry with given key from given folder.
     *
     * @param key    test context key to load from file
     * @param folder folder to laod from
     * @gematik.context.out SSO_TOKEN, SSO_TOKEN_ENCRYPTED, ACCESS_TOKEN, ID_TOKEN
     * @see #iStoreContextKey(ContextKey)
     */
    @When("I load {ContextKey} from folder {string}")
    @SneakyThrows
    public void iLoadContextKeyFromFolder(final ContextKey key, final String folder) {
        final File f = new File("testartefacts" + File.separatorChar +
            cucumberValuesConverter.parseDocString(folder) + File.separatorChar + key + ".txt");
        final String str = IOUtils.toString(new FileInputStream(f), StandardCharsets.UTF_8);
        switch (key) {
            case SSO_TOKEN:
            case SSO_TOKEN_ENCRYPTED:
            case ACCESS_TOKEN:
            case ID_TOKEN:
                Context.getThreadContext().put(key, str);
                break;
            //TODO add support for all other keys
            default:
                Assertions.fail("Unsupported key (Feel free to implement)");
        }
    }

    /**
     * save body or header claim with given name as test variable with given name.
     *
     * @param claimLocation body or header
     * @param claimName     name of the claim to save
     * @param varname       name of the test variable to save the claim value to
     * @gematik.context.in ANY KEY
     * @see CucumberValuesConverter
     */
    @And("I store {ClaimLocation} claim {string} to variable {string}")
    public void iStoreClaimSubToVariable(final ClaimLocation claimLocation, final String claimName,
        final String varname) {
        final JSONObject json = (JSONObject) (
            (claimLocation == ClaimLocation.body) ? Context.getCurrentClaims() :
                Context.getThreadContext().get(ContextKey.HEADER_CLAIMS)
        );
        Context.storeVariable(
            cucumberValuesConverter.parseDocString(varname),
            json.getString(cucumberValuesConverter.parseDocString(claimName)));
    }


    // =================================================================================================================
    //
    // C U S T O M P A R A M E T E R T Y P E S
    //
    // =================================================================================================================
    @DataTableType
    @SneakyThrows
    public ContextKey getContextKey(final List<String> row) {
        return ContextKey.valueOf(row.get(0));
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
    public ContextKey ContextKey(final String contextKeyStr) {
        return ContextKey.valueOf(contextKeyStr);
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


    @Before
    public void initRbelLogger() {
        disc.initializeRbelLogger();
    }

    @After
    public void exportHTMLAndShutdownRbelLogger(final Scenario scenario) {
        disc.exportRbelLog(scenario);
    }
}
