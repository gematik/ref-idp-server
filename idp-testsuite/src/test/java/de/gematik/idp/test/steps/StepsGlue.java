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

import de.gematik.idp.test.steps.helpers.JsonChecker;
import de.gematik.idp.test.steps.helpers.SerenityJSONObject;
import de.gematik.idp.test.steps.model.ClaimLocation;
import de.gematik.idp.test.steps.model.CodeAuthType;
import de.gematik.idp.test.steps.model.Context;
import de.gematik.idp.test.steps.model.ContextKey;
import de.gematik.idp.test.steps.model.DateCompareMode;
import de.gematik.idp.test.steps.model.HttpMethods;
import de.gematik.idp.test.steps.model.HttpStatus;
import io.cucumber.datatable.DataTable;
import io.cucumber.java.en.And;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import java.io.IOException;
import java.net.URISyntaxException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.time.Duration;
import lombok.extern.slf4j.Slf4j;
import net.thucydides.core.annotations.Steps;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.lang.JoseException;
import org.json.JSONException;
import org.json.JSONObject;

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

    // =================================================================================================================
    //
    // D I S C O V E R Y D O C U M E N T
    //
    // =================================================================================================================

    @Given("I request the discovery document")
    public void iRequestTheInternalDiscoveryDocument() {
        disc.iRequestTheInternalDiscoveryDocument(HttpStatus.NOCHECK);
    }

    // =================================================================================================================
    //
    // A U T H E N T I C A T I O N
    //
    // =================================================================================================================

    @Given("I initialize scenario from discovery document endpoint")
    public void iInitializeScenarioFromDiscoveryDocumentEndpoint() throws JSONException, InvalidJwtException {
        auth.initializeFromDiscoveryDocument();
    }

    @Given("I choose code verifier {string}")
    public void iChooseCodeVerifier(final String codeverifier) {
        auth.setCodeVerifier(codeverifier);
    }

    @When("I request a challenge with")
    public void iRequestAChallengeWith(final DataTable params) throws JSONException {
        auth.getChallenge(params, HttpStatus.NOCHECK);
    }

    // =================================================================================================================
    //
    // A U T H O R I Z A T I O N
    //
    // =================================================================================================================

    @When("I request a code token with {CodeAuthType}")
    public void iRequestACodeTokenWith(final CodeAuthType authType) throws URISyntaxException {
        author.getCode(authType, HttpStatus.NOCHECK);
    }

    @When("I sign the challenge with {string}")
    public void iSignTheChallengeWith(final String keyfile)
        throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, JoseException {
        author.signChallenge(keyfile);
    }

    // =================================================================================================================
    //
    // T O K E N E N D P O I N T
    //
    // =================================================================================================================

    @And("I request an access token with")
    public void iRequestAnAccessTokenWith(final DataTable params) {
        access.getToken(HttpStatus.NOCHECK, params);
    }

    @And("I request an access token")
    public void iRequestAnAccessToken() {
        access.getToken(HttpStatus.NOCHECK, null);
    }

    // =================================================================================================================
    //
    // H E L P E R S T E P S
    //
    // =================================================================================================================


    @When("I extract the {ClaimLocation} claims")
    public void iExtractTheClaims(final ClaimLocation claimLocation) throws Throwable {
        disc.iExtractTheClaims(claimLocation);
    }

    @When("I extract the {ClaimLocation} claims from response field {word}")
    public void iExtractTheClaims(final ClaimLocation claimLocation, final String jsonName) throws Throwable {
        disc.iExtractTheClaimsFromResponseJsonField(jsonName, claimLocation);
    }

    @Given("I request the uri from claim {string} with method {HttpMethods} and status {HttpStatus}")
    public void iRequestTheUri(final String claimName, final HttpMethods method, final HttpStatus result)
        throws JSONException {
        disc.iRequestTheUriFromClaim(claimName, method, result);
    }

    @Then("the response status is {HttpStatus}")
    public void theResponseStatusIs(final HttpStatus status) {
        disc.assertResponseStatusIs(status);
    }

    @Then("the response content type is {string}")
    public void theResponseContentTypeIs(final String contentType) {
        disc.assertResponseContentTypeIs(contentType);
    }

    @Then("the response http headers match")
    public void theResponseHTTPHeadersMatch(final String kvps) {
        disc.assertThatHttpResponseHeadersMatch(kvps);
    }

    @Then("the response URI exists with param {string} and value {string}")
    public void theResponseLocationContainsParamAndValue(final String param, final String value) {
        disc.assertThatHttpResponseUriParameterContains(param, value);
    }

    @And("the response must be signed with cert {string}")
    public void theResponseMustBeSignedWithCert(final String filename) throws Throwable {
        disc.assertResponseIsSignedWithCert(filename);
    }

    @Then("URI in claim {string} exists with method {HttpMethods} and status {HttpStatus}")
    public void uriInClaimExistsWithMethod(final String claimName, final HttpMethods method, final HttpStatus status)
        throws JSONException {
        disc.assertUriInClaimExistsWithMethodAndStatus(claimName, method, status);
    }

    @Then("JSON response has node {string}")
    public void jSONResponseHasNode(final String path) throws JSONException {
        jsoncheck.assertJsonResponseHasNode(path);
    }

    @Then("the JSON response should match")
    public void theJSONResponseShouldMatch(final String toMatchJSON) throws JSONException {
        final JSONObject json = new JSONObject(Context.getCurrentResponse().getBody().asString());
        jsoncheck.assertJsonShouldMatchInAnyOrder(new SerenityJSONObject(json), new SerenityJSONObject(toMatchJSON));
    }

    @Then("JSON response has exactly one node {string} at {string}")
    public void jSONResponseHasExactlyOneNodeAt(final String node, final String path) throws JSONException {
        jsoncheck.assertJsonResponseHasExactlyOneNodeAt(node, path);
    }

    @Then("the {ClaimLocation} claims should match in any order")
    public void theClaimsShouldMatchInAnyOrder(final ClaimLocation claimLocation, final String toMatchJSON)
        throws JSONException {
        final JSONObject json;
        if (claimLocation == ClaimLocation.body) {
            json = Context.getCurrentClaims();
        } else {
            json = (JSONObject) Context.getThreadContext().get(ContextKey.HEADER_CLAIMS);
        }
        jsoncheck.assertJsonShouldMatchInAnyOrder(new SerenityJSONObject(json), new SerenityJSONObject(toMatchJSON));
    }

    @When("I start new interaction keeping only {ContextKey}")
    public void iStartNewInteractionKeepingOnly(final ContextKey key) {
        context.iStartNewInteractionKeepingOnly(key);
    }

    @When("I set the context with key {ContextKey} to {string}")
    public void iSetTheContextWithKeyto(final ContextKey key, final String value) {
        context.setValue(key, value);
    }

    @Then("I expect the Context with key {ContextKey} to match {string}")
    public void iExpectTheContextWithKeyToMatch(final ContextKey key, final String regex) {
        context.assertRegexMatches(key, regex);
    }

    @And("I flip bit {int} on context with key {ContextKey}")
    public void iFlipBitOnContextWithKey(final int bitidx, final ContextKey key) {
        context.flipBit(bitidx, key);
    }

    @And("the {ClaimLocation} claim {string} contains a date {DateCompareMode} {Duration}")
    public void theBodyClaimContainsADate(
        final ClaimLocation claimLocation, final String claim, final DateCompareMode compareMode,
        final Duration duration)
        throws JSONException {
        disc.assertDateFromClaimMatches(claimLocation, claim, compareMode, duration);
    }

    @When("I extract the {ClaimLocation} claims from token {ContextKey}")
    public void iExtractTheClaimsFromToken(final ClaimLocation cType, final ContextKey token)
        throws JoseException, InvalidJwtException, JSONException {
        author.extractClaimsFromToken(cType, token);
    }
}
