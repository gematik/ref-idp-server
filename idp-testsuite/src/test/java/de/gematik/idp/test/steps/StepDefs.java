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

package de.gematik.idp.test.steps;

import cucumber.api.PendingException;
import de.gematik.idp.test.steps.helpers.JsonChecker;
import de.gematik.idp.test.steps.model.*;
import io.cucumber.datatable.DataTable;
import io.cucumber.java.en.And;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import lombok.extern.slf4j.Slf4j;
import net.thucydides.core.annotations.Steps;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.lang.JoseException;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.net.URISyntaxException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

@Slf4j
public class StepDefs {

    @Steps
    IdpDiscoveryDocumentSteps disc;

    @Steps
    IdpAuthenticationSteps auth;

    @Steps
    IdpAuthorizationSteps author;

    @Steps
    IdpAccessTokenSteps access;

    @Steps
    JsonChecker jsoncheck;

    // =================================================================================================================
    //
    //      D I S C O V E R Y   D O C U M E N T
    //
    // =================================================================================================================

    @Given("I request the discovery document {HttpStatus}")
    public void iRequestTheInternalDiscoveryDocument(final HttpStatus result) {
        disc.iRequestTheInternalDiscoveryDocument(result);
    }

    // =================================================================================================================
    //
    //            A U T H E N T I C A T I O N
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


    @When("I request a challenge with status {HttpStatus} with")
    public void iRequestAChallengeWith(final HttpStatus expectedResult, final DataTable params) throws JSONException {
        auth.getChallenge(params, expectedResult);
    }

    // =================================================================================================================
    //
    //            A U T H O R I Z A T I O N
    //
    // =================================================================================================================

    @When("I request a code token with {CodeAuthType} with status {HttpStatus}")
    public void iRequestACodeTokenWith(final CodeAuthType authType, final HttpStatus result) throws URISyntaxException {
        author.getCode(authType, result);
    }

    @When("I sign the challenge with {string}")
    public void iSignTheChallengeWith(final String keyfile)
            throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, JoseException {
        author.signChallenge(keyfile);
    }

    // =================================================================================================================
    //
    //            T O K E N   E N D P O I N T
    //
    // =================================================================================================================

    @And("I request an access token {HttpStatus} with")
    public void iRequestAnAccessTokenWith(final HttpStatus result, final DataTable params) {
        access.getToken(result, params);
    }

    @And("I request an access token {HttpStatus}")
    public void iRequestAnAccessToken(final HttpStatus result) {
        access.getToken(result, null);
    }

    // =================================================================================================================
    //
    //      H E L P E R   S T E P S
    //
    // =================================================================================================================

    @When("^I extract the (body|header) claims$")
    public void iExtractTheClaims(final ClaimType claimType) throws Throwable {
        disc.iExtractTheClaims(claimType);
    }

    @Given("I request the uri from claim {string} with method {HttpMethods} and status {HttpStatus}")
    public void iRequestTheUri(final String claim, final HttpMethods method, final HttpStatus result)
            throws JSONException {
        disc.iRequestTheUriFromClaim(claim, method, result);
    }

    @Then("the response status is {HttpStatus}")
    public void theResponseStatusIs(final HttpStatus status) {
        disc.assertResponseStatusIs(status);
    }

    @Then("the response content type is {string}")
    public void theResponseContentTypeIs(final String contentType) {
        disc.assertResponseContentTypeIs(contentType);
    }

    @Then("^the response http headers match$")
    public void theResponseHTTPHeadersMatch(final String kvps) {
        //TODO check that each key value pair exists in response headers
        throw new PendingException("Not implemented! " + kvps);
    }

    @And("the response must be signed with cert '(.*)'")
    public void theResponseMustBeSignedWithCert(final String filename) throws Throwable {
        disc.assertResponseIsSignedWithCert(filename);
    }

    @Then("URI in claim {string} exists with method {HttpMethods} and status {HttpStatus}")
    public void uriInClaimExistsWithMethod(final String claim, final HttpMethods method, final HttpStatus status)
            throws JSONException {
        disc.assertUriInClaimExistsWithMethodAndStatus(claim, method, status);
    }

    @Then("JSON response has node '(.*)'")
    public void jSONResponseHasNode(final String path) throws JSONException {
        jsoncheck.assertJsonResponseHasNode(path);
    }

    @Then("^the JSON response should match$")
    public void theJSONResponseShouldMatch(final String toMatchJSON) throws JSONException {
        final JSONObject jso = new JSONObject(Context.getCurrentResponse().getBody().asString());
        jsoncheck.assertJsonShouldMatchInAnyOrder(jso, toMatchJSON);
    }

    @Then("JSON response has exactly one node '(.*)' at '(.*)'")
    public void jSONResponseHasExactlyOneNodeAt(final String node, final String path) throws JSONException {
        jsoncheck.assertJsonResponseHasExactlyOneNodeAt(node, path);
    }

    @Then("^the (body|header) claims should match in any order$")
    public void theClaimsShouldMatchInAnyOrder(final ClaimType claimType, final String toMatchJSON)
            throws JSONException {
        final JSONObject jso;
        if (claimType == ClaimType.body) {
            jso = Context.getCurrentClaims();
        } else {
            jso = (JSONObject) Context.getThreadContext().get(ContextKey.HEADER_CLAIMS);
        }
        jsoncheck.assertJsonShouldMatchInAnyOrder(jso, toMatchJSON);
    }

    @And("^I start new interaction keeping only (.*)$")
    public void iPurgeContextButKeepOnly(final ContextKey key) {
        disc.iStartNewInteractionKeepingOnly(key);
    }

}
