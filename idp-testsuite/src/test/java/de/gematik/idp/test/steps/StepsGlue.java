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
import de.gematik.idp.test.steps.helpers.JsonChecker;
import de.gematik.idp.test.steps.helpers.SerenityJSONObject;
import de.gematik.idp.test.steps.model.*;
import io.cucumber.datatable.DataTable;
import io.cucumber.java.DataTableType;
import io.cucumber.java.ParameterType;
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
import java.util.List;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import net.thucydides.core.annotations.Steps;
import org.apache.commons.io.IOUtils;
import org.assertj.core.api.Assertions;
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
    @SneakyThrows
    public void iInitializeScenarioFromDiscoveryDocumentEndpoint() {
        auth.initializeFromDiscoveryDocument();
    }

    @Given("I retrieve public keys from URIs")
    @SneakyThrows
    public void iRetrievePublicKeysFromURIs() {
        Context.getDiscoveryDocument().readPublicKeysFromURIs();
    }

    @Given("I choose code verifier {string}")
    public void iChooseCodeVerifier(final String codeverifier) {
        auth.setCodeVerifier(codeverifier);
    }

    @When("I request a challenge with")
    @SneakyThrows
    public void iRequestAChallengeWith(final DataTable params) {
        auth.getChallenge(params, HttpStatus.NOCHECK);
    }

    // =================================================================================================================
    //
    // A U T H O R I Z A T I O N
    //
    // =================================================================================================================

    @When("I request a code token with {CodeAuthType}")
    @SneakyThrows
    public void iRequestACodeTokenWith(final CodeAuthType authType) {
        author.getCode(authType, HttpStatus.NOCHECK);
    }

    @When("I sign the challenge with {string}")
    public void iSignTheChallengeWith(final String keyfile) {
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
    @SneakyThrows
    public void iExtractTheClaims(final ClaimLocation claimLocation) {
        disc.iExtractTheClaims(claimLocation);
    }

    @When("I extract the {ClaimLocation} claims from response field {word}")
    @SneakyThrows
    public void iExtractTheClaims(final ClaimLocation claimLocation, final String jsonName) {
        disc.iExtractTheClaimsFromResponseJsonField(jsonName, claimLocation);
    }

    @Given("I request the uri from claim {string} with method {HttpMethods} and status {HttpStatus}")
    @SneakyThrows
    public void iRequestTheUri(final String claimName, final HttpMethods method, final HttpStatus result) {
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

    @And("the response must be signed with cert {ContextKey}")
    @SneakyThrows
    public void theResponseMustBeSignedWithCert(final ContextKey pukKey) {
        disc.assertResponseIsSignedWithCert(pukKey);
    }

    @And("the context {ContextKey} must be signed with cert {ContextKey}")
    @SneakyThrows
    public void theContextMustBeSignedWithCert(final ContextKey tokenKey, final ContextKey pukKey) {
        disc.assertContextIsSignedWithCert(tokenKey, pukKey);
    }

    @Then("URI in claim {string} exists with method {HttpMethods} and status {HttpStatus}")
    @SneakyThrows
    public void uriInClaimExistsWithMethod(final String claimName, final HttpMethods method, final HttpStatus status) {
        disc.assertUriInClaimExistsWithMethodAndStatus(claimName, method, status);
    }

    @Then("JSON response has node {string}")
    @SneakyThrows
    public void jSONResponseHasNode(final String path) {
        jsoncheck.assertJsonResponseHasNode(path);
    }

    @Then("the JSON response should match")
    @SneakyThrows
    public void theJSONResponseShouldMatch(final String toMatchJSON) {
        final JSONObject json = new JSONObject(Context.getCurrentResponse().getBody().asString());
        jsoncheck
            .assertJsonShouldMatchInAnyOrder(new SerenityJSONObject(json), new SerenityJSONObject(toMatchJSON));
    }

    @Then("JSON response has exactly one node {string} at {string}")
    @SneakyThrows
    public void jSONResponseHasExactlyOneNodeAt(final String node, final String path) {
        jsoncheck.assertJsonResponseHasExactlyOneNodeAt(node, path);
    }

    @Then("the {ClaimLocation} claims should match in any order")
    @SneakyThrows
    public void theClaimsShouldMatchInAnyOrder(final ClaimLocation claimLocation, final String toMatchJSON) {
        final JSONObject json;
        if (claimLocation == ClaimLocation.body) {
            json = Context.getCurrentClaims();
        } else {
            json = (JSONObject) Context.getThreadContext().get(ContextKey.HEADER_CLAIMS);
        }
        jsoncheck
            .assertJsonShouldMatchInAnyOrder(new SerenityJSONObject(json), new SerenityJSONObject(toMatchJSON));
    }

    @Then("the {ClaimLocation} claim {string} should match {string}")
    @SneakyThrows
    public void theClaimShouldMatch(final ClaimLocation claimLocation, final String claimName, final String regex) {
        final JSONObject json;
        if (claimLocation == ClaimLocation.body) {
            json = Context.getCurrentClaims();
        } else {
            json = (JSONObject) Context.getThreadContext().get(ContextKey.HEADER_CLAIMS);
        }
        jsoncheck.assertJsonShouldMatch(new SerenityJSONObject(json), claimName, regex);
    }


    @When("I start new interaction keeping only")
    public void iStartNewInteractionKeepingOnly(final List<ContextKey> keys) {
        context.iStartNewInteractionKeepingOnly(keys);
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
    @SneakyThrows
    public void theBodyClaimContainsADate(final ClaimLocation claimLocation, final String claim,
        final DateCompareMode compareMode, final Duration duration) {
        disc.assertDateFromClaimMatches(claimLocation, claim, compareMode, duration);
    }

    @When("I extract the {ClaimLocation} claims from token {ContextKey}")
    @SneakyThrows
    public void iExtractTheClaimsFromToken(final ClaimLocation cType, final ContextKey token) {
        author.extractClaimsFromToken(cType, token);
    }

    @And("the JSON response should be a valid certificate")
    @SneakyThrows
    public void theJSONResponseShouldBeAValidCertificate() {
        disc.jsonObjectShouldBeValidCertificate(new JSONObject(Context.getCurrentResponse().getBody().asString()));
    }

    @And("the JSON array {string} of response should contain valid certificates")
    @SneakyThrows
    public void theJSONArrayOfResponseShouldContainValidCertificates(final String path) {
        disc.jsonArrayPathShouldContainValidCertificates(path);
    }

    @Then("the response is an 302 error with code {string} and message matching {string}")
    public void theResponseIsAnErrorWithMessageMatching(final String errcode, final String regex) {
        author.responseIs302ErrorWithMessageMatching(errcode, regex);
    }

    @When("I wait {Duration}")
    @SneakyThrows
    public void iWait(final Duration timeout) {
        auth.wait(timeout);
    }

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

    @When("I load {ContextKey} from folder {string}")
    @SneakyThrows
    public void iLoadCOntextKeyFromFolder(final ContextKey key, final String folder) {
        final File f = new File("testartefacts" + File.separatorChar + folder + File.separatorChar + key + ".txt");
        final String str = IOUtils.toString(new FileInputStream(f), StandardCharsets.UTF_8);
        switch (key) {
            case SSO_TOKEN:
            case SSO_TOKEN_ENCRYPTED:
            case ACCESS_TOKEN:
                Context.getThreadContext().put(key, str);
                break;
            //TODO add support for all other keys
            default:
                Assertions.fail("Unsupported key (Feel free to implement)");
        }
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
}
