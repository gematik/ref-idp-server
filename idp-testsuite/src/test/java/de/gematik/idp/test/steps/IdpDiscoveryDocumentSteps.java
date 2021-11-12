/*
 * Copyright (c) 2021 gematik GmbH
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

package de.gematik.idp.test.steps;

import de.gematik.idp.test.steps.helpers.ClaimsStepHelper;
import de.gematik.idp.test.steps.helpers.IdpTestEnvironmentConfigurator;
import de.gematik.idp.test.steps.model.DiscoveryDocument;
import de.gematik.idp.test.steps.model.HttpMethods;
import de.gematik.idp.test.steps.model.HttpStatus;
import de.gematik.test.bdd.Context;
import de.gematik.test.bdd.ContextKey;
import io.restassured.config.SSLConfig;
import io.restassured.response.Response;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import net.serenitybdd.rest.SerenityRest;
import net.thucydides.core.annotations.Step;

@Slf4j
public class IdpDiscoveryDocumentSteps extends IdpStepsBase {

    private final ClaimsStepHelper claimsStepHelper = new ClaimsStepHelper();

    @SneakyThrows
    public void initializeFromDiscoveryDocument() {
        log.info("DiscoveryURL is " + IdpTestEnvironmentConfigurator.getDiscoveryDocumentURL());
        SerenityRest.setDefaultConfig(SerenityRest.config().sslConfig(new SSLConfig().relaxedHTTPSValidation()));
        final Response r = IdpStepsBase.simpleGet(IdpTestEnvironmentConfigurator.getDiscoveryDocumentURL());
        final String discoveryDocumentBodyAsString = r.getBody().asString();

        Context.get()
            .put(ContextKey.DISC_DOC, new DiscoveryDocument(
                claimsStepHelper.getClaims(discoveryDocumentBodyAsString),
                claimsStepHelper.extractHeaderClaimsFromJWSString(r.getBody().asString())));
    }


    @Step
    @SneakyThrows
    public void iRequestTheInternalDiscoveryDocument(final HttpStatus desiredStatus) {
        Context.get().put(ContextKey.RESPONSE,
            requestResponseAndAssertStatus(IdpTestEnvironmentConfigurator.getDiscoveryDocumentURL(), null,
                HttpMethods.GET,
                null,
                null, desiredStatus));
    }
}
