/*
 * Copyright (c) 2022 gematik GmbH
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

import de.gematik.idp.test.steps.helpers.CucumberValuesConverter;
import io.cucumber.java.de.Gegebensei;
import io.cucumber.java.de.Wenn;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.When;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import net.thucydides.core.annotations.Steps;

@Slf4j
public class FedIdpGlue {

    @Steps
    FedIdpSteps fedsteps;

    @Steps
    CucumberValuesConverter cucumberValuesConverter;

    /**
     * put federation enpoints in context
     *
     * @gematik.context.in USER_AGENT
     * @gematik.context.out RESPONSE
     */
    @Given("IDP I initialize the federation endpoints")
    @Gegebensei("IDP ich initialisiere die Endpunkte der Föderation")
    @SneakyThrows
    public void iInitializeFederationEndpoints() {
        fedsteps.initializeIdpFederation();
    }

    /**
     * fetch the fachdienst's IDP List
     *
     * @gematik.context.in USER_AGENT
     * @gematik.context.out CLIENT_ID, RESPONSE, CHALLENGE, USER_CONSENT
     * @see CucumberValuesConverter
     */
    @Wenn("IDP Ich rufe die Liste der IDPs vom Fachdienst ab")
    @When("IDP I fetch the Fachdienst's IDP List")
    @SneakyThrows
    public void iFetchFachdienstIdpList() {
        fedsteps.fetchFachdienstIdpList();
    }

}
