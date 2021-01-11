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

import de.gematik.idp.test.steps.helpers.TestEnvironmentConfigurator;
import de.gematik.idp.test.steps.model.Context;
import de.gematik.idp.test.steps.model.ContextKey;
import de.gematik.idp.test.steps.model.HttpMethods;
import de.gematik.idp.test.steps.model.HttpStatus;
import lombok.extern.slf4j.Slf4j;
import net.thucydides.core.annotations.Step;

@Slf4j
public class IdpDiscoveryDocumentSteps extends IdpStepsBase {

    @Step
    public void iRequestTheInternalDiscoveryDocument(final HttpStatus desiredStatus) {
        log.info("DiscoveryURL is " + TestEnvironmentConfigurator.getDiscoveryDocumentURL());
        Context.getThreadContext().put(ContextKey.RESPONSE,
            requestResponseAndAssertStatus(TestEnvironmentConfigurator.getDiscoveryDocumentURL(), null, HttpMethods.GET,
                null,
                desiredStatus));
        if (log.isDebugEnabled()) {
            log.debug("Response:" + Context.getCurrentResponse().getBody().prettyPrint());
        }
    }

}
