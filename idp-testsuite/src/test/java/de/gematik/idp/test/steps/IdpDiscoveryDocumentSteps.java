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
import de.gematik.idp.test.steps.model.*;
import java.io.File;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import net.thucydides.core.annotations.Step;

@Slf4j
public class IdpDiscoveryDocumentSteps extends IdpStepsBase {

    @Step
    @SneakyThrows
    public void iRequestTheInternalDiscoveryDocument(final HttpStatus desiredStatus) {
        log.info("DiscoveryURL is " + TestEnvironmentConfigurator.getDiscoveryDocumentURL());

        final String idpLocalDiscdoc = System.getenv("IDP_LOCAL_DISCDOC");
        if (idpLocalDiscdoc != null) {
            final DiscoveryDocumentResponse r = new DiscoveryDocumentResponse(new File(idpLocalDiscdoc),
                "authenticatorModule_idpServer.p12");
            Context.getThreadContext().put(ContextKey.RESPONSE, r);
        } else {
            Context.getThreadContext().put(ContextKey.RESPONSE,
                requestResponseAndAssertStatus(TestEnvironmentConfigurator.getDiscoveryDocumentURL(), null,
                    HttpMethods.GET,
                    null,
                    desiredStatus));
            if (log.isDebugEnabled()) {
                log.debug("Response:" + Context.getCurrentResponse().getBody().prettyPrint());
            }
        }
    }
}
