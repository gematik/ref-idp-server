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

import de.gematik.idp.test.steps.helpers.ClaimsStepHelper;
import de.gematik.idp.test.steps.helpers.IdpTestEnvironmentConfigurator;
import de.gematik.test.bdd.Context;
import de.gematik.test.bdd.ContextKey;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class IdpSektoralIdpSteps extends IdpStepsBase {

  private final ClaimsStepHelper claimsStepHelper = new ClaimsStepHelper();

  @SneakyThrows
  public void initializeSektoralIdp() {
    log.info(
        "Authorization Endpoint Sektoral-IDP is "
            + IdpTestEnvironmentConfigurator.getAuthorizationUrlSektoralIdpURL());

    Context.get()
        .put(
            ContextKey.AUTH_URL_SEKTORAL_IDP,
            IdpTestEnvironmentConfigurator.getAuthorizationUrlSektoralIdpURL());
  }
}
