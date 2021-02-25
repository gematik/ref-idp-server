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

package de.gematik.idp.server.services;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import de.gematik.idp.server.configuration.IdpConfiguration;
import de.gematik.idp.server.data.IdpClientConfiguration;
import de.gematik.idp.server.validation.parameterConstraints.ClientIdValidator;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ClientIdValidatorTest {

    private ClientIdValidator clientIdValidator;
    public static final String CLIENT_ID = "eRezeptApp";

    @BeforeEach
    public void init() {
        final IdpConfiguration configuration = new IdpConfiguration();
        final Map<String, IdpClientConfiguration> clientRegistration = new HashMap<>();
        clientRegistration.put(CLIENT_ID, IdpClientConfiguration.builder().build());
        configuration.setRegisteredClient(clientRegistration);
        clientIdValidator = new ClientIdValidator(new ClientRegistrationService(configuration));
    }

    @Test
    public void validateClientIdWithNullValue_ExpectCorrectError() {
        assertThat(clientIdValidator.isValid(null, null))
            .isFalse();
    }

    @Test
    public void validateClientIdWithInvalidValue_ExpectCorrectError() {
        assertThat(clientIdValidator.isValid("invalidClientId", null))
            .isFalse();
    }

    @Test
    public void validateClientIdIsERezeptApp() {
        assertThat(clientIdValidator.isValid(CLIENT_ID, null))
            .isTrue();
    }
}
