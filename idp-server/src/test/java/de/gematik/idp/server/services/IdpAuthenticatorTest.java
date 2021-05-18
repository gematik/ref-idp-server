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

package de.gematik.idp.server.services;

import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;

import de.gematik.idp.TestConstants;
import de.gematik.idp.error.IdpErrorType;
import de.gematik.idp.server.configuration.IdpConfiguration;
import de.gematik.idp.server.data.IdpClientConfiguration;
import de.gematik.idp.server.exceptions.IdpServerException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class IdpAuthenticatorTest {

    @Autowired
    private IdpAuthenticator idpAuthenticator;
    @Autowired
    private IdpConfiguration idpConfiguration;

    @Test
    public void validateRedirectUriWithNullValue_ExpectCorrectError() {
        assertThatThrownBy(() -> idpAuthenticator.validateRedirectUri(TestConstants.CLIENT_ID_E_REZEPT_APP, null))
            .isInstanceOf(IdpServerException.class)
            .hasFieldOrPropertyWithValue("errorType", IdpErrorType.INVALID_REQUEST);
    }

    @Test
    public void validateRedirectUriWithNonValidClientId_ExpectCorrectError() {
        final IdpClientConfiguration idpClientConfiguration = idpConfiguration.getRegisteredClient()
            .get(TestConstants.CLIENT_ID_E_REZEPT_APP);
        assertThatThrownBy(() -> idpAuthenticator.validateRedirectUri("test", idpClientConfiguration.getRedirectUri()))
            .isInstanceOf(IdpServerException.class)
            .hasFieldOrPropertyWithValue("errorType", IdpErrorType.INVALID_REQUEST);
    }

    @Test
    public void validateRedirectUriWithInvalidValue_ExpectCorrectError() {
        assertThatThrownBy(() -> idpAuthenticator.validateRedirectUri(TestConstants.CLIENT_ID_E_REZEPT_APP, "test"))
            .isInstanceOf(IdpServerException.class)
            .hasFieldOrPropertyWithValue("errorType", IdpErrorType.INVALID_REQUEST);
    }

    @Test
    public void validateRedirectUriIsEqualToConfigurationValue() {
        final IdpClientConfiguration idpClientConfiguration = idpConfiguration.getRegisteredClient()
            .get(TestConstants.CLIENT_ID_E_REZEPT_APP);
        idpAuthenticator
            .validateRedirectUri(TestConstants.CLIENT_ID_E_REZEPT_APP, idpClientConfiguration.getRedirectUri());
    }
}
