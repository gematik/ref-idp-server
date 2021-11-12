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

import static de.gematik.idp.field.ClaimName.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import de.gematik.idp.TestConstants;
import de.gematik.idp.error.IdpErrorType;
import de.gematik.idp.server.configuration.IdpConfiguration;
import de.gematik.idp.server.data.IdpClientConfiguration;
import de.gematik.idp.server.exceptions.IdpServerException;
import de.gematik.idp.token.JsonWebToken;
import java.util.HashMap;
import java.util.Map;
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

    @Test
    public void validateAuthorizationCodeLocation() {
        final Map<String, String> sessionMap = new HashMap<>();
        sessionMap.put(CODE_CHALLENGE.getJoseName(), "userAgentCodeChallenge");
        sessionMap.put(CODE_CHALLENGE_METHOD.getJoseName(), "userAgentCodeChallengeMethod");
        sessionMap.put(NONCE.getJoseName(), "userAgentNonce");
        sessionMap.put(STATE.getJoseName(), "userAgentState");
        sessionMap.put(REDIRECT_URI.getJoseName(), "http://userAgentRedirektUri");
        sessionMap.put(CLIENT_ID.getJoseName(), "userAgentId");
        sessionMap.put(RESPONSE_TYPE.getJoseName(), "code");
        final JsonWebToken idToken = new JsonWebToken(
            "eyJhbGciOiJCUDI1NlIxIiwia2lkIjoicHVrX2lkcF9zaWciLCJ0eXAiOiJKV1QifQ.eyJhdXRoX3RpbWUiOjE2MjMwNTYxMzYsIm5vbmNlIjoiOTg3NjUiLCJnaXZlbl9uYW1lIjoiRGFyaXVzIE1pY2hhZWwgQnJpYW4gVWJibyIsImZhbWlseV9uYW1lIjoiQsO2ZGVmZWxkIiwib3JnYW5pemF0aW9uTmFtZSI6IlRlc3QgR0tWLVNWTk9ULVZBTElEIiwicHJvZmVzc2lvbk9JRCI6IjEuMi4yNzYuMC43Ni40LjQ5IiwiaWROdW1tZXIiOiJYMTEwNDExNjc1IiwiYXpwIjoiZVJlemVwdEFwcCIsImFjciI6ImdlbWF0aWstZWhlYWx0aC1sb2EtaGlnaCIsImFtciI6WyJtZmEiLCJzYyIsInBpbiJdLCJhdWQiOiJlUmV6ZXB0QXBwIiwic3ViIjoiOGMwN2UzNzYwZjM1NjE5YzJlNWNjY2JkMzQxMzU0NDcwYjgwMmU5ZGIyZTkyYTgzNjMwMzdlYjc5OTkwYjU2ZSIsImlzcyI6Imh0dHBzOi8vaWRwLXRlc3QuemVudHJhbC5pZHAuc3BsaXRkbnMudGktZGllbnN0ZS5kZSIsImlhdCI6MTYyMzA1NjEzNiwiZXhwIjoxNjIzMDk5MzM2LCJqdGkiOiJjNjRiZmU2YS1kNzUyLTRlNWYtODA5YS0zM2IzOGUwYzNlOGUiLCJhdF9oYXNoIjoicUc5QXU4ei1kNVE2MllJWXlBRV9rQSJ9.Z0mhWFS2TcUtZlj-KAX9ys9Az-MwEvQ6AxRMLh2mKSdG6PKfsxsXJQhldeIzD1s2zcTTe74QPd0xUG8OCz9VuQ");
        final String authorizationCodeLocation = idpAuthenticator.getAuthorizationCodeLocation(idToken, sessionMap);
        assertThat(authorizationCodeLocation).startsWith("http://userAgentRedirektUri").contains("code=ey")
            .contains("state=userAgentState");
    }

}
