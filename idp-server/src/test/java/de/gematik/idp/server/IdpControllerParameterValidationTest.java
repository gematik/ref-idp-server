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

package de.gematik.idp.server;

import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.authentication.AuthenticationChallengeBuilder;
import de.gematik.idp.authentication.AuthenticationTokenBuilder;
import de.gematik.idp.server.configuration.IdpConfiguration;
import de.gematik.idp.server.controllers.IdpController;
import de.gematik.idp.server.exceptions.handler.IdpServerExceptionHandler;
import de.gematik.idp.server.services.IdpAuthenticator;
import de.gematik.idp.server.services.PkceChecker;
import de.gematik.idp.server.validation.parameterConstraints.ClientIdValidator;
import de.gematik.idp.server.validation.parameterConstraints.ScopeValidator;
import de.gematik.idp.token.AccessTokenBuilder;
import de.gematik.idp.token.IdTokenBuilder;
import java.util.List;
import java.util.Map.Entry;
import java.util.function.Function;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

@AutoConfigureMockMvc
@ExtendWith(SpringExtension.class)
@WebMvcTest(IdpController.class)
public class IdpControllerParameterValidationTest {

    private static final List<Pair<String, String>> getChallengeParameterMap = List.of(
        Pair.of("client_id", IdpConstants.CLIENT_ID),
        Pair.of("state", "state"),
        Pair.of("redirect_uri", "fdsafdsa"),
        Pair.of("code_challenge", "l1yM_9krH3fPE2aOkRXzHQDU0lKn0mI0-Gp165Pgb1Y"),
        Pair.of("code_challenge_method", "S256"),
        Pair.of("scope", "openid e-rezept"));

    private static final List<Pair<String, String>> getAccessTokenParameterMap = List.of(
        Pair.of("code",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"),
        Pair.of("code_verifier", "fjdkslafdsa"),
        Pair.of("grant_type", "authorization_code"),
        Pair.of("client_id", IdpConstants.CLIENT_ID),
        Pair.of("redirect_uri", "irgend://ein.uri"));

    @MockBean
    private AuthenticationTokenBuilder authenticationTokenBuilder;
    @MockBean
    private ServerUrlService serverUrlService;
    @MockBean
    private AuthenticationChallengeBuilder authenticationChallengeBuilder;
    @MockBean
    private IdpAuthenticator idpAuthenticator;
    @MockBean
    private AccessTokenBuilder accessTokenBuilder;
    @MockBean
    private IdTokenBuilder idTokenBuilder;
    @MockBean
    private PkceChecker pkceChecker;
    @MockBean
    private ScopeValidator scopeValidator;
    @MockBean
    private IdpConfiguration idpConfiguration;
    @MockBean
    private ClientIdValidator clientIdValidator;

    @Autowired
    private IdpController idpController;
    @Autowired
    private MockMvc mockMvc;

    @BeforeEach
    public void setup() {
        mockMvc = MockMvcBuilders.standaloneSetup(new IdpServerExceptionHandler(), idpController).build();
    }

    @Test
    public void getAuthenticationChallenge_invalidClientId_shouldGiveError() throws Exception {
        mockMvc.perform(buildGetChallengeRequest(getInvalidationFunction("client_id", "invalid_client_id")))
            .andDo(mvcResult -> assertThat(mvcResult.getResponse().getContentAsString()).contains("client_id"))
            .andDo(mvcResult -> assertThat(mvcResult.getResponse().getStatus()).isEqualTo(400));
    }

    @Test
    public void getAuthenticationChallenge_invalidScope_shouldGiveError() throws Exception {
        mockMvc.perform(buildGetChallengeRequest(getInvalidationFunction("scope", "invalidScope")))
            .andDo(mvcResult -> assertThat(mvcResult.getResponse().getContentAsString()).contains("scope"))
            .andDo(mvcResult -> assertThat(mvcResult.getResponse().getStatus()).isEqualTo(400));
    }

    @Test
    public void getAuthenticationChallenge_validPlusInvalidScope_shouldGiveError() throws Exception {
        mockMvc.perform(buildGetChallengeRequest(getInvalidationFunction("scope", "openid e-rezept x")))
            .andDo(mvcResult -> assertThat(mvcResult.getResponse().getContentAsString()).contains("scope"))
            .andDo(mvcResult -> assertThat(mvcResult.getResponse().getStatus()).isEqualTo(400));
    }

    @Test
    public void getAuthenticationChallenge_invalidCodeChallenge_shouldGiveError() throws Exception {
        mockMvc.perform(buildGetChallengeRequest(getInvalidationFunction("code_challenge", "invalid")))
            .andDo(mvcResult -> assertThat(mvcResult.getResponse().getContentAsString()).contains("code_challenge"))
            .andDo(mvcResult -> assertThat(mvcResult.getResponse().getStatus()).isEqualTo(400));
    }

    @Test
    public void getAuthenticationChallenge_missingRedirectUri_shouldGiveError() throws Exception {
        mockMvc.perform(buildGetChallengeRequest(getInvalidationFunction("redirect_uri", null)))
            .andDo(mvcResult -> assertThat(mvcResult.getResponse().getContentAsString()).contains("redirect_uri"))
            .andDo(mvcResult -> assertThat(mvcResult.getResponse().getStatus()).isEqualTo(400));
    }

    @Test
    public void getAuthenticationChallenge_missingState_shouldGiveError() throws Exception {
        mockMvc.perform(buildGetChallengeRequest(getInvalidationFunction("state", null)))
            .andDo(mvcResult -> assertThat(mvcResult.getResponse().getContentAsString()).contains("state"))
            .andDo(mvcResult -> assertThat(mvcResult.getResponse().getStatus()).isEqualTo(400));
    }

    @Test
    public void getAccessToken_missingCode_shouldGiveError() throws Exception {
        mockMvc.perform(buildGetAccessTokenRequest(getInvalidationFunction("code", null)))
            .andDo(mvcResult -> assertThat(mvcResult.getResponse().getContentAsString()).contains("'code'"))
            .andDo(mvcResult -> assertThat(mvcResult.getResponse().getStatus()).isEqualTo(400));
    }

    @Test
    public void getAccessToken_missingCodeVerifier_shouldGiveError() throws Exception {
        mockMvc.perform(buildGetAccessTokenRequest(getInvalidationFunction("code_verifier", null)))
            .andDo(mvcResult -> assertThat(mvcResult.getResponse().getContentAsString()).contains("'code_verifier'"))
            .andDo(mvcResult -> assertThat(mvcResult.getResponse().getStatus()).isEqualTo(400));
    }

    @Test
    public void getAccessToken_missingGrantType_shouldGiveError() throws Exception {
        mockMvc.perform(buildGetAccessTokenRequest(getInvalidationFunction("grant_type", null)))
            .andDo(mvcResult -> assertThat(mvcResult.getResponse().getContentAsString()).contains("'grant_type'"))
            .andDo(mvcResult -> assertThat(mvcResult.getResponse().getStatus()).isEqualTo(400));
    }

    @Test
    public void getAccessToken_invalidGrantType_shouldGiveError() throws Exception {
        mockMvc.perform(buildGetAccessTokenRequest(getInvalidationFunction("grant_type", "falscher_wert")))
            .andDo(mvcResult -> assertThat(mvcResult.getResponse().getContentAsString()).contains("grantType"))
            .andDo(mvcResult -> assertThat(mvcResult.getResponse().getStatus()).isEqualTo(400));
    }

    @Test
    public void getAccessToken_missingRedirectUri_shouldGiveError() throws Exception {
        mockMvc.perform(buildGetAccessTokenRequest(getInvalidationFunction("redirect_uri", null)))
            .andDo(mvcResult -> assertThat(mvcResult.getResponse().getContentAsString()).contains("'redirect_uri'"))
            .andDo(mvcResult -> assertThat(mvcResult.getResponse().getStatus()).isEqualTo(400));
    }

    @Test
    public void getAccessToken_missingClientId_shouldGiveError() throws Exception {
        mockMvc.perform(buildGetAccessTokenRequest(getInvalidationFunction("client_id", null)))
            .andDo(mvcResult -> assertThat(mvcResult.getResponse().getContentAsString()).contains("'client_id'"))
            .andDo(mvcResult -> assertThat(mvcResult.getResponse().getStatus()).isEqualTo(400));
    }

    private MockHttpServletRequestBuilder buildGetChallengeRequest(
        final Function<Entry<String, String>, Entry<String, String>> entryStringFunction) {
        final MockHttpServletRequestBuilder requestBuilder = MockMvcRequestBuilders
            .get(IdpConstants.AUTHORIZATION_ENDPOINT);

        getChallengeParameterMap.stream()
            .map(entryStringFunction)
            .forEach(entry -> requestBuilder.queryParam(entry.getKey(), entry.getValue()));

        return requestBuilder;
    }

    private MockHttpServletRequestBuilder buildGetAccessTokenRequest(
        final Function<Entry<String, String>, Entry<String, String>> entryStringFunction) {
        final MockHttpServletRequestBuilder requestBuilder = MockMvcRequestBuilders
            .post(IdpConstants.TOKEN_ENDPOINT);

        getAccessTokenParameterMap.stream()
            .map(entryStringFunction)
            .forEach(entry -> requestBuilder.queryParam(entry.getKey(), entry.getValue()));

        return requestBuilder;
    }

    private Function<Entry<String, String>, Entry<String, String>> getInvalidationFunction(final String parameterName,
        final String newParameterValue) {
        return entry -> {
            if (entry.getKey().equals(parameterName)) {
                return Pair.of(parameterName, newParameterValue);
            } else {
                return entry;
            }
        };
    }
}
