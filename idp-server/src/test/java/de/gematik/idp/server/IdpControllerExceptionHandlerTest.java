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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.authentication.AuthenticationChallengeBuilder;
import de.gematik.idp.authentication.AuthenticationTokenBuilder;
import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.authentication.UriUtils;
import de.gematik.idp.server.configuration.IdpConfiguration;
import de.gematik.idp.server.controllers.IdpController;
import de.gematik.idp.server.controllers.IdpKey;
import de.gematik.idp.server.exceptions.handler.IdpServerExceptionHandler;
import de.gematik.idp.server.exceptions.oauth2spec.IdpServerInvalidRequestException;
import de.gematik.idp.server.services.IdpAuthenticator;
import de.gematik.idp.server.services.PkceChecker;
import de.gematik.idp.server.services.TokenService;
import de.gematik.idp.server.validation.parameterConstraints.ClientIdValidator;
import de.gematik.idp.server.validation.parameterConstraints.ScopeValidator;
import de.gematik.idp.token.AccessTokenBuilder;
import de.gematik.idp.token.IdTokenBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

@AutoConfigureMockMvc
@ExtendWith(SpringExtension.class)
@WebMvcTest(IdpController.class)
public class IdpControllerExceptionHandlerTest {

    private final static String EXCEPTION_TEXT = "exception text";

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
    private ClientIdValidator clientIdValidator;
    @MockBean
    private TokenService tokenService;
    @MockBean
    private IdpJwtProcessor jwtProcessor;
    @MockBean
    private RequestAccessToken requestAccessToken;
    @MockBean
    private IdpConfiguration idpConfiguration;
    @MockBean
    private IdpKey authKey;

    @Autowired
    private IdpController idpController;
    @Autowired
    private MockMvc mockMvc;

    @BeforeEach
    public void setup() {
        doReturn("http://foo.bar/")
            .when(serverUrlService).determineServerUrl();
        mockMvc = MockMvcBuilders.standaloneSetup(new IdpServerExceptionHandler(serverUrlService, null),
            idpController)
            .build();
    }

    @Test
    public void testIdpServerInvalidRequestException() throws Exception {
        final RuntimeException exc = new IdpServerInvalidRequestException(EXCEPTION_TEXT);
        doThrow(exc)
            .when(idpAuthenticator).validateRedirectUri(any());
        mockMvc.perform(MockMvcRequestBuilders
            .get(IdpConstants.BASIC_AUTHORIZATION_ENDPOINT)
            .queryParam("signed_challenge", "signed_challenge")
            .queryParam("client_id", "eRezeptApp")
            .queryParam("state", "state")
            .queryParam("redirect_uri", "fdsafdsa")
            .queryParam("nonce", "fdsalkfdksalfdsa")
            .queryParam("response_type", "code")
            .queryParam("code_challenge", "fkdsjfkdsjfkjdskafjdksljfkdsjfkldsjjjjjjjjj")
            .queryParam("code_challenge_method", "S256")
            .queryParam("scope", "openid e-rezept")

            .accept(MediaType.APPLICATION_JSON))
            .andExpect(result -> assertThat(result.getResolvedException()).isEqualTo(exc))
            .andExpect(result -> assertThat(result.getResolvedException().getMessage()).isEqualTo(EXCEPTION_TEXT))
            .andExpect(result -> assertThat(result.getResponse().getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value()))
            .andExpect(MockMvcResultMatchers.jsonPath("$.error_code").value("invalid_request"))
            .andExpect(MockMvcResultMatchers.jsonPath("$.error_uuid").exists())
            .andExpect(MockMvcResultMatchers.jsonPath("$.timestamp").exists());
    }

    @Test
    public void authentication_serverError_expectRedirect() throws Exception {
        when(idpAuthenticator.getBasicFlowTokenLocation(any(), any()))
            .thenThrow(new IdpServerInvalidRequestException(EXCEPTION_TEXT));
        mockMvc.perform(MockMvcRequestBuilders
            .post(IdpConstants.BASIC_AUTHORIZATION_ENDPOINT)
            .queryParam("signed_challenge", "signed_challenge")
            .accept(MediaType.APPLICATION_JSON))
            .andExpect(result -> assertThat(result.getResponse().getStatus()).isEqualTo(HttpStatus.FOUND.value()))
            .andExpect(
                result -> assertThat(UriUtils.extractParameterMap(result.getResponse().getHeader(HttpHeaders.LOCATION)))
                    .containsEntry("error", "invalid_request")
                    .containsEntry("error_description", EXCEPTION_TEXT));
    }

    @Test
    public void authentication_genericError_expectRedirect() throws Exception {
        when(idpAuthenticator.getBasicFlowTokenLocation(any(), any()))
            .thenThrow(new RuntimeException(EXCEPTION_TEXT));
        mockMvc.perform(MockMvcRequestBuilders
            .post(IdpConstants.BASIC_AUTHORIZATION_ENDPOINT)
            .queryParam("signed_challenge", "signed_challenge")
            .accept(MediaType.APPLICATION_JSON))
            .andExpect(result -> assertThat(result.getResponse().getStatus()).isEqualTo(HttpStatus.FOUND.value()))
            .andExpect(
                result -> assertThat(UriUtils.extractParameterMap(result.getResponse().getHeader(HttpHeaders.LOCATION)))
                    .containsEntry("error", "invalid_request")
                    .containsEntry("error_description", "Invalid Request"))
            .andExpect(result -> assertThat(result.getResponse().getHeaderValues("Cache-Control"))
                .containsOnlyOnce("no-store"));
    }
}
