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

package de.gematik.idp.server;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;
import de.gematik.idp.IdpConstants;
import de.gematik.idp.TestConstants;
import de.gematik.idp.authentication.UriUtils;
import de.gematik.idp.error.IdpErrorType;
import de.gematik.idp.server.exceptions.IdpServerException;
import de.gematik.idp.server.services.IdpAuthenticator;
import de.gematik.idp.tests.PkiKeyResolver;
import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.Unirest;
import kong.unirest.json.JSONObject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit.jupiter.SpringExtension;


@ExtendWith(SpringExtension.class)
@ExtendWith(PkiKeyResolver.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class IdpControllerExceptionHandlerTest {

    private final static String EXCEPTION_TEXT = "exception text";

    @LocalServerPort
    private int port;
    @MockBean
    private IdpAuthenticator idpAuthenticator;
    private String serverUrl;

    @BeforeAll
    void init() {
        serverUrl = "http://localhost:" + port;
        Unirest.config().reset();
        Unirest.config().followRedirects(false);
    }


    @Test
    void testIdpServerInvalidRequestException() {
        doThrow(new IdpServerException(IdpErrorType.INVALID_REQUEST, HttpStatus.BAD_REQUEST))
            .when(idpAuthenticator).validateRedirectUri(any(), any());
        final HttpResponse<JsonNode> response = Unirest.get(serverUrl + IdpConstants.BASIC_AUTHORIZATION_ENDPOINT)
            .queryString("signed_challenge", "signed_challenge")
            .queryString("client_id", TestConstants.CLIENT_ID_E_REZEPT_APP)
            .queryString("state", "state")
            .queryString("redirect_uri", "fdsafdsavs")
            .queryString("nonce", "fdsalkfdksalfdsa")
            .queryString("response_type", "code")
            .queryString("code_challenge", "fkdsjfkdsjfkjdskafjdksljfkdsjfkldsjjjjjjjjj")
            .queryString("code_challenge_method", "S256")
            .queryString("scope", "openid e-rezept")
            .accept(MediaType.APPLICATION_JSON.toString())
            .asJson();

        final JSONObject errorObject = response.getBody().getObject();

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(errorObject.getString("error")).isEqualTo("invalid_request");
        assertThat(errorObject.get("gematik_uuid")).isNotNull();
        assertThat(errorObject.get("gematik_timestamp")).isNotNull();
    }


    @Test
    void testIdpServerInvalidLengthNonceException() {

        doThrow(new IdpServerException(IdpErrorType.INVALID_REQUEST, HttpStatus.BAD_REQUEST))
            .when(idpAuthenticator).validateRedirectUri(any(), any());
        String nonceToLong = "fdsalkfdksalfdsawertzuiopasdfghdd";
        final HttpResponse<JsonNode> response = Unirest.get(serverUrl + IdpConstants.BASIC_AUTHORIZATION_ENDPOINT)
            .queryString("signed_challenge", "signed_challenge")
            .queryString("client_id", TestConstants.CLIENT_ID_E_REZEPT_APP)
            .queryString("state", "state")
            .queryString("redirect_uri", TestConstants.REDIRECT_URI_E_REZEPT_APP)
            .queryString("nonce", nonceToLong)
            .queryString("response_type", "code")
            .queryString("code_challenge", "P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk")
            .queryString("code_challenge_method", "S256")
            .queryString("scope", "openid e-rezept")
            .accept(MediaType.APPLICATION_JSON.toString())
            .asJson();

        final JSONObject errorObject = response.getBody().getObject();

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(errorObject.getString("error")).isEqualTo("invalid_request");
        assertThat(errorObject.get("gematik_uuid")).isNotNull();
        assertThat(errorObject.get("gematik_timestamp")).isNotNull();
        assertThat(errorObject.get("gematik_error_text")).isEqualTo("nonce ist ungültig");
    }

    @Test
    void testIdpServerInvalidLengthStateException() {

        doThrow(new IdpServerException(IdpErrorType.INVALID_REQUEST, HttpStatus.BAD_REQUEST))
            .when(idpAuthenticator).validateRedirectUri(any(), any());
        String nonceCorrectLength = "dsalkfdksalfdsawertzuiopasdfghdd";
        String stateToLong = "fdsalkfdksalfdsawertzuiopasdfghdd";
        final HttpResponse<JsonNode> response = Unirest.get(serverUrl + IdpConstants.BASIC_AUTHORIZATION_ENDPOINT)
            .queryString("signed_challenge", "signed_challenge")
            .queryString("client_id", TestConstants.CLIENT_ID_E_REZEPT_APP)
            .queryString("state", stateToLong)
            .queryString("redirect_uri", TestConstants.REDIRECT_URI_E_REZEPT_APP)
            .queryString("nonce", nonceCorrectLength)
            .queryString("response_type", "code")
            .queryString("code_challenge", "P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk")
            .queryString("code_challenge_method", "S256")
            .queryString("scope", "openid e-rezept")
            .accept(MediaType.APPLICATION_JSON.toString())
            .asJson();

        final JSONObject errorObject = response.getBody().getObject();

        assertThat(response.getStatus()).isEqualTo(302);
        assertThat(response.getHeaders().get("Location").get(0)).contains("state%20ist%20ung%C3%BCltig");
    }

    @Test
    void authentication_idpServerException_expectRedirect() {
        when(idpAuthenticator.getBasicFlowTokenLocation(any()))
            .thenThrow(new IdpServerException(EXCEPTION_TEXT, IdpErrorType.INVALID_REQUEST, HttpStatus.FOUND));
        final HttpResponse response = Unirest.post(serverUrl + IdpConstants.BASIC_AUTHORIZATION_ENDPOINT)
            .queryString("signed_challenge", "signed_challenge")
            .accept(MediaType.APPLICATION_JSON.toString())
            .asEmpty();

        assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
        assertThat(UriUtils.extractParameterMap(response.getHeaders().getFirst(HttpHeaders.LOCATION)))
            .containsEntry("error", "invalid_request")
            .containsEntry("error_description", EXCEPTION_TEXT)
            .containsEntry("gematik_error_text", EXCEPTION_TEXT)
            .containsKey("gematik_timestamp")
            .containsKey("gematik_uuid");
    }

    @Test
    void authentication_genericError_expectRedirect() {
        when(idpAuthenticator.getBasicFlowTokenLocation(any()))
            .thenThrow(new IdpServerException(EXCEPTION_TEXT, IdpErrorType.SERVER_ERROR, HttpStatus.FOUND));
        final HttpResponse response = Unirest
            .post(serverUrl + IdpConstants.BASIC_AUTHORIZATION_ENDPOINT)
            .queryString("signed_challenge", "signed_challenge")
            .accept(MediaType.APPLICATION_JSON.toString())
            .asEmpty();

        assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
        assertThat(UriUtils.extractParameterMap(response.getHeaders().getFirst(HttpHeaders.LOCATION)))
            .containsEntry("error", "server_error")
            .containsEntry("error_description", EXCEPTION_TEXT);
        assertThat(response.getHeaders().getFirst("Cache-Control"))
            .containsOnlyOnce("no-store");
    }
}
