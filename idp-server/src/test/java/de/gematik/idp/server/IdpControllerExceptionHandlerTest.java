/*
 *  Copyright 2023 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
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
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.TestConstants;
import de.gematik.idp.authentication.UriUtils;
import de.gematik.idp.error.IdpErrorType;
import de.gematik.idp.server.configuration.IdpConfiguration;
import de.gematik.idp.server.controllers.IdpKey;
import de.gematik.idp.server.exceptions.IdpServerException;
import de.gematik.idp.server.exceptions.handler.IdpServerExceptionHandler;
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
import org.springframework.beans.factory.annotation.Autowired;
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

  private static final String EXCEPTION_TEXT = "exception text";
  @Autowired private IdpKey discSig;
  @Autowired private ServerUrlService serverUrlService;
  @Autowired private IdpConfiguration idpConfiguration;
  private IdpServerExceptionHandler idpServerExceptionHandler;

  @LocalServerPort private int port;
  @MockBean private IdpAuthenticator idpAuthenticator;
  private String serverUrl;

  @BeforeAll
  void init() {
    serverUrl = "http://localhost:" + port;
    Unirest.config().reset();
    Unirest.config().followRedirects(false);
    idpServerExceptionHandler =
        new IdpServerExceptionHandler(
            serverUrlService, discSig, idpConfiguration, idpAuthenticator);
  }

  @Test
  void testIdpServerInvalidRequestException() {
    doThrow(new IdpServerException(IdpErrorType.INVALID_REQUEST, HttpStatus.BAD_REQUEST))
        .when(idpAuthenticator)
        .validateRedirectUri(any(), any());
    final HttpResponse<JsonNode> response =
        Unirest.get(serverUrl + IdpConstants.BASIC_AUTHORIZATION_ENDPOINT)
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

    final String nonceToLong =
        "d76ae6c3a23ef5cda33f12826e99b643463a2f0796b232880e93d55f55d820ebdc202e7e4d2486f7374d6a2778fda6dbcf33ae3499a58a8411ee44ff0c56246cfa81970cf3865af63a971e96fbaa9559d223b5e405f009f230644750734423c81c27013c61e492cfb7fa380458be9958f1d8e6405c6ec760e53e6eac35133a2baf305f0909098130a0e12d973a7d773d3e027ffa4d3dba2f28f5cb845517eb832b5b293a5120c2e21fbb3e643ab783170a695707ebe264d610ab135d18131f08e654a082c08a2dd645fb8a3a9faa2f81002117258f36b3e9791912ffd9a42b6253d542e13326602e7e9fce47f873a83f406ed26e8dd9c2942c02ecef6de265a000";
    final HttpResponse<JsonNode> response =
        Unirest.get(serverUrl + IdpConstants.BASIC_AUTHORIZATION_ENDPOINT)
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

    assertThat(response.getStatus()).isEqualTo(302);
    assertThat(response.getHeaders().get("Location").get(0))
        .contains("nonce%20ist%20ung%C3%BCltig");
  }

  @Test
  void testIdpServerInvalidLengthStateException() {

    final String nonceCorrectLength =
        "d76ae6c3a23ef5cda33f12826e99b643463a2f0796b232880e93d55f55d820ebdc202e7e4d2486f7374d6a2778fda6dbcf33ae3499a58a8411ee44ff0c56246cfa81970cf3865af63a971e96fbaa9559d223b5e405f009f230644750734423c81c27013c61e492cfb7fa380458be9958f1d8e6405c6ec760e53e6eac35133a2baf305f0909098130a0e12d973a7d773d3e027ffa4d3dba2f28f5cb845517eb832b5b293a5120c2e21fbb3e643ab783170a695707ebe264d610ab135d18131f08e654a082c08a2dd645fb8a3a9faa2f81002117258f36b3e9791912ffd9a42b6253d542e13326602e7e9fce47f873a83f406ed26e8dd9c2942c02ecef6de265a0";
    final String stateToLong =
        "d76ae6c3a23ef5cda33f12826e99b643463a2f0796b232880e93d55f55d820ebdc202e7e4d2486f7374d6a2778fda6dbcf33ae3499a58a8411ee44ff0c56246cfa81970cf3865af63a971e96fbaa9559d223b5e405f009f230644750734423c81c27013c61e492cfb7fa380458be9958f1d8e6405c6ec760e53e6eac35133a2baf305f0909098130a0e12d973a7d773d3e027ffa4d3dba2f28f5cb845517eb832b5b293a5120c2e21fbb3e643ab783170a695707ebe264d610ab135d18131f08e654a082c08a2dd645fb8a3a9faa2f81002117258f36b3e9791912ffd9a42b6253d542e13326602e7e9fce47f873a83f406ed26e8dd9c2942c02ecef6de265a00";
    final HttpResponse<JsonNode> response =
        Unirest.get(serverUrl + IdpConstants.BASIC_AUTHORIZATION_ENDPOINT)
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

    assertThat(response.getStatus()).isEqualTo(302);
    assertThat(response.getHeaders().get("Location").get(0))
        .contains("state%20ist%20ung%C3%BCltig");
  }

  @Test
  void authentication_idpServerException_expectRedirect() {
    doThrow(new IdpServerException(EXCEPTION_TEXT, IdpErrorType.INVALID_REQUEST, HttpStatus.FOUND))
        .when(idpAuthenticator)
        .validateRedirectUri(any(), any());
    final String redirectUri = "https://redirect.test";
    final HttpResponse response =
        Unirest.get(serverUrl + IdpConstants.BASIC_AUTHORIZATION_ENDPOINT)
            .queryString("signed_challenge", "signed_challenge")
            .queryString("client_id", TestConstants.CLIENT_ID_E_REZEPT_APP)
            .queryString("state", "state")
            .queryString("redirect_uri", redirectUri)
            .queryString("nonce", "fdsalkfdksalfdsa")
            .queryString("response_type", "code")
            .queryString("code_challenge", "fkdsjfkdsjfkjdskafjdksljfkdsjfkldsjjjjjjjjj")
            .queryString("code_challenge_method", "S256")
            .queryString("scope", "openid e-rezept")
            .accept(MediaType.APPLICATION_JSON.toString())
            .asEmpty();

    assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
    final String uri = response.getHeaders().getFirst(HttpHeaders.LOCATION);
    assertThat(uri).startsWith(redirectUri);
    assertThat(UriUtils.extractParameterMap(uri))
        .containsEntry("error", "invalid_request")
        .containsEntry("error_description", EXCEPTION_TEXT)
        .containsEntry("gematik_error_text", EXCEPTION_TEXT)
        .containsKey("gematik_timestamp")
        .containsKey("gematik_uuid");
  }

  @Test
  void authentication_genericError_expectRedirect() {

    doThrow(new IdpServerException(EXCEPTION_TEXT, IdpErrorType.SERVER_ERROR, HttpStatus.FOUND))
        .when(idpAuthenticator)
        .validateRedirectUri(any(), any());
    final HttpResponse response =
        Unirest.get(serverUrl + IdpConstants.BASIC_AUTHORIZATION_ENDPOINT)
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
            .asEmpty();

    assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
    assertThat(UriUtils.extractParameterMap(response.getHeaders().getFirst(HttpHeaders.LOCATION)))
        .containsEntry("error", "server_error")
        .containsEntry("error_description", EXCEPTION_TEXT);
    assertThat(response.getHeaders().getFirst("Cache-Control")).containsOnlyOnce("no-store");
  }

  @Test
  void authentication_genericError_missingRedirectInForwardingError() {
    when(idpAuthenticator.getBasicFlowTokenLocation(any()))
        .thenThrow(
            new IdpServerException(EXCEPTION_TEXT, IdpErrorType.SERVER_ERROR, HttpStatus.FOUND));
    final HttpResponse<JsonNode> response =
        Unirest.post(serverUrl + IdpConstants.BASIC_AUTHORIZATION_ENDPOINT)
            .queryString("signed_challenge", "signed_challenge")
            .accept(MediaType.APPLICATION_JSON.toString())
            .asJson();

    final JSONObject errorObject = response.getBody().getObject();
    assertThat(response.getStatus()).isEqualTo(400);
    assertThat(errorObject.getString("error")).isEqualTo("server_error");
    assertThat(errorObject.get("gematik_uuid")).isNotNull();
    assertThat(errorObject.get("gematik_timestamp")).isNotNull();
  }
}
