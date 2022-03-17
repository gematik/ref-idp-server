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

package de.gematik.idp.sektoral.controller;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import de.gematik.idp.IdpConstants;
import java.util.Set;
import javax.ws.rs.core.HttpHeaders;
import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.Unirest;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

@Slf4j
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class SektoralIdpControllerTest {

    @LocalServerPort
    private int sektoralIdpServerPort;

    @BeforeAll
    public static void beforeAll() {
        Unirest.config().reset();
        Unirest.config().followRedirects(false);
    }

    @Test
    public void authorizationResponse_contains_httpStatus_302() {
        log.info("server port: " + sektoralIdpServerPort);
        final HttpResponse response = Unirest.get(
                "http://localhost:" + sektoralIdpServerPort + IdpConstants.SEKTORAL_IDP_AUTHORIZATION_ENDPOINT)
            .queryString("client_id", "eRezeptApp")
            .queryString("state", "state")
            .queryString("redirect_uri", "https://redirect.smartcard.de/erezept")
            .queryString("nonce", "123456789")
            .queryString("response_type", "code")
            .queryString("scope", "openid")
            .queryString("code_challenge", "P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk")
            .queryString("code_challenge_method", "S256")
            .asEmpty();

        assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());

    }

    @Test
    public void tokenResponse_contains_httpStatus_200() {
        final HttpResponse<JsonNode> httpResponse = Unirest.post(
                "http://localhost:" + sektoralIdpServerPort + IdpConstants.TOKEN_ENDPOINT)
            .field("client_id", "smartcardidp")
            .field("grant_type", "authorization_code")
            .field("code", "BASE64TOBEDONE")
            .field("code_verifier", "CODE_VERIFIER")
            .field("redirect_uri", "smartcardidp_uri")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
            .asJson();
        assertThat(httpResponse.getStatus()).isEqualTo(HttpStatus.OK.value());
    }


    @Test
    public void tokenRequest_missingParams() {
        final HttpResponse<JsonNode> httpResponse = Unirest.post(
                "http://localhost:" + sektoralIdpServerPort + IdpConstants.TOKEN_ENDPOINT)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
            .asJson();
        assertThat(httpResponse.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
    }

    @Test
    public void correctAuthorizationResponseTest() {
        log.info("port: " + sektoralIdpServerPort);
        final HttpResponse response = Unirest.get(
                "http://localhost:" + sektoralIdpServerPort + IdpConstants.SEKTORAL_IDP_AUTHORIZATION_ENDPOINT)
            .queryString("client_id", "smardcardIdp")
            .queryString("state", "state")
            .queryString("redirect_uri", "https://redirect.smartcard.de/erezept")
            .queryString("nonce", "fdsalkfdksalfdsa")
            .queryString("response_type", "code")
            .queryString("scope", "openid erp_sek_auth")
            .queryString("code_challenge", "P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk")
            .queryString("code_challenge_method", "S256")
            .asEmpty();

        final String location = response.getHeaders().getFirst("Location");
        assertThat(location).isNotNull().contains("state").contains("code");
    }

    @Test
    public void correktTokenResponse() {
        log.info("port: " + sektoralIdpServerPort);
        final HttpResponse<JsonNode> httpResponse = Unirest.post(
                "http://localhost:" + sektoralIdpServerPort + IdpConstants.TOKEN_ENDPOINT)
            .field("client_id", "smartcardidp")
            .field("grant_type", "authorization_code")
            .field("code", "BASE64TOBEDONE")
            .field("code_verifier", "CODE_VERIFIER")
            .field("redirect_uri", "smartcardidp_uri")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
            .asJson();
        final Set<String> keySet = httpResponse.getBody().getObject().keySet();
        assertThat(keySet.contains("id_token")).isTrue();
        assertThat(keySet.contains("access_token")).isTrue();
        assertThat(keySet.contains("token_type")).isTrue();
        assertThat(keySet.contains("expires_in")).isTrue();
        assertThat(httpResponse.getBody().getObject().getString("id_token")).startsWith("ey");
    }
}
