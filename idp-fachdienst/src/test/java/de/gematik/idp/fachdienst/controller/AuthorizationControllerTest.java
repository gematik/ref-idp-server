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

package de.gematik.idp.fachdienst.controller;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import de.gematik.idp.IdpConstants;
import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;

@Slf4j
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AuthorizationControllerTest {

    @LocalServerPort
    private int localServerPort;
    private String testHostUrl;

    @BeforeAll
    void setup() {
        testHostUrl = "http://localhost:" + localServerPort;
        log.info("testHostUrl: " + testHostUrl);
        Unirest.config().reset();
        Unirest.config().followRedirects(false);
    }

    @Disabled("Moved to integration tests in Testsuite. (dependencies to other server)")
    @Test
    void authorizationResponse_contains_httpStatus_302() {
        final HttpResponse response = Unirest.get(testHostUrl
                + IdpConstants.FACHDIENST_AUTHORIZATION_ENDPOINT)
            .queryString("client_id", "eRezeptApp")
            .queryString("state", "state")
            .queryString("redirect_uri", "TODO")
            .queryString("code_challenge", "P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk")
            .queryString("code_challenge_method", "S256")
            .queryString("response_type", "code")
            .queryString("scope", "e-rezept")
            .queryString("idp_iss", "IDP_SEKTORAL")
            .asEmpty();

        assertThat(response.getStatus()).isEqualTo(302);
    }

    @Test
    void authorizationRequest_missingParams() {
        final HttpResponse<String> response = Unirest.get(testHostUrl
                + IdpConstants.FACHDIENST_AUTHORIZATION_ENDPOINT)
            .asString();
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getBody().toString()).contains("Required request parameter 'client_id'");
    }

    @Test
    void authorizationRequest_invalidParam_code_challenge_method() {
        final HttpResponse<String> response = Unirest.get(testHostUrl
                + IdpConstants.FACHDIENST_AUTHORIZATION_ENDPOINT)
            .queryString("client_id", "eRezeptApp")
            .queryString("state", "state")
            .queryString("redirect_uri", "TODO")
            .queryString("code_challenge", "P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk")
            .queryString("code_challenge_method", "S257")
            .queryString("response_type", "code")
            .queryString("scope", "e-rezept")
            .queryString("idp_iss", "TODO")
            .asString();
        assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
        assertThat(response.getBody()).contains("must match");
    }

    @Test
    void authorizationRequest_validParams() {
        final HttpResponse response = Unirest.get(testHostUrl
                + IdpConstants.FACHDIENST_AUTHORIZATION_ENDPOINT)
            .queryString("client_id", "eRezeptApp")
            .queryString("state", "state")
            .queryString("redirect_uri", "TODO")
            .queryString("code_challenge", "P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk")
            .queryString("code_challenge_method", "S256")
            .queryString("response_type", "code")
            .queryString("scope", "e-rezept")
            .queryString("idp_iss", "TODO")
            .asString();
        // Invalid parameter would lead to Error 400.
        assertThat(response.getStatus()).isNotEqualTo(HttpStatus.BAD_REQUEST.value());
    }

}
