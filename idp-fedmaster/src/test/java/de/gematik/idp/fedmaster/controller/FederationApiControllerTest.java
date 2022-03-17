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

package de.gematik.idp.fedmaster.controller;

import static de.gematik.idp.EnvHelper.getSystemProperty;
import static org.assertj.core.api.Assertions.assertThat;
import de.gematik.idp.IdpConstants;
import de.gematik.idp.token.JsonWebToken;
import kong.unirest.HttpResponse;
import kong.unirest.HttpStatus;
import kong.unirest.Unirest;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpHeaders;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;

@Slf4j
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class FederationApiControllerTest {

    private final static String IDP_FACHDIENST_PORT;
    private final static String IDP_SEKTORAL_PORT;

    static {
        IDP_FACHDIENST_PORT = "8081";
        IDP_SEKTORAL_PORT = "8082";

        if (getSystemProperty("IDP_FACHDIENST_PORT").isEmpty()) {
            System.setProperty("IDP_FACHDIENST_PORT", IDP_FACHDIENST_PORT);
        }
        if (getSystemProperty("IDP_SEKTORAL_PORT").isEmpty()) {
            System.setProperty("IDP_SEKTORAL_PORT", IDP_SEKTORAL_PORT);
        }
    }

    private final static String IDP_FACHDIENST_URL = "http://127.0.0.1:" + IDP_FACHDIENST_PORT;
    private final static String IDP_SEKTORAL_URL = "http://127.0.0.1:" + IDP_SEKTORAL_PORT;

    @LocalServerPort
    private int localServerPort;
    private String testHostUrl;

    @BeforeAll
    public void setup() {
        testHostUrl = "http://localhost:" + localServerPort;
        log.info("testHostUrl: " + testHostUrl);
    }

    @Test
    void getEntityStatementFdResponse_HttpStatus200() {
        final HttpResponse response = retrieveEntityStatement(IDP_FACHDIENST_URL);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void getEntityStatementIdpResponse_HttpStatus200() {
        final HttpResponse response = retrieveEntityStatement(IDP_SEKTORAL_URL);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void getEntityStatementI_missingParams() {
        final HttpResponse response = Unirest.get(testHostUrl + IdpConstants.FEDMASTER_FEDERATION_API_ENDPOINT)
            .asString();
        assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void EntityStatementFdResponse_ContentTypeJose() {
        final HttpResponse response = retrieveEntityStatement(IDP_FACHDIENST_URL);
        assertThat(response.getHeaders().get(HttpHeaders.CONTENT_TYPE).get(0)).isEqualTo(
            "application/jose;charset=UTF-8");
    }

    @Test
    void EntityStatementIdpResponse_ContentTypeJose() {
        final HttpResponse response = retrieveEntityStatement(IDP_SEKTORAL_URL);
        assertThat(response.getHeaders().get(HttpHeaders.CONTENT_TYPE).get(0)).isEqualTo(
            "application/jose;charset=UTF-8");
    }

    @Test
    void EntityStatementFdResponse_JoseHeader() {
        final JsonWebToken jwtInResponse = retrieveJwtFromEntityStatementFd();
        assertThat(jwtInResponse.extractHeaderClaims()).containsOnlyKeys("typ", "alg", "kid");
    }

    @Test
    void EntityStatementFd_ContainsJwks() {
        final JsonWebToken jwtInResponse = retrieveJwtFromEntityStatementFd();
        assertThat(jwtInResponse.extractBodyClaims().get("jwks")).isNotNull();
    }

    @Test
    void EntityStatementFd_ContainsSub() {
        final JsonWebToken jwtInResponse = retrieveJwtFromEntityStatementFd();
        assertThat(jwtInResponse.extractBodyClaims().get("sub")).isNotNull();
        assertThat(jwtInResponse.extractBodyClaims()).containsEntry("sub", IDP_FACHDIENST_URL);
    }

    @Test
    void EntityStatementIdp_ContainsSub() {
        final JsonWebToken jwtInResponse = retrieveJwtFromEntityStatementIdp();
        assertThat(jwtInResponse.extractBodyClaims().get("sub")).isNotNull();
        assertThat(jwtInResponse.extractBodyClaims()).containsEntry("sub", IDP_SEKTORAL_URL);
    }

    @Test
    void EntityStatementFd_ContainsIss() {
        final JsonWebToken jwtInResponse = retrieveJwtFromEntityStatementFd();
        assertThat(jwtInResponse.extractBodyClaims().get("iss")).isNotNull();
        // Here "iss" is the FedMaster and it is the test host.
        assertThat(jwtInResponse.extractBodyClaims()).containsEntry("iss", testHostUrl);
    }

    @Test
    void EntityStatementIdp_ContainsIss() {
        final JsonWebToken jwtInResponse = retrieveJwtFromEntityStatementIdp();
        assertThat(jwtInResponse.extractBodyClaims().get("iss")).isNotNull();
        assertThat(jwtInResponse.extractBodyClaims()).containsEntry("iss", testHostUrl);
    }

    @Test
    void EntityStatementFd_NotContainsMetadata() {
        final JsonWebToken jwtInResponse = retrieveJwtFromEntityStatementFd();
        assertThat(jwtInResponse.extractBodyClaims().get("metadata")).isNull();
    }

    private JsonWebToken retrieveJwtFromEntityStatementFd() {
        return new JsonWebToken(retrieveEntityStatement(IDP_FACHDIENST_URL).getBody());
    }

    private JsonWebToken retrieveJwtFromEntityStatementIdp() {
        return new JsonWebToken(retrieveEntityStatement(IDP_SEKTORAL_URL).getBody());
    }

    private HttpResponse<String> retrieveEntityStatement(final String sub) {
        return Unirest.get(testHostUrl + IdpConstants.FEDMASTER_FEDERATION_API_ENDPOINT)
            .queryString("iss", "http://master0815.de")
            .queryString("sub", sub)
            .asString();
    }

}
