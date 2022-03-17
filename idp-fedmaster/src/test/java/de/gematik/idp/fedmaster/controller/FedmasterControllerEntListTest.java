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
import java.util.List;
import java.util.Map;
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
class FedmasterControllerEntListTest {

    private static final String IDP_NAME_1 = "IDP_SEKTORAL";
    private static final String IDP_PORT_1 = "8082";

    @LocalServerPort
    private int localServerPort;
    private String testHostUrl;
    private HttpResponse<String> responseGood;
    private JsonWebToken jwtInResponseGood;
    private Map<String, Object> bodyClaims;

    @BeforeAll
    public void setup() {
        setEnv();
        testHostUrl = "http://localhost:" + localServerPort;
        responseGood = retrieveEntityList();
        assertThat(responseGood.getStatus()).isEqualTo(HttpStatus.OK);
        jwtInResponseGood = new JsonWebToken(responseGood.getBody());
        bodyClaims = jwtInResponseGood.extractBodyClaims();
        log.info("testHostUrl: " + testHostUrl);
    }

    @Test
    void entityListResponse_ContentTypeJose() {
        assertThat(responseGood.getHeaders().get(HttpHeaders.CONTENT_TYPE).get(0)).isEqualTo(
            "application/jwt;charset=UTF-8");
    }

    @Test
    void entityListResponse_JoseHeader() {
        assertThat(jwtInResponseGood.extractHeaderClaims()).containsOnlyKeys(
            "typ",
            "alg",
            "kid");
    }

    @Test
    void entityListResponse_Alg() {
        assertThat(jwtInResponseGood.extractHeaderClaims()).containsEntry("alg", "ES256");
    }

    @Test
    void entityList_BodyClaimsComplete() {
        assertThat(bodyClaims)
            .containsOnlyKeys(
                "iss",
                "iat",
                "exp",
                "idp_entity_list");
    }

    @Test
    void entityList_firstEntry() {
        assertThat((List) bodyClaims.get("idp_entity_list")).hasSize(1);
        final Map<String, Object> claims = (Map<String, Object>) ((List) bodyClaims.get("idp_entity_list")).get(0);
        assertThat(claims).containsEntry("name", IDP_NAME_1);
        assertThat(claims).containsEntry("iss", "http://127.0.0.1:" + IDP_PORT_1);
    }

    @Test
    void entityList_BodyIsOfTypeJsonWebToken() {
        final JsonWebToken jwtInResponse = new JsonWebToken(responseGood.getBody());
        assertThat(jwtInResponse).isNotNull();
    }

    private void setEnv() {
        if (getSystemProperty("IDP_FACHDIENST_PORT").isEmpty()) {
            System.setProperty("IDP_FACHDIENST_PORT", "8081");
        }
        if (getSystemProperty(IDP_NAME_1 + "_PORT").isEmpty()) {
            System.setProperty(IDP_NAME_1 + "_PORT", IDP_PORT_1);
        }
    }

    private HttpResponse<String> retrieveEntityList() {
        return Unirest.get(testHostUrl + IdpConstants.ENTITY_LISTING_ENDPOINT).asString();
    }

}
