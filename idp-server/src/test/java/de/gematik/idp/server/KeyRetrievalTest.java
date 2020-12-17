/*
 * Copyright (c) 2020 gematik GmbH
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

import static de.gematik.idp.IdpConstants.DISCOVERY_DOCUMENT_ENDPOINT;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.tests.Afo;
import de.gematik.idp.tests.Rfc;
import de.gematik.idp.token.TokenClaimExtraction;
import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
import kong.unirest.UnirestException;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class KeyRetrievalTest {

    @LocalServerPort
    private int localServerPort;
    private String testHostUrl;

    @BeforeEach
    public void setUpLocalHostUrl() {
        testHostUrl = "http://localhost:" + localServerPort;
    }

    @Afo("A_20458")
    @Rfc({"https://openid.net/specs/openid-connect-discovery-1_0.html",
        "https://connect2id.com/products/server/docs/api/jwk-set"})
    @Test
    public void retrieveTokenKeyStore_ShouldBeAvailable() throws UnirestException, JoseException {
        final HttpResponse<String> httpResponse = retrieveDiscoveryDocument();
        final String pukUriToken = TokenClaimExtraction.extractClaimsFromTokenBody(httpResponse.getBody())
            .get("puk_uri_token").toString();
        final HttpResponse<String> jwks = Unirest.get(pukUriToken).asString();
        final JsonWebKeySet keySet = new JsonWebKeySet(jwks.getBody());
        assertThat(keySet.getJsonWebKeys())
            .extracting(k -> k.getKey())
            .isNotEmpty();
    }

    @Afo("A_20458")
    @Rfc({"https://openid.net/specs/openid-connect-discovery-1_0.html",
        "https://connect2id.com/products/server/docs/api/jwk-set"})
    @Test
    public void retrieveAuthKeyStore_ShouldBeAvailable() throws UnirestException, JoseException {
        final HttpResponse<String> httpResponse = retrieveDiscoveryDocument();
        final String pukUriAuth = TokenClaimExtraction.extractClaimsFromTokenBody(httpResponse.getBody())
            .get("puk_uri_auth").toString();
        final HttpResponse<String> jwks = Unirest.get(pukUriAuth).asString();
        final JsonWebKeySet keySet = new JsonWebKeySet(jwks.getBody());
        assertThat(keySet.getJsonWebKeys())
            .extracting(k -> k.getKey())
            .isNotEmpty();
    }

    private HttpResponse<String> retrieveDiscoveryDocument() {
        return Unirest.get(testHostUrl + DISCOVERY_DOCUMENT_ENDPOINT)
            .asString();
    }
}
