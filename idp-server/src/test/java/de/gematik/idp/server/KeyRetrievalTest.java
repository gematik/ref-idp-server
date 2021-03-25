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

import static de.gematik.idp.IdpConstants.DISCOVERY_DOCUMENT_ENDPOINT;
import static org.assertj.core.api.Assertions.assertThat;
import de.gematik.idp.server.controllers.IdpKey;
import de.gematik.idp.tests.Afo;
import de.gematik.idp.tests.Rfc;
import de.gematik.idp.token.TokenClaimExtraction;
import java.util.stream.Collectors;
import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.Unirest;
import kong.unirest.UnirestException;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class KeyRetrievalTest {

    @LocalServerPort
    private int localServerPort;
    @Autowired
    private IdpKey idpEnc;
    @Autowired
    private IdpKey idpSig;
    @Autowired
    private IdpKey discSig;
    private String testHostUrl;

    @BeforeEach
    public void setUpLocalHostUrl() {
        testHostUrl = "http://localhost:" + localServerPort;
    }

    @Afo("A_20458")
    @Test
    public void retrieveIDPEncKey_ShouldBeAvailable() throws UnirestException, JoseException {
        final HttpResponse<String> httpResponse = retrieveDiscoveryDocument();
        final String pukUriToken = TokenClaimExtraction.extractClaimsFromJwtBody(httpResponse.getBody())
            .get("uri_puk_idp_enc").toString();
        final HttpResponse<String> jwk = Unirest.get(pukUriToken).asString();
        final JsonWebKeySet keySet = constructKeySetFromJwkBody(jwk);
        assertThat(keySet.getJsonWebKeys())
            .extracting(k -> k.getKey())
            .isNotEmpty();
    }

    @Afo("A_20458")
    @Test
    public void retrieveIDPSigKey_ShouldBeAvailable() throws UnirestException, JoseException {
        final HttpResponse<String> httpResponse = retrieveDiscoveryDocument();
        final String pukUriAuth = TokenClaimExtraction.extractClaimsFromJwtBody(httpResponse.getBody())
            .get("uri_puk_idp_sig").toString();
        final HttpResponse<String> jwk = Unirest.get(pukUriAuth).asString();
        final JsonWebKeySet keySet = constructKeySetFromJwkBody(jwk);
        assertThat(keySet.getJsonWebKeys())
            .extracting(k -> k.getKey())
            .isNotEmpty();
    }

    @Afo("A_20458")
    @Test
    public void retrieveSigKey_noRsaFieldShouldBePresent() throws UnirestException {
        final HttpResponse<String> httpResponse = retrieveDiscoveryDocument();
        final String pukUriAuth = TokenClaimExtraction.extractClaimsFromJwtBody(httpResponse.getBody())
            .get("uri_puk_idp_sig").toString();
        final JsonNode jwk = Unirest.get(pukUriAuth).asJson().getBody();
        assertThat(jwk.getObject().has("n")).isFalse();
        assertThat(jwk.getObject().has("e")).isFalse();
    }

    @Test
    public void retrieveSigKey_useFieldShouldBePresent() throws UnirestException {
        final HttpResponse<String> httpResponse = retrieveDiscoveryDocument();
        final String pukUriAuth = TokenClaimExtraction.extractClaimsFromJwtBody(httpResponse.getBody())
            .get("uri_puk_idp_sig").toString();
        final JsonNode jwk = Unirest.get(pukUriAuth).asJson().getBody();
        assertThat(jwk.getObject().has("use")).isTrue();
        assertThat(jwk.getObject().get("use")).isEqualTo("sig");
    }

    @Test
    public void retrieveEndKey_useFieldShouldBePresent() throws UnirestException {
        final HttpResponse<String> httpResponse = retrieveDiscoveryDocument();
        final String pukUriAuth = TokenClaimExtraction.extractClaimsFromJwtBody(httpResponse.getBody())
            .get("uri_puk_idp_enc").toString();
        final JsonNode jwk = Unirest.get(pukUriAuth).asJson().getBody();
        assertThat(jwk.getObject().has("use")).isTrue();
        assertThat(jwk.getObject().get("use")).isEqualTo("enc");
    }

    @Afo("A_20458")
    @Rfc({"https://openid.net/specs/openid-connect-discovery-1_0.html",
        "https://connect2id.com/products/server/docs/api/jwk-set",
        "RFC7517"})
    @Test
    public void retrieveJwksKeyStore_ShouldBeAvailable() throws UnirestException, JoseException {
        final HttpResponse<String> httpResponse = retrieveDiscoveryDocument();
        final String jwksUri = TokenClaimExtraction.extractClaimsFromJwtBody(httpResponse.getBody())
            .get("jwks_uri").toString();
        final HttpResponse<String> jwks = Unirest.get(jwksUri).asString();
        final JsonWebKeySet keySet = new JsonWebKeySet(jwks.getBody());
        assertThat(keySet.getJsonWebKeys())
            .extracting(k -> k.getKey())
            .isNotEmpty();
        assertThat(keySet.getJsonWebKeys())
            .hasSize(2);
        assertThat(keySet.getJsonWebKeys().stream()
            .map(JsonWebKey::getKeyId)
            .collect(Collectors.toList()))
            .containsExactlyInAnyOrder(idpSig.getIdentity().getKeyId().get(),
                idpEnc.getIdentity().getKeyId().get());
    }

    @Test
    public void retrieveJwksKeyStore_shouldContainUseClaims() throws UnirestException, JoseException {
        final HttpResponse<String> httpResponse = retrieveDiscoveryDocument();
        final String jwksUri = TokenClaimExtraction.extractClaimsFromJwtBody(httpResponse.getBody())
            .get("jwks_uri").toString();
        final HttpResponse<JsonNode> jwks = Unirest.get(jwksUri).asJson();
        assertThat(jwks.getBody().getObject().getJSONArray("keys").getJSONObject(0).getString("use"))
            .matches("(sig|enc)");
    }

    @Afo("A_20458")
    @Test
    public void keyIdsShouldMatchAcrossSources() throws UnirestException, JoseException {
        final HttpResponse<String> httpResponse = retrieveDiscoveryDocument();
        final String pukUriAuth = TokenClaimExtraction.extractClaimsFromJwtBody(httpResponse.getBody())
            .get("uri_puk_idp_sig").toString();
        final String jwksUri = TokenClaimExtraction.extractClaimsFromJwtBody(httpResponse.getBody())
            .get("jwks_uri").toString();

        final JsonWebKeySet keySet = new JsonWebKeySet(Unirest.get(jwksUri).asString().getBody());
        final String keyIdFromIndividual = Unirest.get(pukUriAuth).asJson().getBody().getObject().getString("kid");

        assertThat(keySet.findJsonWebKey(keyIdFromIndividual, null, null, null))
            .isNotNull();
    }

    private JsonWebKeySet constructKeySetFromJwkBody(final HttpResponse<String> jwks) throws JoseException {
        final JsonWebKeySet keySet = new JsonWebKeySet("{\"keys\" : [" + jwks.getBody() + "]}");
        return keySet;
    }

    private HttpResponse<String> retrieveDiscoveryDocument() {
        return Unirest.get(testHostUrl + DISCOVERY_DOCUMENT_ENDPOINT)
            .asString();
    }
}
