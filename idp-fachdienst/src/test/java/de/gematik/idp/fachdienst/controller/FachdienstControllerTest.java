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

import static de.gematik.idp.EnvHelper.getSystemProperty;
import static org.assertj.core.api.Assertions.assertThat;
import de.gematik.idp.IdpConstants;
import de.gematik.idp.token.JsonWebToken;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import kong.unirest.HttpResponse;
import kong.unirest.HttpStatus;
import kong.unirest.Unirest;
import org.apache.http.HttpHeaders;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class FachdienstControllerTest {

    static {
        if (getSystemProperty("IDP_FEDMASTER").isEmpty()) {
            System.setProperty("IDP_FEDMASTER", "http://127.0.0.1");
            System.setProperty("IDP_FEDMASTER_PORT", "8080");
        }
    }

    @LocalServerPort
    private int localServerPort;
    private String testHostUrl;
    private HttpResponse<String> responseGood;
    private JsonWebToken jwtInResponseGood;
    private Map<String, Object> bodyClaims;

    final static List<String> OPENID_RELYING_PARTY_CLAIMS = List.of(
        "signed_jwks_uri",
        "organization_name",
        "client_name",
        "logo_uri",
        "redirect_uris",
        "response_types",
        "client_registration_types",
        "grant_types",
        "require_pushed_authorization_requests",
        "token_endpoint_auth_method",
        "token_endpoint_auth_signing_alg",
        "id_token_signed_response_alg",
        "id_token_encrypted_response_alg",
        "id_token_encrypted_response_enc");

    @BeforeAll
    void setup() {
        testHostUrl = "http://localhost:" + localServerPort;
        responseGood = retrieveEntityStatement();
        assertThat(responseGood.getStatus()).isEqualTo(HttpStatus.OK);
        jwtInResponseGood = new JsonWebToken(responseGood.getBody());
        bodyClaims = jwtInResponseGood.extractBodyClaims();
    }

    @Test
    void entityStatementResponse_ContentTypeJose() {
        assertThat(responseGood.getHeaders().get(HttpHeaders.CONTENT_TYPE).get(0)).isEqualTo(
            "application/jose;charset=UTF-8");
    }

    @Test
    void entityStatementResponse_JoseHeader() {
        assertThat(jwtInResponseGood.extractHeaderClaims()).containsOnlyKeys(
            "typ",
            "alg",
            "kid");
    }

    @Test
    void entityStatement_BodyClaimsComplete() {
        assertThat(bodyClaims)
            .containsOnlyKeys(
                "iss",
                "sub",
                "iat",
                "exp",
                "jwks",
                "authority_hints",
                "metadata");
    }

    @Test
    void entityStatement_ContainsJwks() {
        assertThat(bodyClaims.get("jwks")).isNotNull();
    }

    @Test
    void entityStatement_MetadataClaims() {
        final Map<String, Object> metadata = getInnerClaimMap(bodyClaims, "metadata");
        assertThat(metadata).containsOnlyKeys(
            "openid_relying_party",
            "federation_entity");
    }

    @Test
    void entityStatement_OpenidRelyingPartyClaimsComplete() {
        final Map<String, Object> metadata = getInnerClaimMap(bodyClaims, "metadata");
        final Map<String, Object> openidRelyingParty = Objects.requireNonNull(
            (Map<String, Object>) metadata.get("openid_relying_party"), "missing claim: openid_relying_party");

        assertThat(openidRelyingParty).containsOnlyKeys(OPENID_RELYING_PARTY_CLAIMS);
    }

    @SuppressWarnings("unchecked")
    @Test
    void entityStatement_openidRelyingPartyClaimsContentCorrect() {

        final Map<String, Object> metadata = getInnerClaimMap(bodyClaims, "metadata");
        final Map<String, Object> openidRelyingParty = Objects.requireNonNull(
            (Map<String, Object>) metadata.get("openid_relying_party"), "missing claim: openid_relying_party");

        assertThat(openidRelyingParty).containsEntry("signed_jwks_uri", testHostUrl + "/jws.json");
        assertThat(openidRelyingParty.get("organization_name")).asString().isNotEmpty();
        assertThat(openidRelyingParty.get("client_name")).asString().isNotEmpty();
        assertThat(openidRelyingParty.get("logo_uri")).asString().isNotEmpty();
        assertThat((List) openidRelyingParty.get("redirect_uris")).hasSizeGreaterThan(0);
        assertThat((List) openidRelyingParty.get("response_types")).containsExactlyInAnyOrder("code");
        assertThat((List) openidRelyingParty.get("client_registration_types")).containsExactlyInAnyOrder("automatic");
        assertThat((List) openidRelyingParty.get("grant_types")).containsExactlyInAnyOrder("authorization_code");
        assertThat((Boolean) openidRelyingParty.get("require_pushed_authorization_requests")).isTrue();
        assertThat(openidRelyingParty).containsEntry("token_endpoint_auth_method", "private_key_jwt");
        assertThat(openidRelyingParty).containsEntry("token_endpoint_auth_signing_alg", "ES256");
        assertThat(openidRelyingParty).containsEntry("id_token_signed_response_alg", "ES256");
        assertThat(openidRelyingParty).containsEntry("id_token_encrypted_response_alg", "ECDH-ES");
        assertThat(openidRelyingParty).containsEntry("id_token_encrypted_response_enc", "A256GCM");
    }

    @SuppressWarnings("unchecked")
    @Test
    void entityStatement_FederationEntityClaimsContentCorrect() {
        final Map<String, Object> metadata = getInnerClaimMap(bodyClaims, "metadata");
        final Map<String, Object> federationEntity = Objects.requireNonNull(
            (Map<String, Object>) metadata.get("federation_entity"), "missing claim: federation_entity");

        assertThat(federationEntity).containsEntry("name", "Fachdienst007");
        assertThat(federationEntity).containsEntry("contacts", "Support@Fachdienst007.de");
        assertThat(federationEntity).containsEntry("homepage_uri", "https://Fachdienst007.de");
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> getInnerClaimMap(final Map<String, Object> claimMap, final String key) {
        return Objects.requireNonNull(
            (Map<String, Object>) claimMap.get(key), "missing claim: " + key);
    }

    private HttpResponse<String> retrieveEntityStatement() {
        return Unirest.get(testHostUrl + IdpConstants.ENTITY_STATEMENT_ENDPOINT)
            .asString();
    }

}
