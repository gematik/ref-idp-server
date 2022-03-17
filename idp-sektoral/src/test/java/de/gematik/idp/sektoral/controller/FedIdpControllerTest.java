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
class FedIdpControllerTest {

    @LocalServerPort
    private int localServerPort;
    private String testHostUrl;
    private HttpResponse<String> responseGood;
    private JsonWebToken jwtInResponseGood;
    private Map<String, Object> bodyClaims;

    final static List<String> OPENID_PROVIDER_CLAIMS = List.of(
        "issuer",
        "signed_jwks_uri",
        "organization_name",
        "logo_uri",
        "authorization_endpoint",
        "token_endpoint",
        "pushed_authorization_request_endpoint",
        "client_registration_types_supported",
        "subject_types_supported",
        "response_types_supported",
        "scopes_supported",
        "response_modes_supported",
        "grant_types_supported",
        "require_pushed_authorization_requests",
        "token_endpoint_auth_methods_supported",
        "token_endpoint_auth_signing_alg_values_supported",
        "request_authentication_methods_supported",
        "id_token_signing_alg_values_supported",
        "id_token_encryption_alg_values_supported",
        "id_token_encryption_enc_values_supported",
        "claims_supported",
        "claims_parameter_supported",
        "user_type_supported");

    @BeforeAll
    void setup() {
        testHostUrl = "http://localhost:" + localServerPort;
        responseGood = retrieveEntityStatement();
        assertThat(responseGood.getStatus()).isEqualTo(HttpStatus.OK);
        jwtInResponseGood = new JsonWebToken(responseGood.getBody());
        bodyClaims = jwtInResponseGood.extractBodyClaims();
    }

    /************************** ENTITY_STATEMENT_ENDPOINT *****************/

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
            "openid_provider",
            "federation_entity");
    }

    @Test
    void entityStatement_OpenidProviderClaimsComplete() {
        final Map<String, Object> metadata = getInnerClaimMap(bodyClaims, "metadata");
        final Map<String, Object> openidProvider = Objects.requireNonNull(
            (Map<String, Object>) metadata.get("openid_provider"), "missing claim: openid_provider");

        assertThat(openidProvider).containsOnlyKeys(OPENID_PROVIDER_CLAIMS);
    }

    @SuppressWarnings("unchecked")
    @Test
    void entityStatement_OpenidProviderClaimsContentCorrect() {

        final Map<String, Object> metadata = getInnerClaimMap(bodyClaims, "metadata");
        final Map<String, Object> openidProvider = Objects.requireNonNull(
            (Map<String, Object>) metadata.get("openid_provider"), "missing claim: openid_provider");

        assertThat(openidProvider).containsEntry("issuer", testHostUrl);
        assertThat(openidProvider).containsEntry("signed_jwks_uri", testHostUrl + "/jws.json");
        assertThat(openidProvider.get("organization_name")).asString().isNotEmpty();
        assertThat(openidProvider.get("logo_uri")).asString().isNotEmpty();
        assertThat(openidProvider).containsEntry("authorization_endpoint", testHostUrl + "/Auth");
        assertThat(openidProvider).containsEntry("token_endpoint", testHostUrl + "/Token");
        assertThat(openidProvider).containsEntry("pushed_authorization_request_endpoint", testHostUrl + "/PAR_Auth");
        assertThat((List) openidProvider.get("client_registration_types_supported"))
            .containsExactlyInAnyOrder("automatic");
        assertThat((List) openidProvider.get("subject_types_supported")).hasSize(1)
            .isSubsetOf(List.of("pairwise", "public"));
        assertThat((List) openidProvider.get("response_types_supported")).containsExactlyInAnyOrder("code");
        assertThat((List) openidProvider.get("scopes_supported")).containsExactlyInAnyOrder("openid");
        assertThat((List) openidProvider.get("response_modes_supported")).containsExactlyInAnyOrder("query");
        assertThat((List) openidProvider.get("grant_types_supported")).containsExactlyInAnyOrder("authorization_code");
        assertThat((Boolean) openidProvider.get("require_pushed_authorization_requests")).isTrue();
        assertThat((List) openidProvider.get("token_endpoint_auth_methods_supported")).containsExactlyInAnyOrder(
            "private_key_jwt");
        assertThat((List) openidProvider.get("token_endpoint_auth_signing_alg_values_supported"))
            .containsExactlyInAnyOrder("ES256");
        assertThat(openidProvider.get("request_authentication_methods_supported"))
            .hasToString("{\"ar\":[\"none\"],\"par\":[\"private_key_jwt\"]}");
        assertThat((List) openidProvider.get("id_token_signing_alg_values_supported"))
            .containsExactlyInAnyOrder("ES256");
        assertThat((List) openidProvider.get("id_token_encryption_alg_values_supported"))
            .containsExactlyInAnyOrder("ECDH-ES");
        assertThat((List) openidProvider.get("id_token_encryption_enc_values_supported"))
            .containsExactlyInAnyOrder("A256GCM");

        // TODO: check content
        assertThat((List) openidProvider.get("claims_supported"))
            .withFailMessage("claims_supported is NULL").isNotNull();
        assertThat((List) openidProvider.get("claims_parameter_supported"))
            .withFailMessage("claims_parameter_supported is NULL").isNotNull();

        assertThat(openidProvider.get("user_type_supported").toString()).isIn(List.of("HCI", "HP", "IP"));
    }

    @SuppressWarnings("unchecked")
    @Test
    void entityStatement_FederationEntityClaimsContentCorrect() {
        final Map<String, Object> metadata = getInnerClaimMap(bodyClaims, "metadata");
        final Map<String, Object> federationEntity = Objects.requireNonNull(
            (Map<String, Object>) metadata.get("federation_entity"), "missing claim: federation_entity");

        assertThat(federationEntity).containsEntry("name", "idp4711");
        assertThat(federationEntity).containsEntry("contacts", "support@idp4711.de");
        assertThat(federationEntity).containsEntry("homepage_uri", "https://idp4711.de");
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

    /************************** FEDIDP_AUTH_ENDPOINT *****************/

    @Test
    void uriRequest_Response_ContentTypeCorrect() {
        final HttpResponse<String> resp = Unirest.get(testHostUrl + IdpConstants.FEDIDP_AUTH_ENDPOINT)
            .queryString("client_id", testHostUrl)
            .queryString("state", "state_Fachdienst")
            .queryString("redirect_uri", testHostUrl + "/AS")
            .queryString("code_challenge", "P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk")
            .queryString("code_challenge_method", "S256")
            .queryString("response_type", "code")
            .queryString("nonce", "42")
            .queryString("scope", "erp_sek_auth+openid")
            .queryString("acr_values", "TODO")
            .queryString("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
            .queryString("client_assertion", "TODO")
            .queryString("claims", "TODO")
            .asString();
        assertThat(resp.getHeaders().get(HttpHeaders.CONTENT_TYPE).get(0)).isEqualTo("application/json;charset=UTF-8");
    }

}
