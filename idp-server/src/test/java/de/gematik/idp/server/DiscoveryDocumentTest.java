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

import static de.gematik.idp.IdpConstants.BASIC_AUTHORIZATION_ENDPOINT;
import static de.gematik.idp.IdpConstants.DISCOVERY_DOCUMENT_ENDPOINT;
import static de.gematik.idp.IdpConstants.TOKEN_ENDPOINT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.server.controllers.IdpKey;
import de.gematik.idp.tests.Afo;
import de.gematik.idp.tests.Remark;
import de.gematik.idp.tests.Rfc;
import de.gematik.idp.token.JsonWebToken;
import de.gematik.idp.token.TokenClaimExtraction;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
import kong.unirest.UnirestException;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class DiscoveryDocumentTest {

    private static final String CONFIGURED_SERVER_URL = "foobarschmar";
    private static final String CONFIGURED_ISSUER_URL = "issuerUrl";
    @LocalServerPort
    private int localServerPort;
    private String testHostUrl;
    @Autowired
    private IdpKey discSig;
    @MockBean
    private ServerUrlService serverUrlService;

    @BeforeEach
    public void setUpLocalHostUrl() {
        testHostUrl = "http://localhost:" + localServerPort;
        doReturn(CONFIGURED_SERVER_URL)
            .when(serverUrlService).determineServerUrl(any());
        doReturn(CONFIGURED_ISSUER_URL)
            .when(serverUrlService).getIssuerUrl();
    }

    @Test
    void testLogin() throws UnirestException {
        final HttpResponse httpResponse = retrieveDiscoveryDocument();

        assertThat(httpResponse.isSuccess()).isTrue();
    }

    @Test
    void testHttpCacheHeader() throws UnirestException {
        final HttpResponse httpResponse = retrieveDiscoveryDocument();
        assertThat(httpResponse.getHeaders().get("Cache-Control")).isEqualTo(Arrays.asList("max-age=300"));
    }

    @Afo("A_20458")
    @Remark("Die Afo gibt keine vollstaendige Liste der zu verwendenden Attribute. Das ergibt sich mit dem Rfc und anderen Abschnitten der Spec")
    @Rfc("https://openid.net/specs/openid-connect-discovery-1_0.html")
    @Test
    void testContainsMandatoryAttributes() throws UnirestException {
        final HttpResponse<String> httpResponse = retrieveDiscoveryDocument();

        assertThat(extractClaimMapFromResponse(httpResponse))
            .containsOnlyKeys("issuer",
                "authorization_endpoint",
                "auth_pair_endpoint",
                "sso_endpoint",
                "uri_pair",
                "token_endpoint",
                "jwks_uri",
                "subject_types_supported",
                "id_token_signing_alg_values_supported",
                "response_types_supported",
                "scopes_supported",
                "response_modes_supported",
                "grant_types_supported",
                "acr_values_supported",
                "token_endpoint_auth_methods_supported",
                "exp",
                "iat",
                "uri_puk_idp_enc",
                "uri_puk_idp_sig",
                "uri_disc",
                "code_challenge_methods_supported",
                "kk_app_list_uri",
                "third_party_authorization_endpoint");
    }

    @Remark("Ruecksprache mit Tommy in IDP-123, wir verwenden pairwise")
    @Rfc("https://openid.net/specs/openid-connect-discovery-1_0.html")
    @Test
    void testValueForSubjectTypesSupported() throws UnirestException {
        final List<String> subjectTypesSupported = (List) extractClaimMapFromResponse(retrieveDiscoveryDocument())
            .get("subject_types_supported");
        assertThat(subjectTypesSupported)
            .containsExactlyInAnyOrder("pairwise");
    }

    @Test
    @Rfc("rfc 6749 section 3.1.1 and https://openid.net/specs/openid-connect-discovery-1_0.html")
    @Remark("wir machen den authorizationCodeFlow, daher hier der Wert code")
    void testValueForResponseTypesSupported() throws UnirestException {
        final List<String> responseTypesSupported = (List) extractClaimMapFromResponse(retrieveDiscoveryDocument())
            .get("response_types_supported");
        assertThat(responseTypesSupported).containsExactlyInAnyOrder("code");
    }

    @Test
    @Rfc("https://openid.net/specs/openid-connect-discovery-1_0.html")
    @Remark("OIDC verlangt den scope openid, e-rezept ergibt sich aus Beispielen in der Spec")
    void testValueForScopesSupported() throws UnirestException {
        final List<String> scopesSupported = (List) extractClaimMapFromResponse(retrieveDiscoveryDocument())
            .get("scopes_supported");
        assertThat(scopesSupported).containsExactlyInAnyOrder("openid", "e-rezept", "pairing", "authenticator-dev");
    }

    @Test
    @Remark("Ruecksprache mit der Spec hat zu BP256R1 gefuehrt, weil es zuvor keinen Bezeichner fuer ECDSA mit brainpool256r1 bei JWS gab")
    void testValueForIdTokenSigningAlgValuesSupported() throws UnirestException {
        final List<String> responseTypesSupported = (List) extractClaimMapFromResponse(retrieveDiscoveryDocument())
            .get("id_token_signing_alg_values_supported");
        assertThat(responseTypesSupported).containsExactlyInAnyOrder("BP256R1");
    }

    @Test
    @Rfc("https://openid.net/specs/openid-connect-discovery-1_0.html")
    @Remark("wir haben nur den authorization_code grant type")
    void testValueForGrantTypesSupported() throws UnirestException {
        final List<String> grantTypesSupported = (List) extractClaimMapFromResponse(retrieveDiscoveryDocument())
            .get("grant_types_supported");
        assertThat(grantTypesSupported).containsExactlyInAnyOrder("authorization_code");
    }

    @Test
    @Rfc("https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html")
    void testValueForResponseModesSupported() throws UnirestException {
        final List<String> responseModesSupported = (List) extractClaimMapFromResponse(retrieveDiscoveryDocument())
            .get("response_modes_supported");

        assertThat(responseModesSupported).containsExactlyInAnyOrder("query");
    }

    @Test
    @Remark("Ruecksprache mit Tommy in IDP-123, keine Ahnung, woher man das sonst wissen kann")
    void testValueForAcrValuesSupported() throws UnirestException {
        final List<String> acrValuesSupported = (List<String>) retrieveAndParseDiscoveryDocument()
            .getBodyClaim(ClaimName.ACR_VALUES_SUPPORTED).get();

        assertThat(acrValuesSupported).containsExactlyInAnyOrder("gematik-ehealth-loa-high");
    }

    @Test
    @Rfc("https://openid.net/specs/openid-connect-discovery-1_0.html")
    @Remark("bei uns findet keine Auth am Token Endpoint statt, daher none, Parameter vorhanden weil Defaultwert HTTP-Basic-Auth wäre")
    void testValueForTokenEndpointAuthMethodsValuesSupported() throws UnirestException {
        final List<String> tokenEndpointAuthMethodsSupported = (List) extractClaimMapFromResponse(
            retrieveDiscoveryDocument())
            .get("token_endpoint_auth_methods_supported");
        assertThat(tokenEndpointAuthMethodsSupported).containsExactlyInAnyOrder("none");
    }

    @Test
    @Afo("A_20458")
    @Rfc("rfc8414 section 2")
    void testValueForIssuer() throws UnirestException {
        final String issuer = (String) extractClaimMapFromResponse(retrieveDiscoveryDocument())
            .get("issuer");
        assertThat(issuer).isEqualTo(CONFIGURED_ISSUER_URL);
    }

    @Test
    @Afo("A_20458")
    @Remark("nach ruecksprache mit Tommy wird nicht die Bezeichnung aus der afo, sondern die von oidc vorgesehene verwendet")
    void testValueForAuthorizationEndpoint() throws UnirestException {
        final String authorizationEndpointValue = extractClaimMapFromResponse(retrieveDiscoveryDocument())
            .get("authorization_endpoint").toString();
        assertThat(authorizationEndpointValue)
            .isEqualTo(CONFIGURED_SERVER_URL + BASIC_AUTHORIZATION_ENDPOINT);
    }

    @Test
    @Afo("A_20458")
    @Remark("nach ruecksprache mit Tommy wird nicht die Bezeichnung aus der afo, sondern die von oidc vorgesehene verwendet")
    void testValueForTokenEndpoint() throws UnirestException {
        final String tokenEndpointValue = extractClaimMapFromResponse(retrieveDiscoveryDocument())
            .get("token_endpoint").toString();
        assertThat(tokenEndpointValue)
            .isEqualTo(CONFIGURED_SERVER_URL + TOKEN_ENDPOINT);
    }

    @Test
    @Afo("A_20458")
    void testValueForJwksUri() throws UnirestException {
        assertThat(retrieveAndParseDiscoveryDocument()
            .getStringBodyClaim(ClaimName.JWKS_URI)
            .get())
            .startsWith(CONFIGURED_SERVER_URL);
    }

    @Test
    @Afo("A_20591")
    @Remark("Laut Aussage von Gerriet muss das DiscoveryDocument als JWS signiert werden.")
    void testDiscoveryDocumentSignature() throws UnirestException {
        retrieveAndParseDiscoveryDocument()
            .verify(discSig.getIdentity().getCertificate().getPublicKey());
    }

    @Test
    @Afo("A_20691")
    void testValueExpiration() throws UnirestException {
        assertThat(retrieveAndParseDiscoveryDocument().getExpiresAtBody())
            .isBetween(ZonedDateTime.now().minusMinutes(1).plusHours(24),
                ZonedDateTime.now().plusHours(24));
    }

    @Test
    void testValueIssuedAt() throws UnirestException {
        assertThat(retrieveAndParseDiscoveryDocument().getIssuedAt())
            .isBetween(ZonedDateTime.now().minusMinutes(1), ZonedDateTime.now());
    }

    @Remark("Nach RFC 8414, wir verwenden S256, Section 2")
    @Rfc("https://tools.ietf.org/html/rfc8414")
    @Test
    void testValueForCodeChallengeMethodsSupported() throws UnirestException {
        final List<String> codeChallengeMethodsSupported = (List) extractClaimMapFromResponse(
            retrieveDiscoveryDocument())
            .get("code_challenge_methods_supported");
        assertThat(codeChallengeMethodsSupported)
            .containsExactlyInAnyOrder("S256");
    }

    @Test
    @Afo("A_20591")
    void testDiscoveryDocumentSigningCertificateReference() throws UnirestException {
        assertThat(retrieveAndParseDiscoveryDocument()
            .getHeaderClaim(ClaimName.X509_CERTIFICATE_CHAIN)).isPresent();
    }

    @Test
    void postShouldGive405() throws UnirestException {
        assertThat(Unirest.post(testHostUrl + DISCOVERY_DOCUMENT_ENDPOINT)
            .asString().getStatus())
            .isEqualTo(HttpStatus.SC_METHOD_NOT_ALLOWED);
    }

    private Map<String, Object> extractClaimMapFromResponse(final HttpResponse<String> httpResponse) {
        return TokenClaimExtraction.extractClaimsFromJwtBody(httpResponse.getBody());
    }

    private JsonWebToken retrieveAndParseDiscoveryDocument() {
        return new JsonWebToken(retrieveDiscoveryDocument().getBody());
    }

    private HttpResponse<String> retrieveDiscoveryDocument() {
        return Unirest.get(testHostUrl + DISCOVERY_DOCUMENT_ENDPOINT)
            .asString();
    }
}
