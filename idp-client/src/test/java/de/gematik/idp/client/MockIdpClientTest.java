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

package de.gematik.idp.client;

import static de.gematik.idp.field.ClaimName.ALGORITHM;
import static de.gematik.idp.field.ClaimName.ISSUER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.gematik.idp.brainPoolExtension.BrainpoolAlgorithmSuiteIdentifiers;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.tests.Afo;
import de.gematik.idp.tests.PkiKeyResolver;
import de.gematik.idp.token.JsonWebToken;
import java.util.Map;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.InvalidJwtSignatureException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(PkiKeyResolver.class)
public class MockIdpClientTest {

    private static final String URI_IDP_SERVER = "https://idp.zentral.idp.splitdns.ti-dienste.de";
    private static final String CLIENT_ID_E_REZEPT_APP = "eRezeptApp";
    private MockIdpClient mockIdpClient;
    private PkiIdentity serverIdentity;
    private PkiIdentity rsaClientIdentity;

    @BeforeEach
    public void startup(
        @PkiKeyResolver.Filename("ecc") final PkiIdentity serverIdentity,
        @PkiKeyResolver.Filename("C_CH_AUT_R2048") final PkiIdentity rsaClientIdentity) {
        this.serverIdentity = serverIdentity;
        this.rsaClientIdentity = rsaClientIdentity;

        mockIdpClient = MockIdpClient.builder()
            .serverIdentity(serverIdentity)
            .uriIdpServer(URI_IDP_SERVER)
            .clientId(CLIENT_ID_E_REZEPT_APP)
            .build();

        mockIdpClient.initialize();
    }

    @Test
    public void testLogin() {
        Assertions.assertDoesNotThrow(() -> mockIdpClient.login(rsaClientIdentity)
            .getAccessToken()
            .verify(mockIdpClient.getServerIdentity()
                .getCertificate()
                .getPublicKey()));
    }

    @Test
    public void verifyToken() {
        final IdpTokenResult authToken = mockIdpClient.login(rsaClientIdentity);
        authToken.getAccessToken().verify(mockIdpClient.getServerIdentity().getCertificate().getPublicKey());
    }

    @Test
    public void invalidSignatureTokens_verifyShouldFail() {
        final IdpTokenResult authToken = MockIdpClient.builder()
            .serverIdentity(serverIdentity)
            .produceTokensWithInvalidSignature(true)
            .clientId(CLIENT_ID_E_REZEPT_APP)
            .build()
            .initialize()
            .login(rsaClientIdentity);

        assertThatThrownBy(() -> authToken.getAccessToken()
            .verify(mockIdpClient.getServerIdentity().getCertificate().getPublicKey()))
            .hasCauseInstanceOf(InvalidJwtSignatureException.class);
    }

    @Test
    public void loginWithoutInitialize_shouldGiveInitializationError() {
        final MockIdpClient idpClient = MockIdpClient.builder()
            .serverIdentity(serverIdentity)
            .build();

        assertThatThrownBy(() -> idpClient.login(rsaClientIdentity))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("initialize()");
    }

    @Test
    public void expiredTokens_verifyShouldFail() {
        final IdpTokenResult authToken = MockIdpClient.builder()
            .serverIdentity(serverIdentity)
            .produceOnlyExpiredTokens(true)
            .clientId(CLIENT_ID_E_REZEPT_APP)
            .build()
            .initialize()
            .login(rsaClientIdentity);

        assertThatThrownBy(() -> authToken.getAccessToken().verify(
            mockIdpClient.getServerIdentity().getCertificate().getPublicKey()))
            .hasCauseInstanceOf(InvalidJwtException.class);
    }

    @Test
    public void verifyTokenWithEcClientCertificate(
        @PkiKeyResolver.Filename("833621999741600_c.hci.aut-apo-ecc.p12") final PkiIdentity eccClientIdentity) {
        Assertions.assertDoesNotThrow(() -> mockIdpClient.login(eccClientIdentity)
            .getAccessToken()
            .verify(mockIdpClient.getServerIdentity()
                .getCertificate()
                .getPublicKey()));
    }

    @Test
    public void verifyServerSignatureEcc() {
        assertThat(mockIdpClient.login(rsaClientIdentity)
            .getAccessToken()
            .getHeaderClaims())
            .containsEntry(ALGORITHM.getJoseName(), BrainpoolAlgorithmSuiteIdentifiers.BRAINPOOL256_USING_SHA256);
    }

    @Test
    public void verifyServerSignatureRsa(@PkiKeyResolver.Filename("rsa") final PkiIdentity rsaIdentity) {
        mockIdpClient = MockIdpClient.builder()
            .serverIdentity(rsaIdentity)
            .uriIdpServer(URI_IDP_SERVER)
            .clientId(CLIENT_ID_E_REZEPT_APP)
            .build();
        mockIdpClient.initialize();

        assertThat(mockIdpClient.login(rsaClientIdentity)
            .getAccessToken()
            .getHeaderClaims())
            .containsEntry(ALGORITHM.getJoseName(), "PS256");
    }

    @Test
    public void resignTokenWithNewBodyClaim_ShouldContainNewClaim() {
        final JsonWebToken jwt = mockIdpClient.login(rsaClientIdentity)
            .getAccessToken();

        final Map<String, Object> bodyClaims = jwt.getBodyClaims();
        bodyClaims.put("foo", "bar");

        final JsonWebToken resignedAccessToken = mockIdpClient.resignToken(
            jwt.getHeaderClaims(),
            bodyClaims,
            jwt.getExpiresAt());

        assertThat(resignedAccessToken.getBodyClaims())
            .containsEntry("foo", "bar");
    }

    @Test
    public void resignTokenWithNewHeaderClaim_ShouldContainNewHeaderClaim() {
        final JsonWebToken jwt = mockIdpClient.login(rsaClientIdentity)
            .getAccessToken();

        final Map<String, Object> jwtHeaderClaims = jwt.getHeaderClaims();
        final Map<String, Object> jwtBodyClaims = jwt.getBodyClaims();

        jwtHeaderClaims.put("foo", "bar");

        final JsonWebToken resignedAccessToken = mockIdpClient.resignToken(
            jwtHeaderClaims,
            jwtBodyClaims,
            jwt.getExpiresAt());

        assertThat(resignedAccessToken.getHeaderClaims())
            .containsEntry("foo", "bar");
    }

    @Test
    @Afo("A_20297-01")
    public void verifyAccessTokenIssClaim() {
        final JsonWebToken jwt = mockIdpClient.login(rsaClientIdentity).getAccessToken();
        final Map<String, Object> bodyClaims = jwt.getBodyClaims();
        assertThat(bodyClaims.get(ISSUER.getJoseName()))
            .as("AccessToken ISS claim")
            .isEqualTo(URI_IDP_SERVER);
    }
}
