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

import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.client.IdpClient;
import de.gematik.idp.client.IdpTokenResult;
import de.gematik.idp.client.MockIdpClient;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.server.configuration.IdpConfiguration;
import de.gematik.idp.tests.PkiKeyResolver;
import de.gematik.idp.token.JsonWebToken;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
@ExtendWith(PkiKeyResolver.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class MockIdpClientTokenSynchronTest {

    private static final String URI_MOCK_IDP_SERVER = "https://idp.zentral.idp.splitdns.ti-dienste.de";
    private static final List<String> VOLATILE_CLAIMS = new ArrayList<>() {
        {
            add(ClaimName.EXPIRES_AT.getJoseName());
            add(ClaimName.ISSUED_AT.getJoseName());
            add(ClaimName.AUTH_TIME.getJoseName());
            add(ClaimName.SUBJECT.getJoseName());
            add(ClaimName.JWT_ID.getJoseName());
        }
    };
    @Autowired
    private IdpConfiguration idpConfiguration;
    private IdpClient idpClient;
    private PkiIdentity egkUserIdentity;
    @LocalServerPort
    private int localServerPort;
    private MockIdpClient mockIdpClient;
    private PkiIdentity clientIdentity;
    private PkiIdentity serverIdentity;

    private static String sortedScope(final Object scope) {
        final String[] scopeArray = Stream.of(scope).map(String.class::cast).map(a -> a.split(" ")).findAny()
            .orElse(new String[]{});
        return Arrays.asList(scopeArray).stream().sorted().collect(Collectors.joining(" "));
    }

    @BeforeEach
    public void startup(@PkiKeyResolver.Filename("109500969_X114428530_c.ch.aut-ecc") final PkiIdentity clientIdentity,
        @PkiKeyResolver.Filename("ecc") final PkiIdentity serverIdentity) {
        idpClient = IdpClient.builder()
            .clientId(IdpConstants.CLIENT_ID)
            .discoveryDocumentUrl("http://localhost:" + localServerPort + IdpConstants.DISCOVERY_DOCUMENT_ENDPOINT)
            .redirectUrl(idpConfiguration.getRedirectUri())
            .build();
        idpClient.initialize();

        egkUserIdentity = PkiIdentity.builder()
            .certificate(clientIdentity.getCertificate())
            .privateKey(clientIdentity.getPrivateKey())
            .build();

        this.clientIdentity = clientIdentity;
        this.serverIdentity = serverIdentity;
        mockIdpClient = MockIdpClient.builder()
            .serverIdentity(serverIdentity)
            .uriIdpServer(URI_MOCK_IDP_SERVER)
            .clientId(IdpConstants.CLIENT_ID)
            .build().initialize();
    }

    @Test
    public void accesstoken_fromMockIdpClient_shouldHaveSameClaims_As_fromIdpClient_byLogin() {
        final JsonWebToken accessTokenMockIdpClient = mockIdpClient.login(clientIdentity).getAccessToken();

        final JsonWebToken accessTokenIdpClient = idpClient.login(egkUserIdentity).getAccessToken();

        compareClaimMaps(accessTokenMockIdpClient.getHeaderClaims(), accessTokenIdpClient.getHeaderClaims());
        compareClaimMaps(accessTokenMockIdpClient.getBodyClaims(), accessTokenIdpClient.getBodyClaims());
    }

    @Test
    public void accesstoken_fromMockIdpClient_shouldHaveSameClaims_As_fromIdpClient_bySetTokenExpired() {
        final JsonWebToken accessTokenMockIdpClient = MockIdpClient.builder()
            .serverIdentity(serverIdentity)
            .produceOnlyExpiredTokens(true)
            .clientId(IdpConstants.CLIENT_ID)
            .build()
            .initialize()
            .login(clientIdentity)
            .getAccessToken();

        final JsonWebToken accessTokenIdpClient = idpClient.login(egkUserIdentity).getAccessToken();

        compareClaimMaps(accessTokenMockIdpClient.getHeaderClaims(), accessTokenIdpClient.getHeaderClaims());
        compareClaimMaps(accessTokenMockIdpClient.getBodyClaims(), accessTokenIdpClient.getBodyClaims());
    }

    @Test
    public void accesstoken_fromMockIdpClient_shouldHaveSameClaims_As_fromIdpClient_bySetTokenInvalidSignature() {
        final JsonWebToken accessTokenMockIdpClient = MockIdpClient.builder()
            .serverIdentity(serverIdentity)
            .produceTokensWithInvalidSignature(true)
            .clientId(IdpConstants.CLIENT_ID)
            .build()
            .initialize()
            .login(clientIdentity)
            .getAccessToken();

        final JsonWebToken accessTokenIdpClient = idpClient.login(egkUserIdentity).getAccessToken();

        compareClaimMaps(accessTokenMockIdpClient.getHeaderClaims(), accessTokenIdpClient.getHeaderClaims());
        compareClaimMaps(accessTokenMockIdpClient.getBodyClaims(), accessTokenIdpClient.getBodyClaims());
    }

    @Test
    public void accesstoken_fromMockIdpClient_shouldHaveSameClaims_As_fromIdpClient_byResign() {
        final JsonWebToken jwt = mockIdpClient.login(clientIdentity).getAccessToken();
        final Map<String, Object> bodyClaims = jwt.getBodyClaims();
        final Map<String, Object> bodyClaimsCloned = new HashMap<>() {
            {
                putAll(bodyClaims);
            }
        };
        bodyClaims.put("foo", "bar");
        final JsonWebToken resignedAccessToken = mockIdpClient.resignToken(jwt.getHeaderClaims(),
            bodyClaims,
            jwt.getExpiresAt());

        final IdpTokenResult tokenResponse = idpClient.login(egkUserIdentity);
        final JsonWebToken accessTokenIdpClient = tokenResponse.getAccessToken();

        compareClaimMaps(resignedAccessToken.getHeaderClaims(), accessTokenIdpClient.getHeaderClaims());
        compareClaimMaps(bodyClaimsCloned, accessTokenIdpClient.getBodyClaims());
        assertThat(resignedAccessToken.getBodyClaims().size())
            .isEqualTo(accessTokenIdpClient.getBodyClaims().size() + 1);
    }

    private void compareClaimMaps(final Map<String, Object> mockClientClaims,
        final Map<String, Object> referenceClientClaims) {
        assertThat(referenceClientClaims.keySet())
            .as("claims non-mock: \n" + referenceClientClaims + "\nclaims mock: \n" + mockClientClaims)
            .containsExactlyInAnyOrder(mockClientClaims.keySet().toArray(new String[mockClientClaims.size()]));
        assertThat(mockClientClaims.keySet())
            .containsExactlyInAnyOrder(
                referenceClientClaims.keySet().toArray(new String[referenceClientClaims.size()]));

        mockClientClaims.entrySet().stream().forEach(entry -> {
            assertThat(referenceClientClaims).containsKey(entry.getKey());
            compareClaimValue(entry.getKey(), entry.getValue(), referenceClientClaims);
        });
    }

    private void compareClaimValue(final String key, final Object value,
        final Map<String, Object> referenceClientClaims) {
        if (key.equals(ClaimName.SCOPE.getJoseName())) {
            assertThat(sortedScope(value))
                .isEqualTo(sortedScope(referenceClientClaims.get(key)));
        } else if (!VOLATILE_CLAIMS.contains(key)) {
            assertThat(referenceClientClaims).containsValue(value);
        }
    }
}
