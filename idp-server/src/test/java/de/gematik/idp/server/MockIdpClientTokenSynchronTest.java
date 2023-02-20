/*
 * Copyright (c) 2023 gematik GmbH
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

import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.TestConstants;
import de.gematik.idp.client.IdpClient;
import de.gematik.idp.client.IdpTokenResult;
import de.gematik.idp.client.MockIdpClient;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.tests.PkiKeyResolver;
import de.gematik.idp.token.JsonWebToken;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
@ExtendWith(PkiKeyResolver.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class MockIdpClientTokenSynchronTest {

  private static final String URI_MOCK_IDP_SERVER =
      "https://idp.zentral.idp.splitdns.ti-dienste.de";
  private static final Set<String> VOLATILE_CLAIMS =
      Set.of(
          ClaimName.EXPIRES_AT.getJoseName(),
          ClaimName.ISSUED_AT.getJoseName(),
          ClaimName.AUTH_TIME.getJoseName(),
          ClaimName.SUBJECT.getJoseName(),
          ClaimName.SCOPE.getJoseName(),
          ClaimName.AUDIENCE.getJoseName(),
          ClaimName.JWT_ID.getJoseName());
  private IdpClient idpClient;
  private PkiIdentity egkUserIdentity;
  @LocalServerPort private int localServerPort;
  private MockIdpClient mockIdpClient;
  private PkiIdentity clientIdentity;
  private PkiIdentity serverIdentity;

  @BeforeEach
  public void startup(
      @PkiKeyResolver.Filename("109500969_X114428530_c.ch.aut-ecc")
          final PkiIdentity clientIdentity,
      @PkiKeyResolver.Filename("ecc") final PkiIdentity serverIdentity) {
    idpClient =
        IdpClient.builder()
            .clientId(TestConstants.CLIENT_ID_E_REZEPT_APP)
            .discoveryDocumentUrl(
                "http://localhost:" + localServerPort + IdpConstants.DISCOVERY_DOCUMENT_ENDPOINT)
            .redirectUrl(TestConstants.REDIRECT_URI_E_REZEPT_APP)
            .build();
    idpClient.initialize();

    egkUserIdentity =
        PkiIdentity.builder()
            .certificate(clientIdentity.getCertificate())
            .privateKey(clientIdentity.getPrivateKey())
            .build();

    this.clientIdentity = clientIdentity;
    this.serverIdentity = serverIdentity;
    mockIdpClient =
        MockIdpClient.builder()
            .serverIdentity(serverIdentity)
            .uriIdpServer(URI_MOCK_IDP_SERVER)
            .clientId(TestConstants.CLIENT_ID_E_REZEPT_APP)
            .build()
            .initialize();
  }

  @Test
  void accesstoken_fromMockIdpClient_shouldHaveSameClaims_As_fromIdpClient_byLogin() {
    final JsonWebToken accessTokenMockIdpClient =
        mockIdpClient.login(clientIdentity).getAccessToken();

    final JsonWebToken accessTokenIdpClient = idpClient.login(egkUserIdentity).getAccessToken();

    compareClaimMaps(
        accessTokenMockIdpClient.getHeaderClaims(), accessTokenIdpClient.getHeaderClaims());
    compareClaimMaps(
        accessTokenMockIdpClient.getBodyClaims(), accessTokenIdpClient.getBodyClaims());
  }

  @Test
  void accesstoken_fromMockIdpClient_shouldHaveSameClaims_As_fromIdpClient_bySetTokenExpired() {
    final JsonWebToken accessTokenMockIdpClient =
        MockIdpClient.builder()
            .serverIdentity(serverIdentity)
            .produceOnlyExpiredTokens(true)
            .clientId(TestConstants.CLIENT_ID_E_REZEPT_APP)
            .build()
            .initialize()
            .login(clientIdentity)
            .getAccessToken();

    final JsonWebToken accessTokenIdpClient = idpClient.login(egkUserIdentity).getAccessToken();

    compareClaimMaps(
        accessTokenMockIdpClient.getHeaderClaims(), accessTokenIdpClient.getHeaderClaims());
    compareClaimMaps(
        accessTokenMockIdpClient.getBodyClaims(), accessTokenIdpClient.getBodyClaims());
  }

  @Test
  void
      accesstoken_fromMockIdpClient_shouldHaveSameClaims_As_fromIdpClient_bySetTokenInvalidSignature() {
    final JsonWebToken accessTokenMockIdpClient =
        MockIdpClient.builder()
            .serverIdentity(serverIdentity)
            .produceTokensWithInvalidSignature(true)
            .clientId(TestConstants.CLIENT_ID_E_REZEPT_APP)
            .build()
            .initialize()
            .login(clientIdentity)
            .getAccessToken();

    final JsonWebToken accessTokenIdpClient = idpClient.login(egkUserIdentity).getAccessToken();

    compareClaimMaps(
        accessTokenMockIdpClient.getHeaderClaims(), accessTokenIdpClient.getHeaderClaims());
    compareClaimMaps(
        accessTokenMockIdpClient.getBodyClaims(), accessTokenIdpClient.getBodyClaims());
  }

  @Test
  void accesstoken_fromMockIdpClient_shouldHaveSameClaims_As_fromIdpClient_byResign() {
    final JsonWebToken jwt = mockIdpClient.login(clientIdentity).getAccessToken();
    final Map<String, Object> bodyClaims = jwt.getBodyClaims();
    final Map<String, Object> bodyClaimsCloned =
        new HashMap<>() {
          private static final long serialVersionUID = -6148576016469952778L;

          {
            putAll(bodyClaims);
          }
        };
    bodyClaims.put("foo", "bar");
    final JsonWebToken resignedAccessToken =
        mockIdpClient.resignToken(jwt.getHeaderClaims(), bodyClaims, jwt.getExpiresAtBody());

    final IdpTokenResult tokenResponse = idpClient.login(egkUserIdentity);
    final JsonWebToken accessTokenIdpClient = tokenResponse.getAccessToken();

    compareClaimMaps(resignedAccessToken.getHeaderClaims(), accessTokenIdpClient.getHeaderClaims());
    compareClaimMaps(bodyClaimsCloned, accessTokenIdpClient.getBodyClaims());
    assertThat(resignedAccessToken.getBodyClaims())
        .hasSize(accessTokenIdpClient.getBodyClaims().size() + 1);
  }

  private Map<String, Object> filterVolatileClaims(final Map<String, Object> claimsMap) {
    return claimsMap.entrySet().stream()
        .filter(entry -> !VOLATILE_CLAIMS.contains(entry.getKey()))
        .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
  }

  private void compareClaimMaps(
      final Map<String, Object> mockClientClaims, final Map<String, Object> referenceClientClaims) {
    assertThat(filterVolatileClaims(referenceClientClaims))
        .as("claims non-mock: \n" + referenceClientClaims + "\nclaims mock: \n" + mockClientClaims)
        .containsExactlyEntriesOf(filterVolatileClaims(mockClientClaims));
    if (referenceClientClaims.containsKey(ClaimName.SCOPE.getJoseName())) {
      assertThat(mockClientClaims.get(ClaimName.SCOPE.getJoseName()).toString().split(" "))
          .containsExactlyInAnyOrder(
              referenceClientClaims.get(ClaimName.SCOPE.getJoseName()).toString().split(" "));
    }
  }
}
