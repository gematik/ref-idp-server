/*
 *  Copyright 2024 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.idp.server;

import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.TestConstants;
import de.gematik.idp.client.AuthorizationCodeResult;
import de.gematik.idp.client.IdpClient;
import de.gematik.idp.crypto.Nonce;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.field.ClientUtilities;
import de.gematik.idp.tests.PkiKeyResolver;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

@ExtendWith(PkiKeyResolver.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class EpaClientTest {
  private IdpClient idpClient;
  private PkiIdentity smcbIdentity;
  @LocalServerPort private int localServerPort;

  @BeforeEach
  public void startup(
      @PkiKeyResolver.Filename("833621999741600-2_c.hci.aut-apo-ecc")
          final PkiIdentity smcbIdentity) {
    this.smcbIdentity = smcbIdentity;

    final Set<String> epaScopes = new HashSet<>();
    epaScopes.add("epa");
    epaScopes.add("openid");

    idpClient =
        IdpClient.builder()
            .clientId(TestConstants.CLIENT_ID_E_REZEPT_APP)
            .discoveryDocumentUrl("http://localhost:" + localServerPort + "/discoveryDocument")
            .redirectUrl(TestConstants.REDIRECT_URI_E_REZEPT_APP)
            .scopes(epaScopes)
            .build();

    idpClient.initialize();
  }

  @Test
  void verifyLogin() {
    final String nonce = Nonce.getNonceAsBase64UrlEncodedString(24);
    final String codeChallenge =
        ClientUtilities.generateCodeChallenge(ClientUtilities.generateCodeVerifier());
    final String state = "state";

    final AuthorizationCodeResult authorizationCodeResult =
        idpClient.login(smcbIdentity, codeChallenge, state, nonce);

    assertThat(authorizationCodeResult.getState()).isEqualTo(state);
    assertThat(authorizationCodeResult.getRedirectUri()).contains("http");
    assertThat(authorizationCodeResult.getAuthorizationCode()).isNotEmpty();
  }
}
