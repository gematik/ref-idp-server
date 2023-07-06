/*
 *  Copyright 2023 gematik GmbH
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

package de.gematik.idp.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

import de.gematik.idp.brainPoolExtension.BrainpoolCurves;
import de.gematik.idp.client.data.DiscoveryDocumentResponse;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.tests.PkiKeyResolver;
import de.gematik.idp.token.JsonWebToken;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(PkiKeyResolver.class)
class IdpClientTest {

  private IdpClient idpClient;
  private AuthenticatorClient authenticatorClient;

  @BeforeEach
  public void init(final PkiIdentity ecc) {
    authenticatorClient = mock(AuthenticatorClient.class);
    doReturn(
            DiscoveryDocumentResponse.builder()
                .authorizationEndpoint("fdsa")
                .idpSig(ecc.getCertificate())
                .tokenEndpoint("fdsafds")
                .build())
        .when(authenticatorClient)
        .retrieveDiscoveryDocument(anyString(), any());

    doAnswer(call -> ((Function) call.getArguments()[1]).apply(null))
        .when(authenticatorClient)
        .doAuthorizationRequest(any(), any(), any());

    idpClient =
        IdpClient.builder()
            .discoveryDocumentUrl("fjnkdslaö")
            .authenticatorClient(authenticatorClient)
            .build();

    idpClient.initialize();
  }

  @Test
  void testBeforeCallback(final PkiIdentity ecc) {
    final AtomicInteger callCounter = new AtomicInteger(0);
    idpClient.setBeforeAuthorizationCallback(r -> callCounter.incrementAndGet());

    try {
      idpClient.login(ecc);
    } catch (final RuntimeException e) {
      // swallow
    }

    assertThat(callCounter.get()).isOne();
  }

  @Test
  void testBeforeFunction(final PkiIdentity ecc) {
    final AtomicInteger callCounter = new AtomicInteger(0);
    idpClient.setBeforeAuthorizationMapper(
        r -> {
          callCounter.incrementAndGet();
          return r;
        });

    try {
      idpClient.login(ecc);
    } catch (final RuntimeException e) {
      // swallow
    }

    assertThat(callCounter.get()).isOne();
  }

  @SneakyThrows
  @Test
  void pubkeyTest() {
    final ECPoint ecPoint =
        new ECPoint(
            new BigInteger(
                1, Base64.getUrlDecoder().decode("QLpJ_LpFx-6yJhsb4OvHwU1khLnviiOwYOvmf5clK7w")),
            new BigInteger(
                1, Base64.getUrlDecoder().decode("mHuknfNkoMmSbytt4br0YGihOixcmBKy80UfSLdXGe4")));
    final ECPublicKeySpec keySpec = new ECPublicKeySpec(ecPoint, BrainpoolCurves.BP256);

    final PublicKey pk = KeyFactory.getInstance("EC").generatePublic(keySpec);

    final String signedChallenge =
        "eyJ0eXAiOiJKV1QiLCJjdHkiOiJOSldUIiwieDVjIjpbIk1JSUMrakNDQXFDZ0F3SUJBZ0lIQXdBVGFsZGZWVEFLQmdncWhrak9QUVFEQWpDQmxqRUxNQWtHQTFVRUJoTUNSRVV4SHpBZEJnTlZCQW9NRm1kbGJXRjBhV3NnUjIxaVNDQk9UMVF0VmtGTVNVUXhSVEJEQmdOVkJBc01QRVZzWld0MGNtOXVhWE5qYUdVZ1IyVnpkVzVrYUdWcGRITnJZWEowWlMxRFFTQmtaWElnVkdWc1pXMWhkR2xyYVc1bWNtRnpkSEoxYTNSMWNqRWZNQjBHQTFVRUF3d1dSMFZOTGtWSFN5MURRVEV3SUZSRlUxUXRUMDVNV1RBZUZ3MHhPVEEwTURneU1qQXdNREJhRncweU5EQTBNRGd5TVRVNU5UbGFNSDB4Q3pBSkJnTlZCQVlUQWtSRk1SRXdEd1lEVlFRS0RBaEJUMHNnVUd4MWN6RVNNQkFHQTFVRUN3d0pNVEE1TlRBd09UWTVNUk13RVFZRFZRUUxEQXBZTVRFME5ESTROVE13TVE0d0RBWURWUVFFREFWR2RXTm9jekVOTUFzR0ExVUVLZ3dFU25WdVlURVRNQkVHQTFVRUF3d0tTblZ1WVNCR2RXTm9jekJhTUJRR0J5cUdTTTQ5QWdFR0NTc2tBd01DQ0FFQkJ3TkNBQVIxTmRyckk4b0tNaXYweHRVWEY1b3NTN3piRklLeEd0L0J3aXN1a1dvRUs1R3NKMWNDeUdFcENIMHNzOEp2RDRPQUhKUzhJTW0xL3JNNTlqbGlTKzFPbzRIdk1JSHNNQjBHQTFVZERnUVdCQlNjRVo1SDFVeFNNaFBzT2NXWmhHOFpRZVdodlRBTUJnTlZIUk1CQWY4RUFqQUFNREFHQlNza0NBTURCQ2N3SlRBak1DRXdIekFkTUJBTURsWmxjbk5wWTJobGNuUmxMeTF5TUFrR0J5cUNGQUJNQkRFd0h3WURWUjBqQkJnd0ZvQVVSTEZNQVZoVUh0elpONzdrc2o4cWJxUmNpUjB3SUFZRFZSMGdCQmt3RnpBS0JnZ3FnaFFBVEFTQkl6QUpCZ2NxZ2hRQVRBUkdNQTRHQTFVZER3RUIvd1FFQXdJSGdEQTRCZ2dyQmdFRkJRY0JBUVFzTUNvd0tBWUlLd1lCQlFVSE1BR0dIR2gwZEhBNkx5OWxhR05oTG1kbGJXRjBhV3N1WkdVdmIyTnpjQzh3Q2dZSUtvWkl6ajBFQXdJRFNBQXdSUUloQUlQSWNiR2pKUXh1VUdiSm1CVWltV3ZiVWk3bStTdVhZQmNSR0Z5WjBqSUpBaUFtMUlXSWZ2L2dOYy9XbXc0Wk8rNzMwUTlDNWRjY0ZuTWptdmJKZTdpNzVnPT0iXSwiYWxnIjoiQlAyNTZSMSJ9.eyJuand0IjoiZXlKaGJHY2lPaUpDVURJMU5sSXhJaXdpZEhsd0lqb2lTbGRVSWl3aWEybGtJam9pYzJWeWRtVnlTMlY1U1dSbGJuUnBkSGtpZlEuZXlKcGMzTWlPbTUxYkd3c0luSmxjM0J2Ym5ObFgzUjVjR1VpT2lKamIyUmxJaXdpYzI1aklqb2lhVFJDTVhCUExYUXRiSFZCYjJsSlRqRjFlbmN4V2xWdFdEZEJNbUZpZFVoUVYzWXdSa2hrVDFCclp5SXNJbU52WkdWZlkyaGhiR3hsYm1kbFgyMWxkR2h2WkNJNklsTXlOVFlpTENKMGIydGxibDkwZVhCbElqb2lZMmhoYkd4bGJtZGxJaXdpYm05dVkyVWlPaUp1YjI1alpWWmhiSFZsSWl3aVkyeHBaVzUwWDJsa0lqb2laMjl2SWl3aWMyTnZjR1VpT2lKdmNHVnVhV1FnWlMxeVpYcGxjSFFpTENKemRHRjBaU0k2SW1admJ5SXNJbkpsWkdseVpXTjBYM1Z5YVNJNkltSmhjaUlzSW1WNGNDSTZNVFkyTVRnME9ERXpPU3dpYVdGMElqb3hOall4T0RRM09UVTVMQ0pqYjJSbFgyTm9ZV3hzWlc1blpTSTZJbk5qYUcxaGNpSXNJbXAwYVNJNklqRTNNR0poTkRrek5qUXdaVEJrTldVaWZRLk9VMnF3UEVxdnpubXRHTkNCSGRBSTZPQ2R6cE5XLVNpOHhOTFpnbi0ya2NpNnNQd05UckRvdm1xZmptWnVxQ3NuVkI5TW42eWctZmFIV0Eya1ZuN1J3In0.ndsBrCrNq4C2rLi89dGT6blAYCzbpY5ZojTMvKvGtxBln7tEiCf-_8Za1Vjl6OUtEGrk_RtCWyojg3BqjIWHCw";
    final JsonWebToken jwt = new JsonWebToken(signedChallenge);

    Assertions.assertDoesNotThrow(() -> jwt.encryptAsNjwt(pk));
  }
}
