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

package de.gematik.idp.server.data;

import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.brainPoolExtension.BrainpoolCurves;
import de.gematik.idp.crypto.EcKeyUtility;
import de.gematik.idp.data.IdpEccKeyDescriptor;
import de.gematik.idp.data.IdpJwksDocument;
import de.gematik.idp.data.IdpKeyDescriptor;
import de.gematik.idp.server.controllers.IdpKey;
import de.gematik.idp.token.JsonWebToken;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;
import lombok.SneakyThrows;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class EccTest {

  @Autowired IdpKey idpEnc;
  @Autowired IdpKey idpSig;

  @Test
  void encryptWithPubKeyFromXYCoords() {
    final var ecPoint =
        new ECPoint(
            new BigInteger(
                1, Base64.getUrlDecoder().decode("QLpJ_LpFx-6yJhsb4OvHwU1khLnviiOwYOvmf5clK7w")),
            new BigInteger(
                1, Base64.getUrlDecoder().decode("mHuknfNkoMmSbytt4br0YGihOixcmBKy80UfSLdXGe4")));
    final ECPublicKeySpec keySpec = new ECPublicKeySpec(ecPoint, BrainpoolCurves.BP256);

    final PublicKey pk =
        Assertions.assertDoesNotThrow(
            () ->
                KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME)
                    .generatePublic(keySpec));
  }

  @SneakyThrows
  @Test
  void pubKeyToJsonToPubKeyAndEncrypt() {
    final List<IdpKey> identities = new ArrayList<>();
    identities.add(idpSig);
    identities.add(idpEnc);
    final IdpJwksDocument idpJwksDocument =
        IdpJwksDocument.builder()
            .keys(
                identities.stream()
                    .map(
                        idpKey -> {
                          final IdpKeyDescriptor keyDesc =
                              IdpKeyDescriptor.constructFromX509Certificate(
                                  idpKey.getIdentity().getCertificate(),
                                  idpKey.getKeyId(),
                                  idpKey
                                      .getKeyId()
                                      .map(id -> !id.equals("puk_idp_enc"))
                                      .orElse(false));
                          keyDesc.setPublicKeyUse(idpKey.getUse().orElse(null));
                          return keyDesc;
                        })
                    .collect(Collectors.toList()))
            .build();

    final IdpEccKeyDescriptor idpEncDesc = (IdpEccKeyDescriptor) idpJwksDocument.getKeys().get(1);

    final ECPoint ecPoint =
        new ECPoint(
            new BigInteger(1, Base64.getUrlDecoder().decode(idpEncDesc.getEccPointXValue())),
            new BigInteger(1, Base64.getUrlDecoder().decode(idpEncDesc.getEccPointYValue())));

    final ECPublicKeySpec keySpec = new ECPublicKeySpec(ecPoint, BrainpoolCurves.BP256);
    final PublicKey pk =
        KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME).generatePublic(keySpec);

    final String signedChallenge =
        "eyJ0eXAiOiJKV1QiLCJjdHkiOiJOSldUIiwieDVjIjpbIk1JSUMrakNDQXFDZ0F3SUJBZ0lIQXdBVGFsZGZWVEFLQmdncWhrak9QUVFEQWpDQmxqRUxNQWtHQTFVRUJoTUNSRVV4SHpBZEJnTlZCQW9NRm1kbGJXRjBhV3NnUjIxaVNDQk9UMVF0VmtGTVNVUXhSVEJEQmdOVkJBc01QRVZzWld0MGNtOXVhWE5qYUdVZ1IyVnpkVzVrYUdWcGRITnJZWEowWlMxRFFTQmtaWElnVkdWc1pXMWhkR2xyYVc1bWNtRnpkSEoxYTNSMWNqRWZNQjBHQTFVRUF3d1dSMFZOTGtWSFN5MURRVEV3SUZSRlUxUXRUMDVNV1RBZUZ3MHhPVEEwTURneU1qQXdNREJhRncweU5EQTBNRGd5TVRVNU5UbGFNSDB4Q3pBSkJnTlZCQVlUQWtSRk1SRXdEd1lEVlFRS0RBaEJUMHNnVUd4MWN6RVNNQkFHQTFVRUN3d0pNVEE1TlRBd09UWTVNUk13RVFZRFZRUUxEQXBZTVRFME5ESTROVE13TVE0d0RBWURWUVFFREFWR2RXTm9jekVOTUFzR0ExVUVLZ3dFU25WdVlURVRNQkVHQTFVRUF3d0tTblZ1WVNCR2RXTm9jekJhTUJRR0J5cUdTTTQ5QWdFR0NTc2tBd01DQ0FFQkJ3TkNBQVIxTmRyckk4b0tNaXYweHRVWEY1b3NTN3piRklLeEd0L0J3aXN1a1dvRUs1R3NKMWNDeUdFcENIMHNzOEp2RDRPQUhKUzhJTW0xL3JNNTlqbGlTKzFPbzRIdk1JSHNNQjBHQTFVZERnUVdCQlNjRVo1SDFVeFNNaFBzT2NXWmhHOFpRZVdodlRBTUJnTlZIUk1CQWY4RUFqQUFNREFHQlNza0NBTURCQ2N3SlRBak1DRXdIekFkTUJBTURsWmxjbk5wWTJobGNuUmxMeTF5TUFrR0J5cUNGQUJNQkRFd0h3WURWUjBqQkJnd0ZvQVVSTEZNQVZoVUh0elpONzdrc2o4cWJxUmNpUjB3SUFZRFZSMGdCQmt3RnpBS0JnZ3FnaFFBVEFTQkl6QUpCZ2NxZ2hRQVRBUkdNQTRHQTFVZER3RUIvd1FFQXdJSGdEQTRCZ2dyQmdFRkJRY0JBUVFzTUNvd0tBWUlLd1lCQlFVSE1BR0dIR2gwZEhBNkx5OWxhR05oTG1kbGJXRjBhV3N1WkdVdmIyTnpjQzh3Q2dZSUtvWkl6ajBFQXdJRFNBQXdSUUloQUlQSWNiR2pKUXh1VUdiSm1CVWltV3ZiVWk3bStTdVhZQmNSR0Z5WjBqSUpBaUFtMUlXSWZ2L2dOYy9XbXc0Wk8rNzMwUTlDNWRjY0ZuTWptdmJKZTdpNzVnPT0iXSwiYWxnIjoiQlAyNTZSMSJ9.eyJuand0IjoiZXlKaGJHY2lPaUpDVURJMU5sSXhJaXdpZEhsd0lqb2lTbGRVSWl3aWEybGtJam9pYzJWeWRtVnlTMlY1U1dSbGJuUnBkSGtpZlEuZXlKcGMzTWlPbTUxYkd3c0luSmxjM0J2Ym5ObFgzUjVjR1VpT2lKamIyUmxJaXdpYzI1aklqb2lhVFJDTVhCUExYUXRiSFZCYjJsSlRqRjFlbmN4V2xWdFdEZEJNbUZpZFVoUVYzWXdSa2hrVDFCclp5SXNJbU52WkdWZlkyaGhiR3hsYm1kbFgyMWxkR2h2WkNJNklsTXlOVFlpTENKMGIydGxibDkwZVhCbElqb2lZMmhoYkd4bGJtZGxJaXdpYm05dVkyVWlPaUp1YjI1alpWWmhiSFZsSWl3aVkyeHBaVzUwWDJsa0lqb2laMjl2SWl3aWMyTnZjR1VpT2lKdmNHVnVhV1FnWlMxeVpYcGxjSFFpTENKemRHRjBaU0k2SW1admJ5SXNJbkpsWkdseVpXTjBYM1Z5YVNJNkltSmhjaUlzSW1WNGNDSTZNVFkyTVRnME9ERXpPU3dpYVdGMElqb3hOall4T0RRM09UVTVMQ0pqYjJSbFgyTm9ZV3hzWlc1blpTSTZJbk5qYUcxaGNpSXNJbXAwYVNJNklqRTNNR0poTkRrek5qUXdaVEJrTldVaWZRLk9VMnF3UEVxdnpubXRHTkNCSGRBSTZPQ2R6cE5XLVNpOHhOTFpnbi0ya2NpNnNQd05UckRvdm1xZmptWnVxQ3NuVkI5TW42eWctZmFIV0Eya1ZuN1J3In0.ndsBrCrNq4C2rLi89dGT6blAYCzbpY5ZojTMvKvGtxBln7tEiCf-_8Za1Vjl6OUtEGrk_RtCWyojg3BqjIWHCw";

    final JsonWebToken jwt = new JsonWebToken(signedChallenge);
    Assertions.assertDoesNotThrow(() -> jwt.encryptAsNjwt(pk));
  }

  @SneakyThrows
  @Test
  void encryptWithPubKeyFromXYCoordsFromCertificate() {
    final IdpKeyDescriptor idpKeyDescriptor =
        IdpKeyDescriptor.constructFromX509Certificate(idpEnc.getIdentity().getCertificate());
    final IdpEccKeyDescriptor idpEncDesc = (IdpEccKeyDescriptor) idpKeyDescriptor;

    final BigInteger theX =
        new BigInteger(1, Base64.getUrlDecoder().decode(idpEncDesc.getEccPointXValue()));
    final BigInteger theY =
        new BigInteger(1, Base64.getUrlDecoder().decode(idpEncDesc.getEccPointYValue()));

    final ECPoint ecPoint = new ECPoint(theX, theY);
    final ECPublicKeySpec keySpec = new ECPublicKeySpec(ecPoint, BrainpoolCurves.BP256);

    final PublicKey pk =
        KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME).generatePublic(keySpec);

    // extracted from flow
    final String signedChallenge =
        "eyJ0eXAiOiJKV1QiLCJjdHkiOiJOSldUIiwieDVjIjpbIk1JSUMrakNDQXFDZ0F3SUJBZ0lIQXdBVGFsZGZWVEFLQmdncWhrak9QUVFEQWpDQmxqRUxNQWtHQTFVRUJoTUNSRVV4SHpBZEJnTlZCQW9NRm1kbGJXRjBhV3NnUjIxaVNDQk9UMVF0VmtGTVNVUXhSVEJEQmdOVkJBc01QRVZzWld0MGNtOXVhWE5qYUdVZ1IyVnpkVzVrYUdWcGRITnJZWEowWlMxRFFTQmtaWElnVkdWc1pXMWhkR2xyYVc1bWNtRnpkSEoxYTNSMWNqRWZNQjBHQTFVRUF3d1dSMFZOTGtWSFN5MURRVEV3SUZSRlUxUXRUMDVNV1RBZUZ3MHhPVEEwTURneU1qQXdNREJhRncweU5EQTBNRGd5TVRVNU5UbGFNSDB4Q3pBSkJnTlZCQVlUQWtSRk1SRXdEd1lEVlFRS0RBaEJUMHNnVUd4MWN6RVNNQkFHQTFVRUN3d0pNVEE1TlRBd09UWTVNUk13RVFZRFZRUUxEQXBZTVRFME5ESTROVE13TVE0d0RBWURWUVFFREFWR2RXTm9jekVOTUFzR0ExVUVLZ3dFU25WdVlURVRNQkVHQTFVRUF3d0tTblZ1WVNCR2RXTm9jekJhTUJRR0J5cUdTTTQ5QWdFR0NTc2tBd01DQ0FFQkJ3TkNBQVIxTmRyckk4b0tNaXYweHRVWEY1b3NTN3piRklLeEd0L0J3aXN1a1dvRUs1R3NKMWNDeUdFcENIMHNzOEp2RDRPQUhKUzhJTW0xL3JNNTlqbGlTKzFPbzRIdk1JSHNNQjBHQTFVZERnUVdCQlNjRVo1SDFVeFNNaFBzT2NXWmhHOFpRZVdodlRBTUJnTlZIUk1CQWY4RUFqQUFNREFHQlNza0NBTURCQ2N3SlRBak1DRXdIekFkTUJBTURsWmxjbk5wWTJobGNuUmxMeTF5TUFrR0J5cUNGQUJNQkRFd0h3WURWUjBqQkJnd0ZvQVVSTEZNQVZoVUh0elpONzdrc2o4cWJxUmNpUjB3SUFZRFZSMGdCQmt3RnpBS0JnZ3FnaFFBVEFTQkl6QUpCZ2NxZ2hRQVRBUkdNQTRHQTFVZER3RUIvd1FFQXdJSGdEQTRCZ2dyQmdFRkJRY0JBUVFzTUNvd0tBWUlLd1lCQlFVSE1BR0dIR2gwZEhBNkx5OWxhR05oTG1kbGJXRjBhV3N1WkdVdmIyTnpjQzh3Q2dZSUtvWkl6ajBFQXdJRFNBQXdSUUloQUlQSWNiR2pKUXh1VUdiSm1CVWltV3ZiVWk3bStTdVhZQmNSR0Z5WjBqSUpBaUFtMUlXSWZ2L2dOYy9XbXc0Wk8rNzMwUTlDNWRjY0ZuTWptdmJKZTdpNzVnPT0iXSwiYWxnIjoiQlAyNTZSMSJ9.eyJuand0IjoiZXlKaGJHY2lPaUpDVURJMU5sSXhJaXdpZEhsd0lqb2lTbGRVSWl3aWEybGtJam9pYzJWeWRtVnlTMlY1U1dSbGJuUnBkSGtpZlEuZXlKcGMzTWlPbTUxYkd3c0luSmxjM0J2Ym5ObFgzUjVjR1VpT2lKamIyUmxJaXdpYzI1aklqb2lhVFJDTVhCUExYUXRiSFZCYjJsSlRqRjFlbmN4V2xWdFdEZEJNbUZpZFVoUVYzWXdSa2hrVDFCclp5SXNJbU52WkdWZlkyaGhiR3hsYm1kbFgyMWxkR2h2WkNJNklsTXlOVFlpTENKMGIydGxibDkwZVhCbElqb2lZMmhoYkd4bGJtZGxJaXdpYm05dVkyVWlPaUp1YjI1alpWWmhiSFZsSWl3aVkyeHBaVzUwWDJsa0lqb2laMjl2SWl3aWMyTnZjR1VpT2lKdmNHVnVhV1FnWlMxeVpYcGxjSFFpTENKemRHRjBaU0k2SW1admJ5SXNJbkpsWkdseVpXTjBYM1Z5YVNJNkltSmhjaUlzSW1WNGNDSTZNVFkyTVRnME9ERXpPU3dpYVdGMElqb3hOall4T0RRM09UVTVMQ0pqYjJSbFgyTm9ZV3hzWlc1blpTSTZJbk5qYUcxaGNpSXNJbXAwYVNJNklqRTNNR0poTkRrek5qUXdaVEJrTldVaWZRLk9VMnF3UEVxdnpubXRHTkNCSGRBSTZPQ2R6cE5XLVNpOHhOTFpnbi0ya2NpNnNQd05UckRvdm1xZmptWnVxQ3NuVkI5TW42eWctZmFIV0Eya1ZuN1J3In0.ndsBrCrNq4C2rLi89dGT6blAYCzbpY5ZojTMvKvGtxBln7tEiCf-_8Za1Vjl6OUtEGrk_RtCWyojg3BqjIWHCw";
    final JsonWebToken jwt = new JsonWebToken(signedChallenge);
    Assertions.assertDoesNotThrow(() -> jwt.encryptAsNjwt(pk));
  }

  @SneakyThrows
  @Test
  void encryptWithPubKeyFromIdpKeyDescriptor() {
    final String curve = "brainpoolP256r1";

    final IdpKeyDescriptor idpKeyDescriptor =
        IdpKeyDescriptor.constructFromX509Certificate(idpEnc.getIdentity().getCertificate());
    final IdpEccKeyDescriptor idpEncDesc = (IdpEccKeyDescriptor) idpKeyDescriptor;

    final ECPublicKey ecPublicKey =
        EcKeyUtility.genECPublicKey(
            curve, idpEncDesc.getEccPointXValue(), idpEncDesc.getEccPointYValue());

    final String signedChallenge =
        "eyJ0eXAiOiJKV1QiLCJjdHkiOiJOSldUIiwieDVjIjpbIk1JSUMrakNDQXFDZ0F3SUJBZ0lIQXdBVGFsZGZWVEFLQmdncWhrak9QUVFEQWpDQmxqRUxNQWtHQTFVRUJoTUNSRVV4SHpBZEJnTlZCQW9NRm1kbGJXRjBhV3NnUjIxaVNDQk9UMVF0VmtGTVNVUXhSVEJEQmdOVkJBc01QRVZzWld0MGNtOXVhWE5qYUdVZ1IyVnpkVzVrYUdWcGRITnJZWEowWlMxRFFTQmtaWElnVkdWc1pXMWhkR2xyYVc1bWNtRnpkSEoxYTNSMWNqRWZNQjBHQTFVRUF3d1dSMFZOTGtWSFN5MURRVEV3SUZSRlUxUXRUMDVNV1RBZUZ3MHhPVEEwTURneU1qQXdNREJhRncweU5EQTBNRGd5TVRVNU5UbGFNSDB4Q3pBSkJnTlZCQVlUQWtSRk1SRXdEd1lEVlFRS0RBaEJUMHNnVUd4MWN6RVNNQkFHQTFVRUN3d0pNVEE1TlRBd09UWTVNUk13RVFZRFZRUUxEQXBZTVRFME5ESTROVE13TVE0d0RBWURWUVFFREFWR2RXTm9jekVOTUFzR0ExVUVLZ3dFU25WdVlURVRNQkVHQTFVRUF3d0tTblZ1WVNCR2RXTm9jekJhTUJRR0J5cUdTTTQ5QWdFR0NTc2tBd01DQ0FFQkJ3TkNBQVIxTmRyckk4b0tNaXYweHRVWEY1b3NTN3piRklLeEd0L0J3aXN1a1dvRUs1R3NKMWNDeUdFcENIMHNzOEp2RDRPQUhKUzhJTW0xL3JNNTlqbGlTKzFPbzRIdk1JSHNNQjBHQTFVZERnUVdCQlNjRVo1SDFVeFNNaFBzT2NXWmhHOFpRZVdodlRBTUJnTlZIUk1CQWY4RUFqQUFNREFHQlNza0NBTURCQ2N3SlRBak1DRXdIekFkTUJBTURsWmxjbk5wWTJobGNuUmxMeTF5TUFrR0J5cUNGQUJNQkRFd0h3WURWUjBqQkJnd0ZvQVVSTEZNQVZoVUh0elpONzdrc2o4cWJxUmNpUjB3SUFZRFZSMGdCQmt3RnpBS0JnZ3FnaFFBVEFTQkl6QUpCZ2NxZ2hRQVRBUkdNQTRHQTFVZER3RUIvd1FFQXdJSGdEQTRCZ2dyQmdFRkJRY0JBUVFzTUNvd0tBWUlLd1lCQlFVSE1BR0dIR2gwZEhBNkx5OWxhR05oTG1kbGJXRjBhV3N1WkdVdmIyTnpjQzh3Q2dZSUtvWkl6ajBFQXdJRFNBQXdSUUloQUlQSWNiR2pKUXh1VUdiSm1CVWltV3ZiVWk3bStTdVhZQmNSR0Z5WjBqSUpBaUFtMUlXSWZ2L2dOYy9XbXc0Wk8rNzMwUTlDNWRjY0ZuTWptdmJKZTdpNzVnPT0iXSwiYWxnIjoiQlAyNTZSMSJ9.eyJuand0IjoiZXlKaGJHY2lPaUpDVURJMU5sSXhJaXdpZEhsd0lqb2lTbGRVSWl3aWEybGtJam9pYzJWeWRtVnlTMlY1U1dSbGJuUnBkSGtpZlEuZXlKcGMzTWlPbTUxYkd3c0luSmxjM0J2Ym5ObFgzUjVjR1VpT2lKamIyUmxJaXdpYzI1aklqb2lhVFJDTVhCUExYUXRiSFZCYjJsSlRqRjFlbmN4V2xWdFdEZEJNbUZpZFVoUVYzWXdSa2hrVDFCclp5SXNJbU52WkdWZlkyaGhiR3hsYm1kbFgyMWxkR2h2WkNJNklsTXlOVFlpTENKMGIydGxibDkwZVhCbElqb2lZMmhoYkd4bGJtZGxJaXdpYm05dVkyVWlPaUp1YjI1alpWWmhiSFZsSWl3aVkyeHBaVzUwWDJsa0lqb2laMjl2SWl3aWMyTnZjR1VpT2lKdmNHVnVhV1FnWlMxeVpYcGxjSFFpTENKemRHRjBaU0k2SW1admJ5SXNJbkpsWkdseVpXTjBYM1Z5YVNJNkltSmhjaUlzSW1WNGNDSTZNVFkyTVRnME9ERXpPU3dpYVdGMElqb3hOall4T0RRM09UVTVMQ0pqYjJSbFgyTm9ZV3hzWlc1blpTSTZJbk5qYUcxaGNpSXNJbXAwYVNJNklqRTNNR0poTkRrek5qUXdaVEJrTldVaWZRLk9VMnF3UEVxdnpubXRHTkNCSGRBSTZPQ2R6cE5XLVNpOHhOTFpnbi0ya2NpNnNQd05UckRvdm1xZmptWnVxQ3NuVkI5TW42eWctZmFIV0Eya1ZuN1J3In0.ndsBrCrNq4C2rLi89dGT6blAYCzbpY5ZojTMvKvGtxBln7tEiCf-_8Za1Vjl6OUtEGrk_RtCWyojg3BqjIWHCw";
    final JsonWebToken jwt = new JsonWebToken(signedChallenge);
    Assertions.assertDoesNotThrow(() -> jwt.encryptAsNjwt(ecPublicKey));
  }

  @Test
  void encryptWithPubKeyFromCertificate() {
    final X509Certificate certificate = idpEnc.getIdentity().getCertificate();
    final PublicKey pk = certificate.getPublicKey();
    // extracted from flow
    final String signedChallenge =
        "eyJ0eXAiOiJKV1QiLCJjdHkiOiJOSldUIiwieDVjIjpbIk1JSUMrakNDQXFDZ0F3SUJBZ0lIQXdBVGFsZGZWVEFLQmdncWhrak9QUVFEQWpDQmxqRUxNQWtHQTFVRUJoTUNSRVV4SHpBZEJnTlZCQW9NRm1kbGJXRjBhV3NnUjIxaVNDQk9UMVF0VmtGTVNVUXhSVEJEQmdOVkJBc01QRVZzWld0MGNtOXVhWE5qYUdVZ1IyVnpkVzVrYUdWcGRITnJZWEowWlMxRFFTQmtaWElnVkdWc1pXMWhkR2xyYVc1bWNtRnpkSEoxYTNSMWNqRWZNQjBHQTFVRUF3d1dSMFZOTGtWSFN5MURRVEV3SUZSRlUxUXRUMDVNV1RBZUZ3MHhPVEEwTURneU1qQXdNREJhRncweU5EQTBNRGd5TVRVNU5UbGFNSDB4Q3pBSkJnTlZCQVlUQWtSRk1SRXdEd1lEVlFRS0RBaEJUMHNnVUd4MWN6RVNNQkFHQTFVRUN3d0pNVEE1TlRBd09UWTVNUk13RVFZRFZRUUxEQXBZTVRFME5ESTROVE13TVE0d0RBWURWUVFFREFWR2RXTm9jekVOTUFzR0ExVUVLZ3dFU25WdVlURVRNQkVHQTFVRUF3d0tTblZ1WVNCR2RXTm9jekJhTUJRR0J5cUdTTTQ5QWdFR0NTc2tBd01DQ0FFQkJ3TkNBQVIxTmRyckk4b0tNaXYweHRVWEY1b3NTN3piRklLeEd0L0J3aXN1a1dvRUs1R3NKMWNDeUdFcENIMHNzOEp2RDRPQUhKUzhJTW0xL3JNNTlqbGlTKzFPbzRIdk1JSHNNQjBHQTFVZERnUVdCQlNjRVo1SDFVeFNNaFBzT2NXWmhHOFpRZVdodlRBTUJnTlZIUk1CQWY4RUFqQUFNREFHQlNza0NBTURCQ2N3SlRBak1DRXdIekFkTUJBTURsWmxjbk5wWTJobGNuUmxMeTF5TUFrR0J5cUNGQUJNQkRFd0h3WURWUjBqQkJnd0ZvQVVSTEZNQVZoVUh0elpONzdrc2o4cWJxUmNpUjB3SUFZRFZSMGdCQmt3RnpBS0JnZ3FnaFFBVEFTQkl6QUpCZ2NxZ2hRQVRBUkdNQTRHQTFVZER3RUIvd1FFQXdJSGdEQTRCZ2dyQmdFRkJRY0JBUVFzTUNvd0tBWUlLd1lCQlFVSE1BR0dIR2gwZEhBNkx5OWxhR05oTG1kbGJXRjBhV3N1WkdVdmIyTnpjQzh3Q2dZSUtvWkl6ajBFQXdJRFNBQXdSUUloQUlQSWNiR2pKUXh1VUdiSm1CVWltV3ZiVWk3bStTdVhZQmNSR0Z5WjBqSUpBaUFtMUlXSWZ2L2dOYy9XbXc0Wk8rNzMwUTlDNWRjY0ZuTWptdmJKZTdpNzVnPT0iXSwiYWxnIjoiQlAyNTZSMSJ9.eyJuand0IjoiZXlKaGJHY2lPaUpDVURJMU5sSXhJaXdpZEhsd0lqb2lTbGRVSWl3aWEybGtJam9pYzJWeWRtVnlTMlY1U1dSbGJuUnBkSGtpZlEuZXlKcGMzTWlPbTUxYkd3c0luSmxjM0J2Ym5ObFgzUjVjR1VpT2lKamIyUmxJaXdpYzI1aklqb2lhVFJDTVhCUExYUXRiSFZCYjJsSlRqRjFlbmN4V2xWdFdEZEJNbUZpZFVoUVYzWXdSa2hrVDFCclp5SXNJbU52WkdWZlkyaGhiR3hsYm1kbFgyMWxkR2h2WkNJNklsTXlOVFlpTENKMGIydGxibDkwZVhCbElqb2lZMmhoYkd4bGJtZGxJaXdpYm05dVkyVWlPaUp1YjI1alpWWmhiSFZsSWl3aVkyeHBaVzUwWDJsa0lqb2laMjl2SWl3aWMyTnZjR1VpT2lKdmNHVnVhV1FnWlMxeVpYcGxjSFFpTENKemRHRjBaU0k2SW1admJ5SXNJbkpsWkdseVpXTjBYM1Z5YVNJNkltSmhjaUlzSW1WNGNDSTZNVFkyTVRnME9ERXpPU3dpYVdGMElqb3hOall4T0RRM09UVTVMQ0pqYjJSbFgyTm9ZV3hzWlc1blpTSTZJbk5qYUcxaGNpSXNJbXAwYVNJNklqRTNNR0poTkRrek5qUXdaVEJrTldVaWZRLk9VMnF3UEVxdnpubXRHTkNCSGRBSTZPQ2R6cE5XLVNpOHhOTFpnbi0ya2NpNnNQd05UckRvdm1xZmptWnVxQ3NuVkI5TW42eWctZmFIV0Eya1ZuN1J3In0.ndsBrCrNq4C2rLi89dGT6blAYCzbpY5ZojTMvKvGtxBln7tEiCf-_8Za1Vjl6OUtEGrk_RtCWyojg3BqjIWHCw";
    final JsonWebToken jwt = new JsonWebToken(signedChallenge);
    Assertions.assertDoesNotThrow(() -> jwt.encryptAsNjwt(pk));
  }

  @SneakyThrows
  @Test
  void proofUsageSignumOfBigIntegerproducesGoodPubKey() {
    final PublicKey pubKeyCert = idpEnc.getIdentity().getCertificate().getPublicKey();

    final IdpKeyDescriptor idpKeyDescriptor =
        IdpKeyDescriptor.constructFromX509Certificate(idpEnc.getIdentity().getCertificate());
    final IdpEccKeyDescriptor idpEncDesc = (IdpEccKeyDescriptor) idpKeyDescriptor;

    final BigInteger theX =
        new BigInteger(1, Base64.getUrlDecoder().decode(idpEncDesc.getEccPointXValue()));
    final BigInteger theY =
        new BigInteger(1, Base64.getUrlDecoder().decode(idpEncDesc.getEccPointYValue()));

    final ECPoint ecPoint = new ECPoint(theX, theY);
    final ECPublicKeySpec keySpec = new ECPublicKeySpec(ecPoint, BrainpoolCurves.BP256);

    final PublicKey pubKeySignum1 =
        KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME).generatePublic(keySpec);

    assertThat(pubKeySignum1).isEqualTo(pubKeyCert);
  }
}
