/*
 * Copyright (Date see Readme), gematik GmbH
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
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

package de.gematik.idp.brainPoolExtension;

import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.crypto.EcKeyUtility;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Base64;
import lombok.SneakyThrows;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.Test;

class BrainpoolCurvesTest {

  static {
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    Security.insertProviderAt(new BouncyCastleProvider(), 1);
  }

  @Test
  void verify_init() {
    BrainpoolCurves.init();
    final ECParameterSpec ecParameterSpec = EllipticCurves.getSpec("BP-256");
    assertThat(ecParameterSpec).isNotNull();
  }

  @SneakyThrows
  @Test
  void ellipticCurveBouncyCastle_isEqualTo_ellipticCurveBrainPoolExtension() {
    final String curve = "brainpoolP256r1";
    final BigInteger theX =
        new BigInteger(
            Base64.getUrlDecoder().decode("QLpJ_LpFx-6yJhsb4OvHwU1khLnviiOwYOvmf5clK7w"));
    final BigInteger theY =
        new BigInteger(
            Base64.getUrlDecoder().decode("mHuknfNkoMmSbytt4br0YGihOixcmBKy80UfSLdXGe4"));

    final PublicKey pkBouncyCastle = EcKeyUtility.genECPublicKey(curve, theX, theY);

    final ECPoint ecPoint = new ECPoint(theX, theY);
    final ECPublicKeySpec keySpec = new ECPublicKeySpec(ecPoint, BrainpoolCurves.BP256);
    final PublicKey pkBrainPoolExtension = KeyFactory.getInstance("EC").generatePublic(keySpec);

    assertThat(pkBouncyCastle).isEqualTo(pkBrainPoolExtension);
  }
}
