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

package de.gematik.idp.crypto;

import de.gematik.idp.crypto.exceptions.IdpCryptoException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Base64;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class EcKeyUtility {

  public static PublicKey genPublicKey(final String algorithm, final ECPoint ecPoint) {
    try {
      final AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
      parameters.init(new ECGenParameterSpec(getStdName(algorithm)));
      final ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);
      final ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(ecPoint, ecParameters);
      return KeyFactory.getInstance("EC").generatePublic(pubKeySpec);
    } catch (final NoSuchAlgorithmException
        | InvalidParameterSpecException
        | InvalidKeySpecException e) {
      throw new IdpCryptoException("Generation of PublicKey failed.", e);
    }
  }

  public static ECPublicKey genECPublicKey(
      final String curve, final String pXbase64, final String pYbase64)
      throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
    final BigInteger pX = new BigInteger(Base64.getUrlDecoder().decode(pXbase64));
    final BigInteger pY = new BigInteger(Base64.getUrlDecoder().decode(pYbase64));
    return genECPublicKey(curve, pX, pY);
  }

  public static ECPublicKey genECPublicKey(
      final String curve, final BigInteger pX, final BigInteger pY)
      throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {

    final byte[] x = pX.toByteArray();
    final byte[] y = pY.toByteArray();

    final KeyFactory keyFactory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
    final ECPoint point = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
    final ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec(curve);
    final ECParameterSpec spec =
        new ECNamedCurveSpec(
            curve,
            parameterSpec.getCurve(),
            parameterSpec.getG(),
            parameterSpec.getN(),
            parameterSpec.getH(),
            parameterSpec.getSeed());
    return (ECPublicKey) keyFactory.generatePublic(new ECPublicKeySpec(point, spec));
  }

  private static String getStdName(final String algorithm) {
    if ("P-256".equals(algorithm)) {
      return "secp256r1";
    }
    throw new IdpCryptoException("Generation of PublicKey: algorithm not supported.");
  }
}
