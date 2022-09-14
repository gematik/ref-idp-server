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

package de.gematik.idp.crypto;

import de.gematik.idp.crypto.exceptions.IdpCryptoException;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.Base64;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class EcKeyUtility {

    public static PublicKey genPublicKey(final String algorithm, final ECPoint ecPoint) {
        try {
            final AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec(getStdName(algorithm)));
            final ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);
            final ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(ecPoint, ecParameters);
            return KeyFactory.getInstance("EC").generatePublic(pubKeySpec);
        } catch (final NoSuchAlgorithmException | InvalidParameterSpecException | InvalidKeySpecException e) {
            throw new IdpCryptoException("Generation of PublicKey failed.", e);
        }
    }

    public static ECPublicKey genECPublicKey(String curve, String pXbase64, String pYbase64)
        throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        BigInteger pX = new BigInteger(Base64.getUrlDecoder().decode(pXbase64));
        BigInteger pY = new BigInteger(Base64.getUrlDecoder().decode(pYbase64));
        return genECPublicKey(curve, pX, pY);
    }

    public static ECPublicKey genECPublicKey(String curve, BigInteger pX, BigInteger pY)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {

        byte[] x = pX.toByteArray();
        byte[] y = pY.toByteArray();

        KeyFactory keyFactory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        ECPoint point = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
        ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec(curve);
        ECParameterSpec spec = new ECNamedCurveSpec(curve, parameterSpec.getCurve(), parameterSpec.getG(),
            parameterSpec.getN(), parameterSpec.getH(), parameterSpec.getSeed());
        return (ECPublicKey) keyFactory.generatePublic(new ECPublicKeySpec(point, spec));
    }

    private static String getStdName(final String algorithm) {
        switch (algorithm) {
            case "P-256":
                return "secp256r1";
            default:
                throw new IdpCryptoException("Generation of PublicKey: algorithm not supported.");
        }
    }
}
