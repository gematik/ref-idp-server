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
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.*;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

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

    private static String getStdName(final String algorithm) {
        switch (algorithm) {
            case "P-256":
                return "secp256r1";
            default:
                throw new IdpCryptoException("Generation of PublicKey: algorithm not supported.");
        }
    }
}
