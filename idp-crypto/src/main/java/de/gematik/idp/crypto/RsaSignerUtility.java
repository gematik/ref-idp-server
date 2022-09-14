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
import java.security.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class RsaSignerUtility {

    private RsaSignerUtility() {
    }

    public static byte[] createRsaSignature(final byte[] toBeSignedData, final PrivateKey privateKey) {
        try {
            final Signature signer = Signature.getInstance("SHA256withRSAAndMGF1", new BouncyCastleProvider());
            signer.initSign(privateKey);
            signer.update(toBeSignedData);
            return signer.sign();
        } catch (final NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new IdpCryptoException(e);
        }
    }

}
