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

package de.gematik.idp.crypto;

import de.gematik.idp.crypto.exceptions.IdpCryptoException;
import java.util.Base64;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;
import org.bouncycastle.util.encoders.Hex;

public class Nonce {

    private static final int NONCE_BYTE_AMOUNT_MIN = 1;
    private static final int NONCE_BYTE_AMOUNT_MAX = 512;
    private static final int NONCE_STRLEN_MIN = 2;
    private static final int NONCE_STRLEN_MAX = 512;

    public String getNonceAsBase64UrlEncodedString(final int randomByteAmount) {
        if (randomByteAmount < NONCE_BYTE_AMOUNT_MIN || randomByteAmount > NONCE_BYTE_AMOUNT_MAX) {
            throw new IdpCryptoException(
                "Amount of random bytes is expected to be between " + NONCE_BYTE_AMOUNT_MIN + " and "
                    + NONCE_BYTE_AMOUNT_MAX);
        }

        final Random random = ThreadLocalRandom.current();
        final byte[] randomArray = new byte[randomByteAmount];
        random.nextBytes(randomArray);
        return new String(Base64.getUrlEncoder().encode(randomArray));
    }

    public String getNonceAsHex(final int strlen) {
        if (strlen < NONCE_STRLEN_MIN || strlen > NONCE_STRLEN_MAX) {
            throw new IdpCryptoException(
                "Requested string length is expected to be between " + NONCE_STRLEN_MIN + " and " + NONCE_STRLEN_MAX);
        }
        if (strlen % 2 != 0) {
            throw new IdpCryptoException("Requested string length is expected to be even.");
        }
        final Random random = ThreadLocalRandom.current();
        final byte[] randomArray = new byte[strlen / 2];
        random.nextBytes(randomArray);
        return Hex.toHexString(randomArray);
    }

}
