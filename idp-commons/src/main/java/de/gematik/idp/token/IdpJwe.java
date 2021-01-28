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

package de.gematik.idp.token;

import de.gematik.idp.exceptions.IdpJoseException;
import java.security.Key;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.lang.JoseException;

@RequiredArgsConstructor
@Data
public class IdpJwe {

    private final String rawValue;

    public JsonWebToken decrypt(final Key key) {
        final JsonWebEncryption receiverJwe = new JsonWebEncryption();

        receiverJwe.setAlgorithmConstraints(
            new AlgorithmConstraints(ConstraintType.PERMIT, KeyManagementAlgorithmIdentifiers.DIRECT,
                KeyManagementAlgorithmIdentifiers.ECDH_ES_A256KW));
        receiverJwe.setContentEncryptionAlgorithmConstraints(
            new AlgorithmConstraints(ConstraintType.PERMIT,
                ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256,
                ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512));

        try {
            receiverJwe.setCompactSerialization(rawValue);

            receiverJwe.setKey(key);

            return new JsonWebToken(receiverJwe.getPlaintextString());
        } catch (final JoseException e) {
            throw new IdpJoseException("Error during decryption", e);
        }
    }
}
