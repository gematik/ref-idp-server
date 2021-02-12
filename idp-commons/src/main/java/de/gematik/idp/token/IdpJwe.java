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

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import de.gematik.idp.exceptions.IdpJoseException;
import de.gematik.idp.field.ClaimName;
import java.security.Key;
import java.security.PublicKey;
import java.time.ZonedDateTime;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.lang.JoseException;

@EqualsAndHashCode
@Getter
@Setter
@JsonSerialize(using = IdpJoseObject.Serializer.class)
@JsonDeserialize(using = IdpJoseObject.Deserializer.class)
public class IdpJwe extends IdpJoseObject {

    private Key decryptionKey;

    public IdpJwe(final String rawString) {
        super(rawString);
    }

    public static IdpJwe createWithPayloadAndEncryptWithKey(final String payload, final Key key) {
        return createWithPayloadAndExpiryAndEncryptWithKey(payload, Optional.empty(), key);
    }

    public static IdpJwe createWithPayloadAndExpiryAndEncryptWithKey(final String payload,
        final Optional<ZonedDateTime> expiryOptional, final Key key) {
        final JsonWebEncryption jwe = new JsonWebEncryption();

        jwe.setPlaintext(payload);
        if (key instanceof PublicKey) {
            jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.ECDH_ES_A256KW);
        } else {
            jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.DIRECT);
        }
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_256_GCM);
        jwe.setKey(key);
        expiryOptional
            .map(TokenClaimExtraction::zonedDateTimeToClaim)
            .ifPresent(expValue -> jwe.setHeader(ClaimName.EXPIRES_AT.getJoseName(), expValue));

        try {
            return new IdpJwe(jwe.getCompactSerialization());
        } catch (final JoseException e) {
            throw new IdpJoseException("Error during token encryption", e);
        }
    }

    public JsonWebToken decryptNestedJwt(final Key key) {
        return new JsonWebToken(decryptJweAndReturnPayloadString(key));
    }

    private String decryptJweAndReturnPayloadString(final Key key) {
        final JsonWebEncryption receiverJwe = new JsonWebEncryption();

        receiverJwe.setAlgorithmConstraints(
            new AlgorithmConstraints(ConstraintType.PERMIT, KeyManagementAlgorithmIdentifiers.DIRECT,
                KeyManagementAlgorithmIdentifiers.ECDH_ES_A256KW));
        receiverJwe.setContentEncryptionAlgorithmConstraints(
            new AlgorithmConstraints(ConstraintType.PERMIT,
                ContentEncryptionAlgorithmIdentifiers.AES_256_GCM));

        try {
            receiverJwe.setCompactSerialization(getRawString());
            receiverJwe.setKey(key);

            return receiverJwe.getPlaintextString();
        } catch (final JoseException e) {
            throw new IdpJoseException("Error during decryption", e);
        }
    }

    @Override
    public Map<String, Object> extractHeaderClaims() {
        final JsonWebEncryption jwe = new JsonWebEncryption();
        try {
            jwe.setCompactSerialization(getRawString());
            return JsonUtil.parseJson(jwe.getHeaders().getFullHeaderAsJsonString());
        } catch (final JoseException e) {
            throw new IdpJoseException(e);
        }
    }

    @Override
    public Map<String, Object> extractBodyClaims() {
        Objects.requireNonNull(decryptionKey, "Body-claim extraction requires non-null decryption key");
        try {
            return JsonUtil.parseJson(decryptJweAndReturnPayloadString(decryptionKey));
        } catch (final JoseException e) {
            throw new IdpJoseException("Exception occurred during body-claim extraction", e);
        }
    }
}
