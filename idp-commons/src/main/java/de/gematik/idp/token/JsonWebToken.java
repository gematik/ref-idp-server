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

package de.gematik.idp.token;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import de.gematik.idp.authentication.JwtBuilder;
import de.gematik.idp.exceptions.IdpJoseException;
import de.gematik.idp.exceptions.IdpJwtExpiredException;
import de.gematik.idp.exceptions.IdpJwtSignatureInvalidException;
import de.gematik.idp.field.ClaimName;
import java.io.IOException;
import java.security.Key;
import java.security.PublicKey;
import java.time.ZonedDateTime;
import java.util.Map;
import java.util.Optional;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import org.jose4j.jwt.consumer.ErrorCodes;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;

@Getter
@EqualsAndHashCode
@JsonSerialize(using = IdpJoseObject.Serializer.class)
@JsonDeserialize(using = JsonWebToken.Deserializer.class)
public class JsonWebToken extends IdpJoseObject {

    public JsonWebToken(final String rawString) {
        super(rawString);
    }

    public void verify(final PublicKey publicKey) {
        final JwtConsumer jwtConsumer = new JwtConsumerBuilder()
            .setVerificationKey(publicKey)
            .setSkipDefaultAudienceValidation()
            .build();

        try {
            jwtConsumer.process(getRawString());
        } catch (final InvalidJwtException e) {
            if (e.getErrorDetails().stream()
                .filter(error -> error.getErrorCode() == ErrorCodes.EXPIRED)
                .findAny().isPresent()) {
                throw new IdpJwtExpiredException(e);
            }
            if (e.getErrorDetails().stream()
                .filter(error -> error.getErrorCode() == ErrorCodes.SIGNATURE_INVALID)
                .findAny().isPresent()) {
                throw new IdpJwtSignatureInvalidException(e);
            }
            throw new IdpJoseException("Invalid JWT encountered", e);
        }
    }

    public JwtBuilder toJwtDescription() {
        return new JwtBuilder()
            .addAllBodyClaims(getBodyClaims())
            .addAllHeaderClaims(getHeaderClaims());
    }

    public IdpJwe encrypt(final Key key) {
        return IdpJwe.createWithPayloadAndExpiryAndEncryptWithKey("{\"njwt\":\"" + getRawString() + "\"}",
            findExpClaimInNestedJwts(), key, "NJWT");
    }

    public Optional<ZonedDateTime> findExpClaimInNestedJwts() {
        final Optional<ZonedDateTime> expClaim = getBodyDateTimeClaim(ClaimName.EXPIRES_AT);
        if (expClaim.isPresent()) {
            return expClaim;
        } else {
            final Optional<Object> njwtClaim = getBodyClaim(ClaimName.NESTED_JWT);
            if (njwtClaim.isPresent()) {
                try {
                    return new JsonWebToken(njwtClaim.get().toString())
                        .findExpClaimInNestedJwts();
                } catch (final Exception e) {
                    return Optional.empty();
                }
            }
            return Optional.empty();
        }
    }

    @Override
    public Map<String, Object> extractHeaderClaims() {
        return TokenClaimExtraction.extractClaimsFromJwtHeader(getRawString());
    }

    @Override
    public Map<String, Object> extractBodyClaims() {
        return TokenClaimExtraction.extractClaimsFromJwtBody(getRawString());
    }

    public static class Deserializer extends JsonDeserializer<IdpJoseObject> {

        @Override
        public IdpJoseObject deserialize(final JsonParser p, final DeserializationContext ctxt) throws IOException {
            return new JsonWebToken(ctxt.readValue(p, String.class));
        }
    }
}
