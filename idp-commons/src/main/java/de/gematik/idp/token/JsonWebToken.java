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
import java.util.function.Consumer;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwk.JsonWebKey;
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
    final JwtConsumer jwtConsumer =
        new JwtConsumerBuilder()
            .setVerificationKey(publicKey)
            .setSkipDefaultAudienceValidation()
            .build();

    try {
      jwtConsumer.process(getRawString());
    } catch (final InvalidJwtException e) {
      if (e.getErrorDetails().stream()
          .anyMatch(error -> error.getErrorCode() == ErrorCodes.EXPIRED)) {
        throw new IdpJwtExpiredException(e);
      }
      if (e.getErrorDetails().stream()
          .anyMatch(error -> error.getErrorCode() == ErrorCodes.SIGNATURE_INVALID)) {
        throw new IdpJwtSignatureInvalidException(e);
      }
      throw new IdpJoseException("Invalid JWT encountered", e);
    }
  }

  public JwtBuilder toJwtDescription() {
    return new JwtBuilder().addAllBodyClaims(getBodyClaims()).addAllHeaderClaims(getHeaderClaims());
  }

  /**
   * @deprecated This method will be renamed in the next release.
   *     <p>Use {@link #encryptAsNjwt(Key)} instead.
   */
  @Deprecated(since = "24.1.0", forRemoval = true)
  public IdpJwe encrypt(final Key key) {
    return encryptAsNjwt(key);
  }

  /**
   * @param key encryption key
   * @return encrypted nested JWT
   */
  public IdpJwe encryptAsNjwt(final Key key) {
    final Consumer<JsonWebEncryption> setContentTypeAndExp =
        jwe -> {
          jwe.setHeader(ClaimName.CONTENT_TYPE.getJoseName(), "NJWT");
          findExpClaimInNestedJwts()
              .map(TokenClaimExtraction::zonedDateTimeToClaim)
              .ifPresent(expValue -> jwe.setHeader(ClaimName.EXPIRES_AT.getJoseName(), expValue));
        };
    return IdpJwe.createJweWithPayloadAndHeaders(
        "{\"njwt\":\"" + getRawString() + "\"}", key, setContentTypeAndExp);
  }

  /**
   * @param key encryption key as JSON
   * @return encrypted JWT
   */
  public IdpJwe encryptAsJwt(final JsonWebKey key) {
    final Consumer<JsonWebEncryption> setContentTypeAndKid =
        jwe -> {
          jwe.setHeader(ClaimName.CONTENT_TYPE.getJoseName(), "JWT");
          jwe.setHeader(ClaimName.KEY_ID.getJoseName(), key.getKeyId());
        };
    return IdpJwe.createJweWithPayloadAndHeaders(
        getRawString(), key.getKey(), setContentTypeAndKid);
  }

  public Optional<ZonedDateTime> findExpClaimInNestedJwts() {
    final Optional<ZonedDateTime> expClaim = getBodyDateTimeClaim(ClaimName.EXPIRES_AT);
    if (expClaim.isPresent()) {
      return expClaim;
    } else {
      final Optional<Object> njwtClaim = getBodyClaim(ClaimName.NESTED_JWT);
      if (njwtClaim.isPresent()) {
        return new JsonWebToken(njwtClaim.get().toString()).findExpClaimInNestedJwts();
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
    public IdpJoseObject deserialize(final JsonParser p, final DeserializationContext ctxt)
        throws IOException {
      return new JsonWebToken(ctxt.readValue(p, String.class));
    }
  }
}
