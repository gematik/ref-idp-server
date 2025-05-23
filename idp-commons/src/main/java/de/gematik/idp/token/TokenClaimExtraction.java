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

package de.gematik.idp.token;

import de.gematik.idp.exceptions.IdpJoseException;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Map;
import java.util.Objects;
import kong.unirest.core.json.JSONObject;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class TokenClaimExtraction {

  /**
   * @param token jwt as string
   * @return Claims as a map of key value strings
   * @desc Implements the extraction of claims from json web tokens
   */
  public static Map<String, Object> extractClaimsFromJwtBody(final String token) {
    final JwtConsumer jwtConsumer =
        new JwtConsumerBuilder()
            .setSkipSignatureVerification()
            .setSkipDefaultAudienceValidation()
            .setSkipAllValidators()
            .build();

    try {
      return jwtConsumer.process(token).getJwtClaims().getClaimsMap();
    } catch (final InvalidJwtException e) {
      throw new IdpJoseException(e);
    }
  }

  public static Map<String, Object> extractClaimsFromJwtHeader(final String token) {
    final JsonWebSignature jsonWebSignature = new JsonWebSignature();
    try {
      jsonWebSignature.setCompactSerialization(token);
      return JsonUtil.parseJson(jsonWebSignature.getHeaders().getFullHeaderAsJsonString());
    } catch (final JoseException e) {
      throw new IdpJoseException(e);
    }
  }

  public static JsonWebKeySet extractJwksFromBody(final String token) {
    final JwtConsumer jwtConsumer =
        new JwtConsumerBuilder()
            .setSkipSignatureVerification()
            .setSkipDefaultAudienceValidation()
            .setSkipAllValidators()
            .build();
    try {
      final JSONObject payload =
          new JSONObject(jwtConsumer.process(token).getJwtClaims().getRawJson());
      return new JsonWebKeySet(payload.get("jwks").toString());
    } catch (final InvalidJwtException | JoseException e) {
      throw new IdpJoseException(e);
    }
  }

  public static ECPublicKey getECPublicKey(final JsonWebKeySet jsonWebKeySet, final String keyId) {
    final JsonWebKey jsonWebKey =
        Objects.requireNonNull(
            jsonWebKeySet.findJsonWebKey(keyId, null, null, null), "Key not found in jwks");
    return ((EllipticCurveJsonWebKey) jsonWebKey).getECPublicKey();
  }

  public static ZonedDateTime claimToZonedDateTime(final Long claim) {
    return ZonedDateTime.ofInstant(Instant.ofEpochMilli(claim * 1000), ZoneOffset.UTC);
  }

  public static long zonedDateTimeToClaim(final ZonedDateTime dateTime) {
    return dateTime.toEpochSecond();
  }

  public static ZonedDateTime claimToZonedDateTime(final Object claim) {
    Objects.requireNonNull(claim);

    if (claim instanceof final String claimString) {
      return claimToZonedDateTime(Long.parseLong(claimString));
    } else if (claim instanceof final Long claimLong) {
      return claimToZonedDateTime(claimLong);
    } else if (claim instanceof final Integer claimInt) {
      return claimToZonedDateTime(Integer.toUnsignedLong(claimInt));
    } else {
      throw new IllegalArgumentException(
          "Couldn't convert claim: " + claim.getClass().getSimpleName());
    }
  }
}
