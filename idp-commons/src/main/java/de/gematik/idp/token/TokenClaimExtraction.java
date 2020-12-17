/*
 * Copyright (c) 2020 gematik GmbH
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

import de.gematik.idp.crypto.CryptoLoader;
import de.gematik.idp.exceptions.IdpJoseException;
import de.gematik.idp.field.ClaimName;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.jose4j.json.JsonUtil;
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
    public static Map<String, Object> extractClaimsFromTokenBody(final String token) {
        final JwtConsumer jwtConsumer = new JwtConsumerBuilder()
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

    public static Map<String, Object> extractClaimsFromTokenHeader(final String token) {
        final JsonWebSignature jsonWebSignature = new JsonWebSignature();
        try {
            jsonWebSignature.setCompactSerialization(token);
            return JsonUtil.parseJson(jsonWebSignature.getHeaders().getFullHeaderAsJsonString());
        } catch (final JoseException e) {
            throw new IdpJoseException(e);
        }
    }

    public static ZonedDateTime claimToDateTime(final Long claim) {
        return ZonedDateTime.ofInstant(Instant.ofEpochMilli(claim * 1000), ZoneOffset.UTC);
    }

    public static ZonedDateTime claimToDateTime(final Object claim) {
        Objects.requireNonNull(claim);

        if (claim instanceof String) {
            return claimToDateTime(Long.parseLong((String) claim));
        } else if (claim instanceof Long) {
            return claimToDateTime((Long) claim);
        } else {
            throw new IllegalArgumentException("Couldn't convert claim: " + claim.getClass().getSimpleName());
        }
    }

    public static Optional<X509Certificate> extractX509ClientCertificate(final JsonWebToken jwt) {
        return Optional.ofNullable(jwt.getHeaderClaims()
            .get(ClaimName.X509_Certificate_Chain.getJoseName()))
            .filter(List.class::isInstance)
            .map(List.class::cast)
            .stream()
            .flatMap(List::stream)
            .map(b64String -> Base64.getDecoder().decode(b64String.toString()))
            .map(encodedCert -> CryptoLoader.getCertificateFromPem((byte[]) encodedCert))
            .findAny();
    }
}
