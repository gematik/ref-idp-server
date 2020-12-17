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

import de.gematik.idp.exceptions.IdpJoseException;
import de.gematik.idp.field.ClaimName;
import java.security.PublicKey;
import java.time.ZonedDateTime;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;

@Builder
@Getter
@AllArgsConstructor
@RequiredArgsConstructor
public class JsonWebToken {

    private final String jwtRawString;
    private Map<String, Object> headerClaims;
    private Map<String, Object> bodyClaims;

    public void verify(final PublicKey publicKey) {
        final JwtConsumer jwtConsumer = new JwtConsumerBuilder()
            .setVerificationKey(publicKey)
            .setSkipDefaultAudienceValidation()
            .build();

        try {
            jwtConsumer.process(jwtRawString);
        } catch (final InvalidJwtException e) {
            throw new IdpJoseException(e);
        }
    }

    public Map<String, Object> getHeaderClaims() {
        if (headerClaims == null) {
            headerClaims = TokenClaimExtraction.extractClaimsFromTokenHeader(jwtRawString);
        }
        return headerClaims;
    }

    public Map<String, Object> getBodyClaims() {
        if (bodyClaims == null) {
            bodyClaims = TokenClaimExtraction.extractClaimsFromTokenBody(jwtRawString);
        }
        return bodyClaims;
    }

    public ZonedDateTime getExpiresAt() {
        return getBodyClaims().entrySet().stream()
            .filter(entry -> "exp".equals(entry.getKey()))
            .map(Map.Entry::getValue)
            .map(TokenClaimExtraction::claimToDateTime)
            .findAny()
            .orElseThrow();
    }

    public Optional<String> getStringBodyClaim(final String claimName) {
        return Optional
            .ofNullable(getBodyClaims().get(claimName))
            .filter(String.class::isInstance)
            .map(String.class::cast);
    }

    public Optional<ZonedDateTime> getDateTimeBodyClaim(final String claimName) {
        return Optional
            .ofNullable(getBodyClaims().get(claimName))
            .filter(Long.class::isInstance)
            .map(Long.class::cast)
            .map(TokenClaimExtraction::claimToDateTime);
    }

    public String getHeaderDecoded() {
        final String[] split = getJwtRawString().split("\\.");
        if (split.length < 2) {
            throw new IllegalStateException("Could not retrieve Header: only found "
                + split.length + " parts!");
        }
        return StringUtils.newStringUtf8(Base64.decodeBase64(split[0]));
    }

    public String getPayloadDecoded() {
        final String[] split = getJwtRawString().split("\\.");
        if (split.length < 2) {
            throw new IllegalStateException("Could not retrieve Body: only found "
                + split.length + " parts!");
        }
        return StringUtils.newStringUtf8(Base64.decodeBase64(split[1]));
    }

    public Optional<Object> getBodyClaim(final ClaimName claimName) {
        return Optional.ofNullable(getBodyClaims().get(claimName.getJoseName()))
            .filter(Objects::nonNull);
    }
}
