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

import static de.gematik.idp.field.ClaimName.EXPIRES_AT;
import static de.gematik.idp.field.ClaimName.ISSUED_AT;
import static de.gematik.idp.field.ClaimName.NOT_BEFORE;
import static de.gematik.idp.field.ClaimName.X509_Certificate_Chain;

import de.gematik.idp.authentication.JwtDescription;
import de.gematik.idp.crypto.CryptoLoader;
import de.gematik.idp.exceptions.IdpJoseException;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.field.IdpScope;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.*;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;
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
        return getDateTimeClaim(EXPIRES_AT, () -> getHeaderClaims())
            .orElseThrow();
    }

    public ZonedDateTime getExpiresAtBody() {
        return getBodyClaimAsZonedDateTime(EXPIRES_AT)
            .orElseThrow();
    }

    public ZonedDateTime getIssuedAt() {
        return getBodyClaimAsZonedDateTime(ISSUED_AT)
            .orElseThrow();
    }

    public ZonedDateTime getNotBefore() {
        return getBodyClaimAsZonedDateTime(NOT_BEFORE)
            .orElseThrow();
    }

    private Optional<ZonedDateTime> getBodyClaimAsZonedDateTime(final ClaimName claimName) {
        return getBodyClaims().entrySet().stream()
            .filter(entry -> claimName.getJoseName().equals(entry.getKey()))
            .map(Map.Entry::getValue)
            .map(TokenClaimExtraction::claimToDateTime)
            .findAny();
    }

    public Set<IdpScope> getScopesBodyClaim(final ClaimName claimName) {
        return Optional
            .ofNullable(getBodyClaims().get(claimName.getJoseName()))
            .filter(String.class::isInstance)
            .map(String.class::cast)
            .stream()
            .flatMap(value -> Stream.of(value.split(" ")))
            .map(IdpScope::fromJwtValue)
            .filter(Optional::isPresent)
            .map(Optional::get)
            .collect(Collectors.toSet());
    }

    public Optional<String> getStringBodyClaim(final ClaimName claimName) {
        return Optional
            .ofNullable(getBodyClaims().get(claimName.getJoseName()))
            .filter(String.class::isInstance)
            .map(String.class::cast);
    }

    public Optional<ZonedDateTime> getDateTimeClaim(final ClaimName claimName,
        final Supplier<Map<String, Object>> claims) {
        return Optional
            .ofNullable(claims.get().get(claimName.getJoseName()))
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
        return Optional.ofNullable(getBodyClaims()
            .get(claimName.getJoseName()))
            .filter(Objects::nonNull);
    }

    public Optional<Object> getHeaderClaim(final ClaimName claimName) {
        return Optional.ofNullable(getHeaderClaims()
            .get(claimName.getJoseName()))
            .filter(Objects::nonNull);
    }

    public JwtDescription toJwtDescription() {
        return JwtDescription.builder()
            .claims(getBodyClaims())
            .headers(getHeaderClaims())
            .build();
    }

    public Optional<X509Certificate> getClientCertificateFromHeader() {
        return Optional.ofNullable(getHeaderClaims().get(X509_Certificate_Chain.getJoseName()))
            .filter(List.class::isInstance)
            .map(List.class::cast)
            .filter(list -> !list.isEmpty())
            .map(list -> list.get(0))
            .map(Object::toString)
            .map(java.util.Base64.getDecoder()::decode)
            .map(CryptoLoader::getCertificateFromPem);
    }
}
