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

import static de.gematik.idp.field.ClaimName.*;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import de.gematik.idp.authentication.JwtBuilder;
import de.gematik.idp.crypto.CryptoLoader;
import de.gematik.idp.exceptions.IdpJoseException;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.field.IdpScope;
import java.io.IOException;
import java.security.Key;
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
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;

@Builder
@Getter
@AllArgsConstructor
@RequiredArgsConstructor
@JsonSerialize(using = JsonWebToken.Serializer.class)
@JsonDeserialize(using = JsonWebToken.Deserializer.class)
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
            throw new IdpJoseException("Invalid JWT encountered", e);
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

    public Set<IdpScope> getScopesBodyClaim() {
        return Optional
            .ofNullable(getBodyClaims().get(SCOPE.getJoseName()))
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

    public Optional<ZonedDateTime> getBodyDateTimeClaim(final ClaimName claimName) {
        return getDateTimeClaim(claimName, this::getBodyClaims);
    }

    public Optional<ZonedDateTime> getHeaderDateTimeClaim(final ClaimName claimName) {
        return getDateTimeClaim(claimName, this::getHeaderClaims);
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

    public JwtBuilder toJwtDescription() {
        return new JwtBuilder()
            .addAllBodyClaims(getBodyClaims())
            .addAllHeaderClaims(getHeaderClaims());
    }

    public Optional<X509Certificate> getClientCertificateFromHeader() {
        return Optional.ofNullable(getHeaderClaims().get(X509_CERTIFICATE_CHAIN.getJoseName()))
            .filter(List.class::isInstance)
            .map(List.class::cast)
            .filter(list -> !list.isEmpty())
            .map(list -> list.get(0))
            .map(Object::toString)
            .map(java.util.Base64.getDecoder()::decode)
            .map(CryptoLoader::getCertificateFromPem);
    }

    public IdpJwe encrypt(final Key key) {
        final JsonWebEncryption senderJwe = new JsonWebEncryption();

        senderJwe.setPlaintext(jwtRawString);
        if (key instanceof PublicKey) {
            senderJwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.ECDH_ES_A256KW);
        } else {
            senderJwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.DIRECT);
        }
        senderJwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        senderJwe.setKey(key);

        try {
            return new IdpJwe(senderJwe.getCompactSerialization());
        } catch (final JoseException e) {
            throw new IdpJoseException("Error during token encryption", e);
        }
    }

    public static class Serializer extends JsonSerializer<JsonWebToken> {

        @Override
        public void serialize(final JsonWebToken value, final JsonGenerator gen, final SerializerProvider serializers)
            throws IOException {
            gen.writeString(value.getJwtRawString());
        }
    }

    public static class Deserializer extends JsonDeserializer<JsonWebToken> {

        @Override
        public JsonWebToken deserialize(final JsonParser p, final DeserializationContext ctxt) throws IOException {
            return new JsonWebToken(ctxt.readValue(p, String.class));
        }
    }
}
