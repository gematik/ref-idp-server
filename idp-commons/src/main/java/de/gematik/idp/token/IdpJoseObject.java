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

import static de.gematik.idp.field.ClaimName.AUTHENTICATION_CERTIFICATE;
import static de.gematik.idp.field.ClaimName.EXPIRES_AT;
import static de.gematik.idp.field.ClaimName.ISSUED_AT;
import static de.gematik.idp.field.ClaimName.SCOPE;
import static de.gematik.idp.field.ClaimName.X509_CERTIFICATE_CHAIN;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import de.gematik.idp.crypto.CryptoLoader;
import de.gematik.idp.field.ClaimName;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import lombok.RequiredArgsConstructor;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;

@RequiredArgsConstructor
public abstract class IdpJoseObject {

  private final String rawString;
  private Map<String, Object> headerClaims;
  private Map<String, Object> bodyClaims;

  public abstract Map<String, Object> extractHeaderClaims();

  public Map<String, Object> getHeaderClaims() {
    if (headerClaims == null) {
      headerClaims = extractHeaderClaims();
    }
    return headerClaims;
  }

  public abstract Map<String, Object> extractBodyClaims();

  public Map<String, Object> getBodyClaims() {
    if (bodyClaims == null) {
      bodyClaims = extractBodyClaims();
    }
    return bodyClaims;
  }

  public ZonedDateTime getExpiresAt() {
    return getDateTimeClaim(EXPIRES_AT, this::getBodyClaims).orElseThrow();
  }

  public boolean isExpired() {
    return ZonedDateTime.now().isAfter(getExpiresAt());
  }

  public ZonedDateTime getExpiresAtBody() {
    return getBodyClaimAsZonedDateTime(EXPIRES_AT).orElseThrow();
  }

  public ZonedDateTime getIssuedAt() {
    return getBodyClaimAsZonedDateTime(ISSUED_AT).orElseThrow();
  }

  private Optional<ZonedDateTime> getBodyClaimAsZonedDateTime(final ClaimName claimName) {
    return getBodyClaims().entrySet().stream()
        .filter(entry -> claimName.getJoseName().equals(entry.getKey()))
        .map(Map.Entry::getValue)
        .map(TokenClaimExtraction::claimToZonedDateTime)
        .findAny();
  }

  public Set<String> getScopesBodyClaim() {
    return Optional.ofNullable(getBodyClaims().get(SCOPE.getJoseName()))
        .filter(String.class::isInstance)
        .map(String.class::cast)
        .stream()
        .flatMap(value -> Stream.of(value.split(" ")))
        .collect(Collectors.toSet());
  }

  public Optional<String> getStringBodyClaim(final ClaimName claimName) {
    return Optional.ofNullable(getBodyClaims().get(claimName.getJoseName()))
        .filter(String.class::isInstance)
        .map(String.class::cast);
  }

  public Optional<ZonedDateTime> getBodyDateTimeClaim(final ClaimName claimName) {
    return getDateTimeClaim(claimName, this::getBodyClaims);
  }

  public Optional<ZonedDateTime> getHeaderDateTimeClaim(final ClaimName claimName) {
    return getDateTimeClaim(claimName, this::getHeaderClaims);
  }

  public Optional<ZonedDateTime> getDateTimeClaim(
      final ClaimName claimName, final Supplier<Map<String, Object>> claims) {
    return Optional.ofNullable(claims.get().get(claimName.getJoseName()))
        .filter(Long.class::isInstance)
        .map(Long.class::cast)
        .map(TokenClaimExtraction::claimToZonedDateTime);
  }

  public String getHeaderDecoded() {
    final String[] split = getRawString().split("\\.");
    if (split.length < 2) {
      throw new IllegalStateException(
          "Could not retrieve Header: only found " + split.length + " parts!");
    }
    return StringUtils.newStringUtf8(Base64.decodeBase64(split[0]));
  }

  public String getPayloadDecoded() {
    final String[] split = getRawString().split("\\.");
    if (split.length < 2) {
      throw new IllegalStateException(
          "Could not retrieve Body: only found " + split.length + " parts!");
    }
    return StringUtils.newStringUtf8(Base64.decodeBase64(split[1]));
  }

  public Optional<Object> getBodyClaim(final ClaimName claimName) {
    return Optional.ofNullable(getBodyClaims().get(claimName.getJoseName()))
        .filter(Objects::nonNull);
  }

  public Optional<Object> getHeaderClaim(final ClaimName claimName) {
    return Optional.ofNullable(getHeaderClaims().get(claimName.getJoseName()))
        .filter(Objects::nonNull);
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

  public Optional<X509Certificate> getAuthenticationCertificate() {
    return getStringBodyClaim(AUTHENTICATION_CERTIFICATE)
        .map(java.util.Base64.getUrlDecoder()::decode)
        .map(CryptoLoader::getCertificateFromPem);
  }

  public Optional<JsonWebToken> getNestedJwtForClaimName(final ClaimName claimName) {
    return getStringBodyClaim(claimName)
        .filter(String.class::isInstance)
        .map(String.class::cast)
        .filter(org.apache.commons.lang3.StringUtils::isNotBlank)
        .map(JsonWebToken::new);
  }

  public String getRawString() {
    return rawString;
  }

  public static class Serializer extends JsonSerializer<IdpJoseObject> {

    @Override
    public void serialize(
        final IdpJoseObject value, final JsonGenerator gen, final SerializerProvider serializers)
        throws IOException {
      gen.writeString(value.getRawString());
    }
  }
}
