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

import static de.gematik.idp.field.ClaimName.EXPIRES_AT;
import static de.gematik.idp.field.ClaimName.NESTED_JWT;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import de.gematik.idp.exceptions.IdpJoseException;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.token.IdpJwe.Deserializer;
import java.io.IOException;
import java.security.Key;
import java.security.PublicKey;
import java.time.ZonedDateTime;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Consumer;
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
@JsonDeserialize(using = Deserializer.class)
public class IdpJwe extends IdpJoseObject {

  private Key decryptionKey;

  public IdpJwe(final String rawString) {
    super(rawString);
  }

  public static IdpJwe createWithPayloadAndEncryptWithKey(
      final String payload, final Key key, final String contentType) {
    return createWithPayloadAndExpiryAndEncryptWithKey(payload, Optional.empty(), key, contentType);
  }

  /**
   * @deprecated This method will be removed in the next release.
   *     <p>Use {@link #createJweWithPayloadAndHeaders(String,Key, Consumer<JsonWebEncryption>)}
   *     instead.
   */
  @Deprecated(since = "24.1.0", forRemoval = true)
  public static IdpJwe createWithPayloadAndExpiryAndEncryptWithKey(
      final String payload,
      final Optional<ZonedDateTime> expiryOptional,
      final Key key,
      final String contentType) {
    final JsonWebEncryption jwe = new JsonWebEncryption();
    jwe.setPlaintext(payload);
    configureKeyForJwe(key, jwe);
    expiryOptional
        .map(TokenClaimExtraction::zonedDateTimeToClaim)
        .ifPresent(expValue -> jwe.setHeader(ClaimName.EXPIRES_AT.getJoseName(), expValue));
    jwe.setHeader(ClaimName.CONTENT_TYPE.getJoseName(), contentType);

    try {
      return new IdpJwe(jwe.getCompactSerialization());
    } catch (final JoseException e) {
      throw new IdpJoseException("Error during token encryption", e);
    }
  }

  public static IdpJwe createJweWithPayloadAndHeaders(
      final String payload, final Key key, final Consumer<JsonWebEncryption> setHeaderOperator) {
    final JsonWebEncryption jwe = new JsonWebEncryption();
    jwe.setPlaintext(payload);
    configureKeyForJwe(key, jwe);
    setHeaderOperator.accept(jwe);
    try {
      return new IdpJwe(jwe.getCompactSerialization());
    } catch (final JoseException e) {
      throw new IdpJoseException("Error during token encryption", e);
    }
  }

  private static void configureKeyForJwe(final Key key, final JsonWebEncryption jwe) {
    if (key instanceof PublicKey) {
      jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.ECDH_ES);
    } else {
      jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.DIRECT);
    }
    jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_256_GCM);
    jwe.setKey(key);
  }

  public JsonWebToken decryptNestedJwt(final Key key) {
    setDecryptionKey(key);
    return new JsonWebToken(
        getStringBodyClaim(NESTED_JWT)
            .orElseThrow(() -> new IdpJoseException("Could not find njwt")));
  }

  public JsonWebToken decryptJwt(final Key key) {
    setDecryptionKey(key);
    return new JsonWebToken(decryptJweAndReturnPayloadString(key));
  }

  @Override
  public ZonedDateTime getExpiresAt() {
    return getDateTimeClaim(EXPIRES_AT, this::getHeaderClaims).orElseThrow();
  }

  public String decryptJweAndReturnPayloadString(final Key key) {
    final JsonWebEncryption receiverJwe = new JsonWebEncryption();

    receiverJwe.setAlgorithmConstraints(
        new AlgorithmConstraints(
            ConstraintType.PERMIT,
            KeyManagementAlgorithmIdentifiers.DIRECT,
            KeyManagementAlgorithmIdentifiers.ECDH_ES));
    receiverJwe.setContentEncryptionAlgorithmConstraints(
        new AlgorithmConstraints(
            ConstraintType.PERMIT, ContentEncryptionAlgorithmIdentifiers.AES_256_GCM));

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

  public IdpJwe setDecryptionKey(final Key decryptionKey) {
    this.decryptionKey = decryptionKey;
    return this;
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

  public static class Deserializer extends JsonDeserializer<IdpJoseObject> {

    @Override
    public IdpJoseObject deserialize(final JsonParser p, final DeserializationContext ctxt)
        throws IOException {
      return new IdpJwe(ctxt.readValue(p, String.class));
    }
  }
}
