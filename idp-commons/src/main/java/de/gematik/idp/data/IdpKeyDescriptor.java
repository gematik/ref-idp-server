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

package de.gematik.idp.data;

import static de.gematik.idp.crypto.KeyAnalysis.isEcKey;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.idp.crypto.exceptions.IdpCryptoException;
import de.gematik.idp.exceptions.IdpJoseException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.jose4j.json.internal.json_simple.JSONAware;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;

@Getter
@Setter
@EqualsAndHashCode
@NoArgsConstructor
@AllArgsConstructor
public class IdpKeyDescriptor implements JSONAware {

  @JsonInclude(Include.NON_NULL)
  private String[] x5c;

  @JsonInclude(Include.NON_NULL)
  @JsonProperty("use")
  private String publicKeyUse;

  @JsonProperty("kid")
  private String keyId;

  @JsonProperty("kty")
  private String keyType;

  public static String[] getCertArray(final X509Certificate certificate) {
    try {
      return new String[] {Base64.getEncoder().encodeToString(certificate.getEncoded())};
    } catch (final CertificateEncodingException e) {
      throw new IdpCryptoException("Error while retrieving key information", e);
    }
  }

  public static IdpKeyDescriptor constructFromX509Certificate(
      final X509Certificate certificate, final String keyId) {
    return constructFromX509Certificate(certificate, keyId, true);
  }

  public static IdpKeyDescriptor constructFromX509Certificate(
      final X509Certificate certificate, final String keyId, final boolean addX5C) {
    if (isEcKey(certificate.getPublicKey())) {
      return IdpEccKeyDescriptor.constructFromX509Certificate(certificate, keyId, addX5C);
    } else {
      return IdpRsaKeyDescriptor.constructFromX509Certificate(certificate, keyId);
    }
  }

  public static IdpKeyDescriptor createFromPublicKey(
      final PublicKey publicKey, final String keyId) {

    if (isEcKey(publicKey)) {
      return IdpEccKeyDescriptor.createFromPublicKey(publicKey, keyId);
    } else {
      throw new IdpCryptoException("Unknown Key-Format encountered!");
    }
  }

  public static String getKeyType(final X509Certificate certificate) {
    return getKeyType(certificate.getPublicKey());
  }

  public static String getKeyType(final PublicKey publicKey) {
    if (isEcKey(publicKey)) {
      return EllipticCurveJsonWebKey.KEY_TYPE;
    } else {
      return RsaJsonWebKey.KEY_TYPE;
    }
  }

  @Override
  public String toJSONString() {
    try {
      final ObjectMapper objectMapper = new ObjectMapper();
      objectMapper.setSerializationInclusion(Include.NON_NULL);
      return objectMapper.writeValueAsString(this);
    } catch (final JsonProcessingException e) {
      throw new IdpJoseException("Error during Claim serialization", e);
    }
  }
}
