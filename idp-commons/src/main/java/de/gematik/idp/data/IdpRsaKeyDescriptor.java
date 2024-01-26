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

import com.fasterxml.jackson.annotation.JsonProperty;
import de.gematik.idp.crypto.exceptions.IdpCryptoException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class IdpRsaKeyDescriptor extends IdpKeyDescriptor {

  @JsonProperty("n")
  private String rsaModulusValue;

  @JsonProperty("e")
  private String rsaExponentValue;

  @Builder
  public IdpRsaKeyDescriptor(
      final String[] x5c,
      final String publicKeyUse,
      final String keyId,
      final String keyType,
      final String rsaModulusValue,
      final String rsaExponentValue) {
    super(x5c, publicKeyUse, keyId, keyType);
    this.rsaModulusValue = rsaModulusValue;
    this.rsaExponentValue = rsaExponentValue;
  }

  public static IdpKeyDescriptor constructFromX509Certificate(
      final X509Certificate certificate, final String keyId) {
    try {
      final IdpRsaKeyDescriptor.IdpRsaKeyDescriptorBuilder descriptorBuilder =
          IdpRsaKeyDescriptor.builder().keyId(keyId).keyType(getKeyType(certificate));

      descriptorBuilder.x5c(getCertArray(certificate));

      final BCRSAPublicKey bcrsaPublicKey = (BCRSAPublicKey) certificate.getPublicKey();
      descriptorBuilder
          .rsaModulusValue(
              Base64.getUrlEncoder()
                  .withoutPadding()
                  .encodeToString(bcrsaPublicKey.getModulus().toByteArray()))
          .rsaExponentValue(
              Base64.getUrlEncoder()
                  .withoutPadding()
                  .encodeToString(bcrsaPublicKey.getPublicExponent().toByteArray()));

      return descriptorBuilder.build();
    } catch (final ClassCastException e) {
      throw new IdpCryptoException("Unknown Key-Format encountered!", e);
    }
  }
}
