/*
 * Copyright (c) 2022 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.idp.data;

import com.fasterxml.jackson.annotation.JsonProperty;
import de.gematik.idp.crypto.exceptions.IdpCryptoException;
import java.security.cert.X509Certificate;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.jose4j.keys.BigEndianBigInteger;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class IdpEccKeyDescriptor extends IdpKeyDescriptor {

  @JsonProperty("crv")
  private String eccCurveName;

  @JsonProperty("x")
  private String eccPointXValue;

  @JsonProperty("y")
  private String eccPointYValue;

  @Builder
  public IdpEccKeyDescriptor(
      final String[] x5c,
      final String publicKeyUse,
      final String keyId,
      final String keyType,
      final String eccCurveName,
      final String eccPointXValue,
      final String eccPointYValue) {
    super(x5c, publicKeyUse, keyId, keyType);
    this.eccCurveName = eccCurveName;
    this.eccPointXValue = eccPointXValue;
    this.eccPointYValue = eccPointYValue;
  }

  public static IdpKeyDescriptor constructFromX509Certificate(
      final X509Certificate certificate, final String keyId, final boolean addX5C) {
    try {
      final IdpEccKeyDescriptor.IdpEccKeyDescriptorBuilder descriptorBuilder =
          IdpEccKeyDescriptor.builder().keyId(keyId).keyType(getKeyType(certificate));
      if (addX5C) {
        descriptorBuilder.x5c(getCertArray(certificate));
      }

      final BCECPublicKey bcecPublicKey = (BCECPublicKey) (certificate.getPublicKey());
      String eccCurveName = "";
      if (((ECNamedCurveParameterSpec) bcecPublicKey.getParameters())
          .getName()
          .equals("brainpoolP256r1")) {
        eccCurveName = "BP-256";
      } else if (((ECNamedCurveParameterSpec) bcecPublicKey.getParameters())
          .getName()
          .equals("prime256v1")) {
        eccCurveName = "P-256";
      } else {
        throw new IdpCryptoException(
            "Unknown Key-Format encountered: '"
                + ((ECNamedCurveParameterSpec) bcecPublicKey.getParameters()).getName()
                + "'!");
      }

      final ECPoint generator = bcecPublicKey.getQ();
      descriptorBuilder
          .eccCurveName(eccCurveName)
          .eccPointXValue(
              BigEndianBigInteger.toBase64Url(generator.getAffineXCoord().toBigInteger()))
          .eccPointYValue(
              BigEndianBigInteger.toBase64Url(generator.getAffineYCoord().toBigInteger()));

      return descriptorBuilder.build();
    } catch (final ClassCastException e) {
      throw new IdpCryptoException("Unknown Key-Format encountered!", e);
    }
  }
}
