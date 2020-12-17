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

package de.gematik.idp.data;

import static de.gematik.idp.crypto.KeyAnalysis.isEcKey;

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.idp.brainPoolExtension.BrainpoolCurves;
import de.gematik.idp.crypto.exceptions.IdpCryptoException;
import de.gematik.idp.exceptions.IdpJoseException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.jose4j.json.internal.json_simple.JSONAware;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;

@AllArgsConstructor
@NoArgsConstructor
@Builder
@Data
public class IdpJwksDocument implements JSONAware {

    {
        BrainpoolCurves.init();
    }

    private IdpKeyDescriptor[] keys;

    private static String[] getCertArray(final X509Certificate certificate) {
        try {
            return new String[]{
                Base64.getEncoder().encodeToString(
                    certificate.getEncoded())};
        } catch (final CertificateEncodingException e) {
            throw new IdpCryptoException("Error while retrieving key information", e);
        }
    }

    public static IdpJwksDocument constructFromX509Certificate(final X509Certificate certificate) {
        final IdpKeyDescriptor.IdpKeyDescriptorBuilder descriptorBuilder = IdpKeyDescriptor.builder()
            .x5c(getCertArray(certificate))
            .keyId(certificate.getSerialNumber().toString())
            .keyType(getKeyType(certificate));
        if (isEcKey(certificate.getPublicKey())) {
            fillBuilderWithEccProperties(descriptorBuilder, certificate);
        } else {
            fillBuilderWithRsaProperties(descriptorBuilder, certificate);
        }

        return IdpJwksDocument.builder()
            .keys(new IdpKeyDescriptor[]{descriptorBuilder
                .build()})
            .build();
    }

    private static String getKeyType(final X509Certificate certificate) {
        if (isEcKey(certificate.getPublicKey())) {
            return EllipticCurveJsonWebKey.KEY_TYPE;
        } else {
            return RsaJsonWebKey.KEY_TYPE;
        }
    }

    private static void fillBuilderWithRsaProperties(
        final IdpKeyDescriptor.IdpKeyDescriptorBuilder descriptorBuilder,
        final X509Certificate certificate) {
        try {
            final BCRSAPublicKey bcrsaPublicKey = (BCRSAPublicKey) certificate.getPublicKey();
            descriptorBuilder
                .rsaModulusValue(Base64.getEncoder().encodeToString(bcrsaPublicKey.getModulus().toByteArray()))
                .rsaExponentValue(Base64.getEncoder().encodeToString(bcrsaPublicKey.getPublicExponent().toByteArray()));
        } catch (final ClassCastException e) {
            throw new IdpCryptoException("Unknown Key-Format encountered!", e);
        }
    }

    private static void fillBuilderWithEccProperties(
        final IdpKeyDescriptor.IdpKeyDescriptorBuilder descriptorBuilder,
        final X509Certificate certificate) {
        try {
            final BCECPublicKey bcecPublicKey = (BCECPublicKey) (certificate.getPublicKey());
            if (((ECNamedCurveParameterSpec) bcecPublicKey.getParameters()).getName().equals("brainpoolP256r1")) {
                final ECPoint generator = bcecPublicKey.getQ();
                descriptorBuilder
                    .eccCurveName("BP-256")
                    .eccPointXValue(
                        Base64.getEncoder().encodeToString(generator.getAffineXCoord().toBigInteger().toByteArray()))
                    .eccPointYValue(
                        Base64.getEncoder().encodeToString(generator.getAffineYCoord().toBigInteger().toByteArray()));
            } else {
                throw new IdpCryptoException(
                    "Unknown Key-Format encountered: '" + ((ECNamedCurveParameterSpec) bcecPublicKey.getParameters())
                        .getName() + "'!");
            }
        } catch (final ClassCastException e) {
            throw new IdpCryptoException("Unknown Key-Format encountered!", e);
        }
    }

    @Override
    public String toJSONString() {
        try {
            final ObjectMapper objectMapper = new ObjectMapper();
            objectMapper.setSerializationInclusion(Include.NON_NULL);
            return objectMapper
                .writeValueAsString(this);
        } catch (final JsonProcessingException e) {
            throw new IdpJoseException("Error during Claim serialization", e);
        }
    }
}
