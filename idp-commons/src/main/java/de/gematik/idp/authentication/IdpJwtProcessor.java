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

package de.gematik.idp.authentication;

import de.gematik.idp.crypto.exceptions.IdpCryptoException;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.exceptions.IdpJoseException;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.token.JsonWebToken;
import lombok.NonNull;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static de.gematik.idp.brainPoolExtension.BrainpoolAlgorithmSuiteIdentifiers.BRAINPOOL256_USING_SHA256;

public class IdpJwtProcessor {

    private final X509Certificate certificate;
    private final String algorithm;
    private Optional<String> keyId;
    private PrivateKey privateKey;

    public IdpJwtProcessor(@NonNull final PkiIdentity identity) {
        this(identity.getCertificate());
        privateKey = identity.getPrivateKey();
        keyId = identity.getKeyId();
    }

    public IdpJwtProcessor(@NonNull final X509Certificate certificate) {
        this.certificate = certificate;
        if (certificate.getPublicKey() instanceof ECPublicKey) {
            if (((ECPublicKey) certificate.getPublicKey()).getParams() instanceof ECNamedCurveSpec
                    && ((ECNamedCurveSpec) ((ECPublicKey) certificate.getPublicKey()).getParams()).getName().equals("prime256v1")) {
                algorithm = "ES256";
            } else {
                algorithm = BRAINPOOL256_USING_SHA256;
            }
        } else if (certificate.getPublicKey() instanceof RSAPublicKey) {
            algorithm = AlgorithmIdentifiers.RSA_PSS_USING_SHA256;
        } else {
            throw new IdpCryptoException(
                    "Could not identify Public-Key: " + certificate.getPublicKey().getClass().toString());
        }
    }

    public JsonWebToken buildJwt(@NonNull final JwtBuilder jwtBuilder) {
        Objects.requireNonNull(privateKey, "No private key supplied, cancelling JWT signing");
        Objects.requireNonNull(jwtBuilder, "No Descriptor supplied, cancelling JWT signing");
        keyId.ifPresent(keyIdValue -> jwtBuilder.addHeaderClaim(ClaimName.KEY_ID, keyIdValue));
        return jwtBuilder
                .setSignerKey(privateKey)
                .setCertificate(certificate)
                .buildJwt();
    }

    public JsonWebToken buildJws(@NonNull final String payload, @NonNull final Map<String, Object> headerClaims,
                                 final boolean includeSignerCertificateInHeader) {
        final JsonWebSignature jws = new JsonWebSignature();

        jws.setPayload(payload);
        jws.setKey(privateKey);
        jws.setAlgorithmHeaderValue(algorithm);

        headerClaims.keySet().forEach(key -> jws.setHeader(key, headerClaims.get(key)));

        keyId.ifPresent(keyIdValue -> jws.setHeader(ClaimName.KEY_ID.getJoseName(), keyIdValue));

        if (includeSignerCertificateInHeader) {
            jws.setCertificateChainHeaderValue(certificate);
        }

        try {
            return new JsonWebToken(jws.getCompactSerialization());
        } catch (final JoseException e) {
            throw new IdpJoseException(e);
        }
    }

    public void verifyAndThrowExceptionIfFail(@NonNull final JsonWebToken jwt) {
        jwt.verify(certificate.getPublicKey());
    }

    public String getHeaderDecoded(@NonNull final JsonWebToken jwt) {
        return jwt.getHeaderDecoded();
    }

    public String getPayloadDecoded(@NonNull final JsonWebToken jwt) {
        return jwt.getPayloadDecoded();
    }
}
