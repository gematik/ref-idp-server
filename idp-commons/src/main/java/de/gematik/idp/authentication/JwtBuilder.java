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

package de.gematik.idp.authentication;

import static de.gematik.idp.brainPoolExtension.BrainpoolAlgorithmSuiteIdentifiers.BRAINPOOL256_USING_SHA256;

import de.gematik.idp.crypto.exceptions.IdpCryptoException;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.exceptions.IdpJoseException;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.token.JsonWebToken;
import java.security.Key;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.time.ZonedDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.lang.JoseException;

@NoArgsConstructor
@AllArgsConstructor
public class JwtBuilder {

    private final Map<String, Object> headerClaims = new HashMap<>();
    private final Map<String, Object> bodyClaims = new HashMap<>();
    private Key signerKey;
    private X509Certificate certificate;
    private boolean includeSignerCertificateInHeader = false;

    public JwtBuilder replaceAllBodyClaims(final Map<String, Object> additionalClaims) {
        bodyClaims.clear();
        bodyClaims.putAll(additionalClaims);
        return this;
    }

    public JwtBuilder addAllBodyClaims(final Map<String, Object> additionalClaims) {
        bodyClaims.putAll(additionalClaims);
        return this;
    }

    public JwtBuilder replaceAllHeaderClaims(final Map<String, Object> additionalClaims) {
        headerClaims.clear();
        headerClaims.putAll(additionalClaims);
        return this;
    }

    public JwtBuilder addAllHeaderClaims(final Map<String, Object> additionalClaims) {
        headerClaims.putAll(additionalClaims);
        return this;
    }

    public JwtBuilder addHeaderClaim(final ClaimName key, final Object value) {
        headerClaims.put(key.getJoseName(), value);
        return this;
    }

    public JwtBuilder expiresAt(final ZonedDateTime exp) {
        final NumericDate expDate = NumericDate.fromSeconds(exp.toEpochSecond());
        headerClaims.put(ClaimName.EXPIRES_AT.getJoseName(), expDate.getValue());
        bodyClaims.put(ClaimName.EXPIRES_AT.getJoseName(), expDate.getValue());
        return this;
    }

    public JwtBuilder setSignerKey(final Key key) {
        signerKey = key;
        return this;
    }

    public JwtBuilder setCertificate(final X509Certificate certificate) {
        this.certificate = certificate;
        return this;
    }

    public JwtBuilder setIdentity(final PkiIdentity pkiIdentity) {
        certificate = pkiIdentity.getCertificate();
        signerKey = pkiIdentity.getPrivateKey();
        return this;
    }

    public JsonWebToken buildJwt() {
        Objects.requireNonNull(signerKey, "No private key supplied, cancelling JWT signing");

        final JwtClaims claims = new JwtClaims();
        bodyClaims.forEach((key, value) -> claims.setClaim(key, value));

        final JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(signerKey);
        jws.setAlgorithmHeaderValue(determineAlgorithm());

        for (final String key : headerClaims.keySet()) {
            jws.setHeader(key, headerClaims.get(key));
        }

        if (includeSignerCertificateInHeader) {
            if (certificate == null) {
                throw new IdpJoseException("Could not include x5c-header: certificate not set");
            }
            jws.setCertificateChainHeaderValue(certificate);
        }

        try {
            return new JsonWebToken(jws.getCompactSerialization());
        } catch (final JoseException e) {
            throw new IdpJoseException(e);
        }
    }

    private String determineAlgorithm() {
        if (signerKey instanceof ECPrivateKey) {
            return BRAINPOOL256_USING_SHA256;
        } else if (signerKey instanceof RSAPrivateKey) {
            return AlgorithmIdentifiers.RSA_PSS_USING_SHA256;
        } else {
            throw new IdpCryptoException("Could not identify Signer-Key: " + signerKey.getClass().toString());
        }
    }

    public Map<String, Object> getClaims() {
        return bodyClaims;
    }

    public JwtBuilder includeSignerCertificateInHeader(final boolean shouldInclude) {
        includeSignerCertificateInHeader = shouldInclude;
        return this;
    }
}
