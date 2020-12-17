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

package de.gematik.idp.token;

import static de.gematik.idp.field.ClaimName.*;

import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.authentication.JwtDescription;
import de.gematik.idp.brainPoolExtension.BrainpoolAlgorithmSuiteIdentifiers;
import de.gematik.idp.crypto.Nonce;
import de.gematik.idp.crypto.X509ClaimExtraction;
import de.gematik.idp.data.IdpJwksDocument;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.HashMap;
import java.util.Map;
import lombok.Data;

@Data
public class SsoTokenBuilder {

    private final IdpJwtProcessor jwtProcessor;
    private static final int JTI_LENGTH = 16;

    public JsonWebToken buildSsoToken(final X509Certificate certificate, final ZonedDateTime issuingTime) {
        final Map<String, Object> bodyClaimsMap = new HashMap<>();
        final Map<String, Object> headerClaimsMap = new HashMap<>();
        headerClaimsMap.put(ALGORITHM.getJoseName(), BrainpoolAlgorithmSuiteIdentifiers.BRAINPOOL256_USING_SHA256);
        headerClaimsMap.put(TYPE.getJoseName(), "application/jwt");
        headerClaimsMap.put(JWT_ID.getJoseName(), new Nonce().getNonceAsHex(JTI_LENGTH));
        bodyClaimsMap.put(CONFIRMATION.getJoseName(), IdpJwksDocument.constructFromX509Certificate(certificate));
        bodyClaimsMap.put(ISSUER.getJoseName(), certificate.getIssuerX500Principal().getName());
        bodyClaimsMap.put(ISSUED_AT.getJoseName(), issuingTime.toEpochSecond());
        bodyClaimsMap.put(NOT_BEFORE.getJoseName(), issuingTime.toEpochSecond());
        bodyClaimsMap.put(AUTH_TIME.getJoseName(), issuingTime.toEpochSecond());

        bodyClaimsMap.putAll(X509ClaimExtraction.extractClaimsFromCertificate(certificate));
        return jwtProcessor.buildJwt(JwtDescription.builder()
            .headers(headerClaimsMap)
            .claims(bodyClaimsMap)
            .expiresAt(issuingTime.plusMinutes(5))
            .build());
    }
}
