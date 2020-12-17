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

package de.gematik.idp.authentication;

import de.gematik.idp.crypto.Nonce;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.exceptions.IdpJoseException;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;

import java.time.ZonedDateTime;
import java.util.Arrays;

import static de.gematik.idp.brainPoolExtension.BrainpoolAlgorithmSuiteIdentifiers.BRAINPOOL256_USING_SHA256;
import static de.gematik.idp.crypto.KeyAnalysis.isEcKey;
import static de.gematik.idp.field.ClaimName.*;
import static org.jose4j.jws.AlgorithmIdentifiers.RSA_PSS_USING_SHA256;

@Data
@AllArgsConstructor
@Builder
public class AuthenticationChallengeBuilder {

    private static final long CHALLENGE_TOKEN_VALIDITY_IN_MINUTES = 5;
    private final PkiIdentity authenticationIdentity;
    private static final int NONCE_BYTE_AMOUNT = 32;
    private static final int JTI_LENGTH = 16;

    public AuthenticationChallenge buildAuthenticationChallenge(
            final String clientId,
            final String state,
            final String redirect,
            final String code) {
        //TODO die folgenden claims sind Platzhalter. Hier müssen die tatsächlichen Parameter eingebaut werden
        final JwtClaims claims = new JwtClaims();
        claims.setIssuer("sender");
        claims.setAudience("erp.zentral.erp.ti-dienste.de");
        claims.setClaim(EXPIRES_AT.getJoseName(),
                ZonedDateTime.now().plusMinutes(CHALLENGE_TOKEN_VALIDITY_IN_MINUTES).toEpochSecond());
        claims.setClaim(ISSUED_AT.getJoseName(), ZonedDateTime.now().toEpochSecond());
        claims.setClaim(NOT_BEFORE.getJoseName(), ZonedDateTime.now().toEpochSecond());
        claims.setSubject("subject");
        claims.setClaim(RESPONSE_TYPE.getJoseName(), "code");
        claims.setClaim(SCOPE.getJoseName(), "openid e-rezept");
        claims.setClaim(CLIENT_ID.getJoseName(), clientId);
        claims.setClaim(STATE.getJoseName(), state);
        claims.setClaim(REDIRECT_URI.getJoseName(), redirect);
        claims.setClaim(CODE_CHALLENGE_METHOD.getJoseName(), "S256");
        claims.setClaim(CODE_CHALLENGE.getJoseName(), code);
        return AuthenticationChallenge.builder()
                .challenge(buildJwt(claims.toJson()))
                .userConsent(Arrays.asList(GIVEN_NAME, FAMILY_NAME, ORGANIZATION_NAME
                        , PROFESSION_OID, ID_NUMBER))
                .build();
    }

    private String buildJwt(final String payload) {
        final JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(payload);
        jws.setKey(authenticationIdentity.getPrivateKey());
        if (isEcKey(authenticationIdentity.getCertificate().getPublicKey())) {
            jws.setAlgorithmHeaderValue(BRAINPOOL256_USING_SHA256);
        } else {
            jws.setAlgorithmHeaderValue(RSA_PSS_USING_SHA256);
        }
        jws.setHeader(NONCE.getJoseName(), new Nonce().getNonceAsBase64(NONCE_BYTE_AMOUNT));
        jws.setHeader(TYPE.getJoseName(), "JWT");
        final ZonedDateTime zdtNow = ZonedDateTime.now();
        jws.setHeader(JWT_ID.getJoseName(), new Nonce().getNonceAsHex(JTI_LENGTH));

        try {
            return jws.getCompactSerialization();
        } catch (final JoseException e) {
            throw new IdpJoseException(e);
        }
    }
}
