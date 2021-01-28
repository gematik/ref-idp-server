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
import static de.gematik.idp.crypto.KeyAnalysis.isEcKey;
import static de.gematik.idp.field.ClaimName.*;
import static org.jose4j.jws.AlgorithmIdentifiers.RSA_PSS_USING_SHA256;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.crypto.Nonce;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.exceptions.IdpJoseException;
import de.gematik.idp.token.JsonWebToken;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NonNull;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;

@Data
@AllArgsConstructor
@Builder
public class AuthenticationChallengeBuilder {

    private static final long CHALLENGE_TOKEN_VALIDITY_IN_MINUTES = 5;
    private static final int NONCE_BYTE_AMOUNT = 32;
    private final PkiIdentity authenticationIdentity;
    private final String uriIdpServer;

    public AuthenticationChallenge buildAuthenticationChallenge(
        final String clientId,
        final String state,
        final String redirect,
        final String code, final String scope, final String nonce) {
        final JwtClaims claims = new JwtClaims();
        claims.setIssuer(uriIdpServer);

        final ZonedDateTime now = ZonedDateTime.now();
        claims.setClaim(EXPIRES_AT.getJoseName(), now.plusMinutes(CHALLENGE_TOKEN_VALIDITY_IN_MINUTES).toEpochSecond());
        claims.setClaim(ISSUED_AT.getJoseName(), now.toEpochSecond());
        claims.setClaim(RESPONSE_TYPE.getJoseName(), "code");
        claims.setClaim(SCOPE.getJoseName(), scope);
        claims.setClaim(CLIENT_ID.getJoseName(), clientId);
        claims.setClaim(STATE.getJoseName(), state);
        claims.setClaim(REDIRECT_URI.getJoseName(), redirect);
        claims.setClaim(CODE_CHALLENGE_METHOD.getJoseName(), "S256");
        claims.setClaim(CODE_CHALLENGE.getJoseName(), code);
        claims.setClaim(TOKEN_TYPE.getJoseName(), "challenge");
        if (nonce != null) {
            claims.setClaim(NONCE.getJoseName(), nonce);
        }
        claims.setClaim(SERVER_NONCE.getJoseName(), new Nonce().getNonceAsBase64(NONCE_BYTE_AMOUNT));

        final Map<String, Object> headerClaims = new HashMap<>();
        headerClaims.put(TYPE.getJoseName(), "JWT");
        headerClaims
            .put(EXPIRES_AT.getJoseName(), now.plusMinutes(CHALLENGE_TOKEN_VALIDITY_IN_MINUTES).toEpochSecond());
        headerClaims.put(JWT_ID.getJoseName(), new Nonce().getNonceAsHex(IdpConstants.JTI_LENGTH));

        return AuthenticationChallenge.builder()
            .challenge(buildJwt(claims.toJson(), headerClaims))
            .userConsent(Arrays.asList(GIVEN_NAME, FAMILY_NAME, ORGANIZATION_NAME
                , PROFESSION_OID, ID_NUMBER))
            .build();
    }

    private JsonWebToken buildJwt(final String payload, @NonNull final Map<String, Object> headerClaims) {
        final JsonWebSignature jws = new JsonWebSignature();

        jws.setPayload(payload);
        jws.setKey(authenticationIdentity.getPrivateKey());
        if (isEcKey(authenticationIdentity.getCertificate().getPublicKey())) {
            jws.setAlgorithmHeaderValue(BRAINPOOL256_USING_SHA256);
        } else {
            jws.setAlgorithmHeaderValue(RSA_PSS_USING_SHA256);
        }
        headerClaims.keySet().forEach(key -> jws.setHeader(key, headerClaims.get(key)));

        try {
            return new JsonWebToken(jws.getCompactSerialization());
        } catch (final JoseException e) {
            throw new IdpJoseException(e);
        }
    }
}
