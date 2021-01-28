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

import static de.gematik.idp.field.ClaimName.*;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.crypto.CryptoLoader;
import de.gematik.idp.crypto.Nonce;
import de.gematik.idp.crypto.X509ClaimExtraction;
import de.gematik.idp.exceptions.IdpJoseException;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.token.JsonWebToken;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.*;
import java.util.stream.Collectors;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import org.apache.commons.lang3.RandomStringUtils;

@Data
@AllArgsConstructor
@Builder
public class AuthenticationTokenBuilder {

    private final IdpJwtProcessor jwtProcessor;
    private final AuthenticationChallengeVerifier authenticationChallengeVerifier;
    private final Set<String> authenticationTokenClaimsWhitelist = Set.of(
        RESPONSE_TYPE, SCOPE, CLIENT_ID, STATE, REDIRECT_URI, CODE_CHALLENGE, CODE_CHALLENGE_METHOD
    ).stream().map(ClaimName::getJoseName).collect(Collectors.toSet());

    public JsonWebToken buildAuthenticationToken(
        final X509Certificate clientCertificate,
        final Map<String, Object> serverChallengeClaims,
        final ZonedDateTime issueingTime) {
        final Map<String, Object> claimsMap = X509ClaimExtraction.extractClaimsFromCertificate(clientCertificate);
        claimsMap.put(CLIENT_ID.getJoseName(), IdpConstants.CLIENT_ID);
        claimsMap.put(REDIRECT_URI.getJoseName(), serverChallengeClaims.get(REDIRECT_URI.getJoseName()));
        claimsMap.put(NONCE.getJoseName(), serverChallengeClaims.get(NONCE.getJoseName()));
        claimsMap.put(CODE_CHALLENGE.getJoseName(), serverChallengeClaims.get(CODE_CHALLENGE.getJoseName()));
        claimsMap
            .put(CODE_CHALLENGE_METHOD.getJoseName(), serverChallengeClaims.get(CODE_CHALLENGE_METHOD.getJoseName()));
        claimsMap.put(ISSUER.getJoseName(), serverChallengeClaims.get(ISSUER.getJoseName()));
        claimsMap.put(RESPONSE_TYPE.getJoseName(), serverChallengeClaims.get(RESPONSE_TYPE.getJoseName()));
        claimsMap.put(STATE.getJoseName(), serverChallengeClaims.get(STATE.getJoseName()));
        claimsMap.put(SCOPE.getJoseName(), serverChallengeClaims.get(SCOPE.getJoseName()));
        claimsMap.put(ISSUED_AT.getJoseName(), issueingTime.toEpochSecond());
        claimsMap.put(NOT_BEFORE.getJoseName(), issueingTime.toEpochSecond());
        claimsMap.put(TOKEN_TYPE.getJoseName(), "code");
        claimsMap.put(AUTH_TIME.getJoseName(), issueingTime.toEpochSecond());
        claimsMap.put(SERVER_NONCE.getJoseName(), RandomStringUtils.randomAlphanumeric(20));

        final Map<String, Object> headerMap = new HashMap<>();
        headerMap.put(TYPE.getJoseName(), "JWT");
        headerMap.put(JWT_ID.getJoseName(), new Nonce().getNonceAsHex(IdpConstants.JTI_LENGTH));

        return jwtProcessor.buildJwt(new JwtBuilder()
            .addAllBodyClaims(claimsMap)
            .addAllHeaderClaims(headerMap)
            .expiresAt(issueingTime.plusHours(1)));
    }

    public JsonWebToken buildAuthenticationTokenFromSsoToken(final JsonWebToken ssoToken,
        final JsonWebToken challengeToken) {
        final X509Certificate confirmationCertificate = extractConfirmationCertificate(ssoToken);

        final Map<String, Object> claimsMap = new HashMap<>();

        claimsMap.putAll(X509ClaimExtraction.extractClaimsFromCertificate(confirmationCertificate));

        claimsMap.put(CODE_CHALLENGE.getJoseName(), extractClaimFromChallengeToken(challengeToken, CODE_CHALLENGE));
        claimsMap.put(CODE_CHALLENGE_METHOD.getJoseName(),
            extractClaimFromChallengeToken(challengeToken, CODE_CHALLENGE_METHOD));
        claimsMap.put(NONCE.getJoseName(), extractClaimFromChallengeToken(challengeToken, NONCE));
        claimsMap.put(CLIENT_ID.getJoseName(), extractClaimFromChallengeToken(challengeToken, CLIENT_ID));
        claimsMap.put(REDIRECT_URI.getJoseName(), extractClaimFromChallengeToken(challengeToken, REDIRECT_URI));
        claimsMap.put(SCOPE.getJoseName(), extractClaimFromChallengeToken(challengeToken, SCOPE));
        claimsMap.put(STATE.getJoseName(), extractClaimFromChallengeToken(challengeToken, STATE));
        claimsMap.put(RESPONSE_TYPE.getJoseName(), extractClaimFromChallengeToken(challengeToken, RESPONSE_TYPE));
        claimsMap.put(TOKEN_TYPE.getJoseName(), "code");
        claimsMap.put(AUTH_TIME.getJoseName(), ZonedDateTime.now().toEpochSecond());
        claimsMap.put(SERVER_NONCE.getJoseName(), RandomStringUtils.randomAlphanumeric(20));
        claimsMap.put(ISSUER.getJoseName(), extractClaimFromChallengeToken(challengeToken, ISSUER));

        final HashMap headerClaims = new HashMap(ssoToken.getHeaderClaims());
        headerClaims.put(TYPE.getJoseName(), "JWT");
        headerClaims.put(JWT_ID.getJoseName(), new Nonce().getNonceAsHex(IdpConstants.JTI_LENGTH));

        return jwtProcessor.buildJwt(new JwtBuilder()
            .replaceAllHeaderClaims(headerClaims)
            .replaceAllBodyClaims(claimsMap)
            .expiresAt(ZonedDateTime.now().plusHours(1)));
    }

    private Object extractClaimFromChallengeToken(final JsonWebToken challengeToken, final ClaimName claimName) {
        return challengeToken.getBodyClaim(claimName)
            .orElseThrow(() -> new IdpJoseException("Unexpected structure in Challenge-Token"));
    }

    private X509Certificate extractConfirmationCertificate(final JsonWebToken ssoToken) {
        final String certString = ssoToken.getBodyClaim(ClaimName.CONFIRMATION)

            .filter(Map.class::isInstance)
            .map(Map.class::cast)
            .map(map -> map.get(ClaimName.X509_CERTIFICATE_CHAIN.getJoseName()))

            .filter(List.class::isInstance)
            .map(List.class::cast)
            .filter(list -> !list.isEmpty())
            .map(list -> list.get(0))

            .map(Object::toString)

            .orElseThrow(() -> new IdpJoseException(
                "Unsupported cnf-Structure found: Could not extract confirmed Certificate!"));

        final byte[] decode = Base64.getDecoder().decode(certString);

        return CryptoLoader.getCertificateFromPem(decode);
    }
}
