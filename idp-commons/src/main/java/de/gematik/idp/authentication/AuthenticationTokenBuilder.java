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

import static de.gematik.idp.field.ClaimName.*;

import de.gematik.idp.crypto.CryptoLoader;
import de.gematik.idp.crypto.X509ClaimExtraction;
import de.gematik.idp.exceptions.IdpJoseException;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.token.JsonWebToken;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@AllArgsConstructor
@Builder
public class AuthenticationTokenBuilder {

    public static final String EIDAS_LOA_HIGH = "eidas-loa-high";

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
        claimsMap.put(AUTHENTICATION_CONTEXT_CLASS.getJoseName(), EIDAS_LOA_HIGH);
        claimsMap.put(CLIENT_ID.getJoseName(), "client_id");
        claimsMap.put(REDIRECT_URI.getJoseName(), "redirect_uri");
        claimsMap.put(ISSUED_AT.getJoseName(), issueingTime.toEpochSecond());
        claimsMap.put(NOT_BEFORE.getJoseName(), issueingTime.toEpochSecond());
        claimsMap.putAll(serverChallengeClaims);
        claimsMap.put(AUTH_TIME.getJoseName(), issueingTime.toEpochSecond());
        return jwtProcessor.buildJwt(JwtDescription.builder()
            .claims(claimsMap)
            .expiresAt(ZonedDateTime.now().plusHours(1))
            .build());
    }

    public JsonWebToken buildAuthenticationTokenFromSsoToken(final JsonWebToken ssoToken,
        final JsonWebToken challengeToken) {
        final X509Certificate confirmationCertificate = extractConfirmationCertificate(ssoToken);

        final Map<String, Object> claimsMap = new HashMap<>();

        claimsMap.putAll(X509ClaimExtraction.extractClaimsFromCertificate(confirmationCertificate));

        claimsMap.put(CODE_CHALLENGE.getJoseName(), extractClaimFromChallengeToken(challengeToken, CODE_CHALLENGE));
        claimsMap.put(CODE_CHALLENGE_METHOD.getJoseName(),
            extractClaimFromChallengeToken(challengeToken, CODE_CHALLENGE_METHOD));
        claimsMap.put(CLIENT_ID.getJoseName(), extractClaimFromChallengeToken(challengeToken, CLIENT_ID));
        claimsMap.put(REDIRECT_URI.getJoseName(), extractClaimFromChallengeToken(challengeToken, REDIRECT_URI));
        claimsMap.put(SCOPE.getJoseName(), extractClaimFromChallengeToken(challengeToken, SCOPE));

        claimsMap.put(AUTHENTICATION_CONTEXT_CLASS.getJoseName(), EIDAS_LOA_HIGH);
        claimsMap.put(AUTH_TIME.getJoseName(), ZonedDateTime.now().toEpochSecond());

        return jwtProcessor.buildJwt(JwtDescription.builder()
            .headers(ssoToken.getHeaderClaims())
            .claims(claimsMap)
            .expiresAt(ZonedDateTime.now().plusHours(1))
            .build());
    }

    private Object extractClaimFromChallengeToken(final JsonWebToken challengeToken, final ClaimName claimName) {
        return challengeToken.getBodyClaim(claimName)
            .orElseThrow(() -> new IdpJoseException("Unexpected structure in Challenge-Token"));
    }

    private X509Certificate extractConfirmationCertificate(final JsonWebToken ssoToken) {
        final String certString = ssoToken.getBodyClaim(ClaimName.CONFIRMATION)

            .filter(Map.class::isInstance)
            .map(Map.class::cast)
            .map(map -> map.get("keys"))

            .filter(List.class::isInstance)
            .map(List.class::cast)
            .filter(list -> !list.isEmpty())
            .map(list -> list.get(0))

            .filter(Map.class::isInstance)
            .map(Map.class::cast)
            .map(map -> map.get(ClaimName.X509_Certificate_Chain.getJoseName()))

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
