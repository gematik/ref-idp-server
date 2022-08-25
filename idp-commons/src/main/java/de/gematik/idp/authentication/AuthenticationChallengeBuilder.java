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

import static de.gematik.idp.field.ClaimName.*;
import de.gematik.idp.IdpConstants;
import de.gematik.idp.crypto.Nonce;
import de.gematik.idp.data.UserConsent;
import de.gematik.idp.data.UserConsentConfiguration;
import de.gematik.idp.field.IdpScope;
import de.gematik.idp.token.JsonWebToken;
import java.time.ZonedDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import org.apache.commons.lang3.tuple.Pair;

@Data
@AllArgsConstructor
@Builder
public class AuthenticationChallengeBuilder {

    private static final long CHALLENGE_TOKEN_VALIDITY_IN_MINUTES = 3;
    private static final int NONCE_BYTE_AMOUNT = 32;
    private final IdpJwtProcessor serverSigner;
    private final String uriIdpServer;
    private final UserConsentConfiguration userConsentConfiguration;

    public AuthenticationChallenge buildAuthenticationChallenge(final String clientId, final String state,
        final String redirect, final String code, final String scope, final String nonce) {
        final Map<String, Object> claims = new HashMap<>();
        claims.put(ISSUER.getJoseName(), uriIdpServer);

        final ZonedDateTime now = ZonedDateTime.now();
        claims.put(EXPIRES_AT.getJoseName(), now.plusMinutes(CHALLENGE_TOKEN_VALIDITY_IN_MINUTES).toEpochSecond());
        claims.put(ISSUED_AT.getJoseName(), now.toEpochSecond());
        claims.put(RESPONSE_TYPE.getJoseName(), "code");
        claims.put(SCOPE.getJoseName(), scope);
        claims.put(CLIENT_ID.getJoseName(), clientId);
        claims.put(STATE.getJoseName(), state);
        claims.put(REDIRECT_URI.getJoseName(), redirect);
        claims.put(CODE_CHALLENGE_METHOD.getJoseName(), "S256");
        claims.put(CODE_CHALLENGE.getJoseName(), code);
        claims.put(TOKEN_TYPE.getJoseName(), "challenge");
        if (nonce != null) {
            claims.put(NONCE.getJoseName(), nonce);
        }
        claims.put(SERVER_NONCE.getJoseName(), Nonce.getNonceAsBase64UrlEncodedString(NONCE_BYTE_AMOUNT));
        claims.put(JWT_ID.getJoseName(), Nonce.getNonceAsHex(IdpConstants.JTI_LENGTH));

        final Map<String, Object> headerClaims = new HashMap<>();
        headerClaims.put(TYPE.getJoseName(), "JWT");

        final UserConsent userConsent = getUserConsent(scope);
        return AuthenticationChallenge.builder()
            .challenge(buildJwt(claims, headerClaims))
            .userConsent(userConsent)
            .build();
    }

    private UserConsent getUserConsent(final String scopes) {
        final List<IdpScope> requestedScopes = Stream.of(scopes.split(" "))
            .map(IdpScope::fromJwtValue)
            .filter(Optional::isPresent)
            .map(Optional::get)
            .collect(Collectors.toList());
        final Map<String, String> scopeMap = requestedScopes.stream()
            .map(s -> Pair
                .of(s.getJwtValue(), userConsentConfiguration.getDescriptionTexts().getScopes().get(s)))
            .collect(Collectors.toMap(Pair::getKey, Pair::getValue));
        final Map<String, String> clientMap = requestedScopes.stream()
            .filter(id -> userConsentConfiguration.getClaimsToBeIncluded().containsKey(id))
            .map(id -> userConsentConfiguration.getClaimsToBeIncluded().get(id))
            .flatMap(List::stream)
            .distinct()
            .map(s -> Pair
                .of(s.getJoseName(), userConsentConfiguration.getDescriptionTexts().getClaims().get(s)))
            .collect(Collectors.toMap(Pair::getKey, Pair::getValue));
        return UserConsent.builder()
            .requestedScopes(scopeMap)
            .requestedClaims(clientMap)
            .build();
    }

    private JsonWebToken buildJwt(final Map<String, Object> bodyClaims, final Map<String, Object> headerClaims) {
        return serverSigner.buildJwt(new JwtBuilder()
            .addAllBodyClaims(bodyClaims)
            .addAllHeaderClaims(headerClaims));
    }
}
