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
import de.gematik.idp.data.UserConsent;
import de.gematik.idp.data.UserConsentConfiguration;
import de.gematik.idp.exceptions.IdpJoseException;
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
import lombok.NonNull;
import org.apache.commons.lang3.tuple.Pair;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;

@Data
@AllArgsConstructor
@Builder
public class AuthenticationChallengeBuilder {

    private static final long CHALLENGE_TOKEN_VALIDITY_IN_MINUTES = 3;
    private static final int NONCE_BYTE_AMOUNT = 32;
    private final PkiIdentity authenticationIdentity;
    private final String uriIdpServer;
    private final UserConsentConfiguration userConsentConfiguration;

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
        claims.setClaim(JWT_ID.getJoseName(), new Nonce().getNonceAsHex(IdpConstants.JTI_LENGTH));

        final Map<String, Object> headerClaims = new HashMap<>();
        headerClaims.put(TYPE.getJoseName(), "JWT");
        headerClaims
            .put(EXPIRES_AT.getJoseName(), now.plusMinutes(CHALLENGE_TOKEN_VALIDITY_IN_MINUTES).toEpochSecond());

        final UserConsent userConsent = getUserConsent(scope, clientId);
        return AuthenticationChallenge.builder()
            .challenge(buildJwt(claims.toJson(), headerClaims))
            .userConsent(userConsent)
            .build();
    }

    private UserConsent getUserConsent(final String scopes, final String clientId) {
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
