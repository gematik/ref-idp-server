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

package de.gematik.idp.server.services;

import static de.gematik.idp.field.ClaimName.CODE_CHALLENGE;
import static de.gematik.idp.field.ClaimName.REDIRECT_URI;

import de.gematik.idp.field.IdpScope;
import de.gematik.idp.server.data.TokenResponse;
import de.gematik.idp.server.exceptions.oauth2spec.IdpServerInvalidRedirectUriException;
import de.gematik.idp.server.exceptions.oauth2spec.IdpServerInvalidRequestException;
import de.gematik.idp.token.AccessTokenBuilder;
import de.gematik.idp.token.IdTokenBuilder;
import de.gematik.idp.token.JsonWebToken;
import lombok.RequiredArgsConstructor;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class TokenService {

    private final IdTokenBuilder idTokenBuilder;
    private final PkceChecker pkceChecker;
    private final AccessTokenBuilder accessTokenBuilder;
    private final AuthenticationTokenValidator authenticationTokenValidator;

    public TokenResponse getTokenResponse(final JsonWebToken authenticationToken, final String codeVerifier,
        final String redirectUri, final String clientId) {
        final String codeChallenge = (String) authenticationToken.getBodyClaim(CODE_CHALLENGE)
            .orElseThrow(() -> new IdpServerInvalidRequestException(
                "Authentication_Token without " + CODE_CHALLENGE.getJoseName() + " found!"));
        pkceChecker.checkCodeVerifier(codeVerifier, codeChallenge);
        authenticationTokenValidator.validateAuthenticationToken(authenticationToken);

        if (authenticationToken.getBodyClaim(REDIRECT_URI)
            .filter(originalRedirectUri -> originalRedirectUri.equals(redirectUri))
            .isEmpty()) {
            throw new IdpServerInvalidRedirectUriException("Expected redirect_uri to match the original value");
        }

        final String accessToken = getAccessToken(authenticationToken);
        return TokenResponse.builder()
            .tokenType("Bearer")
            .expiresIn(300)
            .accessToken(accessToken)
            .idToken(idTokenBuilder.buildIdToken(clientId, authenticationToken, DigestUtils.sha256(accessToken))
                .getJwtRawString())
            .build();
    }

    private String getAccessToken(final JsonWebToken authenticationToken) {
        if (!authenticationToken.getScopesBodyClaim().contains(IdpScope.EREZEPT)
            && !authenticationToken.getScopesBodyClaim().contains(IdpScope.PAIRING)) {
            return null;
        }
        return accessTokenBuilder.buildAccessToken(authenticationToken).getJwtRawString();
    }
}
