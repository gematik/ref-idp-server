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
import static de.gematik.idp.field.ClaimName.CODE_VERIFIER;
import static de.gematik.idp.field.ClaimName.REDIRECT_URI;

import de.gematik.idp.field.ClaimName;
import de.gematik.idp.server.controllers.IdpKey;
import de.gematik.idp.server.data.TokenResponse;
import de.gematik.idp.server.exceptions.oauth2spec.IdpServerInvalidRedirectUriException;
import de.gematik.idp.server.exceptions.oauth2spec.IdpServerInvalidRequestException;
import de.gematik.idp.token.*;
import java.security.Key;
import java.util.Base64;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import lombok.RequiredArgsConstructor;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class TokenService {

    private final IdTokenBuilder idTokenBuilder;
    private final PkceChecker pkceChecker;
    private final AccessTokenBuilder accessTokenBuilder;
    private final IdpKey tokenKey;
    private final Key symmetricEncryptionKey;

    public TokenResponse getTokenResponse(final IdpJwe encryptedAuthenticationToken, final IdpJwe keyVerifier,
        final String redirectUri, final String clientId) {
        final JsonWebToken authenticationToken = encryptedAuthenticationToken
            .decryptNestedJwt(symmetricEncryptionKey);
        decryptKeyVerifierAndTestStructure(keyVerifier);

        final String codeChallenge = authenticationToken.getStringBodyClaim(CODE_CHALLENGE)
            .orElseThrow(() -> new IdpServerInvalidRequestException(
                "Authentication_Token without " + CODE_CHALLENGE.getJoseName() + " found!"));
        pkceChecker.checkCodeVerifier(keyVerifier.getStringBodyClaim(ClaimName.CODE_VERIFIER)
            .orElseThrow(() -> new IdpServerInvalidRequestException(
                "Could not find claim '" + CODE_VERIFIER.getJoseName() + "' in given key_verifier")), codeChallenge);
        authenticationToken.verify(tokenKey.getIdentity().getCertificate().getPublicKey());

        if (authenticationToken.getBodyClaim(REDIRECT_URI)
            .filter(originalRedirectUri -> originalRedirectUri.equals(redirectUri))
            .isEmpty()) {
            throw new IdpServerInvalidRedirectUriException("Expected redirect_uri to match the original value");
        }

        final JsonWebToken accessToken = getAccessToken(authenticationToken);
        final SecretKey tokenKey = keyVerifier.getStringBodyClaim(ClaimName.TOKEN_KEY)
            .map(Base64.getDecoder()::decode)
            .map(keyBytes -> new SecretKeySpec(keyBytes, "AES"))
            .orElseThrow(() -> new IdpServerInvalidRequestException(
                "Could not find string-claim '" + ClaimName.TOKEN_KEY.getJoseName() + "' in given key_verifier"));
        return TokenResponse.builder()
            .tokenType("Bearer")
            .expiresIn(300)
            .accessToken(accessToken.encrypt(tokenKey).getRawString())
            .idToken(idTokenBuilder
                .buildIdToken(clientId, authenticationToken, DigestUtils.sha256(accessToken.getRawString()))
                .encrypt(tokenKey)
                .getRawString())
            .build();
    }

    private IdpJoseObject decryptKeyVerifierAndTestStructure(final IdpJwe encryptedKeyVerifier) {
        try {
            encryptedKeyVerifier.setDecryptionKey(tokenKey.getIdentity().getPrivateKey());
            // Provokes an exception in case of malformed structure
            encryptedKeyVerifier.getBodyClaims();
            return encryptedKeyVerifier;
        } catch (final RuntimeException e) {
            throw new IdpServerInvalidRequestException("Error during decryption of key_verifier", e);
        }
    }

    private JsonWebToken getAccessToken(final JsonWebToken authenticationToken) {
        return accessTokenBuilder.buildAccessToken(authenticationToken);
    }
}
