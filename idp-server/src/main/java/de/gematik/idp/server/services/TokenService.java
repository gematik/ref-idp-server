/*
 *  Copyright 2023 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.idp.server.services;

import static de.gematik.idp.error.IdpErrorType.INVALID_GRANT;
import static de.gematik.idp.error.IdpErrorType.INVALID_REQUEST;
import static de.gematik.idp.field.ClaimName.CODE_CHALLENGE;
import static de.gematik.idp.field.ClaimName.REDIRECT_URI;

import de.gematik.idp.data.TokenResponse;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.server.controllers.IdpKey;
import de.gematik.idp.server.exceptions.IdpServerException;
import de.gematik.idp.server.exceptions.oauth2spec.IdpServerInvalidRequestException;
import de.gematik.idp.token.AccessTokenBuilder;
import de.gematik.idp.token.IdTokenBuilder;
import de.gematik.idp.token.IdpJoseObject;
import de.gematik.idp.token.IdpJwe;
import de.gematik.idp.token.JsonWebToken;
import java.security.Key;
import java.util.Base64;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class TokenService {

  private final IdTokenBuilder idTokenBuilder;
  private final PkceChecker pkceChecker;
  private final AccessTokenBuilder accessTokenBuilder;
  private final IdpKey idpSig;
  private final IdpKey idpEnc;
  private final Key symmetricEncryptionKey;

  public TokenResponse getTokenResponse(
      final IdpJwe encryptedAuthenticationToken,
      final IdpJwe keyVerifier,
      final String redirectUri,
      final String clientId) {
    final JsonWebToken authenticationToken =
        decryptEncryptedAuthenticationToken(encryptedAuthenticationToken);
    decryptKeyVerifierAndTestStructure(keyVerifier);
    testAuthenticationTokenStructure(authenticationToken);

    final String codeChallenge =
        authenticationToken
            .getStringBodyClaim(CODE_CHALLENGE)
            .orElseThrow(
                () ->
                    new IdpServerException(
                        3001, INVALID_GRANT, "Claims unvollständig im Authorization Code"));
    pkceChecker.checkCodeVerifier(
        keyVerifier
            .getStringBodyClaim(ClaimName.CODE_VERIFIER)
            .orElseThrow(
                () ->
                    new IdpServerException(
                        3004, INVALID_REQUEST, "key_verifier wurde nicht übermittelt")),
        codeChallenge);
    try {
      authenticationToken.verify(idpSig.getIdentity().getCertificate().getPublicKey());
    } catch (final Exception e) {
      throw new IdpServerException(3011, INVALID_GRANT, "Authorization Code ist abgelaufen");
    }

    if (StringUtils.isEmpty(redirectUri)) {
      throw new IdpServerException(1004, INVALID_REQUEST, "redirect_uri wurde nicht übermittelt");
    }
    if (authenticationToken
        .getBodyClaim(REDIRECT_URI)
        .filter(originalRedirectUri -> originalRedirectUri.equals(redirectUri))
        .isEmpty()) {
      throw new IdpServerException(1020, INVALID_REQUEST, "redirect_uri ist ungültig");
    }

    final JsonWebToken accessToken = getAccessToken(authenticationToken);
    final SecretKey tokenKey =
        keyVerifier
            .getStringBodyClaim(ClaimName.TOKEN_KEY)
            .map(Base64.getUrlDecoder()::decode)
            .map(keyBytes -> new SecretKeySpec(keyBytes, "AES"))
            .orElseThrow(
                () ->
                    new IdpServerException(
                        3015, INVALID_REQUEST, "Claims unvollständig im key_verifier"));
    return TokenResponse.builder()
        .tokenType("Bearer")
        .expiresIn(300)
        .accessToken(accessToken.encryptAsNjwt(tokenKey).getRawString())
        .idToken(
            idTokenBuilder
                .buildIdToken(clientId, authenticationToken, accessToken)
                .encryptAsNjwt(tokenKey)
                .getRawString())
        .build();
  }

  private void testAuthenticationTokenStructure(final JsonWebToken authenticationToken) {
    try {
      authenticationToken.getBodyClaims();
    } catch (final Exception e) {
      throw new IdpServerException(3013, INVALID_GRANT, "Authorization Code ist nicht lesbar", e);
    }
  }

  private JsonWebToken decryptEncryptedAuthenticationToken(
      final IdpJwe encryptedAuthenticationToken) {
    try {
      return encryptedAuthenticationToken.decryptNestedJwt(symmetricEncryptionKey);
    } catch (final Exception e) {
      throw new IdpServerException(3013, INVALID_GRANT, "Authorization Code ist nicht lesbar", e);
    }
  }

  private IdpJoseObject decryptKeyVerifierAndTestStructure(final IdpJwe encryptedKeyVerifier) {
    try {
      encryptedKeyVerifier.setDecryptionKey(idpEnc.getIdentity().getPrivateKey());
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
