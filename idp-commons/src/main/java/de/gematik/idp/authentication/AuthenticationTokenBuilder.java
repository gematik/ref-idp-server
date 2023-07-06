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

package de.gematik.idp.authentication;

import static de.gematik.idp.IdpConstants.AMR_FAST_TRACK;
import static de.gematik.idp.field.ClaimName.AUTHENTICATION_METHODS_REFERENCE;
import static de.gematik.idp.field.ClaimName.AUTH_TIME;
import static de.gematik.idp.field.ClaimName.CLIENT_ID;
import static de.gematik.idp.field.ClaimName.CODE_CHALLENGE;
import static de.gematik.idp.field.ClaimName.CODE_CHALLENGE_METHOD;
import static de.gematik.idp.field.ClaimName.CONFIRMATION;
import static de.gematik.idp.field.ClaimName.FAMILY_NAME;
import static de.gematik.idp.field.ClaimName.GIVEN_NAME;
import static de.gematik.idp.field.ClaimName.ID_NUMBER;
import static de.gematik.idp.field.ClaimName.ISSUED_AT;
import static de.gematik.idp.field.ClaimName.ISSUER;
import static de.gematik.idp.field.ClaimName.JWT_ID;
import static de.gematik.idp.field.ClaimName.NONCE;
import static de.gematik.idp.field.ClaimName.ORGANIZATION_NAME;
import static de.gematik.idp.field.ClaimName.PROFESSION_OID;
import static de.gematik.idp.field.ClaimName.REDIRECT_URI;
import static de.gematik.idp.field.ClaimName.RESPONSE_TYPE;
import static de.gematik.idp.field.ClaimName.SCOPE;
import static de.gematik.idp.field.ClaimName.SERVER_NONCE;
import static de.gematik.idp.field.ClaimName.STATE;
import static de.gematik.idp.field.ClaimName.TOKEN_TYPE;
import static de.gematik.idp.field.ClaimName.TYPE;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.crypto.CryptoLoader;
import de.gematik.idp.crypto.Nonce;
import de.gematik.idp.crypto.X509ClaimExtraction;
import de.gematik.idp.exceptions.IdpJoseException;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.token.IdpJwe;
import de.gematik.idp.token.JsonWebToken;
import java.security.Key;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@AllArgsConstructor
@Builder
public class AuthenticationTokenBuilder {

  private final IdpJwtProcessor jwtProcessor;
  private final Key encryptionKey;
  private final String issuerUrl;

  public IdpJwe buildAuthenticationToken(
      final X509Certificate clientCertificate,
      final Map<String, Object> serverChallengeClaims,
      final ZonedDateTime issueingTime) {
    final Map<String, Object> claimsMap = extractClaimsFromCertificate(clientCertificate);

    claimsMap.put(CLIENT_ID.getJoseName(), serverChallengeClaims.get(CLIENT_ID.getJoseName()));
    claimsMap.put(
        REDIRECT_URI.getJoseName(), serverChallengeClaims.get(REDIRECT_URI.getJoseName()));
    claimsMap.put(NONCE.getJoseName(), serverChallengeClaims.get(NONCE.getJoseName()));
    claimsMap.put(
        CODE_CHALLENGE.getJoseName(), serverChallengeClaims.get(CODE_CHALLENGE.getJoseName()));
    claimsMap.put(
        CODE_CHALLENGE_METHOD.getJoseName(),
        serverChallengeClaims.get(CODE_CHALLENGE_METHOD.getJoseName()));
    claimsMap.put(ISSUER.getJoseName(), serverChallengeClaims.get(ISSUER.getJoseName()));
    claimsMap.put(
        RESPONSE_TYPE.getJoseName(), serverChallengeClaims.get(RESPONSE_TYPE.getJoseName()));
    claimsMap.put(STATE.getJoseName(), serverChallengeClaims.get(STATE.getJoseName()));
    claimsMap.put(SCOPE.getJoseName(), serverChallengeClaims.get(SCOPE.getJoseName()));
    claimsMap.put(ISSUED_AT.getJoseName(), issueingTime.toEpochSecond());
    claimsMap.put(TOKEN_TYPE.getJoseName(), "code");
    claimsMap.put(AUTH_TIME.getJoseName(), issueingTime.toEpochSecond());
    claimsMap.put(SERVER_NONCE.getJoseName(), Nonce.getNonceAsBase64UrlEncodedString(24));

    claimsMap.put(JWT_ID.getJoseName(), Nonce.getNonceAsHex(IdpConstants.JTI_LENGTH));
    claimsMap.put(
        AUTHENTICATION_METHODS_REFERENCE.getJoseName(),
        serverChallengeClaims.getOrDefault(
            AUTHENTICATION_METHODS_REFERENCE.getJoseName(), List.of("mfa", "sc", "pin")));

    final Map<String, Object> headerMap = new HashMap<>();
    headerMap.put(TYPE.getJoseName(), "JWT");

    return jwtProcessor
        .buildJwt(
            new JwtBuilder()
                .addAllBodyClaims(claimsMap)
                .addAllHeaderClaims(headerMap)
                .expiresAt(issueingTime.plusMinutes(1)))
        .encryptAsNjwt(encryptionKey);
  }

  private Map<String, Object> extractClaimsFromCertificate(
      final X509Certificate clientCertificate) {
    try {
      return X509ClaimExtraction.extractClaimsFromCertificate(clientCertificate);
    } catch (final RuntimeException e) {
      throw new IdpJoseException("2020", e);
    }
  }

  /*
   * hier wird zwischen dem "klassischen" und dem fast track flow unterschieden. bei letzterem gibt es kein zertifikat
   * im sso_token, so dass alle nutzerspezifischen claims direkt aus dem sso_token gelesen werden müssen
   */
  public IdpJwe buildAuthenticationTokenFromSsoToken(
      final JsonWebToken ssoToken,
      final JsonWebToken challengeToken,
      final ZonedDateTime issueingTime) {

    final Map<String, Object> claimsMap = new HashMap<>();
    if (ssoToken.getBodyClaims().containsKey(CONFIRMATION.getJoseName())) {
      final X509Certificate confirmationCertificate = extractConfirmationCertificate(ssoToken);
      claimsMap.putAll(extractClaimsFromCertificate(confirmationCertificate));
    } else {
      claimsMap.put(GIVEN_NAME.getJoseName(), extractClaimFromChallengeToken(ssoToken, GIVEN_NAME));
      claimsMap.put(
          FAMILY_NAME.getJoseName(), extractClaimFromChallengeToken(ssoToken, FAMILY_NAME));
      claimsMap.put(ID_NUMBER.getJoseName(), extractClaimFromChallengeToken(ssoToken, ID_NUMBER));
      claimsMap.put(
          ORGANIZATION_NAME.getJoseName(),
          extractClaimFromChallengeToken(ssoToken, ORGANIZATION_NAME));
      claimsMap.put(
          PROFESSION_OID.getJoseName(), extractClaimFromChallengeToken(ssoToken, PROFESSION_OID));
    }

    claimsMap.put(
        CODE_CHALLENGE.getJoseName(),
        extractClaimFromChallengeToken(challengeToken, CODE_CHALLENGE));
    claimsMap.put(
        CODE_CHALLENGE_METHOD.getJoseName(),
        extractClaimFromChallengeToken(challengeToken, CODE_CHALLENGE_METHOD));
    claimsMap.put(NONCE.getJoseName(), extractClaimFromChallengeToken(challengeToken, NONCE));
    claimsMap.put(
        CLIENT_ID.getJoseName(), extractClaimFromChallengeToken(challengeToken, CLIENT_ID));
    claimsMap.put(
        REDIRECT_URI.getJoseName(), extractClaimFromChallengeToken(challengeToken, REDIRECT_URI));
    claimsMap.put(SCOPE.getJoseName(), extractClaimFromChallengeToken(challengeToken, SCOPE));
    claimsMap.put(ISSUED_AT.getJoseName(), issueingTime.toEpochSecond());
    claimsMap.put(STATE.getJoseName(), extractClaimFromChallengeToken(challengeToken, STATE));
    claimsMap.put(
        RESPONSE_TYPE.getJoseName(), extractClaimFromChallengeToken(challengeToken, RESPONSE_TYPE));
    claimsMap.put(TOKEN_TYPE.getJoseName(), "code");
    claimsMap.put(AUTH_TIME.getJoseName(), ZonedDateTime.now().toEpochSecond());
    claimsMap.put(SERVER_NONCE.getJoseName(), Nonce.getNonceAsBase64UrlEncodedString(24));
    claimsMap.put(ISSUER.getJoseName(), extractClaimFromChallengeToken(challengeToken, ISSUER));
    claimsMap.put(JWT_ID.getJoseName(), Nonce.getNonceAsHex(IdpConstants.JTI_LENGTH));

    final Map<String, Object> headerClaims = new HashMap<>(ssoToken.getHeaderClaims());
    headerClaims.put(TYPE.getJoseName(), "JWT");

    return jwtProcessor
        .buildJwt(
            new JwtBuilder()
                .replaceAllHeaderClaims(headerClaims)
                .replaceAllBodyClaims(claimsMap)
                .expiresAt(ZonedDateTime.now().plusHours(1)))
        .encryptAsNjwt(encryptionKey);
  }

  public IdpJwe buildAuthenticationTokenFromSektoralIdToken(
      final JsonWebToken idToken,
      final ZonedDateTime issueingTime,
      final Map<String, String> sessionData) {

    final Map<String, Object> claimsMap = new HashMap<>();

    claimsMap.put(GIVEN_NAME.getJoseName(), extractClaimFromChallengeToken(idToken, GIVEN_NAME));
    claimsMap.put(FAMILY_NAME.getJoseName(), extractClaimFromChallengeToken(idToken, FAMILY_NAME));
    claimsMap.put(ID_NUMBER.getJoseName(), extractClaimFromChallengeToken(idToken, ID_NUMBER));
    claimsMap.put(
        PROFESSION_OID.getJoseName(), extractClaimFromChallengeToken(idToken, PROFESSION_OID));

    claimsMap.put(CODE_CHALLENGE.getJoseName(), sessionData.get(CODE_CHALLENGE.getJoseName()));
    claimsMap.put(
        CODE_CHALLENGE_METHOD.getJoseName(), sessionData.get(CODE_CHALLENGE_METHOD.getJoseName()));
    if (sessionData.get(NONCE.getJoseName()) != null) {
      claimsMap.put(NONCE.getJoseName(), sessionData.get(NONCE.getJoseName()));
    }
    claimsMap.put(CLIENT_ID.getJoseName(), sessionData.get(CLIENT_ID.getJoseName()));
    claimsMap.put(REDIRECT_URI.getJoseName(), sessionData.get(REDIRECT_URI.getJoseName()));
    claimsMap.put(SCOPE.getJoseName(), "openid e-rezept");
    claimsMap.put(ISSUED_AT.getJoseName(), issueingTime.toEpochSecond());
    claimsMap.put(STATE.getJoseName(), sessionData.get(STATE.getJoseName()));
    claimsMap.put(RESPONSE_TYPE.getJoseName(), sessionData.get(RESPONSE_TYPE.getJoseName()));
    claimsMap.put(TOKEN_TYPE.getJoseName(), "code");
    claimsMap.put(AUTH_TIME.getJoseName(), ZonedDateTime.now().toEpochSecond());
    claimsMap.put(SERVER_NONCE.getJoseName(), Nonce.getNonceAsBase64UrlEncodedString(24));
    claimsMap.put(ISSUER.getJoseName(), issuerUrl);
    claimsMap.put(JWT_ID.getJoseName(), Nonce.getNonceAsHex(IdpConstants.JTI_LENGTH));
    claimsMap.put(AUTHENTICATION_METHODS_REFERENCE.getJoseName(), List.of(AMR_FAST_TRACK));

    final Map<String, Object> headerMap = new HashMap<>();
    headerMap.put(TYPE.getJoseName(), "JWT");

    return jwtProcessor
        .buildJwt(
            new JwtBuilder()
                .addAllHeaderClaims(headerMap)
                .addAllBodyClaims(claimsMap)
                .expiresAt(ZonedDateTime.now().plusHours(1)))
        .encryptAsNjwt(encryptionKey);
  }

  private Object extractClaimFromChallengeToken(
      final JsonWebToken challengeToken, final ClaimName claimName) {
    return challengeToken
        .getBodyClaim(claimName)
        .orElseThrow(() -> new IdpJoseException("Unexpected structure in Challenge-Token"));
  }

  private X509Certificate extractConfirmationCertificate(final JsonWebToken ssoToken) {
    final String certString =
        ssoToken
            .getBodyClaim(ClaimName.CONFIRMATION)
            .filter(Map.class::isInstance)
            .map(Map.class::cast)
            .map(map -> map.get(ClaimName.X509_CERTIFICATE_CHAIN.getJoseName()))
            .filter(List.class::isInstance)
            .map(List.class::cast)
            .filter(list -> !list.isEmpty())
            .map(list -> list.get(0))
            .map(Object::toString)
            .orElseThrow(
                () ->
                    new IdpJoseException(
                        "Unsupported cnf-Structure found: Could not extract confirmed"
                            + " Certificate!"));

    final byte[] decode = Base64.getDecoder().decode(certString);

    return CryptoLoader.getCertificateFromPem(decode);
  }
}
