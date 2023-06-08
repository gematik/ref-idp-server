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

import static de.gematik.idp.error.IdpErrorType.INVALID_REQUEST;
import static de.gematik.idp.field.ClaimName.AUTHENTICATION_METHODS_REFERENCE;
import static de.gematik.idp.field.ClaimName.CHALLENGE_TOKEN;
import static de.gematik.idp.field.ClaimName.CLIENT_ID;
import static de.gematik.idp.field.ClaimName.CONTENT_TYPE;
import static de.gematik.idp.field.ClaimName.EPHEMERAL_PUBLIC_KEY;
import static de.gematik.idp.field.ClaimName.EXPIRES_AT;
import static de.gematik.idp.field.ClaimName.NESTED_JWT;
import static de.gematik.idp.field.ClaimName.REDIRECT_URI;
import static de.gematik.idp.field.ClaimName.STATE;

import de.gematik.idp.authentication.AuthenticationTokenBuilder;
import de.gematik.idp.error.IdpErrorType;
import de.gematik.idp.exceptions.IdpJoseException;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.server.controllers.IdpKey;
import de.gematik.idp.server.data.IdpClientConfiguration;
import de.gematik.idp.server.exceptions.IdpServerException;
import de.gematik.idp.server.exceptions.authentication.IdpServerLocationBuildException;
import de.gematik.idp.server.exceptions.oauth2spec.IdpServerInvalidRequestException;
import de.gematik.idp.token.IdpJwe;
import de.gematik.idp.token.JsonWebToken;
import de.gematik.idp.token.SsoTokenBuilder;
import de.gematik.idp.token.TokenClaimExtraction;
import de.gematik.pki.gemlibpki.certificate.TucPki018Verifier;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import java.net.URISyntaxException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.client.utils.URIBuilder;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class IdpAuthenticator {

  private final SsoTokenBuilder ssoTokenBuilder;
  private final SsoTokenValidator ssoTokenValidator;
  private final AuthenticationTokenBuilder authenticationTokenBuilder;
  private final IdpKey idpSig;
  private final IdpKey idpEnc;
  private final TucPki018Verifier tucPki018Verifier;
  private final ChallengeTokenValidationService challengeTokenValidationService;
  private final ClientRegistrationService clientRegistrationService;

  public String getBasicFlowTokenLocation(final IdpJwe signedChallenge) {
    try {
      verifyJweHeaderClaims(signedChallenge);
      final JsonWebToken decryptedChallenge = decryptChallenge(signedChallenge);
      verifyExpInChallenge(signedChallenge);
      verifyExpInChallengeEqualsExpInSignedChallenge(signedChallenge, decryptedChallenge);
      return buildBasicFlowTokenLocation(decryptedChallenge).build().toString();
    } catch (final URISyntaxException e) {
      throw new IdpServerLocationBuildException(e);
    }
  }

  private void verifyJweHeaderClaims(final IdpJwe signedChallenge) {
    if (signedChallenge.getHeaderClaim(CONTENT_TYPE).filter("NJWT"::equals).isEmpty()) {
      log.error(signedChallenge.getHeaderDecoded());
      throw new IdpServerException(2030, INVALID_REQUEST, "CTY fehlerhaft");
    }
    if (signedChallenge
        .getHeaderClaim(EPHEMERAL_PUBLIC_KEY)
        .filter(Map.class::isInstance)
        .map(Map.class::cast)
        .filter(epkMap -> "BP-256".equals(epkMap.get("crv")))
        .isEmpty()) {
      log.error(signedChallenge.getHeaderDecoded());
      throw new IdpServerException(2030, INVALID_REQUEST, "EPK-Typ fehlerhaft");
    }
  }

  public String getAlternateFlowTokenLocation(final IdpJwe signedAuthData) {
    try {
      verifyExpInChallenge(signedAuthData);
      return buildAlternateFlowTokenLocation(decryptChallenge(signedAuthData)).build().toString();
    } catch (final URISyntaxException e) {
      throw new IdpServerLocationBuildException(e);
    }
  }

  private JsonWebToken decryptChallenge(final IdpJwe signedChallenge) {
    try {
      return signedChallenge.decryptNestedJwt(idpEnc.getIdentity().getPrivateKey());
    } catch (final RuntimeException e) {
      if (e instanceof IdpServerException) {
        throw e;
      } else {
        throw new IdpServerException(2030, INVALID_REQUEST, "Challenge ist ungültig", e);
      }
    }
  }

  private void verifyExpInChallenge(final IdpJwe signedChallenge) {
    if (signedChallenge.getHeaderClaim(EXPIRES_AT).isEmpty()) {
      log.error(signedChallenge.getHeaderDecoded());
      throw new IdpServerException(2031, INVALID_REQUEST, "exp wurde nicht übermittelt");
    }
    if (signedChallenge
        .getHeaderClaim(EXPIRES_AT)
        .filter(Long.class::isInstance)
        .map(Long.class::cast)
        .map(Instant::ofEpochSecond)
        .map(expInstant -> Instant.now().isAfter(expInstant))
        .orElse(true)) {
      throw new IdpServerException(2032, INVALID_REQUEST, "Challenge ist abgelaufen");
    }
  }

  public void verifyExpInChallengeEqualsExpInSignedChallenge(
      final IdpJwe signedChallenge, final JsonWebToken decryptedChallenge) {
    final Long expInEncHeader = (Long) signedChallenge.getHeaderClaim(EXPIRES_AT).orElseThrow();
    final Long expInChallenge =
        (Long)
            decryptedChallenge
                .getStringBodyClaim(NESTED_JWT)
                .map(JsonWebToken::new)
                .orElseThrow()
                .getBodyClaim(EXPIRES_AT)
                .orElseThrow();

    if (!expInChallenge.equals(expInEncHeader)) {
      throw new IdpServerException(
          2032, INVALID_REQUEST, "Exp in Challenge und signierter Challenge nicht gleich");
    }
  }

  public String getSsoTokenLocation(final IdpJwe ssoToken, final JsonWebToken challengeToken) {
    try {
      final String redirectUrl =
          challengeToken.getBodyClaims().get(REDIRECT_URI.getJoseName()).toString();
      final URIBuilder locationBuilder = new URIBuilder(redirectUrl);
      buildSsoTokenLocation(ssoToken, challengeToken, locationBuilder);
      return locationBuilder.build().toString();
    } catch (final URISyntaxException e) {
      throw new IdpServerLocationBuildException(e);
    }
  }

  public String getAuthorizationCodeLocation(
      final JsonWebToken idToken, final Map<String, String> sessionData) {
    try {
      final String redirectUrl = sessionData.get(REDIRECT_URI.getJoseName());
      final URIBuilder locationBuilder = new URIBuilder(redirectUrl);
      buildLocationUriThirdPartyAuth(locationBuilder, idToken, sessionData);
      return locationBuilder.build().toString();
    } catch (final URISyntaxException e) {
      throw new IdpServerLocationBuildException(e);
    }
  }

  private URIBuilder buildBasicFlowTokenLocation(final JsonWebToken signedChallenge) {
    final Map<String, Object> serverChallengeClaims = getServerChallengeClaims(signedChallenge);

    challengeTokenValidationService.validateChallengeToken(signedChallenge);

    final X509Certificate nestedX509ClientCertificate =
        signedChallenge
            .getClientCertificateFromHeader()
            .orElseThrow(
                () ->
                    new IdpServerException(
                        2044, INVALID_REQUEST, "Das AUT Zertifikat wurde nicht übermittelt"));

    verifyClientCertificate(nestedX509ClientCertificate);

    final String state =
        Optional.ofNullable(serverChallengeClaims.get(ClaimName.STATE.getJoseName()))
            .map(Object::toString)
            .orElseThrow(
                () -> new IdpServerException(IdpErrorType.INVALID_REQUEST, HttpStatus.BAD_REQUEST));
    final String redirectUrl = serverChallengeClaims.get(REDIRECT_URI.getJoseName()).toString();
    try {
      final URIBuilder redirectUriBuilder = new URIBuilder(redirectUrl);
      buildLocationUri(
          redirectUriBuilder, nestedX509ClientCertificate, serverChallengeClaims, state);
      return redirectUriBuilder;
    } catch (final URISyntaxException ex) {
      throw new IdpServerLocationBuildException(ex);
    }
  }

  private Map<String, Object> getServerChallengeClaims(final JsonWebToken signedChallenge) {
    try {
      return signedChallenge
          .getStringBodyClaim(ClaimName.NESTED_JWT)
          .map(TokenClaimExtraction::extractClaimsFromJwtBody)
          .orElseThrow(
              () ->
                  new IdpServerInvalidRequestException(
                      "Expected signed_challenge to contain String-Claim 'njwt'."));
    } catch (final Exception e) {
      throw new IdpServerException(2030, INVALID_REQUEST, "Challenge ist ungültig", e);
    }
  }

  private URIBuilder buildAlternateFlowTokenLocation(final JsonWebToken signedAuthData) {
    final Map<String, Object> authDataClaims;
    try {
      authDataClaims = addAllClaimsFromAuthDataAndChallenge(signedAuthData);
    } catch (final IdpJoseException ije) {
      throw new IdpServerException(
          2000, IdpErrorType.ACCESS_DENIED, "Invalid challenge token", HttpStatus.BAD_REQUEST, ije);
    }
    try {
      challengeTokenValidationService.validateChallengeToken(signedAuthData);
    } catch (final IdpJoseException ije) {
      throw new IdpServerException(
          2000, IdpErrorType.ACCESS_DENIED, "Invalid challenge token", HttpStatus.BAD_REQUEST, ije);
    }

    final X509Certificate nestedX509ClientCertificate =
        signedAuthData
            .getAuthenticationCertificate()
            .orElseThrow(
                () ->
                    new IdpServerException(
                        "No Certificate given in authentication data!",
                        IdpErrorType.INVALID_REQUEST,
                        HttpStatus.BAD_REQUEST));
    final Map<String, Object> challengeTokenClaimsMap =
        TokenClaimExtraction.extractClaimsFromJwtBody(
            (String) authDataClaims.get(CHALLENGE_TOKEN.getJoseName()));
    final String state =
        Optional.ofNullable(challengeTokenClaimsMap.get(ClaimName.STATE.getJoseName()))
            .map(Object::toString)
            .orElseThrow(
                () -> new IdpServerException(IdpErrorType.INVALID_REQUEST, HttpStatus.BAD_REQUEST));
    return Stream.of(authDataClaims.get(REDIRECT_URI.getJoseName()).toString())
        .map(
            param -> {
              try {
                return new URIBuilder(param);
              } catch (final Exception ex) {
                throw new IdpServerLocationBuildException(ex);
              }
            })
        .map(
            param -> {
              buildLocationUri(param, nestedX509ClientCertificate, authDataClaims, state);
              return param;
            })
        .findFirst()
        .orElseThrow(
            () ->
                new IdpServerException(
                    IdpErrorType.SERVER_ERROR, HttpStatus.INTERNAL_SERVER_ERROR));
  }

  private Map<String, Object> addAllClaimsFromAuthDataAndChallenge(
      final JsonWebToken signedAuthData) {
    final Map<String, Object> claimsMap = signedAuthData.getBodyClaims();
    claimsMap.putAll(
        signedAuthData
            .getStringBodyClaim(CHALLENGE_TOKEN)
            .map(TokenClaimExtraction::extractClaimsFromJwtBody)
            .orElseThrow(
                () ->
                    new IdpServerInvalidRequestException(
                        "Expected authentication data to contain claim 'challenge_token'.")));
    return claimsMap;
  }

  private void buildLocationUri(
      final URIBuilder locationBuilder,
      final X509Certificate certificate,
      final Map<String, Object> claimsMap,
      final String state) {
    final ZonedDateTime authTime = ZonedDateTime.now();
    locationBuilder.addParameter(
        "code",
        authenticationTokenBuilder
            .buildAuthenticationToken(certificate, claimsMap, authTime)
            .getRawString());

    final Optional<Boolean> addSsoToken =
        clientRegistrationService
            .getClientConfiguration(claimsMap.get(CLIENT_ID.getJoseName()).toString())
            .map(IdpClientConfiguration::isReturnSsoToken);
    if (addSsoToken.orElse(false)) {
      locationBuilder.addParameter(
          "ssotoken",
          ssoTokenBuilder
              .buildSsoToken(certificate, authTime, getAmrString(claimsMap))
              .getRawString());
    }

    locationBuilder.addParameter("state", state);
  }

  private void buildLocationUriThirdPartyAuth(
      final URIBuilder locationBuilder,
      final JsonWebToken idToken,
      final Map<String, String> sessionData) {
    final ZonedDateTime authTime = ZonedDateTime.now();
    locationBuilder.addParameter(
        "code",
        authenticationTokenBuilder
            .buildAuthenticationTokenFromSektoralIdToken(idToken, authTime, sessionData)
            .getRawString());
    locationBuilder.addParameter("state", sessionData.get(STATE.getJoseName()));
    locationBuilder.addParameter(
        "ssotoken",
        ssoTokenBuilder.buildSsoTokenFromSektoralIdToken(idToken, authTime).getRawString());
  }

  private List<String> getAmrString(final Map<String, Object> claimsMap) {
    if (claimsMap.containsKey(AUTHENTICATION_METHODS_REFERENCE.getJoseName())) {
      final Object o = claimsMap.get(AUTHENTICATION_METHODS_REFERENCE.getJoseName());
      if (o instanceof List) {
        return (List) o;
      } else {
        throw new IdpServerException(
            "Invalid format of AMR-claim given", INVALID_REQUEST, HttpStatus.BAD_REQUEST);
      }
    } else {
      return List.of("mfa", "sc", "pin");
    }
  }

  private void verifyClientCertificate(final X509Certificate nestedX509ClientCertificate) {
    try {
      tucPki018Verifier.performTucPki18Checks(nestedX509ClientCertificate);
    } catch (final GemPkiException | RuntimeException e) {
      throw new IdpServerException(2020, INVALID_REQUEST, "Das AUT Zertifikat ist ungültig", e);
    }
  }

  private void buildSsoTokenLocation(
      final IdpJwe encryptedSsoToken,
      final JsonWebToken challengeToken,
      final URIBuilder locationBuilder) {
    if (challengeToken == null) {
      throw new IdpServerInvalidRequestException(
          "For the use of the SSO-Flow the challengeToken parameter is required");
    }
    if (challengeToken.getExpiresAtBody().isBefore(ZonedDateTime.now())
        || challengeToken.getExpiresAt().isBefore(ZonedDateTime.now())) {
      throw new IdpServerException(2032, INVALID_REQUEST, "Challenge ist abgelaufen");
    }
    try {
      challengeToken.verify(idpSig.getIdentity().getCertificate().getPublicKey());
    } catch (final Exception e) {
      throw new IdpServerException(2030, INVALID_REQUEST, "Challenge ist ungültig");
    }
    final JsonWebToken ssoToken = ssoTokenValidator.decryptAndValidateSsoToken(encryptedSsoToken);

    final ZonedDateTime authTime = ZonedDateTime.now();
    locationBuilder.addParameter(
        "code",
        authenticationTokenBuilder
            .buildAuthenticationTokenFromSsoToken(ssoToken, challengeToken, authTime)
            .getRawString());

    locationBuilder.addParameter(
        "state",
        Optional.ofNullable(challengeToken.getBodyClaims().get(ClaimName.STATE.getJoseName()))
            .map(Object::toString)
            .orElseThrow(
                () ->
                    new IdpServerException(IdpErrorType.INVALID_REQUEST, HttpStatus.BAD_REQUEST)));
  }

  public void validateRedirectUri(final String clientId, final String redirectUri) {
    if (StringUtils.isEmpty(redirectUri)) {
      throw new IdpServerException(1004, INVALID_REQUEST, "redirect_uri wurde nicht übermittelt");
    }
    if (!clientRegistrationService
        .getClientConfiguration(clientId)
        .map(IdpClientConfiguration::getRedirectUri)
        .filter(Objects::nonNull)
        .map(uri -> uri.equals(redirectUri))
        .orElse(false)) {
      throw new IdpServerException(1020, INVALID_REQUEST, "redirect_uri ist ungültig");
    }
  }
}
