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

import static de.gematik.idp.IdpConstants.TOKEN_ENDPOINT;
import static de.gematik.idp.error.IdpErrorType.INVALID_REQUEST;
import static de.gematik.idp.field.ClaimName.CHALLENGE_TOKEN;
import static de.gematik.idp.field.ClaimName.CLIENT_ID;
import static de.gematik.idp.field.ClaimName.REDIRECT_URI;

import de.gematik.idp.authentication.AuthenticationTokenBuilder;
import de.gematik.idp.error.IdpErrorType;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.server.configuration.IdpConfiguration;
import de.gematik.idp.server.controllers.IdpKey;
import de.gematik.idp.server.data.IdpClientConfiguration;
import de.gematik.idp.server.exceptions.IdpServerException;
import de.gematik.idp.server.exceptions.authentication.IdpServerLocationBuildException;
import de.gematik.idp.server.exceptions.oauth2spec.IdpServerInvalidRequestException;
import de.gematik.idp.token.IdpJwe;
import de.gematik.idp.token.JsonWebToken;
import de.gematik.idp.token.SsoTokenBuilder;
import de.gematik.idp.token.TokenClaimExtraction;
import de.gematik.pki.certificate.TucPki018Verifier;
import de.gematik.pki.exception.GemPkiException;
import java.net.URISyntaxException;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;
import lombok.RequiredArgsConstructor;
import org.apache.http.client.utils.URIBuilder;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class IdpAuthenticator {

    private final SsoTokenBuilder ssoTokenBuilder;
    private final SsoTokenValidator ssoTokenValidator;
    private final AuthenticationTokenBuilder authenticationTokenBuilder;
    private final IdpConfiguration idpConfiguration;
    private final IdpKey idpSig;
    private final IdpKey idpEnc;
    private final TucPki018Verifier tucPki018Verifier;
    private final ChallengeTokenValidationService challengeTokenValidationService;
    private final ClientRegistrationService clientRegistrationService;

    public String getBasicFlowTokenLocation(final IdpJwe signedChallenge) {
        try {
            return buildBasicFlowTokenLocation(decryptChallenge(signedChallenge)).build().toString();
        } catch (final URISyntaxException e) {
            throw new IdpServerLocationBuildException(e);
        }
    }

    public String getAlternateFlowTokenLocation(final IdpJwe signedAuthData) {
        try {
            return buildAlternateFlowTokenLocation(decryptChallenge(signedAuthData)).build().toString();
        } catch (final URISyntaxException e) {
            throw new IdpServerLocationBuildException(e);
        }
    }

    private JsonWebToken decryptChallenge(final IdpJwe signedChallenge) {
        try {
            return signedChallenge.decryptNestedJwt(idpEnc.getIdentity().getPrivateKey());
        } catch (final RuntimeException e) {
            throw new IdpServerInvalidRequestException("Error during client-challenge decryption!", e);
        }
    }

    public String getSsoTokenLocation(final IdpJwe ssoToken, final JsonWebToken challengeToken) {
        try {
            final String redirectUrl = challengeToken.getBodyClaims().get(REDIRECT_URI.getJoseName())
                .toString();
            final URIBuilder locationBuilder = new URIBuilder(redirectUrl + TOKEN_ENDPOINT);
            buildSsoTokenLocation(ssoToken, challengeToken, locationBuilder);
            return locationBuilder.build().toString();
        } catch (final URISyntaxException e) {
            throw new IdpServerLocationBuildException(e);
        }
    }

    private URIBuilder buildBasicFlowTokenLocation(final JsonWebToken signedChallenge) {
        final Map<String, Object> serverChallengeClaims = getServerChallengeClaims(signedChallenge);

        challengeTokenValidationService.validateChallengeToken(signedChallenge);

        final X509Certificate nestedX509ClientCertificate =
            signedChallenge.getClientCertificateFromHeader()
                .orElseThrow(
                    () -> new IdpServerException(2044, INVALID_REQUEST, "Das AUT Zertifikat wurde nicht übermittelt"));

        verifyClientCertificate(nestedX509ClientCertificate);

        final String state = Optional.ofNullable(serverChallengeClaims.get(ClaimName.STATE.getJoseName()))
            .map(Object::toString)
            .orElseThrow(() ->
                new IdpServerException(IdpErrorType.INVALID_REQUEST,
                    HttpStatus.BAD_REQUEST));
        final String redirectUrl = serverChallengeClaims.get(REDIRECT_URI.getJoseName()).toString();
        return Stream.of(redirectUrl + TOKEN_ENDPOINT)
            .map(param -> {
                try {
                    return new URIBuilder(param);
                } catch (final Exception ex) {
                    throw new IdpServerLocationBuildException(ex);
                }
            })
            .map(param -> {
                buildLocationUri(param, nestedX509ClientCertificate, serverChallengeClaims, state);
                return param;
            })
            .findFirst().get();
    }

    private Map<String, Object> getServerChallengeClaims(final JsonWebToken signedChallenge) {
        try {
            return signedChallenge
                .getStringBodyClaim(ClaimName.NESTED_JWT)
                .map(TokenClaimExtraction::extractClaimsFromJwtBody)
                .orElseThrow(() -> new IdpServerInvalidRequestException(
                    "Expected signed_challenge to contain String-Claim 'njwt'."));
        } catch (final Exception e) {
            throw new IdpServerException(2030, INVALID_REQUEST, "Challenge ist ungültig", e);
        }
    }

    private URIBuilder buildAlternateFlowTokenLocation(final JsonWebToken signedAuthData) {
        final Map<String, Object> authDataClaims = addAllClaimsFromAuthDataAndChallenge(signedAuthData);
        challengeTokenValidationService.validateChallengeToken(signedAuthData);
        final X509Certificate nestedX509ClientCertificate = signedAuthData.getAuthenticationCertificate()
            .orElseThrow(() -> new IdpServerException("No Certificate given in authentication data!",
                IdpErrorType.INVALID_REQUEST, HttpStatus.BAD_REQUEST));
        //TODO OCSP-Check(nestedX509ClientCertificate)
        final Map<String, Object> challengeTokenClaimsMap = TokenClaimExtraction
            .extractClaimsFromJwtBody((String) authDataClaims.get(CHALLENGE_TOKEN.getJoseName()));
        final String state = Optional.ofNullable(challengeTokenClaimsMap.get(ClaimName.STATE.getJoseName()))
            .map(Object::toString)
            .orElseThrow(() ->
                new IdpServerException(IdpErrorType.INVALID_REQUEST,
                    HttpStatus.BAD_REQUEST));
        return Stream.of(authDataClaims.get(REDIRECT_URI.getJoseName()) + TOKEN_ENDPOINT)
            .map(param -> {
                try {
                    return new URIBuilder(param);
                } catch (final Exception ex) {
                    throw new IdpServerLocationBuildException(ex);
                }
            })
            .map(param -> {
                buildLocationUri(param, nestedX509ClientCertificate, authDataClaims, state);
                return param;
            })
            .findFirst().get();
    }

    private Map<String, Object> addAllClaimsFromAuthDataAndChallenge(final JsonWebToken signedAuthData) {
        final Map<String, Object> claimsMap = signedAuthData.getBodyClaims();
        claimsMap.putAll(signedAuthData.getStringBodyClaim(CHALLENGE_TOKEN)
            .map(TokenClaimExtraction::extractClaimsFromJwtBody)
            .orElseThrow(() -> new IdpServerInvalidRequestException(
                "Expected authentication data to contain claim 'challenge_token'.")));
        return claimsMap;
    }

    private void buildLocationUri(final URIBuilder locationBuilder, final X509Certificate certificate,
        final Map<String, Object> claimsMap, final String state) {
        final ZonedDateTime authTime = ZonedDateTime.now();
        locationBuilder.addParameter("code", authenticationTokenBuilder
            .buildAuthenticationToken(certificate, claimsMap, authTime)
            .getRawString());

        final Optional<Boolean> addSsoToken = clientRegistrationService
            .getClientConfiguration(claimsMap.get(CLIENT_ID.getJoseName()).toString())
            .map(IdpClientConfiguration::isReturnSsoToken);
        if (addSsoToken.orElse(false)) {
            locationBuilder
                .addParameter("ssotoken", ssoTokenBuilder.buildSsoToken(certificate, authTime).getRawString());
        }

        locationBuilder.addParameter("state", state);
    }

    private void verifyClientCertificate(final X509Certificate nestedX509ClientCertificate) {
        try {
            tucPki018Verifier.performTucPki18Checks(nestedX509ClientCertificate);
        } catch (final GemPkiException | RuntimeException e) {
            throw new IdpServerException(2020, INVALID_REQUEST, "Das AUT Zertifikat ist ungültig");
        }
    }

    private void buildSsoTokenLocation(final IdpJwe encryptedSsoToken, final JsonWebToken challengeToken,
        final URIBuilder locationBuilder) {
        if (challengeToken == null) {
            throw new IdpServerInvalidRequestException(
                "For the use of the SSO-Flow the challengeToken parameter is required");
        }
        if (challengeToken.getExpiresAtBody().isBefore(ZonedDateTime.now()) ||
            challengeToken.getExpiresAt().isBefore(ZonedDateTime.now())) {
            throw new IdpServerException(2032, INVALID_REQUEST, "Challenge ist abgelaufen");
        }
        try {
            challengeToken.verify(idpSig.getIdentity().getCertificate().getPublicKey());
        } catch (final Exception e) {
            throw new IdpServerException(2030, INVALID_REQUEST, "Challenge ist ungültig");
        }
        final JsonWebToken ssoToken = ssoTokenValidator.decryptAndValidateSsoToken(encryptedSsoToken);

        locationBuilder.addParameter("code", authenticationTokenBuilder
            .buildAuthenticationTokenFromSsoToken(ssoToken, challengeToken)
            .getRawString());

        locationBuilder
            .addParameter("state",
                Optional.ofNullable(challengeToken.getBodyClaims().get(ClaimName.STATE.getJoseName()))
                    .map(Object::toString)
                    .orElseThrow(() ->
                        new IdpServerException(IdpErrorType.INVALID_REQUEST,
                            HttpStatus.BAD_REQUEST)));
    }

    public void validateRedirectUri(final String clientId, final String redirectUri) {
        if (!clientRegistrationService.getClientConfiguration(clientId)
            .map(clientRegistration -> clientRegistration.getRedirectUri())
            .filter(Objects::nonNull)
            .orElseThrow(() -> new IdpServerException(1004, INVALID_REQUEST, "redirect_uri wurde nicht übermittelt"))
            .equals(redirectUri)) {
            throw new IdpServerException(1020, INVALID_REQUEST, "redirect_uri ist ungültig");
        }
    }
}
