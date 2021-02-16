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
import static de.gematik.idp.error.IdpErrorType.MISSING_PARAMETERS;
import static de.gematik.idp.field.ClaimName.CHALLENGE_TOKEN;

import de.gematik.idp.authentication.AuthenticationTokenBuilder;
import de.gematik.idp.error.IdpErrorType;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.server.configuration.IdpConfiguration;
import de.gematik.idp.server.controllers.IdpKey;
import de.gematik.idp.server.exceptions.IdpServerException;
import de.gematik.idp.server.exceptions.authentication.IdpServerLocationBuildException;
import de.gematik.idp.server.exceptions.oauth2spec.IdpServerInvalidRequestException;
import de.gematik.idp.token.IdpJwe;
import de.gematik.idp.token.JsonWebToken;
import de.gematik.idp.token.SsoTokenBuilder;
import de.gematik.idp.token.TokenClaimExtraction;
import de.gematik.pki.certificate.CertificateVerifier;
import de.gematik.pki.exception.GemPkiException;
import java.net.URISyntaxException;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
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
    private final CertificateVerifier certificateVerifier;
    private final ChallengeTokenValidationService challengeTokenValidationService;

    public String getBasicFlowTokenLocation(final IdpJwe signedChallenge, final String serverUrl) {
        try {
            final URIBuilder locationBuilder = new URIBuilder(serverUrl + TOKEN_ENDPOINT);
            buildBasicFlowTokenLocation(decryptChallenge(signedChallenge), locationBuilder);
            return locationBuilder.build().toString();
        } catch (final URISyntaxException e) {
            throw new IdpServerLocationBuildException(e);
        }
    }

    public String getAlternateFlowTokenLocation(final IdpJwe signedAuthData, final String serverUrl) {
        try {
            final URIBuilder locationBuilder = new URIBuilder(serverUrl + TOKEN_ENDPOINT);
            buildAlternateFlowTokenLocation(decryptChallenge(signedAuthData), locationBuilder);
            return locationBuilder.build().toString();
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

    public String getSsoTokenLocation(final IdpJwe ssoToken, final JsonWebToken challengeToken,
        final String serverUrl) {
        try {
            final URIBuilder locationBuilder = new URIBuilder(serverUrl + TOKEN_ENDPOINT);
            buildSsoTokenLocation(ssoToken, challengeToken, locationBuilder);
            return locationBuilder.build().toString();
        } catch (final URISyntaxException e) {
            throw new IdpServerLocationBuildException(e);
        }
    }

    private void buildBasicFlowTokenLocation(
        final JsonWebToken signedChallenge,
        final URIBuilder locationBuilder) {
        final Map<String, Object> serverChallengeClaims = signedChallenge
            .getStringBodyClaim(ClaimName.NESTED_JWT)
            .map(TokenClaimExtraction::extractClaimsFromJwtBody)
            .orElseThrow(() -> new IdpServerInvalidRequestException(
                "Expected signed_challenge to contain String-Claim 'njwt'."));

        challengeTokenValidationService.validateChallengeToken(signedChallenge);

        final X509Certificate nestedX509ClientCertificate =
            signedChallenge.getClientCertificateFromHeader()
                .orElseThrow(() -> new IdpServerException("No Certificate given in header of Signed-Challenge!"));

        verifyClientCertificate(nestedX509ClientCertificate);

        final String state = Optional.ofNullable(serverChallengeClaims.get(ClaimName.STATE.getJoseName()))
            .map(Object::toString)
            .orElseThrow(() ->
                new IdpServerException(IdpErrorType.STATE_MISSING_IN_NESTED_CHALLENGE,
                    HttpStatus.BAD_REQUEST));
        buildLocationUri(locationBuilder, nestedX509ClientCertificate, serverChallengeClaims, state);
    }

    private void buildAlternateFlowTokenLocation(
        final JsonWebToken signedAuthData,
        final URIBuilder locationBuilder) {
        final Map<String, Object> authDataClaims = addAllClaimsFromAuthDataAndChallenge(signedAuthData);
        challengeTokenValidationService.validateChallengeToken(signedAuthData);
        final X509Certificate nestedX509ClientCertificate = signedAuthData.getAuthenticationCertificate()
            .orElseThrow(() -> new IdpServerException("No Certificate given in authentication data!",
                MISSING_PARAMETERS, HttpStatus.BAD_REQUEST));
        //TODO OCSP-Check(nestedX509ClientCertificate)
        final Map<String, Object> challengeTokenClaimsMap = TokenClaimExtraction
            .extractClaimsFromJwtBody((String) authDataClaims.get(CHALLENGE_TOKEN.getJoseName()));
        final String state = Optional.ofNullable(challengeTokenClaimsMap.get(ClaimName.STATE.getJoseName()))
            .map(Object::toString)
            .orElseThrow(() ->
                new IdpServerException(IdpErrorType.STATE_MISSING_IN_NESTED_CHALLENGE,
                    HttpStatus.BAD_REQUEST));
        buildLocationUri(locationBuilder, nestedX509ClientCertificate, authDataClaims, state);
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
        locationBuilder.addParameter("sso_token", ssoTokenBuilder
            .buildSsoToken(certificate, authTime)
            .getRawString());
        locationBuilder.addParameter("state", state);
    }

    private void verifyClientCertificate(final X509Certificate nestedX509ClientCertificate) {
        try {
            certificateVerifier.performTucPki18Checks(nestedX509ClientCertificate);
        } catch (final GemPkiException | RuntimeException e) {
            throw new IdpServerException("Error while verifying client certificate", e,
                IdpErrorType.SERVER_ERROR, HttpStatus.BAD_REQUEST);
        }
    }

    private void buildSsoTokenLocation(final IdpJwe encryptedSsoToken, final JsonWebToken challengeToken,
        final URIBuilder locationBuilder) {
        if (challengeToken == null) {
            throw new IdpServerInvalidRequestException(
                "For the use of the SSO-Flow the challengeToken parameter is required");
        }
        challengeToken.verify(idpSig.getIdentity().getCertificate().getPublicKey());
        final JsonWebToken ssoToken = ssoTokenValidator.decryptAndValidateSsoToken(encryptedSsoToken);

        locationBuilder.addParameter("code", authenticationTokenBuilder
            .buildAuthenticationTokenFromSsoToken(ssoToken, challengeToken)
            .getRawString());

        locationBuilder
            .addParameter("state",
                Optional.ofNullable(challengeToken.getBodyClaims().get(ClaimName.STATE.getJoseName()))
                    .map(Object::toString)
                    .orElseThrow(() ->
                        new IdpServerException(IdpErrorType.STATE_MISSING_IN_NESTED_CHALLENGE,
                            HttpStatus.BAD_REQUEST)));
    }

    public void validateRedirectUri(final String redirectUri) {
        if (Objects.isNull(redirectUri) || !idpConfiguration.getRedirectUri().equals(redirectUri)) {
            throw new IdpServerException(IdpErrorType.REDIRECT_URI_DEFUNCT, HttpStatus.BAD_REQUEST);
        }
    }
}
