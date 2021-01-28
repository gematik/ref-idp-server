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

import de.gematik.idp.authentication.AuthenticationTokenBuilder;
import de.gematik.idp.error.IdpErrorType;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.server.configuration.IdpConfiguration;
import de.gematik.idp.server.controllers.IdpKey;
import de.gematik.idp.server.exceptions.IdpServerException;
import de.gematik.idp.server.exceptions.oauth2spec.IdpServerInvalidRequestException;
import de.gematik.idp.token.IdpJwe;
import de.gematik.idp.token.JsonWebToken;
import de.gematik.idp.token.SsoTokenBuilder;
import de.gematik.idp.token.TokenClaimExtraction;
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
    private final IdpKey authKey;
    private final SignatureValidationService signatureValidationService;

    public String getBasicFlowTokenLocation(final IdpJwe signedChallenge, final String serverUrl) {
        try {
            final URIBuilder locationBuilder = new URIBuilder(serverUrl + TOKEN_ENDPOINT);
            buildBasicFlowTokenLocation(decryptChallenge(signedChallenge), locationBuilder);
            return locationBuilder.build().toString();
        } catch (final URISyntaxException e) {
            throw new IdpServerException("Error while building the token-location URL", e,
                IdpErrorType.INTERNAL_SERVER_ERROR, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    private JsonWebToken decryptChallenge(final IdpJwe signedChallenge) {
        try {
            return signedChallenge.decrypt(authKey.getIdentity().getPrivateKey());
        } catch (final RuntimeException e) {
            throw new IdpServerInvalidRequestException("Error during challenge decryption", e);
        }
    }

    public String getSsoTokenLocation(final JsonWebToken ssoToken, final JsonWebToken challengeToken,
        final String serverUrl) {
        try {
            final URIBuilder locationBuilder = new URIBuilder(serverUrl + TOKEN_ENDPOINT);
            buildSsoTokenLocation(ssoToken, challengeToken, locationBuilder);
            return locationBuilder.build().toString();
        } catch (final URISyntaxException e) {
            throw new IdpServerException("Error while building the token-location URL", e,
                IdpErrorType.INTERNAL_SERVER_ERROR, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    private void buildBasicFlowTokenLocation(
        final JsonWebToken signedChallenge,
        final URIBuilder locationBuilder) {
        final Map<String, Object> serverChallengeClaims = signedChallenge
            .getStringBodyClaim(ClaimName.NESTED_JWT)
            .map(TokenClaimExtraction::extractClaimsFromTokenBody)
            .orElseThrow(() -> new IdpServerInvalidRequestException(
                "Expected signed_challenge to contain String-Claim 'njwt'."));

        signatureValidationService.validateSignature(signedChallenge);

        final X509Certificate nestedX509ClientCertificate =
            signedChallenge.getClientCertificateFromHeader()
                .orElseThrow(() -> new IdpServerException("No Certificate given in header of Signed-Challenge!"));

        final ZonedDateTime authTime = ZonedDateTime.now();

        locationBuilder.addParameter("code", authenticationTokenBuilder
            .buildAuthenticationToken(nestedX509ClientCertificate, serverChallengeClaims, authTime)
            .getJwtRawString());

        locationBuilder.addParameter("sso_token", ssoTokenBuilder
            .buildSsoToken(nestedX509ClientCertificate, authTime)
            .getJwtRawString());

        locationBuilder
            .addParameter("state", Optional.ofNullable(serverChallengeClaims.get(ClaimName.STATE.getJoseName()))
                .map(Object::toString)
                .orElseThrow(() ->
                    new IdpServerException(IdpErrorType.STATE_MISSING_IN_NESTED_CHALLENGE, HttpStatus.BAD_REQUEST)));
    }


    private void buildSsoTokenLocation(final JsonWebToken ssoToken, final JsonWebToken challengeToken,
        final URIBuilder locationBuilder) {
        ssoTokenValidator.validateSsoToken(ssoToken);
        if (challengeToken == null) {
            throw new IdpServerInvalidRequestException(
                "For the use of the SSO-Flow the challengeToken parameter is required");
        }

        locationBuilder.addParameter("code", authenticationTokenBuilder
            .buildAuthenticationTokenFromSsoToken(ssoToken, challengeToken)
            .getJwtRawString());

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
