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

package de.gematik.idp.server.controllers;

import static de.gematik.idp.IdpConstants.ALTERNATIVE_AUTHORIZATION_ENDPOINT;
import static de.gematik.idp.IdpConstants.BASIC_AUTHORIZATION_ENDPOINT;
import static de.gematik.idp.IdpConstants.SSO_ENDPOINT;
import static de.gematik.idp.IdpConstants.TOKEN_ENDPOINT;
import de.gematik.idp.authentication.AuthenticationChallenge;
import de.gematik.idp.authentication.AuthenticationChallengeBuilder;
import de.gematik.idp.error.IdpErrorType;
import de.gematik.idp.server.ServerUrlService;
import de.gematik.idp.server.data.TokenResponse;
import de.gematik.idp.server.exceptions.IdpServerException;
import de.gematik.idp.server.services.IdpAuthenticator;
import de.gematik.idp.server.services.TokenService;
import de.gematik.idp.server.validation.clientSystem.ValidateClientSystem;
import de.gematik.idp.server.validation.parameterConstraints.CheckClientId;
import de.gematik.idp.server.validation.parameterConstraints.CheckScope;
import de.gematik.idp.token.IdpJwe;
import de.gematik.idp.token.JsonWebToken;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import lombok.RequiredArgsConstructor;
import net.dracoblue.spring.web.mvc.method.annotation.HttpResponseHeader;
import net.dracoblue.spring.web.mvc.method.annotation.HttpResponseHeaders;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Validated
@RequiredArgsConstructor
@Api(tags = {
    "Idp-Dienst"}, description = "REST Endpunkte für das Authentifizieren, Authorisieren und die Tokenabfrage")
@HttpResponseHeaders({
    @HttpResponseHeader(name = "Cache-Control", value = "no-store"),
    @HttpResponseHeader(name = "Pragma", value = "no-cache")
})
public class IdpController {

    private static final String SHA256_AS_BASE64_REGEX = "^[_\\-a-zA-Z0-9]{42,44}[=]{0,2}$";
    private final ServerUrlService serverUrlService;
    private final AuthenticationChallengeBuilder authenticationChallengeBuilder;
    private final IdpAuthenticator idpAuthenticator;
    private final TokenService tokenService;

    @GetMapping(value = BASIC_AUTHORIZATION_ENDPOINT, produces = MediaType.APPLICATION_JSON_VALUE)
    @ApiOperation(httpMethod = "GET", value = "Endpunkt für Authentifizierung", notes = "Die übergebenen Parameter"
        + " werden zu einer Liste von JWTClaims zusammengefasst und daraus dann die zurückgelieferte "
        + "AuthenticationChallenge gebaut.", response = AuthenticationChallenge.class)
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Erfolgreich Daten für Autorisierung erhalten"),
        @ApiResponse(responseCode = "302", description = "Ungültige Anfrage (Parameter fehlen/ungültig)"),
        @ApiResponse(responseCode = "400", description = "Ungültige Anfrage (Parameter fehlen/ungültig)"),
        @ApiResponse(responseCode = "401", description = "Nicht autorisierter Zugriff"),
        @ApiResponse(responseCode = "403", description = "Nicht erlaubter Zugriff"),
        @ApiResponse(responseCode = "404", description = "Nicht gefunden - Methodenaufruf nicht korrekt")
    })
    @ValidateClientSystem
    public AuthenticationChallenge getAuthenticationChallenge(
        @RequestParam(name = "client_id") @NotEmpty(message = "1002") @CheckClientId final String clientId,
        @RequestParam(name = "state") @NotEmpty(message = "2002") @Pattern(regexp = ".+", message = "2006") final String state,
        @RequestParam(name = "redirect_uri") @NotNull(message = "1004") final String redirectUri,
        @RequestParam(name = "nonce", required = false) @Pattern(regexp = ".+", message = "2007") final String nonce,
        @RequestParam(name = "response_type") @NotEmpty(message = "2004") @Pattern(regexp = "code", message = "2005") final String responseType,
        @RequestParam(name = "code_challenge") @NotEmpty(message = "2009") @Pattern(regexp = SHA256_AS_BASE64_REGEX, message = "2010") final String codeChallenge,
        @RequestParam(name = "code_challenge_method") @Pattern(regexp = "S256", message = "2008") final String codeChallengeMethod,
        @RequestParam(name = "scope") @CheckScope final String scope,
        final HttpServletResponse response) {
        idpAuthenticator.validateRedirectUri(clientId, redirectUri);
        setNoCacheHeader(response);
        return authenticationChallengeBuilder
            .buildAuthenticationChallenge(clientId, state, redirectUri, codeChallenge, scope, nonce);
    }

    @PostMapping(BASIC_AUTHORIZATION_ENDPOINT)
    @ApiOperation(httpMethod = "POST", value = "Endpunkt für Basis-Autorisierung", notes =
        "Wird eine signierte Challenge an den Endpunkt übergeben, wird diese validiert, "
            + "das Client-Zertifikat extrahiert und daraus der Code für die Tokenabfrage und ein SSO Token generiert. "
            + "Der Code und der SsoToken werden dann zusammen als Query parameter mit der URL zum Token Endpunkt "
            + "zurückgeliefert.")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "302", description = "Erfolgreich Daten für Token-Abfrage erhalten")
    })
    @ValidateClientSystem
    public void validateChallengeAndGetTokenCode(
        @RequestParam(value = "signed_challenge", required = false) @NotNull(message = "2030") @ApiParam(value = "Signierte und verschlüsselte Challenge") final IdpJwe signedChallenge,
        final HttpServletResponse response) {
        setNoCacheHeader(response);
        response.setStatus(HttpStatus.FOUND.value());

        final String tokenLocation = idpAuthenticator.getBasicFlowTokenLocation(signedChallenge);
        response.setHeader(HttpHeaders.LOCATION, tokenLocation);
    }

    @PostMapping(ALTERNATIVE_AUTHORIZATION_ENDPOINT)
    @ApiOperation(httpMethod = "POST", value = "Endpunkt für alternative Autorisierung", notes =
        "Es werden signierte Autorisierungsdaten für die alternative Autorisierung an den Endpunkt übergeben "
            + "und validiert. Wie bei der Basis-Autorisierung, werden Code und der SsoToken dann zusammen als "
            + "Query parameter mit der URL zum Token Endpunkt zurückgegeben")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "302", description = "Erfolgreich Daten für Token-Abfrage erhalten"),
    })
    @ValidateClientSystem
    public void validateSignedAuthenticationDataAndGetTokenCode(
        @RequestParam(value = "encrypted_signed_authentication_data", required = false) @NotNull @ApiParam(value = "Signierte Autorisierungsdaten") final IdpJwe signedAuthenticationData,
        final HttpServletResponse response,
        final HttpServletRequest request) {
        setNoCacheHeader(response);
        response.setStatus(HttpStatus.FOUND.value());
        final String tokenLocation = idpAuthenticator.getAlternateFlowTokenLocation(signedAuthenticationData);
        response.setHeader(HttpHeaders.LOCATION, tokenLocation);
    }

    @PostMapping(value = SSO_ENDPOINT, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    @ApiOperation(httpMethod = "POST", value = "Endpunkt für SSO-Authorisierung", notes =
        "Wird ein SSO-Token übergeben, so wird aus diesem der Code für die Tokenabfrage generiert. "
            + "Der Code wird dann als Query parameter mit der URL zum Token Endpunkt zurückgeliefert.")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "302", description = "Erfolgreich Daten für Token-Abfrage erhalten")
    })
    @ValidateClientSystem
    public void validateSsoTokenAndGetTokenCode(
        @RequestParam(value = "ssotoken", required = false) @NotNull(message = "2040") @ApiParam(value = "Single Sign-On Token") final IdpJwe ssoToken,
        @RequestParam(value = "unsigned_challenge", required = false) @NotNull(message = "2030") @ApiParam(value = "Originale Server-Challenge. Benötigt für den SSO-Flow") final JsonWebToken challengeToken,
        final HttpServletResponse response,
        final HttpServletRequest request) {
        setNoCacheHeader(response);
        response.setStatus(HttpStatus.FOUND.value());

        final String tokenLocation = idpAuthenticator.getSsoTokenLocation(
            ssoToken,
            challengeToken);
        response.setHeader(HttpHeaders.LOCATION, tokenLocation);
    }

    @PostMapping(value = TOKEN_ENDPOINT, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    @ApiOperation(httpMethod = "POST", value = "Endpunkt für Tokenabfrage", notes = "Es wird der Token Code mit "
        + "dem Code Verifier geprüft, entwertet und bei Erfolg daraus ein Zugangstoken erstellt. Der Zugangstoken "
        + "wird gemeinsam mit einem ID Token zurückgeliefert.", response = TokenResponse.class)
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Erfolgreich Token-Response erhalten"),
        @ApiResponse(responseCode = "401", description = "Nicht autorisierter Zugriff"),
        @ApiResponse(responseCode = "403", description = "Nicht erlaubter Zugriff"),
        @ApiResponse(responseCode = "404", description = "Nicht gefunden - Methodenaufruf nicht korrekt")
    })
    @ValidateClientSystem
    public TokenResponse getTokensForCode(
        @RequestParam("code") @NotNull(message = "3005") @ApiParam(value = "Tokenzugriffscode") final IdpJwe authenticationToken,
        @RequestParam("key_verifier") @NotNull @ApiParam(value = "Für den Server verschlüsseltes JWE, welches den code_verifier und den token_code enthält") final IdpJwe keyVerifier,
        @RequestParam("grant_type") @NotNull(message = "3006") @Pattern(regexp = "authorization_code", message = "3014") @ApiParam(value = "Grant_type. Wert muss 'authorization_code' sein") final String grantType,
        @RequestParam("redirect_uri") @ApiParam(value = "Redirect-URI aus dem Authorization-Request") final String redirectUri,
        @RequestParam("client_id") @NotEmpty(message = "1002") @CheckClientId(message = "3007") @ApiParam(value = "Client-ID") final String clientId,
        final HttpServletResponse response) {
        if (StringUtils.isEmpty(authenticationToken.getRawString())) {
            throw new IdpServerException(3005, IdpErrorType.INVALID_REQUEST,
                "Authorization Code wurde nicht übermittelt");
        }
        setNoCacheHeader(response);
        return tokenService.getTokenResponse(authenticationToken, keyVerifier, redirectUri, clientId);
    }

    private void setNoCacheHeader(final HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Pragma", "no-cache");
    }
}
