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
import de.gematik.idp.field.CodeChallengeMethod;
import de.gematik.idp.server.ServerUrlService;
import de.gematik.idp.server.data.TokenResponse;
import de.gematik.idp.server.services.IdpAuthenticator;
import de.gematik.idp.server.services.TokenService;
import de.gematik.idp.server.validation.clientSystem.ValidateClientSystem;
import de.gematik.idp.server.validation.parameterConstraints.CheckClientId;
import de.gematik.idp.server.validation.parameterConstraints.CheckCodeChallengeMethod;
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
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
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
public class IdpController {

    private static final String SHA256_AS_BASE64_REGEX = "^[_\\-a-zA-Z0-9]{42,44}[=]{0,2}$";
    private final ServerUrlService serverUrlService;
    private final AuthenticationChallengeBuilder authenticationChallengeBuilder;
    private final IdpAuthenticator idpAuthenticator;
    private final TokenService tokenService;

    @GetMapping(BASIC_AUTHORIZATION_ENDPOINT)
    @ApiOperation(httpMethod = "GET", value = "Endpunkt für Authentifizierung", notes = "Die übergebenen Parameter"
        + " werden zu einer Liste von JWTClaims zusammengefasst und daraus dann die zurückgelieferte "
        + "AuthenticationChallenge gebaut.", response = AuthenticationChallenge.class)
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Erfolgreich Daten für Autorisierung erhalten"),
        @ApiResponse(responseCode = "400", description = "Ungültige Anfrage (Parameter fehlen/ungültig)"),
        @ApiResponse(responseCode = "401", description = "Nicht autorisierter Zugriff"),
        @ApiResponse(responseCode = "403", description = "Nicht erlaubter Zugriff"),
        @ApiResponse(responseCode = "404", description = "Nicht gefunden - Methodenaufruf nicht korrekt")
    })
    @ValidateClientSystem
    public AuthenticationChallenge getAuthenticationChallenge(
        @RequestParam(name = "client_id") @CheckClientId @ApiParam(value = "Identifier für den zugreifenden Client") final String clientId,
        @RequestParam(name = "state") @ApiParam(value = "Eine Sicherheitsmaßnahme gegen CSRF-Angriffe") final String state,
        @RequestParam(name = "redirect_uri") @ApiParam(value = "TODO redirect_uri") final String redirectUri,
        @RequestParam(name = "nonce", required = false) @ApiParam(value = "TODO nonce") final String nonce,
        @RequestParam(name = "response_type") @NotEmpty @Pattern(regexp = "code", message = "Expected response_type to be 'code'") @ApiParam(value = "response_type, muss 'code' sein") final String responseType,
        @RequestParam(name = "code_challenge") @Pattern(regexp = SHA256_AS_BASE64_REGEX, message = "invalid code_challenge") @ApiParam(value = "Authentifizierungscode") final String codeChallenge,
        @RequestParam(name = "code_challenge_method") @CheckCodeChallengeMethod @ApiParam(value = "Hash Methode für die Code challenge, derzeit wird nur 'S256' unterstützt") final CodeChallengeMethod codeChallengeMethod,
        @RequestParam(name = "scope") @CheckScope @ApiParam(value = "Scope der Anfrage, derzeit werden 'openid e-rezept', 'openid', 'openid pairing' und 'openid e-rezept pairing' unterstützt") final String scope,
        final HttpServletResponse response) {
        idpAuthenticator.validateRedirectUri(redirectUri);
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
        @RequestParam(value = "signed_challenge", required = false) @NotNull @ApiParam(value = "Signierte und verschlüsselte Challenge") final IdpJwe signedChallenge,
        final HttpServletResponse response,
        final HttpServletRequest request) {
        setNoCacheHeader(response);
        response.setStatus(HttpStatus.FOUND.value());

        final String tokenLocation = idpAuthenticator.getBasicFlowTokenLocation(
            signedChallenge,
            serverUrlService.determineServerUrl(request));

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
        @RequestParam(value = "signed_authentication_data", required = false) @NotNull @ApiParam(value = "Signierte Autorisierungsdaten") final IdpJwe signedAuthenticationData,
        final HttpServletResponse response,
        final HttpServletRequest request) {
        setNoCacheHeader(response);
        response.setStatus(HttpStatus.FOUND.value());

        final String tokenLocation = idpAuthenticator.getAlternateFlowTokenLocation(
            signedAuthenticationData,
            serverUrlService.determineServerUrl(request));

        response.setHeader(HttpHeaders.LOCATION, tokenLocation);
    }

    @PostMapping(SSO_ENDPOINT)
    @ApiOperation(httpMethod = "POST", value = "Endpunkt für SSO-Authorisierung", notes =
        "Wird ein SSO-Token übergeben, so wird aus diesem der Code für die Tokenabfrage generiert. "
            + "Der Code wird dann als Query parameter mit der URL zum Token Endpunkt zurückgeliefert.")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "302", description = "Erfolgreich Daten für Token-Abfrage erhalten")
    })
    @ValidateClientSystem
    public void validateSsoTokenAndGetTokenCode(
        @RequestParam(value = "sso_token", required = false) @NotNull @ApiParam(value = "Single Sign-On Token") final IdpJwe ssoToken,
        @RequestParam(value = "unsigned_challenge", required = false) @NotNull @ApiParam(value = "Originale Server-Challenge. Benötigt für den SSO-Flow") final JsonWebToken challengeToken,
        final HttpServletResponse response,
        final HttpServletRequest request) {
        setNoCacheHeader(response);
        response.setStatus(HttpStatus.FOUND.value());

        final String tokenLocation = idpAuthenticator.getSsoTokenLocation(
            ssoToken,
            challengeToken,
            serverUrlService.determineServerUrl(request));

        response.setHeader(HttpHeaders.LOCATION, tokenLocation);
    }

    @PostMapping(TOKEN_ENDPOINT)
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
        @RequestParam("code") @NotNull @ApiParam(value = "Tokenzugriffscode") final IdpJwe authenticationToken,
        @RequestParam("key_verifier") @NotNull @ApiParam(value = "Für den Server verschlüsseltes JWE, welches den code_verifier und den token_code enthält") final IdpJwe keyVerifier,
        @RequestParam("grant_type") @Pattern(regexp = "authorization_code") @ApiParam(value = "Grant_type. Wert muss 'authorization_code' sein") final String grantType,
        @RequestParam("redirect_uri") @NotEmpty @ApiParam(value = "Redirect-URI aus dem Authorization-Request") final String redirectUri,
        @RequestParam("client_id") @NotEmpty @ApiParam(value = "Client-ID") final String clientId,
        final HttpServletResponse response) {

        setNoCacheHeader(response);

        return tokenService.getTokenResponse(authenticationToken, keyVerifier, redirectUri, clientId);
    }

    private void setNoCacheHeader(final HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Pragma", "no-cache");
    }
}
