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

package de.gematik.idp.server.controllers;

import static de.gematik.idp.EnvHelper.getSystemProperty;
import static de.gematik.idp.IdpConstants.ALTERNATIVE_AUTHORIZATION_ENDPOINT;
import static de.gematik.idp.IdpConstants.BASIC_AUTHORIZATION_ENDPOINT;
import static de.gematik.idp.IdpConstants.SSO_ENDPOINT;
import static de.gematik.idp.IdpConstants.THIRD_PARTY_ENDPOINT;
import static de.gematik.idp.IdpConstants.TOKEN_ENDPOINT;
import static de.gematik.idp.field.ClientUtilities.generateCodeChallenge;
import static de.gematik.idp.field.ClientUtilities.generateCodeVerifier;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.authentication.AuthenticationChallenge;
import de.gematik.idp.authentication.AuthenticationChallengeBuilder;
import de.gematik.idp.crypto.Nonce;
import de.gematik.idp.data.TokenResponse;
import de.gematik.idp.error.IdpErrorType;
import de.gematik.idp.server.ServerUrlService;
import de.gematik.idp.server.data.FasttrackSession;
import de.gematik.idp.server.data.KassenAppList;
import de.gematik.idp.server.exceptions.IdpServerException;
import de.gematik.idp.server.services.IdpAuthenticator;
import de.gematik.idp.server.services.TokenService;
import de.gematik.idp.server.validation.clientSystem.ValidateClientSystem;
import de.gematik.idp.server.validation.parameterConstraints.CheckClientId;
import de.gematik.idp.server.validation.parameterConstraints.CheckScope;
import de.gematik.idp.token.IdpJwe;
import de.gematik.idp.token.JsonWebToken;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import java.net.URISyntaxException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.NoSuchElementException;
import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.Unirest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.client.utils.URIBuilder;
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
@Slf4j
public class IdpController {

  private static final String SHA256_AS_BASE64_REGEX = "^[_\\-a-zA-Z0-9]{42,44}[=]{0,2}$";
  private static final int MAX_FASTTRACK_SESSION_AMOUNT = 10000;
  private static final int FASTTRACK_IDP_STATE_LENGTH = 32;
  private static final int FASTTRACK_IDP_NONCE_LENGTH = 32;
  private static final int NONCE_LENGTH_MAX = 512;
  private static final int STATE_LENGTH_MAX = 512;

  private final ServerUrlService serverUrlService;
  private final AuthenticationChallengeBuilder authenticationChallengeBuilder;
  private final IdpAuthenticator idpAuthenticator;
  private final TokenService tokenService;
  private final Map<String, FasttrackSession> fasttrackSessions =
      new LinkedHashMap<>() {

        @Override
        protected boolean removeEldestEntry(final Entry<String, FasttrackSession> eldest) {
          return size() > MAX_FASTTRACK_SESSION_AMOUNT;
        }
      };
  private final KassenAppList kassenAppList;

  @GetMapping(value = BASIC_AUTHORIZATION_ENDPOINT, produces = MediaType.APPLICATION_JSON_VALUE)
  @ValidateClientSystem
  public AuthenticationChallenge getAuthenticationChallenge(
      @RequestParam(name = "client_id") @NotEmpty(message = "1002") @CheckClientId
          final String clientId,
      @RequestParam(name = "state")
          @NotEmpty(message = "2002")
          @Pattern(regexp = "^[_\\-a-zA-Z0-9]{1," + STATE_LENGTH_MAX + "}$", message = "2006")
          final String state,
      @RequestParam(name = "redirect_uri") @NotNull(message = "1004") final String redirectUri,
      @RequestParam(name = "nonce", required = false)
          @Pattern(regexp = "^[_\\-a-zA-Z0-9]{1," + NONCE_LENGTH_MAX + "}$", message = "2007")
          final String nonce,
      @RequestParam(name = "response_type")
          @NotEmpty(message = "2004")
          @Pattern(regexp = "code", message = "2005")
          final String responseType,
      @RequestParam(name = "code_challenge")
          @NotEmpty(message = "2009")
          @Pattern(regexp = SHA256_AS_BASE64_REGEX, message = "2010")
          final String codeChallenge,
      @RequestParam(name = "code_challenge_method") @Pattern(regexp = "S256", message = "2008")
          final String codeChallengeMethod,
      @RequestParam(name = "scope") @CheckScope final String scope,
      final HttpServletResponse response) {
    idpAuthenticator.validateRedirectUri(clientId, redirectUri);
    setNoCacheHeader(response);
    return authenticationChallengeBuilder.buildAuthenticationChallenge(
        clientId, state, redirectUri, codeChallenge, scope, nonce);
  }

  @PostMapping(BASIC_AUTHORIZATION_ENDPOINT)
  @ValidateClientSystem
  public void validateChallengeAndGetTokenCode(
      @RequestParam(value = "signed_challenge", required = false) @NotNull(message = "2030")
          final IdpJwe signedChallenge,
      final HttpServletResponse response) {
    setNoCacheHeader(response);
    response.setStatus(HttpStatus.FOUND.value());

    final String tokenLocation = idpAuthenticator.getBasicFlowTokenLocation(signedChallenge);
    response.setHeader(HttpHeaders.LOCATION, tokenLocation);
  }

  @PostMapping(ALTERNATIVE_AUTHORIZATION_ENDPOINT)
  @ValidateClientSystem
  public void validateSignedAuthenticationDataAndGetTokenCode(
      @RequestParam(value = "encrypted_signed_authentication_data", required = false) @NotNull
          final IdpJwe signedAuthenticationData,
      final HttpServletResponse response) {
    setNoCacheHeader(response);
    response.setStatus(HttpStatus.FOUND.value());
    final String tokenLocation =
        idpAuthenticator.getAlternateFlowTokenLocation(signedAuthenticationData);
    response.setHeader(HttpHeaders.LOCATION, tokenLocation);
  }

  @PostMapping(value = SSO_ENDPOINT, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  @ValidateClientSystem
  public void validateSsoTokenAndGetTokenCode(
      @RequestParam(value = "ssotoken", required = false) @NotNull(message = "2040")
          final IdpJwe ssoToken,
      @RequestParam(value = "unsigned_challenge", required = false) @NotNull(message = "2030")
          final JsonWebToken challengeToken,
      final HttpServletResponse response) {
    setNoCacheHeader(response);
    response.setStatus(HttpStatus.FOUND.value());

    final String tokenLocation = idpAuthenticator.getSsoTokenLocation(ssoToken, challengeToken);
    response.setHeader(HttpHeaders.LOCATION, tokenLocation);
  }

  @PostMapping(value = TOKEN_ENDPOINT, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  @ValidateClientSystem
  public TokenResponse getTokensForCode(
      @RequestParam("code") @NotNull(message = "3005") final IdpJwe authenticationToken,
      @RequestParam("key_verifier") @NotNull final IdpJwe keyVerifier,
      @RequestParam("grant_type")
          @NotEmpty(message = "3006")
          @Pattern(regexp = "authorization_code", message = "3014")
          final String grantType,
      @RequestParam("redirect_uri") final String redirectUri,
      @RequestParam("client_id") @NotEmpty(message = "1002") @CheckClientId(message = "3007")
          final String clientId,
      final HttpServletResponse response) {
    if (StringUtils.isEmpty(authenticationToken.getRawString())) {
      throw new IdpServerException(
          3005, IdpErrorType.INVALID_REQUEST, "Authorization Code wurde nicht übermittelt");
    }
    setNoCacheHeader(response);
    return tokenService.getTokenResponse(authenticationToken, keyVerifier, redirectUri, clientId);
  }

  /* Fasttrack
   * Request(in)  == message nr.1
   * Response(out)== message nr.2
   */
  @GetMapping(value = THIRD_PARTY_ENDPOINT)
  public void getAuthorizationRequestIncludingRedirect(
      @RequestParam(name = "client_id") @NotEmpty(message = "1002") final String userAgentClientId,
      @RequestParam(name = "state")
          @NotEmpty(message = "2002")
          @Pattern(regexp = ".+", message = "2006")
          final String userAgentState,
      @RequestParam(name = "redirect_uri") @NotNull(message = "1004")
          final String userAgentRedirectUri,
      @RequestParam(name = "nonce", required = false) @Pattern(regexp = ".+", message = "2007")
          final String userAgentNonce,
      @RequestParam(name = "response_type")
          @NotEmpty(message = "2004")
          @Pattern(regexp = "code", message = "2005")
          final String responseType,
      @RequestParam(name = "code_challenge")
          @NotEmpty(message = "2009")
          @Pattern(regexp = SHA256_AS_BASE64_REGEX, message = "2010")
          final String userAgentCodeChallenge,
      @RequestParam(name = "code_challenge_method") @Pattern(regexp = "S256", message = "2008")
          final String userAgentCodeChallengeMethod,
      @RequestParam(name = "scope") @NotEmpty(message = "1002") final String userAgentScope,
      @RequestParam(name = "kk_app_id") @NotEmpty(message = "1002") final String sekIdpId,
      final HttpServletResponse response) {

    final String idpState = Nonce.getNonceAsHex(FASTTRACK_IDP_STATE_LENGTH);
    final String idpCodeChallengeMethod = "S256";
    final String idpNonce = Nonce.getNonceAsHex(FASTTRACK_IDP_NONCE_LENGTH);
    final String idpCodeVerifier = generateCodeVerifier(); // top secret

    log.info("Amount of stored fasttrackSessions: {}", fasttrackSessions.size());

    fasttrackSessions.put(
        idpState,
        FasttrackSession.builder()
            .userAgentCodeChallenge(userAgentCodeChallenge)
            .userAgentCodeChallengeMethod(userAgentCodeChallengeMethod)
            .userAgentNonce(userAgentNonce)
            .userAgentId(userAgentClientId)
            .userAgentSekIdp(sekIdpId)
            .userAgentState(userAgentState)
            .userAgentRedirectUri(userAgentRedirectUri)
            .userResponseType(responseType)
            .idpCodeVerifier(idpCodeVerifier)
            .build());

    try {
      final URIBuilder locationBuilder = new URIBuilder(getKkAppUri(sekIdpId));
      locationBuilder
          .addParameter("client_id", "smartcardIdp")
          .addParameter("state", idpState)
          .addParameter("redirect_uri", userAgentRedirectUri)
          .addParameter("code_challenge", generateCodeChallenge(idpCodeVerifier))
          .addParameter("code_challenge_method", idpCodeChallengeMethod)
          .addParameter("response_type", responseType)
          .addParameter("nonce", idpNonce)
          .addParameter("scope", "erp_sek_auth+openid");
      response.setHeader(HttpHeaders.LOCATION, locationBuilder.build().toString());
      setNoCacheHeader(response);
      response.setStatus(HttpStatus.FOUND.value());
    } catch (final URISyntaxException | NoSuchElementException e) {
      throw new IdpServerException(
          "Parameter problem: \"kk_app_id\"", IdpErrorType.INVALID_REQUEST, HttpStatus.BAD_REQUEST);
    }
  }

  /* Fasttrack
   * Request(in)  == message nr.9
   *   Inner Request(out)  == message nr.10
   *   Inner Response(in)  == message nr.11
   * Response(out) == message nr.12
   */
  @PostMapping(value = THIRD_PARTY_ENDPOINT)
  @ValidateClientSystem
  public void postAuthorizationRequestIncludingAuthorizationCode(
      @RequestParam("code") @NotNull(message = "3005") final String authorizationCode,
      @RequestParam(name = "state")
          @NotEmpty(message = "2002")
          @Pattern(regexp = ".+", message = "2006")
          final String idpState,
      @RequestParam(name = "kk_app_redirect_uri") @NotNull(message = "1004") final String kkAppUri,
      final HttpServletResponse response) {
    final FasttrackSession ftSession = fasttrackSessions.get(idpState);
    log.info(
        "idp-sektoral address: "
            + getSekIdpLocation(ftSession.getUserAgentSekIdp())
            + IdpConstants.TOKEN_ENDPOINT);

    // message nr.10 Token Request as http post
    final HttpResponse<JsonNode> sektoralTokenResponse =
        Unirest.post(
                getSekIdpLocation(ftSession.getUserAgentSekIdp()) + IdpConstants.TOKEN_ENDPOINT)
            .field("client_id", "smartcardidp")
            .field("grant_type", "authorization_code")
            .field("code", authorizationCode)
            .field("code_verifier", ftSession.getIdpCodeVerifier())
            .field("redirect_uri", kkAppUri)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
            .asJson();

    log.info("id_token: {}", sektoralTokenResponse.getBody().getObject().getString("id_token"));

    // message nr.12
    final JsonWebToken idToken =
        new JsonWebToken(sektoralTokenResponse.getBody().getObject().getString("id_token"));
    final String authorizationCodeLocation =
        idpAuthenticator.getAuthorizationCodeLocation(idToken, ftSession.getSessionDataAsMap());
    response.setHeader(HttpHeaders.LOCATION, authorizationCodeLocation);
    setNoCacheHeader(response);
    response.setStatus(HttpStatus.FOUND.value());

    fasttrackSessions.remove(idpState);
  }

  private String getKkAppUri(final String kkAppId) {
    return kassenAppList.getAppUri(kkAppId);
  }

  private String getSekIdpLocation(final String sekIdpIdentifier) {
    log.info(
        "Get location of idp-sektoral from environment. Identifier \"{}\" is not used.",
        sekIdpIdentifier);
    return getSystemProperty("IDP_SEKTORAL").orElse("http://127.0.0.1")
        + ":"
        + getSystemProperty("IDP_SEKTORAL_PORT").orElseThrow();
  }

  private void setNoCacheHeader(final HttpServletResponse response) {
    response.setHeader("Cache-Control", "no-store");
    response.setHeader("Pragma", "no-cache");
  }
}
