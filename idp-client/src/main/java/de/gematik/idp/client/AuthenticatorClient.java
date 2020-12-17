/*
 * Copyright (c) 2020 gematik GmbH
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

package de.gematik.idp.client;

import static de.gematik.idp.authentication.UriUtils.*;
import static de.gematik.idp.crypto.CryptoLoader.*;
import static de.gematik.idp.field.ClaimName.*;
import static org.apache.http.HttpHeaders.*;

import de.gematik.idp.authentication.AuthenticationChallenge;
import de.gematik.idp.client.data.AuthenticationRequest;
import de.gematik.idp.client.data.AuthenticationResponse;
import de.gematik.idp.client.data.AuthorizationRequest;
import de.gematik.idp.client.data.AuthorizationResponse;
import de.gematik.idp.client.data.DiscoveryDocumentResponse;
import de.gematik.idp.client.data.TokenRequest;
import de.gematik.idp.token.JsonWebToken;
import de.gematik.idp.token.TokenClaimExtraction;
import java.util.Base64;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Collectors;
import kong.unirest.BodyPart;
import kong.unirest.GetRequest;
import kong.unirest.Header;
import kong.unirest.HttpRequest;
import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.MultipartBody;
import kong.unirest.Unirest;
import kong.unirest.json.JSONObject;
import org.apache.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;

public class AuthenticatorClient {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticatorClient.class);

    public static Map<String, String> getAllHeaderElementsAsMap(final HttpRequest request) {
        return request.getHeaders().all().stream()
            .collect(Collectors.toMap(Header::getName, Header::getValue));
    }

    public static Map<String, Object> getAllFieldElementsAsMap(final MultipartBody request) {
        return request.multiParts().stream()
            .collect(Collectors.toMap(BodyPart::getName, BodyPart::getValue));
    }

    public AuthorizationResponse doAuthorizationRequest(
        final AuthorizationRequest authorizationRequest,
        final Function<GetRequest, GetRequest> beforeCallback,
        final Consumer<HttpResponse<AuthenticationChallenge>> afterCallback
    ) {
        final GetRequest request = Unirest.get(authorizationRequest.getLink())
            .queryString(CLIENT_ID.getJoseName(), authorizationRequest.getClientId())
            .queryString(RESPONSE_TYPE.getJoseName(), "code")
            .queryString(REDIRECT_URI.getJoseName(), authorizationRequest.getRedirectUri())
            .queryString(STATE.getJoseName(), authorizationRequest.getState())
            .queryString(CODE_CHALLENGE.getJoseName(), authorizationRequest.getCodeChallenge())
            .queryString(CODE_CHALLENGE_METHOD.getJoseName(),
                authorizationRequest.getCodeChallengeMethod())
            .queryString(SCOPE.getJoseName(), "openid");

        final HttpResponse<AuthenticationChallenge> authorizationResponse = beforeCallback
            .apply(request)
            .asObject(AuthenticationChallenge.class);
        afterCallback.accept(authorizationResponse);
        if (authorizationResponse.getStatus() != HttpStatus.SC_OK) {
            throw new IdpClientRuntimeException(
                "Unexpected Server-Response " + authorizationResponse.getStatus());
        }
        return AuthorizationResponse.builder()
            .authenticationChallenge(authorizationResponse.getBody())
            .build();
    }

    public AuthenticationResponse performAuthentication(
        final AuthenticationRequest authenticationRequest,
        final Function<MultipartBody, MultipartBody> beforeAuthenticationCallback,
        final Consumer<HttpResponse<String>> afterAuthenticationCallback) {

        final MultipartBody request = Unirest
            .post(authenticationRequest.getAuthenticationEndpointUrl())
            .field("signed_challenge", authenticationRequest.getSignedChallenge())
            .header("Content-Type", "application/x-www-form-urlencoded");

        final HttpResponse<String> loginResponse = beforeAuthenticationCallback.apply(request).asString();
        afterAuthenticationCallback.accept(loginResponse);
        final String location = retrieveLocationFromResponse(loginResponse);
        LOGGER.debug("Location header value aus authentication response: {}", location);
        return AuthenticationResponse.builder()
            .code(extractParameterValue(location, "code"))
            .location(location)
            .ssoToken(extractParameterValue(location, "sso_token"))
            .build();
    }

    public AuthenticationResponse performAuthenticationWithSsoToken(
        final AuthenticationRequest authenticationRequest,
        final Function<MultipartBody, MultipartBody> beforeAuthenticationCallback,
        final Consumer<HttpResponse<String>> afterAuthenticationCallback) {

        final MultipartBody request = Unirest.post(authenticationRequest.getAuthenticationEndpointUrl())
            .field("sso_token", authenticationRequest.getSsoToken())
            .field("challenge_token", authenticationRequest.getChallengeToken())
            .header(CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE);
        final HttpResponse<String> loginResponse = beforeAuthenticationCallback.apply(request).asString();
        afterAuthenticationCallback.accept(loginResponse);
        final String location = retrieveLocationFromResponse(loginResponse);
        LOGGER.debug("Location header value aus Sso authentication response: {}", location);
        return AuthenticationResponse.builder()
            .code(extractParameterValue(location, "code"))
            .location(location)
            .build();
    }

    private String retrieveLocationFromResponse(final HttpResponse<String> response) {
        if (response.getStatus() != 302) {
            throw new IdpClientRuntimeException("Unexpected status code in response: " + response.getStatus());
        }
        return response.getHeaders().getFirst("Location");
    }

    public IdpTokenResult retrieveAcessToken(
        final TokenRequest tokenRequest,
        final Function<MultipartBody, MultipartBody> beforeTokenCallback,
        final Consumer<HttpResponse<JsonNode>> afterTokenCallback) {
        final MultipartBody request = Unirest.post(tokenRequest.getTokenUrl())
            .header(CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .field("grant_type", "authorization_code")
            .field("client_id", tokenRequest.getClientId())
            .field("client_secret", tokenRequest.getClientSecret())
            .field("code", tokenRequest.getCode())
            .field("code_verifier", tokenRequest.getCodeVerifier())
            .field("redirect_uri", tokenRequest.getRedirectUrl());

        final HttpResponse<JsonNode> tokenResponse = beforeTokenCallback.apply(request)
            .asJson();
        afterTokenCallback.accept(tokenResponse);
        if (tokenResponse.getStatus() != HttpStatus.SC_OK) {
            throw new IdpClientRuntimeException(
                "Unexpected Server-Response " + tokenResponse.getStatus());
        }
        final JSONObject jsonObject = tokenResponse.getBody().getObject();

        final String accessTokenRawString = jsonObject.get("access_token").toString();

        final String idTokenRawString = jsonObject.get("id_token").toString();

        final String tokenType = tokenResponse.getBody().getObject().getString("token_type");
        final int expiresIn = tokenResponse.getBody().getObject().getInt("expires_in");

        return IdpTokenResult.builder()
            .tokenType(tokenType)
            .expiresIn(expiresIn)
            .accessToken(new JsonWebToken(accessTokenRawString))
            .idToken(new JsonWebToken(idTokenRawString))
            .ssoToken(new JsonWebToken(tokenRequest.getSsoToken()))
            .build();
    }

    public DiscoveryDocumentResponse retrieveDiscoveryDocument(final String discoveryDocumentUrl) {
        //TODO aufräumen, checks hinzufügen...
        final HttpResponse<String> discoveryDocumentResponse = Unirest.get(discoveryDocumentUrl)
            .asString();
        final Map<String, Object> discoveryClaims = TokenClaimExtraction
            .extractClaimsFromTokenBody(discoveryDocumentResponse.getBody());

        final HttpResponse<JsonNode> pukAuthResponse = Unirest
            .get(discoveryClaims.get("puk_uri_auth").toString())
            .asJson();
        final JSONObject keyObject = pukAuthResponse.getBody().getObject().getJSONArray("keys")
            .getJSONObject(0);

        final String verificationCertificate = keyObject.getJSONArray(X509_Certificate_Chain.getJoseName())
            .getString(0);

        return DiscoveryDocumentResponse.builder()
            .authorizationEndpoint(discoveryClaims.get("authorization_endpoint").toString())
            .tokenEndpoint(discoveryClaims.get("token_endpoint").toString())

            .keyId(keyObject.getString("kid"))
            .verificationCertificate(verificationCertificate)

            .serverTokenCertificate(
                getCertificateFromPem(Base64.getDecoder().decode(verificationCertificate)))

            .build();
    }
}
