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

package de.gematik.idp.client;

import static de.gematik.idp.authentication.UriUtils.extractParameterValue;
import static de.gematik.idp.crypto.CryptoLoader.getCertificateFromPem;
import static de.gematik.idp.field.ClaimName.*;
import static org.apache.http.HttpHeaders.CONTENT_TYPE;
import de.gematik.idp.authentication.AuthenticationChallenge;
import de.gematik.idp.authentication.UriUtils;
import de.gematik.idp.client.data.*;
import de.gematik.idp.field.IdpScope;
import de.gematik.idp.token.IdpJwe;
import de.gematik.idp.token.JsonWebToken;
import de.gematik.idp.token.TokenClaimExtraction;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Collectors;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.ws.rs.core.HttpHeaders;
import kong.unirest.*;
import kong.unirest.jackson.JacksonObjectMapper;
import kong.unirest.json.JSONObject;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.http.HttpStatus;
import org.jose4j.jwt.JwtClaims;
import org.springframework.http.MediaType;

public class AuthenticatorClient {

    {
        Unirest.config().setObjectMapper(new JacksonObjectMapper());
    }

    private static final String USER_AGENT = "IdP-Client";

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
        final String scope = authorizationRequest.getScopes().stream()
            .map(IdpScope::getJwtValue)
            .collect(Collectors.joining(" "));

        final GetRequest request = Unirest.get(authorizationRequest.getLink())
            .queryString(CLIENT_ID.getJoseName(), authorizationRequest.getClientId())
            .queryString(RESPONSE_TYPE.getJoseName(), "code")
            .queryString(REDIRECT_URI.getJoseName(), authorizationRequest.getRedirectUri())
            .queryString(STATE.getJoseName(), authorizationRequest.getState())
            .queryString(CODE_CHALLENGE.getJoseName(), authorizationRequest.getCodeChallenge())
            .queryString(CODE_CHALLENGE_METHOD.getJoseName(),
                authorizationRequest.getCodeChallengeMethod())
            .queryString(SCOPE.getJoseName(), scope)
            .queryString("nonce", authorizationRequest.getNonce())
            .header(HttpHeaders.USER_AGENT, USER_AGENT);

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
            .field("signed_challenge", authenticationRequest.getSignedChallenge().getRawString())
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header(HttpHeaders.USER_AGENT, USER_AGENT);

        final HttpResponse<String> loginResponse = beforeAuthenticationCallback.apply(request).asString();
        afterAuthenticationCallback.accept(loginResponse);
        final String location = retrieveLocationFromResponse(loginResponse);

        checkForForwardingExceptionAndThrowIfPresent(location);

        return AuthenticationResponse.builder()
            .code(extractParameterValue(location, "code"))
            .location(location)
            .ssoToken(extractParameterValue(location, "ssotoken"))
            .build();
    }

    private void checkForForwardingExceptionAndThrowIfPresent(final String location) {
        UriUtils.extractParameterValueOptional(location, "error")
            .ifPresent(errorCode -> {
                throw new IdpClientRuntimeException("Server-Error with message: " +
                    UriUtils.extractParameterValueOptional(location, "error_description")
                        .orElse(errorCode));
            });
    }

    public AuthenticationResponse performAuthenticationWithSsoToken(
        final AuthenticationRequest authenticationRequest,
        final Function<MultipartBody, MultipartBody> beforeAuthenticationCallback,
        final Consumer<HttpResponse<String>> afterAuthenticationCallback) {
        final MultipartBody request = Unirest.post(authenticationRequest.getAuthenticationEndpointUrl())
            .field("ssotoken", authenticationRequest.getSsoToken())
            .field("unsigned_challenge", authenticationRequest.getChallengeToken().getRawString())
            .header(CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .header(HttpHeaders.USER_AGENT, USER_AGENT);
        final HttpResponse<String> loginResponse = beforeAuthenticationCallback.apply(request).asString();
        afterAuthenticationCallback.accept(loginResponse);
        final String location = retrieveLocationFromResponse(loginResponse);
        checkForForwardingExceptionAndThrowIfPresent(location);
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

    public IdpTokenResult retrieveAccessToken(
        final TokenRequest tokenRequest,
        final Function<MultipartBody, MultipartBody> beforeTokenCallback,
        final Consumer<HttpResponse<JsonNode>> afterTokenCallback) {
        final byte[] tokenKeyBytes = RandomStringUtils.randomAlphanumeric(256 / 8).getBytes();
        final SecretKey tokenKey = new SecretKeySpec(tokenKeyBytes, "AES");
        final IdpJwe keyVerifierToken = buildKeyVerifierToken(tokenKeyBytes, tokenRequest.getCodeVerifier(),
            tokenRequest.getIdpEnc());

        final MultipartBody request = Unirest.post(tokenRequest.getTokenUrl())
            .header(CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .field("grant_type", "authorization_code")
            .field("client_id", tokenRequest.getClientId())
            .field("code", tokenRequest.getCode())
            .field("key_verifier", keyVerifierToken.getRawString())
            .field("redirect_uri", tokenRequest.getRedirectUrl())
            .header(HttpHeaders.USER_AGENT, USER_AGENT);

        final HttpResponse<JsonNode> tokenResponse = beforeTokenCallback.apply(request)
            .asJson();
        afterTokenCallback.accept(tokenResponse);
        if (tokenResponse.getStatus() != HttpStatus.SC_OK) {
            throw new IdpClientRuntimeException(
                "Unexpected Server-Response " + tokenResponse.getStatus() + " with detail_message "
                    + tokenResponse.getBody().getObject().getString("detail_message"));
        }
        final JSONObject jsonObject = tokenResponse.getBody().getObject();

        final String tokenType = tokenResponse.getBody().getObject().getString("token_type");
        final int expiresIn = tokenResponse.getBody().getObject().getInt("expires_in");

        return IdpTokenResult.builder()
            .tokenType(tokenType)
            .expiresIn(expiresIn)
            .accessToken(decryptToken(tokenKey, jsonObject.get("access_token")))
            .idToken(decryptToken(tokenKey, jsonObject.get("id_token")))
            .ssoToken(new IdpJwe(tokenRequest.getSsoToken()))
            .build();
    }

    private JsonWebToken decryptToken(final SecretKey tokenKey, final Object tokenValue) {
        return Optional.ofNullable(tokenValue)
            .filter(String.class::isInstance)
            .map(String.class::cast)
            .map(IdpJwe::new)
            .map(jwe -> jwe.decryptNestedJwt(tokenKey))
            .orElseThrow(() -> new IdpClientRuntimeException("Unable to extract Access-Token from response!"));
    }

    private IdpJwe buildKeyVerifierToken(final byte[] tokenKeyBytes, final String codeVerifier,
        final PublicKey idpEnc) {
        final JwtClaims claims = new JwtClaims();
        claims.setStringClaim(TOKEN_KEY.getJoseName(), new String(Base64.getEncoder().encode(tokenKeyBytes)));
        claims.setStringClaim(CODE_VERIFIER.getJoseName(), codeVerifier);

        return IdpJwe.createWithPayloadAndEncryptWithKey(claims.toJson(), idpEnc);
    }

    public DiscoveryDocumentResponse retrieveDiscoveryDocument(final String discoveryDocumentUrl) {
        //TODO aufräumen, checks hinzufügen...
        final HttpResponse<String> discoveryDocumentResponse = Unirest.get(discoveryDocumentUrl)
            .header(HttpHeaders.USER_AGENT, USER_AGENT)
            .asString();
        final Map<String, Object> discoveryClaims = TokenClaimExtraction
            .extractClaimsFromJwtBody(discoveryDocumentResponse.getBody());

        final HttpResponse<JsonNode> pukAuthResponse = Unirest
            .get(discoveryClaims.get("uri_puk_idp_sig").toString())
            .header(HttpHeaders.USER_AGENT, USER_AGENT)
            .asJson();
        final JSONObject keyObject = pukAuthResponse.getBody().getObject();

        final String verificationCertificate = keyObject.getJSONArray(X509_CERTIFICATE_CHAIN.getJoseName())
            .getString(0);

        return DiscoveryDocumentResponse.builder()
            .authorizationEndpoint(discoveryClaims.get("authorization_endpoint").toString())
            .tokenEndpoint(discoveryClaims.get("token_endpoint").toString())

            .idpSig(retrieveServerCertFromLocation(discoveryClaims.get("uri_puk_idp_sig").toString()))
            .idpEnc(retrieveServerCertFromLocation(discoveryClaims.get("uri_puk_idp_enc").toString()))

            .build();
    }

    private X509Certificate retrieveServerCertFromLocation(final String uri) {
        final HttpResponse<JsonNode> pukAuthResponse = Unirest
            .get(uri)
            .header(HttpHeaders.USER_AGENT, USER_AGENT)
            .asJson();
        final JSONObject keyObject = pukAuthResponse.getBody().getObject();
        final String verificationCertificate = keyObject.getJSONArray(X509_CERTIFICATE_CHAIN.getJoseName())
            .getString(0);
        return getCertificateFromPem(Base64.getDecoder().decode(verificationCertificate));
    }
}
