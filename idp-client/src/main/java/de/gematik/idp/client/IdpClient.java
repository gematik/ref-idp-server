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

import de.gematik.idp.IdpConstants;
import de.gematik.idp.authentication.AuthenticationChallenge;
import de.gematik.idp.authentication.AuthenticationResponseBuilder;
import de.gematik.idp.authentication.UriUtils;
import de.gematik.idp.client.data.*;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.field.CodeChallengeMethod;
import de.gematik.idp.field.IdpScope;
import de.gematik.idp.token.IdpJwe;
import de.gematik.idp.token.JsonWebToken;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Function;
import kong.unirest.GetRequest;
import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.MultipartBody;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.ToString;
import org.apache.commons.lang3.RandomStringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

@Data
@ToString
@AllArgsConstructor
@Builder(toBuilder = true)
public class IdpClient implements IIdpClient {

    private static final Logger LOGGER = LoggerFactory.getLogger(IdpClient.class);
    private static final Consumer NOOP_CONSUMER = o -> {
    };

    private final String clientId;
    private final String redirectUrl;
    private final String discoveryDocumentUrl;
    private final boolean shouldVerifyState;
    @Builder.Default
    private Set<IdpScope> scopes = Set.of(IdpScope.OPENID, IdpScope.EREZEPT);
    @Builder.Default
    private Function<GetRequest, GetRequest> beforeAuthorizationMapper = Function.identity();
    @Builder.Default
    private Consumer<HttpResponse<AuthenticationChallenge>> afterAuthorizationCallback = NOOP_CONSUMER;
    @Builder.Default
    private Function<MultipartBody, MultipartBody> beforeAuthenticationMapper = Function.identity();
    @Builder.Default
    private Consumer<HttpResponse<String>> afterAuthenticationCallback = NOOP_CONSUMER;
    @Builder.Default
    private Function<MultipartBody, MultipartBody> beforeTokenMapper = Function.identity();
    @Builder.Default
    private Consumer<HttpResponse<JsonNode>> afterTokenCallback = NOOP_CONSUMER;
    @Builder.Default
    private AuthenticatorClient authenticatorClient = new AuthenticatorClient();
    @Builder.Default
    private CodeChallengeMethod codeChallengeMethod = CodeChallengeMethod.S256;
    @Builder.Default
    private Function<AuthorizationResponse, AuthorizationResponse> authorizationResponseMapper = Function.identity();
    @Builder.Default
    private Function<AuthenticationResponse, AuthenticationResponse> authenticationResponseMapper = Function.identity();
    private DiscoveryDocumentResponse discoveryDocumentResponse;

    @Override
    public IdpTokenResult login(final PkiIdentity idpIdentity) {
        assertThatIdpIdentityIsValid(idpIdentity);
        assertThatClientIsInitialized();

        final String codeVerifier = ClientUtilities.generateCodeVerifier();
        final String nonce = RandomStringUtils.randomAlphanumeric(20);

        // Authorization
        final String state = RandomStringUtils.randomAlphanumeric(20);
        LOGGER.debug("Performing Authorization with remote-URL '{}'",
            discoveryDocumentResponse.getAuthorizationEndpoint());
        final AuthorizationResponse authorizationResponse = authorizationResponseMapper.apply(
            authenticatorClient
                .doAuthorizationRequest(AuthorizationRequest.builder()
                        .clientId(clientId)
                        .link(discoveryDocumentResponse.getAuthorizationEndpoint())
                        .codeChallenge(ClientUtilities.generateCodeChallenge(codeVerifier))
                        .codeChallengeMethod(codeChallengeMethod)
                        .redirectUri(redirectUrl)
                        .state(state)
                        .scopes(scopes)
                        .nonce(nonce)
                        .build(),
                    beforeAuthorizationMapper,
                    afterAuthorizationCallback));

        // Authentication
        LOGGER.debug("Performing Authentication with remote-URL '{}'",
            discoveryDocumentResponse.getAuthorizationEndpoint());
        final AuthenticationResponse authenticationResponse = authenticationResponseMapper.apply(
            authenticatorClient
                .performAuthentication(AuthenticationRequest.builder()
                        .authenticationEndpointUrl(
                            discoveryDocumentResponse.getAuthorizationEndpoint())
                        .signedChallenge(
                            signChallenge(authorizationResponse.getAuthenticationChallenge(),
                                idpIdentity))
                        .build(),
                    beforeAuthenticationMapper,
                    afterAuthenticationCallback));
        if (shouldVerifyState) {
            final String stringInTokenUrl = UriUtils
                .extractParameterValue(authenticationResponse.getLocation(), "state");
            if (!state.equals(stringInTokenUrl)) {
                throw new IdpClientRuntimeException("state-parameter unexpected changed");
            }
        }

        // get Token
        LOGGER.debug("Performing getToken with remote-URL '{}'", discoveryDocumentResponse.getTokenEndpoint());
        return authenticatorClient.retrieveAcessToken(TokenRequest.builder()
                .tokenUrl(discoveryDocumentResponse.getTokenEndpoint())
                .clientId(clientId)
                .code(authenticationResponse.getCode())
                .ssoToken(authenticationResponse.getSsoToken())
                .redirectUrl(redirectUrl)
                .codeVerifier(codeVerifier)
                .build(),
            beforeTokenMapper,
            afterTokenCallback);
    }

    public IdpTokenResult loginWithSsoToken(final JsonWebToken ssoToken) {
        assertThatClientIsInitialized();

        final String codeVerifier = ClientUtilities.generateCodeVerifier();
        final String nonce = RandomStringUtils.randomAlphanumeric(20);

        // Authorization
        final String state = RandomStringUtils.randomAlphanumeric(20);
        LOGGER.debug("Performing Authorization with remote-URL '{}'",
            discoveryDocumentResponse.getAuthorizationEndpoint());
        final AuthorizationResponse authorizationResponse = authorizationResponseMapper.apply(
            authenticatorClient
                .doAuthorizationRequest(AuthorizationRequest.builder()
                        .clientId(clientId)
                        .link(discoveryDocumentResponse.getAuthorizationEndpoint())
                        .codeChallenge(ClientUtilities.generateCodeChallenge(codeVerifier))
                        .codeChallengeMethod(codeChallengeMethod)
                        .redirectUri(redirectUrl)
                        .state(state)
                        .scopes(scopes)
                        .nonce(nonce)
                        .build(),
                    beforeAuthorizationMapper,
                    afterAuthorizationCallback));

        // Authentication
        final String ssoChallengeEndpoint = discoveryDocumentResponse.getAuthorizationEndpoint().replace(
            IdpConstants.BASIC_AUTHORIZATION_ENDPOINT, IdpConstants.SSO_AUTHORIZATION_ENDPOINT);
        LOGGER.debug("Performing Sso-Authentication with remote-URL '{}'", ssoChallengeEndpoint);
        final AuthenticationResponse authenticationResponse = authenticationResponseMapper.apply(
            authenticatorClient
                .performAuthenticationWithSsoToken(AuthenticationRequest.builder()
                        .authenticationEndpointUrl(ssoChallengeEndpoint)
                        .ssoToken(ssoToken.getJwtRawString())
                        .challengeToken(authorizationResponse.getAuthenticationChallenge().getChallenge())
                        .build(),
                    beforeAuthenticationMapper,
                    afterAuthenticationCallback));
        if (shouldVerifyState) {
            final String stringInTokenUrl = UriUtils
                .extractParameterValue(authenticationResponse.getLocation(), "state");
            if (!state.equals(stringInTokenUrl)) {
                throw new IdpClientRuntimeException("state-parameter unexpected changed");
            }
        }

        // get Token
        LOGGER.debug("Performing getToken with remote-URL '{}'", discoveryDocumentResponse.getTokenEndpoint());
        return authenticatorClient.retrieveAcessToken(TokenRequest.builder()
                .tokenUrl(discoveryDocumentResponse.getTokenEndpoint())
                .clientId(clientId)
                .code(authenticationResponse.getCode())
                .ssoToken(ssoToken.getJwtRawString())
                .redirectUrl(redirectUrl)
                .codeVerifier(codeVerifier)
                .build(),
            beforeTokenMapper,
            afterTokenCallback);
    }

    private void assertThatIdpIdentityIsValid(final PkiIdentity idpIdentity) {
        Objects.requireNonNull(idpIdentity);
        Objects.requireNonNull(idpIdentity.getCertificate());
        Objects.requireNonNull(idpIdentity.getPrivateKey());
    }

    private IdpJwe signChallenge(
        final AuthenticationChallenge authenticationChallenge,
        final PkiIdentity idpIdentity) {
        return AuthenticationResponseBuilder.builder().build()
            .buildResponseForChallenge(authenticationChallenge, idpIdentity)
            .getSignedChallenge()
            .encrypt(discoveryDocumentResponse.getServerTokenCertificate().getPublicKey());
    }

    private void assertThatClientIsInitialized() {
        LOGGER.debug("Verifying IDP-Client initialization...");
        if (discoveryDocumentResponse == null ||
            StringUtils.isEmpty(discoveryDocumentResponse.getKeyId()) ||
            StringUtils.isEmpty(discoveryDocumentResponse.getVerificationCertificate()) ||
            StringUtils.isEmpty(discoveryDocumentResponse.getAuthorizationEndpoint()) ||
            StringUtils.isEmpty(discoveryDocumentResponse.getTokenEndpoint())) {
            throw new IdpClientRuntimeException(
                "IDP-Client not initialized correctly! Call .initialize() before performing an actual operation.");
        }
    }

    @Override
    public IdpClient initialize() {
        LOGGER.info("Initializing using url '{}'", discoveryDocumentUrl);
        discoveryDocumentResponse = authenticatorClient
            .retrieveDiscoveryDocument(discoveryDocumentUrl);
        return this;
    }

    public void verifyAuthTokenToken(final IdpTokenResult authToken) {
        authToken.getAccessToken()
            .verify(discoveryDocumentResponse.getServerTokenCertificate().getPublicKey());
    }

    public void setBeforeAuthorizationCallback(final Consumer<GetRequest> callback) {
        beforeAuthorizationMapper = toNoopIdentity(callback);
    }

    public void setBeforeAuthenticationCallback(final Consumer<MultipartBody> callback) {
        beforeAuthenticationMapper = toNoopIdentity(callback);
    }

    public void setBeforeTokenCallback(final Consumer<MultipartBody> callback) {
        beforeTokenMapper = toNoopIdentity(callback);
    }

    public <T> Function<T, T> toNoopIdentity(final Consumer<T> callback) {
        return t -> {
            callback.accept(t);
            return t;
        };
    }
}
