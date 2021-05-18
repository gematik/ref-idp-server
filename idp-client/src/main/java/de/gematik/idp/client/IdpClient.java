/*
 * Copyright (c) 2021 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.idp.client;

import static de.gematik.idp.brainPoolExtension.BrainpoolAlgorithmSuiteIdentifiers.BRAINPOOL256_USING_SHA256;
import static de.gematik.idp.crypto.KeyAnalysis.isEcKey;
import static org.jose4j.jws.AlgorithmIdentifiers.RSA_PSS_USING_SHA256;
import static org.jose4j.jws.EcdsaUsingShaAlgorithm.convertDerToConcatenated;

import de.gematik.idp.authentication.AuthenticationChallenge;
import de.gematik.idp.authentication.JwtBuilder;
import de.gematik.idp.authentication.UriUtils;
import de.gematik.idp.brainPoolExtension.BrainpoolCurves;
import de.gematik.idp.client.data.*;
import de.gematik.idp.crypto.EcSignerUtility;
import de.gematik.idp.crypto.exceptions.IdpCryptoException;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.field.CodeChallengeMethod;
import de.gematik.idp.field.IdpScope;
import de.gematik.idp.token.IdpJwe;
import de.gematik.idp.token.JsonWebToken;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.*;
import java.util.function.Consumer;
import java.util.function.Function;
import kong.unirest.GetRequest;
import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.MultipartBody;
import lombok.*;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Data
@ToString
@AllArgsConstructor
@Builder(toBuilder = true)
public class IdpClient implements IIdpClient {

    static {
        BrainpoolCurves.init();
    }

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

    @SneakyThrows
    private String signServerChallenge(final String challengeToSign, final X509Certificate certificate,
        final Function<byte[], byte[]> contentSigner) {
        final JwtClaims claims = new JwtClaims();
        claims.setClaim(ClaimName.NESTED_JWT.getJoseName(), challengeToSign);
        final JsonWebSignature jsonWebSignature = new JsonWebSignature();
        jsonWebSignature.setPayload(claims.toJson());
        jsonWebSignature.setHeader("typ", "JWT");
        jsonWebSignature.setHeader("cty", "NJWT");
        jsonWebSignature.setCertificateChainHeaderValue(certificate);
        if (isEcKey(certificate.getPublicKey())) {
            jsonWebSignature.setAlgorithmHeaderValue(BRAINPOOL256_USING_SHA256);
        } else {
            jsonWebSignature.setAlgorithmHeaderValue(RSA_PSS_USING_SHA256);
        }
        final String signedJwt = jsonWebSignature.getHeaders().getEncodedHeader() + "."
            + jsonWebSignature.getEncodedPayload() + "."
            + Base64.getUrlEncoder().withoutPadding().encodeToString(
            getSignatureBytes(contentSigner, jsonWebSignature));
        return new JsonWebToken(signedJwt)
            .encrypt(discoveryDocumentResponse.getIdpEnc())
            .getRawString();
    }

    private byte[] getSignatureBytes(final Function<byte[], byte[]> contentSigner,
        final JsonWebSignature jsonWebSignature) {
        final byte[] signatureBytes = contentSigner.apply((jsonWebSignature.getHeaders().getEncodedHeader() + "."
            + jsonWebSignature.getEncodedPayload()).getBytes(StandardCharsets.UTF_8));
        try {
            final byte[] strippedSignatureBytes = convertDerToConcatenated(signatureBytes, 64);
            return strippedSignatureBytes;
        } catch (final IOException e) {
            return signatureBytes;
        }
    }

    @Override
    public IdpTokenResult login(final PkiIdentity idpIdentity) {
        assertThatIdpIdentityIsValid(idpIdentity);
        return login(idpIdentity.getCertificate(),
            tbsData -> {
                if (idpIdentity.getPrivateKey() instanceof RSAPrivateKey) {
                    return createRsaSignature(tbsData, idpIdentity.getPrivateKey());
                } else {
                    return EcSignerUtility.createEcSignature(tbsData, idpIdentity.getPrivateKey());
                }
            });
    }

    private byte[] createRsaSignature(final byte[] toBeSignedData, final PrivateKey privateKey) {
        try {
            final Signature signer = Signature.getInstance("SHA256withRSAAndMGF1", new BouncyCastleProvider());
            signer.initSign(privateKey);
            signer.update(toBeSignedData);
            return signer.sign();
        } catch (final NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new IdpCryptoException(e);
        }
    }

    public IdpTokenResult login(final X509Certificate certificate, final Function<byte[], byte[]> contentSigner) {
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
                        .signedChallenge(new IdpJwe(
                            signServerChallenge(
                                authorizationResponse.getAuthenticationChallenge().getChallenge().getRawString(),
                                certificate, contentSigner)))
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
        return authenticatorClient.retrieveAccessToken(TokenRequest.builder()
                .tokenUrl(discoveryDocumentResponse.getTokenEndpoint())
                .clientId(clientId)
                .code(authenticationResponse.getCode())
                .ssoToken(authenticationResponse.getSsoToken())
                .redirectUrl(redirectUrl)
                .codeVerifier(codeVerifier)
                .idpEnc(discoveryDocumentResponse.getIdpEnc())
                .build(),
            beforeTokenMapper,
            afterTokenCallback);
    }

    public IdpTokenResult loginWithSsoToken(final IdpJwe ssoToken) {
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
        final String ssoChallengeEndpoint = discoveryDocumentResponse.getSsoEndpoint();
        LOGGER.debug("Performing Sso-Authentication with remote-URL '{}'", ssoChallengeEndpoint);
        final AuthenticationResponse authenticationResponse = authenticationResponseMapper.apply(
            authenticatorClient
                .performAuthenticationWithSsoToken(AuthenticationRequest.builder()
                        .authenticationEndpointUrl(ssoChallengeEndpoint)
                        .ssoToken(ssoToken.getRawString())
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
        return authenticatorClient.retrieveAccessToken(TokenRequest.builder()
                .tokenUrl(discoveryDocumentResponse.getTokenEndpoint())
                .clientId(clientId)
                .code(authenticationResponse.getCode())
                .ssoToken(ssoToken.getRawString())
                .redirectUrl(redirectUrl)
                .codeVerifier(codeVerifier)
                .idpEnc(discoveryDocumentResponse.getIdpEnc())
                .build(),
            beforeTokenMapper,
            afterTokenCallback);
    }

    public IdpTokenResult loginWithAltAuth(final RegistrationData registrationData, final PrivateKey privateKey) {
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

        final JsonWebToken signedPairingData = new JsonWebToken(registrationData.getSignedPairingData());
        final JsonWebToken signedAuthenticationData = new JwtBuilder()
            .addBodyClaim(ClaimName.EXPIRES_AT,
                authorizationResponse.getAuthenticationChallenge().getChallenge()
                    .getBodyClaim(ClaimName.EXPIRES_AT).get())
            .addBodyClaim(ClaimName.CHALLENGE_TOKEN,
                authorizationResponse.getAuthenticationChallenge().getChallenge().getRawString())
            .addBodyClaim(ClaimName.AUTHENTICATION_CERTIFICATE, registrationData.getAuthCert())
            .addBodyClaim(ClaimName.AUTHENTICATION_DATA_VERSION, "1.0")
            .addBodyClaim(ClaimName.KEY_IDENTIFIER,
                signedPairingData.getBodyClaim(ClaimName.KEY_IDENTIFIER).orElseThrow())
            .addBodyClaim(ClaimName.DEVICE_INFORMATION, Map.of(
                "name", registrationData.getDeviceInformation().getName(),
                "device_information_data_version",
                registrationData.getDeviceInformation().getDeviceInformationDataVersion(),
                "device_type", Map.of(
                    "device_type_data_version",
                    registrationData.getDeviceInformation().getDeviceType().getDeviceTypeDataVersion(),
                    "product", registrationData.getDeviceInformation().getDeviceType().getProduct(),
                    "model", registrationData.getDeviceInformation().getDeviceType().getModel(),
                    "os", registrationData.getDeviceInformation().getDeviceType().getOs(),
                    "os_version", registrationData.getDeviceInformation().getDeviceType().getOsVersion(),
                    "manufacturer", registrationData.getDeviceInformation().getDeviceType().getManufacturer()
                )
            ))
            .addBodyClaim(ClaimName.AUTHENTICATION_METHODS_REFERENCE, List.of("mfa", "hwk", "face"))
            .setSignerKey(privateKey)
            .buildJwt();

        // Authentication
        LOGGER.debug("Performing Authentication with remote-URL '{}'",
            discoveryDocumentResponse.getAuthorizationEndpoint());
        final AuthenticationResponse authenticationResponse = authenticationResponseMapper.apply(
            authenticatorClient
                .performAuthenticationWithAltAuth(AuthenticationRequest.builder()
                        .authenticationEndpointUrl(discoveryDocumentResponse.getAuthPairEndpoint())
                        .encryptedSignedAuthenticationData(signedAuthenticationData
                            .encrypt(discoveryDocumentResponse.getIdpEnc()))
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
        return authenticatorClient.retrieveAccessToken(TokenRequest.builder()
                .tokenUrl(discoveryDocumentResponse.getTokenEndpoint())
                .clientId(clientId)
                .code(authenticationResponse.getCode())
                .ssoToken(authenticationResponse.getSsoToken())
                .redirectUrl(redirectUrl)
                .codeVerifier(codeVerifier)
                .idpEnc(discoveryDocumentResponse.getIdpEnc())
                .build(),
            beforeTokenMapper,
            afterTokenCallback);
    }

    private void assertThatIdpIdentityIsValid(final PkiIdentity idpIdentity) {
        Objects.requireNonNull(idpIdentity);
        Objects.requireNonNull(idpIdentity.getCertificate());
        Objects.requireNonNull(idpIdentity.getPrivateKey());
    }

    private void assertThatClientIsInitialized() {
        LOGGER.debug("Verifying IDP-Client initialization...");
        if (discoveryDocumentResponse == null ||
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
            .verify(discoveryDocumentResponse.getIdpSig().getPublicKey());
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