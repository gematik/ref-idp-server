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

package de.gematik.idp.server;

import static de.gematik.idp.brainPoolExtension.BrainpoolAlgorithmSuiteIdentifiers.BRAINPOOL256_USING_SHA256;
import static de.gematik.idp.client.AuthenticatorClient.getAllHeaderElementsAsMap;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.authentication.AuthenticationChallenge;
import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.authentication.UriUtils;
import de.gematik.idp.client.IdpClient;
import de.gematik.idp.client.IdpClientRuntimeException;
import de.gematik.idp.client.IdpTokenResult;
import de.gematik.idp.client.data.AuthenticationResponse;
import de.gematik.idp.client.data.AuthorizationResponse;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.field.IdpScope;
import de.gematik.idp.server.configuration.IdpConfiguration;
import de.gematik.idp.tests.Afo;
import de.gematik.idp.tests.PkiKeyResolver;
import de.gematik.idp.tests.PkiKeyResolver.Filename;
import de.gematik.idp.tests.Remark;
import de.gematik.idp.tests.Rfc;
import de.gematik.idp.token.IdTokenBuilder;
import de.gematik.idp.token.JsonWebToken;
import de.gematik.idp.token.TokenClaimExtraction;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import kong.unirest.Unirest;
import kong.unirest.UnirestException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
@ExtendWith(PkiKeyResolver.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class TokenRetrievalTest {

    @Autowired
    private IdpConfiguration idpConfiguration;
    @Autowired
    private ServerUrlService urlService;
    private IdpClient idpClient;
    private PkiIdentity egkUserIdentity;
    @LocalServerPort
    private int localServerPort;

    @BeforeEach
    public void startup(
        @Filename("109500969_X114428530_c.ch.aut-ecc") final PkiIdentity egkIdentity) {
        idpClient = IdpClient.builder()
            .clientId(IdpConstants.CLIENT_ID)
            .discoveryDocumentUrl("http://localhost:" + localServerPort + "/discoveryDocument")
            .redirectUrl(idpConfiguration.getRedirectUri())
            .build();

        idpClient.initialize();

        egkUserIdentity = PkiIdentity.builder()
            .certificate(egkIdentity.getCertificate())
            .privateKey(egkIdentity.getPrivateKey())
            .build();
    }

    @Rfc("OpenID Connect Core 1.0 incorporating errata set 1 - 2 ID Token")
    @Afo("A_20313")
    @Test
    public void verifyIdTokenClaims() throws UnirestException {
        final IdpTokenResult tokenResponse = idpClient.login(egkUserIdentity);
        final JsonWebToken idToken = new IdTokenBuilder(new IdpJwtProcessor(egkUserIdentity),
            urlService.determineServerUrl())
            .buildIdToken(IdpConstants.CLIENT_ID, tokenResponse.getAccessToken());
        assertThat(tokenResponse.getIdToken().getBodyClaims())
            .containsAllEntriesOf(idToken.getBodyClaims());
    }

    @Rfc({"OpenID Connect Core 1.0 incorporating errata set 1 - 3.1.3.3.  Successful Token Response",
        "RFC6750 October 2012 - 4.  Example Access Token Response"})
    @Afo("A_20463")
    @Remark("ACCESS_TOKEN ist nur 300 s lang gültig, also auch die Response.")
    @Test
    public void verifyExpiresInTokenResponse() throws UnirestException {
        final IdpTokenResult tokenResponse = idpClient.login(egkUserIdentity);

        assertThat(tokenResponse.getExpiresIn())
            .as("ExpiresIn")
            .isEqualTo(300);
    }

    @Rfc({"OpenID Connect Core 1.0 incorporating errata set 1 - 3.1.3.3.  Successful Token Response",
        "RFC6750 October 2012 - 4.  Example Access Token Response"})
    @Test
    public void verifyTokenType() throws UnirestException {
        final IdpTokenResult tokenResponse = idpClient.login(egkUserIdentity);

        assertThat(tokenResponse.getTokenType())
            .as("TokenType")
            .isEqualTo("Bearer");
    }

    @Test
    public void getAccessTokenWithRsa(
        @Filename("833621999741600_c.hci.aut-apo-rsa") final PkiIdentity rsaEgkIdentity) throws UnirestException {
        final IdpTokenResult tokenResponse = idpClient.login(rsaEgkIdentity);

        assertThat(tokenResponse.getTokenType())
            .as("TokenType")
            .isEqualTo("Bearer");
    }

    @Test
    public void authenticationForwardShouldContainSsoToken() throws UnirestException {
        idpClient.setAfterAuthenticationCallback(response ->
            assertThat(response.getHeaders().getFirst("Location"))
                .contains("sso_token="));

        idpClient.login(egkUserIdentity);
    }

    @Rfc("OpenID Connect Core 1.0 incorporating errata set 1 - 3.1.3.3.  Successful Token Response")
    @Test
    public void authenticationHttpHeaderShouldContainCacheControl() throws UnirestException {
        idpClient.setAfterAuthenticationCallback(response ->
            assertThat(response.getHeaders().getFirst("Cache-Control"))
                .contains("no-store"));

        idpClient.login(egkUserIdentity);
    }

    @Rfc("OpenID Connect Core 1.0 incorporating errata set 1 - 3.1.3.3.  Successful Token Response")
    @Test
    public void authenticationHttpHeaderShouldContainPragma() throws UnirestException {
        idpClient.setAfterAuthenticationCallback(response ->
            assertThat(response.getHeaders().getFirst("Pragma"))
                .contains("no-cache"));

        idpClient.login(egkUserIdentity);
    }

    @Rfc("OpenID Connect Core 1.0 incorporating errata set 1 - 3.1.3.3.  Successful Token Response")
    @Test
    public void authorizationHttpHeaderShouldContainCacheControl() throws UnirestException {
        idpClient.setAfterAuthorizationCallback(response ->
            assertThat(response.getHeaders().getFirst("Cache-Control"))
                .contains("no-store"));

        idpClient.login(egkUserIdentity);
    }

    @Rfc("OpenID Connect Core 1.0 incorporating errata set 1 - 3.1.3.3.  Successful Token Response")
    @Test
    public void authorizationHttpHeaderShouldContainPragma() throws UnirestException {
        idpClient.setAfterAuthorizationCallback(response ->
            assertThat(response.getHeaders().getFirst("Pragma"))
                .contains("no-cache"));

        idpClient.login(egkUserIdentity);
    }

    @Rfc("OpenID Connect Core 1.0 incorporating errata set 1 - 3.1.3.3.  Successful Token Response")
    @Test
    public void tokenResponseHttpHeaderShouldContainCacheControl() throws UnirestException {
        idpClient.setAfterTokenCallback(response ->
            assertThat(response.getHeaders().getFirst("Cache-Control"))
                .contains("no-store"));

        idpClient.login(egkUserIdentity);
    }

    @Rfc("OpenID Connect Core 1.0 incorporating errata set 1 - 3.1.3.3.  Successful Token Response")
    @Test
    public void tokenResponseHttpHeaderShouldContainPragma() throws UnirestException {
        idpClient.setAfterTokenCallback(response ->
            assertThat(response.getHeaders().getFirst("Pragma"))
                .contains("no-cache"));

        idpClient.login(egkUserIdentity);
    }

    @Test
    public void ssoTokenAuthorizationShouldReturnCode() throws UnirestException {
        final AtomicReference<String> code = new AtomicReference();
        idpClient.setAfterAuthenticationCallback(response ->
            Optional.of(UriUtils.extractParameterValue(response.getHeaders().getFirst("Location"), "code"))
                .ifPresent(auth_code -> code.set(auth_code)));

        idpClient.loginWithSsoToken(idpClient.login(egkUserIdentity).getSsoToken());

        assertThat(code).isNotNull();
    }

    @Test
    public void getNewAuthenticationCodeViaSsoToken_ResponseURLShouldNotContainSsoToken() throws UnirestException {
        final AtomicReference<String> ssoToken = new AtomicReference();
        idpClient.setAfterAuthenticationCallback(response ->
            Optional.ofNullable(
                UriUtils.extractParameterValue(response.getHeaders().getFirst("Location"), "sso_token"))
                .ifPresent(token -> ssoToken.set(token)));

        assertThatThrownBy(() -> idpClient.loginWithSsoToken(idpClient.login(egkUserIdentity).getSsoToken()))
            .isInstanceOf(RuntimeException.class)
            .hasMessageContaining("sso_token");
    }

    @Test
    public void getNewAccessTokenViaSsoToken_NewAccessTokenShouldHaveLongerValidity() throws UnirestException {
        final IdpTokenResult oldLoginResult = idpClient.login(egkUserIdentity);
        final JsonWebToken newLoginResult = idpClient.loginWithSsoToken(oldLoginResult.getSsoToken()).getAccessToken();

        assertThat(oldLoginResult.getAccessToken().getExpiresAt())
            .isBeforeOrEqualTo(newLoginResult.getExpiresAt());
    }

    @Test
    public void loginWithoutAndThenWithSsoToken_codeChallengeShouldDiffer() throws UnirestException {
        final AtomicReference<JsonWebToken> oldCodeChallenge = new AtomicReference();
        final AtomicReference<JsonWebToken> newCodeChallenge = new AtomicReference();

        idpClient.setAfterAuthenticationCallback(
            response -> oldCodeChallenge.set(extractAuthenticationTokenFromResponse(response, "code")));

        final IdpTokenResult oldLoginResult = idpClient.login(egkUserIdentity);

        idpClient.setAfterAuthenticationCallback(
            response -> newCodeChallenge.set(extractAuthenticationTokenFromResponse(response, "code")));

        idpClient.loginWithSsoToken(oldLoginResult.getSsoToken()).getAccessToken();

        assertThat(oldCodeChallenge.get().getBodyClaim(ClaimName.CODE_CHALLENGE).get())
            .isNotEqualTo(newCodeChallenge.get().getBodyClaim(ClaimName.CODE_CHALLENGE).get());
    }

    @Test
    public void ssoTokenCnfClaimShouldBeJsonObject() throws UnirestException {
        final IdpTokenResult tokenResult = idpClient.login(egkUserIdentity);

        assertThat(tokenResult.getSsoToken().getBodyClaim(ClaimName.CONFIRMATION).get())
            .isInstanceOf(Map.class);
    }

    @Test
    public void ssoTokenShouldNotContainNjwtClaim() throws UnirestException {
        final IdpTokenResult tokenResult = idpClient.login(egkUserIdentity);
        assertThat(tokenResult.getSsoToken().getBodyClaims())
            .doesNotContainKey(ClaimName.NESTED_JWT.getJoseName());
    }

    @Test
    public void verifyTokenAlgorithm() throws UnirestException {
        final IdpTokenResult tokenResponse = idpClient.login(egkUserIdentity);

        assertThat(TokenClaimExtraction
            .extractClaimsFromTokenHeader(tokenResponse.getAccessToken().getJwtRawString()))
            .as("'alg'-Header field")
            .containsEntry("alg", BRAINPOOL256_USING_SHA256);
    }

    @Test
    public void verifyTokenContainsAcr() throws UnirestException {
        final IdpTokenResult tokenResponse = idpClient.login(egkUserIdentity);

        assertThat(TokenClaimExtraction
            .extractClaimsFromTokenBody(tokenResponse.getAccessToken().getJwtRawString()))
            .containsEntry("acr", "eidas-loa-high");
    }

    @Test
    public void verifyTokenContainsGematikClaims() throws UnirestException {
        final IdpTokenResult tokenResponse = idpClient.login(egkUserIdentity);

        assertThat(TokenClaimExtraction
            .extractClaimsFromTokenBody(tokenResponse.getAccessToken().getJwtRawString()))
            .containsKeys("professionOID"); // This is the most robust claim
    }

    @Test
    public void assertThatTokenIsValid() throws UnirestException {
        final IdpTokenResult tokenResponse = idpClient.login(egkUserIdentity);

        idpClient.verifyAuthTokenToken(tokenResponse);
    }

    @Test
    public void testSmcbLogin(@Filename("c.hci.aut-apo-ecc") final PkiIdentity smcbEccIdentity)
        throws UnirestException {
        final PkiIdentity smcbIdentity = PkiIdentity.builder()
            .certificate(smcbEccIdentity.getCertificate())
            .privateKey(smcbEccIdentity.getPrivateKey())
            .build();

        final IdpTokenResult tokenResponse = idpClient.login(smcbIdentity);

        idpClient.verifyAuthTokenToken(tokenResponse);
    }

    @Test
    public void testLoginHba(@Filename("80276883110000129084-C_HP_AUT_E256") final PkiIdentity failIdentity)
        throws UnirestException {
        final PkiIdentity smcbIdentity = PkiIdentity.builder()
            .certificate(failIdentity.getCertificate())
            .privateKey(failIdentity.getPrivateKey())
            .build();

        final IdpTokenResult tokenResponse = idpClient.login(smcbIdentity);

        idpClient.verifyAuthTokenToken(tokenResponse);
    }

    @Afo("A_20376")
    @Test
    public void stateParameterNotGivenInInitialRequest_ServerShouldGiveError()
        throws UnirestException {
        idpClient.setBeforeAuthorizationMapper(request -> Unirest
            .get(request.getUrl().replaceFirst("&state=[\\w-_.~]*", ""))
            .headers(getAllHeaderElementsAsMap(request)));

        assertThatThrownBy(() -> idpClient.login(egkUserIdentity))
            .isInstanceOf(IdpClientRuntimeException.class)
            .hasMessageContaining("Server-Response");
    }

    @Afo("A_20377")
    @Test
    public void stateParameterShouldBeEqualInFirstAndLastRequest() throws UnirestException {
        idpClient.setBeforeAuthorizationMapper(request -> Unirest
            .get(request.getUrl()
                .replaceFirst("&state=[\\w-_.~]*", "&state=foobar"))
            .headers(getAllHeaderElementsAsMap(request)));

        idpClient.setAfterAuthenticationCallback(request -> assertThat(
            Optional.ofNullable(request.getHeaders().getFirst("Location"))
                .map(location -> UriUtils.extractParameterValue(location, "state"))
                .orElseThrow())
            .isEqualTo("foobar"));

        idpClient.login(egkUserIdentity);
    }

    @Afo("A_20376")
    @Test
    public void stateParameterGiven_shouldBePresentInRedirect() throws UnirestException {
        idpClient.setAfterAuthenticationCallback(
            request -> assertThat(Optional.ofNullable(request.getHeaders().getFirst("Location"))
                .map(location -> UriUtils.extractParameterValue(location, "state"))
                .orElseThrow())
                .isNotBlank());

        idpClient.login(egkUserIdentity);
    }

    @Rfc("RFC6749, 4.1.3")
    @Test
    public void missmatchedRedirectUri_shouldGiveErrorOnTokenRetrieval() throws UnirestException {
        idpClient.setBeforeTokenCallback(body -> body.field("redirect_uri", "wrongValue"));

        assertThatThrownBy(() -> idpClient.login(egkUserIdentity))
            .isInstanceOf(IdpClientRuntimeException.class)
            .hasMessageContaining("Server-Response");
    }

    @Test
    public void scopeWithoutErezept_shouldGiveNoAccessToken() throws UnirestException {
        idpClient.setScopes(Set.of(IdpScope.OPENID));

        final IdpTokenResult tokenResponse = idpClient.login(egkUserIdentity);

        assertThat(tokenResponse.getAccessToken()).isNull();
        assertThat(tokenResponse.getIdToken()).isNotNull();
        assertThat(tokenResponse.getSsoToken()).isNotNull();
    }

    @Test
    public void resignedChallengeTokenWithDifferentIdentity_ShouldGiveServerError(
        @Filename("80276883110000129084-C_HP_AUT_E256.p12") final PkiIdentity notTheServerIdentity)
        throws UnirestException {
        final IdpJwtProcessor differentSigner = new IdpJwtProcessor(notTheServerIdentity);
        idpClient.setAuthorizationResponseMapper(response -> {
            final JsonWebToken originalChallenge = new JsonWebToken(
                response.getAuthenticationChallenge().getChallenge());
            final JsonWebToken resignedChallenge = differentSigner.buildJwt(originalChallenge.toJwtDescription());
            return AuthorizationResponse.builder()
                .authenticationChallenge(AuthenticationChallenge.builder()
                    .userConsent(response.getAuthenticationChallenge().getUserConsent())
                    .challenge(resignedChallenge.getJwtRawString())
                    .build())
                .build();
        });

        assertThatThrownBy(() -> idpClient.login(egkUserIdentity))
            .isInstanceOf(IdpClientRuntimeException.class);
    }

    @Test
    public void resignedAuthenticationTokenWithDifferentIdentity_ShouldGiveServerError(
        @Filename("80276883110000129084-C_HP_AUT_E256.p12") final PkiIdentity notTheServerIdentity)
        throws UnirestException {
        final IdpJwtProcessor differentSigner = new IdpJwtProcessor(notTheServerIdentity);
        idpClient.setAuthenticationResponseMapper(response -> {
            final JsonWebToken originalChallenge = new JsonWebToken(response.getCode());
            final JsonWebToken resignedChallenge = differentSigner.buildJwt(originalChallenge.toJwtDescription());
            return AuthenticationResponse.builder()
                .ssoToken(response.getSsoToken())
                .location(response.getLocation())
                .code(resignedChallenge.getJwtRawString())
                .build();
        });

        assertThatThrownBy(() -> idpClient.login(egkUserIdentity))
            .isInstanceOf(IdpClientRuntimeException.class);
    }

    @Test
    public void scopeWithoutOpenid_shouldGiveNoAccessToken() throws UnirestException {
        idpClient.setScopes(Set.of(IdpScope.EREZEPT));

        assertThatThrownBy(() -> idpClient.login(egkUserIdentity))
            .isInstanceOf(IdpClientRuntimeException.class)
            .hasMessageContaining("Server-Response");
    }

    @Test
    public void scopeOpenIdAndPairing_shouldGiveAccessToken() throws UnirestException {
        idpClient.setScopes(Set.of(IdpScope.OPENID, IdpScope.PAIRING));
        final IdpTokenResult loginResult = idpClient.login(egkUserIdentity);

        assertThat(loginResult.getAccessToken().getScopesBodyClaim())
            .containsExactlyInAnyOrder(IdpScope.OPENID, IdpScope.PAIRING);
    }

    @Test
    public void scopeOpenIdErezeptAndPairing_shouldGiveAccessToken() throws UnirestException {
        idpClient.setScopes(Set.of(IdpScope.OPENID, IdpScope.PAIRING, IdpScope.EREZEPT));
        final IdpTokenResult loginResult = idpClient.login(egkUserIdentity);

        assertThat(loginResult.getAccessToken().getScopesBodyClaim())
            .containsExactlyInAnyOrder(IdpScope.OPENID, IdpScope.PAIRING, IdpScope.EREZEPT);
    }

    private JsonWebToken extractAuthenticationTokenFromResponse(final kong.unirest.HttpResponse<String> response,
        final String parameterName) {
        return Optional.ofNullable(response.getHeaders().getFirst("Location"))
            .map(uri -> UriUtils.extractParameterValue(uri, parameterName))
            .map(code -> new JsonWebToken(code))
            .get();
    }
}
