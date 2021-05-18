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

import de.gematik.idp.IdpConstants;
import de.gematik.idp.authentication.*;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.data.UserConsentConfiguration;
import de.gematik.idp.data.UserConsentDescriptionTexts;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.field.IdpScope;
import de.gematik.idp.token.AccessTokenBuilder;
import de.gematik.idp.token.IdpJwe;
import de.gematik.idp.token.JsonWebToken;
import java.time.LocalDateTime;
import java.time.ZonedDateTime;
import java.util.*;
import java.util.stream.Collectors;
import javax.crypto.spec.SecretKeySpec;
import lombok.*;
import org.apache.commons.codec.digest.DigestUtils;

@Getter
@EqualsAndHashCode
@ToString
@AllArgsConstructor
@Builder(toBuilder = true)
public class MockIdpClient implements IIdpClient {

    private final PkiIdentity serverIdentity;
    private final String clientId;
    private final boolean produceTokensWithInvalidSignature;
    private final boolean produceOnlyExpiredTokens;
    @Builder.Default
    private final String uriIdpServer = IdpConstants.DEFAULT_SERVER_URL;
    private final String serverSubSalt = "someArbitrarySubSaltValue";
    private final Map<IdpScope, String> scopeToAudienceUrls = new HashMap<>();
    private AccessTokenBuilder accessTokenBuilder;
    private AuthenticationResponseBuilder authenticationResponseBuilder;
    private AuthenticationTokenBuilder authenticationTokenBuilder;
    private AuthenticationChallengeBuilder authenticationChallengeBuilder;
    private IdpJwtProcessor jwtProcessor;
    private SecretKeySpec encryptionKey;

    @Override
    public IdpTokenResult login(final PkiIdentity clientIdentity) {
        assertThatMockIdClientIsInitialized();

        return IdpTokenResult.builder()
            .accessToken(buildAccessToken(clientIdentity))
            .validUntil(LocalDateTime.now().plusMinutes(5))
            .build();
    }

    private JsonWebToken buildAccessToken(final PkiIdentity clientIdentity) {
        final AuthenticationChallenge challenge = authenticationChallengeBuilder
            .buildAuthenticationChallenge(clientId, "placeholderValue", "foo", "foo",
                IdpScope.OPENID.getJwtValue() + " " + IdpScope.EREZEPT.getJwtValue(), "nonceValue");
        final AuthenticationResponse authenticationResponse = authenticationResponseBuilder
            .buildResponseForChallenge(challenge, clientIdentity);
        final IdpJwe authenticationToken = authenticationTokenBuilder
            .buildAuthenticationToken(clientIdentity.getCertificate(),
                authenticationResponse.getSignedChallenge().getBodyClaim(ClaimName.NESTED_JWT)
                    .map(Objects::toString)
                    .map(JsonWebToken::new)
                    .map(JsonWebToken::getBodyClaims)
                    .orElseThrow(),
                ZonedDateTime.now());

        JsonWebToken accessToken = accessTokenBuilder.buildAccessToken(
            authenticationToken.decryptNestedJwt(encryptionKey));

        if (produceOnlyExpiredTokens) {
            accessToken = resignToken(accessToken.getHeaderClaims(),
                accessToken.getBodyClaims(),
                ZonedDateTime.now().minusMinutes(10));
        }

        if (produceTokensWithInvalidSignature) {
            final List<String> strings = Arrays.asList(accessToken.getRawString().split("\\."));
            strings.set(2, strings.get(2) + "mvK");
            accessToken = new JsonWebToken(strings.stream()
                .collect(Collectors.joining(".")));
        }

        return accessToken;
    }

    public JsonWebToken resignToken(
        final Map<String, Object> headerClaims,
        final Map<String, Object> bodyClaims,
        final ZonedDateTime expiresAt) {
        Objects.requireNonNull(jwtProcessor, "jwtProcessor is null. Did you call initialize()?");
        return jwtProcessor.buildJwt(new JwtBuilder()
            .addAllBodyClaims(bodyClaims)
            .addAllHeaderClaims(headerClaims)
            .expiresAt(expiresAt));
    }

    @Override
    public MockIdpClient initialize() {
        scopeToAudienceUrls.put(IdpScope.EREZEPT, "https://erp-test.zentral.erp.splitdns.ti-dienste.de/");
        scopeToAudienceUrls.put(IdpScope.PAIRING, "https://idp-pairing-test.zentral.idp.splitdns.ti-dienste.de");

        serverIdentity.setKeyId(Optional.of("puk_idp_sig"));
        serverIdentity.setUse(Optional.of("sig"));
        jwtProcessor = new IdpJwtProcessor(serverIdentity);
        accessTokenBuilder = new AccessTokenBuilder(jwtProcessor, uriIdpServer, serverSubSalt,
            scopeToAudienceUrls);
        authenticationChallengeBuilder = AuthenticationChallengeBuilder.builder()
            .serverSigner(new IdpJwtProcessor(serverIdentity))
            .uriIdpServer(uriIdpServer)
            .userConsentConfiguration(UserConsentConfiguration.builder()
                .claimsToBeIncluded(Map.of(IdpScope.OPENID, List.of(),
                    IdpScope.EREZEPT, List.of(),
                    IdpScope.PAIRING, List.of()))
                .descriptionTexts(UserConsentDescriptionTexts.builder()
                    .claims(Collections.emptyMap())
                    .scopes(Map.of(IdpScope.OPENID, "openid",
                        IdpScope.PAIRING, "pairing",
                        IdpScope.EREZEPT, "erezept"))
                    .build())
                .build())
            .build();
        authenticationResponseBuilder = new AuthenticationResponseBuilder();
        encryptionKey = new SecretKeySpec(DigestUtils.sha256("fdsa"), "AES");
        authenticationTokenBuilder = AuthenticationTokenBuilder.builder()
            .jwtProcessor(jwtProcessor)
            .authenticationChallengeVerifier(new AuthenticationChallengeVerifier(serverIdentity))
            .encryptionKey(encryptionKey)
            .build();
        return this;
    }

    private void assertThatMockIdClientIsInitialized() {
        Objects.requireNonNull(accessTokenBuilder, "accessTokenBuilder is null. Did you call initialize()?");
        Objects.requireNonNull(authenticationTokenBuilder,
            "authenticationTokenBuilder is null. Did you call initialize()?");
        Objects.requireNonNull(clientId, "clientId is null. You have to set it!");
    }
}
