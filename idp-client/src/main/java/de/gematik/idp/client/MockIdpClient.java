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

import de.gematik.idp.authentication.*;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.field.IdpScope;
import de.gematik.idp.token.AccessTokenBuilder;
import de.gematik.idp.token.JsonWebToken;
import java.time.LocalDateTime;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import lombok.*;

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
    private final String uriIdpServer;
    private AccessTokenBuilder accessTokenBuilder;
    private AuthenticationResponseBuilder authenticationResponseBuilder;
    private AuthenticationTokenBuilder authenticationTokenBuilder;
    private AuthenticationChallengeBuilder authenticationChallengeBuilder;
    private IdpJwtProcessor jwtProcessor;

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
                IdpScope.EREZEPT.getJwtValue() + " " + IdpScope.OPENID.getJwtValue(), "nonceValue");
        final AuthenticationResponse authenticationResponse = authenticationResponseBuilder
            .buildResponseForChallenge(challenge, clientIdentity);
        final JsonWebToken authenticationToken = authenticationTokenBuilder
            .buildAuthenticationToken(clientIdentity.getCertificate(),
                authenticationResponse.getSignedChallenge().getBodyClaims(), ZonedDateTime.now());

        JsonWebToken accessToken = accessTokenBuilder.buildAccessToken(authenticationToken);

        if (produceOnlyExpiredTokens) {
            accessToken = resignToken(accessToken.getHeaderClaims(),
                accessToken.getBodyClaims(),
                ZonedDateTime.now().minusMinutes(10));
        }

        if (produceTokensWithInvalidSignature) {
            final List<String> strings = Arrays.asList(accessToken.getJwtRawString().split("\\."));
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
        jwtProcessor = new IdpJwtProcessor(serverIdentity);
        accessTokenBuilder = new AccessTokenBuilder(jwtProcessor, uriIdpServer);
        authenticationChallengeBuilder = new AuthenticationChallengeBuilder(serverIdentity, uriIdpServer);
        authenticationResponseBuilder = new AuthenticationResponseBuilder();
        authenticationTokenBuilder = new AuthenticationTokenBuilder(jwtProcessor,
            new AuthenticationChallengeVerifier(serverIdentity));
        return this;
    }

    private void assertThatMockIdClientIsInitialized() {
        Objects.requireNonNull(accessTokenBuilder, "accessTokenBuilder is null. Did you call initialize()?");
        Objects.requireNonNull(authenticationTokenBuilder,
            "authenticationTokenBuilder is null. Did you call initialize()?");
        Objects.requireNonNull(clientId, "clientId is null. You have to set it!");
    }
}
