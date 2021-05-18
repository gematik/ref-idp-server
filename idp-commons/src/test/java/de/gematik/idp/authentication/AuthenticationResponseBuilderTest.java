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

package de.gematik.idp.authentication;

import static de.gematik.idp.field.ClaimName.NESTED_JWT;
import static de.gematik.idp.field.ClaimName.X509_CERTIFICATE_CHAIN;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.data.UserConsentConfiguration;
import de.gematik.idp.data.UserConsentDescriptionTexts;
import de.gematik.idp.exceptions.IdpJoseException;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.field.IdpScope;
import de.gematik.idp.tests.PkiKeyResolver;
import de.gematik.idp.token.JsonWebToken;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.assertj.core.api.Assertions;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(PkiKeyResolver.class)
public class AuthenticationResponseBuilderTest {

    private AuthenticationResponseBuilder authenticationResponseBuilder;
    private AuthenticationChallengeVerifier authenticationChallengeVerifier;
    private PkiIdentity serverIdentity;
    private PkiIdentity clientIdentity;
    private JwtConsumer serverJwtConsumer;
    private AuthenticationChallenge challenge;

    {
        Security.addProvider(new BouncyCastleProvider());
    }

    @BeforeEach
    public void init(@PkiKeyResolver.Filename("hsm_ecc") final PkiIdentity serverIdentity,
        @PkiKeyResolver.Filename("c.ch.aut-ecc") final PkiIdentity clientIdentity) {
        this.clientIdentity = clientIdentity;
        this.serverIdentity = serverIdentity;

        final AuthenticationChallengeBuilder authenticationChallengeBuilder = AuthenticationChallengeBuilder.builder()
            .serverSigner(new IdpJwtProcessor(serverIdentity))
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
        authenticationResponseBuilder = AuthenticationResponseBuilder.builder()
            .build();
        serverJwtConsumer = new JwtConsumerBuilder()
            .setVerificationKey(clientIdentity.getCertificate().getPublicKey())
            .build();

        authenticationChallengeVerifier = AuthenticationChallengeVerifier.builder()
            .serverIdentity(serverIdentity)
            .build();

        challenge = authenticationChallengeBuilder
            .buildAuthenticationChallenge("goo", "foo", "bar", "schmar", "openid e-rezept", "nonceValue");
    }

    @Test
    public void verifyClientCertificateIsInHeaderAttribute() throws CertificateEncodingException {
        final AuthenticationResponse authenticationResponse =
            authenticationResponseBuilder.buildResponseForChallenge(challenge, clientIdentity);

        Assertions.assertThat(authenticationResponse.getSignedChallenge().getHeaderClaims())
            .extractingByKey(X509_CERTIFICATE_CHAIN.getJoseName(), InstanceOfAssertFactories.LIST)
            .contains(Base64.getEncoder().encodeToString(clientIdentity.getCertificate().getEncoded()));
    }

    @Test
    public void verifyResponseIsSignedByClientIdentity() throws InvalidJwtException {
        final AuthenticationResponse authenticationResponse =
            authenticationResponseBuilder.buildResponseForChallenge(challenge, clientIdentity);
        assertDoesNotThrow(() ->
            serverJwtConsumer.process(authenticationResponse.getSignedChallenge().getRawString())
        );
    }

    @Test
    public void verifyResponseIsNotSignedByServerIdentity() {
        final AuthenticationResponse authenticationResponse =
            authenticationResponseBuilder.buildResponseForChallenge(challenge, clientIdentity);

        assertThatThrownBy(() -> authenticationResponse.getSignedChallenge().verify(
            serverIdentity.getCertificate().getPublicKey()))
            .isInstanceOf(IdpJoseException.class);
    }

    @Test
    public void verifyNestedTokenIsEqualToChallenge() {
        final AuthenticationResponse authenticationResponse =
            authenticationResponseBuilder.buildResponseForChallenge(challenge, clientIdentity);

        Assertions.assertThat(authenticationResponse.getSignedChallenge().getBodyClaims())
            .extractingByKey(ClaimName.NESTED_JWT.getJoseName())
            .isEqualTo(challenge.getChallenge().getRawString());
    }

    @Test
    public void verifyChallengeResponseOnlyContainsNestedJwt() {
        final AuthenticationResponse authenticationResponse =
            authenticationResponseBuilder.buildResponseForChallenge(challenge, clientIdentity);

        final Map<String, Object> extractedClaims = authenticationChallengeVerifier
            .extractClaimsFromSignedChallenge(authenticationResponse);
        assertThat(extractedClaims)
            .containsOnlyKeys(NESTED_JWT.getJoseName())
            .containsEntry(NESTED_JWT.getJoseName(), challenge.getChallenge().getRawString());
    }

    @Test
    public void verifyChallengeResponseOnlyContainsExp() {
        final AuthenticationResponse authenticationResponse =
            authenticationResponseBuilder.buildResponseForChallenge(challenge, clientIdentity);

        Assertions.assertThat(authenticationResponse.getSignedChallenge()
            .getStringBodyClaim(ClaimName.NESTED_JWT)
            .map(JsonWebToken::new)
            .map(token -> token.getHeaderDateTimeClaim(ClaimName.EXPIRES_AT)))
            .isPresent();
    }
}
