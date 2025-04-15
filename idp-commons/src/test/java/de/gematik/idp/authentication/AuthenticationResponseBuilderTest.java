/*
 * Copyright (Date see Readme), gematik GmbH
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
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

package de.gematik.idp.authentication;

import static de.gematik.idp.field.ClaimName.FAMILY_NAME;
import static de.gematik.idp.field.ClaimName.GIVEN_NAME;
import static de.gematik.idp.field.ClaimName.NESTED_JWT;
import static de.gematik.idp.field.ClaimName.X509_CERTIFICATE_CHAIN;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.data.ScopeConfiguration;
import de.gematik.idp.data.UserConsentConfiguration;
import de.gematik.idp.data.UserConsentDescriptionTexts;
import de.gematik.idp.exceptions.IdpJoseException;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.tests.PkiKeyResolver;
import de.gematik.idp.token.JsonWebToken;
import java.security.PublicKey;
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
class AuthenticationResponseBuilderTest {

  static {
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    Security.insertProviderAt(new BouncyCastleProvider(), 1);
  }

  private AuthenticationResponseBuilder authenticationResponseBuilder;
  private AuthenticationChallengeVerifier authenticationChallengeVerifier;
  private PkiIdentity serverIdentity;
  private PkiIdentity clientIdentity;
  private JwtConsumer serverJwtConsumer;
  private AuthenticationChallenge challenge;

  @BeforeEach
  public void init(
      @PkiKeyResolver.Filename("idp_sig") final PkiIdentity serverIdentity,
      @PkiKeyResolver.Filename("c.ch.aut-ecc") final PkiIdentity clientIdentity) {
    this.clientIdentity = clientIdentity;
    this.serverIdentity = serverIdentity;
    final ScopeConfiguration openidConfig =
        ScopeConfiguration.builder().description("openid desc").build();
    final ScopeConfiguration pairingConfig =
        ScopeConfiguration.builder()
            .audienceUrl("erplala")
            .description("erp desc")
            .claimsToBeIncluded(List.of(GIVEN_NAME, FAMILY_NAME))
            .build();

    final AuthenticationChallengeBuilder authenticationChallengeBuilder =
        AuthenticationChallengeBuilder.builder()
            .serverSigner(new IdpJwtProcessor(serverIdentity))
            .userConsentConfiguration(
                UserConsentConfiguration.builder()
                    .descriptionTexts(
                        UserConsentDescriptionTexts.builder()
                            .claims(Collections.emptyMap())
                            .build())
                    .build())
            .scopesConfiguration(Map.of("openid", openidConfig, "pairing", pairingConfig))
            .build();
    authenticationResponseBuilder = AuthenticationResponseBuilder.builder().build();
    serverJwtConsumer =
        new JwtConsumerBuilder()
            .setVerificationKey(clientIdentity.getCertificate().getPublicKey())
            .build();

    authenticationChallengeVerifier =
        AuthenticationChallengeVerifier.builder()
            .serverPublicKey(serverIdentity.getCertificate().getPublicKey())
            .build();

    challenge =
        authenticationChallengeBuilder.buildAuthenticationChallenge(
            "goo", "foo", "bar", "schmar", "openid e-rezept", "nonceValue");
  }

  @Test
  void verifyClientCertificateIsInHeaderAttribute() throws CertificateEncodingException {
    final AuthenticationResponse authenticationResponse =
        authenticationResponseBuilder.buildResponseForChallenge(challenge, clientIdentity);

    Assertions.assertThat(authenticationResponse.getSignedChallenge().getHeaderClaims())
        .extractingByKey(X509_CERTIFICATE_CHAIN.getJoseName(), InstanceOfAssertFactories.LIST)
        .contains(Base64.getEncoder().encodeToString(clientIdentity.getCertificate().getEncoded()));
  }

  @Test
  void verifyResponseIsSignedByClientIdentity() throws InvalidJwtException {
    final AuthenticationResponse authenticationResponse =
        authenticationResponseBuilder.buildResponseForChallenge(challenge, clientIdentity);
    assertDoesNotThrow(
        () ->
            serverJwtConsumer.process(authenticationResponse.getSignedChallenge().getRawString()));
  }

  @Test
  void verifyResponseIsNotSignedByServerIdentity() {
    final AuthenticationResponse authenticationResponse =
        authenticationResponseBuilder.buildResponseForChallenge(challenge, clientIdentity);
    final JsonWebToken signedChallenge = authenticationResponse.getSignedChallenge();
    assertThat(signedChallenge).isNotNull();
    final PublicKey publicKey = serverIdentity.getCertificate().getPublicKey();

    assertThatThrownBy(() -> signedChallenge.verify(publicKey))
        .isInstanceOf(IdpJoseException.class);
  }

  @Test
  void verifyNestedTokenIsEqualToChallenge() {
    final AuthenticationResponse authenticationResponse =
        authenticationResponseBuilder.buildResponseForChallenge(challenge, clientIdentity);

    Assertions.assertThat(authenticationResponse.getSignedChallenge().getBodyClaims())
        .extractingByKey(ClaimName.NESTED_JWT.getJoseName())
        .isEqualTo(challenge.getChallenge().getRawString());
  }

  @Test
  void verifyChallengeResponseOnlyContainsNestedJwt() {
    final AuthenticationResponse authenticationResponse =
        authenticationResponseBuilder.buildResponseForChallenge(challenge, clientIdentity);

    final Map<String, Object> extractedClaims =
        authenticationChallengeVerifier.extractClaimsFromSignedChallenge(authenticationResponse);
    assertThat(extractedClaims)
        .containsOnlyKeys(NESTED_JWT.getJoseName())
        .containsEntry(NESTED_JWT.getJoseName(), challenge.getChallenge().getRawString());
  }

  @Test
  void verifyChallengeResponseOnlyContainsExp() {
    final AuthenticationResponse authenticationResponse =
        authenticationResponseBuilder.buildResponseForChallenge(challenge, clientIdentity);

    Assertions.assertThat(
            authenticationResponse
                .getSignedChallenge()
                .getStringBodyClaim(ClaimName.NESTED_JWT)
                .map(JsonWebToken::new)
                .map(token -> token.getHeaderDateTimeClaim(ClaimName.EXPIRES_AT)))
        .isPresent();
  }
}
