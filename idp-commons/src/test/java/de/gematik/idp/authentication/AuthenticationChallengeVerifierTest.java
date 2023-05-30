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

package de.gematik.idp.authentication;

import static de.gematik.idp.IdpConstants.EREZEPT;
import static de.gematik.idp.field.ClaimName.FAMILY_NAME;
import static de.gematik.idp.field.ClaimName.GIVEN_NAME;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.jose4j.jws.AlgorithmIdentifiers.RSA_USING_SHA256;

import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.data.ScopeConfiguration;
import de.gematik.idp.data.UserConsentConfiguration;
import de.gematik.idp.data.UserConsentDescriptionTexts;
import de.gematik.idp.exceptions.ChallengeSignatureInvalidException;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.tests.PkiKeyResolver;
import de.gematik.idp.token.JsonWebToken;
import java.security.Security;
import java.time.ZonedDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.assertj.core.api.Assertions;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(PkiKeyResolver.class)
class AuthenticationChallengeVerifierTest {

  static {
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    Security.insertProviderAt(new BouncyCastleProvider(), 1);
  }

  private AuthenticationChallenge authenticationChallenge;
  private AuthenticationChallengeBuilder authenticationChallengeBuilder;
  private AuthenticationResponseBuilder authenticationResponseBuilder;
  private AuthenticationChallengeVerifier authenticationChallengeVerifier;
  private PkiIdentity clientIdentity;
  private PkiIdentity rsaClientIdentity;
  private PkiIdentity serverIdentity;
  private Map<String, Map<String, String>> userConsentConfiguration;

  ScopeConfiguration openidConfig = ScopeConfiguration.builder().description("openid desc").build();
  ScopeConfiguration pairingConfig =
      ScopeConfiguration.builder()
          .audienceUrl("erplala")
          .description("erp desc")
          .claimsToBeIncluded(List.of(GIVEN_NAME, FAMILY_NAME))
          .build();

  @BeforeEach
  public void init(
      @PkiKeyResolver.Filename("1_C.SGD-HSM.AUT_oid_sgd1_hsm_ecc.p12")
          final PkiIdentity serverIdentity,
      @PkiKeyResolver.Filename("109500969_X114428530_c.ch.aut-ecc.p12")
          final PkiIdentity clientIdentity,
      @PkiKeyResolver.Filename("833621999741600_c.hci.aut-apo-rsa.p12")
          final PkiIdentity rsaClientIdentity) {
    this.clientIdentity = clientIdentity;
    this.serverIdentity = serverIdentity;
    this.rsaClientIdentity = rsaClientIdentity;

    authenticationChallengeBuilder =
        AuthenticationChallengeBuilder.builder()
            .serverSigner(new IdpJwtProcessor(serverIdentity))
            .userConsentConfiguration(
                UserConsentConfiguration.builder()
                    .descriptionTexts(
                        UserConsentDescriptionTexts.builder()
                            .claims(
                                Map.of(GIVEN_NAME, "da given name", FAMILY_NAME, "da family name"))
                            .build())
                    .build())
            .scopesConfiguration(Map.of("openid", openidConfig, "pairing", pairingConfig))
            .build();
    authenticationResponseBuilder = AuthenticationResponseBuilder.builder().build();
    authenticationChallengeVerifier =
        AuthenticationChallengeVerifier.builder().serverIdentity(serverIdentity).build();
    authenticationChallenge =
        authenticationChallengeBuilder.buildAuthenticationChallenge(
            "goo", "foo", "bar", "schmar", "openid pairing", "nonceValue");
  }

  @Test
  void verifyEmptyResponse_shouldGiveException() {
    assertThatThrownBy(
            () -> authenticationChallengeVerifier.verifyResponseAndThrowExceptionIfFail(null))
        .isInstanceOf(RuntimeException.class);
  }

  @Test
  void verifyCorrectResponse_shouldPass() {
    final AuthenticationResponse authenticationResponse =
        authenticationResponseBuilder.buildResponseForChallenge(
            authenticationChallenge, clientIdentity);
    authenticationChallengeVerifier.verifyResponseAndThrowExceptionIfFail(
        authenticationResponse.getSignedChallenge());
  }

  @Test
  void extractClaims_shouldBePresent() {
    final AuthenticationResponse authenticationResponse =
        authenticationResponseBuilder.buildResponseForChallenge(
            authenticationChallenge, clientIdentity);

    Assertions.assertThat(
            authenticationResponse
                .getSignedChallenge()
                .getStringBodyClaim(ClaimName.NESTED_JWT)
                .map(Objects::toString)
                .map(JsonWebToken::new)
                .map(JsonWebToken::getBodyClaims)
                .get())
        .containsEntry("client_id", "goo")
        .containsEntry("state", "foo")
        .containsEntry("redirect_uri", "bar")
        .containsEntry("code_challenge", "schmar");
  }

  @Test
  void checkSignatureNjwt_certMismatch(
      @PkiKeyResolver.Filename("833621999741600_c.hci.aut-apo-ecc.p12")
          final PkiIdentity otherServerIdentity) {
    authenticationChallengeBuilder =
        AuthenticationChallengeBuilder.builder()
            .serverSigner(new IdpJwtProcessor(otherServerIdentity))
            .userConsentConfiguration(
                UserConsentConfiguration.builder()
                    .descriptionTexts(
                        UserConsentDescriptionTexts.builder()
                            .claims(Collections.emptyMap())
                            .build())
                    .build())
            .scopesConfiguration(Map.of("openid", openidConfig, "pairing", pairingConfig))
            .build();
    authenticationChallenge =
        authenticationChallengeBuilder.buildAuthenticationChallenge(
            "goo", "foo", "bar", "schmar", "openid e-rezept", "nonceValue");

    final AuthenticationResponse authenticationResponse =
        authenticationResponseBuilder.buildResponseForChallenge(
            authenticationChallenge, clientIdentity);

    final JsonWebToken signedChallenge = authenticationResponse.getSignedChallenge();
    assertThat(signedChallenge).isNotNull();
    assertThatThrownBy(
            () ->
                authenticationChallengeVerifier.verifyResponseAndThrowExceptionIfFail(
                    signedChallenge))
        .isInstanceOf(RuntimeException.class);
  }

  @Test
  void checkSignatureNjwt_invalidChallenge() {
    final AuthenticationChallenge ch =
        AuthenticationChallenge.builder()
            .challenge(new JsonWebToken("SicherNichtDerRichtigeChallengeCode"))
            .build();
    final AuthenticationResponse authenticationResponse =
        authenticationResponseBuilder.buildResponseForChallenge(ch, clientIdentity);

    final JsonWebToken signedChallenge = authenticationResponse.getSignedChallenge();
    assertThat(signedChallenge).isNotNull();
    assertThatThrownBy(
            () ->
                authenticationChallengeVerifier.verifyResponseAndThrowExceptionIfFail(
                    signedChallenge))
        .isInstanceOf(RuntimeException.class);
  }

  @Test
  void checkSignatureNjwt_challengeOutdated() {
    authenticationChallenge =
        authenticationChallengeBuilder.buildAuthenticationChallenge(
            "goo", "foo", "bar", "schmar", EREZEPT, "nonceValue");
    final JsonWebToken jsonWebToken = authenticationChallenge.getChallenge();
    final IdpJwtProcessor reSignerProcessor = new IdpJwtProcessor(serverIdentity);
    final JwtBuilder jwtDescription = jsonWebToken.toJwtDescription();
    jwtDescription.expiresAt(ZonedDateTime.now().minusSeconds(1));
    authenticationChallenge.setChallenge(reSignerProcessor.buildJwt(jwtDescription));

    final AuthenticationResponse authenticationResponse =
        authenticationResponseBuilder.buildResponseForChallenge(
            authenticationChallenge, clientIdentity);
    final JsonWebToken signedChallenge = authenticationResponse.getSignedChallenge();
    assertThat(signedChallenge).isNotNull();

    assertThatThrownBy(
            () ->
                authenticationChallengeVerifier.verifyResponseAndThrowExceptionIfFail(
                    signedChallenge))
        .isInstanceOf(RuntimeException.class);
  }

  @Test
  void checkSignedChallenge_invalidAlgoInJws() {
    final AuthenticationResponse authenticationResponse =
        buildInvalidResponseForChallenge(authenticationChallenge, rsaClientIdentity);
    final JsonWebToken signedChallenge = authenticationResponse.getSignedChallenge();
    assertThat(signedChallenge).isNotNull();

    assertThatThrownBy(
            () ->
                authenticationChallengeVerifier.verifyResponseAndThrowExceptionIfFail(
                    signedChallenge))
        .isInstanceOf(ChallengeSignatureInvalidException.class);
  }

  private AuthenticationResponse buildInvalidResponseForChallenge(
      final AuthenticationChallenge authenticationChallenge, final PkiIdentity clientIdentity) {
    final JwtClaims claims = new JwtClaims();
    claims.setClaim(
        ClaimName.NESTED_JWT.getJoseName(), authenticationChallenge.getChallenge().getRawString());

    final JsonWebSignature jsonWebSignature = new JsonWebSignature();
    jsonWebSignature.setPayload(claims.toJson());

    jsonWebSignature.setAlgorithmHeaderValue(RSA_USING_SHA256);
    jsonWebSignature.setKey(clientIdentity.getPrivateKey());

    jsonWebSignature.setHeader("typ", "JWT");
    jsonWebSignature.setHeader("cty", "NJWT");
    jsonWebSignature.setCertificateChainHeaderValue(clientIdentity.getCertificate());

    try {
      final String compactSerialization = jsonWebSignature.getCompactSerialization();
      return AuthenticationResponse.builder()
          .signedChallenge(new JsonWebToken(compactSerialization))
          .build();
    } catch (final JoseException e) {
      throw new RuntimeException(e);
    }
  }
}
