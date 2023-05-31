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

import static de.gematik.idp.field.ClaimName.CODE_CHALLENGE_METHOD;
import static de.gematik.idp.field.ClaimName.EXPIRES_AT;
import static de.gematik.idp.field.ClaimName.FAMILY_NAME;
import static de.gematik.idp.field.ClaimName.GIVEN_NAME;
import static de.gematik.idp.field.ClaimName.ISSUED_AT;
import static de.gematik.idp.field.ClaimName.JWT_ID;
import static de.gematik.idp.field.ClaimName.KEY_ID;
import static de.gematik.idp.field.ClaimName.TOKEN_TYPE;
import static de.gematik.idp.field.ClaimName.TYPE;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.data.ScopeConfiguration;
import de.gematik.idp.data.UserConsentConfiguration;
import de.gematik.idp.data.UserConsentDescriptionTexts;
import de.gematik.idp.tests.Afo;
import de.gematik.idp.tests.PkiKeyResolver;
import de.gematik.idp.tests.Remark;
import de.gematik.idp.tests.Rfc;
import java.time.ZonedDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(PkiKeyResolver.class)
class AuthenticationChallengeBuilderTest {

  private static final long CHALLENGE_TOKEN_VALIDITY_IN_MINUTES = 3;
  private static final String SERVER_KEY_IDENTITY = "serverKeyIdentity";
  private AuthenticationChallengeBuilder authenticationChallengeBuilder;

  @BeforeEach
  public void init(@PkiKeyResolver.Filename("rsa") final PkiIdentity serverIdentity) {
    final ScopeConfiguration openidConfig =
        ScopeConfiguration.builder().description("openid desc").build();
    final ScopeConfiguration pairingConfig =
        ScopeConfiguration.builder()
            .audienceUrl("erplala")
            .description("erp desc")
            .claimsToBeIncluded(List.of(GIVEN_NAME, FAMILY_NAME))
            .build();
    authenticationChallengeBuilder =
        AuthenticationChallengeBuilder.builder()
            .serverSigner(new IdpJwtProcessor(serverIdentity, Optional.of(SERVER_KEY_IDENTITY)))
            .userConsentConfiguration(
                UserConsentConfiguration.builder()
                    .descriptionTexts(
                        UserConsentDescriptionTexts.builder()
                            .claims(Collections.emptyMap())
                            .build())
                    .build())
            .scopesConfiguration(Map.of("openid", openidConfig, "pairing", pairingConfig))
            .build();
  }

  @Test
  void authenticationChallengeTest() {
    assertThat(
            authenticationChallengeBuilder.buildAuthenticationChallenge(
                "goo", "foo", "bar", "schmar", "openid e-rezept", "nonceValue"))
        .isNotNull();
  }

  @Test
  void challengeAttributeIsJwtAndSignedByCertificate(
      @PkiKeyResolver.Filename("rsa") final PkiIdentity serverIdentity) throws InvalidJwtException {
    final AuthenticationChallenge response =
        authenticationChallengeBuilder.buildAuthenticationChallenge(
            "goo", "foo", "bar", "schmar", "openid e-rezept", "nonceValue");

    final JwtConsumer jwtConsumer =
        new JwtConsumerBuilder()
            .setVerificationKey(serverIdentity.getCertificate().getPublicKey())
            .setSkipDefaultAudienceValidation()
            .build();

    jwtConsumer.process(response.getChallenge().getRawString());
    assertThat(response.getChallenge()).isNotNull();
  }

  @Test
  void challengeWithClaims() {
    final AuthenticationChallenge response =
        authenticationChallengeBuilder.buildAuthenticationChallenge(
            "goo", "foo", "bar", "schmar", "openid e-rezept", "nonceValue");

    assertThat(response.getChallenge().getBodyClaims())
        .containsEntry(CODE_CHALLENGE_METHOD.getJoseName(), "S256");
  }

  @Test
  @Remark("Ticket IDP-93: typ == JWT")
  void challengeHeaderClaimItemTyp() {
    final AuthenticationChallenge response =
        authenticationChallengeBuilder.buildAuthenticationChallenge(
            "goo", "foo", "bar", "schmar", "openid e-rezept", "nonceValue");

    assertThat(response.getChallenge().getHeaderClaims()).containsEntry(TYPE.getJoseName(), "JWT");
  }

  @Test
  @Remark("Ticket IDP-93: typ == JWT")
  void challengeBodyTokenType() {
    final AuthenticationChallenge response =
        authenticationChallengeBuilder.buildAuthenticationChallenge(
            "goo", "foo", "bar", "schmar", "openid e-rezept", "nonceValue");

    assertThat(response.getChallenge().getBodyClaim(TOKEN_TYPE))
        .get()
        .asString()
        .isEqualTo("challenge");
  }

  @Test
  @Remark("Ticket IDP-93: exp == 5min")
  @Rfc("7519 4.1.4.  \"exp\" (Expiration Time) Claim")
  void challengeBodyClaimItemExp() {
    final AuthenticationChallenge response =
        authenticationChallengeBuilder.buildAuthenticationChallenge(
            "goo", "foo", "bar", "schmar", "openid e-rezept", "nonceValue");

    assertThat(response.getChallenge().getExpiresAt())
        .isBetween(
            ZonedDateTime.now().plusMinutes(CHALLENGE_TOKEN_VALIDITY_IN_MINUTES).minusSeconds(5),
            ZonedDateTime.now().plusMinutes(CHALLENGE_TOKEN_VALIDITY_IN_MINUTES));
  }

  @Test
  @Rfc("7519 4.1.6.  \"iat\" (Issued At) Claim")
  void challengeBodyClaimItemIat() {
    final AuthenticationChallenge response =
        authenticationChallengeBuilder.buildAuthenticationChallenge(
            "goo", "foo", "bar", "schmar", "openid e-rezept", "nonceValue");

    assertThat(response.getChallenge().getBodyDateTimeClaim(ISSUED_AT).get())
        .isBetween(ZonedDateTime.now().minusSeconds(5), ZonedDateTime.now());
  }

  @Test
  @Remark("Ticket IDP-93: \"jti\" string length: 8-64")
  @Rfc("7519 4.1.7.  \"jti\" (JWT ID) Claim")
  void challengeBodyClaimItemJti() {
    final AuthenticationChallenge response =
        authenticationChallengeBuilder.buildAuthenticationChallenge(
            "goo", "foo", "bar", "schmar", "openid e-rezept", "nonceValue");

    assertThat(response.getChallenge().getBodyClaim(JWT_ID).get())
        .asString()
        .hasSizeBetween(16, 64);
  }

  @Test
  @Afo("A_20440")
  void challengeWithConsent() {
    final AuthenticationChallenge response =
        authenticationChallengeBuilder.buildAuthenticationChallenge(
            "goo", "foo", "bar", "schmar", "openid e-rezept", "nonceValue");
    assertThat(response.getUserConsent()).isNotNull();
    assertThat(response.getUserConsent()).isNotNull();
  }

  @Test
  void verifyThatAuthenticationChallengeCarriesNeitherExpNorIatClaimInHeader() {
    final AuthenticationChallenge response =
        authenticationChallengeBuilder.buildAuthenticationChallenge(
            "goo", "foo", "bar", "schmar", "openid e-rezept", "nonceValue");
    assertThat(response.getChallenge().getHeaderClaims().keySet()).isNotEmpty();
    assertThat(response.getChallenge().getHeaderClaims().keySet())
        .doesNotContain(EXPIRES_AT.getJoseName())
        .doesNotContain(ISSUED_AT.getJoseName());
  }

  @Test
  void challengeToken_checkForKidInHeader() {
    final AuthenticationChallenge response =
        authenticationChallengeBuilder.buildAuthenticationChallenge(
            "goo", "foo", "bar", "schmar", "openid e-rezept", "nonceValue");
    assertThat(response.getChallenge().getHeaderClaims()).isNotEmpty();
    assertThat(response.getChallenge().getHeaderClaims())
        .containsEntry(KEY_ID.getJoseName(), SERVER_KEY_IDENTITY);
  }
}
