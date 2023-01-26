/*
 * Copyright (c) 2023 gematik GmbH
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

package de.gematik.idp.token;

import static de.gematik.idp.IdpConstants.EREZEPT;
import static de.gematik.idp.IdpConstants.OPENID;
import static de.gematik.idp.IdpConstants.PAIRING;
import static de.gematik.idp.brainPoolExtension.BrainpoolAlgorithmSuiteIdentifiers.BRAINPOOL256_USING_SHA256;
import static de.gematik.idp.field.ClaimName.ALGORITHM;
import static de.gematik.idp.field.ClaimName.AUDIENCE;
import static de.gematik.idp.field.ClaimName.AUTH_TIME;
import static de.gematik.idp.field.ClaimName.CLIENT_ID;
import static de.gematik.idp.field.ClaimName.FAMILY_NAME;
import static de.gematik.idp.field.ClaimName.GIVEN_NAME;
import static de.gematik.idp.field.ClaimName.ID_NUMBER;
import static de.gematik.idp.field.ClaimName.ISSUED_AT;
import static de.gematik.idp.field.ClaimName.ISSUER;
import static de.gematik.idp.field.ClaimName.ORGANIZATION_NAME;
import static de.gematik.idp.field.ClaimName.PROFESSION_OID;
import static de.gematik.idp.field.ClaimName.SCOPE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

import de.gematik.idp.TestConstants;
import de.gematik.idp.authentication.AuthenticationChallengeVerifier;
import de.gematik.idp.authentication.AuthenticationTokenBuilder;
import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.authentication.JwtBuilder;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.exceptions.RequiredClaimException;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.tests.Afo;
import de.gematik.idp.tests.PkiKeyResolver;
import java.security.Security;
import java.time.ZonedDateTime;
import java.util.Map;
import java.util.Optional;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.digest.DigestUtils;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.ExtendWith;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ExtendWith(PkiKeyResolver.class)
class AccessTokenBuilderTest {

  private static final String URI_IDP_SERVER = "https://idp.zentral.idp.splitdns.ti-dienste.de";
  private static final String KEY_ID = "my_key_id";
  private static final String EREZEPT_AUDIENCE = "erezeptAudience";
  private static final String PAIRING_AUDIENCE = "pairingAudience";

  static {
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    Security.insertProviderAt(new BouncyCastleProvider(), 1);
  }

  private AccessTokenBuilder accessTokenBuilder;
  private IdpJwtProcessor serverTokenProcessor;
  private JsonWebToken authenticationToken;
  private SecretKeySpec encryptionKey;
  private PkiIdentity pkiIdentity;
  private AuthenticationTokenBuilder authenticationTokenBuilder;

  @BeforeAll
  void setup(
      @PkiKeyResolver.Filename("109500969_X114428530_c.ch.aut-ecc")
          final PkiIdentity clientIdentity,
      @PkiKeyResolver.Filename("ecc") final PkiIdentity serverIdentity) {

    serverIdentity.setKeyId(Optional.of(KEY_ID));
    serverTokenProcessor = new IdpJwtProcessor(serverIdentity);
    accessTokenBuilder =
        new AccessTokenBuilder(
            serverTokenProcessor,
            URI_IDP_SERVER,
            "saltValue",
            Map.of("e-rezept", EREZEPT_AUDIENCE, "pairing", PAIRING_AUDIENCE));
    encryptionKey = new SecretKeySpec(DigestUtils.sha256("fdsa"), "AES");
    pkiIdentity = clientIdentity;

    authenticationTokenBuilder =
        AuthenticationTokenBuilder.builder()
            .jwtProcessor(serverTokenProcessor)
            .authenticationChallengeVerifier(mock(AuthenticationChallengeVerifier.class))
            .encryptionKey(encryptionKey)
            .build();
  }

  @BeforeEach
  public void init() {
    createAuthenticationTokenByBodyClaims(
        Map.of(
            "acr",
            "foobar",
            CLIENT_ID.getJoseName(),
            TestConstants.CLIENT_ID_E_REZEPT_APP,
            SCOPE.getJoseName(),
            EREZEPT));
  }

  private void createAuthenticationTokenByBodyClaims(final Map<String, Object> map) {
    authenticationToken =
        authenticationTokenBuilder
            .buildAuthenticationToken(pkiIdentity.getCertificate(), map, ZonedDateTime.now())
            .decryptNestedJwt(encryptionKey);
  }

  @Afo("A_20524")
  @Test
  void requiredFieldMissingFromAuthenticationToken_ShouldThrowRequiredClaimException() {
    JsonWebToken jsonWebToken =
        serverTokenProcessor.buildJwt(
            new JwtBuilder()
                .addAllBodyClaims(
                    Map.of(PROFESSION_OID.getJoseName(), "foo", SCOPE.getJoseName(), EREZEPT))
                .expiresAt(ZonedDateTime.now().plusMinutes(100)));
    assertThat(jsonWebToken).isNotNull();

    assertThatThrownBy(() -> accessTokenBuilder.buildAccessToken(jsonWebToken))
        .isInstanceOf(RequiredClaimException.class);
  }

  @Afo("A_20524")
  @Test
  void verifyThatAllRequiredClaimsAreInBody() {
    final JsonWebToken accessToken = accessTokenBuilder.buildAccessToken(authenticationToken);

    assertThat(accessToken.getBodyClaims())
        .containsEntry(GIVEN_NAME.getJoseName(), "Juna")
        .containsEntry(FAMILY_NAME.getJoseName(), "Fuchs")
        .containsEntry(ORGANIZATION_NAME.getJoseName(), "AOK Plus")
        .containsEntry(PROFESSION_OID.getJoseName(), "1.2.276.0.76.4.49")
        .containsEntry(ID_NUMBER.getJoseName(), "X114428530")
        .containsEntry(ISSUER.getJoseName(), URI_IDP_SERVER)
        .containsEntry(AUDIENCE.getJoseName(), EREZEPT_AUDIENCE)
        .containsKey(ISSUED_AT.getJoseName())
        .containsKey(AUTH_TIME.getJoseName());
  }

  @Test
  void verifyThatAllRequiredClaimsAreInHeader() {
    final JsonWebToken accessToken = accessTokenBuilder.buildAccessToken(authenticationToken);
    assertThat(accessToken.getHeaderClaims()).containsEntry(ClaimName.KEY_ID.getJoseName(), KEY_ID);
  }

  @Test
  void verifyExpiresAtIsPresentAndInNearFuture() {
    final JsonWebToken accessToken = accessTokenBuilder.buildAccessToken(authenticationToken);
    assertThat(accessToken.getExpiresAtBody()).isBefore(ZonedDateTime.now().plusMinutes(5));
  }

  @Test
  void verifyEncryptionAlgorithmIsCorrect() {
    final JsonWebToken accessToken = accessTokenBuilder.buildAccessToken(authenticationToken);

    assertThat(accessToken.getHeaderClaims())
        .containsEntry(ALGORITHM.getJoseName(), BRAINPOOL256_USING_SHA256);
  }

  @Afo("A_20731")
  @Test
  void verifyAuthTimeClaimIsPresentAndIsRecent() {
    final JsonWebToken accessToken = accessTokenBuilder.buildAccessToken(authenticationToken);
    assertThat(accessToken.getBodyClaims())
        .extractingByKey(AUTH_TIME.getJoseName())
        .extracting(
            authTimeValue -> TokenClaimExtraction.claimToZonedDateTime(authTimeValue),
            InstanceOfAssertFactories.ZONED_DATE_TIME)
        .isBetween(ZonedDateTime.now().minusMinutes(1), ZonedDateTime.now());
  }

  @Test
  void verifyAudienceByScopeERezept() {
    createAuthenticationTokenByBodyClaims(
        Map.of(
            CLIENT_ID.getJoseName(),
            TestConstants.CLIENT_ID_E_REZEPT_APP,
            SCOPE.getJoseName(),
            OPENID + " " + EREZEPT));
    final JsonWebToken accessToken = accessTokenBuilder.buildAccessToken(authenticationToken);
    assertThat(accessToken.getBodyClaim(AUDIENCE)).get().isEqualTo(EREZEPT_AUDIENCE);
  }

  @Test
  void verifyAudienceByScopePairing() {
    createAuthenticationTokenByBodyClaims(
        Map.of(
            CLIENT_ID.getJoseName(),
            TestConstants.CLIENT_ID_E_REZEPT_APP,
            SCOPE.getJoseName(),
            OPENID + " " + PAIRING));
    final JsonWebToken accessToken = accessTokenBuilder.buildAccessToken(authenticationToken);
    assertThat(accessToken.getBodyClaim(AUDIENCE)).get().isEqualTo(PAIRING_AUDIENCE);
  }
}
