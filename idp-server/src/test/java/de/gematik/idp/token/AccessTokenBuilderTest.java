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

package de.gematik.idp.token;

import static de.gematik.idp.IdpConstants.EREZEPT;
import static de.gematik.idp.IdpConstants.OID_VERSICHERTER;
import static de.gematik.idp.IdpConstants.OPENID;
import static de.gematik.idp.IdpConstants.PAIRING;
import static de.gematik.idp.brainPoolExtension.BrainpoolAlgorithmSuiteIdentifiers.BRAINPOOL256_USING_SHA256;
import static de.gematik.idp.field.ClaimName.ALGORITHM;
import static de.gematik.idp.field.ClaimName.AUDIENCE;
import static de.gematik.idp.field.ClaimName.AUTH_TIME;
import static de.gematik.idp.field.ClaimName.CLIENT_ID;
import static de.gematik.idp.field.ClaimName.DISPLAY_NAME;
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

import de.gematik.idp.TestConstants;
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

  private static final String URI_IDP_SERVER = "https://myIdp.de";
  private static final String KEY_ID = "my_key_id";
  private static final String EREZEPT_AUDIENCE = "erezeptAudience";
  private static final String PAIRING_AUDIENCE = "pairingAudience";

  private static final String AUTH_CODE_SEKTORALER_IDP =
      "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InB1a19mZF9zaWcifQ.eyJwcm9mZXNzaW9uT0lEIjoiMS4yLjI3Ni4wLjc2LjQuNDkiLCJvcmdhbml6YXRpb25OYW1lIjoiMTA5NTAwOTY5IiwiaWROdW1tZXIiOiJYMTEwNDExNjc1IiwiYW1yIjpbIm1mYSJdLCJpc3MiOiJodHRwczovL2lkcGZhZGkuZGV2LmdlbWF0aWsuc29sdXRpb25zIiwicmVzcG9uc2VfdHlwZSI6bnVsbCwic25jIjoiS1RtWHB6aURXaFBIUjBHS2RUdEY5eV9QeHN5NTRWbWwiLCJjb2RlX2NoYWxsZW5nZV9tZXRob2QiOiJmcm9udGVuZENvZGVDaGFsbGVuZ2VNZXRob2QiLCJkaXNwbGF5X25hbWUiOiJEYXJpdXMgTWljaGFlbCBCcmlhbiBVYmJvIEdyYWYgdm9uIELDtmRlZmVsZCIsInRva2VuX3R5cGUiOiJjb2RlIiwiY2xpZW50X2lkIjoiZnJvbnRlbmRDbGllbnRJZCIsInNjb3BlIjoib3BlbmlkIGUtcmV6ZXB0IiwiYXV0aF90aW1lIjoxNjkwMjAyMzI1LCJyZWRpcmVjdF91cmkiOiJmcm9udGVuZFJlZGlyZWN0VXJpIiwic3RhdGUiOiJmcm9udGVuZFN0YXRlIiwiZXhwIjoxNjkwMjA1OTQyLCJpYXQiOjE2OTAyMDIzMjUsImNvZGVfY2hhbGxlbmdlIjoiZnJvbnRlbmRDb2RlQ2hhbGxlbmdlIiwianRpIjoiOGIyOWI0NTlkMTNiY2NmZCJ9.UIObtP1dS3iuXBkUOgPaAoQm1kHlbe6HRWeweP8-CeizPPQmxjQzHSbevm7o8-UzkllUaSyndliIyeTdV6wJdA";

  private static final String AUTH_CODE_FOR_SMCB =
      "eyJhbGciOiJCUDI1NlIxIiwidHlwIjoiSldUIiwia2lkIjoicHVrX2lkcF9zaWcifQ.eyJvcmdhbml6YXRpb25OYW1lIjoiQXNjaG9mZnNjaGUgQXBvdGhla2UgVEVTVC1PTkxZIiwicHJvZmVzc2lvbk9JRCI6IjEuMi4yNzYuMC43Ni40LjU0IiwiaWROdW1tZXIiOiIzLTItRVBBLTgzMzYyMTk5OTc0MTYwMCIsImFtciI6WyJtZmEiLCJzYyIsInBpbiJdLCJpc3MiOiJodHRwczovL2lkcC56ZW50cmFsLmlkcC5zcGxpdGRucy50aS1kaWVuc3RlLmRlIiwicmVzcG9uc2VfdHlwZSI6ImNvZGUiLCJzbmMiOiJRa1hSVmZvNTNFZ0IybFhCcFp0b0kyTTZjMGE1bFg2TiIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJnaXZlbl9uYW1lIjpudWxsLCJ0b2tlbl90eXBlIjoiY29kZSIsIm5vbmNlIjoiOHVRaURrODBTMjl6QTNWa1lzWjJWZVV0R1N1d2lOcDgiLCJjbGllbnRfaWQiOiJlUmV6ZXB0QXBwIiwic2NvcGUiOiJlLXJlemVwdCBvcGVuaWQiLCJhdXRoX3RpbWUiOjE2OTA0MzgxMTAsInJlZGlyZWN0X3VyaSI6Imh0dHA6Ly9yZWRpcmVjdC5nZW1hdGlrLmRlL2VyZXplcHQiLCJzdGF0ZSI6IndCOWE0cUZZRk1LeVJoRW9pdkRTbDN5eUFaWF9ua3o5IiwiZXhwIjoxNjkwNDM4MTcwLCJmYW1pbHlfbmFtZSI6bnVsbCwiaWF0IjoxNjkwNDM4MTEwLCJjb2RlX2NoYWxsZW5nZSI6Inh3S2t2dlZpU293LTFybnQxLXBMd3RMVFBXQWxzaDdYM1FNd0ZFZDlIWDgiLCJqdGkiOiIzMjc3NTJkOTNlZWE4NTkzIn0.AAOZW9pywmyY3xrHOjnBAZF1OhmiuFQmSRNwvMIDbaGi2bL1HIX943fT8MaXFOFI-q2_kJfj0hpgMOK1omUdvw";

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
      @PkiKeyResolver.Filename("109500969_X114428530-2_c.ch.aut-ecc")
          final PkiIdentity clientIdentity,
      @PkiKeyResolver.Filename("ecc") final PkiIdentity serverIdentity) {

    serverTokenProcessor = new IdpJwtProcessor(serverIdentity, Optional.of(KEY_ID));
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
            EREZEPT + " " + OPENID));
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
    final JsonWebToken jsonWebToken =
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
            TokenClaimExtraction::claimToZonedDateTime, InstanceOfAssertFactories.ZONED_DATE_TIME)
        .isBetween(ZonedDateTime.now().minusMinutes(1), ZonedDateTime.now());
  }

  @Test
  void verifyAudienceAndDisplayNameByScopeERezept() {
    createAuthenticationTokenByBodyClaims(
        Map.of(
            CLIENT_ID.getJoseName(),
            TestConstants.CLIENT_ID_E_REZEPT_APP,
            SCOPE.getJoseName(),
            OPENID + " " + EREZEPT));
    final JsonWebToken accessToken = accessTokenBuilder.buildAccessToken(authenticationToken);
    assertThat(accessToken.getBodyClaim(AUDIENCE).orElseThrow()).isEqualTo(EREZEPT_AUDIENCE);
    assertThat(accessToken.getBodyClaim(DISPLAY_NAME).orElseThrow()).isEqualTo("Juna Fuchs");
  }

  @Test
  void verifyAudienceAndDisplayNameByScopePairing() {
    createAuthenticationTokenByBodyClaims(
        Map.of(
            CLIENT_ID.getJoseName(),
            TestConstants.CLIENT_ID_E_REZEPT_APP,
            SCOPE.getJoseName(),
            OPENID + " " + PAIRING));
    final JsonWebToken accessToken = accessTokenBuilder.buildAccessToken(authenticationToken);
    assertThat(accessToken.getBodyClaim(AUDIENCE).orElseThrow()).isEqualTo(PAIRING_AUDIENCE);
    assertThat(accessToken.getBodyClaims()).doesNotContainKey(DISPLAY_NAME.getJoseName());
  }

  @Test
  void verifyNoDisplayNameForAnSmcbWithNoDisplayNameInAuthCode() {
    final JsonWebToken authCode = new JsonWebToken(AUTH_CODE_FOR_SMCB);
    assertThat(authCode).isNotNull();
    final JsonWebToken accessToken = accessTokenBuilder.buildAccessToken(authCode);
    assertThat(accessToken.getBodyClaims()).containsKey(DISPLAY_NAME.getJoseName());
    assertThat(accessToken.getBodyClaim(DISPLAY_NAME)).isEmpty();
  }

  @Test
  void buildAccessTokenFromSektoralIdpAuthCode() {
    final JsonWebToken authCode = new JsonWebToken(AUTH_CODE_SEKTORALER_IDP);
    assertThat(authCode).isNotNull();
    final JsonWebToken accessToken = accessTokenBuilder.buildAccessToken(authCode);
    assertThat(accessToken.getBodyClaim(DISPLAY_NAME))
        .get()
        .isEqualTo(authCode.getBodyClaim(DISPLAY_NAME).orElseThrow());
    assertThat(accessToken.getBodyClaim(ORGANIZATION_NAME))
        .get()
        .isEqualTo(authCode.getBodyClaim(ORGANIZATION_NAME).orElseThrow());
    assertThat(accessToken.getBodyClaim(PROFESSION_OID).orElseThrow()).isEqualTo(OID_VERSICHERTER);
    assertThat(accessToken.getBodyClaim(ID_NUMBER))
        .get()
        .isEqualTo(authCode.getBodyClaim(ID_NUMBER).orElseThrow());
  }
}
