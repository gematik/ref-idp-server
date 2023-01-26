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
import static de.gematik.idp.field.ClaimName.ACCESS_TOKEN_HASH;
import static de.gematik.idp.field.ClaimName.ALGORITHM;
import static de.gematik.idp.field.ClaimName.AUDIENCE;
import static de.gematik.idp.field.ClaimName.AUTHENTICATION_METHODS_REFERENCE;
import static de.gematik.idp.field.ClaimName.CLIENT_ID;
import static de.gematik.idp.field.ClaimName.EXPIRES_AT;
import static de.gematik.idp.field.ClaimName.FAMILY_NAME;
import static de.gematik.idp.field.ClaimName.GIVEN_NAME;
import static de.gematik.idp.field.ClaimName.ID_NUMBER;
import static de.gematik.idp.field.ClaimName.ISSUED_AT;
import static de.gematik.idp.field.ClaimName.ISSUER;
import static de.gematik.idp.field.ClaimName.JWKS_URI;
import static de.gematik.idp.field.ClaimName.NONCE;
import static de.gematik.idp.field.ClaimName.ORGANIZATION_NAME;
import static de.gematik.idp.field.ClaimName.PROFESSION_OID;
import static de.gematik.idp.field.ClaimName.SCOPE;
import static de.gematik.idp.field.ClaimName.SUBJECT;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.TestConstants;
import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.authentication.JwtBuilder;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.tests.Afo;
import de.gematik.idp.tests.PkiKeyResolver;
import de.gematik.idp.tests.Rfc;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(PkiKeyResolver.class)
class IdTokenBuilderTest {

  private static final String uriIdpServer = "https://idp.zentral.idp.splitdns.ti-dienste.de";
  private static final long maxIdTokenExpirationInSec = 86400;
  private static final String NONCE_VALUE = "wertDerNonce-superRandom";
  private IdTokenBuilder idTokenBuilder;
  private JsonWebToken authenticationToken;
  private PkiIdentity pkiIdentity;

  @BeforeEach
  public void init(@PkiKeyResolver.Filename("authz_rsa") final PkiIdentity clientIdentity) {
    pkiIdentity = clientIdentity;
    final Map<String, Object> bodyClaims = new HashMap<>();
    bodyClaims.put(PROFESSION_OID.getJoseName(), "profession");
    bodyClaims.put(ORGANIZATION_NAME.getJoseName(), "organization");
    bodyClaims.put(ID_NUMBER.getJoseName(), "id_number");
    bodyClaims.put(GIVEN_NAME.getJoseName(), "given_name");
    bodyClaims.put(FAMILY_NAME.getJoseName(), "family_name");
    bodyClaims.put(AUTHENTICATION_METHODS_REFERENCE.getJoseName(), List.of("foo", "bar"));
    bodyClaims.put(JWKS_URI.getJoseName(), "jwks_uri");
    bodyClaims.put(NONCE.getJoseName(), NONCE_VALUE);
    bodyClaims.put(CLIENT_ID.getJoseName(), TestConstants.CLIENT_ID_E_REZEPT_APP);
    bodyClaims.put(SCOPE.getJoseName(), EREZEPT + " " + OPENID);
    createIdTokenBuilder(bodyClaims);
  }

  private void createIdTokenBuilder(final Map<String, Object> bodyClaims) {
    authenticationToken =
        new JwtBuilder()
            .replaceAllHeaderClaims(Map.of("headerNotCopy", "headerNotCopy"))
            .replaceAllBodyClaims(bodyClaims)
            .setSignerKey(pkiIdentity.getPrivateKey())
            .buildJwt();
    idTokenBuilder =
        new IdTokenBuilder(new IdpJwtProcessor(pkiIdentity), uriIdpServer, "saltValue");
  }

  @Rfc("OpenID Connect Core 1.0 incorporating errata set 1 - 2 ID Token")
  @Afo("A_20313")
  @Afo("TODO A_20297/ML-110385?")
  @Test
  void checkIdTokenClaims() {
    final JsonWebToken idToken =
        idTokenBuilder.buildIdToken(
            TestConstants.CLIENT_ID_E_REZEPT_APP, authenticationToken, authenticationToken);

    assertThat(idToken.getBodyClaims())
        .containsEntry(ISSUER.getJoseName(), uriIdpServer)
        .containsKey(SUBJECT.getJoseName())
        .containsKey(EXPIRES_AT.getJoseName())
        .containsKey(ISSUED_AT.getJoseName())
        .containsEntry(PROFESSION_OID.getJoseName(), "profession")
        .containsEntry(ORGANIZATION_NAME.getJoseName(), "organization")
        .containsEntry(ID_NUMBER.getJoseName(), "id_number")
        .containsEntry(GIVEN_NAME.getJoseName(), "given_name")
        .containsEntry(FAMILY_NAME.getJoseName(), "family_name")
        .containsEntry(AUDIENCE.getJoseName(), TestConstants.CLIENT_ID_E_REZEPT_APP)
        .containsEntry(NONCE.getJoseName(), NONCE_VALUE)
        .doesNotContainKey(JWKS_URI.getJoseName());
    assertThat(idToken.getHeaderClaims())
        .containsKey(ALGORITHM.getJoseName())
        .doesNotContainKey(EXPIRES_AT.getJoseName())
        .doesNotContainKey("headerNotCopy");
  }

  @Rfc("OpenID Connect Core 1.0 incorporating errata set 1 - 2 ID Token")
  @Afo("A_20462")
  @Test
  void checkIdTokenClaimTimestamps() {
    final JsonWebToken idToken =
        idTokenBuilder.buildIdToken(
            TestConstants.CLIENT_ID_E_REZEPT_APP, authenticationToken, authenticationToken);

    final long now = ZonedDateTime.now().toEpochSecond();
    final long expBody = idToken.getExpiresAtBody().toEpochSecond();
    final long iat = idToken.getIssuedAt().toEpochSecond();

    assertThat(now).isGreaterThanOrEqualTo(iat).isLessThan(expBody);
    assertThat(expBody - now).isLessThan(maxIdTokenExpirationInSec);
  }

  @Rfc("OpenID Connect Core 1.0 - 3.1.3.6.")
  @Test
  void checkIdTokenClaimAtHash() {
    final JsonWebToken idToken =
        idTokenBuilder.buildIdToken(
            TestConstants.CLIENT_ID_E_REZEPT_APP, authenticationToken, authenticationToken);

    assertThat(Base64.getUrlDecoder().decode(idToken.getStringBodyClaim(ACCESS_TOKEN_HASH).get()))
        .isEqualTo(
            ArrayUtils.subarray(
                DigestUtils.sha256(authenticationToken.getRawString()), 0, (128 / 8)))
        .hasSize(128 / 8);
  }

  @Test
  void checkIdTokenWithoutNotExistingUserConsentTokenFromAuthenticationToken(
      @PkiKeyResolver.Filename("authz_rsa") final PkiIdentity clientIdentity) {
    final Map<String, Object> bodyClaims = new HashMap<>();
    bodyClaims.put(ID_NUMBER.getJoseName(), "id_number");
    bodyClaims.put(GIVEN_NAME.getJoseName(), "given_name");
    bodyClaims.put(FAMILY_NAME.getJoseName(), "family_name");
    bodyClaims.put(JWKS_URI.getJoseName(), "jwks_uri");
    bodyClaims.put(NONCE.getJoseName(), NONCE_VALUE);
    bodyClaims.put(CLIENT_ID.getJoseName(), TestConstants.CLIENT_ID_E_REZEPT_APP);
    bodyClaims.put(AUTHENTICATION_METHODS_REFERENCE.getJoseName(), List.of("foo", "bar"));
    bodyClaims.put(SCOPE.getJoseName(), EREZEPT);
    authenticationToken =
        new JwtBuilder()
            .replaceAllHeaderClaims(Map.of("headerNotCopy", "headerNotCopy"))
            .replaceAllBodyClaims(bodyClaims)
            .setSignerKey(clientIdentity.getPrivateKey())
            .buildJwt();

    final JsonWebToken idToken =
        idTokenBuilder.buildIdToken(
            TestConstants.CLIENT_ID_E_REZEPT_APP, authenticationToken, authenticationToken);

    assertThat(idToken.getBodyClaims())
        .containsEntry(ISSUER.getJoseName(), uriIdpServer)
        .containsKey(SUBJECT.getJoseName())
        .containsEntry(AUDIENCE.getJoseName(), TestConstants.CLIENT_ID_E_REZEPT_APP)
        .containsKey(EXPIRES_AT.getJoseName())
        .containsKey(ISSUED_AT.getJoseName())
        .containsEntry(ID_NUMBER.getJoseName(), "id_number")
        .containsEntry(GIVEN_NAME.getJoseName(), "given_name")
        .containsEntry(FAMILY_NAME.getJoseName(), "family_name")
        .containsEntry(NONCE.getJoseName(), NONCE_VALUE)
        .doesNotContainKey(JWKS_URI.getJoseName())
        .doesNotContainKey(ORGANIZATION_NAME.getJoseName())
        .doesNotContainKey(PROFESSION_OID.getJoseName());
  }

  @Test
  void verifyAudienceByScopeERezept() {
    final Map<String, Object> bodyClaims = new HashMap<>();
    bodyClaims.put(ID_NUMBER.getJoseName(), "id_number");
    bodyClaims.put(CLIENT_ID.getJoseName(), TestConstants.CLIENT_ID_E_REZEPT_APP);
    bodyClaims.put(SCOPE.getJoseName(), EREZEPT);
    bodyClaims.put(AUTHENTICATION_METHODS_REFERENCE.getJoseName(), List.of("foo", "bar"));
    createIdTokenBuilder(bodyClaims);
    final JsonWebToken idToken =
        idTokenBuilder.buildIdToken(
            TestConstants.CLIENT_ID_E_REZEPT_APP, authenticationToken, authenticationToken);
    assertThat(idToken.getBodyClaim(AUDIENCE))
        .get()
        .isEqualTo(TestConstants.CLIENT_ID_E_REZEPT_APP);
  }

  @Test
  void verifyAudienceByScopePairing() {
    final Map<String, Object> bodyClaims = new HashMap<>();
    bodyClaims.put(ID_NUMBER.getJoseName(), "id_number");
    bodyClaims.put(CLIENT_ID.getJoseName(), TestConstants.CLIENT_ID_E_REZEPT_APP);
    bodyClaims.put(SCOPE.getJoseName(), PAIRING);
    bodyClaims.put(AUTHENTICATION_METHODS_REFERENCE.getJoseName(), List.of("foo", "bar"));
    createIdTokenBuilder(bodyClaims);
    final JsonWebToken idToken =
        idTokenBuilder.buildIdToken(
            TestConstants.CLIENT_ID_E_REZEPT_APP, authenticationToken, authenticationToken);
    assertThat(idToken.getBodyClaim(AUDIENCE))
        .get()
        .isEqualTo(TestConstants.CLIENT_ID_E_REZEPT_APP);
  }
}
