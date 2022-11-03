/*
 * Copyright (c) 2022 gematik GmbH
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

import static de.gematik.idp.field.ClaimName.ALGORITHM;
import static de.gematik.idp.field.ClaimName.AUTH_TIME;
import static de.gematik.idp.field.ClaimName.CONFIRMATION;
import static de.gematik.idp.field.ClaimName.EXPIRES_AT;
import static de.gematik.idp.field.ClaimName.FAMILY_NAME;
import static de.gematik.idp.field.ClaimName.GIVEN_NAME;
import static de.gematik.idp.field.ClaimName.ID_NUMBER;
import static de.gematik.idp.field.ClaimName.ISSUED_AT;
import static de.gematik.idp.field.ClaimName.ISSUER;
import static de.gematik.idp.field.ClaimName.ORGANIZATION_NAME;
import static de.gematik.idp.field.ClaimName.PROFESSION_OID;
import static de.gematik.idp.field.ClaimName.TYPE;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.tests.Afo;
import de.gematik.idp.tests.PkiKeyResolver;
import java.security.Security;
import java.time.ZonedDateTime;
import java.util.List;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(PkiKeyResolver.class)
class SsoTokenBuilderTest {

  private static final String uriIdpServer = "https://idp.zentral.idp.splitdns.ti-dienste.de";

  static {
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    Security.insertProviderAt(new BouncyCastleProvider(), 1);
  }

  private PkiIdentity serverIdentity;
  private PkiIdentity clientIdentity;
  private SsoTokenBuilder ssoTokenBuilder;
  private SecretKeySpec encryptionKey;

  @BeforeEach
  public void init(
      final PkiIdentity ecc,
      @PkiKeyResolver.Filename("109500969_X114428530_c.ch.aut-ecc")
          final PkiIdentity clientIdentity) {
    serverIdentity = ecc;
    this.clientIdentity = clientIdentity;
    final IdpJwtProcessor serverJwtProcessor = new IdpJwtProcessor(serverIdentity);
    encryptionKey =
        new SecretKeySpec(
            DigestUtils.sha256("fdsfdsafdsafdsafdsarvdfvcxyvcxyvc".getBytes()), "AES");
    ssoTokenBuilder = new SsoTokenBuilder(serverJwtProcessor, uriIdpServer, encryptionKey);
  }

  @Test
  void ssoTokenShouldContainCnf() {
    final JsonWebToken ssoToken =
        ssoTokenBuilder
            .buildSsoToken(clientIdentity.getCertificate(), ZonedDateTime.now(), List.of(""))
            .decryptNestedJwt(encryptionKey);

    assertThat(ssoToken.getBodyClaims()).containsKey(ClaimName.CONFIRMATION.getJoseName());
  }

  @Test
  void ssoTokenShouldContainValidClaims() {
    final JsonWebToken ssoToken =
        ssoTokenBuilder
            .buildSsoToken(clientIdentity.getCertificate(), ZonedDateTime.now(), List.of(""))
            .decryptNestedJwt(encryptionKey);

    assertThat(ssoToken.getHeaderClaims())
        .containsKeys(ALGORITHM.getJoseName(), TYPE.getJoseName());

    assertThat(ssoToken.getBodyClaims())
        .containsKeys(
            ISSUED_AT.getJoseName(),
            EXPIRES_AT.getJoseName(),
            GIVEN_NAME.getJoseName(),
            FAMILY_NAME.getJoseName(),
            ORGANIZATION_NAME.getJoseName(),
            PROFESSION_OID.getJoseName(),
            ID_NUMBER.getJoseName())
        .containsEntry(ISSUER.getJoseName(), uriIdpServer);
  }

  @Test
  void ssoTokenForIdTokenShouldContainValidClaims() {
    final JsonWebToken idToken =
        new JsonWebToken(
            "eyJhbGciOiJCUDI1NlIxIiwia2lkIjoicHVrX2lkcF9zaWciLCJ0eXAiOiJKV1QifQ.eyJhdXRoX3RpbWUiOjE2MjMwNTYxMzYsIm5vbmNlIjoiOTg3NjUiLCJnaXZlbl9uYW1lIjoiRGFyaXVzIE1pY2hhZWwgQnJpYW4gVWJibyIsImZhbWlseV9uYW1lIjoiQsO2ZGVmZWxkIiwib3JnYW5pemF0aW9uTmFtZSI6IlRlc3QgR0tWLVNWTk9ULVZBTElEIiwicHJvZmVzc2lvbk9JRCI6IjEuMi4yNzYuMC43Ni40LjQ5IiwiaWROdW1tZXIiOiJYMTEwNDExNjc1IiwiYXpwIjoiZVJlemVwdEFwcCIsImFjciI6ImdlbWF0aWstZWhlYWx0aC1sb2EtaGlnaCIsImFtciI6WyJtZmEiLCJzYyIsInBpbiJdLCJhdWQiOiJlUmV6ZXB0QXBwIiwic3ViIjoiOGMwN2UzNzYwZjM1NjE5YzJlNWNjY2JkMzQxMzU0NDcwYjgwMmU5ZGIyZTkyYTgzNjMwMzdlYjc5OTkwYjU2ZSIsImlzcyI6Imh0dHBzOi8vaWRwLXRlc3QuemVudHJhbC5pZHAuc3BsaXRkbnMudGktZGllbnN0ZS5kZSIsImlhdCI6MTYyMzA1NjEzNiwiZXhwIjoxNjIzMDk5MzM2LCJqdGkiOiJjNjRiZmU2YS1kNzUyLTRlNWYtODA5YS0zM2IzOGUwYzNlOGUiLCJhdF9oYXNoIjoicUc5QXU4ei1kNVE2MllJWXlBRV9rQSJ9.Z0mhWFS2TcUtZlj-KAX9ys9Az-MwEvQ6AxRMLh2mKSdG6PKfsxsXJQhldeIzD1s2zcTTe74QPd0xUG8OCz9VuQ");
    final JsonWebToken ssoToken =
        ssoTokenBuilder
            .buildSsoTokenFromSektoralIdToken(idToken, ZonedDateTime.now())
            .decryptNestedJwt(encryptionKey);

    assertThat(ssoToken.getHeaderClaims())
        .containsKeys(ALGORITHM.getJoseName(), TYPE.getJoseName());

    assertThat(ssoToken.getBodyClaims())
        .containsKeys(
            ISSUED_AT.getJoseName(),
            EXPIRES_AT.getJoseName(),
            GIVEN_NAME.getJoseName(),
            FAMILY_NAME.getJoseName(),
            ORGANIZATION_NAME.getJoseName(),
            PROFESSION_OID.getJoseName(),
            ID_NUMBER.getJoseName())
        .containsEntry(ISSUER.getJoseName(), uriIdpServer);
  }

  @Afo("A_20731")
  @Test
  void verifyAuthTime() {
    final JsonWebToken ssoToken =
        ssoTokenBuilder
            .buildSsoToken(clientIdentity.getCertificate(), ZonedDateTime.now(), List.of(""))
            .decryptNestedJwt(encryptionKey);

    assertThat(ssoToken.getDateTimeClaim(AUTH_TIME, () -> ssoToken.getBodyClaims()).get())
        .isBetween(ZonedDateTime.now().minusSeconds(5), ZonedDateTime.now());
  }

  @Test
  void verifyExpClaim() {
    final JsonWebToken ssoToken =
        ssoTokenBuilder
            .buildSsoToken(clientIdentity.getCertificate(), ZonedDateTime.now(), List.of(""))
            .decryptNestedJwt(encryptionKey);

    assertThat(ssoToken.getBodyDateTimeClaim(EXPIRES_AT).get())
        .isBetween(
            ZonedDateTime.now().plusHours(12).minusSeconds(10), ZonedDateTime.now().plusHours(12));
  }

  @Test
  void verifyCnfDoesNotContainNullValues() {
    final JsonWebToken ssoToken =
        ssoTokenBuilder
            .buildSsoToken(clientIdentity.getCertificate(), ZonedDateTime.now(), List.of(""))
            .decryptNestedJwt(encryptionKey);

    assertThat(ssoToken.getBodyClaim(CONFIRMATION).get().toString()).doesNotContain("null");
  }
}
