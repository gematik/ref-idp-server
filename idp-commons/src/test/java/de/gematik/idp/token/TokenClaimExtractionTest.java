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

package de.gematik.idp.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.jose4j.jws.AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256;

import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.authentication.JwtBuilder;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.tests.PkiKeyResolver;
import java.security.PublicKey;
import java.security.Security;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZonedDateTime;
import java.util.Map;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jose4j.jwk.JsonWebKeySet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(PkiKeyResolver.class)
class TokenClaimExtractionTest {

  // exp: Wednesday, 14-Feb-29 00:00:00 UTC, Token soll eigentlich nur 43.200 s alt sein (A_20503)
  // nbf=iat: Monday, 21-Sep-20 08:34:52 UTC
  private static final String ACCESS_TOKEN =
      "eyJhbGciOiJFUzI1NiIsInR5cCI6ImF0K0pXVCJ9.eyJpc3MiOiJodHRwOi8vZ3N0b3BkaDE6ODU4MC9hdXRoL3JlYWxtcy9pZ"
          + "HAiLCJzdWIiOiJhM2ZlMDI3Ni1hNGM1LTQ0NDEtODhiMy1jOGYzNzQ5OTEyN2QiLCJwcm9mZXNzaW9uT0lEIjoiMS4yLjI3Ni4"
          + "wLjc2LjQuNTAiLCJpYXQiOjE2MDA2NzcxNzksIm5iZiI6MTYwMDY3NzE3OSwiZXhwIjoxODY1NzIxNjAwLCJnaXZlbl9uYW1lI"
          + "joiZGVyIFZvcm5hbWUiLCJmYW1pbHlfbmFtZSI6ImRlciBOYWNobmFtZSIsIm9yZ2FuaXphdGlvbk5hbWUiOiJJbnN0aXR1dGl"
          + "vbnMtIG9kZXIgT3JnYW5pc2F0aW9ucy1CZXplaWNobnVuZyIsImlkTnVtbWVyIjoiMy0xNS4xLjEuMTIzNDU2Nzg5Iiwic2Nvc"
          + "GUiOiJvcGVuaWQgZS1yZXplcHQiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6Imp1bGlvIiw"
          + "ianRpIjoiMzlmNzA1MmQtMWZhMy00ODg3LTk0MmItZGQzODcwOThiZmM3IiwiYXVkIjoiaHR0cHM6Ly9ycy5lLXJlemVwdC5jb"
          + "20vIiwic2Vzc2lvbl9zdGF0ZSI6ImRkYjJlN2UyLWU4ZTgtNDAwNy05ODk5LTE4NDQyN2RlOTFjNCIsImFjciI6IjEiLCJyZWF"
          + "sbV9hY2Nlc3MiOnsicm9sZXMiOlsib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZ"
          + "XNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJ"
          + "vZmlsZSJdfX19.owSs71NCqki3X2baaZrH9bx-qu2HQb_BGKOZ6sw-2oZr27hMHuFrU9e5lJPh_THyh-XS10pEySIPYt132Tol"
          + "9g";
  private static final String ENTITY_STMNT_ABOUT_RP_EXPIRES_IN_YEAR_2043 =
      "eyJhbGciOiJFUzI1NiIsInR5cCI6ImVudGl0eS1zdGF0ZW1lbnQrand0Iiwia2lkIjoicHVrX2ZlZF9zaWcifQ.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjU3OTAyIiwic3ViIjoiaHR0cDovLzEyNy4wLjAuMTo4MDg0IiwiYXVkIjpudWxsLCJpYXQiOjE2Nzk1NzE4NTYsImV4cCI6MjMxMDI5MTg1NiwiandrcyI6eyJrZXlzIjpbeyJ1c2UiOiJzaWciLCJraWQiOiJwdWtfZmRfc2lnIiwia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiI5YkpzMjdZQWZsTVVXSzVueHVpRjZYQUcwSmF6dXZ3UmkxRXBGSzBYS2lrIiwieSI6IlA4bHpOVlJPZ1R1d2JEcXNkOHJUMUFJM3plejk0SEJzVERwT3ZhalAwclkifV19fQ.QQN5-IcTdmxg8PT5BlLT7OLlATLBI1PVFvods8dVCBd_b7m6sEOi8Y1GJp2hk08MoQatLbTvMTSVv5lqeH59hQ";

  static {
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    Security.insertProviderAt(new BouncyCastleProvider(), 1);
  }

  @Test
  void verifyAccessTokenExtraction() {
    final Map<String, Object> claims = TokenClaimExtraction.extractClaimsFromJwtBody(ACCESS_TOKEN);

    assertThat(claims)
        .containsEntry("given_name", "der Vorname")
        .containsEntry("family_name", "der Nachname")
        .containsEntry("organizationName", "Institutions- oder Organisations-Bezeichnung")
        .containsEntry("professionOID", "1.2.276.0.76.4.50")
        .containsEntry("idNummer", "3-15.1.1.123456789")
        .doesNotContainEntry("bloedsinn", "keine Ahnung")
        .doesNotContainEntry("idNummer", "1.2.276.0.76.4.666")
        .doesNotContainKeys("alg");
  }

  @Test
  void verifyGetClaimAsDateTime() {
    final Map<String, Object> claims = TokenClaimExtraction.extractClaimsFromJwtBody(ACCESS_TOKEN);
    final String DATE = "2020-09-21T08:32:59";
    assertThat(
            Duration.between(
                LocalDateTime.parse(DATE),
                TokenClaimExtraction.claimToZonedDateTime(claims.get("iat"))))
        .as("Teste korrektes iat:")
        .overridingErrorMessage(
            "iat ist nicht wie erwartet ("
                + DATE
                + "), sondern: "
                + TokenClaimExtraction.claimToZonedDateTime(claims.get("iat")))
        .isEqualTo(Duration.ofMinutes(0));
  }

  @Test
  void verifyExtractHeaderClaimsFromToken() {
    final Map<String, Object> headerClaims =
        TokenClaimExtraction.extractClaimsFromJwtHeader(ACCESS_TOKEN);
    assertThat(headerClaims).hasSize(2).containsKey("typ").containsKey("alg");

    assertThat(headerClaims.get("alg").toString()).contains(ECDSA_USING_P256_CURVE_AND_SHA256);
    assertThat(headerClaims.get("typ").toString()).contains("at+JWT");
  }

  @Test
  void extractClientCertificate_shouldMatch(
      @PkiKeyResolver.Filename("ecc") final PkiIdentity identity) {
    final JsonWebToken token =
        new IdpJwtProcessor(identity)
            .buildJwt(
                new JwtBuilder()
                    .expiresAt(ZonedDateTime.now())
                    .includeSignerCertificateInHeader(true));

    assertThat(token.getClientCertificateFromHeader()).get().isEqualTo(identity.getCertificate());
  }

  @Test
  void readJwks() {
    final JsonWebKeySet jwks =
        TokenClaimExtraction.extractJwksFromBody(ENTITY_STMNT_ABOUT_RP_EXPIRES_IN_YEAR_2043);
    assertThat(jwks.getJsonWebKeys()).hasSize(1);
    assertThat(jwks.findJsonWebKeys("puk_fd_sig", null, null, null)).hasSize(1);
    assertThat(jwks.findJsonWebKey("puk_fd_sig", null, null, null).getUse()).isEqualTo("sig");
  }

  @Test
  void getPublicKeyFromJwks() {
    final JsonWebKeySet jwks =
        TokenClaimExtraction.extractJwksFromBody(ENTITY_STMNT_ABOUT_RP_EXPIRES_IN_YEAR_2043);
    final PublicKey p = TokenClaimExtraction.getECPublicKey(jwks, "puk_fd_sig");
    assertThat(p.getAlgorithm()).isEqualTo("EC");
  }
}
