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

import static de.gematik.idp.field.ClaimName.CONFIRMATION;
import static de.gematik.idp.field.ClaimName.CONTENT_TYPE;
import static de.gematik.idp.field.ClaimName.ENCRYPTION_ALGORITHM;
import static de.gematik.idp.field.ClaimName.EXPIRES_AT;
import static de.gematik.idp.field.ClaimName.NESTED_JWT;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.authentication.JwtBuilder;
import de.gematik.idp.crypto.Nonce;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.tests.PkiKeyResolver;
import de.gematik.idp.tests.PkiKeyResolver.Filename;
import java.security.Security;
import java.time.ZonedDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import javax.crypto.spec.SecretKeySpec;
import lombok.SneakyThrows;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jose4j.jwk.PublicJsonWebKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(PkiKeyResolver.class)
class JsonWebTokenTest {

  static {
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    Security.insertProviderAt(new BouncyCastleProvider(), 1);
  }

  private IdpJwtProcessor idpJwtProcessor;
  private SecretKeySpec aesKey;
  private PkiIdentity identityBrainpool;

  private PkiIdentity identityNist;

  // key from idp\idp-commons\src\test\resources\sig-nist.p12
  private static final String JWK_AS_STRING =
      "{\"use\": \"enc\",\"kid\": \"ref_puk_fd_enc\",\"kty\": \"EC\",\"crv\": \"P-256\",\"x\":"
          + " \"Mq933FT_V8xd1TkfB0pH02d6cx2bmUS-bxHuBtA1yfs\",\"y\":"
          + " \"5uwf8phUbWIi92CqgglM94ft-FC4MHH836khswo6ppo\"}";

  @BeforeEach
  public void setup(
      @PkiKeyResolver.Filename("ecc") final PkiIdentity identityBrainpool,
      @PkiKeyResolver.Filename("nist") final PkiIdentity identityNist) {
    idpJwtProcessor = new IdpJwtProcessor(identityBrainpool);
    aesKey = new SecretKeySpec(Nonce.randomBytes(256 / 8), "AES");
    this.identityBrainpool = identityBrainpool;
    this.identityNist = identityNist;
  }

  @Test
  void getTokenExp_ShouldBeCorrect() {
    final JsonWebToken jsonWebToken =
        idpJwtProcessor.buildJwt(new JwtBuilder().expiresAt(ZonedDateTime.now().plusMinutes(5)));

    assertThat(jsonWebToken.getExpiresAt())
        .isBetween(ZonedDateTime.now().plusMinutes(4), ZonedDateTime.now().plusMinutes(6));
  }

  @Test
  void getBodyClaims_shouldMatch() {
    final JsonWebToken jsonWebToken =
        idpJwtProcessor.buildJwt(
            new JwtBuilder()
                .addAllBodyClaims(Map.of("foo", "bar"))
                .expiresAt(ZonedDateTime.now().plusMinutes(5)));

    assertThat(jsonWebToken.getBodyClaims()).containsEntry("foo", "bar");
  }

  @Test
  void getHeaderClaims_shouldMatch() {
    final JsonWebToken jsonWebToken =
        idpJwtProcessor.buildJwt(
            new JwtBuilder()
                .addAllHeaderClaims(new HashMap<>(Map.of("foo", "bar")))
                .expiresAt(ZonedDateTime.now().plusMinutes(5)));

    assertThat(jsonWebToken.getHeaderClaims())
        .containsEntry("foo", "bar")
        .containsEntry("alg", "BP256R1");
  }

  @Test
  void getAlgHeaderClaimForNist_shouldMatch() {
    final IdpJwtProcessor idpJwtProcessorNist = new IdpJwtProcessor(identityNist);
    final JsonWebToken jsonWebToken =
        idpJwtProcessorNist.buildJwt(
            new JwtBuilder()
                .addAllHeaderClaims(new HashMap<>(Map.of("foo", "bar")))
                .expiresAt(ZonedDateTime.now().plusMinutes(5)));

    assertThat(jsonWebToken.getHeaderClaims())
        .containsEntry("foo", "bar")
        .containsEntry("alg", "ES256");
  }

  @Test
  void getStringBodyClaims_shouldMatch() {
    final JsonWebToken jsonWebToken =
        idpJwtProcessor.buildJwt(new JwtBuilder().addAllBodyClaims(Map.of("foo", "bar")));

    assertThat(jsonWebToken.getBodyClaims()).containsEntry("foo", "bar");
  }

  @Test
  void getDateTimeBodyClaims_shouldMatch() {
    final ZonedDateTime now = ZonedDateTime.now();
    final JsonWebToken jsonWebToken =
        idpJwtProcessor.buildJwt(
            new JwtBuilder()
                .addAllBodyClaims(Map.of(CONFIRMATION.getJoseName(), now.toEpochSecond())));

    assertThat(jsonWebToken.getDateTimeClaim(CONFIRMATION, jsonWebToken::getBodyClaims))
        .get(InstanceOfAssertFactories.ZONED_DATE_TIME)
        .isEqualToIgnoringNanos(now);
  }

  @Test
  void encryptJwtWithEcc_shouldBeJweStructure(
      @Filename("109500969_X114428530_c.ch.aut-ecc") final PkiIdentity id) {
    final JsonWebToken jsonWebToken =
        idpJwtProcessor.buildJwt(
            new JwtBuilder().addAllBodyClaims(Map.of(CONFIRMATION.getJoseName(), "foobarschmar")));

    assertThat(
            jsonWebToken
                .encryptAsNjwt(id.getCertificate().getPublicKey())
                .decryptNestedJwt(id.getPrivateKey())
                .getBodyClaim(CONFIRMATION))
        .get()
        .isEqualTo("foobarschmar");
  }

  @Test
  void encryptJwtWithAes_shouldBeJweStructure() {
    final JsonWebToken jsonWebToken =
        idpJwtProcessor.buildJwt(
            new JwtBuilder()
                .addAllBodyClaims(Map.of(CONFIRMATION.getJoseName(), ZonedDateTime.now())));

    assertThat(jsonWebToken.encryptAsNjwt(aesKey).getRawString())
        .matches("(?:.*\\.){4}.*"); // 5 Teile Base64
  }

  @Test
  void encryptJwtWithAes_algorithmShouldBeAes256Gcm() {
    final JsonWebToken jsonWebToken =
        idpJwtProcessor.buildJwt(
            new JwtBuilder()
                .addAllBodyClaims(Map.of(CONFIRMATION.getJoseName(), ZonedDateTime.now())));

    assertThat(jsonWebToken.encryptAsNjwt(aesKey).getHeaderClaim(ENCRYPTION_ALGORITHM))
        .get()
        .isEqualTo("A256GCM");
  }

  @Test
  void encryptJwtWithAes_ctyShouldBeNJWT() {
    final JsonWebToken jsonWebToken =
        idpJwtProcessor.buildJwt(
            new JwtBuilder()
                .addAllBodyClaims(Map.of(CONFIRMATION.getJoseName(), ZonedDateTime.now())));

    assertThat(jsonWebToken.encryptAsNjwt(aesKey).getHeaderClaim(CONTENT_TYPE))
        .get()
        .isEqualTo("NJWT");
  }

  @Test
  void decryptJweWithAes_shouldMatchSourceJwt() {
    final JsonWebToken jsonWebToken =
        idpJwtProcessor.buildJwt(
            new JwtBuilder().addAllBodyClaims(Map.of(CONFIRMATION.getJoseName(), "foobarschmar")));

    assertThat(
            jsonWebToken.encryptAsNjwt(aesKey).decryptNestedJwt(aesKey).getBodyClaim(CONFIRMATION))
        .get()
        .isEqualTo("foobarschmar");
  }

  @Test
  void encryptJwt_shouldHaveNjwtClaim() {
    final Map<String, Object> bodyClaims =
        idpJwtProcessor
            .buildJwt(new JwtBuilder().addAllBodyClaims(Map.of("foo", "bar")))
            .encryptAsNjwt(aesKey)
            .setDecryptionKey(aesKey)
            .extractBodyClaims();

    assertThat(bodyClaims).containsOnlyKeys(NESTED_JWT.getJoseName());
  }

  @Test
  void encryptJwt_shouldHaveExpClaimForNestedJwt() {
    final long expValue = 1234567L;
    final Optional<Object> expHeaderClaim =
        idpJwtProcessor
            .buildJwt(new JwtBuilder().addAllBodyClaims(Map.of(EXPIRES_AT.getJoseName(), expValue)))
            .encryptAsNjwt(aesKey)
            .getHeaderClaim(EXPIRES_AT);

    assertThat(expHeaderClaim).isPresent().get().isEqualTo(expValue);
  }

  @Test
  void encryptJwt_shouldHaveExpClaimForNestedNestedJwt() {
    final long expValue = 1234567L;
    final JsonWebToken innerJwt =
        idpJwtProcessor.buildJwt(
            new JwtBuilder().addAllBodyClaims(Map.of(EXPIRES_AT.getJoseName(), expValue)));
    final Optional<Object> expHeaderClaim =
        idpJwtProcessor
            .buildJwt(
                new JwtBuilder()
                    .addAllBodyClaims(Map.of(NESTED_JWT.getJoseName(), innerJwt.getRawString())))
            .encryptAsNjwt(aesKey)
            .getHeaderClaim(EXPIRES_AT);

    assertThat(expHeaderClaim).isPresent().get().isEqualTo(expValue);
  }

  @SneakyThrows
  @Test
  void encryptAsJwt_checkEncryptionHeaders() {
    final PublicJsonWebKey jwk = PublicJsonWebKey.Factory.newPublicJwk(JWK_AS_STRING);
    final JsonWebToken jsonWebToken =
        idpJwtProcessor.buildJwt(
            new JwtBuilder().addAllBodyClaims(Map.of(CONFIRMATION.getJoseName(), "foobarschmar")));

    final IdpJwe idpJwe = jsonWebToken.encryptAsJwt(jwk);

    assertThat(idpJwe.getHeaderClaims().keySet()).contains("kid", "cty");
    assertThat(idpJwe.getHeaderClaim(CONTENT_TYPE).get()).isEqualTo("JWT");
  }

  @SneakyThrows
  @Test
  void encryptAsJwt_checkDecryption() {
    final PublicJsonWebKey jwk = PublicJsonWebKey.Factory.newPublicJwk(JWK_AS_STRING);
    final JsonWebToken jsonWebToken =
        idpJwtProcessor.buildJwt(
            new JwtBuilder().addAllBodyClaims(Map.of(CONFIRMATION.getJoseName(), "my plaintext")));

    final IdpJwe idpJwe = jsonWebToken.encryptAsJwt(jwk);
    final JsonWebToken plainToken = idpJwe.decryptJwt(identityNist.getPrivateKey());

    assertThat(plainToken.getBodyClaim(CONFIRMATION)).contains("my plaintext");
  }
}
