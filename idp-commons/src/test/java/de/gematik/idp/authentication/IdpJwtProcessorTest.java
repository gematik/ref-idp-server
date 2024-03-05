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

import static de.gematik.idp.field.ClaimName.ALGORITHM;
import static de.gematik.idp.field.ClaimName.CLIENT_ID;
import static de.gematik.idp.field.ClaimName.CODE_CHALLENGE;
import static de.gematik.idp.field.ClaimName.CODE_CHALLENGE_METHOD;
import static de.gematik.idp.field.ClaimName.EXPIRES_AT;
import static de.gematik.idp.field.ClaimName.ISSUED_AT;
import static de.gematik.idp.field.ClaimName.ISSUER;
import static de.gematik.idp.field.ClaimName.JWT_ID;
import static de.gematik.idp.field.ClaimName.REDIRECT_URI;
import static de.gematik.idp.field.ClaimName.RESPONSE_TYPE;
import static de.gematik.idp.field.ClaimName.SCOPE;
import static de.gematik.idp.field.ClaimName.SERVER_NONCE;
import static de.gematik.idp.field.ClaimName.STATE;
import static java.util.Map.entry;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.gematik.idp.brainPoolExtension.BrainpoolAlgorithmSuiteIdentifiers;
import de.gematik.idp.crypto.KeyUtility;
import de.gematik.idp.crypto.exceptions.IdpCryptoException;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.file.ResourceReader;
import de.gematik.idp.tests.PkiKeyResolver;
import de.gematik.idp.token.JsonWebToken;
import java.io.Serial;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.Security;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.HashMap;
import java.util.Map;
import lombok.SneakyThrows;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(PkiKeyResolver.class)
class IdpJwtProcessorTest {

  static final long TOKEN_VALIDITY_MINUTES = 10;

  static {
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    Security.insertProviderAt(new BouncyCastleProvider(), 1);
  }

  JwtBuilder jwtBuilder =
      new JwtBuilder()
          .expiresAt(ZonedDateTime.now().plusMinutes(10))
          .addAllBodyClaims(
              new HashMap<>(
                  Map.ofEntries(
                      entry(ISSUED_AT.getJoseName(), ZonedDateTime.now().toEpochSecond()),
                      entry(ISSUER.getJoseName(), "https://myIdp.de"),
                      entry(RESPONSE_TYPE.getJoseName(), "code"),
                      entry(SCOPE.getJoseName(), "openid e-rezept"),
                      entry(CLIENT_ID.getJoseName(), "ZXJlemVwdC1hcHA"),
                      entry(STATE.getJoseName(), "af0ifjsldkj"),
                      entry(REDIRECT_URI.getJoseName(), "https://app.e-rezept.com/authnres"),
                      entry(JWT_ID.getJoseName(), "c3a8f9c8-aa62-11ea-ac15-6b7a3355d0f6"),
                      entry(CODE_CHALLENGE_METHOD.getJoseName(), "S256"),
                      entry(
                          CODE_CHALLENGE.getJoseName(),
                          "S41HgHxhXL1CIpfGvivWYpbO9b_QKzva-9ImuZbt0Is"))))
          .addAllHeaderClaims(
              new HashMap<>(
                  Map.ofEntries(
                      // two parts of header are written by library: ("typ", "JWT"),("alg", "ES256")
                      entry(
                          SERVER_NONCE.getJoseName(),
                          "sLlxlkskAyuzdDOwe8nZeeQVFBWgscNkRcpgHmKidFc"),
                      entry(
                          EXPIRES_AT.getJoseName(),
                          LocalDateTime.now()
                              .plusMinutes(TOKEN_VALIDITY_MINUTES)
                              .toEpochSecond(ZoneOffset.UTC)))));

  private IdpJwtProcessor jwtProcessor;

  @Test
  void build_rsa(final PkiIdentity rsa) {
    final JsonWebToken jwt = createJwt(rsa);
    jwtProcessor.verifyAndThrowExceptionIfFail(jwt);
  }

  @Test
  void build_ecc(final PkiIdentity ecc) {
    final JsonWebToken jwt = createJwt(ecc);
    jwtProcessor.verifyAndThrowExceptionIfFail(jwt);
  }

  @Test
  void verifyInvalidHeader_ecc(final PkiIdentity ecc) {
    final JsonWebToken jwt = createJwt(ecc);
    jwtProcessor.verifyAndThrowExceptionIfFail(jwt);
    // delete first character
    final String jwtJasonInvalid = jwt.getRawString().substring(1);
    final JsonWebToken jsonWebToken = new JsonWebToken(jwtJasonInvalid);
    assertThatThrownBy(() -> jwtProcessor.verifyAndThrowExceptionIfFail(jsonWebToken))
        .isInstanceOf(RuntimeException.class);
  }

  @Test
  void verifyInvalidSignature_ecc(final PkiIdentity ecc) {
    final JsonWebToken jwt = createJwt(ecc);
    // delete last character
    final String jwtJasonInvalid = jwt.getRawString().substring(0, jwt.getRawString().length() - 1);
    final JsonWebToken jsonWebToken = new JsonWebToken(jwtJasonInvalid);
    assertThat(jsonWebToken).isNotNull();
    assertThatThrownBy(() -> jwtProcessor.verifyAndThrowExceptionIfFail(jsonWebToken))
        .isInstanceOf(RuntimeException.class);
  }

  @Test
  void verifySignAlgo_ecc(final PkiIdentity ecc) {
    final JsonWebToken jwt = createJwt(ecc);
    jwtProcessor.verifyAndThrowExceptionIfFail(jwt);
    assertThat(IdpJwtProcessor.getHeaderDecoded(jwt))
        .contains(BrainpoolAlgorithmSuiteIdentifiers.BRAINPOOL256_USING_SHA256);
    assertThat(IdpJwtProcessor.getHeaderDecoded(jwt)).doesNotContain("RS256");
  }

  @Test
  void verifyHeaderElementsComplete_ecc(final PkiIdentity ecc) {
    final JsonWebToken jwt = createJwt(ecc);
    jwtProcessor.verifyAndThrowExceptionIfFail(jwt);
    assertThat(IdpJwtProcessor.getHeaderDecoded(jwt)).contains(ALGORITHM.getJoseName());
  }

  @Test
  void verifyPayloadElementsComplete_ecc(final PkiIdentity ecc) {
    final JsonWebToken jwt = createJwt(ecc);
    jwtProcessor.verifyAndThrowExceptionIfFail(jwt);
    final String payloadAsString = IdpJwtProcessor.getPayloadDecoded(jwt);
    assertThat(payloadAsString)
        .contains(RESPONSE_TYPE.getJoseName())
        .contains(SCOPE.getJoseName())
        .contains(CLIENT_ID.getJoseName())
        .contains(STATE.getJoseName())
        .contains(REDIRECT_URI.getJoseName())
        .contains(CODE_CHALLENGE_METHOD.getJoseName())
        .contains(CODE_CHALLENGE.getJoseName())
        .contains(EXPIRES_AT.getJoseName());
  }

  @Test
  void verifyPayloadMeetsJwtDescription_ecc(final PkiIdentity ecc) {
    final JsonWebToken jwtAsBase64 = createJwt(ecc);
    jwtProcessor.verifyAndThrowExceptionIfFail(jwtAsBase64);
    final String payloadAsString = IdpJwtProcessor.getPayloadDecoded(jwtAsBase64);
    jwtBuilder.getClaims().forEach((key, value) -> assertThat(payloadAsString).contains(key));
    jwtBuilder
        .getClaims()
        .forEach((key, value) -> assertThat(payloadAsString).contains(value.toString()));
  }

  @SneakyThrows
  @Test
  void createFromPrivateKeyEcc() {
    final PrivateKey privateKey =
        KeyUtility.readX509PrivateKeyPlain(
            ResourceReader.getFileFromResourceAsTmpFile("keys/ref-es-sig-privkey.pem"));
    assertThat(privateKey).isNotNull();
    final IdpJwtProcessor idpJwtProc = new IdpJwtProcessor(privateKey, "puk_idp_sig_test");
    final JsonWebToken jwt = idpJwtProc.buildJwt(jwtBuilder);
    assertThat(jwt).isNotNull();
  }

  @Test
  void createFromPrivateKey_wrongPrivateKeyObject() {
    final PrivateKey privateKey =
        new DSAPrivateKey() {
          @Serial private static final long serialVersionUID = 8001498111124156703L;

          @Override
          public BigInteger getX() {
            return null;
          }

          @Override
          public String getAlgorithm() {
            return null;
          }

          @Override
          public String getFormat() {
            return null;
          }

          @Override
          public byte[] getEncoded() {
            return new byte[0];
          }

          @Override
          public DSAParams getParams() {
            return null;
          }
        };
    assertThat(privateKey).isNotNull();

    assertThatThrownBy(() -> new IdpJwtProcessor(privateKey, "puk_idp_sig_test"))
        .isInstanceOf(IdpCryptoException.class)
        .hasMessageContaining("Could not identify Private-Key");
  }

  @SneakyThrows
  @Test
  void createFromPrivateKeyBrainpool() {
    final PrivateKey privateKey =
        KeyUtility.readX509PrivateKeyPlain(
            ResourceReader.getFileFromResourceAsTmpFile(
                "keys/1_C.SGD-HSM.AUT_oid_sgd1_hsm-ecc-bpool-privkey.pem"));
    assertThat(privateKey).isNotNull();
    final IdpJwtProcessor idpJwtProc = new IdpJwtProcessor(privateKey, "my_brainpool_key");
    final JsonWebToken jwt = idpJwtProc.buildJwt(jwtBuilder);
    assertThat(jwt).isNotNull();
  }

  @SneakyThrows
  @Test
  void createFromPrivateKeyRsa() {
    final PrivateKey privateKey =
        KeyUtility.readX509PrivateKeyPlain(
            ResourceReader.getFileFromResourceAsTmpFile(
                "keys/1_C.SGD-HSM.AUT_oid_sgd1_hsm_rsa-privKey.pem"));
    assertThat(privateKey).isNotNull();
    final IdpJwtProcessor idpJwtProc = new IdpJwtProcessor(privateKey, "my_rsa_key");
    final JsonWebToken jwt = idpJwtProc.buildJwt(jwtBuilder);
    assertThat(jwt).isNotNull();
  }

  private JsonWebToken createJwt(final PkiIdentity identity) {
    jwtProcessor = new IdpJwtProcessor(identity);
    return jwtProcessor.buildJwt(jwtBuilder);
  }
}
