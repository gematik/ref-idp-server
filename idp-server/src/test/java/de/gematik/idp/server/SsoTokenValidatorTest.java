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

package de.gematik.idp.server;

import static de.gematik.idp.field.ClaimName.ALGORITHM;
import static de.gematik.idp.field.ClaimName.ISSUED_AT;
import static de.gematik.idp.field.ClaimName.TYPE;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.authentication.JwtBuilder;
import de.gematik.idp.brainPoolExtension.BrainpoolAlgorithmSuiteIdentifiers;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.exceptions.IdpJoseException;
import de.gematik.idp.server.configuration.IdpConfiguration;
import de.gematik.idp.server.controllers.IdpKey;
import de.gematik.idp.server.exceptions.IdpServerException;
import de.gematik.idp.server.services.SsoTokenValidator;
import de.gematik.idp.tests.PkiKeyResolver;
import de.gematik.idp.token.IdpJwe;
import de.gematik.idp.token.SsoTokenBuilder;
import java.security.Security;
import java.time.ZonedDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(PkiKeyResolver.class)
class SsoTokenValidatorTest {

  static {
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    Security.insertProviderAt(new BouncyCastleProvider(), 1);
  }

  private final ServerUrlService urlService = new ServerUrlService(new IdpConfiguration());
  private SsoTokenValidator ssoTokenValidator;
  private PkiIdentity rsaUserIdentity;
  private PkiIdentity egkUserIdentity;
  private IdpJwtProcessor serverTokenProzessor;
  private SsoTokenBuilder ssoTokenBuilder;
  private SecretKeySpec tokenEncryptionKey;

  @BeforeEach
  public void init(
      @PkiKeyResolver.Filename("109500969_X114428530_c.ch.aut-ecc") final PkiIdentity egkIdentity,
      @PkiKeyResolver.Filename("rsa") final PkiIdentity rsaIdentity) {
    egkUserIdentity = egkIdentity;
    rsaUserIdentity = rsaIdentity;
    final IdpKey serverKey = new IdpKey(egkUserIdentity);
    serverTokenProzessor = new IdpJwtProcessor(egkUserIdentity);
    tokenEncryptionKey =
        new SecretKeySpec(DigestUtils.sha256("fdsfdsafdsayvcxy".getBytes()), "AES");
    ssoTokenBuilder =
        new SsoTokenBuilder(
            serverTokenProzessor, urlService.determineServerUrl(), tokenEncryptionKey);
    ssoTokenValidator = new SsoTokenValidator(serverKey, tokenEncryptionKey);
  }

  @Test
  void validateValidSsoToken() {
    assertDoesNotThrow(() -> ssoTokenValidator.decryptAndValidateSsoToken(generateValidSsoToken()));
  }

  @Test
  void validateSsoTokenExpired() {
    assertThatThrownBy(
            () -> ssoTokenValidator.decryptAndValidateSsoToken(generateExpiredSsoToken()))
        .isInstanceOf(IdpServerException.class);
  }

  @Test
  void validateSsoTokenInvalidCert() {
    assertThatThrownBy(
            () -> ssoTokenValidator.decryptAndValidateSsoToken(generateInvalidSsoToken()))
        .isInstanceOf(IdpJoseException.class);
  }

  private IdpJwe generateExpiredSsoToken() {
    return serverTokenProzessor
        .buildJwt(
            new JwtBuilder()
                .addAllHeaderClaims(generateHeaderClaims())
                .addAllBodyClaims(generateBodyClaims())
                .expiresAt(ZonedDateTime.now().minusMinutes(1)))
        .encryptAsNjwt(tokenEncryptionKey);
  }

  private IdpJwe generateInvalidSsoToken() {
    final IdpJwtProcessor invalidProcessor = new IdpJwtProcessor(rsaUserIdentity);
    return invalidProcessor
        .buildJwt(
            new JwtBuilder()
                .addAllHeaderClaims(generateHeaderClaims())
                .addAllBodyClaims(generateBodyClaims())
                .expiresAt(ZonedDateTime.now().plusMinutes(5)))
        .encryptAsNjwt(tokenEncryptionKey);
  }

  private Map<String, Object> generateHeaderClaims() {
    final Map<String, Object> headerClaims = new HashMap<>();
    headerClaims.put(
        ALGORITHM.getJoseName(), BrainpoolAlgorithmSuiteIdentifiers.BRAINPOOL256_USING_SHA256);
    headerClaims.put(TYPE.getJoseName(), "JWT");
    return headerClaims;
  }

  private Map<String, Object> generateBodyClaims() {
    final Map<String, Object> bodyClaims = new HashMap<>();
    bodyClaims.put(ISSUED_AT.getJoseName(), ZonedDateTime.now().toEpochSecond());
    return bodyClaims;
  }

  private IdpJwe generateValidSsoToken() {
    return ssoTokenBuilder.buildSsoToken(
        egkUserIdentity.getCertificate(), ZonedDateTime.now(), List.of(""));
  }
}
