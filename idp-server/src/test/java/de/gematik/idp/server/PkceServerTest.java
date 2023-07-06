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

import static de.gematik.idp.client.AuthenticatorClient.getAllFieldElementsAsMap;
import static de.gematik.idp.client.AuthenticatorClient.getAllHeaderElementsAsMap;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;

import de.gematik.idp.TestConstants;
import de.gematik.idp.client.IdpClient;
import de.gematik.idp.client.IdpClientRuntimeException;
import de.gematik.idp.client.IdpTokenResult;
import de.gematik.idp.client.data.AuthenticationResponse;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.field.CodeChallengeMethod;
import de.gematik.idp.server.configuration.IdpConfiguration;
import de.gematik.idp.server.controllers.IdpKey;
import de.gematik.idp.server.exceptions.IdpServerException;
import de.gematik.idp.server.services.PkceChecker;
import de.gematik.idp.tests.PkiKeyResolver;
import de.gematik.idp.tests.Remark;
import de.gematik.idp.tests.Rfc;
import de.gematik.idp.token.IdpJwe;
import java.security.Key;
import java.util.Map;
import kong.unirest.Unirest;
import kong.unirest.UnirestException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
@ExtendWith(PkiKeyResolver.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class PkceServerTest {

  private final PkceChecker pkceChecker = new PkceChecker();
  @Autowired private IdpConfiguration idpConfiguration;
  @Autowired private Key symmetricEncryptionKey;
  @Autowired private IdpKey idpSig;
  private IdpClient idpClient;
  private PkiIdentity egkUserIdentity;
  @LocalServerPort private int localServerPort;

  @BeforeEach
  public void startup(
      @PkiKeyResolver.Filename("109500969_X114428530_c.ch.aut-ecc") final PkiIdentity egkIdentity) {
    idpClient =
        IdpClient.builder()
            .clientId(TestConstants.CLIENT_ID_E_REZEPT_APP)
            .discoveryDocumentUrl("http://localhost:" + localServerPort + "/discoveryDocument")
            .redirectUrl(TestConstants.REDIRECT_URI_E_REZEPT_APP)
            .build();

    idpClient.initialize();

    egkUserIdentity =
        PkiIdentity.builder()
            .certificate(egkIdentity.getCertificate())
            .privateKey(egkIdentity.getPrivateKey())
            .build();
  }

  @Test
  void testPkcePositiv() throws UnirestException {
    idpClient.setBeforeAuthorizationCallback(
        request ->
            assertThat(request.getUrl())
                .contains("code_challenge=")
                .contains("code_challenge_method=S256"));

    final IdpTokenResult tokenResponse = idpClient.login(egkUserIdentity);
  }

  @Test
  @Remark("Client sendet code_challenge_method=plain statt S256, Server muss Error senden")
  @Rfc("rfc7636, section 4.4.1")
  void pkceNegativPlainInAuthorization() throws UnirestException {
    idpClient.setCodeChallengeMethod(CodeChallengeMethod.PLAIN);

    idpClient.setAfterAuthorizationCallback(r -> assertThat(r.getStatus()).isEqualTo(302));

    assertThatThrownBy(() -> idpClient.login(egkUserIdentity))
        .isInstanceOf(IdpClientRuntimeException.class)
        .hasMessageContaining("2008")
        .hasMessageContaining("code_challenge_method ist ungültig");
  }

  @Test
  @Remark("Client sendet kein code_challenge, Server muss Error senden")
  @Rfc("rfc7636, section 4.4.1")
  void pkceNegativNoCodeChallengeInAuthorization() throws UnirestException {
    idpClient.setBeforeAuthorizationMapper(
        request ->
            Unirest.get(
                    request
                        .getUrl()
                        .replaceFirst("&code_challenge=[\\w-_.~]*&code_challenge_method=S256", ""))
                .headers(getAllHeaderElementsAsMap(request)));

    idpClient.setAfterAuthorizationCallback(r -> assertThat(r.getStatus()).isEqualTo(302));

    assertThatThrownBy(() -> idpClient.login(egkUserIdentity))
        .isInstanceOf(IdpClientRuntimeException.class)
        .hasMessageContaining("2009")
        .hasMessageContaining("code_challenge wurde nicht übermittelt");
  }

  @Test
  @Remark("Client sendet falschen code_verifier, Server muss Error senden")
  @Rfc("rfc7636, section 4.4.1")
  void pkceNegativInvalidCodeVerifier() throws UnirestException {
    idpClient.setAuthenticationResponseMapper(
        authenticationResponse ->
            AuthenticationResponse.builder()
                .ssoToken(authenticationResponse.getSsoToken())
                .location(authenticationResponse.getLocation())
                .code(
                    new IdpJwe(authenticationResponse.getCode())
                        .decryptNestedJwt(symmetricEncryptionKey)
                        .toJwtDescription()
                        .addBodyClaim(ClaimName.CODE_CHALLENGE, "wrongCodeChallengeValue")
                        .setSignerKey(idpSig.getIdentity().getPrivateKey())
                        .buildJwt()
                        .encryptAsNjwt(symmetricEncryptionKey)
                        .getRawString())
                .build());

    idpClient.setAfterTokenCallback(r -> assertThat(r.getStatus()).isEqualTo(400));

    assertThatThrownBy(() -> idpClient.login(egkUserIdentity))
        .isInstanceOf(IdpClientRuntimeException.class)
        .hasMessageContaining("3000")
        .hasMessageContaining("code_verifier stimmt nicht mit code_challenge überein");
  }

  @Test
  @Remark("Client sendet keinen code_verifier, Server muss Error senden")
  @Rfc("rfc7636, section 4.4.1")
  void pkceNegativMissingCodeVerifier() throws UnirestException {
    idpClient.setBeforeTokenMapper(
        request -> {
          final Map<String, Object> newFields = getAllFieldElementsAsMap(request);
          newFields.remove("key_verifier");
          return Unirest.post(request.getUrl())
              .headers(getAllHeaderElementsAsMap(request))
              .fields(newFields);
        });

    idpClient.setAfterTokenCallback(r -> assertThat(r.getStatus()).isEqualTo(400));

    assertThatThrownBy(() -> idpClient.login(egkUserIdentity))
        .isInstanceOf(IdpClientRuntimeException.class);
  }

  @Test
  @Rfc("rfc7636 Appendix B")
  @Remark("This example is in rfc7636 Appendix B")
  void checkVerifyCodeVerifier() {
    final String validCodeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    final String validCodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    pkceChecker.checkCodeVerifier(validCodeVerifier, validCodeChallenge);
  }

  @Test
  @Rfc("rfc7636 Appendix B")
  @Remark("code verifier and code challenge dont match")
  void codeVerifierInvalid() {
    final String invalidCodeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" + "_";
    final String validCodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    assertThatThrownBy(
            () -> pkceChecker.checkCodeVerifier(invalidCodeVerifier + "_", validCodeChallenge))
        .isInstanceOf(IdpServerException.class);
  }

  @Test
  @Rfc("rfc7636 Appendix B")
  @Remark("code verifier is too short")
  void codeVerifierTooShort() {
    final String shortCodeVerifier = "too_short_too_short_too_short_too_short_to";
    final String shortCodeChallenge = "9VHAvw0tiyfbpsis_ClQrXjEm0gJgivDIacuuj5kjOY";
    assertThatThrownBy(() -> pkceChecker.checkCodeVerifier(shortCodeVerifier, shortCodeChallenge))
        .isInstanceOf(IdpServerException.class);
  }

  @Test
  @Rfc("rfc7636 Appendix B")
  @Remark("code verifier is too long")
  void codeVerifierTooLong() {
    final String longCodeVerifier =
        "too_long_too_long_too_long_too_long_too_long_too_long_too_long_too_long_too_long_too_long_too_long_too_long_too_long_too_long_too";
    final String longCodeChallenge = "CkXOaKyJw8vCDOWgnvqgQDSVbll0xJRaq_DzY8f5Zr0";
    assertThatThrownBy(() -> pkceChecker.checkCodeVerifier(longCodeVerifier, longCodeChallenge))
        .isInstanceOf(IdpServerException.class);
  }

  @Test
  @Rfc("rfc7636 Appendix B")
  @Remark("code verifier is empty")
  void emptyCodeVerifier() {
    final String validCodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    assertThatThrownBy(() -> pkceChecker.checkCodeVerifier("", validCodeChallenge))
        .isInstanceOf(IdpServerException.class);
  }
}
