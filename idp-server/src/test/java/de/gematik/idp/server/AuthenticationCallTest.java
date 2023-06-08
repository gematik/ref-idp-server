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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

import de.gematik.idp.TestConstants;
import de.gematik.idp.authentication.AuthenticationChallengeBuilder;
import de.gematik.idp.authentication.UriUtils;
import de.gematik.idp.client.IdpClient;
import de.gematik.idp.client.IdpTokenResult;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.server.controllers.IdpController;
import de.gematik.idp.server.controllers.IdpKey;
import de.gematik.idp.tests.PkiKeyResolver;
import de.gematik.idp.token.IdpJwe;
import kong.unirest.MultipartBody;
import kong.unirest.UnirestException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(SpringExtension.class)
@ExtendWith(PkiKeyResolver.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AuthenticationCallTest {

  private IdpClient idpClient;
  private PkiIdentity egkUserIdentity;

  @LocalServerPort private int localServerPort;
  @Autowired private AuthenticationChallengeBuilder authenticationChallengeBuilder;
  @Autowired private IdpController idpController;
  @Autowired private IdpKey idpEnc;
  private AuthenticationChallengeBuilder authenticationChallengeBuilderSpy;

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

    authenticationChallengeBuilderSpy = spy(authenticationChallengeBuilder);
    ReflectionTestUtils.setField(
        idpController, "authenticationChallengeBuilder", authenticationChallengeBuilderSpy);
  }

  @Test
  void verifyTokenAlgorithm() throws UnirestException {
    idpClient.login(egkUserIdentity);
    verify(authenticationChallengeBuilderSpy)
        .buildAuthenticationChallenge(
            eq(TestConstants.CLIENT_ID_E_REZEPT_APP),
            anyString(),
            eq(TestConstants.REDIRECT_URI_E_REZEPT_APP),
            anyString(),
            anyString(),
            anyString());
  }

  @Test
  void verifyResponseStatusCode() {
    idpClient.setBeforeAuthenticationCallback(
        request -> assertThat(request.asJson().getStatus()).isEqualTo(HttpStatus.FOUND.value()));
    idpClient.login(egkUserIdentity);
  }

  @Test
  void verifyResponseAttribute_code() {
    idpClient.setAfterAuthenticationCallback(
        response ->
            assertThat(
                    UriUtils.extractParameterValue(
                        response.getHeaders().get("Location").get(0), "code"))
                .isNotEmpty());
    idpClient.login(egkUserIdentity);
  }

  @Test
  void verifyResponseAttribute_sso_token() {
    idpClient.setAfterAuthenticationCallback(
        response ->
            assertThat(
                    UriUtils.extractParameterValue(
                        response.getHeaders().get("Location").get(0), "ssotoken"))
                .isNotEmpty());
    idpClient.login(egkUserIdentity);
  }

  @Test
  void verifyResponseAttribute_sso_token_forPsNotExists() {
    idpClient =
        IdpClient.builder()
            .clientId(TestConstants.CLIENT_ID_GEAMTIK_TEST_PS)
            .discoveryDocumentUrl("http://localhost:" + localServerPort + "/discoveryDocument")
            .redirectUrl(TestConstants.REDIRECT_URI_GEAMTIK_TEST_PS)
            .build();
    idpClient.initialize();

    idpClient.setAfterAuthenticationCallback(
        response ->
            assertThat(
                    UriUtils.extractParameterValueOptional(
                        response.getHeaders().get("Location").get(0), "ssotoken"))
                .isEmpty());

    final IdpTokenResult tokenResult = idpClient.login(egkUserIdentity);
    assertThat(tokenResult.getSsoToken()).isNull();
  }

  @Test
  void verifyAttribute_content_type() {
    idpClient.setBeforeAuthenticationCallback(
        request -> assertThat(request.getHeaders().containsKey("Content-Type")).isTrue());
    idpClient.login(egkUserIdentity);
  }

  @Test
  void verifyAttribute_signed_challenge() {
    idpClient.setBeforeAuthenticationCallback(
        request ->
            assertThat(request.getBody().get().multiParts().stream().findFirst().get().getName())
                .isEqualTo("signed_challenge"));
    idpClient.login(egkUserIdentity);
  }

  @Test
  void verifySignedChallengeBodyAttribute_njwt() {
    idpClient.setBeforeAuthenticationCallback(
        request ->
            assertThat(
                    new IdpJwe(getTokenOfRequest(request))
                        .decryptNestedJwt(idpEnc.getIdentity().getPrivateKey())
                        .getBodyClaims())
                .containsKey("njwt"));
    idpClient.login(egkUserIdentity);
  }

  private String getTokenOfRequest(final MultipartBody request) {
    return (String) request.getBody().get().multiParts().stream().findFirst().get().getValue();
  }
}
