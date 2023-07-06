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

import static de.gematik.idp.TestConstants.REDIRECT_URI_E_REZEPT_APP;
import static de.gematik.idp.error.IdpErrorType.INVALID_CLIENT;
import static de.gematik.idp.error.IdpErrorType.INVALID_GRANT;
import static de.gematik.idp.error.IdpErrorType.INVALID_REQUEST;
import static de.gematik.idp.error.IdpErrorType.INVALID_SCOPE;
import static de.gematik.idp.error.IdpErrorType.UNSUPPORTED_GRANT_TYPE;
import static de.gematik.idp.error.IdpErrorType.UNSUPPORTED_RESPONSE_TYPE;
import static de.gematik.idp.field.ClaimName.CODE_VERIFIER;
import static de.gematik.idp.field.ClaimName.KEY_ID;
import static de.gematik.idp.field.ClaimName.TOKEN_KEY;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.TestConstants;
import de.gematik.idp.authentication.JwtBuilder;
import de.gematik.idp.authentication.UriUtils;
import de.gematik.idp.client.IdpClient;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.error.IdpErrorType;
import de.gematik.idp.server.controllers.IdpKey;
import de.gematik.idp.tests.PkiKeyResolver;
import de.gematik.idp.tests.PkiKeyResolver.Filename;
import de.gematik.idp.token.IdpJwe;
import java.security.Key;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.UnaryOperator;
import kong.unirest.GetRequest;
import kong.unirest.HttpRequest;
import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.MultipartBody;
import kong.unirest.Unirest;
import lombok.SneakyThrows;
import org.apache.commons.lang3.tuple.Pair;
import org.assertj.core.api.AssertionsForClassTypes;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
@ExtendWith(PkiKeyResolver.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class IdpControllerParameterValidationTest {

  private static final List<Pair<String, String>> getChallengeParameterMap =
      List.of(
          Pair.of("client_id", TestConstants.CLIENT_ID_E_REZEPT_APP),
          Pair.of("state", "state"),
          Pair.of("redirect_uri", REDIRECT_URI_E_REZEPT_APP),
          Pair.of("code_challenge", "l1yM_9krH3fPE2aOkRXzHQDU0lKn0mI0-Gp165Pgb1Y"),
          Pair.of("code_challenge_method", "S256"),
          Pair.of("response_type", "code"),
          Pair.of("nonce", "foobarschmar"),
          Pair.of("scope", "openid e-rezept"));

  private static final List<Pair<String, String>> getThirdPartyAuthorizationParameterMap =
      List.of(
          Pair.of("client_id", TestConstants.CLIENT_ID_E_REZEPT_APP),
          Pair.of("state", "state_erp"),
          Pair.of("redirect_uri", REDIRECT_URI_E_REZEPT_APP),
          Pair.of("code_challenge", "m1yM_9krH3fPE2aOkRXzHQDU0lKn0mI0-Gp165Pgb1Z"),
          Pair.of("code_challenge_method", "S256"),
          Pair.of("response_type", "code"),
          Pair.of("nonce", "anyfoobar"),
          Pair.of("scope", "e-rezept openid"),
          Pair.of("kk_app_id", "kkAppId001"));

  @LocalServerPort private int port;
  @Autowired private Key symmetricEncryptionKey;
  @Autowired private IdpKey idpSig;
  @Autowired private IdpKey idpEnc;
  private IdpClient idpClient;
  private PkiIdentity pkiIdentity;

  @BeforeEach
  public void setup(@Filename("109500969_X114428530_c.ch.aut-ecc") final PkiIdentity egkIdentity) {
    idpClient =
        IdpClient.builder()
            .clientId(TestConstants.CLIENT_ID_E_REZEPT_APP)
            .discoveryDocumentUrl("http://localhost:" + port + "/discoveryDocument")
            .redirectUrl(REDIRECT_URI_E_REZEPT_APP)
            .build();

    idpClient.initialize();

    pkiIdentity = egkIdentity;
  }

  @Test
  void getAuthenticationChallenge_invalidClientId_shouldGiveError() {
    assertErrorResponseMatches(
        buildGetChallengeRequest(getInvalidationFunction("client_id", "invalid_client_id")),
        2012,
        INVALID_REQUEST,
        "client_id ist ungültig");
  }

  @Test
  void getAuthenticationChallenge_missingResponseType_shouldGiveError() {
    assertForwardErrorResponseMatches(
        buildGetChallengeRequest(getInvalidationFunction("response_type", null)),
        2004,
        INVALID_REQUEST,
        "response_type wurde nicht übermittelt");
  }

  @Test
  void getAuthenticationChallenge_invalidResponseType_shouldGiveError() {
    assertForwardErrorResponseMatches(
        buildGetChallengeRequest(getInvalidationFunction("response_type", "something_else")),
        2005,
        UNSUPPORTED_RESPONSE_TYPE,
        "response_type wird nicht unterstützt");
  }

  @Test
  void getAuthenticationChallenge_invalidScope_shouldGiveError() {
    assertForwardErrorResponseMatches(
        buildGetChallengeRequest(getInvalidationFunction("scope", "invalidScope")),
        1022,
        INVALID_SCOPE,
        "scope ist ungültig");
  }

  @Test
  void getAuthenticationChallenge_validPlusInvalidScope_shouldGiveError() {
    assertForwardErrorResponseMatches(
        buildGetChallengeRequest(getInvalidationFunction("scope", "openid e-rezept x")),
        1030,
        INVALID_SCOPE,
        "Fachdienst ist unbekannt");
  }

  @Test
  void getAuthenticationChallenge_onlyOpenidScope_shouldGiveError() {
    assertForwardErrorResponseMatches(
        buildGetChallengeRequest(getInvalidationFunction("scope", "openid")),
        1022,
        INVALID_SCOPE,
        "scope ist ungültig");
  }

  @Test
  void getAuthenticationChallenge_onlyOpenidScope_should200() {
    assertThat(
            buildGetChallengeRequest(getInvalidationFunction("scope", "e-rezept openid"))
                .asString()
                .getStatus())
        .isEqualTo(200);
  }

  @Test
  void getAuthenticationChallenge_missingRedirectUri_shouldGiveError() {
    assertErrorResponseMatches(
        buildGetChallengeRequest(getInvalidationFunction("redirect_uri", null)),
        1004,
        INVALID_REQUEST,
        "redirect_uri wurde nicht übermittelt");
  }

  @Test
  void getAuthenticationChallenge_missingState_shouldGiveError() {
    assertForwardErrorResponseMatches(
        buildGetChallengeRequest(getInvalidationFunction("state", null)),
        2002,
        INVALID_REQUEST,
        "state wurde nicht übermittelt");
  }

  @Test
  void getAuthenticationChallenge_emptyState_shouldGiveError() {
    assertForwardErrorResponseMatches(
        buildGetChallengeRequest(getInvalidationFunction("state", "")),
        2002,
        INVALID_REQUEST,
        "state wurde nicht übermittelt");
  }

  @Test
  void getAuthenticationChallenge_emptyNonce_shouldGiveError() {
    assertForwardErrorResponseMatches(
        buildGetChallengeRequest(getInvalidationFunction("nonce", "")),
        2007,
        INVALID_REQUEST,
        "nonce ist ungültig");
  }

  @Test
  void getAccessToken_missingCode_shouldGiveError() {
    assertErrorResponseMatches(
        buildGetAccessTokenRequest(getInvalidationFunction("code", null)),
        3005,
        INVALID_REQUEST,
        "Authorization Code wurde nicht übermittelt");
  }

  @Test
  void getAccessToken_missingCodeVerifier_shouldGiveError() {
    assertErrorResponseMatches(
        buildGetAccessTokenRequest(getInvalidationFunction("key_verifier", null)),
        3004,
        INVALID_REQUEST,
        "key_verifier wurde nicht übermittelt");
  }

  @Test
  void getAccessToken_missingGrantType_shouldGiveError() {
    assertErrorResponseMatches(
        buildGetAccessTokenRequest(getInvalidationFunction("grant_type", null)),
        3006,
        INVALID_REQUEST,
        "grant_type wurde nicht übermittelt");
  }

  @Test
  void getAccessToken_emptyGrantType_shouldGiveError() {
    assertErrorResponseMatches(
        buildGetAccessTokenRequest(getInvalidationFunction("grant_type", "")),
        3006,
        INVALID_REQUEST,
        "grant_type wurde nicht übermittelt");
  }

  @Test
  void getAccessToken_invalidGrantType_shouldGiveError() {
    assertErrorResponseMatches(
        buildGetAccessTokenRequest(getInvalidationFunction("grant_type", "falscher_wert")),
        3014,
        UNSUPPORTED_GRANT_TYPE,
        "grant_type wird nicht unterstützt");
  }

  @Test
  void getAccessToken_wrongClientId_shouldGiveError() {
    assertErrorResponseMatches(
        buildGetAccessTokenRequest(getInvalidationFunction("client_id", "falscher_wert")),
        3007,
        INVALID_CLIENT,
        "client_id ist ungültig");
  }

  @Test
  void getAccessToken_codeVerifierWrong_shouldGiveError() {
    assertErrorResponseMatches(
        buildGetAccessTokenRequest(getInvalidationFunction("client_id", "falscher_wert")),
        3007,
        INVALID_CLIENT,
        "client_id ist ungültig");
  }

  @Test
  void getAccessToken_missingRedirectUri_shouldGiveError() {
    assertErrorResponseMatches(
        buildGetAccessTokenRequest(getInvalidationFunction("redirect_uri", null)),
        1004,
        INVALID_REQUEST,
        "redirect_uri wurde nicht übermittelt");
  }

  @Test
  void getAccessToken_missingClientId_shouldGiveError() {
    assertErrorResponseMatches(
        buildGetAccessTokenRequest(getInvalidationFunction("client_id", null)),
        1002,
        INVALID_REQUEST,
        "client_id wurde nicht übermittelt");
  }

  @Test
  void getAccessToken_wrongCodeVerifier_shouldGiveError() {
    final JwtClaims claims = new JwtClaims();
    claims.setStringClaim(TOKEN_KEY.getJoseName(), "Z0t6Y3AwVE1RN2xuTUVFcXpweDVGV0FzdTFucWt5aHI=");
    claims.setStringClaim(
        CODE_VERIFIER.getJoseName(),
        "WrongCodeVerifierWrongCodeVerifierWrongCodeVerifierWrongCodeVerifier");

    final String keyVerifierPayload =
        IdpJwe.createWithPayloadAndEncryptWithKey(
                claims.toJson(), idpEnc.getIdentity().getCertificate().getPublicKey(), "JSON")
            .getRawString();
    assertErrorResponseMatches(
        buildGetAccessTokenRequest(getInvalidationFunction("key_verifier", keyVerifierPayload)),
        3000,
        INVALID_GRANT,
        "code_verifier stimmt nicht mit code_challenge überein");
  }

  @Test
  void getAccessToken_missingClaimsInAuthCode_shouldGiveError() {
    final String alteredAuthToken =
        new JwtBuilder()
            .addBodyClaim(KEY_ID, "bar")
            .setSignerKey(idpSig.getIdentity().getPrivateKey())
            .buildJwt()
            .encryptAsNjwt(symmetricEncryptionKey)
            .getRawString();
    assertErrorResponseMatches(
        buildGetAccessTokenRequest(getInvalidationFunction("code", alteredAuthToken)),
        3001,
        INVALID_GRANT,
        "Claims unvollständig im Authorization Code");
  }

  @Test
  void getAccessToken_differentRedirectUri_shouldGiveError() {
    assertErrorResponseMatches(
        buildGetAccessTokenRequest(getInvalidationFunction("redirect_uri", "foobar")),
        1020,
        INVALID_REQUEST,
        "redirect_uri ist ungültig");
  }

  @Test
  void getAccessToken_missingClaimsInKeyVerifier1_shouldGiveError() {
    final JwtClaims claims = new JwtClaims();
    claims.setStringClaim(TOKEN_KEY.getJoseName(), "Z0t6Y3AwVE1RN2xuTUVFcXpweDVGV0FzdTFucWt5aHI=");

    final String keyVerifierPayload =
        IdpJwe.createWithPayloadAndEncryptWithKey(
                claims.toJson(), idpEnc.getIdentity().getCertificate().getPublicKey(), "JSON")
            .getRawString();
    assertErrorResponseMatches(
        buildGetAccessTokenRequest(getInvalidationFunction("key_verifier", keyVerifierPayload)),
        3004,
        INVALID_REQUEST,
        "key_verifier wurde nicht übermittelt");
  }

  @Test
  void getThirdPartyAuthorizationRequest_should302() {
    assertThat(
            buildGetThirdPartyAuthorizationRequest(
                    getInvalidationFunction("scope", "e-rezept openid"))
                .asString()
                .getStatus())
        .isEqualTo(302);
  }

  @Test
  void getThirdPartyAuthorizationRequest_should400() {
    assertThat(
            buildGetThirdPartyAuthorizationRequest(getInvalidationFunction("client_id", null))
                .asString()
                .getStatus())
        .isEqualTo(400);
  }

  @SneakyThrows
  private void assertErrorResponseMatches(
      final HttpRequest getRequest,
      final int errorCode,
      final IdpErrorType errorType,
      final String errorText) {
    final HttpResponse<JsonNode> response = getRequest.asJson();

    assertThat(response.getStatus()).isEqualTo(400);

    assertThat(response.getBody().getObject().get("error"))
        .isEqualTo(errorType.getSerializationValue());
    assertThat(response.getBody().getObject().get("gematik_code"))
        .isEqualTo(String.valueOf(errorCode));
    assertThat(response.getBody().getObject().get("gematik_error_text")).isEqualTo(errorText);
  }

  @SneakyThrows
  private void assertForwardErrorResponseMatches(
      final HttpRequest getRequest,
      final int errorCode,
      final IdpErrorType errorType,
      final String errorText) {
    final HttpResponse<String> response = getRequest.asJson();

    assertThat(response.getStatus()).isEqualTo(302);

    final Map<String, String> locationUrlParameterMap =
        UriUtils.extractParameterMap(response.getHeaders().getFirst("Location"));

    assertThat(locationUrlParameterMap).containsEntry("error", errorType.getSerializationValue());
    assertThat(locationUrlParameterMap).containsEntry("gematik_code", Integer.toString(errorCode));
    assertThat(locationUrlParameterMap).containsEntry("gematik_error_text", errorText);
  }

  private GetRequest buildGetChallengeRequest(
      final UnaryOperator<Entry<String, String>> entryStringFunction) {
    final GetRequest getRequest =
        Unirest.get("http://localhost:" + port + IdpConstants.BASIC_AUTHORIZATION_ENDPOINT);

    getChallengeParameterMap.stream()
        .map(entryStringFunction)
        .filter(Objects::nonNull)
        .forEach(entry -> getRequest.queryString(entry.getKey(), entry.getValue()));

    return getRequest;
  }

  /** Sonar satisfaction */
  @Test
  void testSekIdpLocationNotFound() {
    final HttpResponse<String> response =
        Unirest.post("http://localhost:" + port + IdpConstants.THIRD_PARTY_ENDPOINT)
            .header(
                org.springframework.http.HttpHeaders.CONTENT_TYPE,
                MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .field("state", "unknownState")
            .field("code", "todoCode")
            .field("kk_app_redirect_uri", "todoUri")
            .asString();
    AssertionsForClassTypes.assertThat(response.getStatus())
        .isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR.value());
  }

  private GetRequest buildGetThirdPartyAuthorizationRequest(
      final UnaryOperator<Entry<String, String>> entryStringFunction) {
    final GetRequest getRequest =
        Unirest.get("http://localhost:" + port + IdpConstants.THIRD_PARTY_ENDPOINT);

    getThirdPartyAuthorizationParameterMap.stream()
        .map(entryStringFunction)
        .filter(Objects::nonNull)
        .forEach(entry -> getRequest.queryString(entry.getKey(), entry.getValue()));

    return getRequest;
  }

  private MultipartBody buildGetAccessTokenRequest(
      final UnaryOperator<Entry<String, String>> entryStringFunction) {
    final AtomicReference<MultipartBody> resultPtr = new AtomicReference<>();
    idpClient.setBeforeTokenMapper(
        request -> {
          final MultipartBody post = Unirest.post(request.getUrl()).fields(Collections.emptyMap());
          request.multiParts().stream()
              .map(part -> Pair.of(part.getName(), part.getValue().toString()))
              .map(entryStringFunction)
              .filter(Objects::nonNull)
              .forEach(entry -> post.queryString(entry.getKey(), entry.getValue()));
          resultPtr.set(post);
          return request;
        });
    idpClient.login(pkiIdentity);

    return resultPtr.get();
  }

  private UnaryOperator<Entry<String, String>> getInvalidationFunction(
      final String parameterName, final String newParameterValue) {
    return entry -> {
      if (entry.getKey().equals(parameterName)) {
        if (newParameterValue == null) {
          return null;
        } else {
          return Pair.of(parameterName, newParameterValue);
        }
      } else {
        return entry;
      }
    };
  }
}
