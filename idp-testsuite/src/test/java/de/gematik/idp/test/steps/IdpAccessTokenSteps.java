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

package de.gematik.idp.test.steps;

import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.crypto.Nonce;
import de.gematik.idp.test.steps.helpers.CucumberValuesConverter;
import de.gematik.idp.test.steps.helpers.IdpTestEnvironmentConfigurator;
import de.gematik.idp.test.steps.model.CodeAuthType;
import de.gematik.idp.test.steps.model.DiscoveryDocument;
import de.gematik.idp.test.steps.model.HttpMethods;
import de.gematik.idp.test.steps.model.HttpStatus;
import de.gematik.rbellogger.key.RbelKey;
import de.gematik.test.bdd.Context;
import de.gematik.test.bdd.ContextKey;
import de.gematik.test.tiger.lib.TigerDirector;
import io.cucumber.datatable.DataTable;
import io.restassured.response.Response;
import java.security.PublicKey;
import java.security.Security;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jose4j.jwt.JwtClaims;
import org.json.JSONObject;

@Slf4j
public class IdpAccessTokenSteps extends IdpStepsBase {

  private final CucumberValuesConverter cucumberValuesConverter = new CucumberValuesConverter();

  @SneakyThrows
  public void getToken(final HttpStatus result, final DataTable paramsTable) {
    final Map<String, Object> ctxt = de.gematik.test.bdd.Context.get().getMapForCurrentThread();
    assertThat(ctxt)
        .containsKey(ContextKey.CODE_VERIFIER)
        .doesNotContainEntry(ContextKey.CODE_VERIFIER, null)
        .containsKey(ContextKey.CLIENT_ID)
        .doesNotContainEntry(ContextKey.CLIENT_ID, null)
        .containsKey(ContextKey.TOKEN_CODE_ENCRYPTED)
        .doesNotContainEntry(ContextKey.TOKEN_CODE_ENCRYPTED, null);

    final Map<String, String> params = new HashMap<>();
    if (paramsTable != null) {
      params.putAll(cucumberValuesConverter.getMapFromDatatable(paramsTable));
      if (params.containsKey("redirect_uri")) {
        ctxt.put(ContextKey.REDIRECT_URI, params.get("redirect_uri"));
      }
      Security.addProvider(new BouncyCastleProvider());
      if (params.containsKey("token_code")) {
        final String token_code = params.get("token_code");
        ctxt.put(ContextKey.TOKEN_CODE, token_code);
        if (token_code != null) {
          ctxt.put(
              ContextKey.TOKEN_CODE_ENCRYPTED,
              keyAndCertificateStepsHelper.encrypt(
                  "{\"njwt\":\"" + params.get("token_code") + "\"}",
                  IdpTestEnvironmentConfigurator.getSymmetricEncryptionKey(
                      CodeAuthType.SIGNED_CHALLENGE)));
        } else {
          ctxt.put(ContextKey.TOKEN_CODE_ENCRYPTED, null);
        }
        params.put("token_code", (String) ctxt.get(ContextKey.TOKEN_CODE_ENCRYPTED));
      }
      if (params.containsKey("token_code_encrypted")) {
        final String token = params.remove("token_code_encrypted");
        ctxt.put(ContextKey.TOKEN_CODE_ENCRYPTED, token);
        params.put("token_code", token);
      }
      if (params.containsKey("code_verifier")) {
        ctxt.put(ContextKey.CODE_VERIFIER, params.get("code_verifier"));
      }
      if (params.containsKey("client_id")) {
        ctxt.put(ContextKey.CLIENT_ID, params.get("client_id"));
      }
    } else {
      params.put("grant_type", "authorization_code");
      params.put("redirect_uri", (String) ctxt.get(ContextKey.REDIRECT_URI));
      params.put("token_code", (String) ctxt.get(ContextKey.TOKEN_CODE_ENCRYPTED));
      params.put("code_verifier", (String) ctxt.get(ContextKey.CODE_VERIFIER));
      params.put("client_id", (String) ctxt.get(ContextKey.CLIENT_ID));
    }

    // map token_code to request param code
    params.put("code", params.remove("token_code"));

    // create/encrypt key_verifier
    final byte[] tokenKeyBytes = Nonce.randomBytes(256 / 8);
    final SecretKey tokenKey = new SecretKeySpec(tokenKeyBytes, "AES");
    if (IdpTestEnvironmentConfigurator.isRbelLoggerActive()) {
      TigerDirector.getTigerTestEnvMgr()
          .getLocalTigerProxy()
          .getRbelLogger()
          .getRbelKeyManager()
          .addKey("token_key", tokenKey, RbelKey.PRECEDENCE_KEY_FOLDER);
    }
    log.info(
        "Using dynamic token key "
            + Base64.getUrlEncoder().withoutPadding().encodeToString(tokenKey.getEncoded()));
    Context.getDiscoveryDocument();
    final PublicKey pukToken = DiscoveryDocument.getPublicKeyFromContextKey(ContextKey.PUK_ENC);
    params.put(
        "key_verifier",
        buildKeyVerifierToken(tokenKeyBytes, params.get("code_verifier"), pukToken));
    final Response r =
        requestResponseAndAssertStatus(
            Context.getDiscoveryDocument().getTokenEndpoint(),
            null,
            HttpMethods.POST,
            params,
            null,
            result);
    ctxt.put(ContextKey.RESPONSE, r);

    if (r.getStatusCode() == 200) {
      final JSONObject json = new JSONObject(r.getBody().asString());
      ctxt.put(ContextKey.ACCESS_TOKEN_ENCRYPTED, json.getString("access_token"));
      // decrypt access and id token
      ctxt.put(
          ContextKey.ACCESS_TOKEN,
          keyAndCertificateStepsHelper.decryptAndExtractNjwt(
              json.getString("access_token"), tokenKey));
      ctxt.put(ContextKey.ID_TOKEN_ENCRYPTED, json.getString("id_token"));
      ctxt.put(
          ContextKey.ID_TOKEN,
          keyAndCertificateStepsHelper.decryptAndExtractNjwt(json.getString("id_token"), tokenKey));
    } else {
      ctxt.put(ContextKey.ACCESS_TOKEN_ENCRYPTED, null);
      ctxt.put(ContextKey.ACCESS_TOKEN, null);
      ctxt.put(ContextKey.ID_TOKEN_ENCRYPTED, null);
      ctxt.put(ContextKey.ID_TOKEN, null);
    }
  }

  @SneakyThrows
  private String buildKeyVerifierToken(
      final byte[] tokenKeyBytes, final String codeVerifier, final PublicKey pukToken) {
    final JwtClaims claims = new JwtClaims();
    claims.setStringClaim(
        "token_key", new String(Base64.getUrlEncoder().withoutPadding().encode(tokenKeyBytes)));
    claims.setStringClaim("code_verifier", codeVerifier);
    return keyAndCertificateStepsHelper.encrypt(claims.toJson(), pukToken);
  }
}
