/*
 * Copyright (c) 2021 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.idp.test.steps;

import static org.apache.http.HttpHeaders.CONTENT_TYPE;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.test.steps.helpers.CucumberValuesConverter;
import de.gematik.idp.test.steps.helpers.TestEnvironmentConfigurator;
import de.gematik.idp.test.steps.model.*;
import io.cucumber.datatable.DataTable;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import java.security.PublicKey;
import java.security.Security;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import lombok.SneakyThrows;
import org.apache.commons.lang3.RandomStringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jose4j.jwt.JwtClaims;
import org.json.JSONObject;

public class IdpAccessTokenSteps extends IdpStepsBase {

    private final CucumberValuesConverter cucumberValuesConverter = new CucumberValuesConverter();

    @SneakyThrows
    public void getToken(final HttpStatus result, final DataTable paramsTable) {
        final Map<ContextKey, Object> ctxt = Context.getThreadContext();
        assertThat(ctxt)
            .containsKey(ContextKey.TOKEN_CODE)
            .doesNotContainEntry(ContextKey.TOKEN_CODE, null)
            .containsKey(ContextKey.CODE_VERIFIER)
            .doesNotContainEntry(ContextKey.CODE_VERIFIER, null)
            .containsKey(ContextKey.CLIENT_ID)
            .doesNotContainEntry(ContextKey.CLIENT_ID, null);

        if (TestEnvironmentConfigurator.isTokenEncryptionActive()) {
            assertThat(ctxt)
                .containsKey(ContextKey.TOKEN_CODE_ENCRYPTED)
                .doesNotContainEntry(ContextKey.TOKEN_CODE_ENCRYPTED, null);
        }

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
                if (TestEnvironmentConfigurator.isTokenEncryptionActive()) {
                    if (token_code != null) {
                        ctxt.put(ContextKey.TOKEN_CODE_ENCRYPTED,
                            keyAndCertificateStepsHelper.encrypt(
                                "{\"njwt\":\"" + params.get("token_code") + "\"}",
                                TestEnvironmentConfigurator.getSymmetricEncryptionKey()));
                    } else {
                        ctxt.put(ContextKey.TOKEN_CODE_ENCRYPTED, null);
                    }
                    params.put("token_code", (String) ctxt.get(ContextKey.TOKEN_CODE_ENCRYPTED));
                }
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
            if (TestEnvironmentConfigurator.isTokenEncryptionActive()) {
                params.put("token_code", (String) ctxt.get(ContextKey.TOKEN_CODE_ENCRYPTED));
            } else {
                params.put("token_code", (String) ctxt.get(ContextKey.TOKEN_CODE));
            }
            params.put("code_verifier", (String) ctxt.get(ContextKey.CODE_VERIFIER));
            params.put("client_id", (String) ctxt.get(ContextKey.CLIENT_ID));
        }

        // map token_code to request param code
        // TODO RISE ??? strange sure we remove the same param?
        if (TestEnvironmentConfigurator.isTokenEncryptionActive()) {
            params.put("code", params.remove("token_code"));
        } else {
            params.put("code", params.remove("token_code"));
        }

        // create/encrypt key_verifier
        final byte[] tokenKeyBytes = RandomStringUtils.randomAlphanumeric(256 / 8).getBytes();
        final SecretKey tokenKey = new SecretKeySpec(tokenKeyBytes, "AES");
        if (TestEnvironmentConfigurator.isTokenEncryptionActive()) {
            Context.getDiscoveryDocument();
            final PublicKey pukToken = DiscoveryDocument.getPublicKeyFromContextKey(ContextKey.PUK_ENC);
            params.put(
                "key_verifier",
                buildKeyVerifierToken(tokenKeyBytes, params.get("code_verifier"), pukToken));
        }
        final Response r = requestResponseAndAssertStatus(
            Context.getDiscoveryDocument().getTokenEndpoint(),
            Map.of(CONTENT_TYPE, ContentType.URLENC.withCharset("UTF-8")),
            HttpMethods.POST,
            params,
            null, result);
        ctxt.put(ContextKey.RESPONSE, r);

        if (r.getStatusCode() == 200) {
            final JSONObject json = new JSONObject(r.getBody().asString());
            if (TestEnvironmentConfigurator.isTokenEncryptionActive()) {
                // decrypt access and id token
                ctxt.put(ContextKey.ACCESS_TOKEN, keyAndCertificateStepsHelper
                    .decryptAndExtractNjwt(json.getString("access_token"), tokenKey));
                ctxt.put(ContextKey.ID_TOKEN,
                    keyAndCertificateStepsHelper.decryptAndExtractNjwt(json.getString("id_token"), tokenKey));
            } else {
                ctxt.put(ContextKey.ACCESS_TOKEN, json.getString("access_token"));
                ctxt.put(ContextKey.ID_TOKEN, json.getString("id_token"));
            }
        } else {
            ctxt.put(ContextKey.ACCESS_TOKEN, null);
            ctxt.put(ContextKey.ID_TOKEN, null);
        }
    }

    @SneakyThrows
    private String buildKeyVerifierToken(final byte[] tokenKeyBytes, final String codeVerifier,
        final PublicKey pukToken) {
        final JwtClaims claims = new JwtClaims();
        claims.setStringClaim("token_key", new String(Base64.getUrlEncoder().withoutPadding().encode(tokenKeyBytes)));
        claims.setStringClaim("code_verifier", codeVerifier);
        return keyAndCertificateStepsHelper.encrypt(claims.toJson(), pukToken);
    }
}
