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

import de.gematik.idp.test.steps.model.Context;
import de.gematik.idp.test.steps.model.ContextKey;
import de.gematik.idp.test.steps.model.HttpMethods;
import de.gematik.idp.test.steps.model.HttpStatus;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import lombok.SneakyThrows;
import org.apache.commons.codec.digest.DigestUtils;
import org.json.JSONException;
import org.json.JSONObject;

public class IdpAuthenticationSteps extends IdpStepsBase {

    public void setCodeVerifier(final String codeverifier) {
        Context.getThreadContext().put(ContextKey.CODE_VERIFIER, codeverifier);
    }

    @SneakyThrows
    public String generateCodeChallenge(final String codeVerifier) {
        final byte[] bytes = codeVerifier.getBytes(StandardCharsets.UTF_8);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(DigestUtils.sha256(bytes));
    }

    public void getChallenge(final Map<String, String> mapParsedParams, final HttpStatus status) throws JSONException {
        final Map<ContextKey, Object> ctxt = Context.getThreadContext();
        if (mapParsedParams.containsKey("client_id")) {
            final String cid = mapParsedParams.get("client_id");
            ctxt.put(ContextKey.CLIENT_ID, cid);
        }
        ctxt.put(ContextKey.RESPONSE, requestResponseAndAssertStatus(
            Context.getDiscoveryDocument().getAuthorizationEndpoint(), null, HttpMethods.GET,
            mapParsedParams, null, status));

        final HttpStatus responseStatus = new HttpStatus(Context.getCurrentResponse().getStatusCode());
        if (responseStatus.isError() || responseStatus.is3xxRedirection()) {
            ctxt.put(ContextKey.CHALLENGE, null);
            ctxt.put(ContextKey.USER_CONSENT, null);
        } else {
            final JSONObject json = new JSONObject(Context.getCurrentResponse().getBody().asString());
            ctxt.put(ContextKey.CHALLENGE, json.getString("challenge"));
            ctxt.put(ContextKey.USER_CONSENT, json.getJSONObject("user_consent"));
        }
    }
}
