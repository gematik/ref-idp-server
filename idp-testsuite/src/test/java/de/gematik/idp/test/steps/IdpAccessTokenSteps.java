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

import de.gematik.idp.test.steps.model.Context;
import de.gematik.idp.test.steps.model.ContextKey;
import de.gematik.idp.test.steps.model.HttpMethods;
import de.gematik.idp.test.steps.model.HttpStatus;
import io.cucumber.datatable.DataTable;
import io.restassured.response.Response;
import java.util.HashMap;
import java.util.Map;
import org.springframework.http.MediaType;

public class IdpAccessTokenSteps extends IdpStepsBase {

    public void getToken(final HttpStatus result, final DataTable paramsTable) {
        final Map<ContextKey, Object> ctxt = Context.getThreadContext();
        assertThat(ctxt)
            .containsKey(ContextKey.TOKEN_CODE)
            .doesNotContainEntry(ContextKey.TOKEN_CODE, null)
            .containsKey(ContextKey.CODE_VERIFIER)
            .doesNotContainEntry(ContextKey.CODE_VERIFIER, null)
            .containsKey(ContextKey.CLIENT_ID)
            .doesNotContainEntry(ContextKey.CLIENT_ID, null);

        final Map<String, String> params = new HashMap<>();
        if (paramsTable != null) {
            params.putAll(getMapFromDatatable(paramsTable));
            if (params.containsKey("redirect_uri")) {
                ctxt.put(ContextKey.REDIRECT_URI, params.get("redirect_uri"));
            }
            if (params.containsKey("code")) {
                ctxt.put(ContextKey.TOKEN_CODE, params.get("code"));
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
            params.put("code", (String) ctxt.get(ContextKey.TOKEN_CODE));
            params.put("code_verifier", (String) ctxt.get(ContextKey.CODE_VERIFIER));
            params.put("client_id", (String) ctxt.get(ContextKey.CLIENT_ID));
        }

        final Map<String, String> headers = new HashMap<>();
        headers.put(CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE);
        final Response r = requestResponseAndAssertStatus(
            Context.getDiscoveryDocument().getTokenEndpoint(),
            headers,
            HttpMethods.POST,
            params,
            result);
        ctxt.put(ContextKey.RESPONSE, r);
        // TODO store response content
    }
}
