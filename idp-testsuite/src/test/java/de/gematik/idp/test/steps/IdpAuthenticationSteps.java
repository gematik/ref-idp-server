/*
 * Copyright (c) 2020 gematik GmbH
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
import io.cucumber.datatable.DataTable;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.Map;

public class IdpAuthenticationSteps extends IdpStepsBase {

    public void getChallenge(final DataTable params, final HttpStatus status) throws JSONException {
        final Map<String, String> mapParsedParams = getMapFromDatatable(params);

        final Map<ContextKey, Object> ctxt = Context.getThreadContext();
        if (mapParsedParams.containsKey("client_id")) {
            final String cid = mapParsedParams.get("client_id");
            ctxt.put(ContextKey.CLIENT_ID, cid);
            // TODO where do we get the secrets from? Currently not used or?
            if ("oidc_client".equals(cid)) {
                ctxt.put(ContextKey.CLIENT_SECRET, "c4000d38-6d02-46d4-ba28-bce8e57ede9e");
            }
        }
        ctxt.put(ContextKey.RESPONSE, requestResponseAndAssertStatus(
                Context.getDiscoveryDocument().getAuthorizationEndpoint(), null, HttpMethods.GET, mapParsedParams, status));

        if (status.equals(HttpStatus.FAIL)) {
            ctxt.put(ContextKey.CHALLENGE, null);
            ctxt.put(ContextKey.USER_CONSENT, null);
        } else {
            final JSONObject jso = new JSONObject(Context.getCurrentResponse().getBody().asString());
            ctxt.put(ContextKey.CHALLENGE, jso.getString("challenge"));
            ctxt.put(ContextKey.USER_CONSENT, jso.getString("user_consent")); // TODO user consent is string or an JSO?
            //TODO add data to report ? or is REST query info enough
        }
    }
}
