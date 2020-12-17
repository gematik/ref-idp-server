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

package de.gematik.idp.test.steps.model;

import lombok.Getter;
import net.serenitybdd.rest.SerenityRest;
import org.json.JSONException;
import org.json.JSONObject;

@Getter
public class DiscoveryDocument {

    public DiscoveryDocument(final JSONObject jso) throws JSONException {
        pukUriToken = new JSONObject(SerenityRest.get(jso.getString("puk_uri_token")).getBody().asString());
        pukUriAuth = new JSONObject(SerenityRest.get(jso.getString("puk_uri_auth")).getBody().asString());
        pukUriDisc = new JSONObject(SerenityRest.get(jso.getString("puk_uri_disc")).getBody().asString());
        authorizationEndpoint = jso.getString("authorization_endpoint");
        tokenEndpoint = jso.getString("token_endpoint");
        jwksUri = jso.getString("jwks_uri");
    }


    private final JSONObject pukUriToken;
    // puk_uri_token
    private final JSONObject pukUriAuth;
    // puk_uri_auth
    private final JSONObject pukUriDisc;
    // puk_uri_disc"
    private final String authorizationEndpoint;
    // authorization_endpoint
    private final String tokenEndpoint;
    // token_endpoint
    private final String jwksUri;
    // jwks_uri
}
