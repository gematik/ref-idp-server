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

import static org.assertj.core.api.Assertions.assertThat;

import io.restassured.response.Response;
import java.util.HashMap;
import java.util.Map;
import org.json.JSONObject;

public class Context {

    private static final Map<String, Map<ContextKey, Object>> threadedContexts = new HashMap<>();

    public static Map<ContextKey, Object> getThreadContext() {
        return threadedContexts
            .computeIfAbsent(String.valueOf(Thread.currentThread().getId()), threadid -> new HashMap<>());
    }

    public static Response getCurrentResponse() {
        return (Response) getThreadContext().get(ContextKey.RESPONSE);
    }

    public static JSONObject getCurrentClaims() {
        return (JSONObject) getThreadContext().get(ContextKey.CLAIMS);
    }

    @SuppressWarnings("unused")
    void purgeContext(final ContextKey key) {
        assertThat(getThreadContext()).containsKey(key);
        getThreadContext().remove(key);
    }

    // TODO implement steps to modify context string objects
    @SuppressWarnings("unused")
    void setContext(final ContextKey key, final String value) {
        assertThat(key)
            .withFailMessage("Only String context values can be set!")
            .isNotIn(ContextKey.CLAIMS, ContextKey.RESPONSE, ContextKey.DISC_DOC, ContextKey.USER_CONSENT);
        getThreadContext().put(key, value);
    }

    public static DiscoveryDocument getDiscoveryDocument() {
        return (DiscoveryDocument) (getThreadContext().get(ContextKey.DISC_DOC));
    }
}
