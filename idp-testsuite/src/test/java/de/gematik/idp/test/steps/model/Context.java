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

package de.gematik.idp.test.steps.model;

import static org.assertj.core.api.Assertions.assertThat;
import io.restassured.response.Response;
import java.nio.charset.StandardCharsets;
import java.util.AbstractMap;
import java.util.AbstractMap.SimpleEntry;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import net.thucydides.core.annotations.Step;
import org.json.JSONObject;

public class Context {

    private static final Map<String, Map<ContextKey, Object>> threadedContexts = new HashMap<>();

    public static Map<ContextKey, Object> getThreadContext() {
        return threadedContexts
            .computeIfAbsent(String.valueOf(Thread.currentThread().getId()), threadid -> new HashMap<>());
    }

    public static Response getCurrentResponse() {
        assertThat(getThreadContext().get(ContextKey.RESPONSE)).withFailMessage("No Response in context!").isNotNull();
        return (Response) getThreadContext().get(ContextKey.RESPONSE);
    }

    public static JSONObject getCurrentClaims() {
        assertThat(getThreadContext().get(ContextKey.CLAIMS)).withFailMessage("No Claims in context!").isNotNull();
        return (JSONObject) getThreadContext().get(ContextKey.CLAIMS);
    }

    @SuppressWarnings("unused")
    void purgeContext(final ContextKey key) {
        assertThat(getThreadContext()).containsKey(key);
        getThreadContext().remove(key);
    }

    public static DiscoveryDocument getDiscoveryDocument() {
        assertThat(getThreadContext().get(ContextKey.DISC_DOC)).withFailMessage("No Discovery Document in context!")
            .isNotNull();
        return (DiscoveryDocument) (getThreadContext().get(ContextKey.DISC_DOC));
    }

    public void setValue(final ContextKey key, final String value) {
        assertThat(key).isNotIn(ContextKey.USER_CONSENT, ContextKey.RESPONSE, ContextKey.DISC_DOC,
            ContextKey.HEADER_CLAIMS, ContextKey.CLAIMS);
        getThreadContext().put(key, value);
    }

    @SuppressWarnings("unused")
    public void deleteKey(final ContextKey key) {
        getThreadContext().remove(key);
    }

    public void assertRegexMatches(final ContextKey key, final String regex) {
        assertThat(key).isNotIn(ContextKey.USER_CONSENT, ContextKey.RESPONSE, ContextKey.DISC_DOC,
            ContextKey.HEADER_CLAIMS, ContextKey.CLAIMS);

        final Map<ContextKey, Object> ctxt = getThreadContext();
        if ("$NULL".equals(regex)) {
            assertThat(ctxt).containsEntry(key, null);
        } else if ("$DOESNOTEXIST".equals(regex)) {
            assertThat(ctxt).doesNotContainKey(key);
        } else {
            assertThat(ctxt).doesNotContainEntry(key, null);
            assertThat((String) ctxt.get(key)).matches(regex);
        }
    }

    @Step
    public void iStartNewInteractionKeepingOnly(final List<ContextKey> keys) {
        final Map<ContextKey, Object> ctxt = Context.getThreadContext();
        assertThat(ctxt.keySet()).containsAll(keys);
        final Map<ContextKey, Object> ctxt2 = keys.stream()
            .map(key -> new AbstractMap.SimpleEntry<>(key, ctxt.get(key)))
            .collect(Collectors.toMap(SimpleEntry::getKey, e -> ctxt.get(e.getKey())));
        ctxt.clear();
        ctxt.putAll(ctxt2);
    }

    public void flipBit(final int bitidx, final ContextKey key) {
        assertThat(getThreadContext().get(key)).withFailMessage("No " + key + " in context!").isNotNull();
        final String value = Context.getThreadContext().get(key).toString();
        final byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        final int idx;
        final int shift;
        if (bitidx < 0) {
            idx = bytes.length - 1 + bitidx / 8;
            shift = -bitidx % 8;
        } else {
            idx = bitidx / 8;
            shift = 8 - (bitidx % 8);
        }
        bytes[idx] ^= (byte) (0b00000001 << shift);
        final String flippedValue = new String(bytes);
        assertThat(flippedValue).isNotEqualTo(value);
        Context.getThreadContext().put(key, flippedValue);
    }
}
