/*
 * Copyright (c) 2021 gematik GmbH
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

package de.gematik.test.bdd;

import static org.assertj.core.api.Assertions.assertThat;
import java.nio.charset.StandardCharsets;
import java.util.AbstractMap.SimpleEntry;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class ThreadedContextProvider {

    private final Map<String, Map<String, Object>> threadedContexts = new HashMap<>();

    public Map<String, Object> getMapForCurrentThread() {
        return threadedContexts.computeIfAbsent(getThreadId(), threadid -> new HashMap<>());
    }

    public Object get(final String key) {
        assertThat(getMapForCurrentThread()).containsKey(key);
        return getMapForCurrentThread().get(key);
    }

    public Object put(final String key, final Object value) {
        return getMapForCurrentThread().put(key, value);
    }

    public String getString(final String key) {
        assertThat(getMapForCurrentThread()).containsKey(key);
        return getMapForCurrentThread().get(key).toString();
    }

    public String putString(final String key, final String value) {
        final Object o = getMapForCurrentThread().put(key, value);
        return o == null ? null : o.toString();
    }

    public Map<String, Object> getObjectMapCopy(final String key) {
        assertThat(getMapForCurrentThread().get(key)).isInstanceOf(Map.class);
        return new HashMap<>((Map<String, Object>) getMapForCurrentThread().get(key));
    }

    public void assertRegexMatches(final String key, final String regex) {
        final Map<String, Object> ctxt = getMapForCurrentThread();
        if (regex == null || "$NULL" .equals(regex)) {
            assertThat(ctxt).containsEntry(key, null);
        } else if ("$DOESNOTEXIST" .equals(regex)) {
            assertThat(ctxt).doesNotContainKey(key);
        } else {
            assertThat(ctxt).containsKey(key);
            assertThat(ctxt).doesNotContainEntry(key, null);
            assertThat(ctxt.get(key).toString()).matches(regex);
        }
    }

    public void purge(final String key) {
        assertThat(getMapForCurrentThread()).containsKey(key);
        getMapForCurrentThread().remove(key);
    }

    public void purgeButKeep(final List<String> keys) {
        final Map<String, Object> ctxt = getMapForCurrentThread();
        assertThat(ctxt.keySet()).containsAll(keys);
        final Map<String, Object> ctxt2 = keys.stream()
            .map(key -> new SimpleEntry<>(key, ctxt.get(key)))
            .collect(Collectors.toMap(SimpleEntry::getKey, e -> ctxt.get(e.getKey())));
        ctxt.clear();
        ctxt.putAll(ctxt2);
    }


    public void flipBit(final int bitidx, final String key) {
        assertThat(getMapForCurrentThread()).containsKey(key);
        assertThat(getMapForCurrentThread().get(key)).withFailMessage("No " + key + " in context!").isNotNull();
        final String value = getMapForCurrentThread().get(key).toString();
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
        getMapForCurrentThread().put(key, flippedValue);
    }

    protected static String getThreadId() {
        return String.valueOf(Thread.currentThread().getId());
    }
}
