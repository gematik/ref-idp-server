/*
 * Copyright (c) 2022 gematik GmbH
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
import de.gematik.idp.test.steps.helpers.StringModifier;
import java.util.AbstractMap.SimpleEntry;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;

@Slf4j
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
        if (regex == null || "$NULL".equals(regex)) {
            assertThat(ctxt).containsEntry(key, null);
        } else if ("$DOESNOTEXIST".equals(regex)) {
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

    public void flipBitInContextValue(final int bitidx, final String key) {
        assertThat(getMapForCurrentThread()).containsKey(key);
        assertThat(getMapForCurrentThread().get(key)).withFailMessage("No " + key + " in context!").isNotNull();
        final String value = getMapForCurrentThread().get(key).toString();
        final String flippedValue = StringModifier.flipBit(bitidx, value);
        log.info("flipBitInContextValue, old and new:\n {} \n {}  ", value, flippedValue);
        getMapForCurrentThread().put(key, flippedValue);
    }

    protected static String getThreadId() {
        return String.valueOf(Thread.currentThread().getId());
    }
}
