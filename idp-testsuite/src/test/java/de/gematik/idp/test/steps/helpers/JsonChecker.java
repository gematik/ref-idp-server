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

package de.gematik.idp.test.steps.helpers;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static net.javacrumbs.jsonunit.assertj.JsonAssertions.json;
import static net.javacrumbs.jsonunit.jsonpath.JsonPathAdapter.inPath;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

import de.gematik.idp.test.steps.model.Context;
import java.util.Iterator;
import net.thucydides.core.annotations.Step;
import org.apache.commons.collections.IteratorUtils;
import org.json.JSONException;
import org.json.JSONObject;

public class JsonChecker {

    @Step
    public void assertJsonResponseHasNode(final String path) throws JSONException {
        assertThatJson(new JSONObject(Context.getCurrentResponse().getBody().asString())).node(path).isNotNull();
    }

    @Step
    public void assertJsonShouldMatchInAnyOrder(final SerenityJSONObject json, final SerenityJSONObject oracle)
        throws JSONException {
        try {
            assertThat(IteratorUtils.toArray(json.keys()))
                .containsExactlyInAnyOrder(IteratorUtils.toArray(oracle.keys()));

            @SuppressWarnings("unchecked") final Iterator<String> keyIt = oracle.keys();
            while (keyIt.hasNext()) {
                final String key = keyIt.next();
                final String oracleValue = oracle.getString(key);
                if ("${json-unit.ignore}".equals(oracleValue)) {
                    continue;
                }
                final String jsoValue = json.get(key).toString();
                if (!jsoValue.equals(oracleValue)) {
                    assertThat(jsoValue)
                        .withFailMessage(
                            String.format(
                                "JSON object does not match at key '%s'\nExpected:\n%s\n\n--------\n\nReceived:\n%s",
                                key, oracleValue, jsoValue))
                        .matches(oracleValue);
                }
            }
        } catch (final NoSuchMethodError nsme) {
            fail(String.format("JSON does not match!\nExpected:\n%s\n\n--------\n\nReceived:\n%s",
                oracle.toString(2), json.toString(2)), nsme);
        }
    }

    @Step
    public void assertJsonResponseHasExactlyOneNodeAt(final String node, final String path) throws JSONException {
        final JSONObject json = new JSONObject(Context.getCurrentResponse().getBody().asString());
        assertThatJson(inPath(json, path))
            .withFailMessage("JSON did not contain only the node '" + node + "' at path '" + path + "'")
            .isEqualTo(json("{\"" + node + "\": \"${json-unit.ignore}\"}"));
    }
}
