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
import de.gematik.idp.test.steps.model.Context;
import java.util.Iterator;
import lombok.SneakyThrows;
import net.thucydides.core.annotations.Step;
import org.apache.commons.collections.IteratorUtils;
import org.assertj.core.api.Assertions;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.skyscreamer.jsonassert.Customization;
import org.skyscreamer.jsonassert.JSONAssert;
import org.skyscreamer.jsonassert.JSONCompareMode;
import org.skyscreamer.jsonassert.comparator.CustomComparator;

public class JsonChecker {

    @Step
    public void assertJsonResponseHasNode(final String path) throws JSONException {
        assertThatJson(new JSONObject(Context.getCurrentResponse().getBody().asString())).node(path).isNotNull();
    }


    @Step
    @SneakyThrows
    public void assertJsonArrayShouldMatchInAnyOrder(final String json, final String oracle) {
        JSONAssert.assertEquals(json, oracle, new CustomComparator(
            JSONCompareMode.LENIENT, new Customization("***", (oracleJson, testJson) -> {
            if (testJson instanceof JSONObject) {
                assertJsonShouldMatchInAnyOrder(testJson.toString(), oracleJson.toString());
                return true;
            } else if (testJson instanceof JSONArray) {
                assertJsonArrayShouldMatchInAnyOrder(testJson.toString(), oracleJson.toString());
                return true;
            } else {
                if ("${json-unit.ignore}".equals(oracleJson) ||
                    testJson.toString().equals(oracleJson.toString())) {
                    return true;
                }
                return testJson.toString().matches(oracleJson.toString());
            }
        })));
    }

    @Step
    @SneakyThrows
    public void assertJsonShouldMatchInAnyOrder(final String jsonStr, final String oracleStr) {
        final JSONObject json = new JSONObject(jsonStr);
        final JSONObject oracle = new JSONObject(oracleStr);
        try {
            assertThat(IteratorUtils.toArray(json.keys()))
                .containsExactlyInAnyOrder(IteratorUtils.toArray(oracle.keys()));

            final Iterator<String> keyIt = oracle.keys();
            while (keyIt.hasNext()) {
                final String key = keyIt.next();
                final String oracleValue = oracle.get(key).toString();
                if (!"${json-unit.ignore}".equals(oracleValue)) {
                    if (json.get(key) instanceof JSONObject) {
                        assertJsonShouldMatchInAnyOrder(json.get(key).toString(), oracle.get(key).toString());
                    } else if (json.get(key) instanceof JSONArray) {
                        JSONAssert
                            .assertEquals(json.get(key).toString(), oracle.get(key).toString(), new CustomComparator(
                                JSONCompareMode.LENIENT, new Customization("***", (oracleJson, testJson) -> {
                                if (oracleJson.toString().equals("${json-unit.ignore}") ||
                                    testJson.toString().equals(oracleJson.toString())) {
                                    return true;
                                }
                                assertJsonShouldMatchInAnyOrder(testJson.toString(), oracleJson.toString());
                                return true;
                            })));
                    } else {
                        final String jsoValue = json.get(key).toString();
                        if (!jsoValue.equals(oracleValue)) {
                            try {
                                assertThat(jsoValue)
                                    .withFailMessage(
                                        String.format(
                                            "JSON object does not match at key '%s'\nExpected:\n%s\n\n--------\n\nReceived:\n%s",
                                            key, oracleValue, jsoValue))
                                    .matches(oracleValue);
                            } catch (final Exception ex) {
                                Assertions.fail(String.format(
                                    "JSON object does differ at key '%s'\nExpected:\n%s\n\n--------\n\nReceived:\n%s",
                                    key, oracleValue, jsoValue));
                            }
                        }
                    }
                }
            }
        } catch (final NoSuchMethodError nsme) {
            Assertions.fail(String.format("JSON does not match!\nExpected:\n%s\n\n--------\n\nReceived:\n%s",
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

    @Step
    @SneakyThrows
    public void assertJsonShouldMatch(final SerenityJSONObject serenityJSONObject, final String claimName,
        final String regex) {
        assertThat(IteratorUtils.toArray(serenityJSONObject.keys())).contains(claimName);
        final String jsoValue = serenityJSONObject.get(claimName).toString();

        if (!jsoValue.equals(regex)) {
            assertThat(jsoValue).withFailMessage(
                String.format(
                    "JSON object does not match at key '%s'\nExpected:\n%s\n\n--------\n\nReceived:\n%s",
                    claimName, regex, jsoValue))
                .matches(regex);
        }
    }
}
