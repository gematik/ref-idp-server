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

package de.gematik.idp.test.steps.helpers;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static net.javacrumbs.jsonunit.assertj.JsonAssertions.json;
import static net.javacrumbs.jsonunit.jsonpath.JsonPathAdapter.inPath;
import static org.assertj.core.api.Assertions.assertThat;
import de.gematik.test.bdd.Context;
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
import org.skyscreamer.jsonassert.JSONCompareResult;
import org.skyscreamer.jsonassert.comparator.CustomComparator;

/**
 * values will be first checked for containing "${json-unit.ignore}" then for equals and finally for regex matches
 * <p>
 * JSON object attributes starting with four underscores "____" are optional and allow the oracle string to contain
 * attributes to be checked for value ONLY if it exists in the test JSON
 */
public class JsonChecker {

    final CustomComparator customComparatpr = new CustomComparator(JSONCompareMode.LENIENT,
        new Customization("***", (testJson, oracleJson) -> {
            try {
                new JSONObject(testJson.toString());
                new JSONObject(oracleJson.toString());
                assertJsonShouldMatchInAnyOrder(testJson.toString(), oracleJson.toString());
            } catch (final Exception e) {
                try {
                    new JSONArray(testJson.toString());
                    new JSONArray(oracleJson.toString());
                    assertJsonArrayShouldMatchInAnyOrder(testJson.toString(), oracleJson.toString());
                } catch (final Exception e2) {
                    return oracleJson.toString().equals("${json-unit.ignore}") ||
                        testJson.toString().equals(oracleJson.toString()) ||
                        testJson.toString().matches(oracleJson.toString());
                }
            }
            return true;
        })) {
        @Override
        protected void compareJSONArrayOfJsonObjects(final String key, final JSONArray expected,
            final JSONArray actual, final JSONCompareResult result) throws JSONException {
            if (expected.length() == 1 && actual.length() == 1) {
                compareJSON(expected.getJSONObject(0), actual.getJSONObject(0));
                return;
            }
            // TODO LO PRIO make it without unique key based approach
            super.compareJSONArrayOfJsonObjects(key, expected, actual, result);
        }
    };

    @Step
    public void assertJsonResponseHasNode(final String path) throws JSONException {
        assertThatJson(new JSONObject(Context.getCurrentResponse().getBody().asString())).node(path).isNotNull();
    }


    @Step
    @SneakyThrows
    public void assertJsonArrayShouldMatchInAnyOrder(final String json, final String oracle) {
        JSONAssert.assertEquals(oracle, json, new CustomComparator(
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
        JSONObject json = null;
        JSONObject oracle = null;

        try {
            json = new JSONObject(jsonStr);
            oracle = new JSONObject(oracleStr);
            assertThat(IteratorUtils.toArray(json.keys()))
                .contains(
                    IteratorUtils.toList(oracle.keys()).stream()
                        .filter(key -> !key.toString().startsWith("____"))
                        .toArray());

            // check json keys are all in oracle (either as name or as ____name
            final JSONObject finalOracle = oracle;
            json.keySet().forEach(
                key -> assertThat(finalOracle.has(key.toString()) || finalOracle.has("____" + key))
                    .withFailMessage("EXTRA Key " + key + " in JSON").isTrue()
            );

            final Iterator<String> keyIt = oracle.keys();
            while (keyIt.hasNext()) {
                final String oracleKey = keyIt.next();
                final boolean optionalAttribute = oracleKey.startsWith("____");
                final String jsonKey = optionalAttribute ? oracleKey.substring(4) : oracleKey;
                if (optionalAttribute && !json.has(jsonKey)) {
                    continue;
                }
                final String oracleValue = oracle.get(oracleKey).toString();
                if ("$NULL".equals(oracleValue) && json.get(jsonKey) == JSONObject.NULL) {
                    continue;
                }
                if (!"${json-unit.ignore}".equals(oracleValue)) {
                    if (json.get(jsonKey) instanceof JSONObject) {
                        assertJsonShouldMatchInAnyOrder(json.get(jsonKey).toString(),
                            oracle.get(oracleKey).toString());
                    } else if (json.get(jsonKey) instanceof JSONArray) {

                        JSONAssert.assertEquals(oracle.get(oracleKey).toString(), json.get(jsonKey).toString(),
                            customComparatpr);
                    } else {
                        final String jsoValue = json.get(jsonKey).toString();
                        if (!jsoValue.equals(oracleValue)) {
                            try {
                                assertThat(jsoValue)
                                    .withFailMessage(
                                        String.format(
                                            "JSON object does not match at key '%s'\nExpected:\n%s\n\n--------\n\nReceived:\n%s",
                                            oracleKey, oracleValue, jsoValue))
                                    .matches(oracleValue);
                            } catch (final Exception ex) {
                                Assertions.fail(String.format(
                                    "JSON object does differ at key '%s'\nExpected:\n%s\n\n--------\n\nReceived:\n%s",
                                    oracleKey, oracleValue, jsoValue));
                            }
                        }
                    }
                }
            }
        } catch (final NoSuchMethodError nsme) {
            Assertions.fail(String.format("JSON does not match!\nExpected:\n%s\n\n--------\n\nReceived:\n%s",
                oracle == null ? null : oracle.toString(2),
                json == null ? null : json.toString(2)), nsme);
        } catch (final JSONException jse) {
            Assertions.fail(String.format(
                "Unable to parse JSON!\nExpected:\n%s\n\n--------\n\nReceived:\n%s", jsonStr, oracleStr));
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

        if (regex != null && regex.equals("$REMOVE")) {
            assertThat(IteratorUtils.toArray(serenityJSONObject.keys())).doesNotContain(claimName);
            return;
        }
        assertThat(IteratorUtils.toArray(serenityJSONObject.keys())).contains(claimName);

        if (regex == null) {
            assertThat(serenityJSONObject.get(claimName)).isNull();
            return;
        }
        final String jsoValue = serenityJSONObject.get(claimName).toString();
        if (!jsoValue.equals(regex)) {
            assertThat(jsoValue).withFailMessage(
                String.format(
                    "JSON object does not match at key '%s'\nExpected:\n%s\n\n--------\n\nReceived:\n%s",
                    claimName, regex, jsoValue))
                .matches(regex);
        }
    }

    @Step
    @SneakyThrows
    public void assertJsonShouldNotMatch(final SerenityJSONObject serenityJSONObject, final String claimName,
        final String regex) {

        assertThat(IteratorUtils.toArray(serenityJSONObject.keys())).contains(claimName);

        if (regex == null) {
            assertThat(serenityJSONObject.get(claimName)).isNotNull();
            return;
        }

        final String jsoValue = serenityJSONObject.get(claimName).toString();
        if (!jsoValue.equals(regex)) {
            assertThat(jsoValue).withFailMessage(
                String.format(
                    "JSON object does match at key '%s'\nExpected:\n%s\n\n--------\n\nReceived:\n%s",
                    claimName, regex, jsoValue))
                .doesNotMatch(regex);
        } else {
            Assertions.fail(
                String.format("JSON object does match at key '%s'\nExpected:\n%s\n\n--------\n\nReceived:\n%s",
                    claimName, regex, jsoValue));
        }
    }
}
