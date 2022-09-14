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

import de.gematik.test.bdd.Context;
import de.gematik.test.bdd.Variables;
import io.cucumber.datatable.DataTable;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import org.assertj.core.api.Assertions;
import org.jetbrains.annotations.NotNull;

public class CucumberValuesConverter {

    public CucumberValuesConverter() {
    }

    @NotNull
    public Map<String, String> getMapFromDatatable(final DataTable params) {
        final List<Map<String, String>> rows = params.asMaps(String.class, String.class);
        Assertions.assertThat(rows)
            .withFailMessage("Expected one data row, check your feature file")
            .hasSize(1);
        return parseParams(rows.get(0));

    }

    public Map<String, String> parseParams(final Map<String, String> params) {
        final Map<String, String> mapParsedParams = new HashMap<>();
        for (final Entry<String, String> entry : params.entrySet()) {
            if (!"$REMOVE".equals(entry.getValue())) {
                if ("$NULL".equals(entry.getValue())) {
                    mapParsedParams.put(entry.getKey(), null);
                } else if ("$CONTEXT".equals(entry.getValue())) {
                    mapParsedParams.put(entry.getKey(), (String) Context.get().get(entry.getKey().toUpperCase()));
                } else {
                    mapParsedParams.put(entry.getKey(), parseDocString(entry.getValue()));
                }
            }
        }
        return mapParsedParams;
    }

    public String parseDocString(String docString) {
        int testEnvIdx = docString.indexOf("${TESTENV.");
        while (testEnvIdx != -1) {
            final int endTestEnv = docString.indexOf("}", testEnvIdx);
            final String varName = docString.substring(testEnvIdx + "${TESTENV.".length(), endTestEnv);
            docString = docString.substring(0, testEnvIdx) +
                IdpTestEnvironmentConfigurator.getTestEnvVar(varName) +
                docString.substring(endTestEnv + 1);
            testEnvIdx = docString.indexOf("${TESTENV.");
        }
        docString = Variables.substituteVariables(docString);
        return docString;
    }
}
