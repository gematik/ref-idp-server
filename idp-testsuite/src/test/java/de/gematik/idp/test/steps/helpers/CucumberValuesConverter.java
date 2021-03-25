package de.gematik.idp.test.steps.helpers;

import de.gematik.idp.test.steps.model.Context;
import de.gematik.idp.test.steps.model.ContextKey;
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
        Assertions.assertThat(rows.size())
            .withFailMessage("Expected one data row, check your feature file")
            .isEqualTo(1);
        return parseParams(rows.get(0));

    }

    public Map<String, String> parseParams(final Map<String, String> params) {
        final Map<String, String> mapParsedParams = new HashMap<>();
        for (final Entry<String, String> entry : params.entrySet()) {
            if (!"$REMOVE".equals(entry.getValue())) {
                if ("$NULL".equals(entry.getValue())) {
                    mapParsedParams.put(entry.getKey(), null);
                } else if ("$CONTEXT".equals(entry.getValue())) {
                    final ContextKey key = ContextKey.valueOf(entry.getKey().toUpperCase());
                    mapParsedParams.put(entry.getKey(), (String) Context.getThreadContext().get(key));
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
                TestEnvironmentConfigurator.getTestEnvVar(varName) +
                docString.substring(endTestEnv + 1);
            testEnvIdx = docString.indexOf("${TESTENV.");
        }
        int varIdx = docString.indexOf("${VAR.");
        while (varIdx != -1) {
            final int endVar = docString.indexOf("}", varIdx);
            final String varName = docString.substring(varIdx + "${VAR.".length(), endVar);
            docString = docString.substring(0, varIdx) + Context.getVariable(varName) + docString.substring(endVar + 1);
            varIdx = docString.indexOf("${VAR.");
        }
        return docString;
    }
}