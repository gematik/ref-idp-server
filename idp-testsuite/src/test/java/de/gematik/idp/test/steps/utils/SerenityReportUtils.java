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

package de.gematik.idp.test.steps.utils;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import lombok.extern.slf4j.Slf4j;
import net.serenitybdd.core.Serenity;
import net.thucydides.core.steps.StepEventBus;

@Slf4j
public class SerenityReportUtils {

    public static void addCustomData(final String title, final String content) {
        if (StepEventBus.getEventBus().isBaseStepListenerRegistered()) {
            Serenity.recordReportData().withTitle(title).andContents(content);
        }
        log.info(String.format("%s: %s", title, content));
    }

    public static void addCurlCommand(final String rALogDetails) {
        final String[] lines = rALogDetails.split("\\n");
        final String uri = Stream.of(lines)
            .filter(l -> l.trim().startsWith("Request URI:"))
            .map(SerenityReportUtils::getValueFromLogLine)
            .findFirst().orElse(null);
        final String method = Stream.of(lines)
            .filter(l -> l.trim().startsWith("Request method:"))
            .map(SerenityReportUtils::getValueFromLogLine)
            .findFirst().orElse(null);

        final StringBuilder curlCmd = new StringBuilder("curl -v ");
        if (uri != null && method != null) {
            // add headers
            final List<String> headers = getValuesForBlock(lines, "Headers");
            for (final String header : headers) {
                final int equal = header.indexOf("=");
                curlCmd.append("-H \"").append(header, 0, equal)
                    .append(": ").append(header.substring(equal + 1)).append("\" ");
            }

            switch (method) {
                case "GET":
                    curlCmd.append("-X GET \"").append(uri).append("\" ");
                    break;
                case "POST":
                    // add form params
                    final StringBuilder paramsStr = new StringBuilder();
                    if (createCurlParamString(paramsStr, getValuesForBlock(lines, "Form params"))) {
                        curlCmd.append(" ").append(paramsStr).append("\" ");
                    }
                    curlCmd.append("-X POST \"").append(uri).append("\" ");
                    break;
                case "DELETE":
                    curlCmd.append("-X DELETE \"").append(uri).append("\" ");
                    break;
                case "PUT":
                    curlCmd.append("-X PUT -d '").append(createCurlBodyString(getValuesForBlock(lines, "Body")))
                        .append("' \"").append(uri).append("\" ");
                    break;
            }
        } else {
            curlCmd.append("Unable to parse log data");
        }
        if (StepEventBus.getEventBus().isBaseStepListenerRegistered()) {
            Serenity.recordReportData().withTitle("cURL").andContents(curlCmd.toString());
        }
        log.info("cURL command: " + curlCmd);
        log.debug("RestAssured details:\n" + rALogDetails);
    }

    private static boolean createCurlParamString(final StringBuilder paramsStr, final List<String> params) {
        boolean first = true;
        for (final String param : params) {
            final int equal = param.indexOf("=");
            if (first) {
                first = false;
                paramsStr.append("--data \"");
            } else {
                paramsStr.append("&");
            }
            if (equal == -1) {
                paramsStr.append(param).append("=");
            } else {
                paramsStr.append(param, 0, equal)
                    .append("=").append(param.substring(equal + 1));
            }
        }
        return !first;
    }

    private static String getValueFromLogLine(final String line) {
        final int start = line.lastIndexOf("\t");
        if (start == -1) {
            return line.trim();
        } else {
            return line.substring(start).trim();
        }
    }

    private static String createCurlBodyString(final List<String> bodyLines) {
        final StringBuilder bodyStr = new StringBuilder();
        bodyLines.forEach(line -> bodyStr.append(line).append("\n"));
        return bodyStr.toString();
    }

    private static List<String> getValuesForBlock(final String[] lines, final String blockToken) {
        final List<String> values = new ArrayList<>();
        boolean blockStarted = false;
        for (final String line : lines) {
            if (!blockStarted && line.startsWith(blockToken + ":")) {
                blockStarted = true;
                final String v = getValueFromLogLine(line);
                if ("<none>".equals(v)) {
                    return new ArrayList<>();
                }
                if (!line.trim().equals(v)) {
                    values.add(v);
                }
            } else if (blockStarted) {
                final int tab = line.indexOf("\t");
                final int colon = line.indexOf(":");
                if (colon != -1 && colon < tab) {
                    // next block starts
                    return values;
                } else {
                    // add value
                    values.add(getValueFromLogLine(line));
                }
            }
        }
        return values;
    }
}
