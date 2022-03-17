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

import de.gematik.rbellogger.RbelLogger;
import de.gematik.rbellogger.converter.RbelConverter;
import de.gematik.rbellogger.data.RbelElement;
import io.restassured.response.Response;
import lombok.Data;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.Arrays;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Data
@Slf4j
@Getter
public class RestAssuredCapture {

    private RbelConverter rbel;

    public void initialize(final RbelLogger rbelLogger) {
        rbel = rbelLogger.getRbelConverter();
    }

    public void logRequest(final String method, String url, final Map<String, String> headers, String body,
                           final Map<String, String> params) {

        if (params != null) {
            final String query = params.entrySet().stream()
                .map(e -> e.getKey() + "=" + URLEncoder.encode(String.valueOf(e.getValue()), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));
            if (!query.isBlank()) {
                if (method.equals("GET")) {
                    url = url + "?" + query;
                } else {
                    body = query;
                }
            }
        }
        if (body == null) {
            body = "";
        }
        rbel.convertElement(requestToRbelMessage(method, url, headers, body));
    }

    public void logResponse(final Response response) {
        rbel.convertElement(responseToRbelMessage(response));
    }

    public RbelElement requestToRbelMessage(final String method, final String url, Map<String, String> headers,
                                            String body) {
        if (body == null) {
            body = "";
        }
        byte[] httpRequestHeader = (method + " " + url + " HTTP/1.1\r\n"
            + Optional.ofNullable(headers)
            .map(Map::entrySet)
            .stream()
            .flatMap(Set::stream)
            .map(entry -> entry.getKey() + ": " + entry.getValue())
            .collect(Collectors.joining("\r\n")) + "\r\n\r\n").getBytes();

        return new RbelElement(
            Arrays.concatenate(httpRequestHeader, body.getBytes(StandardCharsets.UTF_8)),
            null);
    }

    public RbelElement responseToRbelMessage(final Response response) {
/*
        byte[] httpResponseHeader = ("HTTP/1.1 " + response.getStatus() + " "
            + (response.getStatusMessage() != null ? response.getStatusMessage() : "") + "\r\n"
            + response.getHeaders().all().stream().map(HttpHeader::toString)
            .map(str -> str.replace("\n", "\r\n"))
            .collect(Collectors.joining("\r\n"))
            + "\r\n\r\n").getBytes();

        response.getBody().asByteArray();
        response.asByteArray()*/

        return new RbelElement(response.asByteArray(), null);
    }
}
