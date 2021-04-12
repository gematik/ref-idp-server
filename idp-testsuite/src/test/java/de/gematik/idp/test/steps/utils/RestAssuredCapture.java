package de.gematik.idp.test.steps.utils;

import de.gematik.rbellogger.RbelLogger;
import de.gematik.rbellogger.converter.RbelConverter;
import de.gematik.rbellogger.data.*;
import io.restassured.http.Header;
import io.restassured.http.Headers;
import io.restassured.response.Response;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import lombok.Data;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

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
        rbel.convertMessage(requestToRbelMessage(method, url, headers, body));
    }

    public void logResponse(final Response response) {
        rbel.convertMessage(responseToRbelMessage(response));
    }

    public RbelElement requestToRbelMessage(final String method, final String url, Map<String, String> headers,
        String body) {
        if (headers == null) {
            headers = new HashMap<>();
        }
        if (body == null) {
            body = "";
        }

        final Headers h = new Headers(headers.entrySet().stream()
            .map(e -> new Header(e.getKey(), e.getValue()))
            .collect(Collectors.toList()));

        return RbelHttpRequest.builder()
            .method(method)
            .path((RbelPathElement) rbel.convertMessage(url))
            .header(mapHeader(h))
            .body(convertMessageBody(body, h.getValue("content-type")))
            .build();
    }

    public RbelElement responseToRbelMessage(final Response response) {
        return RbelHttpResponse.builder()
            .responseCode(response.getStatusCode())
            .header(mapHeader(response.getHeaders()))
            .body(convertMessageBody(response.getBody().asString(), response.getHeaders().getValue("content-type")))
            .build();
    }

    private RbelElement convertMessageBody(final String bodyAsString, final String contentTypeHeader) {
        if (Optional.ofNullable(contentTypeHeader)
            .map(mime -> mime.startsWith("application/x-www-form-urlencoded"))
            .orElse(false)) {
            try {
                if (bodyAsString.isEmpty()) {
                    return new RbelMapElement(new HashMap<>());
                } else {
                    return new RbelMapElement(Stream.of(bodyAsString.split("&"))
                        .map(str -> str.split("="))
                        .collect(Collectors.toMap(array -> array[0], array -> rbel.convertMessage(array[1]))));
                }
            } catch (final Exception e) {
                log.warn("Unable to parse form-data '" + bodyAsString + "'. Using fallback", e);
                return rbel.convertMessage(bodyAsString);
            }
        } else {
            return rbel.convertMessage(bodyAsString);
        }
    }

    private RbelMapElement mapHeader(final Headers headers) {
        final Map<String, String> headersMap = headers.asList().stream()
            .collect(Collectors.toMap(Header::getName, Header::getValue));
        // TODO REF once rbel logger deals with GET,POST,.... in header values appropriately remove again
        //headersMap.computeIfPresent("allow", (key, val) -> val.toLowerCase());
        return new RbelMapElement(
            headersMap.entrySet().stream()
                .collect(Collectors.toMap(Entry::getKey, entry -> rbel.convertMessage(entry.getValue())))
        );
    }
}
