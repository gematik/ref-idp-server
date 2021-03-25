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

package de.gematik.idp.test.steps;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import de.gematik.idp.test.steps.helpers.KeyAndCertificateStepsHelper;
import de.gematik.idp.test.steps.helpers.TestEnvironmentConfigurator;
import de.gematik.idp.test.steps.model.*;
import de.gematik.idp.test.steps.utils.RestAssuredCapture;
import de.gematik.idp.test.steps.utils.SerenityReportUtils;
import de.gematik.rbellogger.converter.RbelConfiguration;
import de.gematik.rbellogger.converter.RbelConverter;
import de.gematik.rbellogger.converter.initializers.RbelKeyFolderInitializer;
import de.gematik.rbellogger.data.RbelElement;
import de.gematik.rbellogger.data.RbelJsonElement;
import de.gematik.rbellogger.data.RbelJweElement;
import de.gematik.rbellogger.data.RbelMapElement;
import de.gematik.rbellogger.renderer.RbelHtmlRenderer;
import io.cucumber.java.Scenario;
import io.restassured.filter.log.LogDetail;
import io.restassured.filter.log.RequestLoggingFilter;
import io.restassured.http.ContentType;
import io.restassured.http.Header;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.cert.Certificate;
import java.time.Duration;
import java.util.*;
import java.util.function.BiConsumer;
import java.util.stream.Collectors;
import javax.crypto.spec.SecretKeySpec;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import net.serenitybdd.core.Serenity;
import net.serenitybdd.rest.SerenityRest;
import net.thucydides.core.annotations.Step;
import org.apache.commons.io.FileUtils;
import org.assertj.core.api.Assertions;
import org.jetbrains.annotations.NotNull;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;
import wiremock.org.apache.commons.codec.digest.DigestUtils;

@Slf4j
public class IdpStepsBase {

    protected static Context context = new Context();
    protected final KeyAndCertificateStepsHelper keyAndCertificateStepsHelper = new KeyAndCertificateStepsHelper();
    protected final static Map<String, RestAssuredCapture> threadIdToRestAssuredCaptureMap = new HashMap<>();

    @Step
    public void iRequestTheUriFromClaim(final String claim, final HttpMethods method, final HttpStatus result)
        throws JSONException {
        Context.getThreadContext().put(ContextKey.RESPONSE,
            requestResponseAndAssertStatus(Context.getCurrentClaims().getString(claim), null, method, null,
                null, result));
    }

    @Step
    public void assertUriInClaimExistsWithMethodAndStatus(final String claim, final HttpMethods method,
        final HttpStatus status)
        throws JSONException {
        Assertions.assertThat(Context.getCurrentClaims().has(claim))
            .withFailMessage("Current claims do not contain key " + claim)
            .isTrue();
        requestResponseAndAssertStatus(Context.getCurrentClaims().getString(claim), null, method, null, null,
            status);
    }

    @SneakyThrows
    public void wait(final Duration timeout) {
        final long start = System.currentTimeMillis();
        final long end = start + timeout.getSeconds() * 1000;
        long sleepms;
        if (timeout.getSeconds() < 90) {
            sleepms = 5000;
        } else {
            sleepms = 15000;
        }
        while (end > System.currentTimeMillis()) {
            log.info(String
                .format("Waiting %ds, passed %ds...",
                    timeout.getSeconds(),
                    (System.currentTimeMillis() - start) / 1000));
            if (System.currentTimeMillis() + sleepms > end) {
                sleepms = end - System.currentTimeMillis();
            }
            //noinspection BusyWait
            Thread.sleep(sleepms);
        }
    }

    // =================================================================================================================
    //
    // R E S P O N S E R E L A T E D S T E P S
    //
    // =================================================================================================================

    @Step
    Response requestResponseAndAssertStatus(final String uri,
        Map<String, String> headers, final HttpMethods method,
        final Map<String, String> params, final String body, final HttpStatus status) {
        final RequestSpecification reqSpec = SerenityRest.rest();
        reqSpec.redirects().follow(false);
        if (params != null) {
            if (method == HttpMethods.GET) {
                reqSpec.queryParams(params);
            } else /* "POST / PUT" */ {
                reqSpec.formParams(params);
            }
        }
        if (body != null) {
            reqSpec.body(body);
        }
        if (headers == null) {
            if (method == HttpMethods.POST || method == HttpMethods.PUT) {
                headers = Map.of("Content-Type", ContentType.URLENC.withCharset("UTF-8"));
            }
        }
        if (headers != null && !headers.isEmpty()) {
            reqSpec.headers(headers);
        }

        if (TestEnvironmentConfigurator.isRbelLoggerActive()) {
            logRequestToRbelLogger(uri, headers, params, body, method.toString());
        }
        final ByteArrayOutputStream reqDetails = new ByteArrayOutputStream();
        reqSpec.filter(
            new RequestLoggingFilter(
                LogDetail.ALL, true, new PrintStream(reqDetails), true));
        final Response r = reqSpec.request(method.toString(), uri).thenReturn();
        if (TestEnvironmentConfigurator.isRbelLoggerActive()) {
            logResponseToRbelLogger(r);
        }
        SerenityReportUtils.addCurlCommand(reqDetails.toString(StandardCharsets.UTF_8));

        checkHTTPStatus(r, status);
        return r;
    }

    private static void logRequestToRbelLogger(final String uri, final Map<String, String> headers,
        final Map<String, String> params,
        final String body, final String s) {
        final RestAssuredCapture capture = threadIdToRestAssuredCaptureMap.get(getThreadId());
        if (capture != null) {
            capture.logRequest(s, uri, headers, body, params);
        }
    }

    private static void logResponseToRbelLogger(final Response r) {
        final RestAssuredCapture capture = threadIdToRestAssuredCaptureMap.get(getThreadId());
        if (capture != null) {
            capture.logResponse(r);
        }
    }

    @NotNull
    private static String getThreadId() {
        return String.valueOf(Thread.currentThread().getId());
    }

    public static Response simpleGet(final String url) {
        if (TestEnvironmentConfigurator.isRbelLoggerActive()) {
            logRequestToRbelLogger(url, null, null, "", "GET");
        }
        final Response r = SerenityRest.get(url);
        if (TestEnvironmentConfigurator.isRbelLoggerActive()) {
            logResponseToRbelLogger(r);
        }
        return r;
    }

    public void checkHTTPStatus(final Response r, final HttpStatus status) {
        final int resStatus = r.getStatusCode();
        final HttpStatus resSt = new HttpStatus(resStatus);
        if (status.equals(HttpStatus.SUCCESS)) {
            if (resSt.is3xxRedirection()) {
                assertThat(getLocationHeader(r))
                    .withFailMessage("Expected redirect to NOT contain error params, got " + getLocationHeader(r))
                    .doesNotContain("error=");
            } else {
                assertThat(!resSt.isError())
                    .withFailMessage("Expected status code to be successful, got " + resStatus)
                    .isTrue();
            }
        } else if (status.equals(HttpStatus.FAIL)) {
            if (resSt.is3xxRedirection()) {
                assertThat(getLocationHeader(r))
                    .withFailMessage("Expected redirect to contain error params, got " + getLocationHeader(r))
                    .contains("error=");
            } else {
                assertThat(resSt.isError())
                    .withFailMessage("Expected status code to be indicating an error, got " + resStatus)
                    .isTrue();
            }
        } else //noinspection StatementWithEmptyBody
            if (status.equals(HttpStatus.NOCHECK)) {
                // DO NOTHING
            } else {
                assertThat(resStatus).isEqualTo(status.getValue());
            }

    }

    public void assertResponseStatusIs(final HttpStatus status) {
        log.debug("STATUS " + Context.getCurrentResponse().statusCode());
        checkHTTPStatus(Context.getCurrentResponse(), status);
    }

    @Step
    public void assertResponseIsSignedWithCert(final ContextKey certKey) throws Throwable {
        final Certificate cert = DiscoveryDocument
            .getCertificateFromJWK((JSONObject) Context.getThreadContext().get(certKey));
        keyAndCertificateStepsHelper
            .assertJWTIsSignedWithCertificate(Context.getCurrentResponse().getBody().asString(), cert);
    }

    @Step
    public void assertResponseContentTypeMatches(final String contentType) {
        final String cty = Context.getCurrentResponse().getContentType();
        if (!cty.equals(contentType)) {
            assertThat(cty).matches(contentType);
        }
    }

    @Step
    // header names are case insensitive
    // http://www.w3.org/Protocols/rfc2616/rfc2616.html (outdated but base)
    // https://tools.ietf.org/html/rfc7230#appendix-A.2 (current rfc and no changes to rfc2616)
    public void assertThatHttpResponseHeadersMatch(final String kvps) {
        final Properties props = new Properties();
        try (final StringReader sr = new StringReader(kvps)) {
            props.load(sr);
        } catch (final IOException e) {
            fail("Invalid KeyValuePairs in DocString", e);
        }
        try {
            final Map<String, String> responseHeaders = Context.getCurrentResponse().getHeaders().asList().stream()
                .collect(Collectors.toMap(h -> h.getName().toLowerCase(), Header::getValue));
            final Map<String, String> stringProps = props.entrySet().stream()
                .collect(Collectors.toMap(e -> e.getKey().toString(), e -> e.getValue().toString()));
            stringProps.forEach((key, value) -> {
                assertThat(responseHeaders).containsKey(key.toLowerCase());
                assertThat(responseHeaders.get(key.toLowerCase())).matches(value);
            });
        } catch (final IllegalStateException ise) {
            Assertions.fail(ise.getMessage());
        }
    }

    public void assertThatHttpResponseUriParameterContains(final String parameter, final String value) {
        final String location = getLocationHeader(Context.getCurrentResponse());
        assertThat(location).withFailMessage("No Location header found!").isNotNull();
        final MultiValueMap<String, String> parameters = UriComponentsBuilder.fromUriString(location).build()
            .getQueryParams();
        assertThat(parameters).containsKey(parameter);
        assertThat(parameters.get(parameter)).contains(value);
    }


    protected String getLocationHeader(final Response r) {
        assertThat(r.getHeaders()).anySatisfy(h -> assertThat(h.getName().toLowerCase()).isEqualTo("location"));
        String loc = r.getHeader("location");
        if (loc == null) {
            loc = r.getHeader("Location");
        }
        return loc;
    }

    public void initializeRbelLogger() {
        if (!TestEnvironmentConfigurator.isRbelLoggerActive()) {
            return;
        }

        final BiConsumer<RbelElement, RbelConverter> RBEL_IDP_TOKEN_KEY_LISTENER = (element, converter) ->
            Optional.ofNullable(((RbelJweElement) element).getBody())
                .filter(RbelJsonElement.class::isInstance)
                .map(RbelJsonElement.class::cast)
                .map(RbelJsonElement::getJsonElement)
                .filter(RbelMapElement.class::isInstance)
                .map(RbelMapElement.class::cast)
                .map(RbelMapElement::getChildElements)
                .filter(map -> map.containsKey("token_key"))
                .map(map -> map.get("token_key"))
                .map(tokenB64 -> Base64.getUrlDecoder().decode(tokenB64.getContent()))
                .map(tokenKeyBytes -> new SecretKeySpec(tokenKeyBytes, "AES"))
                .ifPresent(aesKey -> converter.getKeyIdToKeyDatabase().put("token_key", aesKey));

        final RbelConverter rbel = RbelConverter.build(new RbelConfiguration()
            .addKey("IDP symmetricEncryptionKey",
                new SecretKeySpec(DigestUtils.sha256("geheimerSchluesselDerNochGehashtWird"), "AES"))
            .addInitializer(new RbelKeyFolderInitializer("src/test/resources/rbel"))
            .addPostConversionListener(RbelJweElement.class, RBEL_IDP_TOKEN_KEY_LISTENER));
        final RestAssuredCapture capture = new RestAssuredCapture();
        capture.initialize(rbel);
        threadIdToRestAssuredCaptureMap.put(getThreadId(), capture);
    }

    public void exportRbelLog(final Scenario scenario) {
        if (!TestEnvironmentConfigurator.isRbelLoggerActive()) {
            return;
        }
        final File folder = Paths.get("target", "rbel").toFile();
        if (!folder.exists()) {
            if (!folder.mkdirs()) {
                assertThat(folder).exists();
            }
        }
        final RbelHtmlRenderer renderer = new RbelHtmlRenderer();
        renderer.setSubTitle("<p><b>" + scenario.getName() + "</b></p><p><i>" + scenario.getUri() + "</i></p>");
        final String html = renderer.doRender(
            threadIdToRestAssuredCaptureMap.get(getThreadId()).getRbel().getMessageHistory());
        try {
            String name = scenario.getName();
            final String map = "äaÄAöoÖOüuÜUßs _(_)_[_]_{_}_<_>_|_$_%_&_/_\\_?_:_*_\"_";
            for (int i = 0; i < map.length(); i += 2) {
                name = name.replace(map.charAt(i), map.charAt(i + 1));
            }
            if (name.length() > 103) { // Serenity can not deal with longer filenames
                name = name.substring(0, 60) + UUID.nameUUIDFromBytes(name.getBytes(StandardCharsets.UTF_8)).toString();
            }
            final File logFile = Paths.get("target", "rbel", name + ".html").toFile();
            FileUtils.writeStringToFile(logFile, html, StandardCharsets.UTF_8);
            (Serenity.recordReportData().asEvidence().withTitle("RBellog")).downloadable()
                .fromFile(logFile.toPath());
            log.info("Saved HTML report to " + logFile.getAbsolutePath());
        } catch (final IOException e) {
            log.error("Unable to save rbel log for scenario " + scenario.getName());
        }
    }
}
