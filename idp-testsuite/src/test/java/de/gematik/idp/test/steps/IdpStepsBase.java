/*
 *  Copyright 2023 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
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
import static org.awaitility.Awaitility.await;

import de.gematik.idp.test.steps.helpers.IdpTestEnvironmentConfigurator;
import de.gematik.idp.test.steps.helpers.KeyAndCertificateStepsHelper;
import de.gematik.idp.test.steps.model.DiscoveryDocument;
import de.gematik.idp.test.steps.model.HttpMethods;
import de.gematik.idp.test.steps.model.HttpStatus;
import de.gematik.idp.test.steps.utils.SerenityReportUtils;
import de.gematik.test.bdd.Context;
import de.gematik.test.bdd.ContextKey;
import io.restassured.filter.log.LogDetail;
import io.restassured.filter.log.RequestLoggingFilter;
import io.restassured.http.ContentType;
import io.restassured.http.Header;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import net.serenitybdd.annotations.Step;
import net.serenitybdd.rest.SerenityRest;
import org.apache.commons.lang3.StringUtils;
import org.assertj.core.api.Assertions;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

@Slf4j
public class IdpStepsBase {

  protected final KeyAndCertificateStepsHelper keyAndCertificateStepsHelper =
      new KeyAndCertificateStepsHelper();

  // =================================================================================================================
  //
  // R E S P O N S E R E L A T E D S T E P S
  //
  // =================================================================================================================

  public static Response simpleGet(final String url) {
    return SerenityRest.with() // .header("X-Auth", "MTRqU2cwPXx+Pit4aCVUT2pNVVN2VDllPj1cUUUqCg==")
        .get(url);
  }

  @Step
  public void iRequestTheUriFromClaim(
      final String claim, final HttpMethods method, final HttpStatus result) throws JSONException {
    String urlFromClaim = Context.getCurrentClaims().getString(claim);
    if (!IdpTestEnvironmentConfigurator.getFqdnInternet().isEmpty()) {
      urlFromClaim = DiscoveryDocument.adaptUrlToSymbolicIdpHost(urlFromClaim);
    }
    Context.get()
        .put(
            ContextKey.RESPONSE,
            requestResponseAndAssertStatus(urlFromClaim, null, method, null, null, result));
  }

  @Step
  public void assertUriInClaimExistsWithMethodAndStatus(
      final String claim, final HttpMethods method, final HttpStatus status) throws JSONException {
    Assertions.assertThat(Context.getCurrentClaims().has(claim))
        .withFailMessage("Current claims do not contain key " + claim)
        .isTrue();
    String urlFromClaim = Context.getCurrentClaims().getString(claim);
    if (!IdpTestEnvironmentConfigurator.getFqdnInternet().isEmpty()) {
      urlFromClaim = DiscoveryDocument.adaptUrlToSymbolicIdpHost(urlFromClaim);
    }
    Context.get()
        .put(
            ContextKey.RESPONSE,
            requestResponseAndAssertStatus(urlFromClaim, null, method, null, null, status));
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
      log.info(
          String.format(
              "Waiting %ds, passed %ds...",
              timeout.getSeconds(), (System.currentTimeMillis() - start) / 1000));
      if (System.currentTimeMillis() + sleepms > end) {
        sleepms = end - System.currentTimeMillis();
      }

      await().atLeast(sleepms, TimeUnit.MILLISECONDS);
    }
  }

  @Step
  Response requestResponseAndAssertStatus(
      final String uri,
      Map<String, String> headers,
      final HttpMethods method,
      final Map<String, String> params,
      final String body,
      final HttpStatus status) {
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
      headers = new HashMap<>();
    }
    if (method == HttpMethods.POST || method == HttpMethods.PUT) {
      headers.putIfAbsent("Content-Type", ContentType.URLENC.withCharset("UTF-8"));
    }
    headers.putIfAbsent(
        "User-Agent",
        Context.get()
            .getMapForCurrentThread()
            .getOrDefault(
                ContextKey.USER_AGENT,
                IdpTestEnvironmentConfigurator.getTestEnvVar("user_agent_valid"))
            .toString());
    headers.putIfAbsent("X-Auth", "MTRqU2cwPXx+Pit4aCVUT2pNVVN2VDllPj1cUUUqCg==");
    reqSpec.headers(headers);

    final ByteArrayOutputStream reqDetails = new ByteArrayOutputStream();
    reqSpec.filter(
        new RequestLoggingFilter(LogDetail.ALL, true, new PrintStream(reqDetails), true));
    final Response r = reqSpec.request(method.toString(), uri).thenReturn();

    log.info("RESTASSURED REQUEST details:\n" + reqDetails.toString(StandardCharsets.UTF_8));
    log.info("RESTASSURED RESPONSE details:");
    log.info("  Status:   {}", r.getStatusCode() + "/" + r.getStatusLine());
    final StringBuilder sb = new StringBuilder();
    r.getHeaders()
        .asList()
        .forEach(
            header ->
                sb.append(header.getName())
                    .append(" = ")
                    .append(header.getValue())
                    .append("\n            "));
    log.info("  Headers:  \n            {}", sb);
    String bodyStr = r.getBody().prettyPrint();
    if (bodyStr.isBlank()) {
      bodyStr = StringUtils.abbreviate(r.getBody().asString(), 1000);
    }
    if (bodyStr.isBlank()) {
      bodyStr = "<none>";
    }
    log.info("  Body:     {}", bodyStr);
    SerenityReportUtils.addCurlCommand(reqDetails.toString(StandardCharsets.UTF_8));

    checkHTTPStatus(r, status);
    return r;
  }

  public void checkHTTPStatus(final Response r, final HttpStatus status) {
    final int resStatus = r.getStatusCode();
    final HttpStatus resSt = new HttpStatus(resStatus);
    if (status.equals(HttpStatus.SUCCESS)) {
      if (resSt.is3xxRedirection()) {
        assertThat(getLocationHeader(r))
            .withFailMessage(
                "Expected redirect to NOT contain error params, got " + getLocationHeader(r))
            .doesNotContain("error=");
      } else {
        assertThat(!resSt.isError())
            .withFailMessage("Expected status code to be successful, got " + resStatus)
            .isTrue();
      }
    } else if (status.equals(HttpStatus.FAIL)) {
      if (resSt.is3xxRedirection()) {
        assertThat(getLocationHeader(r))
            .withFailMessage(
                "Expected redirect to contain error params, got " + getLocationHeader(r))
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
  public void assertResponseIsSignedWithCert(final String certKey) throws Throwable {
    final Certificate cert =
        DiscoveryDocument.getCertificateFromJWK((JSONObject) Context.get().get(certKey));
    keyAndCertificateStepsHelper.assertJWTIsSignedWithCertificate(
        Context.getCurrentResponse().getBody().asString(), cert);
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
      final Map<String, String> responseHeaders =
          Context.getCurrentResponse().getHeaders().asList().stream()
              .collect(Collectors.toMap(h -> h.getName().toLowerCase(), Header::getValue));
      final Map<String, String> stringProps =
          props.entrySet().stream()
              .collect(Collectors.toMap(e -> e.getKey().toString(), e -> e.getValue().toString()));
      stringProps.forEach(
          (key, value) -> {
            assertThat(responseHeaders).containsKey(key.toLowerCase());
            assertThat(responseHeaders.get(key.toLowerCase())).matches(value);
          });
    } catch (final IllegalStateException ise) {
      Assertions.fail(ise.getMessage());
    }
  }

  public void assertThatHttpResponseUriParameterContains(
      final String parameter, final String value) {
    final String location = getLocationHeader(Context.getCurrentResponse());
    assertThat(location).withFailMessage("No Location header found!").isNotNull();
    final MultiValueMap<String, String> parameters =
        UriComponentsBuilder.fromUriString(location).build().getQueryParams();
    assertThat(parameters).containsKey(parameter);
    assertThat(parameters.getFirst(parameter)).matches(value);
  }

  protected String getLocationHeader(final Response r) {
    assertThat(r.getHeaders())
        .anySatisfy(h -> assertThat(h.getName().toLowerCase()).isEqualTo("location"));
    String loc = r.getHeader("location");
    if (loc == null) {
      loc = r.getHeader("Location");
    }
    return loc;
  }
}
