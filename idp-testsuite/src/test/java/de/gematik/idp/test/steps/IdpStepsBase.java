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

import de.gematik.idp.test.steps.helpers.TestEnvironmentConfigurator;
import de.gematik.idp.test.steps.model.ClaimLocation;
import de.gematik.idp.test.steps.model.Context;
import de.gematik.idp.test.steps.model.ContextKey;
import de.gematik.idp.test.steps.model.DateCompareMode;
import de.gematik.idp.test.steps.model.DiscoveryDocument;
import de.gematik.idp.test.steps.model.HttpMethods;
import de.gematik.idp.test.steps.model.HttpStatus;
import de.gematik.idp.test.steps.utils.SerenityReportUtils;
import io.cucumber.datatable.DataTable;
import io.restassured.filter.log.LogDetail;
import io.restassured.filter.log.RequestLoggingFilter;
import io.restassured.http.ContentType;
import io.restassured.http.Header;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.io.StringReader;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import net.serenitybdd.rest.SerenityRest;
import net.thucydides.core.annotations.Step;
import org.apache.commons.collections.IteratorUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jetbrains.annotations.NotNull;
import org.jose4j.json.JsonUtil;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

@Slf4j
public class IdpStepsBase {

    protected static Context context = new Context();

    @Step
    Response requestResponseAndAssertStatus(final String uri,
        final Map<String, String> headers, final HttpMethods method,
        final Map<String, String> params, final HttpStatus status) {
        final RequestSpecification reqSpec = SerenityRest.rest();
        if (params != null) {
            if (method == HttpMethods.GET) {
                reqSpec.queryParams(params);
            } else /* "POST" */ {
                reqSpec.contentType(ContentType.URLENC.withCharset("UTF-8")).formParams(params);
            }
        }
        if (headers != null) {
            reqSpec.headers(headers);
        }
        final ByteArrayOutputStream reqDetails = new ByteArrayOutputStream();
        reqSpec.filter(
            new RequestLoggingFilter(
                LogDetail.ALL, true, new PrintStream(reqDetails), true));
        final Response r = reqSpec.request(method.toString(), uri).thenReturn();
        SerenityReportUtils.addCurlCommand(reqDetails.toString(StandardCharsets.UTF_8));

        checkHTTPStatus(r.statusCode(), status);
        return r;
    }

    public void checkHTTPStatus(final int resStatus, final HttpStatus status) {
        final HttpStatus resSt = new HttpStatus(resStatus);
        if (status.equals(HttpStatus.SUCCESS)) {
            assertThat(!resSt.isError() || resSt.is3xxRedirection())
                .withFailMessage("Expected status code to be successful, got " + resStatus)
                .isTrue();
        } else if (status.equals(HttpStatus.FAIL)) {
            assertThat(resSt.isError() && !resSt.is3xxRedirection())
                .withFailMessage("Expected status code to be indicating an error, got " + resStatus)
                .isTrue();
        } else //noinspection StatementWithEmptyBody
            if (status.equals(HttpStatus.NOCHECK)) {
                // DO NOTHING
            } else {
                assertThat(resStatus).isEqualTo(status.getValue());
            }

    }

    protected JSONObject getClaims(final String jwt) throws InvalidJwtException {
        final JwtConsumerBuilder jwtConsBuilder = new JwtConsumerBuilder()
            .setSkipDefaultAudienceValidation()
            .setSkipSignatureVerification();
        return new JSONObject(jwtConsBuilder.build().process(jwt).getJwtClaims().getClaimsMap());
    }

    public JSONObject extractHeaderClaimsFromString(final String token) throws JoseException {
        final JsonWebSignature jsonWebSignature = new JsonWebSignature();
        jsonWebSignature.setCompactSerialization(token);
        return new JSONObject(JsonUtil.parseJson(jsonWebSignature.getHeaders().getFullHeaderAsJsonString()));
    }

    @NotNull
    protected Map<String, String> getMapFromDatatable(final DataTable params) {
        final List<Map<String, String>> rows = params.asMaps(String.class, String.class);
        assertThat(rows.size())
            .withFailMessage("Expected one data row, check your feature file")
            .isEqualTo(1);

        final Map<String, String> mapParsedParams = new HashMap<>();
        for (final Map.Entry<String, String> entry : rows.get(0).entrySet()) {
            if (!"$REMOVE".equals(entry.getValue())) {
                if ("$NULL".equals(entry.getValue())) {
                    mapParsedParams.put(entry.getKey(), null);
                } else {
                    mapParsedParams.put(entry.getKey(), entry.getValue());
                }
            }
        }
        return mapParsedParams;
    }

    // =================================================================================================================
    //    K E Y / C E R T   R E L A T E D   M E T H O D S
    // =================================================================================================================
    Certificate readCertFrom(final String certFile)
        throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        final InputStream is = getClass().getResourceAsStream(certFile);
        assertThat(is).withFailMessage("Unable to locate cert resource '" + certFile + "'").isNotNull();
        final KeyStore keyStore = KeyStore.getInstance("pkcs12", new BouncyCastleProvider());
        try (final ByteArrayInputStream bis = new ByteArrayInputStream(is.readAllBytes())) {
            keyStore.load(bis, "00".toCharArray());
        }
        return keyStore.getCertificate(keyStore.aliases().nextElement());
    }

    Key readPrivateKeyFrom(final String keyFile)
        throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        final InputStream is = getClass().getResourceAsStream(keyFile);
        assertThat(is).withFailMessage("Unable to locate key resource '" + keyFile + "'").isNotNull();
        final KeyStore keyStore = KeyStore.getInstance("pkcs12", new BouncyCastleProvider());
        keyStore.load(new ByteArrayInputStream(is.readAllBytes()), "00".toCharArray());
        return keyStore.getKey(keyStore.aliases().nextElement(), "00".toCharArray());
    }

    void assertJWTIsSignedByCertificate(final String jwt, final Certificate cert) {
        final PublicKey publicKey = cert.getPublicKey();
        final JwtConsumer jwtConsumer = new JwtConsumerBuilder()
            .setVerificationKey(publicKey)
            .setSkipDefaultAudienceValidation()
            .build();
        try {
            jwtConsumer.process(jwt).getJwtClaims().getClaimsMap();
        } catch (final InvalidJwtException ije) {
            fail("Checking signature failed", ije);
        }
    }

    // =================================================================================================================
    //
    //    G E N E R A L   W O R K F L O W   S T E P S
    //
    // =================================================================================================================
    @Step
    public void initializeFromDiscoveryDocument()
        throws JSONException, InvalidJwtException, IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, URISyntaxException {
        final String idpLocalDiscdoc = System.getenv("IDP_LOCAL_DISCDOC");
        if (idpLocalDiscdoc == null || idpLocalDiscdoc.isBlank()) {
            final Response r = SerenityRest.get(TestEnvironmentConfigurator.getDiscoveryDocumentURL()).thenReturn();
            Context.getThreadContext()
                .put(ContextKey.DISC_DOC, new DiscoveryDocument(getClaims(r.getBody().asString())));
        } else {
            Context.getThreadContext()
                .put(ContextKey.DISC_DOC, new DiscoveryDocument(new File(idpLocalDiscdoc)));
        }
    }

    @Step
    public void setCodeVerifier(final String codeverifier) {
        Context.getThreadContext().put(ContextKey.CODE_VERIFIER, codeverifier);
    }

    // =================================================================================================================
    //
    //    R E S P O N S E   R E L A T E D   S T E P S
    //
    // =================================================================================================================

    public void assertResponseStatusIs(final HttpStatus status) {
        log.debug("STATUS " + Context.getCurrentResponse().statusCode());
        checkHTTPStatus(Context.getCurrentResponse().getStatusCode(), status);
    }

    @Step
    public void assertResponseIsSignedWithCert(final ContextKey pukKey) throws Throwable {
        final Certificate cert = Context.getDiscoveryDocument()
            .getCertificateFromJWKS((JSONObject) Context.getThreadContext().get(pukKey));
        assertJWTIsSignedByCertificate(Context.getCurrentResponse().getBody().asString(), cert);
    }

    @Step
    public void assertResponseContentTypeIs(final String contentType) {
        assertThat(Context.getCurrentResponse().getContentType()).isEqualTo(contentType);
    }

    // =================================================================================================================
    //
    // C L A I M R E L A T E D S T E P S
    //
    // =================================================================================================================
    @Step
    public void iExtractTheClaims(final ClaimLocation type) throws Throwable {
        extractClaimsFromString(type, Context.getCurrentResponse().getBody().asString());
    }

    @Step
    public void iExtractTheClaimsFromResponseJsonField(final String jsonName, final ClaimLocation type)
        throws Throwable {
        final String jsoValue = new JSONObject(Context.getCurrentResponse().getBody().asString())
            .getString(jsonName);
        extractClaimsFromString(type, jsoValue);
    }

    @Step
    public void extractClaimsFromToken(final ClaimLocation cType, final ContextKey token)
        throws JoseException, InvalidJwtException, JSONException {
        assertThat(token).isIn(ContextKey.TOKEN_CODE, ContextKey.SIGNED_CHALLENGE);
        extractClaimsFromString(cType, Context.getThreadContext().get(token).toString());
    }

    private void extractClaimsFromString(final ClaimLocation cType, final String str)
        throws InvalidJwtException, JSONException, JoseException {
        if (cType == ClaimLocation.body) {
            Context.getThreadContext().put(ContextKey.CLAIMS, getClaims(str));
            SerenityReportUtils.addCustomData("Claims", Context.getCurrentClaims().toString(2));
        } else {
            final JSONObject json = extractHeaderClaimsFromString(str);
            Context.getThreadContext().put(ContextKey.HEADER_CLAIMS, json);
            SerenityReportUtils.addCustomData("Header Claims", json.toString(2));
        }
    }


    @Step
    public void iRequestTheUriFromClaim(final String claim, final HttpMethods method, final HttpStatus result)
        throws JSONException {
        Context.getThreadContext().put(ContextKey.RESPONSE,
            requestResponseAndAssertStatus(Context.getCurrentClaims().getString(claim), null, method, null,
                result));
    }

    @Step
    public void assertUriInClaimExistsWithMethodAndStatus(final String claim, final HttpMethods method,
        final HttpStatus status)
        throws JSONException {
        assertThat(Context.getCurrentClaims().has(claim))
            .withFailMessage("Current claims do not contain key " + claim)
            .isTrue();
        requestResponseAndAssertStatus(Context.getCurrentClaims().getString(claim), null, method, null, status);
    }

    public void assertDateFromClaimMatches(final ClaimLocation claimLocation, final String claimName,
        final DateCompareMode compareMode,
        final Duration duration) throws JSONException {
        final JSONObject claims;
        final Map<ContextKey, Object> ctxt = Context.getThreadContext();
        if (claimLocation == ClaimLocation.body) {
            assertThat(ctxt).containsKey(ContextKey.CLAIMS).doesNotContainEntry(ContextKey.CLAIMS, null);
            claims = (JSONObject) ctxt.get(ContextKey.CLAIMS);
        } else {
            assertThat(ctxt).containsKey(ContextKey.HEADER_CLAIMS).doesNotContainEntry(ContextKey.HEADER_CLAIMS, null);
            claims = (JSONObject) ctxt.get(ContextKey.HEADER_CLAIMS);
        }
        assertThat(IteratorUtils.toArray(claims.keys())).contains(claimName);

        final ZonedDateTime d = ZonedDateTime
            .ofInstant(Instant.ofEpochSecond(Long.parseLong(claims.getString(claimName))),
                ZoneId.of("UTC"));

        final ZonedDateTime expectedDate = ZonedDateTime
            .ofInstant(Instant.ofEpochMilli(System.currentTimeMillis()), ZoneId.of("UTC")).plus(duration);
        switch (compareMode) {
            case NOT_BEFORE:
                assertThat(d).isAfterOrEqualTo(expectedDate);
                break;
            case AFTER:
                assertThat(d).isAfter(expectedDate);
                break;
            case BEFORE:
                assertThat(d).isBefore(expectedDate);
                break;
            case NOT_AFTER:
                assertThat(d).isBeforeOrEqualTo(expectedDate);
                break;
        }
        log.info(d + " " + compareMode.mathSign() + " " + expectedDate);
    }

    @Step
    public void assertThatHttpResponseHeadersMatch(final String kvps) {
        final Properties props = new Properties();
        try (final StringReader sr = new StringReader(kvps)) {
            props.load(sr);
        } catch (final IOException e) {
            fail("Invalid KeyValuePairs in DocString", e);
        }
        final Map<String, String> responseHeaders = Context.getCurrentResponse().getHeaders().asList().stream()
            .collect(Collectors.toMap(Header::getName, Header::getValue));
        final Map<String, String> stringProps = props.entrySet().stream()
            .collect(Collectors.toMap(e -> e.getKey().toString(), e -> e.getValue().toString()));
        stringProps.forEach((key, value) -> {
            assertThat(responseHeaders).containsKey(key);
            assertThat(responseHeaders.get(key)).matches(value);
        });
    }

    public void assertThatHttpResponseUriParameterContains(final String parameter, final String value) {
        final Map<String, String> responseHeaders = Context.getCurrentResponse().getHeaders().asList().stream()
            .collect(Collectors.toMap(Header::getName, Header::getValue));
        final String location = responseHeaders.get("Location");
        final MultiValueMap<String, String> parameters =
            UriComponentsBuilder.fromUriString(location).build().getQueryParams();
        assertThat(parameters).containsKey(parameter);
        assertThat(parameters.get(parameter)).contains(value);
    }

    public void assertContextIsSignedWithCert(final ContextKey key, final ContextKey certName)
        throws CertificateException, JSONException {
        final Certificate cert = Context.getDiscoveryDocument()
            .getCertificateFromJWKS((JSONObject) Context.getThreadContext().get(certName));
        assertJWTIsSignedByCertificate(Context.getThreadContext().get(key).toString(), cert);
    }
}
