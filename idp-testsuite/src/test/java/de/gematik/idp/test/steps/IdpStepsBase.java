/*
 * Copyright (c) 2020 gematik GmbH
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

import de.gematik.idp.test.steps.helpers.TestEnvironmentConfigurator;
import de.gematik.idp.test.steps.model.*;
import de.gematik.idp.test.steps.utils.SerenityReportUtils;
import io.cucumber.datatable.DataTable;
import io.restassured.filter.log.LogDetail;
import io.restassured.filter.log.RequestLoggingFilter;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import lombok.extern.slf4j.Slf4j;
import net.serenitybdd.rest.SerenityRest;
import net.thucydides.core.annotations.Step;
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

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

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
        SerenityReportUtils.addCurlCommand(new String(reqDetails.toByteArray(), StandardCharsets.UTF_8));

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
        } else {
            assertThat(resStatus).isEqualTo(status.getValue());
        }

    }

    protected JSONObject getClaims(final String jwt) throws InvalidJwtException {
        // TODO what is audience validation and do we enforce / validate this?
        final JwtConsumerBuilder jwtConsBuilder = new JwtConsumerBuilder()
                .setSkipDefaultAudienceValidation()
                .setSkipSignatureVerification();
        return new JSONObject(jwtConsBuilder.build().process(jwt).getJwtClaims().getClaimsMap());
    }

    public JSONObject extractHeaderClaimsFromResponse() throws JoseException {
        final JsonWebSignature jsonWebSignature = new JsonWebSignature();
        jsonWebSignature.setCompactSerialization(Context.getCurrentResponse().getBody().asString());
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
    Certificate readCertFrom(final InputStream is)
            throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        final KeyStore keyStore = KeyStore.getInstance("pkcs12", new BouncyCastleProvider());
        try (final ByteArrayInputStream bis = new ByteArrayInputStream(is.readAllBytes())) {
            keyStore.load(bis, "00".toCharArray());
        }
        return keyStore.getCertificate(keyStore.aliases().nextElement());
    }

    Key readPrivateKeyFrom(final InputStream is)
            throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
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
    public void initializeFromDiscoveryDocument() throws JSONException, InvalidJwtException {
        final Response r = SerenityRest.get(TestEnvironmentConfigurator.getDiscoveryDocumentURL()).thenReturn();
        Context.getThreadContext().put(ContextKey.DISC_DOC, new DiscoveryDocument(getClaims(r.getBody().asString())));
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
    public void assertResponseIsSignedWithCert(final String filename) throws Throwable {
        final Certificate cert = readCertFrom(getClass().getResourceAsStream(filename));
        assertJWTIsSignedByCertificate(Context.getCurrentResponse().getBody().asString(), cert);
    }

    @Step
    public void assertResponseContentTypeIs(final String contentType) {
        assertThat(Context.getCurrentResponse().getContentType()).isEqualTo(contentType);
    }

    // =================================================================================================================
    //
    //    C L A I M   R E L A T E D   S T E P S
    //
    // =================================================================================================================
    @Step
    public void iExtractTheClaims(final ClaimType type) throws Throwable {
        if (type == ClaimType.body) {
            Context.getThreadContext().put(ContextKey.CLAIMS,
                    getClaims(Context.getCurrentResponse().getBody().asString()));
            SerenityReportUtils.addCustomData("Claims", Context.getCurrentClaims().toString(2));
        } else {
            final JSONObject jso = extractHeaderClaimsFromResponse();
            Context.getThreadContext().put(ContextKey.HEADER_CLAIMS, jso);
            SerenityReportUtils.addCustomData("Header Claims", jso.toString(2));
        }
    }

    @Step
    public void iRequestTheUriFromClaim(final String claim, final HttpMethods method, final HttpStatus result)
            throws JSONException {
        Context.getThreadContext().put(ContextKey.RESPONSE,
                requestResponseAndAssertStatus(Context.getCurrentClaims().getString(claim), null, method, null, result));
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

    @Step
    public void iStartNewInteractionKeepingOnly(final ContextKey key) {
        final Map<ContextKey, Object> ctxt = Context.getThreadContext();
        assertThat(ctxt).containsKey(key);
        final Object o = ctxt.get(key);
        ctxt.clear();
        ctxt.put(key, o);
    }
}
