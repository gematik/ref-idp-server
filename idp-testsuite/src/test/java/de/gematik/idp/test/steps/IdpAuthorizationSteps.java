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

import static de.gematik.idp.brainPoolExtension.BrainpoolAlgorithmSuiteIdentifiers.BRAINPOOL256_USING_SHA256;
import static org.assertj.core.api.Assertions.assertThat;
import de.gematik.idp.test.steps.helpers.TestEnvironmentConfigurator;
import de.gematik.idp.test.steps.model.*;
import io.restassured.response.Response;
import java.io.IOException;
import java.net.URISyntaxException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import lombok.SneakyThrows;
import net.thucydides.core.annotations.Step;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URIBuilder;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;
import org.json.JSONObject;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

public class IdpAuthorizationSteps extends IdpStepsBase {

    @Step
    public void signChallenge(final String keyfile)
        throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, UnrecoverableKeyException, JoseException {
        final Map<ContextKey, Object> ctxt = Context.getThreadContext();
        final String challenge = (String) ctxt.get(ContextKey.CHALLENGE);

        final Key pkey = readPrivateKeyFrom(keyfile);
        final Certificate cert = readCertFrom(keyfile);

        final String signedChallenge = devGetSignedChallenge(challenge, pkey, cert);

        ctxt.put(ContextKey.SIGNED_CHALLENGE, signedChallenge);
    }

    private String devGetSignedChallenge(final String challenge, final Key pkey, final Certificate cert)
        throws JoseException {
        // TODO this is taken from dev code, REVIEW and check with SPEC/REF
        final JwtClaims claims = new JwtClaims();
        claims.setClaim("njwt", challenge);
        final JsonWebSignature jsonWebSignature = new JsonWebSignature();
        jsonWebSignature.setPayload(claims.toJson());
        jsonWebSignature.setKey(pkey);
        if (cert.getPublicKey().getAlgorithm().equals("EC")) {
            jsonWebSignature.setAlgorithmHeaderValue(BRAINPOOL256_USING_SHA256);
        } else {
            jsonWebSignature.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_PSS_USING_SHA256);
        }
        jsonWebSignature.setHeader("typ", "JWT");
        jsonWebSignature.setHeader("cty", "NJWT");
        jsonWebSignature.setCertificateChainHeaderValue((X509Certificate) cert);
        return jsonWebSignature.getCompactSerialization();
    }

    public void getCode(final CodeAuthType authType, final HttpStatus expectedStatus)
        throws URISyntaxException {
        final Map<ContextKey, Object> ctxt = Context.getThreadContext();
        final Map<String, String> params = new HashMap<>();
        final String path = checkParamsNGetPath(authType, params);
        final Response r = requestResponseAndAssertStatus(
            Context.getDiscoveryDocument().getAuthorizationEndpoint() + path, null, HttpMethods.POST,
            params, expectedStatus);

        ctxt.put(ContextKey.RESPONSE, r);
        final HttpStatus responseStatus = new HttpStatus(r.getStatusCode());

        String error = null;
        if (responseStatus.getValue() == 302) {
            assertThat(r.getHeaders()).anySatisfy(h -> assertThat(h.getName()).isEqualTo("Location"));
            error = new URIBuilder(r.getHeader("Location")).getQueryParams().stream()
                .filter(param -> param.getName().equalsIgnoreCase("error"))
                .map(NameValuePair::getValue)
                .findFirst()
                .orElse(null);
        } else if (responseStatus.isError()) {
            error = "Error " + responseStatus.getValue();
        }
        if (error == null) {
            storeReponseContentInContext(authType, ctxt, r);
        } else {
            ctxt.put(ContextKey.TOKEN_REDIRECT_URL, null);
            ctxt.put(ContextKey.TOKEN_CODE, null);
            ctxt.put(ContextKey.STATE, null);
            if (authType == CodeAuthType.SSO_TOKEN) {
                ctxt.put(ContextKey.SSO_TOKEN, null);
            }
        }
    }

    @SneakyThrows
    private String checkParamsNGetPath(final CodeAuthType authType, final Map<String, String> params) {
        switch (authType) {
            case SIGNED_CHALLENGE:
                checkContextAddToParams(ContextKey.SIGNED_CHALLENGE, "signed_challenge", params);
                // encrypt signed challenge
                final String unencSignedChallenge = params.get("signed_challenge");
                final JsonWebEncryption senderJwe = new JsonWebEncryption();
                senderJwe.setPlaintext(unencSignedChallenge);
                senderJwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.ECDH_ES_A256KW);
                senderJwe
                    .setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
                final PublicKey pukAuth = DiscoveryDocument
                    .getCertificateFromJWK((JSONObject) Context.getThreadContext().get(ContextKey.PUK_AUTH))
                    .getPublicKey();
                senderJwe.setKey(pukAuth);
                params.put("signed_challenge", senderJwe.getCompactSerialization());
                break;
            case SSO_TOKEN:
                checkContextAddToParams(ContextKey.CHALLENGE, "unsigned_challenge", params);
                checkContextAddToParams(ContextKey.SSO_TOKEN, "sso_token", params);
                break;
            case SSO_TOKEN_NO_CHALLENGE:
                checkContextAddToParams(ContextKey.SSO_TOKEN, "sso_token", params);
                break;
        }
        return authType == CodeAuthType.SIGNED_CHALLENGE || authType == CodeAuthType.NO_PARAMS ?
            TestEnvironmentConfigurator.getPostSignedChallengeUrl() :
            TestEnvironmentConfigurator.getPostSSOTokenUrl();
    }

    private void checkContextAddToParams(final ContextKey key, final String paramName,
        final Map<String, String> params) {
        final Map<ContextKey, Object> ctxt = Context.getThreadContext();
        assertThat(ctxt).containsKey(key).doesNotContainEntry(key, null);
        params.put(paramName, String.valueOf(ctxt.get(key)));
    }

    private void storeReponseContentInContext(
        final CodeAuthType authType, final Map<ContextKey, Object> ctxt, final Response r)
        throws URISyntaxException {
        final String reloc = r.getHeader("Location");
        assertThat(reloc).withFailMessage("No Location header in response", r.getHeaders()).isNotBlank();
        ctxt.put(ContextKey.TOKEN_REDIRECT_URL, reloc);
        storeParamOfReloc(reloc, "code", ContextKey.TOKEN_CODE);
        storeParamOfReloc(reloc, "state", ContextKey.STATE);
        if (authType == CodeAuthType.SIGNED_CHALLENGE) {
            storeParamOfReloc(reloc, "sso_token", ContextKey.SSO_TOKEN);
        } else {
            ctxt.put(ContextKey.SSO_TOKEN, null);
        }
    }

    private void storeParamOfReloc(final String reloc, final String paramName, final ContextKey key)
        throws URISyntaxException {
        final String value = new URIBuilder(reloc).getQueryParams().stream()
            .filter(param -> param.getName().equalsIgnoreCase(paramName))
            .map(NameValuePair::getValue)
            .findFirst()
            .orElse(null);
        assertThat(value).isNotBlank();
        Context.getThreadContext().put(key, value);
    }

    public void responseIs302ErrorWithMessageMatching(final String errcode, final String regex) {
        final Response r = Context.getCurrentResponse();
        assertThat(r.getStatusCode()).isEqualTo(302);

        assertThat(r.getHeaders()).anySatisfy(h -> assertThat(h.getName()).isEqualTo("Location"));
        final String location = r.getHeader("Location");
        final MultiValueMap<String, String> parameters =
            UriComponentsBuilder.fromUriString(location).build().getQueryParams();

        assertThat(parameters).containsKeys("error_description",
            "error"); // TODO activate once Julian has his cod ein place   , "error_uri");
        assertThat(parameters.getFirst("error")).matches(errcode);
        assertThat(parameters.getFirst("error_description")).matches(regex);

        /* TODO activate once Julian has his cod ein place
        final String state = (String) Context.getThreadContext().getOrDefault(ContextKey.STATE, null);
        if (state != null) {
            assertThat(parameters).containsKey("state");
            assertThat(parameters.getFirst("state")).isEqualTo(state);
        } else {
            assertThat(parameters).doesNotContainKey("state");
        }
        */
        // TODO check error_uri
    }
}
