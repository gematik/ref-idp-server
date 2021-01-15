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
import de.gematik.idp.test.steps.model.CodeAuthType;
import de.gematik.idp.test.steps.model.Context;
import de.gematik.idp.test.steps.model.ContextKey;
import de.gematik.idp.test.steps.model.HttpMethods;
import de.gematik.idp.test.steps.model.HttpStatus;
import io.restassured.response.Response;
import java.io.IOException;
import java.net.URISyntaxException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import net.thucydides.core.annotations.Step;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URIBuilder;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;

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
        throws URISyntaxException, IOException {
        final Map<ContextKey, Object> ctxt = Context.getThreadContext();
        final Map<String, String> params = new HashMap<>();
        final String path = checkParamsNGetPath(authType, params);
        final Response r = requestResponseAndAssertStatus(
            Context.getDiscoveryDocument().getAuthorizationEndpoint() + path, null, HttpMethods.POST,
            params, expectedStatus);

        ctxt.put(ContextKey.RESPONSE, r);
        final HttpStatus responseStatus = new HttpStatus(r.getStatusCode());
        if (responseStatus.isError()) {
            ctxt.put(ContextKey.TOKEN_REDIRECT_URL, null);
            ctxt.put(ContextKey.TOKEN_CODE, null);
            ctxt.put(ContextKey.STATE, null);
            if (authType == CodeAuthType.SSO_TOKEN) {
                ctxt.put(ContextKey.SSO_TOKEN, null);
            }
        } else {
            storeReponseContentInContext(authType, ctxt, r);
        }
    }

    private String checkParamsNGetPath(final CodeAuthType authType, final Map<String, String> params)
        throws IOException {
        switch (authType) {
            case SIGNED_CHALLENGE:
                checkContextAddToParams(ContextKey.SIGNED_CHALLENGE, "signed_challenge", params);
                break;
            case SSO_TOKEN:
                checkContextAddToParams(ContextKey.CHALLENGE, "challenge_token", params);
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
}
