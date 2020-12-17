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

import de.gematik.idp.test.steps.model.*;
import io.restassured.response.Response;
import net.thucydides.core.annotations.Step;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URIBuilder;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;

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

import static de.gematik.idp.brainPoolExtension.BrainpoolAlgorithmSuiteIdentifiers.BRAINPOOL256_USING_SHA256;
import static org.assertj.core.api.Assertions.assertThat;

public class IdpAuthorizationSteps extends IdpStepsBase {

    @Step
    public void signChallenge(final String keyfile)
            throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, UnrecoverableKeyException, JoseException {
        final Map<ContextKey, Object> ctxt = Context.getThreadContext();
        final String challenge = (String) ctxt.get(ContextKey.CHALLENGE);

        final Key pkey = readPrivateKeyFrom(getClass().getResourceAsStream(keyfile));
        final Certificate cert = readCertFrom(getClass().getResourceAsStream(keyfile));

        final String signedChallenge = devGetSignedChallenge(challenge, pkey, cert);

        ctxt.put(ContextKey.SIGNED_CHALLENGE, signedChallenge);
    }

    private String devGetSignedChallenge(final String challenge, final Key pkey, final Certificate cert)
            throws JoseException {
        // TODO this is taken from dev code, REVIEW and check with SPEC/REF
        final JwtClaims claims = new JwtClaims();
        claims.setClaim("njwt", challenge);
        //TODO: Hash des NJWT, der mit der Signatur des Certificates der Smartcard signiert wird
        claims.setClaim("csig", "signed_hash_of_njwt");
        final JsonWebSignature jsonWebSignature = new JsonWebSignature();
        jsonWebSignature.setPayload(claims.toJson());
        jsonWebSignature.setKey(pkey);
        if (cert.getPublicKey().getAlgorithm().equals("EC")) {
            jsonWebSignature.setAlgorithmHeaderValue(BRAINPOOL256_USING_SHA256);
        } else {
            jsonWebSignature.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_PSS_USING_SHA256);
        }
        jsonWebSignature.setHeader("typ", "jwt");
        jsonWebSignature.setHeader("cty", "njwt");
        jsonWebSignature.setCertificateChainHeaderValue((X509Certificate) cert);
        return jsonWebSignature.getCompactSerialization();
    }

    public void getCode(final CodeAuthType authType, final HttpStatus expectedStatus) throws URISyntaxException {
        final Map<ContextKey, Object> ctxt = Context.getThreadContext();
        final Map<String, String> params = new HashMap<>();
        switch (authType) {
            case SIGNED_CHALLENGE:
                assertThat(ctxt).containsKey(ContextKey.SIGNED_CHALLENGE)
                        .doesNotContainEntry(ContextKey.SIGNED_CHALLENGE, null);
                params.put("signed_challenge", String.valueOf(ctxt.get(ContextKey.SIGNED_CHALLENGE)));
                break;
            case SSO_TOKEN:
                assertThat(ctxt).containsKey(ContextKey.SSO_TOKEN)
                        .doesNotContainEntry(ContextKey.SSO_TOKEN, null);
                params.put("sso_token", String.valueOf(ctxt.get(ContextKey.SSO_TOKEN)));
        }
        final Response r = requestResponseAndAssertStatus(
                Context.getDiscoveryDocument().getAuthorizationEndpoint(), null, HttpMethods.POST,
                params, expectedStatus);

        ctxt.put(ContextKey.RESPONSE, r);
        if (expectedStatus.equals(HttpStatus.SUCCESS)) {
            storeReponseContentInContext(authType, ctxt, r);
        } else {
            ctxt.put(ContextKey.REDIRECT_URL, null);
            ctxt.put(ContextKey.TOKEN_CODE, null);
            if (authType == CodeAuthType.SSO_TOKEN) {
                ctxt.put(ContextKey.SSO_TOKEN, null);
            }
        }
    }

    private void storeReponseContentInContext(
            final CodeAuthType authType, final Map<ContextKey, Object> ctxt, final Response r)
            throws URISyntaxException {
        final String reloc = r.getHeader("Location");
        assertThat(reloc).withFailMessage("No Location header in response", r.getHeaders()).isNotBlank();
        ctxt.put(ContextKey.REDIRECT_URL, reloc);
        final String code = new URIBuilder(reloc).getQueryParams().stream()
                .filter(param -> param.getName().equalsIgnoreCase("code"))
                .map(NameValuePair::getValue)
                .findFirst()
                .orElse(null);
        assertThat(code).isNotBlank();
        ctxt.put(ContextKey.TOKEN_CODE, code);
        if (authType == CodeAuthType.SIGNED_CHALLENGE) {
            final String ssotoken = new URIBuilder(reloc).getQueryParams().stream()
                    .filter(param -> param.getName().equalsIgnoreCase("sso_token"))
                    .map(NameValuePair::getValue)
                    .findFirst()
                    .orElse(null);
            assertThat(ssotoken).isNotBlank();
            ctxt.put(ContextKey.SSO_TOKEN, ssotoken);
        }
    }
}
