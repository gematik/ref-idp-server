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

package de.gematik.idp.test.steps.model;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Enumeration;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import net.serenitybdd.rest.SerenityRest;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.jose4j.keys.X509Util;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

@Getter
@Slf4j
public class DiscoveryDocument {

    private static final BouncyCastleProvider BOUNCY_CASTLE_PROVIDER = new BouncyCastleProvider();

    private JSONObject json = null;

    private JSONObject pukUriToken;
    // puk_uri_token
    private JSONObject pukUriAuth;
    // puk_uri_auth
    private JSONObject pukUriDisc;
    // puk_uri_disc"
    private final String authorizationEndpoint;
    // authorization_endpoint
    private final String tokenEndpoint;
    // token_endpoint
    private final String jwksUri;

    public DiscoveryDocument(final JSONObject jso)
        throws JSONException {
        json = jso;
        authorizationEndpoint = jso.getString("authorization_endpoint");
        tokenEndpoint = jso.getString("token_endpoint");
        jwksUri = jso.getString("jwks_uri");
    }

    public DiscoveryDocument(final File template)
        throws IOException, JSONException, KeyStoreException, CertificateException, NoSuchAlgorithmException, URISyntaxException {
        this(new JSONObject(IOUtils.toString(new FileReader(template, StandardCharsets.UTF_8))));
    }

    public void readPublicKeysFromURIs()
        throws JSONException, URISyntaxException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        pukUriToken = getPuKFromJSONAttribute(json.getString("puk_uri_token"));
        Context.getThreadContext().put(ContextKey.PUK_TOKEN, pukUriToken);
        pukUriAuth = getPuKFromJSONAttribute(json.getString("puk_uri_auth"));
        Context.getThreadContext().put(ContextKey.PUK_AUTH, pukUriAuth);
        pukUriDisc = getPuKFromJSONAttribute(json.getString("puk_uri_disc"));
        Context.getThreadContext().put(ContextKey.PUK_DISC, pukUriDisc);
    }

    private JSONObject getPuKFromJSONAttribute(final String uri)
        throws JSONException, KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, URISyntaxException {
        if (uri.equals("$NULL")) {
            return null;
        } else if (uri.startsWith("http")) {
            log.info("Retrieving key from URI " + uri);
            return new JSONObject(SerenityRest.get(uri).getBody().asString());
        } else {
            log.info("Retrieving key from file " + uri);

            final byte[] p12FileContent = FileUtils
                .readFileToByteArray(new File(new URI(uri).getPath()));

            final KeyStore p12 = KeyStore.getInstance("pkcs12", BOUNCY_CASTLE_PROVIDER);
            p12.load(new ByteArrayInputStream(p12FileContent), "00".toCharArray());
            final Enumeration<String> e = p12.aliases();
            X509Certificate certificate = null;
            while (e.hasMoreElements() && certificate == null) {
                final String alias = e.nextElement();
                certificate = (X509Certificate) p12.getCertificate(alias);
            }
            final JSONObject json = new JSONObject();
            final JSONArray x5c = new JSONArray();
            x5c.put(0, new X509Util().toBase64(certificate));
            json.put("x5c", x5c);
            json.put("kid", String.valueOf(certificate.getSerialNumber()));
            json.put("kty", certificate.getPublicKey().getAlgorithm());

            final BCECPublicKey bcecPublicKey = (BCECPublicKey) (certificate.getPublicKey());
            assertThat(((ECNamedCurveParameterSpec) bcecPublicKey.getParameters()).getName())
                .isEqualTo("brainpoolP256r1");
            final ECPoint generator = bcecPublicKey.getQ();
            json.put("crv", "BP-256"); // hard coded as we assert the curve type above
            json.put("x", Base64.getEncoder()
                .encodeToString(generator.getAffineXCoord().toBigInteger().toByteArray()));
            json.put("y", Base64.getEncoder()
                .encodeToString(generator.getAffineYCoord().toBigInteger().toByteArray()));
            return json;
        }
    }

    // jwks_uri

    public X509Certificate getCertificateFromJWKS(final JSONObject jwks) throws JSONException, CertificateException {
        final String certString = jwks.getJSONArray("x5c").getString(0);
        final byte[] decode = Base64.getDecoder().decode(certString);
        final CertificateFactory certFactory = CertificateFactory.getInstance("X.509", BOUNCY_CASTLE_PROVIDER);
        final InputStream in = new ByteArrayInputStream(decode);
        return (X509Certificate) certFactory.generateCertificate(in);
    }
}
