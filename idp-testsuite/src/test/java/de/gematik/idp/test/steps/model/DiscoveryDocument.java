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

package de.gematik.idp.test.steps.model;

import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.brainPoolExtension.BrainpoolCurves;
import de.gematik.idp.test.steps.IdpStepsBase;
import de.gematik.idp.test.steps.helpers.IdpTestEnvironmentConfigurator;
import de.gematik.test.bdd.Context;
import de.gematik.test.bdd.ContextKey;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECPublicKeySpec;
import java.util.Base64;
import java.util.Enumeration;
import lombok.Getter;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.validator.routines.UrlValidator;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.jose4j.keys.X509Util;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.web.util.UriComponentsBuilder;

@Getter
@Slf4j
public class DiscoveryDocument {

  private static final BouncyCastleProvider BOUNCY_CASTLE_PROVIDER = new BouncyCastleProvider();

  private final JSONObject jsonBody;
  private final JSONObject jsonHeader;
  private final String authorizationEndpoint;
  private final String ssoEndpoint;
  private final String altAuthEndpoint;
  private final String tokenEndpoint;
  private final String pairingEndpoint;
  private final String jwksUri;
  private JSONObject pukUriEnc;
  private JSONObject pukUriSign;
  private JSONObject pukUriDisc;

  public DiscoveryDocument(final JSONObject jsoBody, final JSONObject jsoHeader)
      throws JSONException {
    if (!IdpTestEnvironmentConfigurator.getFqdnInternet().isEmpty()) {
      jsoBody.keySet().stream()
          .filter(key -> jsoBody.get(key) instanceof String)
          .filter(key -> UrlValidator.getInstance().isValid(jsoBody.getString(key)))
          .forEach(key -> jsoBody.put(key, adaptUrlToSymbolicIdpHost(jsoBody.getString(key))));
    }
    jsonBody = jsoBody;
    jsonHeader = jsoHeader;
    authorizationEndpoint = jsoBody.getString("authorization_endpoint");
    ssoEndpoint = jsoBody.getString("sso_endpoint");
    tokenEndpoint = jsoBody.getString("token_endpoint");
    // TODO RISE reactivate mandatory altauth attributes
    altAuthEndpoint =
        jsoBody.has("auth_pair_endpoint") ? jsoBody.getString("auth_pair_endpoint") : "UNDEFINED";
    pairingEndpoint = jsoBody.has("uri_pair") ? jsoBody.getString("uri_pair") : "UNDEFINED";
    jwksUri = jsoBody.getString("jwks_uri");
    IdpTestEnvironmentConfigurator.initializeIDPTestEnvironment();
  }

  public DiscoveryDocument(final File templateBody, final File templateHeader)
      throws IOException, JSONException {
    this(
        new JSONObject(IOUtils.toString(new FileReader(templateBody, StandardCharsets.UTF_8))),
        new JSONObject(IOUtils.toString(new FileReader(templateHeader, StandardCharsets.UTF_8))));
  }

  public static String adaptUrlToSymbolicIdpHost(final String url) {
    if (url.contains("pairing")) {
      return url;
    }
    final UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(url);
    return builder
        .host(IdpTestEnvironmentConfigurator.getFqdnInternet())
        .port(null)
        .scheme("http")
        .toUriString();
  }

  // jwks_uri
  public static X509Certificate getCertificateFromJWK(final JSONObject jwk)
      throws JSONException, CertificateException {
    final String certString = jwk.getJSONArray("x5c").getString(0);
    final byte[] decode = Base64.getDecoder().decode(certString);
    final CertificateFactory certFactory =
        CertificateFactory.getInstance("X.509", BOUNCY_CASTLE_PROVIDER);
    final InputStream in = new ByteArrayInputStream(decode);
    return (X509Certificate) certFactory.generateCertificate(in);
  }

  @SneakyThrows
  public static PublicKey getPublicKeyFromContextKey(final String key) {
    final JSONObject jwk = new JSONObject(Context.get().get(key).toString());
    return getPublicKeyFromJWK(jwk);
  }

  @SneakyThrows
  public static PublicKey getPublicKeyFromJWK(final JSONObject jwk) {
    if (!jwk.has("x5c")) {
      assertThat(jwk.getString("kty")).isEqualTo("EC");
      assertThat(jwk.getString("crv")).isEqualTo("BP-256");
      final java.security.spec.ECPoint ecPoint =
          new java.security.spec.ECPoint(
              new BigInteger(1, Base64.getUrlDecoder().decode(jwk.getString("x"))),
              new BigInteger(1, Base64.getUrlDecoder().decode(jwk.getString("y"))));

      final ECPublicKeySpec keySpec = new ECPublicKeySpec(ecPoint, BrainpoolCurves.BP256);
      return KeyFactory.getInstance("EC").generatePublic(keySpec);
    } else {
      final String certString = jwk.getJSONArray("x5c").getString(0);
      final byte[] decode = Base64.getDecoder().decode(certString);
      final CertificateFactory certFactory =
          CertificateFactory.getInstance("X.509", BOUNCY_CASTLE_PROVIDER);
      final InputStream in = new ByteArrayInputStream(decode);
      return certFactory.generateCertificate(in).getPublicKey();
    }
  }

  @SneakyThrows
  public void readPublicKeysFromURIs() {
    pukUriEnc = getPuKFromJSONAttribute(jsonBody.getString("uri_puk_idp_enc"));
    de.gematik.test.bdd.Context.get().put(ContextKey.PUK_ENC, pukUriEnc);
    pukUriSign = getPuKFromJSONAttribute(jsonBody.getString("uri_puk_idp_sig"));
    Context.get().put(ContextKey.PUK_SIGN, pukUriSign);

    pukUriDisc = new JSONObject();
    pukUriDisc.put("x5c", jsonHeader.getJSONArray("x5c"));
    Context.get().put(ContextKey.PUK_DISC, pukUriDisc);
  }

  private JSONObject getPuKFromJSONAttribute(String uri)
      throws JSONException,
          KeyStoreException,
          CertificateException,
          NoSuchAlgorithmException,
          IOException,
          URISyntaxException {
    if (uri.equals("$NULL")) {
      return null;
    } else if (uri.startsWith("http")) {
      log.info("Retrieving key from URI " + uri);
      return new JSONObject(IdpStepsBase.simpleGet(uri).getBody().asString());
    } else {
      final int hash = uri.indexOf("#");
      String certalias = null;
      if (hash != -1) {
        certalias = uri.substring(hash + 1);
        uri = uri.substring(0, hash);
      }
      log.info("Retrieving key from file " + uri);

      final byte[] p12FileContent = FileUtils.readFileToByteArray(new File(new URI(uri).getPath()));

      final KeyStore p12 = KeyStore.getInstance("pkcs12", BOUNCY_CASTLE_PROVIDER);
      p12.load(new ByteArrayInputStream(p12FileContent), "00".toCharArray());
      final Enumeration<String> e = p12.aliases();
      X509Certificate certificate = null;
      while (e.hasMoreElements() && certificate == null) {
        final String alias = e.nextElement();
        if (certalias == null || certalias.equals(alias)) {
          certificate = (X509Certificate) p12.getCertificate(alias);
        }
      }
      assertThat(certificate)
          .withFailMessage("No Certificate found in file '" + uri + "'")
          .isNotNull();

      final JSONObject json = new JSONObject();
      final JSONArray x5c = new JSONArray();
      x5c.put(0, new X509Util().toBase64(certificate));
      json.put("x5c", x5c);
      //noinspection ConstantConditions
      json.put("kid", String.valueOf(certificate.getSerialNumber()));
      json.put("kty", certificate.getPublicKey().getAlgorithm());

      final BCECPublicKey bcecPublicKey = (BCECPublicKey) (certificate.getPublicKey());
      assertThat(((ECNamedCurveParameterSpec) bcecPublicKey.getParameters()).getName())
          .isEqualTo("brainpoolP256r1");
      final ECPoint generator = bcecPublicKey.getQ();
      json.put("crv", "BP-256"); // hard coded as we assert the curve type above
      json.put(
          "x",
          Base64.getUrlEncoder()
              .encodeToString(generator.getAffineXCoord().toBigInteger().toByteArray()));
      json.put(
          "y",
          Base64.getUrlEncoder()
              .encodeToString(generator.getAffineYCoord().toBigInteger().toByteArray()));
      return json;
    }
  }
}
