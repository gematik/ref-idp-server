/*
 * Copyright (c) 2023 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.idp.test.steps.helpers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.fail;

import de.gematik.idp.crypto.CryptoLoader;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.test.steps.model.DiscoveryDocument;
import de.gematik.test.bdd.Context;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;
import java.util.Map.Entry;
import java.util.Objects;
import lombok.SneakyThrows;
import org.apache.commons.collections.IteratorUtils;
import org.assertj.core.api.Assertions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class KeyAndCertificateStepsHelper {

  public KeyAndCertificateStepsHelper() {}

  public X509Certificate readCertFrom(final String certFile, final String password)
      throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
    final InputStream is;
    if (certFile.startsWith("file://")) {
      is = new FileInputStream(certFile.substring("file://".length()));
    } else {
      is = getClass().getResourceAsStream(certFile);
    }
    Assertions.assertThat(is)
        .withFailMessage("Unable to locate cert resource '" + certFile + "'")
        .isNotNull();
    final KeyStore keyStore = KeyStore.getInstance("pkcs12", new BouncyCastleProvider());
    try (final ByteArrayInputStream bis =
        new ByteArrayInputStream(Objects.requireNonNull(is).readAllBytes())) {
      keyStore.load(bis, password.toCharArray());
    }
    return (X509Certificate) keyStore.getCertificate(keyStore.aliases().nextElement());
  }

  public Key readPrivateKeyFromKeyStore(final String keyStoreFileName, final String password)
      throws IOException {
    final InputStream is;
    if (keyStoreFileName.startsWith("file://")) {
      is = new FileInputStream(keyStoreFileName.substring("file://".length()));
    } else {
      is = getClass().getResourceAsStream(keyStoreFileName);
    }
    Assertions.assertThat(is)
        .withFailMessage("Unable to locate key resource '" + keyStoreFileName + "'")
        .isNotNull();
    final PkiIdentity pkiIdentity =
        CryptoLoader.getIdentityFromP12(Objects.requireNonNull(is).readAllBytes(), password);
    return pkiIdentity.getPrivateKey();
  }

  @SneakyThrows
  public PrivateKey readPrivatKeyFromPkcs8(final String keyFile) {
    final InputStream is;
    if (keyFile.startsWith("file://")) {
      is = new FileInputStream(keyFile.substring("file://".length()));
    } else {
      is = getClass().getResourceAsStream(keyFile);
    }
    Assertions.assertThat(is)
        .withFailMessage("Unable to locate key resource '" + keyFile + "'")
        .isNotNull();
    final PKCS8EncodedKeySpec privKeySpec =
        new PKCS8EncodedKeySpec(Objects.requireNonNull(is).readAllBytes());
    final KeyFactory factory = KeyFactory.getInstance("EC");
    return factory.generatePrivate(privKeySpec);
  }

  @SneakyThrows
  public SubjectPublicKeyInfo readSubjectPublicKeyInfoFromPem(final String keyFile) {
    final InputStream is;
    if (keyFile.startsWith("file://")) {
      is = new FileInputStream(keyFile.substring("file://".length()));
    } else {
      is = getClass().getResourceAsStream(keyFile);
    }
    final PEMParser pemParser = new PEMParser(new InputStreamReader(Objects.requireNonNull(is)));
    return SubjectPublicKeyInfo.getInstance(pemParser.readObject());
  }

  @SafeVarargs
  @SneakyThrows
  public final String encrypt(
      final String payload, final Key puk, final Entry<String, Object>... additionalHeaderValues) {
    final JsonWebEncryption jwe = new JsonWebEncryption();
    jwe.setPlaintext(payload);
    if (puk instanceof PublicKey) {
      jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.ECDH_ES);
    } else {
      jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.DIRECT);
    }
    jwe.setContentTypeHeaderValue("NJWT");
    jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_256_GCM);
    jwe.setKey(puk);
    for (final Entry<String, Object> entry : additionalHeaderValues) {
      if (entry != null) {
        jwe.setHeader(entry.getKey(), entry.getValue());
      }
    }
    return jwe.getCompactSerialization();
  }

  @SneakyThrows
  public String decryptAndExtractNjwt(final String payload, final Key puk) {
    return new JSONObject(decrypt(payload, puk)).getString("njwt");
  }

  @SneakyThrows
  public String decrypt(final String payload, final Key puk) {
    final JsonWebEncryption receiverJwe = new JsonWebEncryption();

    receiverJwe.setAlgorithmConstraints(
        new AlgorithmConstraints(
            ConstraintType.PERMIT,
            KeyManagementAlgorithmIdentifiers.DIRECT,
            KeyManagementAlgorithmIdentifiers.ECDH_ES));
    receiverJwe.setContentEncryptionAlgorithmConstraints(
        new AlgorithmConstraints(
            ConstraintType.PERMIT, ContentEncryptionAlgorithmIdentifiers.AES_256_GCM));

    receiverJwe.setCompactSerialization(payload);
    receiverJwe.setKey(puk);
    return receiverJwe.getPlaintextString();
  }

  public void assertJWTIsSignedWithCertificate(final String jwt, final Certificate cert) {
    final PublicKey publicKey = cert.getPublicKey();
    final JwtConsumer jwtConsumer =
        new JwtConsumerBuilder()
            .setVerificationKey(publicKey)
            .setSkipDefaultAudienceValidation()
            .build();
    try {
      jwtConsumer.process(jwt).getJwtClaims().getClaimsMap();
    } catch (final InvalidJwtException ije) {
      fail("Checking signature failed", ije);
    }
  }

  public void assertContextIsSignedWithCertificate(final String key, final String certName)
      throws CertificateException, JSONException {
    final Certificate cert =
        DiscoveryDocument.getCertificateFromJWK((JSONObject) Context.get().get(certName));
    assertJWTIsSignedWithCertificate(Context.get().get(key).toString(), cert);
  }

  @SneakyThrows
  public void jsonObjectShouldBeValidCertificate(final JSONObject jsonObject) {
    final X509Certificate cert = DiscoveryDocument.getCertificateFromJWK(jsonObject);

    // check for self signed
    assertThatThrownBy(() -> cert.verify(cert.getPublicKey()))
        .isInstanceOf(SignatureException.class);
    assertThat(cert.getSubjectX500Principal().getName()).isNotEqualTo(cert.getIssuerDN().getName());

    // TODO pkilib check revocation of cert once pkilib is able to do it

    // check for outdated
    cert.checkValidity(new Date());
  }

  @SneakyThrows
  public void jsonArrayPathShouldContainValidCertificatesWithKeyId(
      final String arrStr, final String keyid) {
    final JSONObject json = new JSONObject(Context.getCurrentResponse().getBody().asString());
    assertThat(IteratorUtils.toArray(json.keys())).contains(arrStr);
    assertThat(json.get(arrStr)).isInstanceOf(JSONArray.class);
    final JSONArray jarr = json.getJSONArray(arrStr);
    for (int i = 0; i < jarr.length(); i++) {
      final JSONObject jsonCert = jarr.getJSONObject(i);
      if (jsonCert.getString("kid").equals(keyid)) {
        jsonObjectShouldBeValidCertificate(jsonCert);
      }
    }
  }

  public void jsonObjectShouldBeValidPublicKey(final JSONObject jsonObject) {
    DiscoveryDocument.getPublicKeyFromJWK(jsonObject);
  }
}
