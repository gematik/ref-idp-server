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

import static de.gematik.idp.brainPoolExtension.BrainpoolAlgorithmSuiteIdentifiers.BRAINPOOL256_USING_SHA256;

import de.gematik.idp.field.ClaimName;
import de.gematik.idp.test.steps.model.DiscoveryDocument;
import de.gematik.idp.test.steps.model.HttpMethods;
import de.gematik.idp.test.steps.model.HttpStatus;
import de.gematik.idp.token.JsonWebToken;
import de.gematik.test.bdd.Context;
import de.gematik.test.bdd.ContextKey;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import java.security.Key;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.chrono.ChronoZonedDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.jetbrains.annotations.NotNull;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.json.JSONArray;
import org.json.JSONObject;

@Slf4j
public class IdpBiometricsSteps extends IdpStepsBase {

  @SneakyThrows
  public void signPairingData(final String keyfile) {
    final Key pkey = keyAndCertificateStepsHelper.readPrivateKeyFromKeyStore(keyfile, "00");
    final Certificate cert = keyAndCertificateStepsHelper.readCertFrom(keyfile, "00");
    final Map<String, Object> pairingData = Context.get().getObjectMapCopy(ContextKey.PAIRING_DATA);

    pairingData.putIfAbsent("pairing_data_version", "1.0");
    if (pairingData.get("key_identifier") != null) {
      pairingData.put(
          "key_identifier", normalizeKeyIdentifier(pairingData.get("key_identifier").toString()));
    }

    final AtomicReference<X509Certificate> authCertificate = new AtomicReference<>();
    if (pairingData.get("auth_cert_subject_public_key_info") != null) {
      authCertificate.set(
          keyAndCertificateStepsHelper.readCertFrom(
              pairingData.get("auth_cert_subject_public_key_info").toString(), "00"));
      final PublicKey pubKey = authCertificate.get().getPublicKey();
      pairingData.put(
          "auth_cert_subject_public_key_info",
          Base64.encodeBase64URLSafeString(pubKey.getEncoded()));
    }
    if (pairingData.get("se_subject_public_key_info") != null) {
      final SubjectPublicKeyInfo pubKeyKeyData =
          keyAndCertificateStepsHelper.readSubjectPublicKeyInfoFromPem(
              pairingData.get("se_subject_public_key_info").toString());
      pairingData.put(
          "se_subject_public_key_info",
          Base64.encodeBase64URLSafeString(pubKeyKeyData.getEncoded()));
    }
    if ("$FILL_FROM_CERT".equals(pairingData.get("serialnumber"))) {
      pairingData.put("serialnumber", extractSerialNumberFromCertificate(authCertificate.get()));
    }
    if ("$FILL_FROM_CERT".equals(pairingData.get("issuer"))) {
      pairingData.put(
          "issuer",
          Base64.encodeBase64URLSafeString(
              authCertificate.get().getIssuerX500Principal().getEncoded()));
    }
    if ("$FILL_FROM_CERT".equals(pairingData.get("not_after"))) {
      pairingData.put(
          "not_after", authCertificate.get().getNotAfter().toInstant().getEpochSecond());
    } else if (pairingData.get("not_after") != null) {
      pairingData.put("not_after", Long.parseLong(pairingData.get("not_after").toString()));
    }

    final JsonWebSignature jsonWebSignature = new JsonWebSignature();
    jsonWebSignature.setPayload(new JSONObject(pairingData).toString());
    jsonWebSignature.setKey(pkey);
    if (cert.getPublicKey().getAlgorithm().equals("EC")) {
      jsonWebSignature.setAlgorithmHeaderValue(BRAINPOOL256_USING_SHA256);
    } else {
      jsonWebSignature.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_PSS_USING_SHA256);
    }
    jsonWebSignature.setHeader("typ", "JWT");
    Context.get().put(ContextKey.SIGNED_PAIRING_DATA, jsonWebSignature.getCompactSerialization());
  }

  public void createAuthenticationData(final Map<String, String> mapFromDatatable) {
    final Map<String, Object> processedMap = new HashMap<>(mapFromDatatable);
    if (processedMap.containsKey("amr") && processedMap.get("amr") != null) {
      processedMap.put("amr", new JSONArray(processedMap.get("amr").toString()));
    }
    Context.get().put(ContextKey.AUTHENTICATION_DATA, processedMap);
  }

  @SneakyThrows
  public void signAuthenticationData(final String keyfile, final String version) {
    final Key pkey = keyAndCertificateStepsHelper.readPrivatKeyFromPkcs8(keyfile);

    final Map<String, Object> authenticationData =
        Context.get().getObjectMapCopy(ContextKey.AUTHENTICATION_DATA);
    authenticationData.put("challenge_token", Context.get().get(ContextKey.CHALLENGE));

    authenticationData.put("device_information", createDeviceInfoJSON());
    if (authenticationData.get("auth_cert") != null) {
      final String certFile = authenticationData.get("auth_cert").toString();
      final Certificate cert = keyAndCertificateStepsHelper.readCertFrom(certFile, "00");
      authenticationData.put("auth_cert", Base64.encodeBase64URLSafeString(cert.getEncoded()));
    }
    authenticationData.putIfAbsent("authentication_data_version", version);
    if (authenticationData.get("key_identifier") != null) {
      authenticationData.put(
          "key_identifier",
          normalizeKeyIdentifier(authenticationData.get("key_identifier").toString()));
    }

    final JsonWebSignature jsonWebSignature = new JsonWebSignature();
    jsonWebSignature.setPayload(new JSONObject(authenticationData).toString());
    jsonWebSignature.setKey(pkey);
    jsonWebSignature.setAlgorithmHeaderValue("ES256");
    jsonWebSignature.setHeader("typ", "JWT");
    Context.get()
        .put(ContextKey.SIGEND_AUTHENTICATION_DATA, jsonWebSignature.getCompactSerialization());
  }

  @SneakyThrows
  public void registerDeviceWithCert(final String certFile, final String versionReg) {
    final Certificate cert = keyAndCertificateStepsHelper.readCertFrom(certFile, "00");

    final JSONObject regData = new JSONObject();
    regData.put("signed_pairing_data", Context.get().get(ContextKey.SIGNED_PAIRING_DATA));
    regData.put("auth_cert", Base64.encodeBase64URLSafeString(cert.getEncoded()));
    regData.put("device_information", createDeviceInfoJSON());
    regData.put("registration_data_version", versionReg);

    final Map<String, String> headers = initializeAuthHeaders();
    headers.put("Accept", "application/json;charset=UTF-8");
    headers.put("Content-Type", ContentType.URLENC.withCharset("UTF-8"));

    final PublicKey pukEnc = DiscoveryDocument.getPublicKeyFromContextKey(ContextKey.PUK_ENC);
    Context.get()
        .put(
            ContextKey.RESPONSE,
            requestResponseAndAssertStatus(
                Context.getDiscoveryDocument().getPairingEndpoint(),
                headers,
                HttpMethods.POST,
                null,
                "encrypted_registration_data="
                    + keyAndCertificateStepsHelper.encrypt(
                        regData.toString(), pukEnc, Pair.of("typ", "JWT"), Pair.of("cty", "JSON")),
                HttpStatus.NOCHECK));
  }

  public void requestAllPairings() {
    final Map<String, String> headers = initializeAuthHeaders();
    headers.put("Accept", "application/json;charset=UTF-8");
    Context.get()
        .put(
            ContextKey.RESPONSE,
            requestResponseAndAssertStatus(
                Context.getDiscoveryDocument().getPairingEndpoint(),
                headers,
                HttpMethods.GET,
                null,
                null,
                HttpStatus.NOCHECK));
  }

  @SneakyThrows
  public void deregisterDeviceWithKey(String keyVerifier) {
    final Map<String, String> headers = initializeAuthHeaders();
    if ("$NULL".equals(keyVerifier)) {
      keyVerifier = null;
    } else if ("$REMOVE".equals(keyVerifier)) {
      keyVerifier = "";
    } else {
      keyVerifier = normalizeKeyIdentifier(keyVerifier);
    }
    final Response r =
        requestResponseAndAssertStatus(
            Context.getDiscoveryDocument().getPairingEndpoint() + "/" + keyVerifier,
            headers,
            HttpMethods.DELETE,
            null,
            null,
            HttpStatus.NOCHECK);
    Context.get().put(ContextKey.RESPONSE, r);
  }

  private String normalizeKeyIdentifier(final String rawKeyId) {
    return Base64.encodeBase64URLSafeString(StringUtils.leftPad(rawKeyId, 32).getBytes());
  }

  @SneakyThrows
  private String extractSerialNumberFromCertificate(final X509Certificate certificate) {
    return certificate.getSerialNumber().toString();
  }

  @NotNull
  private JSONObject createDeviceInfoJSON() {
    final Map<String, Object> devTypeInfo = Context.get().getObjectMapCopy(ContextKey.DEVICE_INFO);
    devTypeInfo.remove("name");
    devTypeInfo.remove("device_information_data_version");
    devTypeInfo.putIfAbsent("device_type_data_version", "1.0");

    final Map<String, Object> ctxtDevInfo = Context.get().getObjectMapCopy(ContextKey.DEVICE_INFO);
    ctxtDevInfo.putIfAbsent("device_information_data_version", "1.0");

    final JSONObject devInfo = new JSONObject();
    devInfo.put("name", ctxtDevInfo.get("name"));
    devInfo.put(
        "device_information_data_version", ctxtDevInfo.get("device_information_data_version"));
    devInfo.put("device_type", new JSONObject(devTypeInfo));
    return devInfo;
  }

  @NotNull
  private Map<String, String> initializeAuthHeaders() {
    final Map<String, String> headers = new HashMap<>();
    // TODO where to get exp from
    final Optional<Pair<String, Object>> expHeader =
        extractExpHeader(Context.get().get(ContextKey.ACCESS_TOKEN).toString());
    final String encryptedAccessToken =
        keyAndCertificateStepsHelper.encrypt(
            "{\"njwt\":\"" + Context.get().get(ContextKey.ACCESS_TOKEN) + "\"}",
            DiscoveryDocument.getPublicKeyFromContextKey(ContextKey.PUK_ENC),
            expHeader.get());
    headers.put("Authorization", "Bearer " + encryptedAccessToken);
    return headers;
  }

  private Optional<Pair<String, Object>> extractExpHeader(final String signedChallenge) {
    try {
      return new JsonWebToken(signedChallenge)
          .findExpClaimInNestedJwts()
          .map(ChronoZonedDateTime::toEpochSecond)
          .map(epoch -> Pair.of(ClaimName.EXPIRES_AT.getJoseName(), epoch));
    } catch (final Exception e) {
      return Optional.empty();
    }
  }
}
