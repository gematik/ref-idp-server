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

package de.gematik.idp.server;

import static de.gematik.idp.IdpConstants.OPENID;
import static de.gematik.idp.IdpConstants.PAIRING;
import static de.gematik.idp.brainPoolExtension.BrainpoolAlgorithmSuiteIdentifiers.BRAINPOOL256_USING_SHA256;
import static de.gematik.idp.crypto.KeyAnalysis.isEcKey;
import static de.gematik.idp.field.ClaimName.AUTHORITY_INFO_ACCESS;
import static de.gematik.idp.field.ClaimName.AUTH_CERT_SUBJECT_PUBLIC_KEY_INFO;
import static de.gematik.idp.field.ClaimName.CERTIFICATE_ISSUER;
import static de.gematik.idp.field.ClaimName.CERTIFICATE_NOT_AFTER;
import static de.gematik.idp.field.ClaimName.CERTIFICATE_SERIALNUMBER;
import static de.gematik.idp.field.ClaimName.DEVICE_PRODUCT;
import static de.gematik.idp.field.ClaimName.KEY_IDENTIFIER;
import static de.gematik.idp.field.ClaimName.PAIRING_DATA_VERSION;
import static de.gematik.idp.field.ClaimName.SE_SUBJECT_PUBLIC_KEY_INFO;
import static de.gematik.idp.field.ClaimName.SIGNATURE_ALGORITHM_IDENTIFIER;
import static de.gematik.idp.field.ClaimName.TYPE;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.jose4j.jws.AlgorithmIdentifiers.RSA_PSS_USING_SHA256;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.TestConstants;
import de.gematik.idp.client.IdpClient;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.exceptions.IdpJoseException;
import de.gematik.idp.server.controllers.IdpKey;
import de.gematik.idp.server.data.DeviceInformation;
import de.gematik.idp.server.data.DeviceType;
import de.gematik.idp.server.data.RegistrationData;
import de.gematik.idp.server.devicevalidation.DeviceValidationData;
import de.gematik.idp.server.devicevalidation.DeviceValidationRepository;
import de.gematik.idp.server.pairing.PairingRepository;
import de.gematik.idp.server.services.PairingService;
import de.gematik.idp.tests.PkiKeyResolver;
import de.gematik.idp.tests.PkiKeyResolver.Filename;
import de.gematik.idp.token.IdpJwe;
import de.gematik.idp.token.JsonWebToken;
import jakarta.transaction.Transactional;
import jakarta.ws.rs.core.HttpHeaders;
import java.security.cert.CertificateEncodingException;
import java.util.Base64;
import java.util.Set;
import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.Unirest;
import kong.unirest.UnirestException;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
@ExtendWith(PkiKeyResolver.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Transactional
class PairingControllerAccessTest {

  private static final String TEST_KVNR_VALID = "X114428530";
  @Autowired private IdpKey idpEnc;
  @Autowired private PairingService pairingService;
  @Autowired private PairingRepository pairingRepository;
  @Autowired private DeviceValidationRepository deviceValidationRepository;
  private IdpClient idpClient;
  private PkiIdentity egkUserIdentity;
  private PkiIdentity rsaUserIdentity;
  private JsonWebToken accessToken;
  @LocalServerPort private int localServerPort;

  @BeforeEach
  public void startup(
      @Filename("109500969_X114428530_c.ch.aut-ecc") final PkiIdentity egkIdentity,
      @PkiKeyResolver.Filename("rsa") final PkiIdentity rsaIdentity) {
    idpClient =
        IdpClient.builder()
            .clientId(TestConstants.CLIENT_ID_E_REZEPT_APP)
            .discoveryDocumentUrl("http://localhost:" + localServerPort + "/discoveryDocument")
            .redirectUrl(TestConstants.REDIRECT_URI_E_REZEPT_APP)
            .build();

    idpClient.initialize();

    egkUserIdentity =
        PkiIdentity.builder()
            .certificate(egkIdentity.getCertificate())
            .privateKey(egkIdentity.getPrivateKey())
            .build();
    rsaUserIdentity =
        PkiIdentity.builder()
            .certificate(rsaIdentity.getCertificate())
            .privateKey(rsaIdentity.getPrivateKey())
            .build();
  }

  @AfterEach
  public void cleanUp() {
    pairingRepository.deleteAll();
    deviceValidationRepository.deleteAll();
  }

  @Test
  void listPairings_noHeaderGiven_expectAccessDenied() throws UnirestException {
    assertThat(
            Unirest.get("http://localhost:" + localServerPort + IdpConstants.PAIRING_ENDPOINT)
                .asString()
                .getStatus())
        .isEqualTo(HttpStatus.FORBIDDEN.value());
  }

  @Test
  void listPairings_placeholderToken_expectAccessDenied() throws UnirestException {
    assertThat(
            Unirest.get("http://localhost:" + localServerPort + IdpConstants.PAIRING_ENDPOINT)
                .header(HttpHeaders.AUTHORIZATION, "Bearer fdsafds.fdsafd.fdsafds")
                .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                .asString()
                .getStatus())
        .isEqualTo(HttpStatus.FORBIDDEN.value());
  }

  @Test
  void listPairings_tokenWithoutPairingScope_expectAccessDenied() throws UnirestException {
    final String accessToken = idpClient.login(egkUserIdentity).getAccessToken().getRawString();

    assertThat(
            Unirest.get("http://localhost:" + localServerPort + IdpConstants.PAIRING_ENDPOINT)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                .asString()
                .getStatus())
        .isEqualTo(HttpStatus.FORBIDDEN.value());
  }

  @Test
  void listPairings_correctToken_expect200() throws UnirestException {
    idpClient.setScopes(Set.of(OPENID, PAIRING));
    accessToken = idpClient.login(egkUserIdentity).getAccessToken();

    assertThat(
            Unirest.get("http://localhost:" + localServerPort + IdpConstants.PAIRING_ENDPOINT)
                .header(HttpHeaders.AUTHORIZATION, buildAccessTokenString())
                .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                .asString()
                .getStatus())
        .isEqualTo(HttpStatus.OK.value());
  }

  @Test
  void insertPairing_correctToken_expect200()
      throws UnirestException, CertificateEncodingException {
    idpClient.setScopes(Set.of(OPENID, PAIRING));
    accessToken = idpClient.login(egkUserIdentity).getAccessToken();
    assertThat(
            Unirest.post("http://localhost:" + localServerPort + IdpConstants.PAIRING_ENDPOINT)
                .field(
                    "encrypted_registration_data",
                    createIdpJweFromRegistrationData(createValidRegistrationData("123")))
                .header(HttpHeaders.AUTHORIZATION, buildAccessTokenString())
                .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .asString()
                .getStatus())
        .isEqualTo(HttpStatus.OK.value());

    assertThat(pairingService.getPairingDtoForIdNumberAndKeyIdentifier(TEST_KVNR_VALID, "123"))
        .isPresent()
        .isNotEmpty();
  }

  private String buildAccessTokenString() {
    return "Bearer "
        + accessToken
            .encryptAsNjwt(idpEnc.getIdentity().getCertificate().getPublicKey())
            .getRawString();
  }

  @Test
  void insertPairing_AlreadyInDb_expect409Conflict()
      throws UnirestException, CertificateEncodingException {
    idpClient.setScopes(Set.of(OPENID, PAIRING));
    accessToken = idpClient.login(egkUserIdentity).getAccessToken();

    Unirest.post("http://localhost:" + localServerPort + IdpConstants.PAIRING_ENDPOINT)
        .field(
            "encrypted_registration_data",
            createIdpJweFromRegistrationData(createValidRegistrationData("abc")))
        .header(HttpHeaders.AUTHORIZATION, buildAccessTokenString())
        .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
        .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        .asString()
        .getStatus();

    final HttpResponse<JsonNode> httpResponse =
        Unirest.post("http://localhost:" + localServerPort + IdpConstants.PAIRING_ENDPOINT)
            .field(
                "encrypted_registration_data",
                createIdpJweFromRegistrationData(createValidRegistrationData("abc")))
            .header(HttpHeaders.AUTHORIZATION, buildAccessTokenString())
            .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
            .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .asJson();

    assertThat(httpResponse.getStatus()).isEqualTo(HttpStatus.CONFLICT.value());
    assertThat(httpResponse.getBody().getObject().keySet().toArray())
        .containsAnyOf(
            "error", "gematik_code", "gematik_timestamp", "gematik_uuid", "gematik_error_text");
  }

  @Test
  void insertPairing_missingData_expect4xxAndValidIdpError()
      throws UnirestException, CertificateEncodingException {
    idpClient.setScopes(Set.of(OPENID, PAIRING));
    accessToken = idpClient.login(egkUserIdentity).getAccessToken();

    final RegistrationData registrationData = createValidRegistrationData("abc");
    registrationData.getDeviceInformation().setName(null);

    final HttpResponse<JsonNode> httpResponse =
        Unirest.post("http://localhost:" + localServerPort + IdpConstants.PAIRING_ENDPOINT)
            .field(
                "encrypted_registration_data", createIdpJweFromRegistrationData(registrationData))
            .header(HttpHeaders.AUTHORIZATION, buildAccessTokenString())
            .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
            .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .asJson();
    assertThat(httpResponse.getStatus()).isEqualTo(HttpStatus.FORBIDDEN.value());
    assertThat(httpResponse.getBody().getObject().keySet().toArray())
        .containsAnyOf(
            "error", "gematik_code", "gematik_timestamp", "gematik_uuid", "gematik_error_text");
  }

  @Test
  void insertPairing_missmatchKvnr_expect400()
      throws UnirestException, CertificateEncodingException {
    idpClient.setScopes(Set.of(OPENID, PAIRING));
    accessToken = idpClient.login(rsaUserIdentity).getAccessToken();

    final HttpResponse<String> httpResponse =
        Unirest.post("http://localhost:" + localServerPort + IdpConstants.PAIRING_ENDPOINT)
            .field(
                "encrypted_registration_data",
                createIdpJweFromRegistrationData(createValidRegistrationData("123")))
            .header(HttpHeaders.AUTHORIZATION, buildAccessTokenString())
            .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
            .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .asString();
    assertThat(httpResponse.getStatus()).isEqualTo(HttpStatus.FORBIDDEN.value());
  }

  @Test
  void deletePairing_valid_expect400() throws UnirestException, CertificateEncodingException {
    idpClient.setScopes(Set.of(OPENID, PAIRING));
    accessToken = idpClient.login(egkUserIdentity).getAccessToken();

    Unirest.post("http://localhost:" + localServerPort + IdpConstants.PAIRING_ENDPOINT)
        .field(
            "encrypted_registration_data",
            createIdpJweFromRegistrationData(createValidRegistrationData("456")))
        .header(HttpHeaders.AUTHORIZATION, buildAccessTokenString())
        .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
        .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        .asString();

    final HttpResponse<String> httpResponse =
        Unirest.delete(
                "http://localhost:" + localServerPort + IdpConstants.PAIRING_ENDPOINT + "/654321")
            .header(HttpHeaders.AUTHORIZATION, buildAccessTokenString())
            .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .asString();
    assertThat(httpResponse.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
  }

  @Test
  void deletePairing_noKeyIdentifier_expect500() throws UnirestException {
    idpClient.setScopes(Set.of(OPENID, PAIRING));
    accessToken = idpClient.login(egkUserIdentity).getAccessToken();

    final HttpResponse<String> httpResponse =
        Unirest.delete("http://localhost:" + localServerPort + IdpConstants.PAIRING_ENDPOINT)
            .header(HttpHeaders.AUTHORIZATION, buildAccessTokenString())
            .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .asString();
    assertThat(httpResponse.getStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR.value());
  }

  private String createIdpJweFromRegistrationData(final RegistrationData registrationData) {
    return IdpJwe.createWithPayloadAndEncryptWithKey(
            registrationData.toJSONString(),
            idpEnc.getIdentity().getCertificate().getPublicKey(),
            "JSON")
        .getRawString();
  }

  private RegistrationData createValidRegistrationData(final String keyIdentifier)
      throws CertificateEncodingException {
    return RegistrationData.builder()
        .authCert(
            Base64.getUrlEncoder().encodeToString(egkUserIdentity.getCertificate().getEncoded()))
        .deviceInformation(createDeviceInformation(createTestDeviceValidationData()))
        .signedPairingData(createSignedPairingData(keyIdentifier).getRawString())
        .registrationDataVersion("1.0")
        .build();
  }

  private JsonWebToken createSignedPairingData(final String keyIdentifier) {
    final JwtClaims claims = new JwtClaims();

    claims.setClaim(
        SE_SUBJECT_PUBLIC_KEY_INFO.getJoseName(),
        java.util.Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(rsaUserIdentity.getCertificate().getPublicKey().getEncoded()));
    if (keyIdentifier != null) {
      claims.setClaim(KEY_IDENTIFIER.getJoseName(), keyIdentifier);
    }
    claims.setClaim(CERTIFICATE_ISSUER.getJoseName(), "gkropre");
    claims.setClaim(CERTIFICATE_NOT_AFTER.getJoseName(), "fdsfdsa");
    claims.setClaim(SIGNATURE_ALGORITHM_IDENTIFIER.getJoseName(), "vjiw");
    claims.setClaim(DEVICE_PRODUCT.getJoseName(), "S8");
    claims.setClaim(CERTIFICATE_SERIALNUMBER.getJoseName(), "321654");
    claims.setClaim(AUTHORITY_INFO_ACCESS.getJoseName(), "blubblab");
    claims.setClaim(
        AUTH_CERT_SUBJECT_PUBLIC_KEY_INFO.getJoseName(),
        java.util.Base64.getEncoder()
            .encodeToString(egkUserIdentity.getCertificate().getPublicKey().getEncoded()));
    claims.setClaim(PAIRING_DATA_VERSION.getJoseName(), "1.0");
    final JsonWebSignature jws = new JsonWebSignature();
    jws.setPayload(claims.toJson());
    jws.setKey(egkUserIdentity.getPrivateKey());
    if (isEcKey(egkUserIdentity.getCertificate().getPublicKey())) {
      jws.setAlgorithmHeaderValue(BRAINPOOL256_USING_SHA256);
    } else {
      jws.setAlgorithmHeaderValue(RSA_PSS_USING_SHA256);
    }
    jws.setHeader(TYPE.getJoseName(), "JWT");

    try {
      return new JsonWebToken(jws.getCompactSerialization());
    } catch (final JoseException e) {
      throw new IdpJoseException(e);
    }
  }

  private DeviceInformation createDeviceInformation(final DeviceValidationData data) {
    final DeviceType deviceType =
        DeviceType.builder()
            .manufacturer(data.getManufacturer())
            .product(data.getProduct())
            .os(data.getOs())
            .osVersion(data.getOsVersion())
            .model("foobarModel")
            .deviceTypeDataVersion("1.0")
            .build();
    return DeviceInformation.builder()
        .deviceType(deviceType)
        .name("TestDevice")
        .deviceInformationDataVersion("1.0")
        .build();
  }

  private DeviceValidationData createTestDeviceValidationData() {
    return DeviceValidationData.builder()
        .product("S8")
        .manufacturer("Samsung")
        .os("Android")
        .osVersion("11")
        .build();
  }
}
