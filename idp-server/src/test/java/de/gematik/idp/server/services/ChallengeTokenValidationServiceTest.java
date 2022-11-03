/*
 * Copyright (c) 2022 gematik GmbH
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

package de.gematik.idp.server.services;

import static de.gematik.idp.brainPoolExtension.BrainpoolAlgorithmSuiteIdentifiers.BRAINPOOL256_USING_SHA256;
import static de.gematik.idp.crypto.KeyAnalysis.isEcKey;
import static de.gematik.idp.field.ClaimName.ALGORITHM;
import static de.gematik.idp.field.ClaimName.AUTHENTICATION_CERTIFICATE;
import static de.gematik.idp.field.ClaimName.AUTHENTICATION_DATA_VERSION;
import static de.gematik.idp.field.ClaimName.AUTHENTICATION_METHODS_REFERENCE;
import static de.gematik.idp.field.ClaimName.AUTH_CERT_SUBJECT_PUBLIC_KEY_INFO;
import static de.gematik.idp.field.ClaimName.CERTIFICATE_SERIALNUMBER;
import static de.gematik.idp.field.ClaimName.DEVICE_INFORMATION;
import static de.gematik.idp.field.ClaimName.DEVICE_PRODUCT;
import static de.gematik.idp.field.ClaimName.ID_NUMBER;
import static de.gematik.idp.field.ClaimName.KEY_IDENTIFIER;
import static de.gematik.idp.field.ClaimName.SE_SUBJECT_PUBLIC_KEY_INFO;
import static de.gematik.idp.field.ClaimName.TYPE;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.jose4j.jws.AlgorithmIdentifiers.RSA_PSS_USING_SHA256;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.idp.crypto.X509ClaimExtraction;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.exceptions.IdpJoseException;
import de.gematik.idp.exceptions.NoNestedJwtFoundException;
import de.gematik.idp.server.data.DeviceInformation;
import de.gematik.idp.server.data.DeviceType;
import de.gematik.idp.server.exceptions.IdpServerException;
import de.gematik.idp.server.pairing.PairingData;
import de.gematik.idp.tests.PkiKeyResolver;
import de.gematik.idp.tests.PkiKeyResolver.Filename;
import de.gematik.idp.token.JsonWebToken;
import java.security.cert.CertificateEncodingException;
import java.time.ZonedDateTime;
import java.util.Map;
import javax.transaction.Transactional;
import lombok.SneakyThrows;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
@ExtendWith(PkiKeyResolver.class)
@Transactional
class ChallengeTokenValidationServiceTest {

  private static final String testDeviceName = "Peters Fon";
  private static final String testKeyIdentifier = "654321";
  @Autowired private ChallengeTokenValidationService challengeTokenValidationService;
  @Autowired private PairingService pairingService;
  private PkiIdentity egkIdentity;
  private PkiIdentity altIdentity;

  @BeforeEach
  public void startup(
      @Filename("109500969_X114428530_c.ch.aut-ecc") final PkiIdentity egkIdentity,
      @PkiKeyResolver.Filename("833621999741600_c.hci.aut-apo-ecc") final PkiIdentity rsaIdentity) {
    this.egkIdentity =
        PkiIdentity.builder()
            .certificate(egkIdentity.getCertificate())
            .privateKey(egkIdentity.getPrivateKey())
            .build();
    altIdentity =
        PkiIdentity.builder()
            .certificate(rsaIdentity.getCertificate())
            .privateKey(rsaIdentity.getPrivateKey())
            .build();
  }

  @Test
  void validateValidPairingChallenge() throws CertificateEncodingException {
    createPairingDataEntry();
    challengeTokenValidationService.validateChallengeToken(
        createSignedAuthenticationData(altIdentity, new String[] {"mfa", "hwk", "face"}));
  }

  @Test
  void validateInvalidPairingChallenge(
      @PkiKeyResolver.Filename("109500969_X114428530_c.ch.aut-ecc") final PkiIdentity egkIdentity,
      @PkiKeyResolver.Filename("833621999741600_c.hci.aut-apo-ecc")
          final PkiIdentity authModuleIdentity) {
    assertThatThrownBy(
            () ->
                challengeTokenValidationService.validateChallengeToken(
                    createSignedAuthenticationData(
                        authModuleIdentity, new String[] {"mfa", "hwk", "face"})))
        .isInstanceOf(IdpServerException.class);
  }

  @Test
  void validateInvalidCertChallenge(
      @PkiKeyResolver.Filename("833621999741600_c.hci.aut-apo-ecc")
          final PkiIdentity authModuleIdentity) {
    assertThatThrownBy(
            () ->
                challengeTokenValidationService.validateChallengeToken(
                    createSignedAuthenticationData(authModuleIdentity, null)))
        .isInstanceOf(NoNestedJwtFoundException.class);
  }

  @SneakyThrows
  private JsonWebToken createSignedAuthenticationData(
      final PkiIdentity authModuleIdentity, final String[] amrValue)
      throws CertificateEncodingException {

    final JwtClaims authDataClaims = new JwtClaims();
    authDataClaims.setClaim(KEY_IDENTIFIER.getJoseName(), testKeyIdentifier);
    if (amrValue != null) {
      authDataClaims.setClaim(AUTHENTICATION_METHODS_REFERENCE.getJoseName(), amrValue);
    }
    authDataClaims.setClaim(
        AUTHENTICATION_CERTIFICATE.getJoseName(),
        java.util.Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(authModuleIdentity.getCertificate().getEncoded()));
    final Map<String, Object> devInfoMap =
        new ObjectMapper().readValue(createDeviceInformation().toJson(), new TypeReference<>() {});
    authDataClaims.setClaim(DEVICE_INFORMATION.getJoseName(), devInfoMap);
    authDataClaims.setClaim(AUTHENTICATION_DATA_VERSION.getJoseName(), "1.0");

    return buildSignedJwt(authDataClaims.toJson(), altIdentity);
  }

  private DeviceInformation createDeviceInformation() {
    final DeviceType deviceType =
        DeviceType.builder()
            .manufacturer("Samsungs")
            .product("S8")
            .os("Android")
            .osVersion("14")
            .deviceTypeDataVersion("1.0")
            .build();
    return DeviceInformation.builder()
        .deviceType(deviceType)
        .name(testDeviceName)
        .deviceInformationDataVersion("1.0")
        .build();
  }

  private void createPairingDataEntry() {
    pairingService.insertPairing(createPairingDtoFromRegistrationData());
  }

  private PairingData createPairingDtoFromRegistrationData() {
    final Map<String, Object> claimsMap =
        X509ClaimExtraction.extractClaimsFromCertificate(altIdentity.getCertificate());
    return PairingData.builder()
        .id(null)
        .idNumber(claimsMap.get(ID_NUMBER.getJoseName()).toString())
        .keyIdentifier(testKeyIdentifier)
        .deviceName(testDeviceName)
        .signedPairingData(createSignedPairingData().getRawString())
        .timestampPairing(ZonedDateTime.now())
        .build();
  }

  private JsonWebToken createSignedPairingData() {
    final JwtClaims claims = new JwtClaims();
    claims.setClaim(
        SE_SUBJECT_PUBLIC_KEY_INFO.getJoseName(),
        java.util.Base64.getUrlEncoder()
            .encodeToString(altIdentity.getCertificate().getPublicKey().getEncoded()));
    claims.setClaim(KEY_IDENTIFIER.getJoseName(), "654321");
    claims.setClaim(ALGORITHM.getJoseName(), "SHA256");
    claims.setClaim(DEVICE_PRODUCT.getJoseName(), "S8");
    claims.setClaim(CERTIFICATE_SERIALNUMBER.getJoseName(), "257423680229794");
    claims.setClaim(
        AUTH_CERT_SUBJECT_PUBLIC_KEY_INFO.getJoseName(),
        java.util.Base64.getUrlEncoder()
            .encodeToString(egkIdentity.getCertificate().getPublicKey().getEncoded()));
    return buildSignedJwt(claims.toJson(), egkIdentity);
  }

  private JsonWebToken buildSignedJwt(final String payload, final PkiIdentity identity) {
    final JsonWebSignature jws = new JsonWebSignature();
    jws.setPayload(payload);
    jws.setKey(identity.getPrivateKey());
    jws.setCertificateChainHeaderValue(identity.getCertificate());
    if (isEcKey(identity.getCertificate().getPublicKey())) {
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
}
