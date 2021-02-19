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

package de.gematik.idp.server.services;

import static de.gematik.idp.brainPoolExtension.BrainpoolAlgorithmSuiteIdentifiers.BRAINPOOL256_USING_SHA256;
import static de.gematik.idp.crypto.KeyAnalysis.isEcKey;
import static de.gematik.idp.field.ClaimName.*;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.jose4j.jws.AlgorithmIdentifiers.RSA_PSS_USING_SHA256;

import de.gematik.idp.crypto.X509ClaimExtraction;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.exceptions.IdpJoseException;
import de.gematik.idp.server.data.DeviceInformation;
import de.gematik.idp.server.data.DeviceType;
import de.gematik.idp.server.data.PairingDto;
import de.gematik.idp.server.exceptions.IdpServerException;
import de.gematik.idp.tests.PkiKeyResolver;
import de.gematik.idp.tests.PkiKeyResolver.Filename;
import de.gematik.idp.token.JsonWebToken;
import java.security.cert.CertificateEncodingException;
import java.time.ZonedDateTime;
import java.util.Map;
import javax.transaction.Transactional;
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
public class ChallengeTokenValidationServiceTest {

    @Autowired
    private ChallengeTokenValidationService challengeTokenValidationService;
    @Autowired
    private PairingService pairingService;
    private static final String testDeviceName = "Peters Fon";
    private static final String testKeyIdentifier = "654321";
    private PkiIdentity egkIdentity;
    private PkiIdentity altIdentity;

    @BeforeEach
    public void startup(@Filename("109500969_X114428530_c.ch.aut-ecc") final PkiIdentity egkIdentity,
        @PkiKeyResolver.Filename("833621999741600_c.hci.aut-apo-ecc") final PkiIdentity rsaIdentity) {
        this.egkIdentity = PkiIdentity.builder()
            .certificate(egkIdentity.getCertificate())
            .privateKey(egkIdentity.getPrivateKey())
            .build();
        altIdentity = PkiIdentity.builder()
            .certificate(rsaIdentity.getCertificate())
            .privateKey(rsaIdentity.getPrivateKey())
            .build();
    }

    @Test
    public void validateValidPairingChallenge()
        throws CertificateEncodingException {
        createPairingDataEntry();
        challengeTokenValidationService
            .validateChallengeToken(createSignedAuthenticationData(egkIdentity, altIdentity, "hwk"));
    }

    @Test
    public void validateInvalidPairingChallenge(
        @PkiKeyResolver.Filename("109500969_X114428530_c.ch.aut-ecc") final PkiIdentity egkIdentity,
        @PkiKeyResolver.Filename("833621999741600_c.hci.aut-apo-ecc") final PkiIdentity authModuleIdentity) {
        assertThatThrownBy(
            () -> challengeTokenValidationService
                .validateChallengeToken(createSignedAuthenticationData(egkIdentity, authModuleIdentity, "hwk")))
            .isInstanceOf(IdpServerException.class);
    }

    @Test
    public void validateInvalidCertChallenge(
        @PkiKeyResolver.Filename("109500969_X114428530_c.ch.aut-ecc") final PkiIdentity egkIdentity,
        @PkiKeyResolver.Filename("833621999741600_c.hci.aut-apo-ecc") final PkiIdentity authModuleIdentity) {
        assertThatThrownBy(
            () -> challengeTokenValidationService
                .validateChallengeToken(createSignedAuthenticationData(egkIdentity, authModuleIdentity, null)))
            .isInstanceOf(IdpJoseException.class);
    }

    private JsonWebToken createSignedAuthenticationData(final PkiIdentity egkIdentity,
        final PkiIdentity authModuleIdentity, final String amrValue)
        throws CertificateEncodingException {

        final JwtClaims authDataClaims = new JwtClaims();
        authDataClaims.setClaim(KEY_IDENTIFIER.getJoseName(), testKeyIdentifier);
        if (amrValue != null) {
            authDataClaims.setClaim(AUTHENTICATION_METHODS_REFERENCE.getJoseName(), amrValue);
        }
        authDataClaims.setClaim(AUTHENTICATION_CERTIFICATE.getJoseName(),
            java.util.Base64.getEncoder().encodeToString(authModuleIdentity.getCertificate().getEncoded()));
        authDataClaims
            .setClaim(DEVICE_INFORMATION.getJoseName(), createDeviceInformation().toJson());
        return buildSignedJwt(authDataClaims.toJson(), altIdentity);
    }

    private DeviceInformation createDeviceInformation() {
        final DeviceType deviceType = DeviceType.builder()
            .deviceManufacturer("Samsungs")
            .deviceProduct("S8")
            .deviceOs("Android")
            .deviceVersion("14")
            .build();
        return DeviceInformation.builder()
            .deviceType(deviceType)
            .deviceName(testDeviceName)
            .build();
    }

    private void createPairingDataEntry() {
        pairingService.insertPairing(createPairingDtoFromRegistrationData());
    }

    private PairingDto createPairingDtoFromRegistrationData() {
        final Map<String, Object> claimsMap = X509ClaimExtraction
            .extractClaimsFromCertificate(altIdentity.getCertificate());
        return PairingDto.builder()
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
        claims.setClaim(KEY_DATA.getJoseName(), java.util.Base64.getEncoder()
            .encodeToString(altIdentity.getCertificate().getPublicKey().getEncoded()));
        claims.setClaim(KEY_IDENTIFIER.getJoseName(), "654321");
        claims.setClaim(ALGORITHM.getJoseName(), "SHA256");
        claims.setClaim(DEVICE_PRODUCT.getJoseName(), "S8");
        claims.setClaim(CERT_ID.getJoseName(),
            "1.2.840.10045.4.3.2347338df949aad79ed9db17cad14ad2658c5f2b1c2a1b026b30d324a8b7d4c84115d4e3bd55896bc257423680229794");
        claims.setClaim(PUBLIC_KEY.getJoseName(), java.util.Base64.getEncoder()
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
