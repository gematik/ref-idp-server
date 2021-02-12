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

package de.gematik.idp.server;

import static de.gematik.idp.brainPoolExtension.BrainpoolAlgorithmSuiteIdentifiers.BRAINPOOL256_USING_SHA256;
import static de.gematik.idp.crypto.KeyAnalysis.isEcKey;
import static de.gematik.idp.field.ClaimName.*;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.jose4j.jws.AlgorithmIdentifiers.RSA_PSS_USING_SHA256;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.client.IdpClient;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.exceptions.IdpJoseException;
import de.gematik.idp.field.IdpScope;
import de.gematik.idp.server.configuration.IdpConfiguration;
import de.gematik.idp.server.data.DeviceInformation;
import de.gematik.idp.server.data.DeviceType;
import de.gematik.idp.server.data.RegistrationData;
import de.gematik.idp.server.devicevalidation.DeviceValidationData;
import de.gematik.idp.server.devicevalidation.DeviceValidationRepository;
import de.gematik.idp.server.pairing.PairingRepository;
import de.gematik.idp.server.services.PairingService;
import de.gematik.idp.tests.PkiKeyResolver;
import de.gematik.idp.tests.PkiKeyResolver.Filename;
import de.gematik.idp.token.JsonWebToken;
import java.security.cert.CertificateEncodingException;
import java.time.ZonedDateTime;
import java.util.Set;
import javax.transaction.Transactional;
import javax.ws.rs.core.HttpHeaders;
import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
import kong.unirest.UnirestException;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
@ExtendWith(PkiKeyResolver.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Transactional
public class PairingControllerAccessTest {

    @Autowired
    private IdpConfiguration idpConfiguration;
    @Autowired
    private PairingService pairingService;
    @Autowired
    private PairingRepository pairingRepository;
    @Autowired
    private DeviceValidationRepository deviceValidationRepository;
    private IdpClient idpClient;
    private PkiIdentity egkUserIdentity;
    private PkiIdentity rsaUserIdentity;
    private JsonWebToken accessToken;
    @LocalServerPort
    private int localServerPort;
    private static final String TEST_KVNR_VALID = "X114428530";

    @BeforeEach
    public void startup(@Filename("109500969_X114428530_c.ch.aut-ecc") final PkiIdentity egkIdentity,
        @PkiKeyResolver.Filename("rsa") final PkiIdentity rsaIdentity) {
        idpClient = IdpClient.builder()
            .clientId(IdpConstants.CLIENT_ID)
            .discoveryDocumentUrl("http://localhost:" + localServerPort + "/discoveryDocument")
            .redirectUrl(idpConfiguration.getRedirectUri())
            .build();

        idpClient.initialize();

        egkUserIdentity = PkiIdentity.builder()
            .certificate(egkIdentity.getCertificate())
            .privateKey(egkIdentity.getPrivateKey())
            .build();
        rsaUserIdentity = PkiIdentity.builder()
            .certificate(rsaIdentity.getCertificate())
            .privateKey(rsaIdentity.getPrivateKey())
            .build();
    }

    @Test
    public void listPairings_noHeaderGiven_expectAccessDenied() throws UnirestException {
        assertThat(
            Unirest.get("http://localhost:" + localServerPort + IdpConstants.PAIRING_ENDPOINT)
                .asString().getStatus())
            .isEqualTo(HttpStatus.FORBIDDEN.value());
    }

    @Test
    public void listPairings_placeholderToken_expectAccessDenied() throws UnirestException {
        assertThat(
            Unirest.get("http://localhost:" + localServerPort + IdpConstants.PAIRING_ENDPOINT)
                .header(HttpHeaders.AUTHORIZATION, "Bearer fdsafds.fdsafd.fdsafds")
                .asString().getStatus())
            .isEqualTo(HttpStatus.FORBIDDEN.value());
    }

    @Test
    public void listPairings_tokenWithoutPairingScope_expectAccessDenied() throws UnirestException {
        final String accessToken = idpClient.login(egkUserIdentity).getAccessToken().getRawString();

        assertThat(
            Unirest.get("http://localhost:" + localServerPort + IdpConstants.PAIRING_ENDPOINT)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .asString().getStatus())
            .isEqualTo(HttpStatus.FORBIDDEN.value());
    }

    @Test
    public void listPairings_correctToken_expect200() throws UnirestException {
        idpClient.setScopes(Set.of(IdpScope.OPENID, IdpScope.PAIRING));
        accessToken = idpClient.login(egkUserIdentity).getAccessToken();

        assertThat(
            Unirest.get("http://localhost:" + localServerPort + IdpConstants.PAIRING_ENDPOINT)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken.getRawString())
                .asString().getStatus())
            .isEqualTo(HttpStatus.OK.value());
    }

    @Test
    public void insertPairing_correctToken_expect200() throws UnirestException, CertificateEncodingException {
        idpClient.setScopes(Set.of(IdpScope.OPENID, IdpScope.PAIRING));
        accessToken = idpClient.login(egkUserIdentity).getAccessToken();

        assertThat(Unirest.put("http://localhost:" + localServerPort + IdpConstants.PAIRING_ENDPOINT)
            .body(createValidRegistrationData("abc"))
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken.getRawString())
            .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
            .asString().getStatus())
            .isEqualTo(HttpStatus.OK.value());

        assertThat(pairingService.getPairingDtoForIdNumberAndKeyIdentifier(TEST_KVNR_VALID, "abc"))
            .isPresent()
            .isNotEmpty();
        cleanUp();
    }

    @Test
    public void insertPairing_missmatchKvnr_expect400() throws UnirestException, CertificateEncodingException {
        idpClient.setScopes(Set.of(IdpScope.OPENID, IdpScope.PAIRING));
        accessToken = idpClient.login(rsaUserIdentity).getAccessToken();

        final HttpResponse<String> httpResponse = Unirest
            .put("http://localhost:" + localServerPort + IdpConstants.PAIRING_ENDPOINT)
            .body(createValidRegistrationData("123"))
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken.getRawString())
            .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
            .asString();
        assertThat(httpResponse.getStatus())
            .isEqualTo(HttpStatus.BAD_REQUEST.value());
        cleanUp();
    }

    @Test
    public void deletePairing_valid_expect200() throws UnirestException, CertificateEncodingException {
        idpClient.setScopes(Set.of(IdpScope.OPENID, IdpScope.PAIRING));
        accessToken = idpClient.login(egkUserIdentity).getAccessToken();
        pairingService
            .validateAndInsertPairingData(accessToken, createValidRegistrationData("456"));

        final HttpResponse httpResponse = Unirest
            .delete("http://localhost:" + localServerPort + IdpConstants.PAIRING_ENDPOINT + "/654321")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken.getRawString())
            .asString();
        assertThat(httpResponse.getStatus())
            .isEqualTo(HttpStatus.OK.value());
        cleanUp();
    }

    private RegistrationData createValidRegistrationData(final String keyIdentifier)
        throws CertificateEncodingException {
        return RegistrationData.builder()
            .authenticationCert(java.util.Base64.getEncoder()
                .encodeToString(egkUserIdentity.getCertificate().getEncoded()))
            .deviceInformation(createDeviceInformation(createTestDeviceValidationData()))
            .signedPairingData(createSignedPairingData(keyIdentifier).getRawString())
            .build();
    }

    private JsonWebToken createSignedPairingData(final String keyIdentifier) {
        final JwtClaims claims = new JwtClaims();
        claims.setClaim(PUK_SE_AUT_PUBLIC_KEY.getJoseName(), java.util.Base64.getEncoder()
            .encodeToString(rsaUserIdentity.getCertificate().getPublicKey().getEncoded()));
        claims.setClaim(KEY_IDENTIFIER.getJoseName(), keyIdentifier);
        claims.setClaim(ALGORITHM.getJoseName(), "SHA256");
        claims.setClaim(DEVICE_PRODUCT.getJoseName(), "S8");
        claims.setClaim(PUK_EGK_AUT_CERT_ID.getJoseName(), "321654");
        claims.setClaim(PUK_EGK_AUT_CERT_ISSUER.getJoseName(), "testIssuer");
        claims.setClaim(PUK_EGK_AUT_CERT_NOT_AFTER.getJoseName(), ZonedDateTime.now().plusMinutes(5));
        claims.setClaim(PUK_EGK_AUT_PUBLIC_KEY.getJoseName(), java.util.Base64.getEncoder()
            .encodeToString(egkUserIdentity.getCertificate().getPublicKey().getEncoded()));
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
        final DeviceType deviceType = DeviceType.builder()
            .deviceManufacturer(data.getManufacturer())
            .deviceProduct(data.getProduct())
            .deviceOs(data.getOs())
            .deviceVersion(data.getOsVersion())
            .build();
        return DeviceInformation.builder()
            .deviceType(deviceType)
            .deviceName("TestDevice")
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

    private void cleanUp() {
        pairingRepository.deleteAll();
        deviceValidationRepository.deleteAll();
    }
}
