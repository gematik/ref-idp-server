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
import static de.gematik.idp.field.ClaimName.AUTHENTICATION_METHODS_REFERENCE;
import static de.gematik.idp.field.ClaimName.DEVICE_MANUFACTURER;
import static de.gematik.idp.field.ClaimName.ID_NUMBER;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;

import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.exceptions.IdpJoseException;
import de.gematik.idp.server.data.PairingDto;
import de.gematik.idp.server.exceptions.IdpServerException;
import de.gematik.idp.tests.PkiKeyResolver;
import de.gematik.idp.token.JsonWebToken;
import java.security.cert.CertificateEncodingException;
import java.time.ZonedDateTime;
import java.util.Base64;
import javax.transaction.Transactional;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
@ExtendWith(PkiKeyResolver.class)
@Transactional
public class SignatureValidationServiceTest {

    @Autowired
    private SignatureValidationService signatureValidationService;
    @Autowired
    private PairingService pairingService;
    private final String KVNR = "X114428530";
    private final String MANUFACTURER = "testManufacturer";

    @Test
    public void validateValidPairingChallenge(
        @PkiKeyResolver.Filename("109500969_X114428530_c.ch.aut-ecc") final PkiIdentity clientIdentity)
        throws CertificateEncodingException {
        createPairingDataEntry(clientIdentity);
        signatureValidationService.validateSignature(createSignedChallenge(clientIdentity, "hwk"));
    }

    @Test
    public void validateInvalidPairingChallenge(
        @PkiKeyResolver.Filename("109500969_X114428530_c.ch.aut-ecc") final PkiIdentity clientIdentity) {
        assertThatThrownBy(
            () -> signatureValidationService.validateSignature(createSignedChallenge(clientIdentity, "hwk")))
            .isInstanceOf(IdpServerException.class);
    }

    @Test
    public void validateInvalidCertChallenge(
        @PkiKeyResolver.Filename("109500969_X114428530_c.ch.aut-ecc") final PkiIdentity clientIdentity) {
        assertThatThrownBy(
            () -> signatureValidationService.validateSignature(createSignedChallenge(clientIdentity, null)))
            .isInstanceOf(IdpJoseException.class);
    }

    private JsonWebToken createSignedChallenge(final PkiIdentity identity, final String amrValue) {
        final JsonWebToken signedChallenge;
        final JwtClaims claims = new JwtClaims();
        claims.setClaim(DEVICE_MANUFACTURER.getJoseName(), MANUFACTURER);
        if (amrValue != null) {
            claims.setClaim(AUTHENTICATION_METHODS_REFERENCE.getJoseName(), amrValue);
        }
        claims.setClaim(ID_NUMBER.getJoseName(), KVNR);
        final JsonWebSignature jsonWebSignature = new JsonWebSignature();
        jsonWebSignature.setAlgorithmHeaderValue(BRAINPOOL256_USING_SHA256);
        jsonWebSignature.setKey(identity.getPrivateKey());
        jsonWebSignature.setHeader("typ", "JWT");
        jsonWebSignature.setHeader("cty", "NJWT");
        jsonWebSignature.setPayload(claims.toJson());
        jsonWebSignature.setCertificateChainHeaderValue(identity.getCertificate());
        try {
            final String compactSerialization = jsonWebSignature.getCompactSerialization();
            signedChallenge = new JsonWebToken(compactSerialization);
        } catch (final JoseException e) {
            throw new RuntimeException(e);
        }
        return signedChallenge;
    }

    private void createPairingDataEntry(final PkiIdentity clientIdentity) throws CertificateEncodingException {
        final PairingDto pairingDto = PairingDto.builder()
            .kvnr(KVNR)
            .deviceBiometry("TouchID")
            .deviceManufacturer(MANUFACTURER)
            .deviceModel("s8")
            .deviceOS("android")
            .deviceName("Peters Fon")
            .deviceVersion("10")
            .pukSeB64(Base64.getEncoder().encodeToString(clientIdentity.getCertificate().getEncoded()))
            .serial("123456789")
            .timestampPairing(ZonedDateTime.now().minusDays(1))
            .timestampSmartcardAuth(ZonedDateTime.now())
            .build();
        pairingService.insertPairing(pairingDto);
    }
}
