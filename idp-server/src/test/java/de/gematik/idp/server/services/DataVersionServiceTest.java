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

import static de.gematik.idp.field.ClaimName.AUTHENTICATION_DATA_VERSION;
import static de.gematik.idp.field.ClaimName.PAIRING_DATA_VERSION;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.idp.authentication.JwtBuilder;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.server.data.DeviceInformation;
import de.gematik.idp.server.exceptions.IdpServerException;
import de.gematik.idp.tests.PkiKeyResolver;
import de.gematik.idp.token.JsonWebToken;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(PkiKeyResolver.class)
public class DataVersionServiceTest {

    private final DataVersionService dataVersionService = new DataVersionService();
    private final String ALLOWED_VERSION = "1.0";

    @Test
    public void testDeviceInformationVersionIsAllowed() {
        assertDoesNotThrow(() ->
            dataVersionService.checkDataVersion(
                DeviceInformation.builder().deviceInformationDataVersion(ALLOWED_VERSION).build())
        );
    }

    @Test
    public void testDeviceInformationVersionIsNotAllowed() {
        assertThatThrownBy(() ->
            dataVersionService.checkDataVersion(
                DeviceInformation.builder().deviceInformationDataVersion("1.1").build()))
            .isInstanceOf(IdpServerException.class)
            .hasMessage("DeviceInformation version is not supported!");
    }

    @Test
    public void testDeviceInformationVersionIsNull() {
        assertThatThrownBy(() ->
            dataVersionService.checkDataVersion(
                DeviceInformation.builder().build()))
            .isInstanceOf(IdpServerException.class)
            .hasMessage("DeviceInformation version is not supported!");
    }

    @Test
    public void testDeviceInformationVersionIsEmpty() {
        assertThatThrownBy(() ->
            dataVersionService.checkDataVersion(
                DeviceInformation.builder().deviceInformationDataVersion("").build()))
            .isInstanceOf(IdpServerException.class)
            .hasMessage("DeviceInformation version is not supported!");
    }

    @Test
    public void testSignedAuthDataVersionIsAllowed(
        @PkiKeyResolver.Filename("109500969_X114428530_c.ch.aut-ecc.p12") final PkiIdentity identity) {
        final JsonWebToken webToken = new JwtBuilder().addBodyClaim(AUTHENTICATION_DATA_VERSION,
            ALLOWED_VERSION)
            .setSignerKey(identity.getPrivateKey()).setCertificate(identity.getCertificate())
            .buildJwt();

        assertDoesNotThrow(() ->
            dataVersionService.checkSignedAuthDataVersion(webToken)
        );
    }

    @Test
    public void testSignedAuthDataVersionIsNotAllowed(
        @PkiKeyResolver.Filename("109500969_X114428530_c.ch.aut-ecc.p12") final PkiIdentity identity) {
        final JsonWebToken webToken = new JwtBuilder().addBodyClaim(AUTHENTICATION_DATA_VERSION, "0.1")
            .setSignerKey(identity.getPrivateKey()).setCertificate(identity.getCertificate())
            .buildJwt();
        assertThatThrownBy(() ->
            dataVersionService.checkSignedAuthDataVersion(webToken))
            .isInstanceOf(IdpServerException.class)
            .hasMessage("Authentication data version is not supported!");
    }

    @Test
    public void testSignedAuthDataVersionClaimNotExists(
        @PkiKeyResolver.Filename("109500969_X114428530_c.ch.aut-ecc.p12") final PkiIdentity identity) {
        final JsonWebToken webToken = new JwtBuilder()
            .setSignerKey(identity.getPrivateKey()).setCertificate(identity.getCertificate())
            .buildJwt();

        assertThatThrownBy(() ->
            dataVersionService.checkSignedAuthDataVersion(webToken))
            .isInstanceOf(IdpServerException.class)
            .hasMessage("Authentication data version is not supported!");
    }

    @Test
    public void testSignedAuthDataVersionIsNull(
        @PkiKeyResolver.Filename("109500969_X114428530_c.ch.aut-ecc.p12") final PkiIdentity identity) {
        final JsonWebToken webToken = new JwtBuilder().addBodyClaim(AUTHENTICATION_DATA_VERSION, null)
            .setSignerKey(identity.getPrivateKey()).setCertificate(identity.getCertificate())
            .buildJwt();

        assertThatThrownBy(() ->
            dataVersionService.checkSignedAuthDataVersion(webToken))
            .isInstanceOf(IdpServerException.class)
            .hasMessage("Authentication data version is not supported!");
    }

    @Test
    public void testSignedAuthDataVersionIsEmpty(
        @PkiKeyResolver.Filename("109500969_X114428530_c.ch.aut-ecc.p12") final PkiIdentity identity) {
        final JsonWebToken webToken = new JwtBuilder().addBodyClaim(AUTHENTICATION_DATA_VERSION, "")
            .setSignerKey(identity.getPrivateKey()).setCertificate(identity.getCertificate())
            .buildJwt();

        assertThatThrownBy(() ->
            dataVersionService.checkSignedAuthDataVersion(webToken))
            .isInstanceOf(IdpServerException.class)
            .hasMessage("Authentication data version is not supported!");
    }

    @Test
    public void testSignedPairingDataVersionIsAllowed(
        @PkiKeyResolver.Filename("109500969_X114428530_c.ch.aut-ecc.p12") final PkiIdentity identity) {
        final JsonWebToken webToken = new JwtBuilder().addBodyClaim(PAIRING_DATA_VERSION, "1.0")
            .setSignerKey(identity.getPrivateKey()).setCertificate(identity.getCertificate())
            .buildJwt();

        assertDoesNotThrow(() -> dataVersionService.checkSignedPairingDataVersion(webToken));
    }

    @Test
    public void testCurrentVersion() {
        assertThat(dataVersionService.getCurrentVersion()).isEqualTo("1.0");
    }
}
