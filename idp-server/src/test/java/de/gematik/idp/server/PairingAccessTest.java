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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.client.BiometrieClient;
import de.gematik.idp.client.IdpClient;
import de.gematik.idp.client.IdpClientRuntimeException;
import de.gematik.idp.client.IdpTokenResult;
import de.gematik.idp.client.data.BiometrieData;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.field.IdpScope;
import de.gematik.idp.server.configuration.IdpConfiguration;
import de.gematik.idp.tests.PkiKeyResolver;
import de.gematik.idp.tests.PkiKeyResolver.Filename;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
@ExtendWith(PkiKeyResolver.class)
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
public class PairingAccessTest {

    @Autowired
    private IdpConfiguration idpConfiguration;
    private IdpClient idpClient;
    private PkiIdentity egkUserIdentity;
    @LocalServerPort
    private int localServerPort;
    private BiometrieClient biometrieClient;

    @BeforeEach
    public void startup(
        @Filename("109500969_X114428530_c.ch.aut-ecc") final PkiIdentity egkIdentity) {
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
        idpClient.setScopes(Set.of(IdpScope.OPENID, IdpScope.PAIRING));
        final IdpTokenResult tokenResponse = idpClient.login(egkUserIdentity);
        biometrieClient = new BiometrieClient(
            "http://localhost:" + localServerPort + IdpConstants.PAIRING_ENDPOINT, tokenResponse.getAccessToken());
    }

    private BiometrieData initBiometrieData(String kvnr) {
        return BiometrieData.builder()
            .kvnr(kvnr)
            .timestampPairing(ZonedDateTime.now().toString())
            .timestampSmartcardAuth(ZonedDateTime.now().plusHours(1).toString())
            .build();
    }

    @Test
    public void shouldWork_PairingActions_withCorrectKvnr() {
        String kvnrOfEgk = "X114428530";
        BiometrieData biometrieData = initBiometrieData(kvnrOfEgk);
        assertThat(biometrieClient.insertPairing(biometrieData)).isTrue();

        List<BiometrieData> allPairingsForKvnr = biometrieClient
            .getAllPairingsForKvnr(kvnrOfEgk);
        assertThat(allPairingsForKvnr).size().isGreaterThan(0);
        assertThat(allPairingsForKvnr.stream().filter(a -> a.getKvnr().equals(kvnrOfEgk))).isNotNull();

        assertThat(biometrieClient.deleteAllPairingsForKvnr(kvnrOfEgk))
            .isTrue();

        assertThat(biometrieClient.getAllPairingsForKvnr(kvnrOfEgk))
            .size().isEqualTo(0);
    }


    @Test
    public void shouldNotWork_PairingActions_withIncorrectKvnr() {
        String kvnrAny = "X123456789";
        BiometrieData biometrieData = initBiometrieData(kvnrAny);
        assertThat(biometrieClient.insertPairing(biometrieData)).isTrue();

        assertThatThrownBy(() -> biometrieClient.getAllPairingsForKvnr(kvnrAny))
            .isInstanceOf(IdpClientRuntimeException.class);

        assertThat(biometrieClient.deleteAllPairingsForKvnr(kvnrAny))
            .isFalse();

        assertThatThrownBy(() -> biometrieClient.getAllPairingsForKvnr(kvnrAny))
            .isInstanceOf(IdpClientRuntimeException.class);
    }
}
