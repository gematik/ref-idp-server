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

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.client.IdpClient;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.field.IdpScope;
import de.gematik.idp.server.configuration.IdpConfiguration;
import de.gematik.idp.tests.PkiKeyResolver;
import de.gematik.idp.tests.PkiKeyResolver.Filename;
import java.time.ZonedDateTime;
import java.util.Set;
import javax.ws.rs.core.HttpHeaders;
import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
import kong.unirest.UnirestException;
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
public class PairingControllerAccessTest {

    @Autowired
    private IdpConfiguration idpConfiguration;
    private IdpClient idpClient;
    private PkiIdentity egkUserIdentity;
    @LocalServerPort
    private int localServerPort;

    @BeforeEach
    public void startup(@Filename("109500969_X114428530_c.ch.aut-ecc") final PkiIdentity egkIdentity) {
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
    }

    @Test
    public void listPairings_noHeaderGiven_expectAccessDenied() throws UnirestException {
        assertThat(Unirest.get("http://localhost:" + localServerPort + IdpConstants.PAIRING_ENDPOINT + "/X114428530")
            .asString().getStatus())
            .isEqualTo(HttpStatus.FORBIDDEN.value());
    }

    @Test
    public void listPairings_placeholderToken_expectAccessDenied() throws UnirestException {
        assertThat(Unirest.get("http://localhost:" + localServerPort + IdpConstants.PAIRING_ENDPOINT + "/X114428530")
            .header(HttpHeaders.AUTHORIZATION, "Bearer fdsafds.fdsafd.fdsafds")
            .asString().getStatus())
            .isEqualTo(HttpStatus.FORBIDDEN.value());
    }

    @Test
    public void listPairings_tokenWithoutPairingScope_expectAccessDenied() throws UnirestException {
        final String accessToken = idpClient.login(egkUserIdentity).getAccessToken().getJwtRawString();

        assertThat(Unirest.get("http://localhost:" + localServerPort + IdpConstants.PAIRING_ENDPOINT + "/X114428530")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
            .asString().getStatus())
            .isEqualTo(HttpStatus.FORBIDDEN.value());
    }

    @Test
    public void listPairings_tokenForDifferentKvnr_expectAccessDenied() throws UnirestException {
        idpClient.setScopes(Set.of(IdpScope.OPENID, IdpScope.PAIRING));
        final String accessToken = idpClient.login(egkUserIdentity).getAccessToken().getJwtRawString();

        assertThat(Unirest.get("http://localhost:" + localServerPort + IdpConstants.PAIRING_ENDPOINT + "/X123456789")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
            .asString().getStatus())
            .isEqualTo(HttpStatus.BAD_REQUEST.value());
    }

    @Test
    public void listPairings_correctToken_expect200() throws UnirestException {
        idpClient.setScopes(Set.of(IdpScope.OPENID, IdpScope.PAIRING));
        final String accessToken = idpClient.login(egkUserIdentity).getAccessToken().getJwtRawString();

        assertThat(Unirest.get("http://localhost:" + localServerPort + IdpConstants.PAIRING_ENDPOINT + "/X114428530")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
            .asString().getStatus())
            .isEqualTo(HttpStatus.OK.value());
    }

    @Test
    public void insertPairing_correctToken_expect200() throws UnirestException {
        idpClient.setScopes(Set.of(IdpScope.OPENID, IdpScope.PAIRING));
        final String accessToken = idpClient.login(egkUserIdentity).getAccessToken().getJwtRawString();

        assertThat(Unirest.put("http://localhost:" + localServerPort + IdpConstants.PAIRING_ENDPOINT)
            .body(getPairingBodyForKvnr("X114428530"))
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
            .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
            .asString().getStatus())
            .isEqualTo(HttpStatus.OK.value());
    }

    @Test
    public void insertPairing_missmatchKvnr_expect400() throws UnirestException {
        idpClient.setScopes(Set.of(IdpScope.OPENID, IdpScope.PAIRING));
        final String accessToken = idpClient.login(egkUserIdentity).getAccessToken().getJwtRawString();

        final HttpResponse<String> httpResponse = Unirest
            .put("http://localhost:" + localServerPort + IdpConstants.PAIRING_ENDPOINT)
            .body(getPairingBodyForKvnr("X987654321"))
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
            .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
            .asString();
        assertThat(httpResponse.getStatus())
            .isEqualTo(HttpStatus.OK.value());
    }

    private String getPairingBodyForKvnr(final String kvnr) {
        return "{" +
            "\"kvnr\": \"" + kvnr + "\"," +
            "\"deviceBiometry\": \"TouchID\"," +
            "\"deviceManufacturer\": \"samsung\"," +
            "\"deviceModel\": \"s8\"," +
            "\"deviceOS\": \"android\"," +
            "\"deviceName\": \"Peters Fon\"," +
            "\"deviceVersion\": \"10\"," +
            "\"pukSeB64\": \"132164g6d4gfd35g15311\"," +
            "\"serial\": \"123456789\"," +
            "\"timestampPairing\": \"" + ZonedDateTime.now().minusDays(1).toString() + "\"," +
            "\"timestampSmartcardAuth\": \"" + ZonedDateTime.now().toString() + "\"" +
            "}";
    }
}
