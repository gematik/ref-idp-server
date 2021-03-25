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

package de.gematik.idp.client;

import de.gematik.idp.client.data.BiometrieData;
import de.gematik.idp.token.JsonWebToken;
import java.util.List;
import javax.ws.rs.core.HttpHeaders;
import kong.unirest.GenericType;
import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
import lombok.Builder;
import lombok.Data;
import org.apache.http.HttpStatus;
import org.springframework.http.MediaType;

@Builder
@Data
public class BiometrieClient {

    private static final String USER_AGENT = "IdP-Client";
    private static final String BEARER = "Bearer ";
    private final String serverUrl;
    private JsonWebToken accessToken;

    public boolean insertPairing(final BiometrieData biometrieData) {
        final HttpResponse<String> response = Unirest.put(serverUrl)
            .field("encrypted_registration_data", biometrieData)
            .header(HttpHeaders.AUTHORIZATION, BEARER + accessToken.getRawString())
            .header(HttpHeaders.USER_AGENT, USER_AGENT)
            .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .asString();
        return response.getStatus() == HttpStatus.SC_OK;
    }

    public List<BiometrieData> getAllPairingsForKvnr(final String kvnr) {
        final HttpResponse<List<BiometrieData>> response = Unirest
            .get(serverUrl + "/" + kvnr)
            .header(HttpHeaders.AUTHORIZATION, BEARER + accessToken.getRawString())
            .header(HttpHeaders.USER_AGENT, USER_AGENT)
            .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
            .asObject(new GenericType<>() {
            });

        if (response.getStatus() != HttpStatus.SC_OK) {
            throw new IdpClientRuntimeException(
                "Unexpected Server-Response " + response.getStatus());
        }

        return response.getBody();
    }

    public boolean deleteAllPairingsForKvnr(final String kvnr) {
        final HttpResponse<String> response = Unirest.delete(serverUrl + "/" + kvnr)
            .header(HttpHeaders.AUTHORIZATION, BEARER + accessToken.getRawString())
            .header(HttpHeaders.USER_AGENT, USER_AGENT)
            .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
            .asString();
        return response.getStatus() == HttpStatus.SC_OK;
    }
}

