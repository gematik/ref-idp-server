package de.gematik.idp.client;

import de.gematik.idp.client.data.BiometrieData;
import de.gematik.idp.token.JsonWebToken;
import java.util.List;
import javax.ws.rs.core.HttpHeaders;
import kong.unirest.GenericType;
import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
import lombok.RequiredArgsConstructor;
import org.apache.http.HttpStatus;
import org.springframework.http.MediaType;

@RequiredArgsConstructor
public class BiometrieClient {

    private final String serverUrl;
    private final JsonWebToken accessToken;

    public boolean insertPairing(final BiometrieData biometrieData) {
        final HttpResponse<String> response = Unirest.put(serverUrl)
            .body(biometrieData)
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken.getJwtRawString())
            .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
            .asString();
        return response.getStatus() == HttpStatus.SC_OK;
    }

    public List<BiometrieData> getAllPairingsForKvnr(final String kvnr) {
        final HttpResponse<List<BiometrieData>> response = Unirest
            .get(serverUrl + "/" + kvnr)
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken.getJwtRawString())
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
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken.getJwtRawString())
            .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
            .asString();
        return response.getStatus() == HttpStatus.SC_OK;
    }
}
