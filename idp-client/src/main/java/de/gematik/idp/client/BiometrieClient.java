package de.gematik.idp.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.idp.client.data.BiometrieData;
import de.gematik.idp.token.JsonWebToken;
import java.util.List;
import javax.ws.rs.core.HttpHeaders;
import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
import org.apache.http.HttpStatus;
import org.springframework.http.MediaType;

public class BiometrieClient {

    private String host;
    private final String accessToken;

    public BiometrieClient(String host, JsonWebToken token) {
        this.host = host;
        this.accessToken = token.getJwtRawString();
    }

    public boolean insertPairing(BiometrieData biometrieData) {
        HttpResponse<String> response = Unirest.put(host)
            .body(biometrieData)
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
            .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
            .asString();
        return response.getStatus() == HttpStatus.SC_OK;
    }

    public List<BiometrieData> getAllPairingsForKvnr(String kvnr) {
        HttpResponse<String> response = Unirest
            .get(host + "/" + kvnr)
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
            .asString();

        if (response.getStatus() != HttpStatus.SC_OK) {
            throw new IdpClientRuntimeException(
                "Unexpected Server-Response " + response.getStatus());
        }
        try {
            ObjectMapper mapper = new ObjectMapper();
            List<BiometrieData> biometrieDataList = mapper.reader()
                .forType(new TypeReference<List<BiometrieData>>() {
                })
                .readValue(response.getBody());
            return biometrieDataList;
        } catch (JsonProcessingException e) {
            throw new IdpClientRuntimeException("error occured: " + e);
        }
    }

    public boolean deleteAllPairingsForKvnr(String kvnr) {
        HttpResponse<String> response = Unirest.delete(host + "/" + kvnr)
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
            .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
            .asString();
        return response.getStatus() == HttpStatus.SC_OK;
    }
}
