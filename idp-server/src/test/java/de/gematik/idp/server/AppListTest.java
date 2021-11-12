package de.gematik.idp.server;

import static de.gematik.idp.IdpConstants.APPLIST_ENDPOINT;
import static org.assertj.core.api.Assertions.assertThat;
import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
import kong.unirest.UnirestException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class AppListTest {

    @LocalServerPort
    private int localServerPort;
    private String testHostUrl;

    @BeforeEach
    public void setUpLocalHostUrl() {
        testHostUrl = "http://localhost:" + localServerPort;
    }

    @Test
    public void testGetAppList() throws UnirestException {
        final HttpResponse httpResponse = retrieveAppList();

        assertThat(httpResponse.isSuccess()).isTrue();
    }

    private HttpResponse<String> retrieveAppList() {
        return Unirest.get(testHostUrl + APPLIST_ENDPOINT)
            .asString();
    }
}
