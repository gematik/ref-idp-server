/*
 * Copyright (c) 2022 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AppListTest {

    @LocalServerPort
    private int localServerPort;
    private String testHostUrl;

    @BeforeEach
    public void setUpLocalHostUrl() {
        testHostUrl = "http://localhost:" + localServerPort;
    }

    @Test
    void testGetAppList() throws UnirestException {
        final HttpResponse httpResponse = retrieveAppList();

        assertThat(httpResponse.isSuccess()).isTrue();
    }

    private HttpResponse<String> retrieveAppList() {
        return Unirest.get(testHostUrl + APPLIST_ENDPOINT)
            .asString();
    }
}
