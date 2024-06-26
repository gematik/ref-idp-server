/*
 *  Copyright 2023 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.idp.server;

import static de.gematik.idp.IdpConstants.FEDIDP_LIST_ENDPOINT;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.server.data.FedIdpListEntry;
import de.gematik.idp.token.JsonWebToken;
import java.util.List;
import kong.unirest.core.HttpResponse;
import kong.unirest.core.Unirest;
import kong.unirest.core.UnirestException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class FederationIdpListControllerTest {

  @LocalServerPort private int localServerPort;
  private String testHostUrl;

  @BeforeAll
  public static void beforeAll() {
    Unirest.config().reset();
    Unirest.config().followRedirects(false);
  }

  @BeforeEach
  public void setUpLocalHostUrl() {
    testHostUrl = "http://localhost:" + localServerPort;
  }

  @Test
  void testGetFedIdpList() throws UnirestException {
    final HttpResponse<String> httpResponse = retrieveFedIdpList();
    final JsonWebToken fedIdpListJwt = new JsonWebToken(httpResponse.getBody());
    assertThat(httpResponse.isSuccess()).isTrue();
    assertThat(fedIdpListJwt.getBodyClaims().keySet()).containsExactlyInAnyOrder("fed_idp_list");
    Assertions.assertDoesNotThrow(
        () -> ((List<FedIdpListEntry>) fedIdpListJwt.getBodyClaims().get("fed_idp_list")));
  }

  private HttpResponse<String> retrieveFedIdpList() {
    return Unirest.get(testHostUrl + FEDIDP_LIST_ENDPOINT).asString();
  }
}
