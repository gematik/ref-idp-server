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

import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.server.configuration.IdpConfiguration;
import de.gematik.idp.tests.Afo;
import javax.ws.rs.core.HttpHeaders;
import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
public class ClientSystemValidationTest {

  @LocalServerPort private int port;
  @Autowired private IdpConfiguration idpConfiguration;

  @AfterAll
  public static void reset() {
    Unirest.config().reset();
  }

  @Test
  @Afo("A_20588")
  @Disabled("Breaks the server build, even though it shouldn't")
  void retrieveWithoutUserAgent_shouldYield403() {
    final String defaultUserAgent =
        Unirest.config().getDefaultHeaders().getFirst(HttpHeaders.USER_AGENT);
    try {
      Unirest.config().setDefaultHeader(HttpHeaders.USER_AGENT, "");

      final HttpResponse<String> response =
          Unirest.get("http://localhost:" + port + IdpConstants.DISCOVERY_DOCUMENT_ENDPOINT)
              .asString();
      assertThat(response.getStatus()).isEqualTo(403);
      assertThat(response.getBody()).contains("No Client-System found in request");
    } finally {
      Unirest.config().setDefaultHeader(HttpHeaders.USER_AGENT, defaultUserAgent);
      Unirest.config().reset();
    }
  }

  @Test
  @Afo("A_20589")
  void retrieveWithBlockeUserAgent_shouldYield403() {
    final HttpResponse<String> response =
        Unirest.get("http://localhost:" + port + IdpConstants.DISCOVERY_DOCUMENT_ENDPOINT)
            .header(HttpHeaders.USER_AGENT, idpConfiguration.getBlockedClientSystems().get(0))
            .asString();
    assertThat(response.getStatus()).isEqualTo(403);
    assertThat(response.getBody()).contains("Given Client-System is blocked");
  }
}
