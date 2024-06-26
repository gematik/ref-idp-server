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

package de.gematik.idp.server.services;

import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.server.configuration.IdpConfiguration;
import kong.unirest.core.Unirest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ServerVersionInterceptorTest {

  @LocalServerPort private int localServerPort;
  @Autowired private IdpConfiguration idpConfiguration;

  @Test
  void getDiscoveryDocument_shouldHaveVersionHeader() {
    assertThat(
            Unirest.get(
                    "http://localhost:"
                        + localServerPort
                        + IdpConstants.DISCOVERY_DOCUMENT_ENDPOINT)
                .asString()
                .getHeaders()
                .get("Version"))
        .containsExactly(idpConfiguration.getVersion());
  }
}
