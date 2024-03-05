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

package de.gematik.idp.server.controllers;

import static de.gematik.idp.IdpConstants.DEFAULT_SERVER_URL;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doReturn;

import de.gematik.idp.server.ServerUrlService;
import de.gematik.idp.server.configuration.IdpConfiguration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class ServerUrlServiceTest {

  @InjectMocks private ServerUrlService serverUrlService;
  @Mock private IdpConfiguration idpConfiguration;

  @Test
  void serverUrlSetInConfiguration_shouldReturnValueForHttpRequestRetrieval() {
    doReturn("FooBar").when(idpConfiguration).getServerUrl();

    assertThat(serverUrlService.determineServerUrlConfigured()).isEqualTo("FooBar");
  }

  @Test
  void serverUrlNotSetInConfiguration_shouldReturnLocalAddress() {
    doReturn(null).when(idpConfiguration).getServerUrl();

    assertThat(serverUrlService.determineServerUrlConfigured()).isEqualTo(DEFAULT_SERVER_URL);
  }

  @Test
  void serverUrlSetInConfiguration_shouldReturnValueForNoParameterRetrieval() {
    doReturn("FooBar").when(idpConfiguration).getServerUrl();

    assertThat(serverUrlService.determineServerUrlConfigured()).isEqualTo("FooBar");
  }

  @Test
  void serverUrlNotSetInConfiguration_shouldReturnPlaceholderForNoParameterRetrieval() {
    doReturn(null).when(idpConfiguration).getServerUrl();

    assertThat(serverUrlService.determineServerUrlConfigured())
        .matches("http[s]?:\\/\\/[\\w-.]*[\\:[\\d]*]?");
  }
}
