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

package de.gematik.idp.server.controllers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

import de.gematik.idp.server.ServerUrlService;
import de.gematik.idp.server.configuration.IdpConfiguration;
import javax.servlet.http.HttpServletRequest;
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
  void serverUrlSetInYaml_shouldReturnValueForHttpRequestRetrieval() {
    doReturn("FooBar").when(idpConfiguration).getServerUrl();

    assertThat(serverUrlService.determineServerUrl(mock(HttpServletRequest.class)))
        .isEqualTo("FooBar");
  }

  @Test
  void serverUrlNotSetInYaml_shouldReturnRequestValueForHttpRequestRetrieval() {
    doReturn(null).when(idpConfiguration).getServerUrl();

    final HttpServletRequest servletRequest = mock(HttpServletRequest.class);
    doReturn("server").when(servletRequest).getServerName();
    doReturn(666).when(servletRequest).getServerPort();
    assertThat(serverUrlService.determineServerUrl(servletRequest)).isEqualTo("http://server:666");
  }

  @Test
  void serverUrlSetInYaml_shouldReturnValueForNoParameterRetrieval() {
    doReturn("FooBar").when(idpConfiguration).getServerUrl();

    assertThat(serverUrlService.determineServerUrl()).isEqualTo("FooBar");
  }

  @Test
  void serverUrlNotSetInYaml_shouldReturnPlaceholderForNoParameterRetrieval() {
    doReturn(null).when(idpConfiguration).getServerUrl();

    assertThat(serverUrlService.determineServerUrl())
        .matches("http[s]?:\\/\\/[\\w-.]*[\\:[\\d]*]?");
  }
}
