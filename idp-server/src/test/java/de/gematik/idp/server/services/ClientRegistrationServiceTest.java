/*
 * Copyright (Date see Readme), gematik GmbH
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
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

package de.gematik.idp.server.services;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.Mockito.when;

import de.gematik.idp.server.configuration.IdpConfiguration;
import de.gematik.idp.server.data.IdpClientConfiguration;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class ClientRegistrationServiceTest {

  private final IdpClientConfiguration clientConfiguration =
      IdpClientConfiguration.builder().redirectUri("eRezeptUrl").returnSsoToken(true).build();

  @Mock private Map<String, IdpClientConfiguration> registeredClient;
  @Mock private IdpConfiguration configuration;
  @InjectMocks private ClientRegistrationService clientRegistrationService;

  @BeforeEach
  public void init() {
    when(configuration.getRegisteredClient()).thenReturn(registeredClient);
  }

  @Test
  void validateClientIdWithNullValue_ExpectCorrectError() {
    when(registeredClient.get(null)).thenReturn(null);
    assertThat(clientRegistrationService.getClientConfiguration(null)).isEmpty();
  }

  @Test
  void validateClientIdWithInvalidValue_ExpectCorrectError() {
    when(registeredClient.get("eRezeptApp")).thenReturn(clientConfiguration);
    assertThat(clientRegistrationService.getClientConfiguration("eRezeptApp"))
        .hasValue(clientConfiguration);
  }
}
