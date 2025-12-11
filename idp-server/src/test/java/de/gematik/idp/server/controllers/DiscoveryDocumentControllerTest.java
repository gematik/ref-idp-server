/*
 * Copyright (Change Date see Readme), gematik GmbH
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

package de.gematik.idp.server.controllers;

import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.crypto.CryptoLoader;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.data.IdpDiscoveryDocument;
import de.gematik.idp.server.ServerUrlService;
import de.gematik.idp.server.exceptions.IdpServerException;
import de.gematik.idp.server.services.DiscoveryDocumentBuilder;
import de.gematik.idp.server.services.ScopeService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.File;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import lombok.SneakyThrows;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.json.JsonMapper;

@ExtendWith(MockitoExtension.class)
class DiscoveryDocumentControllerTest {

  @InjectMocks private DiscoveryDocumentController controller;

  @Mock private ScopeService scopeService;

  @Mock private IdpJwtProcessor jwtProcessor;

  @Mock private ServerUrlService serverUrlService;

  @Mock private IdpKey discSig;
  @Mock private DiscoveryDocumentBuilder discoveryDocumentBuilder;

  @SneakyThrows
  @BeforeEach
  void init() {
    final byte[] p12FileContent =
        FileUtils.readFileToByteArray(
            new File("src/test/resources/833621999741600-2_c.hci.aut-apo-ecc.p12"));
    final PkiIdentity identity = CryptoLoader.getIdentityFromP12(p12FileContent, "00");

    when(discSig.getIdentity()).thenReturn(identity);
    when(discSig.getKeyId()).thenReturn(Optional.of("kid"));
    controller.setUp();
  }

  @Test
  void shouldThrowIdpServerException_whenJacksonSerializationFailsInSignMethod() {
    final HttpServletRequest request = mock(HttpServletRequest.class);
    final HttpServletResponse response = mock(HttpServletResponse.class);

    // Erzeuge ein gültiges Discovery Document, das serialisiert werden soll
    final IdpDiscoveryDocument discoveryDoc = new IdpDiscoveryDocument();

    when(discoveryDocumentBuilder.buildDiscoveryDocument(any(), any(), any(), any()))
        .thenReturn(discoveryDoc);
    when(scopeService.getScopes()).thenReturn(new HashSet<>(List.of("openid", "profile")));

    try (final MockedStatic<JsonMapper> jsonMapperMock = mockStatic(JsonMapper.class)) {
      final JsonMapper.Builder builder = mock(JsonMapper.Builder.class);
      final JsonMapper mapper = mock(JsonMapper.class);

      jsonMapperMock.when(JsonMapper::builder).thenReturn(builder);
      when(builder.build()).thenReturn(mapper);
      when(mapper.writeValueAsString(any(IdpDiscoveryDocument.class)))
          .thenThrow(new JacksonException("Serialization failed") {});

      assertThatThrownBy(() -> controller.getDiscoveryDocument(request, response))
          .isInstanceOf(IdpServerException.class)
          .hasMessageContaining("Ein Fehler ist aufgetreten")
          .hasCauseInstanceOf(JacksonException.class);
    }
  }
}
