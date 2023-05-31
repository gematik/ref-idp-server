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

import static de.gematik.idp.IdpConstants.DISCOVERY_DOCUMENT_ENDPOINT;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.data.IdpDiscoveryDocument;
import de.gematik.idp.data.IdpJwksDocument;
import de.gematik.idp.data.IdpKeyDescriptor;
import de.gematik.idp.error.IdpErrorType;
import de.gematik.idp.server.ServerUrlService;
import de.gematik.idp.server.exceptions.IdpServerException;
import de.gematik.idp.server.services.DiscoveryDocumentBuilder;
import de.gematik.idp.server.services.ScopeService;
import de.gematik.idp.server.validation.clientSystem.ValidateClientSystem;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class DiscoveryDocumentController {

  private final IdpKey idpSig;
  private final IdpKey idpEnc;
  private final IdpKey discSig;
  private final ObjectMapper objectMapper;
  private final ServerUrlService serverUrlService;
  private final DiscoveryDocumentBuilder discoveryDocumentBuilder;
  private IdpJwtProcessor jwtProcessor;

  private final String cacheControlDiscDoc;

  @Autowired private ScopeService scopeService;

  @PostConstruct
  public void setUp() {
    jwtProcessor = new IdpJwtProcessor(discSig.getIdentity(), discSig.getKeyId());
  }

  @GetMapping("/jwks")
  public IdpJwksDocument getJwks() {
    final List<IdpKey> identities = new ArrayList<>();
    identities.add(idpSig);
    identities.add(idpEnc);
    return IdpJwksDocument.builder()
        .keys(
            identities.stream()
                .map(
                    identity -> {
                      final IdpKeyDescriptor keyDesc =
                          IdpKeyDescriptor.constructFromX509Certificate(
                              identity.getIdentity().getCertificate(),
                              identity.getKeyId(),
                              identity
                                  .getKeyId()
                                  .map(id -> !id.equals("puk_idp_enc"))
                                  .orElse(false));
                      keyDesc.setPublicKeyUse(identity.getUse().orElse(null));
                      return keyDesc;
                    })
                .toList())
        .build();
  }

  @GetMapping(
      value = {
        DISCOVERY_DOCUMENT_ENDPOINT,
        "/discoveryDocument",
        "auth/realms/idp/.well-known/openid-configuration"
      },
      produces = "application/jwt;charset=UTF-8")
  @ValidateClientSystem
  public String getDiscoveryDocument(
      final HttpServletRequest request, final HttpServletResponse response) {
    final String[] scopes = scopeService.getScopes().toArray(new String[0]);
    setNoCacheHeader(response);
    return signDiscoveryDocument(
        discoveryDocumentBuilder.buildDiscoveryDocument(
            serverUrlService.determineServerUrl(request), serverUrlService.getIssuerUrl(), scopes));
  }

  private String signDiscoveryDocument(final IdpDiscoveryDocument discoveryDocument) {
    try {
      return jwtProcessor
          .buildJws(
              objectMapper.writeValueAsString(discoveryDocument),
              Map.ofEntries(Map.entry("typ", "JWT")),
              true)
          .getRawString();
    } catch (final JsonProcessingException e) {
      throw new IdpServerException(
          2100, IdpErrorType.SERVER_ERROR, "Ein Fehler ist aufgetreten", e);
    }
  }

  private void setNoCacheHeader(final HttpServletResponse response) {
    response.setHeader("Cache-Control", cacheControlDiscDoc);
  }
}
