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

package de.gematik.idp.server.controllers;

import static de.gematik.idp.IdpConstants.FEDIDP_LIST_ENDPOINT;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.error.IdpErrorType;
import de.gematik.idp.server.data.FederationIdpList;
import de.gematik.idp.server.exceptions.IdpServerException;
import jakarta.annotation.PostConstruct;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Validated
@RequiredArgsConstructor
@Slf4j
public class FederationIdpListController {

  private IdpJwtProcessor jwtProcessor;
  private final ObjectMapper objectMapper;
  private final FederationIdpList federationIdpList;
  private final IdpKey discSig;

  @PostConstruct
  public void setUp() {
    jwtProcessor = new IdpJwtProcessor(discSig.getIdentity(), discSig.getKeyId());
  }

  @GetMapping(value = FEDIDP_LIST_ENDPOINT, produces = "application/jwt;charset=UTF-8")
  public String getAllFedIdpEntries() {
    return signFedIdpList(federationIdpList);
  }

  private String signFedIdpList(final FederationIdpList federationIdpList) {
    try {
      return jwtProcessor
          .buildJws(
              objectMapper.writeValueAsString(federationIdpList),
              Map.ofEntries(Map.entry("typ", "JWT")),
              true)
          .getRawString();
    } catch (final JsonProcessingException e) {
      throw new IdpServerException(
          2100, IdpErrorType.SERVER_ERROR, "Ein Fehler ist aufgetreten", e);
    }
  }
}
