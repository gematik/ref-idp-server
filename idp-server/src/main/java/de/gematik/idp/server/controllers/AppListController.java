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

import static de.gematik.idp.IdpConstants.APPLIST_ENDPOINT;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.error.IdpErrorType;
import de.gematik.idp.server.data.KassenAppList;
import de.gematik.idp.server.exceptions.IdpServerException;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class AppListController {

  private final IdpKey discSig;
  private final KassenAppList kassenAppList;
  private final ObjectMapper objectMapper;
  private IdpJwtProcessor jwtProcessor;

  @PostConstruct
  public void setUp() {
    jwtProcessor = new IdpJwtProcessor(discSig.getIdentity());
  }

  @GetMapping(value = APPLIST_ENDPOINT, produces = "application/jwt;charset=UTF-8")
  public String getAppList(final HttpServletRequest request) {
    return signAppList(kassenAppList);
  }

  private String signAppList(final KassenAppList kassenAppList) {
    try {
      return jwtProcessor
          .buildJws(
              objectMapper.writeValueAsString(kassenAppList),
              Map.ofEntries(Map.entry("typ", "JWT")),
              true)
          .getRawString();
    } catch (final JsonProcessingException e) {
      throw new IdpServerException(
          2100, IdpErrorType.SERVER_ERROR, "Ein Fehler ist aufgetreten", e);
    }
  }
}
