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

import static de.gematik.idp.IdpConstants.APPLIST_ENDPOINT;

import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.server.data.KkAppList;
import java.util.Map;
import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class AppListController {

  private final IdpKey discSig;
  private final KkAppList kkAppList;
  private IdpJwtProcessor jwtProcessor;

  @PostConstruct
  public void setUp() {
    jwtProcessor = new IdpJwtProcessor(discSig.getIdentity());
  }

  @GetMapping(value = APPLIST_ENDPOINT, produces = "application/jwt;charset=UTF-8")
  public String getAppList(final HttpServletRequest request) {
    return signAppList(kkAppList.getListAsJson().toString());
  }

  private String signAppList(final String list) {

    return jwtProcessor.buildJws(list, Map.ofEntries(Map.entry("typ", "JWT")), true).getRawString();
  }
}
