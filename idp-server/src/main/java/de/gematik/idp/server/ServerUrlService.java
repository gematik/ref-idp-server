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

package de.gematik.idp.server;

import static de.gematik.idp.IdpConstants.DEFAULT_SERVER_URL;

import de.gematik.idp.server.configuration.IdpConfiguration;
import de.gematik.idp.server.services.ServerPortListener;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class ServerUrlService {
  @Autowired private ServerPortListener serverPortListener;

  private final IdpConfiguration idpConfiguration;

  public String determineServerUrlRuntime() {
    return getServerUrlFromConfig().orElse(getServerUrlLocalInstance());
  }

  public String determineServerUrlConfigured() {
    return getServerUrlFromConfig().orElse(DEFAULT_SERVER_URL);
  }

  public String getIssuerUrl() {
    return Optional.ofNullable(idpConfiguration.getIssuerUrl())
        .filter(StringUtils::isNotBlank)
        .or(
            () ->
                Optional.ofNullable(idpConfiguration.getServerUrl())
                    .filter(StringUtils::isNotBlank))
        .orElse(DEFAULT_SERVER_URL);
  }

  private Optional<String> getServerUrlFromConfig() {
    return Optional.ofNullable(idpConfiguration.getServerUrl()).filter(StringUtils::isNotBlank);
  }

  private String getServerRunningPort() {
    return String.valueOf(serverPortListener.getServerPort());
  }

  private String getServerUrlLocalInstance() {
    return "http://localhost:" + getServerRunningPort();
  }
}
