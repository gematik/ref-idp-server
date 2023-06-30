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

package de.gematik.idp.server.configuration;

import de.gematik.idp.data.ScopeConfiguration;
import de.gematik.idp.data.UserConsentConfiguration;
import de.gematik.idp.server.data.IdpClientConfiguration;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties("idp")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class IdpConfiguration {

  private IdpKeyConfiguration idpSig;
  private IdpKeyConfiguration idpEnc;
  private IdpKeyConfiguration discSig;
  private String symmetricEncryptionKey;
  private String fedAuthEndpoint;
  private String serverUrl;
  private String issuerUrl;
  private String version;
  private String redirectUri;
  private String loglevel;
  private String subjectSaltValue;
  private List<String> blockedClientSystems;
  private String productTypeDisplayString;
  private Locale defaultLocale;
  private Map<String, IdpClientConfiguration> registeredClient;
  private UserConsentConfiguration userConsent;
  private IdpErrorConfiguration errors;
  private Map<String, ScopeConfiguration> scopesConfiguration;
}
