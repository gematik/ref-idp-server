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

package de.gematik.idp.client.data;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Builder
@Data
public class DiscoveryDocumentResponse {

  private String authorizationEndpoint;
  private String ssoEndpoint;
  private String tokenEndpoint;
  private String pairingEndpoint;
  private String authPairEndpoint;
  private X509Certificate idpSig;
  private PublicKey idpEnc;
  private X509Certificate discSig;
}
