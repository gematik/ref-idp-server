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

package de.gematik.idp.data;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class IdpDiscoveryDocument {

  private String authorizationEndpoint;
  private String authPairEndpoint;
  private String ssoEndpoint;
  private String uriPair;
  private String tokenEndpoint;
  private String thirdPartyAuthorizationEndpoint;
  private String federationAuthorizationEndpoint;
  private String uriDisc;
  private String issuer;
  private String jwksUri;
  private long exp;
  private long iat;
  private String uriPukIdpEnc;
  private String uriPukIdpSig;
  private String[] subjectTypesSupported;
  private String[] idTokenSigningAlgValuesSupported;
  private String[] responseTypesSupported;
  private String[] scopesSupported;
  private String[] responseModesSupported;
  private String[] grantTypesSupported;
  private String[] acrValuesSupported;
  private String[] tokenEndpointAuthMethodsSupported;
  private String[] codeChallengeMethodsSupported;
  private String kkAppListUri;
  private String fedIdpListUri;
}
