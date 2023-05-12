/*
 * Copyright (c) 2023 gematik GmbH
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

package de.gematik.idp;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class IdpConstants {

  public static final String DISCOVERY_DOCUMENT_ENDPOINT = "/.well-known/openid-configuration";
  public static final String APPLIST_ENDPOINT = "/directory/kk_apps";
  public static final String BASIC_AUTHORIZATION_ENDPOINT = "/sign_response";
  public static final String ALTERNATIVE_AUTHORIZATION_ENDPOINT = "/alt_response";
  public static final String SSO_ENDPOINT = "/sso_response";
  public static final String TOKEN_ENDPOINT = "/token";
  public static final String PAIRING_ENDPOINT = "/pairings";
  public static final String THIRD_PARTY_ENDPOINT = "/extauth";
  public static final String DEFAULT_SERVER_URL = "https://idp.zentral.idp.splitdns.ti-dienste.de";
  public static final String EIDAS_LOA_HIGH = "gematik-ehealth-loa-high";
  public static final int JTI_LENGTH = 16;
  public static final String AMR_FAST_TRACK = "mfa";

  public static final String FED_AUTH_ENDPOINT = "/auth";
  public static final String FED_AUTH_APP_ENDPOINT = "/auth/app";

  public static final String FED_LIST_ENDPOINT = "/federation_list";

  public static final String SEKTORAL_IDP_AUTHORIZATION_ENDPOINT = "/authorization";
  public static final String ENTITY_STATEMENT_ENDPOINT = "/.well-known/openid-federation";

  public static final String IDP_LIST_ENDPOINT = "/.well-known/idp_list";

  public static final String FEDMASTER_FEDERATION_FETCH_ENDPOINT = "/federation_fetch_endpoint";

  public static final String ENTITY_STATEMENT_TYP = "entity-statement+jwt";

  public static final String OPENID = "openid";
  public static final String EREZEPT = "e-rezept";
  public static final String PAIRING = "pairing";
}
