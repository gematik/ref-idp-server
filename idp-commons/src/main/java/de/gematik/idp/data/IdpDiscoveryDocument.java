/*
 * Copyright (c) 2021 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.idp.data;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IdpDiscoveryDocument {

    private String authorization_endpoint;
    private String token_endpoint;
    private String issuer;
    private String jwks_uri;
    private long exp;
    private long nbf;
    private long iat;
    private String puk_uri_auth;
    private String puk_uri_token;
    private String puk_uri_disc;
    private String[] subject_types_supported;
    private String[] id_token_signing_alg_values_supported;
    private String[] response_types_supported;
    private String[] scopes_supported;
    private String[] response_modes_supported;
    private String[] grant_types_supported;
    private String[] acr_values_supported;
    private String[] token_endpoint_auth_methods_supported;
}
