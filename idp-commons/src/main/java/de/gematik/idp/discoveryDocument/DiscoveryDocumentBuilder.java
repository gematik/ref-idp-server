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

package de.gematik.idp.discoveryDocument;

import static de.gematik.idp.IdpConstants.*;

import de.gematik.idp.data.IdpDiscoveryDocument;
import java.time.ZonedDateTime;
import lombok.Data;

@Data
public class DiscoveryDocumentBuilder {

    public IdpDiscoveryDocument buildDiscoveryDocument(final String serverUrl) {
        final ZonedDateTime currentTime = ZonedDateTime.now();
        return IdpDiscoveryDocument.builder()
            .authorization_endpoint(serverUrl + AUTHORIZATION_ENDPOINT)
            .token_endpoint(serverUrl + TOKEN_ENDPOINT)
            .grant_types_supported(new String[]{"authorization_code"})
            .id_token_signing_alg_values_supported(new String[]{"BP256R1"})
            .scopes_supported(new String[]{"openid", "e-rezept"})
            .response_types_supported(new String[]{"code"})
            .subject_types_supported(new String[]{"pairwise"})
            .token_endpoint_auth_methods_supported(new String[]{"none"})
            .acr_values_supported(new String[]{"urn:eidas:loa:high"})
            .response_modes_supported(new String[]{"query"})
            .issuer(serverUrl + "/auth/realms/idp")
            .jwks_uri(serverUrl + "/jwks")
            .exp(currentTime.plusHours(24).toEpochSecond())
            .iat(currentTime.toEpochSecond())
            .nbf(currentTime.toEpochSecond())
            .puk_uri_auth(serverUrl + PUK_URI_AUTH)
            .puk_uri_token(serverUrl + PUK_URI_TOKEN)
            .puk_uri_disc(serverUrl + PUK_URI_DISC)
            .build();
    }

}
