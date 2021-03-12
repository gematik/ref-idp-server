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

package de.gematik.idp.server.services;

import static de.gematik.idp.IdpConstants.*;
import de.gematik.idp.data.IdpDiscoveryDocument;
import de.gematik.idp.server.controllers.IdpKey;
import de.gematik.idp.server.controllers.KeyInformationController;
import java.time.ZonedDateTime;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class DiscoveryDocumentBuilder {

    private IdpKey idpEnc;
    private IdpKey idpSig;

    public IdpDiscoveryDocument buildDiscoveryDocument(final String serverUrl, final String issuerUrl) {
        final ZonedDateTime currentTime = ZonedDateTime.now();
        return IdpDiscoveryDocument.builder()
            .authorizationEndpoint(serverUrl + BASIC_AUTHORIZATION_ENDPOINT)
            .tokenEndpoint(serverUrl + TOKEN_ENDPOINT)
            .uriDisc(serverUrl + DISCOVERY_DOCUMENT_ENDPOINT)
            .authPairEndpoint(serverUrl + ALTERNATIVE_AUTHORIZATION_ENDPOINT)
            .ssoEndpoint(serverUrl + SSO_ENDPOINT)
            .uriPair(serverUrl + PAIRING_ENDPOINT)
            .grantTypesSupported(new String[]{"authorization_code"})
            .idTokenSigningAlgValuesSupported(new String[]{"BP256R1"})
            .scopesSupported(new String[]{"openid", "e-rezept"})
            .responseTypesSupported(new String[]{"code"})
            .subjectTypesSupported(new String[]{"pairwise"})
            .tokenEndpointAuthMethodsSupported(new String[]{"none"})
            .acrValuesSupported(new String[]{"gematik-ehealth-loa-high"})
            .responseModesSupported(new String[]{"query"})
            .issuer(issuerUrl)
            .jwksUri(serverUrl + "/jwks")
            .exp(currentTime.plusHours(24).toEpochSecond())
            .iat(currentTime.toEpochSecond())
            .uriPukIdpEnc(serverUrl + KeyInformationController.PUK_URI_ENC)
            .uriPukIdpSig(serverUrl + KeyInformationController.PUK_URI_SIG)
            .build();
    }
}
