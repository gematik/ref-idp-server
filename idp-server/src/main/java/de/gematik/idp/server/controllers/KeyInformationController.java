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

package de.gematik.idp.server.controllers;

import de.gematik.idp.data.IdpKeyDescriptor;
import de.gematik.idp.server.validation.ValidateClientSystem;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Api(tags = {
    "Schlüssel-Informations-Dienst"}, description = "REST Endpunkte für das einholen von Schlüssel-Informationen zur Authentifizierung, zur Tokenabfrage und für die öffentlichen Verzeichnisdienste")
@RequiredArgsConstructor
public class KeyInformationController {

    public static final String PUK_URI_AUTH = "/authKey/jwks.json";
    public static final String PUK_URI_TOKEN = "/tokenKey/jwks.json";
    public static final String PUK_URI_DISC = "/discKey/jwks.json";
    private final IdpKey authKey;
    private final IdpKey tokenKey;
    private final IdpKey discKey;

    @GetMapping(PUK_URI_AUTH)
    @ApiOperation(httpMethod = "GET", value = "Endpunkt für Schlüsselinformationen für den Authentifizierungsprozess", notes = "Verbaut Schlüsselinformationen in ein JwksDocument und liefert dieses zurück.")
    @ValidateClientSystem
    public IdpKeyDescriptor getAuthJwks() {
        return authKey.buildJwk();
    }

    @GetMapping(PUK_URI_TOKEN)
    @ApiOperation(httpMethod = "GET", value = "Endpunkt für Schlüsselinformationen für die Tokenabfrage", notes = "Verbaut Schlüsselinformationen in ein JwksDocument und liefert dieses zurück.")
    @ValidateClientSystem
    public IdpKeyDescriptor getTokenJwks() {
        return tokenKey.buildJwk();
    }

    @GetMapping(PUK_URI_DISC)
    @ApiOperation(httpMethod = "GET", value = "Endpunkt für Schlüsselinformationen für den öffentlichen Verzeichnisdienst", notes = "Verbaut Schlüsselinformationen in ein JwksDocument und liefert dieses zurück.")
    @ValidateClientSystem
    public IdpKeyDescriptor getDiscJwks() {
        return discKey.buildJwk();
    }
}
