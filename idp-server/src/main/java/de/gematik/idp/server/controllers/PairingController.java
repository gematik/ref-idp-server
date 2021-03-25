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

import static de.gematik.idp.IdpConstants.PAIRING_ENDPOINT;

import de.gematik.idp.server.RequestAccessToken;
import de.gematik.idp.server.data.PairingDto;
import de.gematik.idp.server.data.PairingList;
import de.gematik.idp.server.services.PairingService;
import de.gematik.idp.server.validation.accessToken.ValidateAccessToken;
import de.gematik.idp.server.validation.clientSystem.ValidateClientSystem;
import de.gematik.idp.token.IdpJwe;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import java.util.List;
import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import net.dracoblue.spring.web.mvc.method.annotation.HttpResponseHeader;
import net.dracoblue.spring.web.mvc.method.annotation.HttpResponseHeaders;
import org.springframework.http.MediaType;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@Transactional
@Valid
@Api(tags = {"Pairing-Dienst"})
@HttpResponseHeaders({
    @HttpResponseHeader(name = "Cache-Control", value = "no-store"),
    @HttpResponseHeader(name = "Pragma", value = "no-cache")
})
public class PairingController {

    private final PairingService pairingService;
    private final RequestAccessToken requestAccessToken;

    @GetMapping(value = PAIRING_ENDPOINT, produces = MediaType.APPLICATION_JSON_VALUE)
    @ApiOperation(httpMethod = "GET", value = "Endpunkt für Abrufen der Pairingdaten", notes = "Es werden zur übergebenen KVNR alle Pairingdaten abgerufen.", response = List.class)
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Erfolgreich Pairingdaten erhalten"),
        @ApiResponse(responseCode = "400", description = "Ungültige Anfrage (Parameter fehlen/ungültig)"),
        @ApiResponse(responseCode = "403", description = "Nicht erlaubter Zugriff"),
        @ApiResponse(responseCode = "404", description = "Nicht gefunden - Methodenaufruf nicht korrekt")
    })
    @ValidateClientSystem
    @ValidateAccessToken
    public PairingList getAllPairingsForKvnr() {
        return new PairingList(pairingService.validateTokenAndGetPairingList(requestAccessToken.getAccessToken()));
    }

    @DeleteMapping(value = PAIRING_ENDPOINT + "/{key_identifier}")
    @ApiOperation(httpMethod = "DELETE", value = "Endpunkt zum Löschen eines spezifischen Pairingdatensatzes",
        notes = "Es wird zur übergebenen KVNR und ID der entsprechende Pairingdatensatz gelöscht. ")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Erfolgreich Pairingdaten gelöscht"),
        @ApiResponse(responseCode = "400", description = "Ungültige Anfrage (Parameter fehlen/ungültig)"),
        @ApiResponse(responseCode = "403", description = "Nicht erlaubter Zugriff"),
        @ApiResponse(responseCode = "404", description = "Nicht gefunden - Methodenaufruf nicht korrekt")
    })
    @ValidateAccessToken
    @ValidateClientSystem
    public void deleteSinglePairing(
        @PathVariable(value = "key_identifier") @NotNull(message = "4001") @ApiParam(value = "Key Identifier") final String keyIdentifier
    ) {
        pairingService
            .validateTokenAndDeleteSelectedPairing(requestAccessToken.getAccessToken(), keyIdentifier);
    }

    @PostMapping(value = PAIRING_ENDPOINT, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
        produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    @ApiOperation(httpMethod = "POST", value = "Endpunkt zum Hinzufügen von Pairingdaten",
        notes = "Die hier engereichten Pairingdaten werden in der Pairing-DB hinterlegt. Ist dies erfolgreich, wird die ID für den DB-Eintrag zurückgegeben.")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Erfolgreich Pairingdaten hinzugefügt"),
        @ApiResponse(responseCode = "400", description = "Ungültige Anfrage (Parameter fehlen/ungültig)"),
        @ApiResponse(responseCode = "403", description = "Nicht erlaubter Zugriff"),
        @ApiResponse(responseCode = "404", description = "Nicht gefunden - Methodenaufruf nicht korrekt")
    })
    @ValidateAccessToken
    @ValidateClientSystem
    public PairingDto insertPairing(
        @RequestParam(value = "encrypted_registration_data", required = false) @NotNull final String registrationData) {
        return pairingService
            .validateAndInsertPairingData(requestAccessToken.getAccessToken(), new IdpJwe(registrationData));
    }
}
