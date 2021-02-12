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

import static de.gematik.idp.IdpConstants.DEVICE_VALIDATION_ENDPOINT;

import de.gematik.idp.server.data.DeviceValidationDto;
import de.gematik.idp.server.services.DeviceValidationService;
import de.gematik.idp.server.validation.clientSystem.ValidateClientSystem;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import java.util.List;
import javax.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@Transactional
@Validated
@Api(tags = {
    "Device-Validation-Dienst"}, description = "REST Endpunkte Abrufen, Einfügen und löschen von Device-Validation Daten")
public class DeviceValidationController {

    private final DeviceValidationService deviceValidationService;

    @GetMapping(DEVICE_VALIDATION_ENDPOINT)
    @ApiOperation(httpMethod = "GET", value = "Endpunkt für Device-Validation", notes = "Es werden alle vorhandenen Device-Validation Daten zurüchgeliefert.", response = List.class)
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Erfolgreich alle Device-Validation Daten erhalten"),
        @ApiResponse(responseCode = "403", description = "Nicht erlaubter Zugriff"),
        @ApiResponse(responseCode = "404", description = "Nicht gefunden - Methodenaufruf nicht korrekt")
    })
    @ValidateClientSystem
    public List<DeviceValidationDto> getDeviceValidation() {
        return deviceValidationService.getAllDeviceValidation();
    }

    @DeleteMapping(DEVICE_VALIDATION_ENDPOINT)
    @ApiOperation(httpMethod = "DELETE", value = "Endpunkt zum Löschen einer Device Validation", notes = "Die zugehörige Device-Validation wird gelöscht.")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Device-Validation erfolgreich gelöscht"),
        @ApiResponse(responseCode = "400", description = "Ungültige Anfrage (Parameter fehlen/ungültig)"),
        @ApiResponse(responseCode = "403", description = "Nicht erlaubter Zugriff"),
        @ApiResponse(responseCode = "404", description = "Nicht gefunden - Methodenaufruf nicht korrekt")
    })
    @ValidateClientSystem
    public void deleteDeviceValidation(
        @RequestParam("device_validation") @NotNull @ApiParam(value = "Device-Validation ID") final Long deviceValidationId
    ) {
        deviceValidationService.deleteDeviceValidation(deviceValidationId);
    }

    @PutMapping(value = DEVICE_VALIDATION_ENDPOINT)
    @ApiOperation(httpMethod = "PUT", value = "Endpunkt zum Hinzufügen von Device Validation",
        notes = "Die Devciedaten werden in der Device-Validation-DB hinterlegt",
        response = String.class)
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Erfolgreich eine Device-Validation hinzugefügt"),
        @ApiResponse(responseCode = "400", description = "Ungültige Anfrage (Parameter fehlen/ungültig/Datensatz bereits vorhanden)"),
        @ApiResponse(responseCode = "403", description = "Nicht erlaubter Zugriff"),
        @ApiResponse(responseCode = "404", description = "Nicht gefunden - Methodenaufruf nicht korrekt")
    })
    @ValidateClientSystem
    public String insertValidationData(
        @RequestParam @ApiParam(value = "device_validation") @NotNull final DeviceValidationDto deviceValidationDTO) {
        return deviceValidationService.saveDeviceValidation(deviceValidationDTO);
    }
}
