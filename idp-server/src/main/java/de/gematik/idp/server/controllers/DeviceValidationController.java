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
public class DeviceValidationController {

    private final DeviceValidationService deviceValidationService;

    @GetMapping(DEVICE_VALIDATION_ENDPOINT)
    @ValidateClientSystem
    public List<DeviceValidationDto> getDeviceValidation() {
        return deviceValidationService.getAllDeviceValidation();
    }

    @DeleteMapping(DEVICE_VALIDATION_ENDPOINT)
    @ValidateClientSystem
    public void deleteDeviceValidation(
        @RequestParam("device_validation") @NotNull final Long deviceValidationId
    ) {
        deviceValidationService.deleteDeviceValidation(deviceValidationId);
    }

    @PutMapping(value = DEVICE_VALIDATION_ENDPOINT)
    @ValidateClientSystem
    public String insertValidationData(
        @RequestParam @NotNull final DeviceValidationDto deviceValidationDTO) {
        return deviceValidationService.saveDeviceValidation(deviceValidationDTO);
    }
}
