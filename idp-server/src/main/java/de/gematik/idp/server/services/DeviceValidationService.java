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

import static de.gematik.idp.field.ClaimName.*;

import de.gematik.idp.exceptions.RequiredClaimException;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.server.devicevalidation.DeviceValidationData;
import de.gematik.idp.server.devicevalidation.DeviceValidationRepository;
import de.gematik.idp.server.devicevalidation.DeviceValidationState;
import de.gematik.idp.token.JsonWebToken;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class DeviceValidationService {

    private final DeviceValidationRepository deviceValidationRepository;


    public DeviceValidationState assess(final JsonWebToken deviceInformation) {
        final Optional<DeviceValidationData> deviceValidation = getDeviceValidation(deviceInformation);
        return deviceValidation.orElse(addUnknownDevice(deviceInformation)).getState();
    }

    public Optional<DeviceValidationData> getDeviceValidation(final JsonWebToken deviceInformation) {
        final DeviceValidationData deviceData = convertJwtToDeviceValidationData(deviceInformation);
        return deviceValidationRepository
            .findByManufacturerAndProductAndModelAndOsAndOsVersionAndName(deviceData.getManufacturer(),
                deviceData.getProduct(), deviceData.getModel(), deviceData.getOs(), deviceData.getOsVersion(),
                deviceData.getName());
    }

    private DeviceValidationData addUnknownDevice(final JsonWebToken deviceInformation) {
        final DeviceValidationData deviceValidationData = convertJwtToDeviceValidationData(deviceInformation);
        deviceValidationData.setState(DeviceValidationState.UNKNOWN);
        return deviceValidationRepository.save(deviceValidationData);
    }

    private DeviceValidationData convertJwtToDeviceValidationData(final JsonWebToken deviceInformation) {
        return DeviceValidationData.builder()
            .manufacturer(getStringBodyClaim(deviceInformation, DEVICE_MANUFACTURER))
            .product(getStringBodyClaim(deviceInformation, DEVICE_PRODUCT))
            .model(getStringBodyClaim(deviceInformation, DEVICE_MODEL))
            .os(getStringBodyClaim(deviceInformation, DEVICE_OS))
            .osVersion(getStringBodyClaim(deviceInformation, DEVICE_OS_VERSION))
            .name(getStringBodyClaim(deviceInformation, DEVICE_NAME))
            .build();
    }

    private String getStringBodyClaim(final JsonWebToken deviceInformation, final ClaimName claimName) {
        return deviceInformation.getStringBodyClaim(claimName)
            .orElseThrow(() -> new RequiredClaimException("Unable to obtain " + claimName.getJoseName() + "!"));
    }
}
