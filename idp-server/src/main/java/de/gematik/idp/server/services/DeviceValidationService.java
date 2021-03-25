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

import de.gematik.idp.server.data.DeviceType;
import de.gematik.idp.server.data.DeviceValidationDto;
import de.gematik.idp.server.devicevalidation.DeviceValidationData;
import de.gematik.idp.server.devicevalidation.DeviceValidationRepository;
import de.gematik.idp.server.devicevalidation.DeviceValidationState;
import de.gematik.idp.server.exceptions.oauth2spec.IdpServerInvalidRequestException;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class DeviceValidationService {

    private final DeviceValidationRepository deviceValidationRepository;

    private final ModelMapper modelMapper;

    public DeviceValidationState assess(final DeviceType deviceType) {
        final Optional<DeviceValidationData> deviceValidation = getDeviceValidation(deviceType);
        return deviceValidation.orElseGet(() -> addNewDevice(deviceType)).getState();
    }

    public Optional<DeviceValidationData> getDeviceValidation(final DeviceType deviceType) {
        final DeviceValidationData deviceData = convertDeviceTypeToDeviceValidationData(deviceType);
        return deviceValidationRepository
            .findByManufacturerAndProductAndOsAndOsVersion(deviceData.getManufacturer(),
                deviceData.getProduct(), deviceData.getOs(), deviceData.getOsVersion());
    }

    public List<DeviceValidationDto> getAllDeviceValidation() {
        return deviceValidationRepository.findAll().stream()
            .map(deviceValidationData -> modelMapper.map(deviceValidationData, DeviceValidationDto.class)).collect(
                Collectors.toList());
    }

    public void deleteDeviceValidation(final Long id) {
        deviceValidationRepository.deleteById(id);
    }

    public String saveDeviceValidation(final DeviceValidationDto deviceValidation) {
        return save(modelMapper.map(deviceValidation, DeviceValidationData.class)).getId().toString();
    }

    private DeviceValidationData addNewDevice(final DeviceType deviceType) {
        final DeviceValidationData deviceValidationData = convertDeviceTypeToDeviceValidationData(deviceType);
        deviceValidationData.setState(DeviceValidationState.UNKNOWN);
        return save(deviceValidationData);
    }

    private DeviceValidationData convertDeviceTypeToDeviceValidationData(final DeviceType deviceType) {
        return DeviceValidationData.builder()
            .manufacturer(deviceType.getManufacturer())
            .product(deviceType.getProduct())
            .os(deviceType.getOs())
            .osVersion(deviceType.getOsVersion())
            .build();
    }

    private DeviceValidationData save(final DeviceValidationData deviceValidationData) {
        try {
            return deviceValidationRepository.save(deviceValidationData);
        } catch (final DataIntegrityViolationException exp) {
            throw new IdpServerInvalidRequestException("Duplicate device data", exp);
        }
    }
}
