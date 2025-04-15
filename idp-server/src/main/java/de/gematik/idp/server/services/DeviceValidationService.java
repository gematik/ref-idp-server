/*
 * Copyright (Date see Readme), gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

package de.gematik.idp.server.services;

import de.gematik.idp.server.data.DeviceType;
import de.gematik.idp.server.devicevalidation.DeviceValidationData;
import de.gematik.idp.server.devicevalidation.DeviceValidationRepository;
import de.gematik.idp.server.devicevalidation.DeviceValidationState;
import jakarta.annotation.PostConstruct;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class DeviceValidationService {

  private final DeviceValidationRepository deviceValidationRepository;

  @PostConstruct
  public void intDbWithDevices() {
    deviceValidationRepository.save(
        DeviceValidationData.builder()
            .manufacturer("Samsung")
            .product("Galaxy-8")
            .model("SM-950F")
            .os("Android")
            .osVersion("4.0.3")
            .state(DeviceValidationState.ALLOW)
            .build());
    deviceValidationRepository.save(
        DeviceValidationData.builder()
            .manufacturer("Samsung")
            .product("Galaxy-S3")
            .model("GT-I9300")
            .os("Android")
            .osVersion("2.2")
            .state(DeviceValidationState.ALLOW)
            .build());
    deviceValidationRepository.save(
        DeviceValidationData.builder()
            .manufacturer("Apple")
            .product("iPhone")
            .model("iPhone Xs")
            .os("iOS")
            .osVersion("14.4.2")
            .state(DeviceValidationState.ALLOW)
            .build());
    deviceValidationRepository.save(
        DeviceValidationData.builder()
            .manufacturer("Google")
            .product("Pixel 2")
            .model("Pixel 2")
            .os("Android")
            .osVersion("11.0.0")
            .state(DeviceValidationState.BLOCK)
            .build());
    deviceValidationRepository.save(
        DeviceValidationData.builder()
            .manufacturer("Google")
            .product("Pixel 2")
            .model("Pixel 2 XL")
            .os("Android")
            .osVersion("10.0.0")
            .state(DeviceValidationState.BLOCK)
            .build());
    deviceValidationRepository.save(
        DeviceValidationData.builder()
            .manufacturer("Apple")
            .product("iPhone")
            .model("iPhone 3G")
            .os("iOS")
            .osVersion("6.1.6")
            .state(DeviceValidationState.BLOCK)
            .build());
  }

  public DeviceValidationState assess(final DeviceType deviceType) {
    final Optional<DeviceValidationData> deviceValidation = getDeviceValidation(deviceType);
    return deviceValidation
        .map(DeviceValidationData::getState)
        .orElse(DeviceValidationState.UNKNOWN);
  }

  private Optional<DeviceValidationData> getDeviceValidation(final DeviceType deviceType) {
    final DeviceValidationData deviceData = convertDeviceTypeToDeviceValidationData(deviceType);
    return deviceValidationRepository.findByManufacturerAndProductAndModelAndOsAndOsVersion(
        deviceData.getManufacturer(),
        deviceData.getProduct(),
        deviceData.getModel(),
        deviceData.getOs(),
        deviceData.getOsVersion());
  }

  private DeviceValidationData convertDeviceTypeToDeviceValidationData(
      final DeviceType deviceType) {
    return DeviceValidationData.builder()
        .manufacturer(deviceType.getManufacturer())
        .product(deviceType.getProduct())
        .model(deviceType.getModel())
        .os(deviceType.getOs())
        .osVersion(deviceType.getOsVersion())
        .build();
  }
}
