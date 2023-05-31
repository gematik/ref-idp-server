/*
 *  Copyright 2023 gematik GmbH
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
 */

package de.gematik.idp.server.services;

import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.server.data.DeviceType;
import de.gematik.idp.server.devicevalidation.DeviceValidationData;
import de.gematik.idp.server.devicevalidation.DeviceValidationRepository;
import de.gematik.idp.server.devicevalidation.DeviceValidationState;
import jakarta.transaction.Transactional;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
@Transactional
class DeviceValidationServiceTest {

  @Autowired private DeviceValidationService deviceValidationService;
  @Autowired private DeviceValidationRepository deviceValidationRepository;

  @Test
  void testAssessDeviceValidation() {
    final DeviceValidationData deviceValidationData = createDeviceValidationData();
    final DeviceType deviceType = createDeviceType(deviceValidationData);
    assertThat(findDeviceValidationDataFromRepo(deviceValidationData)).isEmpty();
    final DeviceValidationState state = deviceValidationService.assess(deviceType);
    assertThat(state).isEqualTo(DeviceValidationState.UNKNOWN);
  }

  @Test
  void testAssessWithExistingDeviceValidation() {
    final DeviceValidationData deviceValidationData = createDeviceValidationData();
    deviceValidationRepository.save(deviceValidationData);
    final DeviceType deviceType = createDeviceType(deviceValidationData);
    final DeviceValidationState state = deviceValidationService.assess(deviceType);
    assertThat(state).isEqualTo(DeviceValidationState.ALLOW);
    cleanUp();
  }

  @Test
  void testValidationRepository() {
    final DeviceValidationData expected =
        deviceValidationRepository.save(createDeviceValidationData());
    final DeviceValidationData validationData = deviceValidationRepository.getOne(expected.getId());
    assertThat(validationData).usingRecursiveComparison().isEqualTo(expected);
    final Optional<DeviceValidationData> findData = findDeviceValidationDataFromRepo(expected);
    assertThat(findData).isPresent();
    assertThat(findData.get()).usingRecursiveComparison().isEqualTo(expected);
    cleanUp();
  }

  private Optional<DeviceValidationData> findDeviceValidationDataFromRepo(
      final DeviceValidationData expected) {
    return deviceValidationRepository.findByManufacturerAndProductAndModelAndOsAndOsVersion(
        expected.getManufacturer(),
        expected.getProduct(),
        expected.getModel(),
        expected.getOs(),
        expected.getOsVersion());
  }

  private DeviceType createDeviceType(final DeviceValidationData data) {
    return DeviceType.builder()
        .manufacturer(data.getManufacturer())
        .product(data.getProduct())
        .model(data.getModel())
        .os(data.getOs())
        .osVersion(data.getOsVersion())
        .build();
  }

  private DeviceValidationData createDeviceValidationData() {
    return DeviceValidationData.builder()
        .manufacturer("TestManufacturer")
        .product("TestProduct")
        .model("TestModel")
        .os("testOs")
        .osVersion("testOsVersion")
        .state(DeviceValidationState.ALLOW)
        .build();
  }

  private void cleanUp() {
    deviceValidationRepository.deleteAll();
  }
}
