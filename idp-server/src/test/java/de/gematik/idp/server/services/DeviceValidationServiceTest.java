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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.server.data.DeviceType;
import de.gematik.idp.server.data.DeviceValidationDto;
import de.gematik.idp.server.devicevalidation.DeviceValidationData;
import de.gematik.idp.server.devicevalidation.DeviceValidationRepository;
import de.gematik.idp.server.devicevalidation.DeviceValidationState;
import de.gematik.idp.server.exceptions.oauth2spec.IdpServerInvalidRequestException;
import de.gematik.idp.tests.PkiKeyResolver;
import java.util.Optional;
import javax.transaction.Transactional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
@Transactional
@ExtendWith(PkiKeyResolver.class)
class DeviceValidationServiceTest {

    private static PkiIdentity identity;
    @Autowired
    private DeviceValidationService deviceValidationService;
    @Autowired
    private DeviceValidationRepository deviceValidationRepository;
    @Autowired
    private ModelMapper modelmapper;

    @BeforeEach
    public void init(@PkiKeyResolver.Filename("109500969_X114428530_c.ch.aut-ecc") final PkiIdentity identity) {
        DeviceValidationServiceTest.identity = identity;
        cleanUp();
    }

    @Test
    public void testAssessDeviceValidation() {
        final DeviceValidationData deviceValidationData = createDeviceValidationData();
        final DeviceType deviceType = createDeviceType(deviceValidationData);
        assertThat(findDeviceValidationDataFromRepo(deviceValidationData)).isEmpty();
        final DeviceValidationState state = deviceValidationService.assess(deviceType);
        assertThat(state).isEqualTo(DeviceValidationState.UNKNOWN);
        assertThat(findDeviceValidationDataFromRepo(deviceValidationData)).isPresent();
        cleanUp();
    }

    @Test
    public void testAssessWithExistingDeviceValidation() {
        final DeviceValidationData deviceValidationData = createDeviceValidationData();
        deviceValidationRepository.save(deviceValidationData);
        final DeviceType deviceType = createDeviceType(deviceValidationData);
        final DeviceValidationState state = deviceValidationService.assess(deviceType);
        assertThat(state).isEqualTo(DeviceValidationState.ALLOWED);
        cleanUp();
    }

    @Test
    public void testValidationRepository() {
        final DeviceValidationData expected = deviceValidationRepository.save(createDeviceValidationData());
        final DeviceValidationData validationData = deviceValidationRepository.getOne(expected.getId());
        assertThat(validationData)
            .usingRecursiveComparison()
            .isEqualTo(expected);
        final Optional<DeviceValidationData> findData = findDeviceValidationDataFromRepo(
            expected);
        assertThat(findData).isPresent();
        assertThat(findData.get())
            .usingRecursiveComparison().isEqualTo(expected);
        cleanUp();
    }

    @Test
    public void testDeviceValidationDataFromJwt() {
        final DeviceValidationData deviceValidationData = createDeviceValidationData();
        final DeviceType deviceType = createDeviceType(deviceValidationData);
        final Optional<DeviceValidationData> deviceData = deviceValidationService
            .getDeviceValidation(deviceType);
        assertThat(deviceData.isEmpty()).isTrue();
        deviceValidationRepository.save(deviceValidationData);
        final Optional<DeviceValidationData> dataFromService = deviceValidationService
            .getDeviceValidation(deviceType);
        assertThat(dataFromService).isPresent();
        assertThat(dataFromService.get())
            .usingRecursiveComparison()
            .ignoringFields("id")
            .isEqualTo(deviceValidationData);
        cleanUp();
    }

    @Test
    public void testDuplicatDeviceData() {
        final DeviceValidationData deviceValidationData = createDeviceValidationData();
        deviceValidationService.saveDeviceValidation(modelmapper.map(deviceValidationData, DeviceValidationDto.class));
        assertThatThrownBy(
            () -> deviceValidationService
                .saveDeviceValidation(modelmapper.map(deviceValidationData, DeviceValidationDto.class)))
            .isInstanceOf(IdpServerInvalidRequestException.class)
            .hasMessage("Duplicate device data");
        deviceValidationData.setState(DeviceValidationState.GREY);
        assertThatThrownBy(
            () -> deviceValidationService
                .saveDeviceValidation(modelmapper.map(deviceValidationData, DeviceValidationDto.class)))
            .isInstanceOf(IdpServerInvalidRequestException.class)
            .hasMessage("Duplicate device data");
    }

    @Test
    public void testGetAllDeviceValidationData() {
        assertThat(deviceValidationService.getAllDeviceValidation()).isEmpty();
        final DeviceValidationData deviceValidationData = deviceValidationRepository.save(createDeviceValidationData());
        assertThat(deviceValidationService.getAllDeviceValidation())
            .hasSize(1).contains(modelmapper.map(deviceValidationData, DeviceValidationDto.class));
        cleanUp();
    }

    @Test
    public void testDeleteDeviceValidationData() {
        final DeviceValidationData deviceValidationData = deviceValidationRepository.save(createDeviceValidationData());
        assertThat(deviceValidationService.getAllDeviceValidation())
            .hasSize(1);
        deviceValidationService.deleteDeviceValidation(deviceValidationData.getId());
        assertThat(deviceValidationService.getAllDeviceValidation())
            .hasSize(0);
        cleanUp();
    }

    @Test
    public void testSaveDeviceValidationData() {
        final DeviceValidationData deviceValidationData = createDeviceValidationData();
        final String id = deviceValidationService
            .saveDeviceValidation(modelmapper.map(deviceValidationData, DeviceValidationDto.class));
        assertThat(deviceValidationRepository.getOne(Long.parseLong(id))).usingRecursiveComparison()
            .ignoringFields("id")
            .isEqualTo(deviceValidationData);
        cleanUp();
    }

    private Optional<DeviceValidationData> findDeviceValidationDataFromRepo(final DeviceValidationData expected) {
        return deviceValidationRepository
            .findByManufacturerAndProductAndOsAndOsVersion(expected.getManufacturer(),
                expected.getProduct(), expected.getOs(), expected.getOsVersion());
    }

    private DeviceType createDeviceType(final DeviceValidationData data) {
        return DeviceType.builder()
            .deviceManufacturer(data.getManufacturer())
            .deviceProduct(data.getProduct())
            .deviceOs(data.getOs())
            .deviceVersion(data.getOsVersion())
            .build();
    }

    private DeviceValidationData createDeviceValidationData() {
        return DeviceValidationData.builder().manufacturer("TestManufacturer").product("TestProduct")
            .os("testOs").osVersion("testOsVersion").state(
                DeviceValidationState.ALLOWED).build();
    }

    private void cleanUp() {
        deviceValidationRepository.deleteAll();
    }
}
