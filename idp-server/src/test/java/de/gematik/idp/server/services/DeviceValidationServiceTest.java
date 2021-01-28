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
import static java.util.Map.entry;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.authentication.JwtBuilder;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.server.devicevalidation.DeviceValidationData;
import de.gematik.idp.server.devicevalidation.DeviceValidationRepository;
import de.gematik.idp.server.devicevalidation.DeviceValidationState;
import de.gematik.idp.tests.PkiKeyResolver;
import de.gematik.idp.token.JsonWebToken;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import javax.transaction.Transactional;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
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

    @BeforeAll
    public static void init(@PkiKeyResolver.Filename("109500969_X114428530_c.ch.aut-ecc") final PkiIdentity identity) {
        DeviceValidationServiceTest.identity = identity;
    }

    @Test
    public void testAssessDeviceValidation() {
        final DeviceValidationData deviceValidationData = createDeviceValidationData();
        final JsonWebToken deviceDataJWT = createDeviceDataJWT(deviceValidationData);
        assertThat(findDeviceValidationDataFromRepo(deviceValidationData)).isEmpty();
        final DeviceValidationState state = deviceValidationService.assess(deviceDataJWT);
        assertThat(state).isEqualTo(DeviceValidationState.UNKNOWN);
        assertThat(findDeviceValidationDataFromRepo(deviceValidationData)).isPresent();
    }

    @Test
    public void testAssessWithExistingDeviceValidation() {
        final DeviceValidationData deviceValidationData = createDeviceValidationData();
        deviceValidationRepository.save(deviceValidationData);
        final JsonWebToken deviceDataJWT = createDeviceDataJWT(deviceValidationData);
        final DeviceValidationState state = deviceValidationService.assess(deviceDataJWT);
        assertThat(state).isEqualTo(DeviceValidationState.ALLOWED);
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
    }

    @Test
    public void testDeviceValidationDataFromJwt() {
        final DeviceValidationData deviceValidationData = createDeviceValidationData();
        final JsonWebToken deviceDataJWT = createDeviceDataJWT(deviceValidationData);
        final Optional<DeviceValidationData> deviceData = deviceValidationService
            .getDeviceValidation(deviceDataJWT);
        assertThat(deviceData.isEmpty()).isTrue();
        deviceValidationRepository.save(deviceValidationData);
        final Optional<DeviceValidationData> dataFromService = deviceValidationService
            .getDeviceValidation(deviceDataJWT);
        assertThat(dataFromService).isPresent();
        assertThat(dataFromService.get())
            .usingRecursiveComparison()
            .ignoringFields("id")
            .isEqualTo(deviceValidationData);
    }

    private Optional<DeviceValidationData> findDeviceValidationDataFromRepo(final DeviceValidationData expected) {
        return deviceValidationRepository
            .findByManufacturerAndProductAndModelAndOsAndOsVersionAndName(expected.getManufacturer(),
                expected.getProduct(), expected.getModel(), expected.getOs(),
                expected.getOsVersion(),
                expected.getName());
    }

    private JsonWebToken createDeviceDataJWT(final DeviceValidationData data) {
        final JwtBuilder jwtBuilder = new JwtBuilder();
        jwtBuilder.addAllBodyClaims(new HashMap<>(Map.ofEntries(
            entry(DEVICE_MANUFACTURER.getJoseName(), data.getManufacturer()),
            entry(DEVICE_PRODUCT.getJoseName(), data.getProduct()),
            entry(DEVICE_MODEL.getJoseName(), data.getModel()),
            entry(DEVICE_OS.getJoseName(), data.getOs()),
            entry(DEVICE_OS_VERSION.getJoseName(), data.getOsVersion()),
            entry(DEVICE_NAME.getJoseName(), data.getName())
        )));
        jwtBuilder.setSignerKey(identity.getPrivateKey());
        return jwtBuilder.buildJwt();
    }

    private DeviceValidationData createDeviceValidationData() {
        return DeviceValidationData.builder().manufacturer("TestManufacturer").product("TestProduct").model("TestModel")
            .os("testOs").osVersion("testOsVersion").name("TestName").state(
                DeviceValidationState.ALLOWED).build();
    }
}
