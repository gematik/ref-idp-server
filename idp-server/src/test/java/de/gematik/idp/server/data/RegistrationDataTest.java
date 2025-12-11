/*
 * Copyright (Change Date see Readme), gematik GmbH
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

package de.gematik.idp.server.data;

import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.mockito.Mockito.mock;

import de.gematik.idp.exceptions.IdpJoseException;
import org.junit.jupiter.api.Test;
import tools.jackson.core.JacksonException;

class RegistrationDataTest {

  @Test
  void toJSONString_ObjectMapperWriteValue_exception() {
    final DeviceInformation badDeviceInfo =
        mock(
            DeviceInformation.class,
            invocation -> {
              throw new JacksonException("forced") {};
            });

    final RegistrationData registrationData =
        RegistrationData.builder()
            .signedPairingData("pairing")
            .authCert("cert")
            .deviceInformation(badDeviceInfo)
            .registrationDataVersion("1")
            .build();

    assertThatThrownBy(registrationData::toJSONString)
        .isInstanceOf(IdpJoseException.class)
        .hasMessage("Error during Claim serialization")
        .hasCauseInstanceOf(JacksonException.class);
  }
}
