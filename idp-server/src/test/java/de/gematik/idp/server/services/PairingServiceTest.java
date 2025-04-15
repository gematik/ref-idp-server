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

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.idp.server.pairing.PairingData;
import de.gematik.idp.tests.PkiKeyResolver;
import java.time.ZonedDateTime;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(PkiKeyResolver.class)
@Transactional
class PairingServiceTest {

  private static final String testIdNumber = "X114428530";
  private static final String testDeviceName = "Peters Fon";

  @Autowired private PairingService pairingService;

  @BeforeEach
  public void cleanUp() {
    pairingService.deleteAllPairing(testIdNumber);
  }

  @Test
  void insertPairingAndFindEntrySuccessfully() {
    pairingService.insertPairing(createPairingDto("123"));
    assertThat(pairingService.getPairingList(testIdNumber)).isNotEmpty();
  }

  @Test
  void insertPairingAndDeleteEntrySuccessfully() {
    pairingService.insertPairing(createPairingDto("456"));
    assertDoesNotThrow(() -> pairingService.deleteAllPairing(testIdNumber));
    assertThat(pairingService.getPairingList(testIdNumber)).isEmpty();
  }

  private PairingData createPairingDto(final String keyIdentifier) {
    return PairingData.builder()
        .id(null)
        .idNumber(testIdNumber)
        .keyIdentifier(keyIdentifier)
        .deviceName(testDeviceName)
        .signedPairingData("bla")
        .timestampPairing(ZonedDateTime.now())
        .build();
  }
}
