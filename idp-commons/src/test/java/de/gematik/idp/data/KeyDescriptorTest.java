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

package de.gematik.idp.data;

import static de.gematik.idp.data.IdpEccKeyDescriptor.constructFromX509Certificate;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.crypto.CryptoLoader;
import java.io.File;
import java.security.cert.X509Certificate;
import lombok.SneakyThrows;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Test;

public class KeyDescriptorTest {

  @SneakyThrows
  @Test
  void correctPointCoordsInEccKeyDescriptor_pubkeyWithLeadingZeros() {
    final byte[] pemFileContent =
        FileUtils.readFileToByteArray(
            new File("src/test/resources/jwk_testcert.pem"));
    final X509Certificate certificate = CryptoLoader.getCertificateFromPem(pemFileContent);
    final IdpEccKeyDescriptor keyDescriptor = (IdpEccKeyDescriptor) constructFromX509Certificate(certificate, "myKid", false);
    assertThat(keyDescriptor.getEccPointXValue()).isEqualTo("YzEPFvphu4T3GgWmjPXxPT0-Pdm_Q04OLENAH98zn-M");
    assertThat(keyDescriptor.getEccPointYValue()).isEqualTo("AHPHggsq6YwFfW2fSIJtawMLAh9ZoKPFTZqPFgQW0t4");
  }

}
