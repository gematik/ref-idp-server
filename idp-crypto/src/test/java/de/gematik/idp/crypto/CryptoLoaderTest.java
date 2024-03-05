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

package de.gematik.idp.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.gematik.idp.crypto.model.PkiIdentity;
import java.io.File;
import java.io.IOException;
import java.security.cert.X509Certificate;
import lombok.SneakyThrows;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Test;

class CryptoLoaderTest {

  @Test
  void loadRsaCertificateFromP12() throws IOException {
    final byte[] p12FileContent =
        FileUtils.readFileToByteArray(
            new File("src/test/resources/833621999741600-2_c.hci.aut-apo-rsa.p12"));
    final X509Certificate certificate = CryptoLoader.getCertificateFromP12(p12FileContent, "00");

    assertThat(certificate.getSubjectX500Principal().toString()).containsIgnoringCase("CN=");
  }

  @Test
  void loadEccCertificateFromP12() throws IOException {
    final byte[] p12FileContent =
        FileUtils.readFileToByteArray(
            new File("src/test/resources/authenticatorModule_idpServer.p12"));
    final X509Certificate certificate = CryptoLoader.getCertificateFromP12(p12FileContent, "00");

    assertThat(certificate.getSubjectX500Principal().toString()).containsIgnoringCase("CN=");
  }

  @SneakyThrows
  @Test
  void loadNonCertificateFile() {
    final byte[] thisFileIsNoCertificate = FileUtils.readFileToByteArray(new File("pom.xml"));
    assertThat(thisFileIsNoCertificate).hasSizeGreaterThan(0);
    assertThatThrownBy(() -> CryptoLoader.getCertificateFromP12(thisFileIsNoCertificate, "00"))
        .isInstanceOf(RuntimeException.class);
  }

  @Test
  void loadIdentityFromP12() throws IOException {
    final byte[] p12FileContent =
        FileUtils.readFileToByteArray(
            new File("src/test/resources/authenticatorModule_idpServer.p12"));
    final PkiIdentity identity = CryptoLoader.getIdentityFromP12(p12FileContent, "00");

    assertThat(identity.getCertificate().getSubjectX500Principal().toString())
        .containsIgnoringCase("CN=");
  }
}
