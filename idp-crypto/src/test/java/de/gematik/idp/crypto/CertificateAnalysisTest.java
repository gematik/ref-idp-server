/*
 * Copyright (c) 2022 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.idp.crypto;

import static de.gematik.idp.crypto.CertificateAnalysis.doesCertificateContainPolicyExtensionOid;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.junit.jupiter.api.Test;

class CertificateAnalysisTest {

  private static final String EGK_FILE = "src/test/resources/109500969_X114428530_c.ch.aut-ecc.p12";

  @Test
  void testPolicyExtensionForEgk() throws IOException, CertificateEncodingException {
    final X509Certificate certificate = certificateDataFrom(EGK_FILE);
    assertThat(
            doesCertificateContainPolicyExtensionOid(
                certificate, new ASN1ObjectIdentifier("1.2.276.0.76.4.75")))
        .isFalse();
    assertThat(
            doesCertificateContainPolicyExtensionOid(
                certificate, new ASN1ObjectIdentifier("1.2.276.0.76.4.77")))
        .isFalse();
    assertThat(
            doesCertificateContainPolicyExtensionOid(
                certificate, new ASN1ObjectIdentifier("1.2.276.0.76.4.70")))
        .isTrue();
  }

  private X509Certificate certificateDataFrom(final String filename) throws IOException {
    return CryptoLoader.getCertificateFromP12(
        FileUtils.readFileToByteArray(new File(filename)), "00");
  }
}
