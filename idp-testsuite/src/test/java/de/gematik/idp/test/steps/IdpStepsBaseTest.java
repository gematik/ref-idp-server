/*
 * Copyright (c) 2021 gematik GmbH
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

package de.gematik.idp.test.steps;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import de.gematik.idp.crypto.CryptoLoader;
import de.gematik.idp.data.IdpKeyDescriptor;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;
import lombok.SneakyThrows;
import org.apache.commons.io.IOUtils;
import org.json.JSONObject;
import org.junit.Test;

public class IdpStepsBaseTest {

    @Test
    @SneakyThrows
    public void checkSelfSignedCertIsDetected() {
        final byte[] data = IOUtils
            .toByteArray(getClass().getResourceAsStream("/certs/invalid/smcb-idp-selfsigned.p12"));
        final X509Certificate cert = CryptoLoader.getCertificateFromP12(data, "00");
        final IdpKeyDescriptor desc = IdpKeyDescriptor.constructFromX509Certificate(cert);

        assertThatThrownBy(() ->
            new IdpStepsBase().keyAndCertificateStepsHelper
                .jsonObjectShouldBeValidCertificate(new JSONObject(desc.toJSONString())))
            .isInstanceOf(AssertionError.class);
    }

    @Test
    @SneakyThrows
    public void checkExpiredCertIsDetected() {
        final byte[] data = IOUtils
            .toByteArray(getClass().getResourceAsStream("/certs/invalid/smcb-idp-expired-ecc.p12"));
        final X509Certificate cert = CryptoLoader.getCertificateFromP12(data, "00");
        final IdpKeyDescriptor desc = IdpKeyDescriptor.constructFromX509Certificate(cert);

        assertThatThrownBy(() ->
            new IdpStepsBase().keyAndCertificateStepsHelper
                .jsonObjectShouldBeValidCertificate(new JSONObject(desc.toJSONString())))
            .isInstanceOf(CertificateExpiredException.class);
    }

    @Test
    @SneakyThrows
    public void checkValidCertPassChecks() {
        final byte[] data = IOUtils
            .toByteArray(getClass().getResourceAsStream("/certs/valid/80276883110000129068-C_SMCB_HCI_AUT_E256.p12"));
        final X509Certificate cert = CryptoLoader.getCertificateFromP12(data, "00");
        assertThat(cert).isNotNull();
        final IdpKeyDescriptor desc = IdpKeyDescriptor.constructFromX509Certificate(cert);
        new IdpStepsBase().keyAndCertificateStepsHelper
            .jsonObjectShouldBeValidCertificate(new JSONObject(desc.toJSONString()));
    }
}
