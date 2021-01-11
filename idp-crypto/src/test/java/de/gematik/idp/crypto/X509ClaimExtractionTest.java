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

package de.gematik.idp.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.util.Map;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Test;

public class X509ClaimExtractionTest {

    private static final String EGK_FILE = "src/test/resources/109500969_X114428530_c.ch.aut-ecc.p12";
    private static final String HBA_CERT_FILE = "src/test/resources/hba_aut.pem";
    private static final String PSYCHOTHERAPEUT_FILE = "src/test/resources/Psychotherapeut_zwei_prof_E256.pem";
    private static final String SMCB_FILE = "src/test/resources/833621999741600_c.hci.aut-apo-ecc.p12";
    private static final String ARZTPRAXIS_FILE = "src/test/resources/Betriebsstatte_Arzt_max_E256.pem";
    private static final String KRANKENHAUS_FILE = "src/test/resources/Krankenhaus_min_R2048_X509.pem";

    @Test
    public void extractFromEgk() throws IOException, CertificateEncodingException {
        final Map<String, Object> claims = X509ClaimExtraction
            .extractClaimsFromCertificate(certificateDataFromP12(EGK_FILE));
        assertThat(claims)
            .containsEntry("given_name", "Juna")
            .containsEntry("family_name", "Fuchs")
            .containsEntry("organizationName", "gematik GmbH NOT-VALID")
            .containsEntry("professionOID", "1.2.276.0.76.4.49")
            .containsEntry("idNummer", "X114428530");
    }

    @Test
    public void extractFromSmcbApotheke() throws IOException, CertificateEncodingException {
        final Map<String, Object> claims = X509ClaimExtraction
            .extractClaimsFromCertificate(certificateDataFromP12(SMCB_FILE));
        assertThat(claims)
            .containsEntry("given_name", null)
            .containsEntry("family_name", null)
            .containsEntry("organizationName", "3-2-EPA-833621999741600 NOT-VALID")
            .containsEntry("professionOID", "1.2.276.0.76.4.54")
            .containsEntry("idNummer", "3-2-EPA-833621999741600");
    }

    @Test
    public void extractFromSmcbArztpraxis() throws IOException, CertificateEncodingException {
        final Map<String, Object> claims = X509ClaimExtraction
            .extractClaimsFromCertificate(certificateDataFrom(ARZTPRAXIS_FILE));
        assertThat(claims)
            .containsEntry("given_name", "Rainer")
            .containsEntry("family_name", "Agóstino")
            .containsEntry("organizationName", "Praxis Rainer Graf d' AgóstinoNOT-VALID")
            .containsEntry("professionOID", "1.2.276.0.76.4.50")
            .containsEntry("idNummer", "1-SMC-B-Testkarte-883110000129077");
    }

    @Test
    public void extractFromSmcbKrankenhaus() throws IOException, CertificateEncodingException {
        final Map<String, Object> claims = X509ClaimExtraction
            .extractClaimsFromCertificate(certificateDataFrom(KRANKENHAUS_FILE));
        assertThat(claims)
            .containsEntry("given_name", null)
            .containsEntry("family_name", null)
            .containsEntry("organizationName", null)
            .containsEntry("professionOID", "1.2.276.0.76.4.53")
            .containsEntry("idNummer", "5-SMC-B-Testkarte-883110000129072");
    }

    @Test
    public void extractFromHbaArzt() throws IOException, CertificateEncodingException {
        final Map<String, Object> claims = X509ClaimExtraction
            .extractClaimsFromCertificate(certificateDataFrom(HBA_CERT_FILE));
        assertThat(claims)
            .containsEntry("given_name", "Siegfried Graf")
            .containsEntry("family_name", "Heckhausén")
            .containsEntry("organizationName", null)
            .containsEntry("professionOID", "1.2.276.0.76.4.30")
            .containsEntry("idNummer", "1-HBA-Testkarte-883110000129085");
    }

    @Test
    public void extractFromHbaPsychtherapeut() throws IOException, CertificateEncodingException {
        final Map<String, Object> claims = X509ClaimExtraction
            .extractClaimsFromCertificate(certificateDataFrom(PSYCHOTHERAPEUT_FILE));
        assertThat(claims)
            .containsEntry("given_name", "Gisbert Gustav")
            .containsEntry("family_name", "Goldstück")
            .containsEntry("organizationName", null)
            .containsEntry("professionOID", "1.2.276.0.76.4.46")
            .containsEntry("idNummer", "4-2123456789");
    }

    // TODO Testcase extractFromHbaPsychtherapeut is wip, open question: https://projekt-jira.int.gematik.de/browse/IDP-98

    private byte[] certificateDataFromP12(final String filename) throws IOException, CertificateEncodingException {
        return CryptoLoader.getCertificateFromP12(
            FileUtils.readFileToByteArray(new File(filename)), "00")
            .getEncoded();
    }

    private byte[] certificateDataFrom(final String filename) throws IOException, CertificateEncodingException {
        return CryptoLoader.getCertificateFromPem(
            FileUtils.readFileToByteArray(new File(filename)))
            .getEncoded();
    }
}
