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

package de.gematik.idp;

import static org.assertj.core.api.Assertions.assertThat;
import de.gematik.idp.field.ClientUtilities;
import de.gematik.idp.tests.Remark;
import de.gematik.idp.tests.Rfc;
import org.junit.jupiter.api.Test;

public class PkceClientTest {

    @Test
    @Rfc("https://tools.ietf.org/html/rfc7636#section-4.1")
    public void checkAlphabetforCodeVerifier() {
        final String codeVerifier = ClientUtilities.generateCodeVerifier();
        assertThat(codeVerifier).matches("[\\w-_.~]*");
    }

    @Test
    @Rfc("https://tools.ietf.org/html/rfc7636#section-4.1")
    public void checkLengthOfCodeVerifier() {
        final String codeVerifier = ClientUtilities.generateCodeVerifier();
        assertThat(codeVerifier.length()).isGreaterThanOrEqualTo(43).isLessThanOrEqualTo(128);
    }

    @Test
    @Rfc("https://tools.ietf.org/html/rfc7636#section-4.1")
    public void checkEachCodeVerifierIsDifferent() {
        final String firstCodeVerifier = ClientUtilities.generateCodeVerifier();
        final String seccondCodeVerifier = ClientUtilities.generateCodeVerifier();
        assertThat(firstCodeVerifier).isNotEqualTo(seccondCodeVerifier);
    }

    @Test
    @Rfc("rfc7636 Appendix B")
    @Remark("This example is in rfc7636 Appendix B")
    public void checkTransformationS256() {
        assertThat(ClientUtilities.generateCodeChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))
            .isEqualTo("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    @Test
    @Remark("base64urlencode auf output von sha256 gibt laenger 43 oder 44")
    @Rfc("rfc7636")
    public void checkLengthOfCodeChellange() {
        final String codeChellange = ClientUtilities.generateCodeChallenge(ClientUtilities.generateCodeVerifier());
        assertThat(codeChellange.length()).isEqualTo(43);
    }
}
