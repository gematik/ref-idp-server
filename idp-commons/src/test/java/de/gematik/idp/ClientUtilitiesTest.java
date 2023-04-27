/*
 * Copyright (c) 2023 gematik GmbH
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

import static de.gematik.idp.field.ClientUtilities.generateCodeVerifier;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.field.ClientUtilities;
import java.util.Arrays;
import org.apache.commons.lang3.ArrayUtils;
import org.junit.jupiter.api.Test;

class ClientUtilitiesTest {

  private static final String BASE64_URL_REGEX = "^[0-9a-zA-Z\\-\\.~_]+$";
  private static final int SHA256_AS_B64_LENGTH = 43;

  @Test
  void generateCodeChallengeFromVerifier() {
    final String codeVerifier = generateCodeVerifier();

    final String codeChallenge = ClientUtilities.generateCodeChallenge(codeVerifier);

    assertThat(codeChallenge)
        .matches(BASE64_URL_REGEX)
        .isEqualTo(ClientUtilities.generateCodeChallenge(codeVerifier))
        .hasSize(SHA256_AS_B64_LENGTH);
  }

  /*
   * https://datatracker.ietf.org/doc/rfc7636/
   * Appendix B.  Example for the S256 code_challenge_method
   */
  @Test
  void getCodeVerifierAndChallengeIetf() {
    final int[] ietfExampleOctets = {
      116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173, 187, 186, 22, 212, 37, 77,
      105, 214, 191, 240, 91, 88, 5, 88, 83, 132, 141, 121
    };
    final String codeVerifierIetf = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    final String codeChallengeIetf = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    final Byte[] objByteArray =
        Arrays.stream(ietfExampleOctets).boxed().map(Integer::byteValue).toArray(Byte[]::new);
    final byte[] primitiveByteArray = ArrayUtils.toPrimitive(objByteArray);

    final String codeVerifier = generateCodeVerifier(primitiveByteArray);
    assertThat(codeVerifier).isEqualTo(codeVerifierIetf);

    final String codeChallenge = ClientUtilities.generateCodeChallenge(codeVerifier);
    assertThat(codeChallenge).isEqualTo(codeChallengeIetf);
  }
}
