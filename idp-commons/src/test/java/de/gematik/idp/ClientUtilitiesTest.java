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

import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.field.ClientUtilities;
import org.junit.jupiter.api.Test;

class ClientUtilitiesTest {

  private static final String BASE64_URL_REGEX = "^[0-9a-zA-Z\\-\\.~_]+$";
  private static final int SHA256_AS_B64_LENGTH = 43;

  @Test
  void generateCodeChallengeFromVerifier() {
    final String codeVerifier = ClientUtilities.generateCodeVerifier();

    final String codeChallenge = ClientUtilities.generateCodeChallenge(codeVerifier);

    assertThat(codeChallenge)
        .matches(BASE64_URL_REGEX)
        .isEqualTo(ClientUtilities.generateCodeChallenge(codeVerifier))
        .hasSize(SHA256_AS_B64_LENGTH);
  }
}
