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

package de.gematik.idp.data;

import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.error.IdpErrorType;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

class IdpErrorResponseTest {

  @Test
  void getError() {
    final String errorJson =
        """
        {
          "error" : "invalid_grant",
          "gematik_code" : "3000",
          "gematik_timestamp" : 1764757439,
          "gematik_uuid" : "885f677b-a2c7-4fe4-b15a-b200b71c70d2",
          "gematik_error_text" : "code_verifier stimmt nicht mit code_challenge überein"
        }""";

    final JsonMapper jsonMapper = JsonMapper.builder().build();
    final IdpErrorResponse idpErrorResponse;

    idpErrorResponse = jsonMapper.readValue(errorJson, IdpErrorResponse.class);

    assertThat(idpErrorResponse).isNotNull();
    assertThat(idpErrorResponse.getError()).isEqualTo(IdpErrorType.INVALID_GRANT);
    assertThat(idpErrorResponse.getCode()).isEqualTo("3000");
    assertThat(idpErrorResponse.getTimestamp()).isEqualTo(1764757439L);
    assertThat(idpErrorResponse.getErrorUuid()).isEqualTo("885f677b-a2c7-4fe4-b15a-b200b71c70d2");
    assertThat(idpErrorResponse.getDetailMessage())
        .isEqualTo("code_verifier stimmt nicht mit code_challenge überein");
  }
}
