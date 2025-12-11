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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.HashMap;
import java.util.List;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.exc.InvalidFormatException;
import tools.jackson.databind.exc.PropertyBindingException;
import tools.jackson.databind.json.JsonMapper;

class Oauth2ErrorResponseTest {

  static final String OAUTH_2_ERROR_CODE_AS_STRING_VALID = "{\"error\":\"invalid_grant\"}";
  static final String OAUTH_2_ERROR_CODE_AS_STRING_WITH_DESCRIPTION =
      "{\"error\":\"invalid_client\",\"error_description\":\"something strange happened\"}";
  static final String OAUTH_2_ERROR_CODE_AS_STRING_INVALID_LETTER = "{\"error\":\"invalid_Grant\"}";
  static final String OAUTH_2_ERROR_CODE_AS_STRING_INVALID_PARAM =
      "{\"timestamp\":\"2023-02-16T11:26:09.900+00:00\",\"status\":\"400\",\"error\":\"Bad"
          + " Request\",\"path\":\"/auth\"}";
  static final String OAUTH_2_ERROR_CODE_AS_STRING_UNKNOWN_PROPERTY =
      "{\"error\":\"invalid_grant\",\"unknown_field\":\"some_value\"}";

  @SneakyThrows
  @Test
  void constructFromStringValid() {
    final List<String> validJson =
        List.of(OAUTH_2_ERROR_CODE_AS_STRING_VALID, OAUTH_2_ERROR_CODE_AS_STRING_WITH_DESCRIPTION);
    for (final String json : validJson) {
      final Oauth2ErrorResponse oauth2ErrorResponse =
          new ObjectMapper().readValue(json, Oauth2ErrorResponse.class);
      assertThat(oauth2ErrorResponse).isNotNull();
    }
  }

  @Test
  void constructFromStringInvalid() {
    assertThatThrownBy(
            () ->
                JsonMapper.builder()
                    .build()
                    .readValue(
                        OAUTH_2_ERROR_CODE_AS_STRING_INVALID_LETTER, Oauth2ErrorResponse.class))
        .isInstanceOf(InvalidFormatException.class);
    assertThatThrownBy(
            () ->
                JsonMapper.builder()
                    .build()
                    .readValue(
                        OAUTH_2_ERROR_CODE_AS_STRING_INVALID_PARAM, Oauth2ErrorResponse.class))
        .isInstanceOf(InvalidFormatException.class);
    assertThatThrownBy(
            () ->
                JsonMapper.builder()
                    .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true)
                    .build()
                    .readValue(
                        OAUTH_2_ERROR_CODE_AS_STRING_UNKNOWN_PROPERTY, Oauth2ErrorResponse.class))
        .isInstanceOf(PropertyBindingException.class);
  }

  @SuppressWarnings("unchecked")
  @SneakyThrows
  @Test
  void constructHashMap() {
    assertThat(
            new ObjectMapper()
                .readValue(OAUTH_2_ERROR_CODE_AS_STRING_WITH_DESCRIPTION, HashMap.class))
        .hasSize(2);
  }
}
