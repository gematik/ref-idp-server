/*
 * Copyright (Date see Readme), gematik GmbH
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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;

class Oauth2ErrorCodeTest {

  @SneakyThrows
  @Test
  void constructInvalidGrantFromStringValid() {
    final Oauth2ErrorCode oauth2ErrorCode =
        new ObjectMapper().readValue("\"invalid_grant\"", Oauth2ErrorCode.class);
    assertThat(oauth2ErrorCode).isNotNull();
  }

  @SneakyThrows
  @Test
  void constructInvalidScopeFromStringValid() {
    final Oauth2ErrorCode oauth2ErrorCode =
        new ObjectMapper().readValue("\"invalid_scope\"", Oauth2ErrorCode.class);
    assertThat(oauth2ErrorCode).isNotNull();
  }

  @SneakyThrows
  @Test
  void constructFromStringInvalid() {
    assertThatThrownBy(
            () -> new ObjectMapper().readValue("\"Invalid_grant\"", Oauth2ErrorCode.class))
        .isInstanceOf(InvalidFormatException.class);
  }
}
