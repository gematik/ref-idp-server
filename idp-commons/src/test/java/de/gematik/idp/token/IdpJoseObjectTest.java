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

package de.gematik.idp.token;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Collections;
import java.util.Map;
import org.junit.jupiter.api.Test;

class IdpJoseObjectTest {
  // Test-subclass because IdpJoseObject is abstract
  static class TestJoseObject extends IdpJoseObject {
    public TestJoseObject(final String rawString) {
      super(rawString);
    }

    @Override
    public Map<String, Object> extractHeaderClaims() {
      return Collections.emptyMap();
    }

    @Override
    public Map<String, Object> extractBodyClaims() {
      return Collections.emptyMap();
    }
  }

  @Test
  void shouldThrowIllegalStateException_whenHeaderHasTooFewParts() {
    //  rawString without . -> split.length == 1
    final IdpJoseObject obj = new TestJoseObject("abc");

    assertThatThrownBy(obj::getHeaderDecoded)
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("only found 1 parts");
  }
}
