/*
 *  Copyright 2023 gematik GmbH
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
 */

package de.gematik.idp.test.steps.helpers;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.Test;

public class JsonCheckerTest {

  final JsonChecker check = new JsonChecker();

  @Test
  public void testOptionalJSONAttirbuteFlatOKMissing() {
    check.assertJsonShouldMatchInAnyOrder(
        "{ attr1: 'val1' }", "{ attr1: 'val1', ____attr2: 'val2' }");
  }

  @Test
  public void testOptionalJSONAttributeFlatOKEquals() {
    check.assertJsonShouldMatchInAnyOrder(
        "{ attr1:'val1', attr2:'val2' }", "{ attr1: 'val1', ____attr2: 'val2' }");
  }

  @Test
  public void testOptionalJSONAttirbuteFlatOKMatches() {
    check.assertJsonShouldMatchInAnyOrder(
        "{ attr1:'val1', attr2:'val2' }", "{ attr1: 'val1', ____attr2: 'v.*' }");
  }

  @Test
  public void testOptionalJSONAttirbuteFlatNOKNotEquals() {
    assertThatThrownBy(
            () ->
                check.assertJsonShouldMatchInAnyOrder(
                    "{ attr1:'val1', attr2:'val2' }", "{ attr1: 'val1', ____attr2: 'valXXX' }"))
        .isInstanceOf(AssertionError.class);
  }

  @Test
  public void testOptionalJSONAttirbuteFlatNOKMismatch() {
    assertThatThrownBy(
            () ->
                check.assertJsonShouldMatchInAnyOrder(
                    "{ attr1:'val1', attr2:'val2' }", "{ attr1: 'val1', ____attr2: 'v?\\\\d' }"))
        .isInstanceOf(AssertionError.class);
  }
}
