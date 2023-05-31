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

package de.gematik.idp.test.steps.model;

import java.util.Arrays;

public enum DateCompareMode {
  BEFORE,
  AFTER,
  NOT_BEFORE,
  NOT_AFTER;

  public static final String CUCUMBER_REGEX = "(before|after|not\\ before|not\\ after)";

  private final String value;
  private final String compareMathSign;

  DateCompareMode() {
    value = name().toLowerCase().replace("_", " ");
    switch (value) {
      case "not before":
        compareMathSign = ">=";
        break;
      case "after":
        compareMathSign = ">";
        break;
      case "before":
        compareMathSign = "<";
        break;
      case "not after":
        compareMathSign = "<=";
        break;
      default:
        compareMathSign = "??";
    }
  }

  public static DateCompareMode fromString(final String value) {
    return Arrays.stream(DateCompareMode.values())
        .filter(e -> e.value.equals(value))
        .findFirst()
        .orElseThrow(() -> new AssertionError("Invalid date compare mode '" + value + "'"));
  }

  @Override
  public String toString() {
    return value;
  }

  public String mathSign() {
    return compareMathSign;
  }
}
