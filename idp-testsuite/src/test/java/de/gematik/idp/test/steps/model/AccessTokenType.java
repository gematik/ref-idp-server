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

public enum AccessTokenType {
  EREZEPT,
  PAIRING;

  public static final String CUCUMBER_REGEX = "(erezept|pairing)";

  private final String value;

  AccessTokenType() {
    value = name().toLowerCase();
  }

  public static AccessTokenType fromString(final String value) {
    return Arrays.stream(AccessTokenType.values())
        .filter(e -> e.value.equals(value))
        .findFirst()
        .orElseThrow(() -> new AssertionError("Invalid access token type '" + value + "'"));
  }

  @Override
  public String toString() {
    return value;
  }

  public String toScope() {
    return value.replace("erezept", "e-rezept");
  }
}
