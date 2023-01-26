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

package de.gematik.idp.test.steps.model;

import java.util.Arrays;

public enum CodeAuthType {
  SIGNED_CHALLENGE,
  SSO_TOKEN,
  SSO_TOKEN_NO_CHALLENGE,
  NO_PARAMS,
  SIGNED_CHALLENGE_WITH_SSO_TOKEN,
  ALTERNATIVE_AUTHENTICATION,
  THIRD_PARTY_AUTHORIZATION_CODE;

  public static final String CUCUMBER_REGEX =
      "(signed challenge|sso token|sso token no challenge|no params|signed challenge with sso"
          + " token|alternative authentication|third party authorization code)";

  private final String value;

  CodeAuthType() {
    value = name().toLowerCase().replace("_", " ");
  }

  public static CodeAuthType fromString(final String value) {
    return Arrays.stream(CodeAuthType.values())
        .filter(e -> e.value.equals(value))
        .findFirst()
        .orElseThrow(() -> new AssertionError("Invalid code auth type '" + value + "'"));
  }

  @Override
  public String toString() {
    return value;
  }
}
