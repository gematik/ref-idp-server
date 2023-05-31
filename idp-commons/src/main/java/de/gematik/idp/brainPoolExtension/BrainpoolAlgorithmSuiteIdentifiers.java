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

package de.gematik.idp.brainPoolExtension;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class BrainpoolAlgorithmSuiteIdentifiers {

  protected static final String INTERNAL_BRAINPOOL256_USING_SHA256 = "BP256R1";
  public static final String BRAINPOOL256_USING_SHA256 =
      getValueAndExecuteInitialisation(INTERNAL_BRAINPOOL256_USING_SHA256);
  protected static final String INTERNAL_BRAINPOOL384_USING_SHA384 = "BP384R1";
  public static final String BRAINPOOL384_USING_SHA384 =
      getValueAndExecuteInitialisation(INTERNAL_BRAINPOOL384_USING_SHA384);
  protected static final String INTERNAL_BRAINPOOL512_USING_SHA512 = "BP512R1";
  public static final String BRAINPOOL512_USING_SHA512 =
      getValueAndExecuteInitialisation(INTERNAL_BRAINPOOL512_USING_SHA512);

  private static String getValueAndExecuteInitialisation(final String value) {
    BrainpoolCurves.init();
    return value;
  }
}
