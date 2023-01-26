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

package de.gematik.test.bdd;

public class Variables extends ThreadedContextProvider {

  private static final Variables SINGLETON = new Variables();

  public static Variables get() {
    return SINGLETON;
  }

  public static String substituteVariables(String str) {
    int varIdx = str.indexOf("${VAR.");
    while (varIdx != -1) {
      final int endVar = str.indexOf("}", varIdx);
      final String varName = str.substring(varIdx + "${VAR.".length(), endVar);
      str = str.substring(0, varIdx) + Variables.get().get(varName) + str.substring(endVar + 1);
      varIdx = str.indexOf("${VAR.");
    }
    return str;
  }
}
