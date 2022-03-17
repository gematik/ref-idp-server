#
# Copyright (c) 2022 gematik GmbH
# 
# Licensed under the Apache License, Version 2.0 (the License);
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#


@Product:Fachdienst
@Federation
@Fachdienst
@RefImplOnly
Feature: IDP Liste am Fachdienst abrufen

  Background: Initialisiere Testkontext der Föderation
    Given IDP I initialize the federation endpoints

  @TCID:FACHDIENST_IDPLIST_001 @PRIO:1
  Scenario: FD IDP List - Gutfall - Validiere IDP List Response

  ```
  Wir rufen die Liste der IDPs beim Fachdienst ab

  Die HTTP Response muss:

  - den Code 200
  - einen JWS enthalten

    Given IDP I fetch the Fachdienst's IDP List
    Then the response status is 200
    And IDP the response content type matches 'application/jwt.*'
    When IDP I extract the body claims
    Then IDP the body claims should match in any order
        """
          { iss:                   ".*",
            iat:                   ".*",
            idp_entity_list:       [{"name":"IDP_SEKTORAL","iss":".*","user_type_supported":"todo-utsupp","logo_uri":"todo-logo"}],
            exp:                   ".*"
          }
        """


