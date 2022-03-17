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

@Product:Sektoral-IDP
@FastTrack
@SektoralIdp
@RefImplOnly
Feature: Authentifiziere User am Sektoral-IDP

  Die Kassen-App

  Background: Initialisiere Testkontext durch Abfrage des Discovery Dokuments
    Given IDP I initialize scenario from discovery document endpoint
    And IDP I initialize the sektoral idp endpoints

  @TCID:IDP_SEKTORAL_AUTH_001 @PRIO:1
  @Approval @Ready
  Scenario: Auth - Gutfall - Validiere Antwortstruktur

  ```
  Wir senden einen gültigen Authorization Request an den Sektoral-IDP

  Die HTTP Response muss:

  - den Code 302

    Given IDP I send an authorization request to sektoral idp with
      | client_id    | scope  | redirect_uri                          | state       | nonce     | response_type | code_challenge                              | code_challenge_method |
      | smardcardIdp | openid | https://redirect.smartcard.de/erezept | yyystateyyy | 987654321 | code          | P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk | S256                  |
    Then the response status is 302
    And IDP the response http headers match
        """
        Content-Length=0
        Location=https://redirect.smartcard.de/erezept[?|&]code=.*
        """
#    And IDP I expect the Context with key STATE to match 'state123456'


