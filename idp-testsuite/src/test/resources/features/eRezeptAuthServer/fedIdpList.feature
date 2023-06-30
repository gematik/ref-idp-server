#
# Copyright 2023 gematik GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

@FedIdpList
Feature: Fed Idp List Endpoint

  Die eRezept-App stößt eine Authentisierung über die IDP Föderation an

  Background: Initialisiere Testkontext durch Abfrage des Discovery Dokuments
    Given IDP I initialize scenario from discovery document endpoint
    And TGR find request to path "/.well-known/openid-configuration"
    And TGR set local variable "fed_list_endpoint" to "!{rbel:currentResponseAsString('$.body.body.fed_idp_list_uri')}"

  @TCID:FED_IDP_LIST_001
  @Approval
  Scenario: Fed Idp List - Die fed_idp_list_uri ist erreichbar

  ```
  Wir fordern das Discovery Dokument an und überprüfen die fed_idp_list_uri

    Given TGR clear recorded messages
    When TGR sende eine leere GET Anfrage an "${fed_list_endpoint}"
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "200"
    And TGR current response with attribute "$.header.Content-Type" matches "application/jwt.*"


  @TCID:FED_IDP_LIST_002
  @Approval
  Scenario: Fed Idp List - Die fed_idp_list_uri hat korrekte Header Claims

  ```
  Wir fordern die fed_idp_list an und prüfen die Header Claims

    Given TGR clear recorded messages
    When TGR sende eine leere GET Anfrage an "${fed_list_endpoint}"
    And TGR find request to path ".*"
    Then TGR current response at "$.body.header" matches as JSON:
            """
          {
          alg:        'BP256R1',
          kid:        'puk_disc_sig',
          typ:        'JWT',
          x5c:        "${json-unit.ignore}"
          }
        """


  @TCID:FED_IDP_LIST_003
  @Approval
  Scenario: Fed Idp List - Die fed_idp_list_uri hat korrekte Body Claims

  ```
  Wir fordern die fed_idp_list an und prüfen die Body Claims

    Given TGR clear recorded messages
    When TGR sende eine leere GET Anfrage an "${fed_list_endpoint}"
    And TGR find request to path ".*"
    Then TGR current response at "$.body.body.fed_idp_list.0" matches as JSON:
            """
            {
              "idp_name": "gematik reference authorization server",
              "idp_iss_id": "https://idpfadi.dev.gematik.solutions",
              "idp_logo": "",
              "idp_sek_2": true
            }
        """
