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

@Product:IDP-D
@Biometrics
Feature: Fordere Pairingliste für Alternative Authentisierung am IDP Server an

  Frontends müssen mit einer eGK und einem Pairing Access oder SSO Token ihre Pairings einsehen können.

  Background: Initialisiere Testkontext durch Abfrage des Discovery Dokuments
    Given IDP I initialize scenario from discovery document endpoint
    And IDP I retrieve public keys from URIs

  @Approval @Ready
    @TCID:IDP_REF_LIST_000 @PRIO:1
  Scenario Outline: Biometrie Pairingliste - Gutfall - Löschen alle Pairings vor Start der Tests

  ```
  Wir löschen vor den Tests alle evt. vorhandenen Pairings die danach angelegt werden sollen.

    Given IDP I request an pairing access token with eGK cert '<auth_cert>'
    And IDP I deregister the device with '<key_id>'

    Examples: Zu deregistrierende Daten
      | auth_cert                                     | key_id       |
      | /certs/valid/egk-idp-idnumber-d-valid-ecc.p12 | keyidlist100 |
      | /certs/valid/egk-idp-idnumber-d-valid-ecc.p12 | keyidlist200 |
      | /certs/valid/egk-idp-idnumber-d-valid-ecc.p12 | keyidlist201 |

  @Approval @Ready
  @Afo:A_21424 @Afo:A_21450 @Afo:A_21452
  @TCID:IDP_REF_LIST_001 @PRIO:1
  Scenario: Biometrie Pairingliste - Gutfall - Erzeuge einen Pairingeintrag für IDNummer und fordere Pairingliste an
    Given IDP I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-d-valid-ecc.p12'
    And IDP I create a device information token with
      | name                 | manufacturer | product     | model | os      | os_version |
      | ${TESTENV.client_id} | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And IDP I create pairing data with
      | se_subject_public_key_info   | key_identifier | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info             |
      | /keys/valid/Pub_Se_Aut-1.pem | keyidlist100   | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-d-valid-ecc.p12 |
    And IDP I sign pairing data with '/certs/valid/egk-idp-idnumber-d-valid-ecc.p12'
    And IDP I register the device with '/certs/valid/egk-idp-idnumber-d-valid-ecc.p12'
    And IDP I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-d-valid-ecc.p12'
    When IDP I request all pairings
    Then the response status is 200
    And IDP the response http headers match
        """
        Cache-Control=no-store
        Pragma=no-cache
        """
    And IDP the JSON response should match
      """
        {
          pairing_entries: [
            {
              creation_time:         ".*",
              signed_pairing_data:   "ey.*",
              name:                  "eRezeptApp",
              pairing_entry_version: ".*"
            }
          ]
        }
      """
    When IDP I deregister the device with 'keyidlist100'
    Then the response status is 204

  @Approval @Ready
  @Afo:A_21452
  @TCID:IDP_REF_LIST_002 @PRIO:1
  Scenario: Biometrie Pairingliste - Gutfall - Erzeuge mehrere Pairingeinträge für IDNummer und fordere Pairingliste an
    Given IDP I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-d-valid-ecc.p12'
    And IDP I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And IDP I create pairing data with
      | se_subject_public_key_info   | key_identifier | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info             | product     |
      | /keys/valid/Pub_Se_Aut-1.pem | keyidlist200   | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-d-valid-ecc.p12 | FairPhone 3 |
    And IDP I sign pairing data with '/certs/valid/egk-idp-idnumber-d-valid-ecc.p12'
    And IDP I register the device with '/certs/valid/egk-idp-idnumber-d-valid-ecc.p12'
    And IDP I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-d-valid-ecc.p12'
    And IDP I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And IDP I create pairing data with
      | se_subject_public_key_info   | key_identifier | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info             |
      | /keys/valid/Pub_Se_Aut-1.pem | keyidlist201   | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-d-valid-ecc.p12 |
    And IDP I sign pairing data with '/certs/valid/egk-idp-idnumber-d-valid-ecc.p12'
    And IDP I register the device with '/certs/valid/egk-idp-idnumber-d-valid-ecc.p12'
    And IDP I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-d-valid-ecc.p12'
    When IDP I request all pairings
    Then the response status is 200
    And IDP the JSON response should match
      """
        {
          pairing_entries: [
            {
              creation_time:         ".*",
              signed_pairing_data:   "ey.*",
              name:                  "eRezeptApp",
              pairing_entry_version: ".*"
            },
            {
              creation_time:         ".*",
              signed_pairing_data:   "ey.*",
              name:                  "eRezeptApp",
              pairing_entry_version: ".*"
            }
          ]
        }
      """
    When IDP I deregister the device with 'keyidlist200'
    Then the response status is 204
    When IDP I deregister the device with 'keyidlist201'
    Then the response status is 204

  @Approval @Ready
  @Afo:A_21452
  @TCID:IDP_REF_LIST_003 @PRIO:1 @Negative
  Scenario: Biometrie Pairingliste - Fordere Pairingliste an für IdNummer, welche kein Pairing hat
    And IDP I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-e-valid-ecc.p12'
    When IDP I request all pairings
    Then the response status is 200
    And IDP the JSON response should match
      """
        {
          pairing_entries: []
        }
      """

  @Approval @Ready
  @Afo:A_21442
  @TCID:IDP_REF_LIST_004 @PRIO:1 @Negative
  Scenario: Biometrie Pairingliste - Fordere Pairingliste an mit eRezept Access Token
    And IDP I request an erezept access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    When IDP I request all pairings
    Then IDP the response is an 403 error with gematik code 4001 and error 'access_denied'


  @Approval @Ready
  @Afo:A_21442
  @TCID:IDP_REF_LIST_005 @PRIO:1 @Negative
  Scenario: Biometrie Pairingliste - Fordere Pairingliste an mit eRezept SSO Token
    And IDP I request an erezept access token via SSO token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    When IDP I request all pairings
    Then IDP the response is an 403 error with gematik code 4001 and error 'access_denied'
