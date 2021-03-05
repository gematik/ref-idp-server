#
# Copyright (c) 2021 gematik GmbH
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#    http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

@testsuite
@biometrics
Feature: Fordere Pairingliste für Alternative Authentisierung am IDP Server an

  Frontends müssen mit einer eGK und einem Pairing Access oder SSO Token ihre Pairings einsehen können.

  Background: Initialisiere Testkontext durch Abfrage des Discovery Dokuments
    Given I initialize scenario from discovery document endpoint
    And I retrieve public keys from URIs

  @Approval @Ready
  Scenario: Biometrie Pairingliste - Gutfall - Erzeuge einen Pairingeintrag für IDNummer und fordere Pairingliste an
    Given I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-d-valid-ecc.p12'
    And I create a device information token with
      | device_name | device_manufacturer | device_product | device_model | device_os | device_version |
      | eRezeptApp  | Fair Phone          | FairPhone 3    | F3           | Android   | 1.0.2 f        |
    And I create pairing data with
      | key_data                     | key_identifier | signature_algorithm_identifier | device_product | serialnumber    | issuer  | not_after | public_key                                    |
      | /keys/valid/Pub_Se_Aut-1.pem | keyidlist100   | ES256                          | FairPhone 3    | 419094927676993 | Android | 1.0.2 f   | /certs/valid/egk-idp-idnumber-d-valid-ecc.p12 |
    And I sign pairing data with '/certs/valid/egk-idp-idnumber-d-valid-ecc.p12'
    And I register the device with '/certs/valid/egk-idp-idnumber-d-valid-ecc.p12'
    And I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-d-valid-ecc.p12'
    When I request all pairings
    Then the response status is 200
    And the JSON Array response should match
      """
        [
          {
            keyIdentifier:      "keyidlist100",
            timestampPairing:   ".*",
            signedPairingData:  "ey.*",
            id:                 ".*",
            idNumber:           "X764228433",
            deviceName:         "eRezeptApp"
          }
        ]
      """

  @Approval @Ready
  Scenario: Biometrie Pairingliste - Gutfall - Erzeuge mehrere Pairingeinträge für IDNummer und fordere Pairingliste an
    Given I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-d-valid-ecc.p12'
    And I create a device information token with
      | device_name | device_manufacturer | device_product | device_model | device_os | device_version |
      | eRezeptApp  | Fair Phone          | FairPhone 3    | F3           | Android   | 1.0.2 f        |
    And I create pairing data with
      | key_data                     | key_identifier | signature_algorithm_identifier | device_product | serialnumber    | issuer  | not_after | public_key                                    |
      | /keys/valid/Pub_Se_Aut-1.pem | keyidlist200   | ES256                          | FairPhone 3    | 419094927676993 | Android | 1.0.2 f   | /certs/valid/egk-idp-idnumber-d-valid-ecc.p12 |
    And I sign pairing data with '/certs/valid/egk-idp-idnumber-d-valid-ecc.p12'
    And I register the device with '/certs/valid/egk-idp-idnumber-d-valid-ecc.p12'
    And I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-d-valid-ecc.p12'
    And I create a device information token with
      | device_name | device_manufacturer | device_product | device_model | device_os | device_version |
      | eRezeptApp  | Fair Phone          | FairPhone 3    | F3           | Android   | 1.0.2 f        |
    And I create pairing data with
      | key_data                     | key_identifier | signature_algorithm_identifier | device_product | serialnumber    | issuer  | not_after | public_key                                    |
      | /keys/valid/Pub_Se_Aut-1.pem | keyidlist201   | ES256                          | FairPhone 3    | 419094927676993 | Android | 1.0.2 f   | /certs/valid/egk-idp-idnumber-d-valid-ecc.p12 |
    And I sign pairing data with '/certs/valid/egk-idp-idnumber-d-valid-ecc.p12'
    And I register the device with '/certs/valid/egk-idp-idnumber-d-valid-ecc.p12'
    And I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-d-valid-ecc.p12'
    When I request all pairings
    Then the response status is 200
    And the JSON Array response should match
      """
        [
          {
            keyIdentifier:      "keyidlist100",
            timestampPairing:   ".*",
            signedPairingData:  "ey.*",
            id:                 ".*",
            idNumber:           "X764228433",
            deviceName:         "eRezeptApp"
          },
          {
            keyIdentifier:      "keyidlist200",
            timestampPairing:   ".*",
            signedPairingData:  "ey.*",
            id:                 ".*",
            idNumber:           "X764228433",
            deviceName:         "eRezeptApp"
          },
          {
            keyIdentifier:      "keyidlist201",
            timestampPairing:   ".*",
            signedPairingData:  "ey.*",
            id:                 ".*",
            idNumber:           "X764228433",
            deviceName:         "eRezeptApp"
          }
        ]
      """

  @Approval @Ready
  Scenario: Biometrie Pairingliste - Fordere Pairingliste an für IdNummer, welche kein Pairing hat
    And I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-e-valid-ecc.p12'
    When I request all pairings
    Then the response status is 200
    And the JSON Array response should match
      """
        []
      """

  @Approval @Ready
  Scenario: Biometrie Pairingliste - Fordere Pairingliste an mit eRezept Access Token
    And I request an erezept access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    When I request all pairings
    Then the response status is 403
    And the JSON response should match
        """
          { error:              "access_denied",
	        gematik_error_text: ".*",
	        gematik_timestamp:  "[\\d]*",
	        gematik_uuid:       ".*",
	        gematik_code:       "-1"
          }
        """

  @Approval @Ready
  Scenario: Biometrie Pairingliste - Fordere Pairingliste an mit eRezept SSO Token
    And I request an erezept access token via SSO token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    When I request all pairings
    Then the response status is 403
    And the JSON response should match
        """
          { error:              "access_denied",
	        gematik_error_text: ".*",
	        gematik_timestamp:  "[\\d]*",
	        gematik_uuid:       ".*",
	        gematik_code:       "-1"
          }
        """

  # obsolet da wir keinen access token kriegen
  # Scenario: Biometrie Pairingliste - Fordere Pairingliste an mit Zertifikat ohne IDNummer

