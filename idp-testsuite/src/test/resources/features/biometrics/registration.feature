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
@TODO:GematikErrId
Feature: Registrierung für Alternative Authentisierung am IDP Server

  Frontends müssen mit einer eGK und einem pairing Access oder SSO Token Geräte registrieren können.

  Background: Initialisiere Testkontext durch Abfrage des Discovery Dokuments
    Given I initialize scenario from discovery document endpoint
    And I retrieve public keys from URIs

  @Approval @Ready
  Scenario: Biometrie Register - Gutfall - Registriere ein Pairing
    Given I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'

    When I create a device information token with
      | device_name | device_manufacturer | device_product | device_model | device_os | device_version |
      | eRezeptApp  | Fair Phone          | FairPhone 3    | F3           | Android   | 1.0.2 f        |
    And I create pairing data with
      | key_data                     | key_identifier | signature_algorithm_identifier | device_product | serialnumber    | issuer  | not_after | public_key                                    |
      | /keys/valid/Pub_Se_Aut-1.pem | keyident001    | ES256                          | FairPhone 3    | 419094927676993 | Android | 1.0.2 f   | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    Then the response status is 200
    And the response is empty

  # TODO user agent ? Relevanz, add testcases without user agents if relevant

  # TODO add variants for different PukSE AUThs
  @TODOErlaubenWir2PairingsAufDemselbenDevice?
  @Approval @Ready
  Scenario: Biometrie Register - Gutfall - Zwei Pairings mit identem Identifier und Pub SE Auth aber unterschiedlicher IdNummer
    Given I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I create a device information token with
      | device_name | device_manufacturer | device_product | device_model | device_os | device_version |
      | eRezeptApp  | Fair Phone          | FairPhone 3    | F3           | Android   | 1.0.2 f        |
    And I create pairing data with
      | key_data                     | key_identifier | signature_algorithm_identifier | device_product | serialnumber    | issuer  | not_after | public_key                                    |
      | /keys/valid/Pub_Se_Aut-1.pem | keyident002    | ES256                          | FairPhone 3    | 419094927676993 | Android | 1.0.2 f   | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-b-valid-ecc.p12'
    And I create a device information token with
      | device_name | device_manufacturer | device_product | device_model | device_os | device_version |
      | eRezeptApp  | Fair Phone          | FairPhone 3    | F3           | Android   | 1.0.2 f        |
    And I create pairing data with
      | key_data                     | key_identifier | signature_algorithm_identifier | device_product | serialnumber    | issuer  | not_after | public_key                                    |
      | /keys/valid/Pub_Se_Aut-1.pem | keyident002    | ES256                          | FairPhone 3    | 419094927676993 | Android | 1.0.2 f   | /certs/valid/egk-idp-idnumber-b-valid-ecc.p12 |
    And I sign pairing data with '/certs/valid/egk-idp-idnumber-b-valid-ecc.p12'
    And I register the device with '/certs/valid/egk-idp-idnumber-b-valid-ecc.p12'
    Then the response status is 200
    And the response is empty

  @Approval @Ready
  Scenario: Biometrie Register - Gutfall - Zwei Pairings mit unterschiedlichem key identifier und unterschiedlicher IDNummer
    Given I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I create a device information token with
      | device_name | device_manufacturer | device_product | device_model | device_os | device_version |
      | eRezeptApp  | Fair Phone          | FairPhone 3    | F3           | Android   | 1.0.2 f        |
    And I create pairing data with
      | key_data                     | key_identifier | signature_algorithm_identifier | device_product | serialnumber    | issuer  | not_after | public_key                                    |
      | /keys/valid/Pub_Se_Aut-1.pem | keyident003    | ES256                          | FairPhone 3    | 419094927676993 | Android | 1.0.2 f   | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-b-valid-ecc.p12'
    And I create a device information token with
      | device_name | device_manufacturer | device_product | device_model | device_os | device_version |
      | eRezeptApp  | Fair Phone          | FairPhone 3    | F3           | Android   | 1.0.2 f        |
    And I create pairing data with
      | key_data                     | key_identifier | signature_algorithm_identifier | device_product | serialnumber    | issuer  | not_after | public_key                                    |
      | /keys/valid/Pub_Se_Aut-1.pem | keyident004    | ES256                          | FairPhone 3    | 419094927676993 | Android | 1.0.2 f   | /certs/valid/egk-idp-idnumber-b-valid-ecc.p12 |
    And I sign pairing data with '/certs/valid/egk-idp-idnumber-b-valid-ecc.p12'
    And I register the device with '/certs/valid/egk-idp-idnumber-b-valid-ecc.p12'
    Then the response status is 200
    And the response is empty

  @Approval @Ready
  Scenario: Biometrie Register - Zweifacher Eintragungsversuch Idente Daten
    Given I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I create a device information token with
      | device_name | device_manufacturer | device_product | device_model | device_os | device_version |
      | eRezeptApp  | Fair Phone          | FairPhone 3    | F3           | Android   | 1.0.2 f        |
    And I create pairing data with
      | key_data                     | key_identifier   | signature_algorithm_identifier | device_product | serialnumber    | issuer  | not_after | public_key                                    |
      | /keys/valid/Pub_Se_Aut-1.pem | keyidentdoppel01 | ES256                          | FairPhone 3    | 419094927676993 | Android | 1.0.2 f   | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'

    When I request an access token
    And I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    Then the response status is 409
    And the JSON response should match
        """
          { error:              "invalid_request",
	        gematik_error_text: ".*",
	        gematik_timestamp:  "[\\d]*",
	        gematik_uuid:       ".*",
	        gematik_code:       "-1"
          }
        """

  @Approval @Ready
  Scenario: Biometrie Register - Zweifacher Eintragungsversuch Devicedaten unterschiedlich
    Given I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I create a device information token with
      | device_name | device_manufacturer | device_product | device_model | device_os | device_version |
      | eRezeptApp  | Motorola            | GOTA 1         | G2           | Android   | 1.3.2          |
    And I create pairing data with
      | key_data                     | key_identifier   | signature_algorithm_identifier | device_product | serialnumber    | issuer  | not_after | public_key                                    |
      | /keys/valid/Pub_Se_Aut-1.pem | keyidentdoppel02 | ES256                          | FairPhone 3    | 419094927676993 | Android | 1.0.2 f   | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I request an access token

    When I create a device information token with
      | device_name | device_manufacturer | device_product | device_model | device_os | device_version |
      | eRezeptApp  | Fair Phone          | FairPhone 3    | F3           | Android   | 1.0.2 f        |
    And I create pairing data with
      | key_data                     | key_identifier   | signature_algorithm_identifier | device_product | serialnumber    | issuer  | not_after | public_key                                    |
      | /keys/valid/Pub_Se_Aut-1.pem | keyidentdoppel02 | ES256                          | FairPhone 3    | 419094927676993 | Android | 1.0.2 f   | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    Then the response status is 409
    And the JSON response should match
        """
          { error:              "invalid_request",
	        gematik_error_text: ".*",
	        gematik_timestamp:  "[\\d]*",
	        gematik_uuid:       ".*",
	        gematik_code:       "-1"
          }
        """

  @Approval @Ready
  Scenario: Biometrie Register - Zweifacher Eintragungsversuch alles bis auf key identifier und Zertifikat unterschiedlich
    Given I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I create a device information token with
      | device_name | device_manufacturer | device_product | device_model | device_os | device_version |
      | eRezeptApp  | Motorola            | GOTA 1         | G2           | Ubuntu    | 1.3.2          |
    And I create pairing data with
      | key_data                     | key_identifier   | signature_algorithm_identifier | device_product | serialnumber    | issuer | not_after | public_key                                    |
      | /keys/valid/Pub_Se_Aut-1.pem | keyidentdoppel03 | ES256                          | GOTA 1         | 419094927676993 | Ubuntu | 1.3.2     | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I request an access token

    When I create a device information token with
      | device_name | device_manufacturer | device_product | device_model | device_os | device_version |
      | eRezeptApp  | Fair Phone          | FairPhone 3    | F3           | Android   | 1.0.2 f        |
    And I create pairing data with
      | key_data                     | key_identifier   | signature_algorithm_identifier | device_product | serialnumber    | issuer  | not_after | public_key                                    |
      | /keys/valid/Pub_Se_Aut-1.pem | keyidentdoppel03 | ES256                          | FairPhone 3    | 419094927676993 | Android | 1.0.2 f   | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    Then the response status is 409
    And the JSON response should match
        """
          { error:              "invalid_request",
	        gematik_error_text: ".*",
	        gematik_timestamp:  "[\\d]*",
	        gematik_uuid:       ".*",
	        gematik_code:       "-1"
          }
        """

    # TODO check variants regarding new info about keys/certs

  @issue:IDP-453 @OpenBug
    @Approval
  Scenario Outline: Biometrie Register - Unterschiedliche Zertifikate mit identer IDNummer in Verwendung
    # Real world scenario: alte Karte verloren, neue Karte, neues Zert, alte Karte wieder verwendet, bevor diese abgelaufen ist/gesperrt wurde
    Given I request an pairing access token with eGK cert '/certs/valid/<cert_access>'

    When I create a device information token with
      | device_name | device_manufacturer | device_product | device_model | device_os | device_version |
      | eRezeptApp  | Fair Phone          | FairPhone 3    | F3           | Android   | 1.0.2 f        |
    And I create pairing data with
      | key_data                   | key_identifier   | signature_algorithm_identifier | device_product | serialnumber    | issuer  | not_after | public_key                     |
      | /keys/valid/<cert_keydata> | <key_identifier> | ES256                          | FairPhone 3    | 419094927676993 | Android | 1.0.2 f   | /certs/valid/<cert_public_key> |
    And I sign pairing data with '/certs/valid/<cert_sign>'
    And I register the device with '/certs/valid/<cert_register>'
    Then the response status is <status>
    And the JSON response should match
        """
          { error:              "<errcode>",
	        gematik_error_text: ".*",
	        gematik_timestamp:  "[\\d]*",
	        gematik_uuid:       ".*",
	        gematik_code:       "<errid>"
          }
        """

    #TODO Clarify with Spec: first and second scenario is OK?
    Examples: Liste mit Einträgen wo immer ein Zertifikat unterschiedlich aber gültig ist
      | status | errcode                 | errid | key_identifier     | cert_access                           | cert_keydata     | cert_public_key                       | cert_sign                             | cert_register                         |
      | 400    | invalid_parameter_value | -1    | keyidentdiffcert01 | egk-idp-idnumber-a-folgekarte-ecc.p12 | Pub_Se_Aut-1.pem | egk-idp-idnumber-a-valid-ecc.p12      | egk-idp-idnumber-a-valid-ecc.p12      | egk-idp-idnumber-a-valid-ecc.p12      |
      | 500    | internal_server_error   | -1    | keyidentdiffcert03 | egk-idp-idnumber-a-valid-ecc.p12      | Pub_Se_Aut-1.pem | egk-idp-idnumber-a-folgekarte-ecc.p12 | egk-idp-idnumber-a-valid-ecc.p12      | egk-idp-idnumber-a-valid-ecc.p12      |
      | 400    | invalid_request         | -1    | keyidentdiffcert04 | egk-idp-idnumber-a-valid-ecc.p12      | Pub_Se_Aut-1.pem | egk-idp-idnumber-a-valid-ecc.p12      | egk-idp-idnumber-a-folgekarte-ecc.p12 | egk-idp-idnumber-a-valid-ecc.p12      |
      | 400    | invalid_request         | -1    | keyidentdiffcert05 | egk-idp-idnumber-a-valid-ecc.p12      | Pub_Se_Aut-1.pem | egk-idp-idnumber-a-valid-ecc.p12      | egk-idp-idnumber-a-valid-ecc.p12      | egk-idp-idnumber-a-folgekarte-ecc.p12 |

  @Approval @Ready
    @OpenBug
  Scenario Outline: Biometrie Register - Unterschiedliche Zertifikate mit unterschiedlicher IDNummer in Verwendung
    Given I request an pairing access token with eGK cert '/certs/valid/<cert_access>'

    When I create a device information token with
      | device_name | device_manufacturer | device_product | device_model | device_os | device_version |
      | eRezeptApp  | Fair Phone          | FairPhone 3    | F3           | Android   | 1.0.2 f        |
    And I create pairing data with
      | key_data                   | key_identifier   | signature_algorithm_identifier | device_product | serialnumber    | issuer  | not_after | public_key                     |
      | /keys/valid/<cert_keydata> | <key_identifier> | ES256                          | FairPhone 3    | 419094927676993 | Android | 1.0.2 f   | /certs/valid/<cert_public_key> |
    And I sign pairing data with '/certs/valid/<cert_sign>'
    And I register the device with '/certs/valid/<cert_register>'
    Then the response status is <status>
    And the JSON response should match
        """
          { error:              "<errcode>",
	        gematik_error_text: ".*",
	        gematik_timestamp:  "[\\d]*",
	        gematik_uuid:       ".*",
	        gematik_code:       "<errid>"
          }
        """

    Examples: Liste mit Einträgen wo immer ein Zertifikat mit anderer IDNummer unterschiedlich aber gültig ist
      | status | errcode                 | errid | key_identifier     | cert_access                      | cert_keydata     | cert_public_key                  | cert_sign                        | cert_register                    |
      | 400    | invalid_parameter_value | -1    | keyidentdiffcert01 | egk-idp-idnumber-b-valid-ecc.p12 | Pub_Se_Aut-1.pem | egk-idp-idnumber-a-valid-ecc.p12 | egk-idp-idnumber-a-valid-ecc.p12 | egk-idp-idnumber-a-valid-ecc.p12 |
      | 409    | invalid_request         | -1    | keyidentdiffcert03 | egk-idp-idnumber-a-valid-ecc.p12 | Pub_Se_Aut-1.pem | egk-idp-idnumber-b-valid-ecc.p12 | egk-idp-idnumber-a-valid-ecc.p12 | egk-idp-idnumber-a-valid-ecc.p12 |
      | 400    | invalid_request         | -1    | keyidentdiffcert04 | egk-idp-idnumber-a-valid-ecc.p12 | Pub_Se_Aut-1.pem | egk-idp-idnumber-a-valid-ecc.p12 | egk-idp-idnumber-b-valid-ecc.p12 | egk-idp-idnumber-a-valid-ecc.p12 |
      | 400    | invalid_parameter_value | -1    | keyidentdiffcert05 | egk-idp-idnumber-a-valid-ecc.p12 | Pub_Se_Aut-1.pem | egk-idp-idnumber-a-valid-ecc.p12 | egk-idp-idnumber-a-valid-ecc.p12 | egk-idp-idnumber-b-valid-ecc.p12 |

  @Approval
  Scenario Outline: Biometrie Register - Null Werte in device info

    Given I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'

    When I create a device information token with
      | device_name   | device_manufacturer   | device_product   | device_model   | device_os   | device_version   |
      | <device_name> | <device_manufacturer> | <device_product> | <device_model> | <device_os> | <device_version> |
    And I create pairing data with
      | key_data                     | key_identifier  | signature_algorithm_identifier | device_product | serialnumber    | issuer  | not_after | public_key                                    |
      | /keys/valid/Pub_Se_Aut-1.pem | <keyidentifier> | ES256                          | Fair Phone 3   | 419094927676993 | Android | 1.0.2 f   | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    Then the response status is 400
    And the JSON response should match
        """
          { error:              "invalid_request",
	        gematik_error_text: ".*",
	        gematik_timestamp:  "[\\d]*",
	        gematik_uuid:       ".*",
	        gematik_code:       "-1"
          }
        """

    Examples: Biometrie Register - Null Device Info Beispiele
      | keyidentifier  | device_name | device_manufacturer | device_product | device_model | device_os | device_version |
      | keyidentnull01 | $NULL       | Fair Phone          | FairPhone 3    | F3           | Android   | 1.0.2 f        |
      | keyidentnull02 | eRezeptApp  | $NULL               | FairPhone 3    | F3           | Android   | 1.0.2 f        |
      | keyidentnull03 | eRezeptApp  | Fair Phone          | $NULL          | F3           | Android   | 1.0.2 f        |
      | keyidentnull04 | eRezeptApp  | Fair Phone          | FairPhone 3    | $NULL        | Android   | 1.0.2 f        |
      | keyidentnull05 | eRezeptApp  | Fair Phone          | FairPhone 3    | F3           | $NULL     | 1.0.2 f        |
      | keyidentnull06 | eRezeptApp  | Fair Phone          | FairPhone 3    | F3           | Android   | $NULL          |

  @Approval
  Scenario Outline: Biometrie Register - Fehlende Werte in device info
    Given I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'

    When I create a device information token with
      | device_name   | device_manufacturer   | device_product   | device_model   | device_os   | device_version   |
      | <device_name> | <device_manufacturer> | <device_product> | <device_model> | <device_os> | <device_version> |
    And I create pairing data with
      | key_data                     | key_identifier  | signature_algorithm_identifier | device_product | serialnumber    | issuer  | not_after | public_key                                    |
      | /keys/valid/Pub_Se_Aut-1.pem | <keyidentifier> | ES256                          | Fair Phone 3   | 419094927676993 | Android | 1.0.2 f   | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    Then the response status is 400
    And the JSON response should match
        """
          { error:              "invalid_request",
	        gematik_error_text: ".*",
	        gematik_timestamp:  "[\\d]*",
	        gematik_uuid:       ".*",
	        gematik_code:       "-1"
          }
        """

    Examples: Biometrie Register - Fehlende Device info Beispiele
      | keyidentifier    | device_name | device_manufacturer | device_product | device_model | device_os | device_version |
      | keyidentremove01 | $REMOVE     | Fair Phone          | FairPhone 3    | F3           | Android   | 1.0.2 f        |
      | keyidentremove02 | eRezeptApp  | $REMOVE             | FairPhone 3    | F3           | Android   | 1.0.2 f        |
      | keyidentremove03 | eRezeptApp  | Fair Phone          | $REMOVE        | F3           | Android   | 1.0.2 f        |
      | keyidentremove04 | eRezeptApp  | Fair Phone          | FairPhone 3    | $REMOVE      | Android   | 1.0.2 f        |
      | keyidentremove05 | eRezeptApp  | Fair Phone          | FairPhone 3    | F3           | $REMOVE   | 1.0.2 f        |
      | keyidentremove06 | eRezeptApp  | Fair Phone          | FairPhone 3    | F3           | Android   | $REMOVE        |

  @Approval
  Scenario Outline: Biometrie Register - Null Werte in pairing data

    Given I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'

    When I create a device information token with
      | device_name | device_manufacturer | device_product | device_model | device_os | device_version |
      | eRezeptApp  | Motorola            | GOTA 1         | G2           | Android   | 1.3.2          |
    And I create pairing data with
      | key_data   | key_identifier  | signature_algorithm_identifier   | device_product   | serialnumber   | issuer   | not_after   | public_key   |
      | <key_data> | <keyidentifier> | <signature_algorithm_identifier> | <device_product> | <serialnumber> | <issuer> | <not_after> | <public_key> |
    And I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    Then the response status is 400
    And the JSON response should match
        """
          { error:              "invalid_request",
	        gematik_error_text: ".*",
	        gematik_timestamp:  "[\\d]*",
	        gematik_uuid:       ".*",
	        gematik_code:       "-1"
          }
        """

    Examples: Biometrie Register - Null Pairing Data Beispiele
      | keyidentifier  | key_data                     | signature_algorithm_identifier | device_product | serialnumber    | issuer  | not_after | public_key                                    |
      | keyidentnull11 | $NULL                        | ES256                          | FairPhone 3    | 419094927676993 | Android | 1.0.2 f   | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
      | keyidentnull12 | /keys/valid/Pub_Se_Aut-1.pem | $NULL                          | FairPhone 3    | 419094927676993 | Android | 1.0.2 f   | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
      | keyidentnull13 | /keys/valid/Pub_Se_Aut-1.pem | ES256                          | $NULL          | 419094927676993 | Android | 1.0.2 f   | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
      | keyidentnull14 | /keys/valid/Pub_Se_Aut-1.pem | ES256                          | FairPhone 3    | $NULL           | Android | 1.0.2 f   | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
      | keyidentnull15 | /keys/valid/Pub_Se_Aut-1.pem | ES256                          | FairPhone 3    | 419094927676993 | $NULL   | 1.0.2 f   | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
      | keyidentnull16 | /keys/valid/Pub_Se_Aut-1.pem | ES256                          | FairPhone 3    | 419094927676993 | Android | $NULL     | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
      | keyidentnull17 | /keys/valid/Pub_Se_Aut-1.pem | ES256                          | FairPhone 3    | 419094927676993 | Android | 1.0.2 f   | $NULL                                         |

  @Approval
  Scenario Outline: Biometrie Register - Fehlende Werte in pairing data
    Given I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'

    When I create a device information token with
      | device_name | device_manufacturer | device_product | device_model | device_os | device_version |
      | eRezeptApp  | Motorola            | GOTA 1         | G2           | Android   | 1.3.2          |
    And I create pairing data with
      | key_data   | key_identifier  | signature_algorithm_identifier   | device_product   | serialnumber   | issuer   | not_after   | public_key   |
      | <key_data> | <keyidentifier> | <signature_algorithm_identifier> | <device_product> | <serialnumber> | <issuer> | <not_after> | <public_key> |
    And I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    Then the response status is 400
    And the JSON response should match
        """
          { error:              "invalid_request",
	        gematik_error_text: ".*",
	        gematik_timestamp:  "[\\d]*",
	        gematik_uuid:       ".*",
	        gematik_code:       "-1"
          }
        """

    Examples: Biometrie Register - Fehlende Pairing Data Beispiele
      | keyidentifier    | key_data                     | signature_algorithm_identifier | device_product | serialnumber    | issuer  | not_after | public_key                                    |
      | keyidentremove11 | $REMOVE                      | ES256                          | FairPhone 3    | 419094927676993 | Android | 1.0.2 f   | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
      | keyidentremove12 | /keys/valid/Pub_Se_Aut-1.pem | $REMOVE                        | FairPhone 3    | 419094927676993 | Android | 1.0.2 f   | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
      | keyidentremove13 | /keys/valid/Pub_Se_Aut-1.pem | ES256                          | $REMOVE        | 419094927676993 | Android | 1.0.2 f   | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
      | keyidentremove14 | /keys/valid/Pub_Se_Aut-1.pem | ES256                          | FairPhone 3    | $REMOVE         | Android | 1.0.2 f   | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
      | keyidentremove15 | /keys/valid/Pub_Se_Aut-1.pem | ES256                          | FairPhone 3    | 419094927676993 | $REMOVE | 1.0.2 f   | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
      | keyidentremove16 | /keys/valid/Pub_Se_Aut-1.pem | ES256                          | FairPhone 3    | 419094927676993 | Android | $REMOVE   | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
      | keyidentremove17 | /keys/valid/Pub_Se_Aut-1.pem | ES256                          | FairPhone 3    | 419094927676993 | Android | 1.0.2 f   | $REMOVE                                       |

  @Approval @issue:IDP-470 @OpenBug
  Scenario Outline: Biometrie Register - Ungültige Zertifikate (selfsigned, outdated, revoced)
    Given I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'

    When I create a device information token with
      | device_name | device_manufacturer | device_product | device_model | device_os | device_version |
      | eRezeptApp  | Motorola            | GOTA 1         | G2           | Android   | 1.3.2          |
    And I create pairing data with
      | key_data                     | key_identifier  | signature_algorithm_identifier | device_product | serialnumber    | issuer  | not_after | public_key    |
      | /keys/valid/Pub_Se_Aut-1.pem | <keyidentifier> | ES256                          | FairPhone 3    | 419094927676993 | Android | 1.0.2 f   | <invalidcert> |
    And I sign pairing data with '<invalidcert>'
    And I register the device with '<invalidcert>'
    Then the response status is 500
    And the JSON response should match
        """
          { error:              "invalid_request",
	        gematik_error_text: ".*",
	        gematik_timestamp:  "[\\d]*",
	        gematik_uuid:       ".*",
	        gematik_code:       "-1"
          }
        """

    Examples: Biometrie Register - Ungültige Zertifikate
      | keyidentifier     | invalidcert                                              |
      | keyidentinvcert01 | /certs/invalid/egk-idp-idnumber-a-expired-ecc.p12        |
      | keyidentinvcert02 | /certs/invalid/egk-idp-idnumber-a-invalid-issuer-ecc.p12 |
      | keyidentinvcert03 | /certs/invalid/egk-idp-idnumber-a-revoked-ecc.p12        |

  @Approval @OpenBug
  Scenario Outline: Biometrie Register - Registriere Pairing mit Zertifikat ohne IDNummer
    Given I request an pairing access token with eGK cert '/certs/valid/<cert_access>'

    When I create a device information token with
      | device_name | device_manufacturer | device_product | device_model | device_os | device_version |
      | eRezeptApp  | Fair Phone          | FairPhone 3    | F3           | Android   | 1.0.2 f        |
    And I create pairing data with
      | key_data                   | key_identifier   | signature_algorithm_identifier | device_product | serialnumber    | issuer  | not_after | public_key                     |
      | /keys/valid/<cert_keydata> | <key_identifier> | ES256                          | FairPhone 3    | 419094927676993 | Android | 1.0.2 f   | /certs/valid/<cert_public_key> |
    And I sign pairing data with '/certs/valid/<cert_sign>'
    And I register the device with '/certs/valid/<cert_register>'
    Then the response status is <status>
    And the JSON response should match
         """
          { error:              "<errcode>",
	        gematik_error_text: ".*",
	        gematik_timestamp:  "[\\d]*",
	        gematik_uuid:       ".*",
	        gematik_code:       "<errid>"
          }
        """

    Examples: Liste mit Einträgen wo immer ein Zertifikat ohne IdNummer verwendet wird
      | status | errcode               | errid | key_identifier | cert_access                      | cert_keydata     | cert_public_key                   | cert_sign                         | cert_register                     |
      | 500    | internal_server_error | -1    | keyidentnoid03 | egk-idp-idnumber-a-valid-ecc.p12 | Pub_Se_Aut-1.pem | egk-idp-idnumber-missing1-ecc.p12 | egk-idp-idnumber-a-valid-ecc.p12  | egk-idp-idnumber-a-valid-ecc.p12  |
      | 400    | invalid_request       | -1    | keyidentnoid04 | egk-idp-idnumber-a-valid-ecc.p12 | Pub_Se_Aut-1.pem | egk-idp-idnumber-a-valid-ecc.p12  | egk-idp-idnumber-missing1-ecc.p12 | egk-idp-idnumber-a-valid-ecc.p12  |
      | 500    | internal_server_error | -1    | keyidentnoid05 | egk-idp-idnumber-a-valid-ecc.p12 | Pub_Se_Aut-1.pem | egk-idp-idnumber-a-valid-ecc.p12  | egk-idp-idnumber-a-valid-ecc.p12  | egk-idp-idnumber-missing1-ecc.p12 |

  @manual
  @manual-result:passed
  Scenario: Biometrie Register - Ungültige Werte in device info, derzeit keine Einschränkung, daher OK

  @Todo:Implementieren
  @WiP
  @Approval
  Scenario: Biometrie Register - Ungültige Werte in pairing data
    #TODO derzeit macht nur certid / nach Umstellung cert sn sinn
    # TODO Gerriet/Hannes was ist eine gültig SN, welche ist nicht gültig?

  @Afo:A_20463
  @LongRunning
  @Approval @Ready
  Scenario: Biometrie Register - Pairing mit veraltetem Access Token wird abgelehnt
    Given I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I create a device information token with
      | device_name | device_manufacturer | device_product | device_model | device_os | device_version |
      | eRezeptApp  | Fair Phone          | FairPhone 3    | F3           | Android   | 1.0.2 f        |
    And I create pairing data with
      | key_data                     | key_identifier | signature_algorithm_identifier | device_product | serialnumber    | issuer  | not_after | public_key                                    |
      | /keys/valid/Pub_Se_Aut-1.pem | keyidentacc001 | ES256                          | FairPhone 3    | 419094927676993 | Android | 1.0.2 f   | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'

    When I wait PT5M
    And I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
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

  # TODO Hannes klärt Scenario: Biometrie Register - Gültigkeitsdauer der signierten Pairing data?

  @Approval
  Scenario: Biometrie Register - Zugriff mit ACCESS_TOKEN von signierter Challenge mit falschem Scope (erezept)
    Given I request an erezept access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'

    When I create a device information token with
      | device_name | device_manufacturer | device_product | device_model | device_os | device_version |
      | eRezeptApp  | Fair Phone          | FairPhone 3    | F3           | Android   | 1.0.2 f        |
    And I create pairing data with
      | key_data                     | key_identifier | signature_algorithm_identifier | device_product | serialnumber    | issuer  | not_after | public_key                                    |
      | /keys/valid/Pub_Se_Aut-1.pem | keyidentacc001 | ES256                          | FairPhone 3    | 419094927676993 | Android | 1.0.2 f   | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
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

  @Approval
  Scenario: Biometrie Register - Zugriff mit ACCESS_TOKEN via SSO Token mit falschem Scope (erezept)
    Given I request an erezept access token via SSO token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'

    When I create a device information token with
      | device_name | device_manufacturer | device_product | device_model | device_os | device_version |
      | eRezeptApp  | Fair Phone          | FairPhone 3    | F3           | Android   | 1.0.2 f        |
    And I create pairing data with
      | key_data                     | key_identifier | signature_algorithm_identifier | device_product | serialnumber    | issuer  | not_after | public_key                                    |
      | /keys/valid/Pub_Se_Aut-1.pem | keyidentacc001 | ES256                          | FairPhone 3    | 419094927676993 | Android | 1.0.2 f   | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
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
