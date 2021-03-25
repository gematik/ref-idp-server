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
Feature: Deregistrierung für Alternative Authentisierung am IDP Server

  Frontends müssen mit eGK und auch mit alternativer Authentisierung Geräte deregistrieren können.

  Background: Initialisiere Testkontext durch Abfrage des Discovery Dokuments
    Given I initialize scenario from discovery document endpoint
    And I retrieve public keys from URIs

  @Approval @Ready
  Scenario: Biometrie Deregister - Gutfall - Erzeuge Pairing und lösche dieses wieder
    Given I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And I create pairing data with
      | se_subject_public_key_info   | key_identifier | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info             |
      | /keys/valid/Pub_Se_Aut-1.pem | keyiddereg001  | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'

    When I deregister the device with 'keyiddereg001'
    Then the response status is 200

  @Approval @Ready
  Scenario: Biometrie Deregister - Gutfall - Erzeuge mehrere Pairings und lösche nur eines
    Given I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-c-valid-ecc.p12'
    And I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And I create pairing data with
      | se_subject_public_key_info   | key_identifier | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info             |
      | /keys/valid/Pub_Se_Aut-1.pem | keyiddereg100  | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-c-valid-ecc.p12 |
    And I sign pairing data with '/certs/valid/egk-idp-idnumber-c-valid-ecc.p12'
    And I register the device with '/certs/valid/egk-idp-idnumber-c-valid-ecc.p12'
    And I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-c-valid-ecc.p12'
    And I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And I create pairing data with
      | se_subject_public_key_info   | key_identifier | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info             |
      | /keys/valid/Pub_Se_Aut-1.pem | keyiddereg101  | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-c-valid-ecc.p12 |
    And I sign pairing data with '/certs/valid/egk-idp-idnumber-c-valid-ecc.p12'
    And I register the device with '/certs/valid/egk-idp-idnumber-c-valid-ecc.p12'
    And I deregister the device with 'keyiddereg101'
    When I request all pairings
    Then the response status is 200
    And the JSON response should match
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

  @Approval @Ready
  Scenario: Biometrie Deregister - Lösche Pairing für nicht existenten key identifier

  ```
  Die Anfrage soll OHNE Fehlermeldung behandelt werden um keine Informationen über (nicht-)existierende
  Pairings nach außen zu geben.

    Given I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-c-valid-ecc.p12'
    When I deregister the device with 'keyidderegNEDDA'
    Then the response status is 200
    And the response should match
      """
      """

  @Approval @Ready
  Scenario: Biometrie Deregister - Lösche Pairing für key identifier einer anderen IDNummer

  ```
  Die Anfrage soll OHNE Fehlermeldung behandelt werden um keine Informationen über (nicht-)existierende
  Pairings nach außen zu geben.

    Given I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-c-valid-ecc.p12'
    And I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And I create pairing data with
      | se_subject_public_key_info   | key_identifier | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info             |
      | /keys/valid/Pub_Se_Aut-1.pem | keyiddereg200  | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-c-valid-ecc.p12 |
    And I sign pairing data with '/certs/valid/egk-idp-idnumber-c-valid-ecc.p12'
    And I register the device with '/certs/valid/egk-idp-idnumber-c-valid-ecc.p12'
    Given I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I deregister the device with 'keyiddereg200'
    Then the response status is 200
    And the response should match
      """
      """

  # Scenario: Biometrie Deregister - Lösche Pairing mit Zertifikate ohne IDNummer
  # So nicht testbar, da kein access token angefordert werden kann

  @Approval @Ready
  Scenario: Biometrie Deregister - Lösche Pairing mit e-Rezept Access Token
    Given I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-c-valid-ecc.p12'
    And I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And I create pairing data with
      | se_subject_public_key_info   | key_identifier | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info             |
      | /keys/valid/Pub_Se_Aut-1.pem | keyiddereg300  | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-c-valid-ecc.p12 |
    And I sign pairing data with '/certs/valid/egk-idp-idnumber-c-valid-ecc.p12'
    And I register the device with '/certs/valid/egk-idp-idnumber-c-valid-ecc.p12'
    Given I request an erezept access token with eGK cert '/certs/valid/egk-idp-idnumber-c-valid-ecc.p12'
    And I deregister the device with 'keyiddereg300'
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
  Scenario: Biometrie Deregister - Lösche Pairing mit e-Rezept SSO Token
    Given I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-c-valid-ecc.p12'
    And I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And I create pairing data with
      | se_subject_public_key_info   | key_identifier | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info             |
      | /keys/valid/Pub_Se_Aut-1.pem | keyiddereg400  | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-c-valid-ecc.p12 |
    And I sign pairing data with '/certs/valid/egk-idp-idnumber-c-valid-ecc.p12'
    And I register the device with '/certs/valid/egk-idp-idnumber-c-valid-ecc.p12'
    Given I request an erezept access token via SSO token with eGK cert '/certs/valid/egk-idp-idnumber-c-valid-ecc.p12'
    And I deregister the device with 'keyiddereg400'
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
  Scenario: Biometrie Deregister - Lösche Pairing fehlender key identifier in der Anfrage
    Given I request an pairing access token via SSO token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    When I deregister the device with '$REMOVE'
    Then the response status is 405
    And the JSON response should match
        """
          { error:              "invalid_request",
	        gematik_error_text: ".*",
	        gematik_timestamp:  "[\\d]*",
	        gematik_uuid:       ".*",
	        gematik_code:       "-1"
          }
        """

  @Approval
  Scenario: Biometrie Deregister - Lösche Pairing Null key identifier in der Anfrage
  ```
  Das Senden eines null Wertes wird am Server als KeyIdentifier "null" interpretiert.

  Da es dazu keinen Eintrag gibt und um potentiall exisitierende KeyIdentifier nicht zu verraten wird,
  statt eines Fehlers hier eine leere 200 Antwort gesendet.

    Given I request an pairing access token via SSO token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    When I deregister the device with '$NULL'
    Then the response status is 200
    And the response should match
        """
        """
