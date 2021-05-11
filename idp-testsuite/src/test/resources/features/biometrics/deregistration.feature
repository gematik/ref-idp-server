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

@Biometrics
Feature: Deregistrierung für Alternative Authentisierung am IDP Server

  Frontends müssen mit eGK und auch mit alternativer Authentisierung Geräte deregistrieren können.

  Background: Initialisiere Testkontext durch Abfrage des Discovery Dokuments
    Given IDP I initialize scenario from discovery document endpoint
    And IDP I retrieve public keys from URIs


  @TCID:IDP_REF_DEREG_001
  Scenario Outline: GetToken signed authentication data - Gutfall - Löschen alle Pairings vor Start der Tests

  ```
  Wir löschen vor den Tests alle Pairings die danach angelegt werden sollen.

    Given IDP I request an pairing access token with eGK cert '<auth_cert>'
    And IDP I deregister the device with '<key_id>'

    Examples: Zu deregistrierende Daten
      | auth_cert                                     | key_id        |
      | /certs/valid/egk-idp-idnumber-c-valid-ecc.p12 | keyiddereg001 |
      | /certs/valid/egk-idp-idnumber-c-valid-ecc.p12 | keyiddereg101 |
      | /certs/valid/egk-idp-idnumber-c-valid-ecc.p12 | keyiddereg200 |
      | /certs/valid/egk-idp-idnumber-c-valid-ecc.p12 | keyiddereg300 |
      | /certs/valid/egk-idp-idnumber-c-valid-ecc.p12 | keyiddereg400 |


  @Approval @Ready
  @Afo:A_21447
  @TCID:IDP_REF_DEREG_002
  Scenario: Biometrie Deregister - Gutfall - Erzeuge Pairing und lösche dieses wieder
    Given IDP I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And IDP I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And IDP I create pairing data with
      | se_subject_public_key_info   | key_identifier | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info             |
      | /keys/valid/Pub_Se_Aut-1.pem | keyiddereg001  | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And IDP I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And IDP I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'

    When IDP I deregister the device with 'keyiddereg001'
    Then the response status is 204
    # TODO REF 204

  @Approval @Ready
  @Afo:A_21447
  @TCID:IDP_REF_DEREG_003
  Scenario: Biometrie Deregister - Gutfall - Erzeuge mehrere Pairings und lösche nur eines
    Given IDP I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-c-valid-ecc.p12'
    And IDP I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And IDP I create pairing data with
      | se_subject_public_key_info   | key_identifier | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info             |
      | /keys/valid/Pub_Se_Aut-1.pem | keyiddereg100  | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-c-valid-ecc.p12 |
    And IDP I sign pairing data with '/certs/valid/egk-idp-idnumber-c-valid-ecc.p12'
    And IDP I register the device with '/certs/valid/egk-idp-idnumber-c-valid-ecc.p12'
    And IDP I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-c-valid-ecc.p12'
    And IDP I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And IDP I create pairing data with
      | se_subject_public_key_info   | key_identifier | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info             |
      | /keys/valid/Pub_Se_Aut-1.pem | keyiddereg101  | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-c-valid-ecc.p12 |
    And IDP I sign pairing data with '/certs/valid/egk-idp-idnumber-c-valid-ecc.p12'
    And IDP I register the device with '/certs/valid/egk-idp-idnumber-c-valid-ecc.p12'
    And IDP I deregister the device with 'keyiddereg101'
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
            }
          ]
        }
      """

  @Approval @Ready
  @Afo:A_21447 @Afo:A_21448
  @TCID:IDP_REF_DEREG_004
  Scenario: Biometrie Deregister - Lösche Pairing für nicht existenten key identifier

  ```
  Die Anfrage soll OHNE Fehlermeldung behandelt werden um keine Informationen über (nicht-)existierende
  Pairings nach außen zu geben.

    Given IDP I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-c-valid-ecc.p12'
    When IDP I deregister the device with 'keyidderegNEDDA'
    Then the response status is 204
    And IDP the response should match
      """
      """

  @Approval @Ready
  @Afo:A_21448
  @TCID:IDP_REF_DEREG_005
  Scenario: Biometrie Deregister - Lösche Pairing für key identifier einer anderen IDNummer

  ```
  Die Anfrage soll OHNE Fehlermeldung behandelt werden um keine Informationen über (nicht-)existierende
  Pairings nach außen zu geben.

    Given IDP I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-c-valid-ecc.p12'
    And IDP I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And IDP I create pairing data with
      | se_subject_public_key_info   | key_identifier | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info             |
      | /keys/valid/Pub_Se_Aut-1.pem | keyiddereg200  | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-c-valid-ecc.p12 |
    And IDP I sign pairing data with '/certs/valid/egk-idp-idnumber-c-valid-ecc.p12'
    And IDP I register the device with '/certs/valid/egk-idp-idnumber-c-valid-ecc.p12'
    Given IDP I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And IDP I deregister the device with 'keyiddereg200'
    Then the response status is 204
    And IDP the response should match
      """
      """

  # Scenario: Biometrie Deregister - Lösche Pairing mit Zertifikate ohne IDNummer
  # So nicht testbar, da kein access token angefordert werden kann

  @Approval @Ready
  @Afo:A_21442
  @TCID:IDP_REF_DEREG_006
  Scenario: Biometrie Deregister - Lösche Pairing mit e-Rezept Access Token
    Given IDP I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-c-valid-ecc.p12'
    And IDP I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And IDP I create pairing data with
      | se_subject_public_key_info   | key_identifier | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info             |
      | /keys/valid/Pub_Se_Aut-1.pem | keyiddereg300  | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-c-valid-ecc.p12 |
    And IDP I sign pairing data with '/certs/valid/egk-idp-idnumber-c-valid-ecc.p12'
    And IDP I register the device with '/certs/valid/egk-idp-idnumber-c-valid-ecc.p12'
    Given IDP I request an erezept access token with eGK cert '/certs/valid/egk-idp-idnumber-c-valid-ecc.p12'
    And IDP I deregister the device with 'keyiddereg300'
    Then IDP the response is an 403 error with gematik code 4001 and error 'access_denied'

    # TODO RISE add error attribute, see https://gematik-ext.atlassian.net/browse/STIDPD-142

  @Approval @Ready
  @Afo:A_21442
  @TCID:IDP_REF_DEREG_007
  Scenario: Biometrie Deregister - Lösche Pairing mit e-Rezept SSO Token
    Given IDP I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-c-valid-ecc.p12'
    And IDP I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And IDP I create pairing data with
      | se_subject_public_key_info   | key_identifier | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info             |
      | /keys/valid/Pub_Se_Aut-1.pem | keyiddereg400  | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-c-valid-ecc.p12 |
    And IDP I sign pairing data with '/certs/valid/egk-idp-idnumber-c-valid-ecc.p12'
    And IDP I register the device with '/certs/valid/egk-idp-idnumber-c-valid-ecc.p12'
    Given IDP I request an erezept access token via SSO token with eGK cert '/certs/valid/egk-idp-idnumber-c-valid-ecc.p12'
    And IDP I deregister the device with 'keyiddereg400'
    Then IDP the response is an 403 error with gematik code 4001 and error 'access_denied'

    # TODO RISE add error attribute, see https://gematik-ext.atlassian.net/browse/STIDPD-142

  @Approval @Ready
  @Afo:A_21448
  @TCID:IDP_REF_DEREG_008
  Scenario: Biometrie Deregister - Lösche Pairing fehlender key identifier in der Anfrage
    Given IDP I request an pairing access token via SSO token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    When IDP I deregister the device with '$REMOVE'
    Then IDP the response is an 405 error with gematik code -1 and error 'invalid_request'


  @Approval
  @Afo:A_21448
  @TCID:IDP_REF_DEREG_009
  Scenario: Biometrie Deregister - Lösche Pairing Null key identifier in der Anfrage
  ```
  Das Senden eines null Wertes wird am Server als KeyIdentifier "null" interpretiert.

  Da es dazu keinen Eintrag gibt und um potentiall exisitierende KeyIdentifier nicht zu verraten wird,
  statt eines Fehlers hier eine leere 200 Antwort gesendet.

    Given IDP I request an pairing access token via SSO token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    When IDP I deregister the device with '$NULL'
    Then the response status is 204
    And IDP the response should match
        """
        """
