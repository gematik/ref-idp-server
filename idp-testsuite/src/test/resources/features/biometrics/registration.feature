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
@Todo:ImplementErrorMessages
@Afo:A_21415
@Afo:A_21425
@Afo:A_21427
@Afo:A_21420
Feature: Registrierung für Alternative Authentisierung am IDP Server

  Frontends müssen mit einer eGK und einem pairing Access oder SSO Token Geräte registrieren können.

  Der not_after Wert von 1893456000 entspricht dem 1.1.2030

  Background: Initialisiere Testkontext durch Abfrage des Discovery Dokuments
    Given IDP I initialize scenario from discovery document endpoint
    And IDP I retrieve public keys from URIs


  @TCID:IDP_REF_ALTAUTREG_000
  Scenario Outline: Biometrie AltAutReg - Gutfall - Löschen alle Pairings vor Start der Tests

  ```
  Wir löschen vor den Tests alle evt. vorhandenen Pairings die danach angelegt werden sollen.

    Given IDP I request an pairing access token with eGK cert '<auth_cert>'
    And IDP I deregister the device with '<key_id>'

    Examples: Zu deregistrierende Daten
      | auth_cert                                     | key_id             |
      | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyident001allow   |
      | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyident001unknown |
      | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyident002        |
      | /certs/valid/egk-idp-idnumber-b-valid-ecc.p12 | keyident002        |
      | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyident003        |
      | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyident004        |
      | /certs/valid/egk-idp-idnumber-b-valid-ecc.p12 | keyident004        |

  @Approval @Ready
    @Afo:A_21423
    @TCID:IDP_REF_ALTAUTREG_001
  Scenario Outline: AltAutReg - Gutfall - Registriere ein Pairing

  ```
  Registrierung eines Geräts. Das erste steht auf der Allow-List, das zweite ist unbekannt.
  Die Registrierung muss jeweils erfolgreich sein.

    Given IDP I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'

    When IDP I create a device information token with
      | name       | manufacturer   | product   | model   | os   | os_version   |
      | eRezeptApp | <manufacturer> | <product> | <model> | <os> | <os_version> |
    And IDP I create pairing data with
      | se_subject_public_key_info   | key_identifier | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info             |
      | /keys/valid/Pub_Se_Aut-1.pem | <keyid>        | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And IDP I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And IDP I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    Then the response status is 200
    And IDP the JSON response should match
        """
          {
            name:                  "eRezeptApp",
            signed_pairing_data:   "ey.*",
            creation_time:         "[\\d]*",
            pairing_entry_version: ".*"
          }
        """

    Examples: Device Information
      | manufacturer | product     | model   | os      | os_version | keyid              |
      | Samsung      | Galaxy-8    | SM-950F | Android | 4.0.3      | keyident001allow   |
      | Fair Phone   | FairPhone 3 | F3      | Android | 1.0.2 f    | keyident001unknown |


  # TODO user agent ? Relevanz, add testcases without user agents if relevant

  # TODO not_after mit Wert aus der Vergangenheit

  # TODO add variants for different PukSE AUThs
  @Approval @Ready
  @Afo:A_21412
  @TCID:IDP_REF_ALTAUTREG_002
  Scenario: AltAutReg - Gutfall - Zwei Pairings mit identem Identifier und Pub SE Auth aber unterschiedlicher IdNummer
    Given IDP I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And IDP I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And IDP I create pairing data with
      | se_subject_public_key_info   | key_identifier | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info             |
      | /keys/valid/Pub_Se_Aut-1.pem | keyident002    | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And IDP I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And IDP I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And IDP I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-b-valid-ecc.p12'
    And IDP I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And IDP I create pairing data with
      | se_subject_public_key_info   | key_identifier | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info             |
      | /keys/valid/Pub_Se_Aut-1.pem | keyident002    | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-b-valid-ecc.p12 |
    And IDP I sign pairing data with '/certs/valid/egk-idp-idnumber-b-valid-ecc.p12'
    And IDP I register the device with '/certs/valid/egk-idp-idnumber-b-valid-ecc.p12'
    Then the response status is 200
    And IDP the JSON response should match
        """
          {
            name:                  "eRezeptApp",
            signed_pairing_data:   "ey.*",
            creation_time:         "[\\d]*",
            pairing_entry_version: ".*"
          }
        """

  @Approval @Ready
  @Afo:A_21412
  @TCID:IDP_REF_ALTAUTREG_003
  Scenario: AltAutReg - Gutfall - Zwei Pairings mit unterschiedlichem key identifier und unterschiedlicher IDNummer
    Given IDP I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And IDP I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And IDP I create pairing data with
      | se_subject_public_key_info   | key_identifier | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info             |
      | /keys/valid/Pub_Se_Aut-1.pem | keyident003    | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And IDP I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And IDP I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And IDP I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-b-valid-ecc.p12'
    And IDP I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And IDP I create pairing data with
      | se_subject_public_key_info   | key_identifier | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info             |
      | /keys/valid/Pub_Se_Aut-1.pem | keyident004    | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-b-valid-ecc.p12 |
    And IDP I sign pairing data with '/certs/valid/egk-idp-idnumber-b-valid-ecc.p12'
    And IDP I register the device with '/certs/valid/egk-idp-idnumber-b-valid-ecc.p12'
    Then the response status is 200
    And IDP the JSON response should match
        """
          {
            name:                  "eRezeptApp",
            signed_pairing_data:   "ey.*",
            creation_time:         "[\\d]*",
            pairing_entry_version: ".*"
          }
        """

  @Approval @Ready
  @TCID:IDP_REF_ALTAUTREG_004
  Scenario: AltAutReg - Zweifacher Eintragungsversuch Idente Daten
    Given IDP I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And IDP I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And IDP I create pairing data with
      | se_subject_public_key_info   | key_identifier   | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info             |
      | /keys/valid/Pub_Se_Aut-1.pem | keyidentdoppel01 | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And IDP I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And IDP I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'

    When IDP I request an access token
    And IDP I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    Then IDP the response is an 409 error with gematik code 4004 and error "invalid_request"

      # TODO RISE add error attribute, see https://gematik-ext.atlassian.net/browse/STIDPD-142

  @Approval @Ready
  @Afo:A_21412
  @Afo:A_21427
  @TCID:IDP_REF_ALTAUTREG_005
  Scenario: AltAutReg - Zweifacher Eintragungsversuch Devicedaten unterschiedlich
    Given IDP I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And IDP I create a device information token with
      | name       | manufacturer | product | model | os      | os_version |
      | eRezeptApp | Motorola     | GOTA 1  | G2    | Android | 1.3.2      |
    And IDP I create pairing data with
      | se_subject_public_key_info   | key_identifier   | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info             |
      | /keys/valid/Pub_Se_Aut-1.pem | keyidentdoppel02 | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And IDP I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And IDP I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And IDP I request an access token

    When IDP I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And IDP I create pairing data with
      | se_subject_public_key_info   | key_identifier   | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info             |
      | /keys/valid/Pub_Se_Aut-1.pem | keyidentdoppel02 | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And IDP I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And IDP I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    Then IDP the response is an 409 error with gematik code 4004 and error "invalid_request"

 # TODO RISE add error attribute, see https://gematik-ext.atlassian.net/browse/STIDPD-142

  @Approval @Ready
  @TCID:IDP_REF_ALTAUTREG_006
  Scenario: AltAutReg - Zweifacher Eintragungsversuch alles bis auf key identifier und Zertifikat unterschiedlich
    Given IDP I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And IDP I create a device information token with
      | name       | manufacturer | product | model | os     | os_version |
      | eRezeptApp | Motorola     | GOTA 1  | G2    | Ubuntu | 1.3.2      |
    And IDP I create pairing data with
      | se_subject_public_key_info   | key_identifier   | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info             |
      | /keys/valid/Pub_Se_Aut-1.pem | keyidentdoppel03 | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And IDP I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And IDP I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And IDP I request an access token

    When IDP I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And IDP I create pairing data with
      | se_subject_public_key_info   | key_identifier   | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info             |
      | /keys/valid/Pub_Se_Aut-1.pem | keyidentdoppel03 | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And IDP I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And IDP I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    Then IDP the response is an 409 error with gematik code 4004 and error "invalid_request"

  @OpenBug @issue:IDP-453
    @Approval
    @Afo:A_21422
    @Afo:A_21421
    @TCID:IDP_REF_ALTAUTREG_007
  Scenario Outline: AltAutReg - Unterschiedliche Zertifikate mit identer IDNummer in Verwendung
    # Real world scenario: alte Karte verloren, neue Karte, neues Zert, alte Karte wieder verwendet, bevor diese abgelaufen ist/gesperrt wurde
    Given IDP I request an pairing access token with eGK cert '/certs/valid/<cert_access>'

    When IDP I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And IDP I create pairing data with
      | se_subject_public_key_info | key_identifier   | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info |
      | /keys/valid/<cert_keydata> | <key_identifier> | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/<cert_public_key>    |
    And IDP I sign pairing data with '/certs/valid/<cert_sign>'
    And IDP I register the device with '/certs/valid/<cert_register>'
    And IDP the response is an <status> error with gematik code <errid> and error '<errcode>'

    Examples: Liste mit Einträgen wo immer ein Zertifikat unterschiedlich aber gültig ist
      | status | errcode               | errid | key_identifier     | cert_access                      | cert_keydata     | cert_public_key                       | cert_sign                             | cert_register                         |
      | 500    | internal_server_error | -1    | keyidentdiffcert03 | egk-idp-idnumber-a-valid-ecc.p12 | Pub_Se_Aut-1.pem | egk-idp-idnumber-a-folgekarte-ecc.p12 | egk-idp-idnumber-a-valid-ecc.p12      | egk-idp-idnumber-a-valid-ecc.p12      |
      | 400    | invalid_request       | -1    | keyidentdiffcert04 | egk-idp-idnumber-a-valid-ecc.p12 | Pub_Se_Aut-1.pem | egk-idp-idnumber-a-valid-ecc.p12      | egk-idp-idnumber-a-folgekarte-ecc.p12 | egk-idp-idnumber-a-valid-ecc.p12      |
      | 400    | invalid_request       | -1    | keyidentdiffcert05 | egk-idp-idnumber-a-valid-ecc.p12 | Pub_Se_Aut-1.pem | egk-idp-idnumber-a-valid-ecc.p12      | egk-idp-idnumber-a-valid-ecc.p12      | egk-idp-idnumber-a-folgekarte-ecc.p12 |


    # not done above TODO ERRROR


  @Approval @Ready
    @Afo:A_21422
    @TCID:IDP_REF_ALTAUTREG_008
  Scenario Outline: AltAutReg - Unterschiedliche Zertifikate mit unterschiedlicher IDNummer in Verwendung
    Given IDP I request an pairing access token with eGK cert '/certs/valid/<cert_access>'

    When IDP I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And IDP I create pairing data with
      | se_subject_public_key_info | key_identifier   | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info |
      | /keys/valid/<cert_keydata> | <key_identifier> | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/<cert_public_key>    |
    And IDP I sign pairing data with '/certs/valid/<cert_sign>'
    And IDP I register the device with '/certs/valid/<cert_register>'
    Then the response status is <status>
    And IDP the response is an <status> error with gematik code <errid> and error '<errcode>'

    Examples: Liste mit Einträgen wo immer ein Zertifikat mit anderer IDNummer unterschiedlich aber gültig ist
      | status | errcode         | errid | key_identifier     | cert_access                      | cert_keydata     | cert_public_key                  | cert_sign                        | cert_register                    |
     # | 400    | invalid_parameter_value | -1    | keyidentdiffcert01 | egk-idp-idnumber-a-folgekarte-ecc.p12 | Pub_Se_Aut-1.pem | egk-idp-idnumber-a-valid-ecc.p12 | egk-idp-idnumber-a-valid-ecc.p12 | egk-idp-idnumber-a-valid-ecc.p12 |
      | 403    | invalid_request | 4001  | keyidentdiffcert01 | egk-idp-idnumber-b-valid-ecc.p12 | Pub_Se_Aut-1.pem | egk-idp-idnumber-a-valid-ecc.p12 | egk-idp-idnumber-a-valid-ecc.p12 | egk-idp-idnumber-a-valid-ecc.p12 |
      # | 409    | invalid_request | 4004  | keyidentdiffcert03 | egk-idp-idnumber-a-valid-ecc.p12 | Pub_Se_Aut-1.pem | egk-idp-idnumber-b-valid-ecc.p12 | egk-idp-idnumber-a-valid-ecc.p12 | egk-idp-idnumber-a-valid-ecc.p12 |
      | 403    | invalid_request | 4001  | keyidentdiffcert04 | egk-idp-idnumber-a-valid-ecc.p12 | Pub_Se_Aut-1.pem | egk-idp-idnumber-a-valid-ecc.p12 | egk-idp-idnumber-b-valid-ecc.p12 | egk-idp-idnumber-a-valid-ecc.p12 |
      | 403    | invalid_request | 4001  | keyidentdiffcert05 | egk-idp-idnumber-a-valid-ecc.p12 | Pub_Se_Aut-1.pem | egk-idp-idnumber-a-valid-ecc.p12 | egk-idp-idnumber-a-valid-ecc.p12 | egk-idp-idnumber-b-valid-ecc.p12 |
      # TODO REF second request liefert 200!
      # Das erste Example ist kein Fehler. In diesem Setting hat der IDP keine Möglichkeit zu bemerken, dass für die Beantragung des ACCESS_TOKEN ein anderes Zertifikat/Schlüssel verwendet
      # wurde, als für die Registrierung. Alles was er hier hat, ist die ID_NUMBER (KVNR) und die ist dieselbe.

  @Approval
    @Afo:A_21423
    @TCID:IDP_REF_ALTAUTREG_009
  Scenario Outline: AltAutReg - Null Werte in device info

    Given IDP I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'

    When IDP I create a device information token with
      | name   | manufacturer   | product   | model   | os   | os_version |
      | <name> | <manufacturer> | <product> | <model> | <os> | <version>  |
    And IDP I create pairing data with
      | se_subject_public_key_info   | key_identifier  | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info             |
      | /keys/valid/Pub_Se_Aut-1.pem | <keyidentifier> | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And IDP I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And IDP I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    Then IDP the response is an 403 error with gematik code 4001 and error 'invalid_request'

    Examples: AltAutReg - Null Device Info Beispiele
      | keyidentifier  | name       | manufacturer | product     | model | os      | version |
      | keyidentnull01 | $NULL      | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f |
      | keyidentnull02 | eRezeptApp | $NULL        | FairPhone 3 | F3    | Android | 1.0.2 f |
      | keyidentnull03 | eRezeptApp | Fair Phone   | $NULL       | F3    | Android | 1.0.2 f |
      | keyidentnull04 | eRezeptApp | Fair Phone   | FairPhone 3 | $NULL | Android | 1.0.2 f |
      | keyidentnull05 | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | $NULL   | 1.0.2 f |
      | keyidentnull06 | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | $NULL   |

  @Approval
    @Afo:A_21423
    @TCID:IDP_REF_ALTAUTREG_010
  Scenario Outline: AltAutReg - Fehlende Werte in device info
    Given IDP I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'

    When IDP I create a device information token with
      | name   | manufacturer   | product   | model   | os   | os_version |
      | <name> | <manufacturer> | <product> | <model> | <os> | <version>  |
    And IDP I create pairing data with
      | se_subject_public_key_info   | key_identifier  | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info             |
      | /keys/valid/Pub_Se_Aut-1.pem | <keyidentifier> | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And IDP I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And IDP I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    Then IDP the response is an 403 error with gematik code 4001 and error 'invalid_request'

    Examples: AltAutReg - Fehlende Device info Beispiele
      | keyidentifier    | name       | manufacturer | product     | model   | os      | version |
      | keyidentremove01 | $REMOVE    | Fair Phone   | FairPhone 3 | F3      | Android | 1.0.2 f |
      | keyidentremove02 | eRezeptApp | $REMOVE      | FairPhone 3 | F3      | Android | 1.0.2 f |
      | keyidentremove03 | eRezeptApp | Fair Phone   | $REMOVE     | F3      | Android | 1.0.2 f |
      | keyidentremove04 | eRezeptApp | Fair Phone   | FairPhone 3 | $REMOVE | Android | 1.0.2 f |
      | keyidentremove05 | eRezeptApp | Fair Phone   | FairPhone 3 | F3      | $REMOVE | 1.0.2 f |
      | keyidentremove06 | eRezeptApp | Fair Phone   | FairPhone 3 | F3      | Android | $REMOVE |

  @Approval
    @Afo:A_21470
    @TCID:IDP_REF_ALTAUTREG_011
  Scenario Outline: AltAutReg - Null Werte in pairing data

    Given IDP I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'

    When IDP I create a device information token with
      | name       | manufacturer | product | model | os      | os_version |
      | eRezeptApp | Motorola     | GOTA 1  | G2    | Android | 1.3.2      |
    And IDP I create pairing data with
      | se_subject_public_key_info | key_identifier  | product   | serialnumber   | issuer   | not_after   | auth_cert_subject_public_key_info |
      | <key_data>                 | <keyidentifier> | <product> | <serialnumber> | <issuer> | <not_after> | <public_key>                      |
    And IDP I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And IDP I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    Then IDP the response is an 403 error with gematik code 4001 and error 'invalid_request'

    Examples: AltAutReg - Null Pairing Data Beispiele
      | keyidentifier  | key_data                     | product     | serialnumber    | issuer  | not_after  | public_key                                    |
      | keyidentnull11 | $NULL                        | FairPhone 3 | 419094927676993 | Android | 1893456000 | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
      | keyidentnull13 | /keys/valid/Pub_Se_Aut-1.pem | $NULL       | 419094927676993 | Android | 1893456000 | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
      | keyidentnull14 | /keys/valid/Pub_Se_Aut-1.pem | FairPhone 3 | $NULL           | Android | 1893456000 | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
      | keyidentnull15 | /keys/valid/Pub_Se_Aut-1.pem | FairPhone 3 | 419094927676993 | $NULL   | 1893456000 | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
      | keyidentnull16 | /keys/valid/Pub_Se_Aut-1.pem | FairPhone 3 | 419094927676993 | Android | $NULL      | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
      | keyidentnull17 | /keys/valid/Pub_Se_Aut-1.pem | FairPhone 3 | 419094927676993 | Android | 1893456000 | $NULL                                         |

  @Approval
    @Afo:A_21470
    @TCID:IDP_REF_ALTAUTREG_012
  Scenario Outline: AltAutReg - Fehlende Werte in pairing data
    Given IDP I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'

    When IDP I create a device information token with
      | name       | manufacturer | product | model | os      | os_version |
      | eRezeptApp | Motorola     | GOTA 1  | G2    | Android | 1.3.2      |
    And IDP I create pairing data with
      | se_subject_public_key_info | key_identifier  | product   | serialnumber   | issuer   | not_after   | auth_cert_subject_public_key_info |
      | <key_data>                 | <keyidentifier> | <product> | <serialnumber> | <issuer> | <not_after> | <public_key>                      |
    And IDP I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And IDP I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    Then IDP the response is an 403 error with gematik code 4001 and error 'invalid_request'

    Examples: AltAutReg - Fehlende Pairing Data Beispiele
      | keyidentifier    | key_data                     | product     | serialnumber    | issuer  | not_after  | public_key                                    |
      | keyidentremove11 | $REMOVE                      | FairPhone 3 | 419094927676993 | Android | 1893456000 | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
      | keyidentremove13 | /keys/valid/Pub_Se_Aut-1.pem | $REMOVE     | 419094927676993 | Android | 1893456000 | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
      | keyidentremove14 | /keys/valid/Pub_Se_Aut-1.pem | FairPhone 3 | $REMOVE         | Android | 1893456000 | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
      | keyidentremove15 | /keys/valid/Pub_Se_Aut-1.pem | FairPhone 3 | 419094927676993 | $REMOVE | 1893456000 | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
      | keyidentremove16 | /keys/valid/Pub_Se_Aut-1.pem | FairPhone 3 | 419094927676993 | Android | $REMOVE    | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
      | keyidentremove17 | /keys/valid/Pub_Se_Aut-1.pem | FairPhone 3 | 419094927676993 | Android | 1893456000 | $REMOVE                                       |

  @Approval @issue:IDP-470 @OpenBug
    @Afo:A_21421
    @TCID:IDP_REF_ALTAUTREG_013
  Scenario Outline: AltAutReg - Ungültige Zertifikate (selfsigned, outdated, revoced)
    Given IDP I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'

    When IDP I create a device information token with
      | name       | manufacturer | product | model | os      | os_version |
      | eRezeptApp | Motorola     | GOTA 1  | G2    | Android | 1.3.2      |
    And IDP I create pairing data with
      | se_subject_public_key_info   | key_identifier  | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info |
      | /keys/valid/Pub_Se_Aut-1.pem | <keyidentifier> | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | <invalidcert>                     |
    And IDP I sign pairing data with '<invalidcert>'
    And IDP I register the device with '<invalidcert>'
    Then IDP the response is an 500 error with gematik code -1 and error 'invalid_request'

    Examples: AltAutReg - Ungültige Zertifikate
      | keyidentifier     | invalidcert                                              |
      | keyidentinvcert01 | /certs/invalid/egk-idp-idnumber-a-expired-ecc.p12        |
      | keyidentinvcert02 | /certs/invalid/egk-idp-idnumber-a-invalid-issuer-ecc.p12 |
      | keyidentinvcert03 | /certs/invalid/egk-idp-idnumber-a-revoked-ecc.p12        |

  @Approval @OpenBug
    @Afo:A_21422
    @TCID:IDP_REF_ALTAUTREG_014
  Scenario Outline: AltAutReg - Registriere Pairing mit Zertifikat ohne IDNummer
    Given IDP I request an pairing access token with eGK cert '/certs/valid/<cert_access>'

    When IDP I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And IDP I create pairing data with
      | se_subject_public_key_info | key_identifier   | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info |
      | /keys/valid/<cert_keydata> | <key_identifier> | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/<cert_public_key>    |
    And IDP I sign pairing data with '/certs/valid/<cert_sign>'
    And IDP I register the device with '/certs/valid/<cert_register>'
    Then IDP the response is an <status> error with gematik code <errid> and error '<errcode>'

    Examples: Liste mit Einträgen wo immer ein Zertifikat ohne IdNummer verwendet wird
      | status | errcode          | errid | key_identifier | cert_access                      | cert_keydata     | cert_public_key                   | cert_sign                         | cert_register                     |
      | 403    | invalid_request< | 4001  | keyidentnoid03 | egk-idp-idnumber-a-valid-ecc.p12 | Pub_Se_Aut-1.pem | egk-idp-idnumber-missing1-ecc.p12 | egk-idp-idnumber-a-valid-ecc.p12  | egk-idp-idnumber-a-valid-ecc.p12  |
      | 403    | invalid_request  | 4001  | keyidentnoid04 | egk-idp-idnumber-a-valid-ecc.p12 | Pub_Se_Aut-1.pem | egk-idp-idnumber-a-valid-ecc.p12  | egk-idp-idnumber-missing1-ecc.p12 | egk-idp-idnumber-a-valid-ecc.p12  |
      | 403    | invalid_request  | 4001  | keyidentnoid05 | egk-idp-idnumber-a-valid-ecc.p12 | Pub_Se_Aut-1.pem | egk-idp-idnumber-a-valid-ecc.p12  | egk-idp-idnumber-a-valid-ecc.p12  | egk-idp-idnumber-missing1-ecc.p12 |
      # TODO REF first variant liefert 200 retour! public key of cert is not validated at all
      # dieser Testfall ist etwas akademisch, weil die Zertifikatsherausgeber sicherstellen, dass es keine korrekt signierte Zertifikate ohne ID-Number gibt.
      # Nichts spricht dagegen, sich trotzdem anzugucken, wie sich der IDP verhalten würde, aber die Eintrittswahrscheinlichkeit dieses Fehlers ist eher gering.

  @manual
  @Approval @Ready
  Scenario: AltAutReg - Ungültige Werte in device info
  Derzeit gibt es für die Geräteinformationen keine Einschränkung, daher OK per definitionem


  @WiP
  @Approval
  Scenario: AltAutReg - Ungültige Serial number in pairing data

  @Afo:A_20463
  @Afo:A_21413
  @Afo:A_21418
  @Afo:A_21425
  @LongRunning
  @Approval @Ready
  @TCID:IDP_REF_ALTAUTREG_015
  Scenario: AltAutReg - Pairing mit veraltetem Access Token wird abgelehnt
    Given IDP I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And IDP I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And IDP I create pairing data with
      | se_subject_public_key_info   | key_identifier | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info             |
      | /keys/valid/Pub_Se_Aut-1.pem | keyidentacc001 | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And IDP I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'

    When IDP I wait PT5M
    And IDP I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    Then IDP the response is an 403 error with gematik code 4001 and error 'access_denied'
 # TODO REF status 403 and error code 4001, error value to be discussed https://gematik-ext.atlassian.net/browse/STIDPD-142
  # TODO Hannes klärt Scenario: AltAutReg - Gültigkeitsdauer der signierten Pairing data?

  @Approval
  @Afo:A_21413
  @TCID:IDP_REF_ALTAUTREG_016
  Scenario: AltAutReg - Zugriff mit ACCESS_TOKEN von signierter Challenge mit falschem Scope (erezept)
    Given IDP I request an erezept access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'

    When IDP I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And IDP I create pairing data with
      | se_subject_public_key_info   | key_identifier | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info             |
      | /keys/valid/Pub_Se_Aut-1.pem | keyidentacc002 | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And IDP I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And IDP I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    Then IDP the response is an 403 error with gematik code 4001 and error 'access_denied'

  @Approval
  @Afo:A_21413
  @TCID:IDP_REF_ALTAUTREG_017
  Scenario: AltAutReg - Zugriff mit ACCESS_TOKEN via SSO Token mit falschem Scope (erezept)
    Given IDP I request an erezept access token via SSO token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'

    When IDP I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And IDP I create pairing data with
      | se_subject_public_key_info   | key_identifier | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info             |
      | /keys/valid/Pub_Se_Aut-1.pem | keyidentacc003 | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And IDP I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And IDP I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    Then IDP the response is an 403 error with gematik code 4001 and error 'access_denied'

  @Approval @Ready
    @TCID:IDP_REF_ALTAUTREG_018
  Scenario Outline: AltAutReg - Registriere ein Pairing mit falschen Versionen
    Given IDP I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'

    When IDP I create a device information token with
      | device_information_data_version | name                 | device_type_data_version | manufacturer | product     | model | os      | os_version |
      | <versionDevInfo>                | ${TESTENV.client_id} | <versionDevTyp>          | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And IDP I create pairing data with
      | pairing_data_version | se_subject_public_key_info   | key_identifier | signature_algorithm_identifier | product     | serialnumber    | issuer  | not_after  | auth_cert_subject_public_key_info             |
      | <versionPairingData> | /keys/valid/Pub_Se_Aut-1.pem | <keyid>        | ES256                          | FairPhone 3 | 419094927676993 | Android | 1893456000 | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And IDP I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And IDP I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12' and version '<versionReg>'
    Then IDP the response is an 403 error with gematik code 4001 and error 'invalid_request'

    Examples: invalid versions
      | versionDevInfo | versionDevTyp | versionReg | versionPairingData | keyid           |
      | 0.9            | 1.0           | 1.0        | 1.0                | keyinvversreg01 |
      | 1.1            | 1.0           | 1.0        | 1.0                | keyinvversreg02 |
      | 2.0            | 1.0           | 1.0        | 1.0                | keyinvversreg03 |
      | 1.0            | 0.9           | 1.0        | 1.0                | keyinvversreg10 |
      | 1.0            | 1.1           | 1.0        | 1.0                | keyinvversreg11 |
      | 1.0            | 1.0           | 0.9        | 1.0                | keyinvversreg20 |
      | 1.0            | 1.0           | 1.1        | 1.0                | keyinvversreg21 |
      | 1.0            | 1.0           | 1.0        | 0.9                | keyinvversreg30 |
      | 1.0            | 1.0           | 1.0        | 1.1                | keyinvversreg31 |
