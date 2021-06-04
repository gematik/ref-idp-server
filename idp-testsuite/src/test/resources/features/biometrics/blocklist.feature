#
# Copyright (c) 2021 gematik GmbH
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
@Blocklist
Feature: Blocklist für Registrierung und alternative Authentisierung am IDP Server

  Der IDP muss bei der Registrierung und bei der alternativen Authentisierung Geräte ablehen, die auf der Blocklist stehen.

  Background: Initialisiere Testkontext durch Abfrage des Discovery Dokuments
    Given IDP I initialize scenario from discovery document endpoint
    And IDP I retrieve public keys from URIs


  @Approval @Ready
    @TCID:IDP_REF_BLOCK_001 @PRIO:1
  Scenario Outline: Blocklist - Gutfall - Löschen alle Pairings vor Start der Tests

  ```
  Wir löschen vor den Tests alle Pairings die danach angelegt werden sollen.

    Given IDP I request an pairing access token with eGK cert '<auth_cert>'
    And IDP I deregister the device with '<key_id>'

    Examples: Zu deregistrierende Daten
      | auth_cert                                     | key_id        |
      | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyidblock001 |
      | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyidblock002 |
      | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyidblock003 |
      | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyidblock004 |
      | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyidblock005 |
      | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyidblock006 |
      | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyidblock007 |
      | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyidblock008 |
      | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyidblock009 |
      | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyidblock010 |
      | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyidblock011 |
      | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyidblock012 |

  @Afo:A_21423
  @TCID:IDP_REF_BLOCK_002
  @Approval @PRIO:1
  Scenario: Blocklist - Gutfall - Ablehnen der Registriere eines geblockten Geräts

  ```
  Wir registrierten ein Gerät, das auf der Blocklist steht. Die Registrierung muss abgelehnt werden.

    Given IDP I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'

    When IDP I create a device information token with
      | name       | manufacturer | product | model   | os      | os_version |
      | eRezeptApp | Google       | Pixel 2 | Pixel 2 | Android | 11.0.0     |
    And IDP I create pairing data with
      | se_subject_public_key_info   | key_identifier | product | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info             |
      | /keys/valid/Pub_Se_Aut-1.pem | keyidblock001  | Pixel 2 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And IDP I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And IDP I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    Then IDP the response is an 400 error with gematik code 4002 and error 'access_denied'


  @Afo:A_21404
    @TCID:IDP_REF_BLOCK_003
    @Approval @Ready @PRIO:1
  Scenario Outline: Blocklist - Gutfall - Registrieren eines nicht geblockten Geräts

  ```
  Wir registrierten ein Gerät, das nicht auf der Blocklist steht, weil für die Blocklist Name, Manufacturer, Product, Model, OS und OS Version herangezogen werden
  Die Registrierung muss erfolgreich sein.

    Given IDP I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'

    When IDP I create a device information token with
      | name       | manufacturer   | product   | model   | os   | os_version   |
      | eRezeptApp | <manufacturer> | <product> | <model> | <os> | <os_version> |
    And IDP I create pairing data with
      | se_subject_public_key_info   | key_identifier | product   | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info             |
      | /keys/valid/Pub_Se_Aut-1.pem | <keyid>        | <product> | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
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
    Examples: Zu registrierende Daten
      | manufacturer | product | model   | os             | os_version | keyid         |
      | Apple        | Pixel 2 | Pixel 2 | Android        | 11.0.0     | keyidblock002 |
      | Google       | Pixel * | Pixel 2 | Android        | 11.0.0     | keyidblock003 |
      | Google       | Pixel 2 | Pixel   | Android        | 11.0.0     | keyidblock004 |
      | Google       | Pixel 2 | Pixel 2 | Android 11.0.0 | 11.0.0     | keyidblock005 |
      | Google       | Pixel 2 | Pixel 2 | Android        | 11.0.1     | keyidblock006 |


  @Afo:A_21423
  @TCID:IDP_REF_BLOCK_004
  @Approval @PRIO:1
  Scenario: Blocklist - Gutfall - Ablehnung von alternativer Authentisierung mit geblocktem Gerät

  ```
  Wir registrierten ein Pairing mit einem erlaubten Gerät und authentisieren uns dann mit einem geblockten Gerät. (os_version wird von erlaubter auf nicht erlaubte geändert)

    Given IDP I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And IDP I create a device information token with
      | name       | manufacturer | product | model   | os      | os_version |
      | eRezeptApp | Google       | Pixel 2 | Pixel 2 | Android | 12.0.0     |
    And IDP I create pairing data with
      | se_subject_public_key_info   | key_identifier | product | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info             |
      | /keys/valid/Pub_Se_Aut-1.pem | keyidblock007  | Pixel 2 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And IDP I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And IDP I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And the response status is 200

    Then IDP I choose code verifier '${TESTENV.code_verifier01}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 12345 | code          |
    And IDP I create a device information token with
      | name       | manufacturer | product | model   | os      | os_version |
      | eRezeptApp | Google       | Pixel 2 | Pixel 2 | Android | 11.0.0     |
    And IDP I create authentication data with
      | authentication_data_version | auth_cert                                     | key_identifier | amr                    |
      | ${TESTENV.pairing_version}  | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyidblock007  | ["mfa", "hwk", "face"] |
    And IDP I sign authentication data with '/keys/valid/Priv_Se_Aut-1-pkcs8.der'
    When IDP I request a code token with alternative authentication
    Then IDP the response is an 400 error with gematik code 2000 and error 'access_denied'


  @Afo:A_21404
    @TCID:IDP_REF_BLOCK_005
    @Approval @Ready @PRIO:1
  Scenario Outline: Blocklist - Gutfall - alternativer Authentisierung mit nicht geblocktem Gerät

  ```
  Wir registrierten ein Pairing mit einem erlaubten Gerät und authentisieren uns dann mit einem erlaubtem Gerät. Die Device Information des für die Authentisierung verwendeten
  Geräts entsprechen bis auf in einem Feld den eines geblockten Geräts. So wird geprüft, dass wirklich alle Felder für den Vergleich mit der Blocklist herangezogen werden.

    Given IDP I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And IDP I create a device information token with
      | name       | manufacturer | product | model   | os      | os_version |
      | eRezeptApp | Google       | Pixel 2 | Pixel 2 | Android | 12.0.0     |
    And IDP I create pairing data with
      | se_subject_public_key_info   | key_identifier | product | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info             |
      | /keys/valid/Pub_Se_Aut-1.pem | <keyid>        | Pixel 2 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And IDP I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And IDP I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And the response status is 200

    Then IDP I choose code verifier '${TESTENV.code_verifier01}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 12345 | code          |
    And IDP I create a device information token with
      | name       | manufacturer   | product   | model   | os   | os_version   |
      | eRezeptApp | <manufacturer> | <product> | <model> | <os> | <os_version> |
    And IDP I create authentication data with
      | authentication_data_version | auth_cert                                     | key_identifier | amr                    |
      | ${TESTENV.pairing_version}  | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyidblock002  | ["mfa", "hwk", "face"] |
    And IDP I sign authentication data with '/keys/valid/Priv_Se_Aut-1-pkcs8.der'
    When IDP I request a code token with alternative authentication
    Then the response status is 302
    And IDP the response http headers match
        """
        Cache-Control=no-store
        Pragma=no-cache
        Content-Length=0
        Location=${TESTENV.redirect_uri_regex}[?|&]code=.*
        """

    Examples: Zu registrierende Daten
      | manufacturer | product | model   | os             | os_version | keyid         |
      | Apple        | Pixel 2 | Pixel 2 | Android        | 11.0.0     | keyidblock008 |
      | Google       | Pixel * | Pixel 2 | Android        | 11.0.0     | keyidblock009 |
      | Google       | Pixel 2 | Pixel   | Android        | 11.0.0     | keyidblock010 |
      | Google       | Pixel 2 | Pixel 2 | Android 11.0.0 | 11.0.0     | keyidblock011 |
      | Google       | Pixel 2 | Pixel 2 | Android        | 11.0.1     | keyidblock012 |
