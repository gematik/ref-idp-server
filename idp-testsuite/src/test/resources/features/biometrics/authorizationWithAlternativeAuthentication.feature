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
@alternativeAuth
@Todo:CheckAfos
@Todo:ErrorMessages
Feature: Alternative Authentisierung, Anwendung am IDP Server

  Frontends von TI Diensten müssen sich mit ihren zuvor registrierten Pairingdaten beim IDP authentisieren können

  Background: Initialisiere Testkontext durch Abfrage des Discovery Dokuments und registriere Gerät
    Given I initialize scenario from discovery document endpoint
    And I retrieve public keys from URIs


  @todo:pairingdatenHinterlegen
  @Afo:A_20699 @Afo:A_20951
  @Approval
  Scenario: Author mit alternativer Authentisierung - Gutfall - Validiere Antwortstruktur

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, bauen die signed authentication data passend zu dem im Background registrierten Pairing, signieren diese mit dem PrK_SE_Aut und
  fordern einen AUTHORIZATION_CODE mit den signed authentication data an.

  Die Antwort muss den Code 302 und die richtigen HTTP Header haben.

    Given I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And I create pairing data with
      | se_subject_public_key_info   | key_identifier | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info             |
      | /keys/valid/Pub_Se_Aut-1.pem | keyidauth001   | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'

    And I choose code verifier '${TESTENV.code_verifier01}'
    And I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 12345 | code          |
    And I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And I create authentication data with
      | authentication_data_version | auth_cert                                     | key_identifier | amr                    |
      | 1.0                         | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyidauth001   | ["mfa", "hwk", "face"] |
    And I sign authentication data with '/keys/valid/Priv_Se_Aut-1-pkcs8.der'
    When I request a code token with alternative authentication
    Then the response status is 302
    And the response http headers match
        """
        Cache-Control=no-store
        Pragma=no-cache
        Content-Length=0
        Location=${TESTENV.redirect_uri_regex}[?|&]code=.*
        """
    And I expect the Context with key STATE to match 'xxxstatexxx'
    And I expect the Context with key SSO_TOKEN to match '.*'

  @Afo:A_20699 @Afo:A_20951 @Afo:A_20731 @Afo:A_20377 @Afo:A_20697 @Afo:A_21317
  @Todo:ClarifyTokenCodeContentRelevant @Todo:CompareSubjectInfosInTokenAndInAuthenticationData
  @Approval
  Scenario: Author mit alternativer Authentisierung - Gutfall - Validiere Location Header und Code Token Claims

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, bauen die signed authentication data passend zu dem im Background registrierten Pairing, signieren diese mit dem PrK_SE_Aut und
  fordern einen AUTHORIZATION_CODE mit den signed authentication data an.

  Die AUTHORIZATION_CODE Antwort muss im Location header state, code und SSO Token als Query Parameter enthalten und
  die richtigen Claims im Token haben.

    Given I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And I create pairing data with
      | se_subject_public_key_info   | key_identifier | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info             |
      | /keys/valid/Pub_Se_Aut-1.pem | keyidauth002   | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'

    And I choose code verifier '${TESTENV.code_verifier01}'
    And I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 12345 | code          |
    And I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And I create authentication data with
      | authentication_data_version | auth_cert                                     | key_identifier | amr                    |
      | ${TESTENV.pairing_version}  | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyidauth002   | ["mfa", "hwk", "face"] |
    And I sign authentication data with '/keys/valid/Priv_Se_Aut-1-pkcs8.der'
    When I request a code token with alternative authentication

    When I extract the header claims from token TOKEN_CODE
    Then the header claims should match in any order
        """
          { alg: "BP256R1",
            kid: "${json-unit.ignore}",
            typ: "JWT"
          }
        """
    When I extract the body claims from token TOKEN_CODE
    Then the body claims should match in any order
        """
        {
            auth_time:             "${json-unit.ignore}",
            client_id:             "${TESTENV.client_id}",
            code_challenge:        "${TESTENV.code_challenge01}",
            code_challenge_method: "S256",
            exp:                   "[\\d]*",
            jti:                   "${json-unit.ignore}",
            family_name:           "(.{1,64})",
            given_name:            "(.{1,64})",
            iat:                   "[\\d]*",
            idNummer:              "[A-Z][\\d]{9,10}",
            iss:                   "${TESTENV.issuer}",
            nonce:                 "12345",
            organizationName:      "(.{1,64})",
            professionOID:         "1\\.2\\.276\\.0\\.76\\.4\\.(3\\d|4\\d|178|23[2-90]|240|241)",
            redirect_uri:          "${TESTENV.redirect_uri}",
            response_type:         "code",
            scope:                 "${TESTENV.scopes_basisflow_regex}",
            snc:                   ".*",
            state:                 "xxxstatexxx",
            token_type:            "code"
        }
        """

  @Afo:A_20319
  @Signature @Approval
  Scenario: Author mit alternativer Authentisierung - Validiere Signatur des Code Token

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, bauen die signed authentication data passend zu dem im Background registrierten Pairing, signieren diese mit dem PrK_SE_Aut und
  fordern einen AUTHORIZATION_CODE mit den signed authentication data an.

  Der AUTHORIZATION_CODE muss mit dem passenden FD.Sig Zertifikat des IDPs gültig signiert sein.

    Given I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And I create pairing data with
      | se_subject_public_key_info   | key_identifier | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info             |
      | /keys/valid/Pub_Se_Aut-1.pem | keyidauth003   | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'

    And I choose code verifier '${TESTENV.code_verifier01}'
    And I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 12345 | code          |
    And I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And I create authentication data with
      | authentication_data_version | auth_cert                                     | key_identifier | amr                    |
      | ${TESTENV.pairing_version}  | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyidauth002   | ["mfa", "hwk", "face"] |
    And I sign authentication data with '/keys/valid/Priv_Se_Aut-1-pkcs8.der'
    When I request a code token with alternative authentication

    Then the context TOKEN_CODE must be signed with cert PUK_SIGN

  @Afo:A_20695
  @Signature @Approval
  Scenario: Author mit alternativer Authentisierung - Validiere Signatur des SSO Token

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, bauen die signed authentication data passend zu dem im Background registrierten Pairing, signieren diese mit dem PrK_SE_Aut und
  fordern einen AUTHORIZATION_CODE und einen SSO_TOKEN mit den signed authentication data an.

  Der SSO_TOKEN muss mit dem Auth Zertifikat gültig signiert sein.

    Given I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And I create pairing data with
      | se_subject_public_key_info   | key_identifier | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info             |
      | /keys/valid/Pub_Se_Aut-1.pem | keyidauth004   | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'

    And I choose code verifier '${TESTENV.code_verifier01}'
    And I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 12345 | code          |
    And I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And I create authentication data with
      | authentication_data_version | auth_cert                                     | key_identifier | amr                    |
      | ${TESTENV.pairing_version}  | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyidauth002   | ["mfa", "hwk", "face"] |
    And I sign authentication data with '/keys/valid/Priv_Se_Aut-1-pkcs8.der'
    When I request a code token with alternative authentication

    Then the context SSO_TOKEN must be signed with cert PUK_SIGN



# ------------------------------------------------------------------------------------------------------------------
    #
    # negative cases

  @WIP
  Scenario: Author mit alternativer Authentisierung - Aufruf ohne Parameter

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, bauen die signed authentication data passend zu dem im Background registrierten Pairing, signieren diese mit dem PrK_SE_Aut und
  fordern einen TOKEN_CODE, ohne den Parameter "encrypted_signed_authentication_data" mitzugeben.

  Der Server muss diese Anfrage mit HTTP Status 302 und einer Fehlermeldung im Location Header ablehnen.

    Given I choose code verifier '${TESTENV.code_verifier02}'
    And I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state        | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge02} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx1 | 1212  | code          |

    When I request a code token with no params
    Then the response is an 302 error with gematik code -1 and error 'invalid_request'

  @WIP
  @Todo:testfallAnpassenDerServerHatNichtSoVieleDatenInDatenbankHierWirdGegenBlockAllowListGeprueft
  Scenario: Author mit alternativer Authentisierung - Gutfall - fehlende Parameter in device_information

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, bauen die signed authentication data passend zu dem im Background registrierten Pairing, signieren diese mit dem PrK_SE_Aut und
  fordern einen AUTHORIZATION_CODE mit den signed authentication data an. In den device_information fehlt ein Parameter, daher kann das Gerät nicht mehr auf der Allow-List gefunden werden

  Der Server muss diese Anfrage mit HTTP Status 302 und einer Fehlermeldung im Location Header ablehnen.

    Given I choose code verifier '${TESTENV.code_verifier01}'
    And I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 12345 | code          |
    And I create a device information token with
      | device_information_data_version | name       | device_type_data_version   | manufacturer | product     | model | os      | os_version |
      | ${TESTENV.pairing_version}      | eRezeptApp | ${TESTENV.pairing_version} | $NULL        | FairPhone 3 | F3    | Android | 8.0.0      |
    And I create authentication data with
      | authentication_data_version | auth_cert                                     | key_identifier | amr                    |
      | ${TESTENV.pairing_version}  | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyident002    | ["mfa","hwk", "face" ] |
    And I sign authentication data with '/keys/valid/Priv_Se_Aut-1-pkcs8.der'
    When I request a code token with alternative authentication
    Then the response is an 302 error with gematik code -1 and error 'invalid_request'

  @Todo:RueckspracheMitHannesOhneAmrAblehnen
  @WIP
  Scenario: Author mit alternativer Authentisierung - Gutfall - fehlende AMR in authentication_data

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, bauen die signed authentication data passend zu dem im Background registrierten Pairing, signieren diese mit dem PrK_SE_Aut und
  fordern einen AUTHORIZATION_CODE mit den signed authentication data an. In den authentication_data fehlt die AMR.

  Der Server muss diese Anfrage mit HTTP Status 302 und einer Fehlermeldung im Location Header ablehnen.

    Given I choose code verifier '${TESTENV.code_verifier01}'
    And I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 12345 | code          |
    And I create a device information token with
      | device_information_data_version | name       | device_type_data_version   | manufacturer | product     | model | os      | os_version |
      | ${TESTENV.pairing_version}      | eRezeptApp | ${TESTENV.pairing_version} | Fair Phone   | FairPhone 3 | F3    | Android | 8.0.0      |
    And I create authentication data with
      | authentication_data_version | auth_cert                                     | key_identifier | amr   |
      | ${TESTENV.pairing_version}  | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyident002    | $NULL |
    And I sign authentication data with '/keys/valid/Priv_Se_Aut-1-pkcs8.der'
    When I request a code token with alternative authentication
    Then the response is an 302 error with gematik code -1 and error 'invalid_request'


  @Afo:A_20951
  @WIP
  Scenario: Author mit alternativer Authentisierung - im signed authenication data ist ein abgelaufenes zertifikat hinterlegt

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, bauen die signed authentication data passend zu dem im Background registrierten Pairing, signieren diese mit dem PrK_SE_Aut und
  fordern einen TOKEN_CODE mit den signed authentication data an. In den signed authentication data ist ein abgelaufenes zertifikat hinterlegt

  Der Server muss diese Anfrage mit HTTP Status 302 und einer Fehlermeldung im Location Header ablehnen.


    Given I choose code verifier '${TESTENV.code_verifier01}'
    And I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 3344  | code          |
    And I create a device information token with
      | device_information_data_version | name       | device_type_data_version   | manufacturer | product     | model | os      | os_version |
      | ${TESTENV.pairing_version}      | eRezeptApp | ${TESTENV.pairing_version} | Fair Phone   | FairPhone 3 | F3    | Android | 8.0.0      |
    And I create authentication data with
      | authentication_data_version | auth_cert                                     | key_identifier | amr                    |
      | ${TESTENV.pairing_version}  | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyident002    | ["mfa","hwk", "face" ] |
    And I sign authentication data with '/keys/valid/Priv_Se_Aut-1-pkcs8.der'
    When I request a code token with alternative authentication
    Then the response is an 302 error with gematik code -1 and error 'TODO'

  @WIP
  @Afo:A_20951
  @Todo:HierMitZuvorRegistrietenDatenArbeitenDamitManNichtEtwasUngueltigesRegistrierenMussUndDaranScheitert
  @OutOfScope:OCSP
  Scenario: Author mit alternativer Authentisierung - im signed authenication data ist ein gesperrtes zertifikat hinterlegt

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, bauen die signed authentication data passend zu dem im Background registrierten Pairing, signieren diese mit dem PrK_SE_Aut und
  fordern einen TOKEN_CODE mit den signed authentication data an. In den signed authentication data ist ein gesperrtes zertifikat hinterlegt

  Der Server muss diese Anfrage mit HTTP Status 302 und einer Fehlermeldung im Location Header ablehnen.


    Given I choose code verifier '${TESTENV.code_verifier01}'
    And I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 3344  | code          |
    And I create a device information token with
      | device_information_data_version | name       | device_type_data_version   | manufacturer | product     | model | os      | os_version |
      | ${TESTENV.pairing_version}      | eRezeptApp | ${TESTENV.pairing_version} | Fair Phone   | FairPhone 3 | F3    | Android | 8.0.0      |
    And I create authentication data with
      | authentication_data_version | auth_cert                                     | key_identifier | amr                    |
      | ${TESTENV.pairing_version}  | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyident002    | ["mfa","hwk", "face" ] |
    And I sign authentication data with '/keys/valid/Priv_Se_Aut-1-pkcs8.der'
    When I request a code token with alternative authentication
    Then the response is an 302 error with gematik code -1 and error 'TODO'

  @Afo:A_20951
  @Todo:HierMitZuvorRegistrietenDatenArbeitenDamitManNichtEtwasUngueltigesRegistrierenMussUndDaranScheitert
  @WIP
  Scenario: Author mit alternativer Authentisierung - im signed authenication data ist ein falsches zertifikat (andere idNumber) hinterlegt

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, bauen die signed authentication data passend zu dem im Background registrierten Pairing, signieren diese mit dem PrK_SE_Aut und
  fordern einen TOKEN_CODE mit den signed authentication data an. In den signed authentication data ist ein zertifikat mit einer anderen idNumber hinterlegt

  Der Server muss diese Anfrage mit HTTP Status 302 und einer Fehlermeldung im Location Header ablehnen.


    Given I choose code verifier '${TESTENV.code_verifier01}'
    And I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 3344  | code          |
    And I create a device information token with
      | device_information_data_version | name       | device_type_data_version   | manufacturer | product     | model | os      | os_version |
      | ${TESTENV.pairing_version}      | eRezeptApp | ${TESTENV.pairing_version} | Fair Phone   | FairPhone 3 | F3    | Android | 8.0.0      |
    And I create authentication data with
      | authentication_data_version | auth_cert                                     | key_identifier | amr                    |
      | ${TESTENV.pairing_version}  | /certs/valid/egk-idp-idnumber-b-valid-ecc.p12 | keyident002    | ["mfa","hwk", "face" ] |
    And I sign authentication data with '/keys/valid/Priv_Se_Aut-1-pkcs8.der'
    When I request a code token with alternative authentication
    Then the response is an 302 error with gematik code -1 and error 'TODO'

  @Afo:A_20951
  @Todo:HierMitZuvorRegistrietenDatenArbeitenDamitManNichtEtwasUngueltigesRegistrierenMussUndDaranScheitert
  @WIP
  Scenario: Author mit alternativer Authentisierung - im signed authenication data ist ein falsches zertifikat (gleiche idNumber) hinterlegt

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, bauen die signed authentication data passend zu dem im Background registrierten Pairing, signieren diese mit dem PrK_SE_Aut und
  fordern einen TOKEN_CODE mit den signed authentication data an. In den signed authentication data ist ein anderes Zertifikat als bei der registrierung, aber mit derselben idNumber hinterlegt

  Der Server muss diese Anfrage mit HTTP Status 302 und einer Fehlermeldung im Location Header ablehnen (weil er die signatur der signed_pairing_data nicht validieren kann).


    Given I choose code verifier '${TESTENV.code_verifier01}'
    And I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 3344  | code          |
    And I create a device information token with
      | device_information_data_version | name       | device_type_data_version   | manufacturer | product     | model | os      | os_version |
      | ${TESTENV.pairing_version}      | eRezeptApp | ${TESTENV.pairing_version} | Fair Phone   | FairPhone 3 | F3    | Android | 8.0.0      |
    And I create authentication data with
      | authentication_data_version | auth_cert                                     | key_identifier | amr                    |
      | ${TESTENV.pairing_version}  | /certs/valid/egk-idp-idnumber-b-valid-ecc.p12 | keyident002    | ["mfa","hwk", "face" ] |
    And I sign authentication data with '/keys/valid/Priv_Se_Aut-1-pkcs8.der'
    When I request a code token with alternative authentication
    Then the response is an 302 error with gematik code -1 and error 'TODO'


  @Afo:A_20951
  @WIP
  Scenario: Author mit alternativer Authentisierung - key_identifier passt nicht zum vorhandenen pairing

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, bauen die signed authentication data passend zu dem im Background registrierten Pairing, signieren diese mit dem PrK_SE_Aut und
  fordern einen TOKEN_CODE mit den signed authentication data an. In den signed authentication data ist ein zertifikat mit einer anderen idNumber hinterlegt

  Der Server muss diese Anfrage mit HTTP Status 302 und einer Fehlermeldung im Location Header ablehnen.


    Given I choose code verifier '${TESTENV.code_verifier01}'
    And I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 3344  | code          |
    And I create a device information token with
      | device_information_data_version | name       | device_type_data_version   | manufacturer | product     | model | os      | os_version |
      | ${TESTENV.pairing_version}      | eRezeptApp | ${TESTENV.pairing_version} | Fair Phone   | FairPhone 3 | F3    | Android | 8.0.0      |
    And I create authentication data with
      | authentication_data_version | auth_cert                                     | key_identifier     | amr                    |
      | ${TESTENV.pairing_version}  | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | invalidkeyident003 | ["mfa","hwk", "face" ] |
    And I sign authentication data with '/keys/valid/Priv_Se_Aut-1-pkcs8.der'
    When I request a code token with alternative authentication
    Then the response is an 302 error with gematik code -1 and error 'TODO'

  @WIP
  Scenario: Author mit alternativer Authentisierung - im signed authenication data fehlen device informationen

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, bauen die signed authentication data aber ohne device_information, signieren diese mit dem PrK_SE_Aut und
  fordern einen TOKEN_CODE mit den signed authentication data an.

  Der Server muss diese Anfrage mit HTTP Status 302 und einer Fehlermeldung im Location Header ablehnen.


    Given I choose code verifier '${TESTENV.code_verifier01}'
    And I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 3344  | code          |
    And I create authentication data with
      | authentication_data_version | auth_cert                                     | key_identifier | amr                    |
      | ${TESTENV.pairing_version}  | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyident002    | ["mfa","hwk", "face" ] |
    And I sign authentication data with '/keys/valid/Priv_Se_Aut-1-pkcs8.der'
    When I request a code token with alternative authentication
    Then the response is an 302 error with gematik code -1 and error 'TODO'


  @Afo:A_20951
  @Todo:HierMitZuvorRegistrietenDatenArbeitenDamitManNichtEtwasUngueltigesRegistrierenMussUndDaranScheitert
  @WIP
  Scenario: Author mit alternativer Authentisierung - Signatur der signed authenication data ist mit falschem Schlüssel erstellt

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, bauen die signed authentication data passend zu dem im Background registrierten Pairing, signieren diese mit einem anderen PrK_SE_Aut als dem zuvor registrierten und
  fordern einen TOKEN_CODE mit den signed authentication data an.

  Der Server muss diese Anfrage mit HTTP Status 302 und einer Fehlermeldung im Location Header ablehnen.


    Given I choose code verifier '${TESTENV.code_verifier01}'
    And I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 3344  | code          |
    And I create a device information token with
      | device_information_data_version | name       | device_type_data_version   | manufacturer | product     | model | os      | os_version |
      | ${TESTENV.pairing_version}      | eRezeptApp | ${TESTENV.pairing_version} | Fair Phone   | FairPhone 3 | F3    | Android | 8.0.0      |
    And I create authentication data with
      | authentication_data_version | auth_cert                                     | key_identifier     | amr                    |
      | ${TESTENV.pairing_version}  | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | invalidkeyident003 | ["mfa","hwk", "face" ] |
    And I sign authentication data with '/keys/valid/Priv_Se_Aut-2-pkcs8.der'
    When I request a code token with alternative authentication
    Then the response is an 302 error with gematik code -1 and error 'TODO'


  @WIP
  Scenario: Author mit alternativer Authentisierung - pairing daten wurden vorher gelöscht

  ```
  Wir löschen einen bestimmten Pairing Entry. Dann wählen wir einen gültigen Code verifier, fordern einen Challenge Token an, bauen die signed authentication data passend zu dem zuvor gelöschten Pairing, signieren diese mit dem PrK_SE_Aut und
  fordern einen TOKEN_CODE mit den signed authentication data an.

  Der Server muss diese Anfrage mit HTTP Status 302 und einer Fehlermeldung im Location Header ablehnen.


    Given I choose code verifier '${TESTENV.code_verifier01}'
    And I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 3344  | code          |
    And I create a device information token with
      | device_information_data_version | name       | device_type_data_version   | manufacturer | product     | model | os      | os_version |
      | ${TESTENV.pairing_version}      | eRezeptApp | ${TESTENV.pairing_version} | Fair Phone   | FairPhone 3 | F3    | Android | 8.0.0      |
    And I create authentication data with
      | authentication_data_version | auth_cert                                     | key_identifier     | amr                    |
      | ${TESTENV.pairing_version}  | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | invalidkeyident003 | ["mfa","hwk", "face" ] |
    And I sign authentication data with '/keys/valid/Priv_Se_Aut-1-pkcs8.der'
    When I request a code token with alternative authentication
    Then the response is an 302 error with gematik code -1 and error 'TODO'


  @Approval
  Scenario: Author mit alternativer Authentisierung - Falsche Versionsnummer im signed auth data

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, bauen die signed authentication data
  passend zu dem im Backend registrierten Pairing, aber mit falscher Version, signieren diese mit dem PrK_SE_Aut und
  fordern einen AUTHORIZATION_CODE mit den signed authentication data an.

  Die Antwort muss den Fehler mit TODO

    Given I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And I create pairing data with
      | se_subject_public_key_info   | key_identifier   | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info             |
      | /keys/valid/Pub_Se_Aut-1.pem | keyidwrongvers01 | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'

    And I choose code verifier '${TESTENV.code_verifier01}'
    And I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 12345 | code          |
    And I create a device information token with
      | device_information_data_version | name                 | device_type_data_version   | manufacturer | product     | model | os      | os_version |
      | ${TESTENV.pairing_version}      | ${TESTENV.client_id} | ${TESTENV.pairing_version} | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And I create authentication data with
      | authentication_data_version | auth_cert                                     | key_identifier   | amr                    |
      | 0.9                         | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyidwrongvers01 | ["mfa", "hwk", "face"] |
    And I sign authentication data with '/keys/valid/Priv_Se_Aut-1-pkcs8.der'
    When I request a code token with alternative authentication
    Then the response is an 400 error with gematik code -1 and error 'invalid_request'
