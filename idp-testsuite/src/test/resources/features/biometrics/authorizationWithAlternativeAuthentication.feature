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

@PRODUKT:IDP-D
@Biometrics
Feature: Alternative Authentisierung, Anwendung am IDP Server

  Frontends von TI Diensten müssen sich mit ihren zuvor registrierten Pairingdaten beim IDP authentisieren können

  Background: Initialisiere Testkontext durch Abfrage des Discovery Dokuments und registriere Gerät
    Given IDP I initialize scenario from discovery document endpoint
    And IDP I retrieve public keys from URIs


  @TCID:IDP_REF_ALTAUTH_001 @PRIO:1
    @Approval
    @TESTSTUFE:4
  Scenario Outline: Author mit alternativer Authentisierung - Gutfall - Löschen alle Pairings vor Start der Tests

  ```
  Wir löschen vor den Tests alle Pairings die danach angelegt werden sollen.

    Given IDP I request an pairing access token with eGK cert '<auth_cert>'
    And IDP I deregister the device with '<key_id>'

    Examples: Zu deregistrierende Daten
      | auth_cert                                       | key_id              |
      | /certs/valid/egk-idp-idnumber-a-valid-ecc-2.p12 | keyidauth001allow   |
      | /certs/valid/egk-idp-idnumber-a-valid-ecc-2.p12 | keyidauth001unknown |
      | /certs/valid/egk-idp-idnumber-a-valid-ecc-2.p12 | keyidauth002        |
      | /certs/valid/egk-idp-idnumber-a-valid-ecc-2.p12 | keyidauth003        |
      | /certs/valid/egk-idp-idnumber-a-valid-ecc-2.p12 | keyidauth004        |
      | /certs/valid/egk-idp-idnumber-a-valid-ecc-2.p12 | keyidauth007        |


  @AFO-ID:A_21439 @AFO-ID:A_21449 @AFO-ID:A_21440
    @TCID:IDP_REF_ALTAUTH_002 @PRIO:1
    @Approval
    @TESTSTUFE:4
  Scenario Outline: Author mit alternativer Authentisierung - Gutfall - Validiere Antwortstruktur

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, bauen die signed authentication data passend zu dem im Background registrierten Pairing, signieren diese mit dem PrK_SE_Aut und
  fordern einen AUTHORIZATION_CODE mit den signed authentication data an.

  Die Antwort muss den Code 302 und die richtigen HTTP Header haben.

    Given IDP I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc-2.p12'
    And IDP I create a device information token with
      | name       | manufacturer   | product   | model   | os   | os_version   |
      | eRezeptApp | <manufacturer> | <product> | <model> | <os> | <os_version> |
    And IDP I create pairing data with
      | se_subject_public_key_info   | key_identifier | product   | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info               |
      | /keys/valid/Pub_Se_Aut-1.pem | <keyid>        | <product> | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-a-valid-ecc-2.p12 |
    And IDP I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc-2.p12'
    And IDP I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc-2.p12'

    And IDP I choose code verifier '${TESTENV.code_verifier01}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 12345 | code          |
    And IDP I create a device information token with
      | name       | manufacturer   | product   | model   | os   | os_version   |
      | eRezeptApp | <manufacturer> | <product> | <model> | <os> | <os_version> |
    And IDP I create authentication data with
      | authentication_data_version | auth_cert                                       | key_identifier | amr                                 |
      | 1.0                         | /certs/valid/egk-idp-idnumber-a-valid-ecc-2.p12 | <keyid>        | ["mfa", "hwk", "generic-biometric"] |
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
    And IDP I expect the Context with key STATE to match 'xxxstatexxx'
    And IDP I expect the Context with key SSO_TOKEN_ENCRYPTED to match '.*'

    Examples: Device Information
      | manufacturer | product     | model   | os      | os_version | keyid               |
      | Samsung      | Galaxy-8    | SM-950F | Android | 4.0.3      | keyidauth001allow   |
      | Fair Phone   | FairPhone 3 | F3      | Android | 1.0.2 f    | keyidauth001unknown |


  @AFO-ID:A_20731 @AFO-ID:A_20377 @AFO-ID:A_20697 @AFO-ID:A_21317
  @Approval @RefImplOnly @PRIO:1
  @TCID:IDP_REF_ALTAUTH_003
  @TESTSTUFE:4
  Scenario: Author mit alternativer Authentisierung - Gutfall - Validiere Location Header und Code Token Claims

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, bauen die signed authentication data passend zu dem im Background registrierten Pairing, signieren diese mit dem PrK_SE_Aut und
  fordern einen AUTHORIZATION_CODE mit den signed authentication data an.

  Die AUTHORIZATION_CODE Antwort muss im Location header state, code und SSO Token als Query Parameter enthalten und
  die richtigen Claims im Token haben.

    Given IDP I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc-2.p12'
    And IDP I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And IDP I create pairing data with
      | se_subject_public_key_info   | key_identifier | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info               |
      | /keys/valid/Pub_Se_Aut-1.pem | keyidauth002   | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-a-valid-ecc-2.p12 |
    And IDP I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc-2.p12'
    And IDP I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc-2.p12'

    And IDP I choose code verifier '${TESTENV.code_verifier01}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 12345 | code          |
    And IDP I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And IDP I create authentication data with
      | authentication_data_version | auth_cert                                       | key_identifier | amr                   |
      | ${TESTENV.pairing_version}  | /certs/valid/egk-idp-idnumber-a-valid-ecc-2.p12 | keyidauth002   | ["mfa", "hwk", "kba"] |
    And IDP I sign authentication data with '/keys/valid/Priv_Se_Aut-1-pkcs8.der'
    When IDP I request a code token with alternative authentication successfully

    When IDP I extract the header claims from token TOKEN_CODE
    Then IDP the header claims should match in any order
        """
          { alg: "BP256R1",
            kid: "${json-unit.ignore}",
            typ: "JWT"
          }
        """
    When IDP I extract the body claims from token TOKEN_CODE
    Then IDP the body claims should match in any order
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
            token_type:            "code",
            amr:                   ["mfa", "hwk", "kba"]
        }
        """

  @AFO-ID:A_20319-01
  @Signature @Approval @RefImplOnly
  @TCID:IDP_REF_ALTAUTH_004 @PRIO:1
  @TESTSTUFE:4
  Scenario: Author mit alternativer Authentisierung - Validiere Signatur des Code Token

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, bauen die signed authentication data passend zu dem im Background registrierten Pairing, signieren diese mit dem PrK_SE_Aut und
  fordern einen AUTHORIZATION_CODE mit den signed authentication data an.

  Der AUTHORIZATION_CODE muss mit dem passenden FD.Sig Zertifikat des IDPs gültig signiert sein.

    Given IDP I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc-2.p12'
    And IDP I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And IDP I create pairing data with
      | se_subject_public_key_info   | key_identifier | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info               |
      | /keys/valid/Pub_Se_Aut-1.pem | keyidauth003   | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-a-valid-ecc-2.p12 |
    And IDP I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc-2.p12'
    And IDP I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc-2.p12'

    And IDP I choose code verifier '${TESTENV.code_verifier01}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 12345 | code          |
    And IDP I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And IDP I create authentication data with
      | authentication_data_version | auth_cert                                       | key_identifier | amr                    |
      | ${TESTENV.pairing_version}  | /certs/valid/egk-idp-idnumber-a-valid-ecc-2.p12 | keyidauth002   | ["mfa", "hwk", "face"] |
    And IDP I sign authentication data with '/keys/valid/Priv_Se_Aut-1-pkcs8.der'
    When IDP I request a code token with alternative authentication successfully

    Then IDP the context TOKEN_CODE must be signed with cert PUK_SIGN

  @AFO-ID:A_20695-01
  @Signature @Approval @RefImplOnly
  @TCID:IDP_REF_ALTAUTH_005 @PRIO:1
  @TESTSTUFE:4
  Scenario: Author mit alternativer Authentisierung - Validiere Signatur des SSO Token

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, bauen die signed authentication data passend zu dem im Background registrierten Pairing, signieren diese mit dem PrK_SE_Aut und
  fordern einen AUTHORIZATION_CODE und einen SSO_TOKEN mit den signed authentication data an.

  Der SSO_TOKEN muss mit dem Auth Zertifikat gültig signiert sein.

    Given IDP I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc-2.p12'
    And IDP I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And IDP I create pairing data with
      | se_subject_public_key_info   | key_identifier | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info               |
      | /keys/valid/Pub_Se_Aut-1.pem | keyidauth004   | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-a-valid-ecc-2.p12 |
    And IDP I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc-2.p12'
    And IDP I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc-2.p12'

    And IDP I choose code verifier '${TESTENV.code_verifier01}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 12345 | code          |
    And IDP I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And IDP I create authentication data with
      | authentication_data_version | auth_cert                                       | key_identifier | amr                                 |
      | ${TESTENV.pairing_version}  | /certs/valid/egk-idp-idnumber-a-valid-ecc-2.p12 | keyidauth004   | ["mfa", "hwk", "generic-biometric"] |
    And IDP I sign authentication data with '/keys/valid/Priv_Se_Aut-1-pkcs8.der'
    When IDP I request a code token with alternative authentication successfully

    Then IDP the context SSO_TOKEN must be signed with cert PUK_SIGN



# ------------------------------------------------------------------------------------------------------------------
    #
    # negative cases
  @Approval
  @TCID:IDP_REF_ALTAUTH_006 @PRIO:1
  @TESTSTUFE:4
  Scenario: Author mit alternativer Authentisierung - Pairing anlegen für Negativtests

  ```
  Wir registrierten ein Pairing, das für alle Negativtests verwendet wird. Damit entfallen diese Schritte in den folgenden Testfällen.

    Given IDP I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc-2.p12'
    And IDP I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And IDP I create pairing data with
      | se_subject_public_key_info   | key_identifier | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info               |
      | /keys/valid/Pub_Se_Aut-1.pem | keyidauth007   | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-a-valid-ecc-2.p12 |
    And IDP I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc-2.p12'
    And IDP I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc-2.p12'
    Then the response status is 200

  @Approval
  @AFO-ID:A_21438
  @TCID:IDP_REF_ALTAUTH_007 @PRIO:1 @TESTFALL:Negativ
  @TESTSTUFE:4
  Scenario: Author mit alternativer Authentisierung - Aufruf ohne Parameter encrypted_signed_authentication_data

  ```
  Mit dem in "Pairing anlegen für Negativtests" angelegten Pairing wird eine Authentisierung angestoßen. Dabei wird der Parameter "encrypted_signed_authentication_data" nicht mitgegeben.

  Der Server muss diese Anfrage mit HTTP Status 400 und einer passenden Fehlermeldung ablehnen.


    Given IDP I choose code verifier '${TESTENV.code_verifier02}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state        | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge02} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx1 | 1212  | code          |

    When IDP I request a code token with no params
    Then IDP the response is an 400 error with gematik code 2030 and error 'invalid_request'


  @Approval
    @AFO-ID:A_21434
    @TCID:IDP_REF_ALTAUTH_008 @PRIO:1 @TESTFALL:Negativ
    @TESTSTUFE:4
  Scenario Outline: Author mit alternativer Authentisierung - fehlende Inhalte in encrypted_signed_authentication_data

  ```
  Mit dem in "Pairing anlegen für Negativtests" angelegten Pairing wird eine Authentisierung angestoßen. Alles ist soweit korrekt, nur in den encrypted_signed_authentication_data
  fehlen notwendige Inhalte (auth_cert, key_id, amr).

  Der Server muss diese Anfrage mit HTTP Status 400 und einer Fehlermeldung ablehnen.

    Given IDP I choose code verifier '${TESTENV.code_verifier01}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 12345 | code          |
    And IDP I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And IDP I create authentication data with
      | authentication_data_version | auth_cert   | key_identifier | amr   |
      | ${TESTENV.pairing_version}  | <auth_cert> | <key_id>       | <amr> |
    And IDP I sign authentication data with '/keys/valid/Priv_Se_Aut-1-pkcs8.der'
    When IDP I request a code token with alternative authentication
    Then IDP the response is an 400 error with gematik code <error_code> and error '<error>'

    Examples: Parameter für authentication data
      | auth_cert                                       | key_id       | amr                                 | error_code | error         |
      | $NULL                                           | keyidauth007 | ["mfa", "hwk", "generic-biometric"] | 2000       | access_denied |
      | /certs/valid/egk-idp-idnumber-a-valid-ecc-2.p12 | $NULL        | ["mfa", "hwk", "generic-biometric"] | 2000       | access_denied |
      | /certs/valid/egk-idp-idnumber-a-valid-ecc-2.p12 | keyidauth007 | $NULL                               | 2000       | access_denied |

  @Approval
  @AFO-ID:A_20699-03
  @TCID:IDP_REF_ALTAUTH_009 @PRIO:1 @TESTFALL:Negativ
  @TESTSTUFE:4
  Scenario: Author mit alternativer Authentisierung - fehlerhafte Challenge in encrypted_signed_authentication_data

  ```
  Mit dem in "Pairing anlegen für Negativtests" angelegten Pairing wird eine Authentisierung angestoßen. Dabei ist die Challenge in den encryted signed authentication data nicht die
  ursprüngliche Challenge.

  Der Server muss diese Anfrage mit HTTP Status 400 und einer Fehlermeldung ablehnen.

    Given IDP I choose code verifier '${TESTENV.code_verifier01}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 12345 | code          |
    And IDP I set the context with key CHALLENGE to 'malicious content test'
    And IDP I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And IDP I create authentication data with
      | authentication_data_version | auth_cert                                       | key_identifier | amr                    |
      | ${TESTENV.pairing_version}  | /certs/valid/egk-idp-idnumber-a-valid-ecc-2.p12 | keyidauth007   | ["mfa", "hwk", "face"] |
    And IDP I sign authentication data with '/keys/valid/Priv_Se_Aut-1-pkcs8.der'
    When IDP I request a code token with alternative authentication
    Then IDP the response is an 400 error with gematik code 2000 and error 'access_denied'

  @Approval
  @AFO-ID:A_21438
  @TCID:IDP_REF_ALTAUTH_010 @PRIO:1 @TESTFALL:Negativ
  @TESTSTUFE:4
  Scenario: Author mit alternativer Authentisierung - fehlerhafte Signatur der encrypted_signed_authentication_data

  ```
  Mit dem in "Pairing anlegen für Negativtests" angelegten Pairing wird eine Authentisierung angestoßen. Dabei signieren wir die signed authentication data mit dem falschen Schlüssel.

  Der Server muss diese Anfrage mit HTTP Status 400 und einer Fehlermeldung ablehnen.

    Given IDP I choose code verifier '${TESTENV.code_verifier01}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 12345 | code          |
    And IDP I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And IDP I create authentication data with
      | authentication_data_version | auth_cert                                       | key_identifier | amr                    |
      | ${TESTENV.pairing_version}  | /certs/valid/egk-idp-idnumber-a-valid-ecc-2.p12 | keyidauth007   | ["mfa", "hwk", "face"] |
    And IDP I sign authentication data with '/keys/valid/Priv_Se_Aut-2-pkcs8.der'
    When IDP I request a code token with alternative authentication
    Then IDP the response is an 400 error with gematik code 2000 and error 'access_denied'

  @Approval
    @AFO-ID:A_21434
    @TCID:IDP_REF_ALTAUTH_011 @PRIO:1 @TESTFALL:Negativ
    @TESTSTUFE:4
  Scenario Outline: Author mit alternativer Authentisierung - Konflikt mit zuvor registrierten Daten - falsche Inhalte in encrypted_signed_authentication_data

  ```
  Mit dem in "Pairing anlegen für Negativtests" angelegten Pairing wird eine Authentisierung angestoßen.
  In den signed authentication passt ein Datum (key_identifier oder auth_certificate) nicht zu den zuvor registrierten Daten.

  Der Server muss diese Anfrage mit HTTP Status 400 und einer Fehlermeldung ablehnen.

    Given IDP I choose code verifier '${TESTENV.code_verifier01}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 12345 | code          |
    And IDP I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And IDP I create authentication data with
      | authentication_data_version | auth_cert   | key_identifier | amr                    |
      | ${TESTENV.pairing_version}  | <auth_cert> | <key_id>       | ["mfa", "hwk", "face"] |
    And IDP I sign authentication data with '/keys/valid/Priv_Se_Aut-1-pkcs8.der'
    When IDP I request a code token with alternative authentication
    Then IDP the response is an 400 error with gematik code <error_code> and error '<error>'

    Examples: Parameter für authentication data
      | auth_cert                                       | key_id           | error_code | error         |
      | /certs/valid/egk-idp-idnumber-c-valid-ecc-2.p12 | keyidauth007     | 2000       | access_denied |
      | /certs/valid/egk-idp-idnumber-a-valid-ecc-2.p12 | keyidauthInvalid | 2000       | access_denied |

