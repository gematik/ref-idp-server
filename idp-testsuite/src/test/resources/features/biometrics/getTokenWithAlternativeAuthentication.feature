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

@Biometrics
@AlternativeAuth
Feature: Alternative Authentisierung, Anwendung am IDP Server

  Frontends von TI Diensten müssen sich mit ihrem zuvor registrierten Pairingdaten beim IDP authentisieren können

  Background: Initialisiere Testkontext durch Abfrage des Discovery Dokuments und registriere Gerät
    Given IDP I initialize scenario from discovery document endpoint
    And IDP I retrieve public keys from URIs

  @TCID:IDP_REF_BIOTOKEN_006
    @Approval
  Scenario Outline: GetToken signed authentication data - Gutfall - Löschen alle Pairings vor Start der Tests

  ```
  Wir löschen vor den Tests alle Pairings die danach angelegt werden sollen.

    Given IDP I request an pairing access token with eGK cert '<auth_cert>'
    And IDP I deregister the device with '<key_id>'
#    Then the response status is 204

    Examples: Zu deregistrierende Daten
      | auth_cert                                     | key_id      |
      | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyidget001 |
      | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyidget002 |
      | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyidget003 |


  @Afo:A_20731 @Afo:A_20464 @Afo:A_20952 @Afo:A_21320
  @Approval
  @TCID:IDP_REF_BIOTOKEN_007
  Scenario: GetToken signed authentication data - Gutfall - Validiere Antwortstruktur

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, bauen die signed authentication data passend zu dem im Background registrierten Pairing, signieren diese mit dem PrK_SE_Aut.
  fordern einen AUTHORIZATION_CODE und damit dann einen ACCESS_TOKEN.

  Die Response muss ein JSON Objekt enthalten mit den richtigen Attributen access_token, expires_in, id_token und token_type

    Given IDP I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And IDP I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And IDP I create pairing data with
      | se_subject_public_key_info   | key_identifier | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info             |
      | /keys/valid/Pub_Se_Aut-1.pem | keyidget001    | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And IDP I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And IDP I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'

    And IDP I choose code verifier '${TESTENV.code_verifier01}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 12345 | code          |
    And IDP I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And IDP I create authentication data with
      | authentication_data_version | auth_cert                                     | key_identifier | amr                    |
      | ${TESTENV.pairing_version}  | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyidget001    | ["mfa", "hwk", "face"] |
    And IDP I sign authentication data with '/keys/valid/Priv_Se_Aut-1-pkcs8.der'
    When IDP I request a code token with alternative authentication successfully
    And IDP I set the context with key REDIRECT_URI to '${TESTENV.redirect_uri}'
    And IDP I request an access token

    Then the response status is 200
    And IDP the JSON response should match
        """
          { access_token: "ey.*",
            expires_in:   300,
            id_token:     "ey.*",
            token_type:   "Bearer"
          }
        """


  @Afo:A_20731 @Afo:A_20464 @Afo:A_20952 @Afo:A_21320 @Afo:A_21321 @Afo:A_20524
  @Approval
  @OpenBug
  @TCID:IDP_REF_BIOTOKEN_008
    # TODO: wollen wir noch den Wert der auth_time gegen den Zeitpunkt der Authentifizierung pruefen
  Scenario: GetToken signed pairing data - Gutfall - Check Access Token - Validiere Access Token Claims

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, bauen die signed authentication data passend zu dem im Background registrierten Pairing, signieren diese mit dem PrK_SE_Aut.
  fordern einen AUTHORIZATION_CODE und damit dann einen ACCESS_TOKEN.

  Der ACCESS_TOKEN muss die richtigen Claims mit den richtigen Inhalten haben.

    Given IDP I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And IDP I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And IDP I create pairing data with
      | se_subject_public_key_info   | key_identifier | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info             |
      | /keys/valid/Pub_Se_Aut-1.pem | keyidget002    | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And IDP I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And IDP I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'

    And IDP I choose code verifier '${TESTENV.code_verifier01}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 12345 | code          |
    And IDP I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And IDP I create authentication data with
      | authentication_data_version | auth_cert                                     | key_identifier | amr                    |
      | ${TESTENV.pairing_version}  | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyidget002    | ["mfa", "hwk", "face"] |
    And IDP I sign authentication data with '/keys/valid/Priv_Se_Aut-1-pkcs8.der'
    When IDP I request a code token with alternative authentication successfully
    And IDP I set the context with key REDIRECT_URI to '${TESTENV.redirect_uri}'
    And IDP I request an access token

    When IDP I extract the header claims from token ACCESS_TOKEN_ENCRYPTED
    Then IDP the header claims should match in any order
        """
          {
            alg: "dir",
            enc: "A256GCM",
            cty: "NJWT",
            exp: "[\\d]*"
          }
        """

    When IDP I extract the header claims from token ACCESS_TOKEN
    Then IDP the header claims should match in any order
        """
          { alg: "BP256R1",
            kid: "${json-unit.ignore}",
            typ: "at+JWT"
          }
        """
    When IDP I extract the body claims from token ACCESS_TOKEN
    Then IDP the body claims should match in any order
        """
          { acr:              "gematik-ehealth-loa-high",
            aud:              "${TESTENV.aud}",
            amr:              ["mfa", "hwk", "face"],
            auth_time:        "[\\d]*",
            azp:              "${TESTENV.client_id}",
            client_id:        "${TESTENV.client_id}",
            exp:              "[\\d]*",
            jti:              "${json-unit.ignore}",
            family_name:      "Lausén",
            given_name:       "Maike",
            iat:              "[\\d]*",
            idNummer:         "X510554251",
            iss:              "${TESTENV.issuer}",
            organizationName: "(.{1,64})",
            professionOID:    "1\\.2\\.276\\.0\\.76\\.4\\.(3\\d|4\\d|178|23[2-90]|240|241)",
            scope:            "${TESTENV.scopes_basisflow_regex}",
            sub:              ".*"
          }
        """

  @Afo:A_21321
  @Approval
  @OpenBug
  @TCID:IDP_REF_BIOTOKEN_009
  Scenario: GetToken signed pairing data - Gutfall - Check ID Token - Validiere ID Token Claims
    Given IDP I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And IDP I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And IDP I create pairing data with
      | se_subject_public_key_info   | key_identifier | product     | serialnumber    | issuer          | not_after       | auth_cert_subject_public_key_info             |
      | /keys/valid/Pub_Se_Aut-1.pem | keyidget003    | FairPhone 3 | $FILL_FROM_CERT | $FILL_FROM_CERT | $FILL_FROM_CERT | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And IDP I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And IDP I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'

    And IDP I choose code verifier '${TESTENV.code_verifier01}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 12345 | code          |
    And IDP I create a device information token with
      | name       | manufacturer | product     | model | os      | os_version |
      | eRezeptApp | Fair Phone   | FairPhone 3 | F3    | Android | 1.0.2 f    |
    And IDP I create authentication data with
      | authentication_data_version | auth_cert                                     | key_identifier | amr                    |
      | ${TESTENV.pairing_version}  | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyidget003    | ["mfa", "hwk", "face"] |
    And IDP I sign authentication data with '/keys/valid/Priv_Se_Aut-1-pkcs8.der'
    When IDP I request a code token with alternative authentication successfully
    And IDP I set the context with key REDIRECT_URI to '${TESTENV.redirect_uri}'
    And IDP I request an access token

    When IDP I extract the header claims from token ID_TOKEN_ENCRYPTED
    Then IDP the header claims should match in any order
        """
          {
            alg: "dir",
            enc: "A256GCM",
            cty: "NJWT",
            exp: "[\\d]*"
          }
        """

    When IDP I extract the header claims from token ID_TOKEN
    Then IDP the header claims should match in any order
        """
          { alg: "BP256R1",
            kid: "${json-unit.ignore}",
            typ: "JWT"
          }
        """
    When IDP I extract the body claims from token ID_TOKEN
    Then IDP the body claims should match in any order
        """
          { acr:              "gematik-ehealth-loa-high",
            amr:              ["mfa","hwk","face"],
            at_hash:          "[A-Za-z0-9\\-\\_]*",
            aud:              "${TESTENV.client_id}",
            auth_time:        "[\\d]*",
            azp:              "${TESTENV.client_id}",
            exp:              "[\\d]*",
            family_name:      "(.{1,64})",
            given_name:       "(.{1,64})",
            iat:              "[\\d]*",
            idNummer:         "[A-Z][\\d]{9,10}",
            iss:              "${TESTENV.issuer}",
            nonce:            "12345",
            professionOID:    "1\\.2\\.276\\.0\\.76\\.4\\.(3\\d|4\\d|178|23[2-90]|240|241)",
            organizationName: "(.{1,64})",
            sub:              ".*",
            jti:              ".*"
           }
        """

# ------------------------------------------------------------------------------------------------------------------
    #
    # no negative cases here. as alternative authentication does not change the token endpoint they are in getTokenWithSignedChallenge

