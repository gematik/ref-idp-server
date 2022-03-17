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
@SignedChallengeFlow
Feature: Fordere Access Token mit einer signierten Challenge an
  Frontends von TI Diensten müssen vom IDP Server über ein HTTP POST an den Token Endpoint ein Access/SSO/ID Token abfragen können.

  Background: Initialisiere Testkontext durch Abfrage des Discovery Dokuments
    Given IDP I initialize scenario from discovery document endpoint
    And IDP I retrieve public keys from URIs

  @TCID:IDP_REF_TOK_001 @PRIO:1
    @Afo:A_20463 @Afo:A_20321
    @Approval @Ready
  Scenario Outline: GetTokenSigned - Gutfall - Validiere Antwortstruktur
  ```
  Wir fordern einen Access Token an und überprüfen dass die JSON Antwort folgende Felder enthält:

  - den Access Token
  - den ID Token
  - Ablaufzeitraum (expires, 300 Sekunden)
  - Token Typ Bearer


    Given IDP I choose code verifier '${TESTENV.code_verifier01}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce  | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 887766 | code          |
    And IDP I sign the challenge with '<cert>'
    And IDP I request a code token with signed challenge successfully
    And IDP I set the context with key REDIRECT_URI to '${TESTENV.redirect_uri}'

    When IDP I request an access token
    Then the response status is 200
    And IDP the JSON response should match
        """
          { access_token: "ey.*",
            expires_in:   300,
            id_token:     "ey.*",
            token_type:   "Bearer"
          }
        """
    Examples: GetToken - Zertifikate zur Signatur der Challenge
      | cert                                                 |
      | /certs/valid/80276883110000018680-C_CH_AUT_E256.p12  |
      | /certs/valid/80276883110000018680-C_CH_AUT_R2048.p12 |


  #noinspection NonAsciiCharacters
  @TCID:IDP_REF_TOK_002 @PRIO:1
    @Afo:A_20731 @Afo:A_20464 @Afo:A_20952 @Afo:A_21320 @Afo:A_21321 @Afo:A_20313
    @Approval @Ready
  Scenario Outline: GetTokenSigned - Gutfall - Validiere Access Token Claims
  ```
  Wir fordern einen Access Token an und überprüfen dass der Access Token korrekte Header und Body Claims enthält.


    Given IDP I choose code verifier '${TESTENV.code_verifier01}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce  | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 887766 | code          |
    And IDP I sign the challenge with '<cert>'
    And IDP I request a code token with signed challenge successfully
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
            amr:              ["mfa", "sc", "pin"],
            aud:              "${TESTENV.aud}",
            auth_time:        "[\\d]*",
            azp:              "${TESTENV.client_id}",
            client_id:        "${TESTENV.client_id}",
            exp:              "[\\d]*",
            jti:              "${json-unit.ignore}",
            family_name:      "<family_name>",
            given_name:       "<given_name>",
            iat:              "[\\d]*",
            idNummer:         "<idNumber>",
            iss:              "${TESTENV.issuer}",
            organizationName: "<organisationName>",
            professionOID:    "<professionOID>",
            scope:            "${TESTENV.scopes_basisflow_regex}",
            sub:              ".*"
          }
        """
    Examples: GetToken - Zertifikate zur Signatur der Challenge
      | cert                                                        | professionOID      | idNumber                          | organisationName                                            | family_name | given_name                |
      | /certs/valid/80276883110000018680-C_CH_AUT_E256.p12         | 1.2.276.0.76.4.49  | X110411675                        | Test GKV-SVNOT-VALID                                        | Bödefeld    | Darius Michael Brian Ubbo |
      | /certs/valid/80276883110000018680-C_CH_AUT_R2048.p12        | 1.2.276.0.76.4.49  | X110411675                        | Test GKV-SVNOT-VALID                                        | Bödefeld    | Darius Michael Brian Ubbo |
      | /certs/valid/80276883110000129068-C_SMCB_AUT_R2048_X509.p12 | 1.2.276.0.76.4.54  | 3-SMC-B-Testkarte-883110000129068 | Apotheke am SportzentrumTEST-ONLY                           | Blankenberg | Dominik-Peter             |
      | /certs/valid/80276883110000129071-C_SMCB_HCI_AUT_E256.p12   | 1.2.276.0.76.4.53  | 5-SMC-B-Testkarte-883110000129071 | Universitätsklinik MitteTEST-ONLY                           | $NULL       | $NULL                     |
      | /certs/valid/80276883110000129074-C_SMCB_AUT_R2048_X509.p12 | 1.2.276.0.76.4.52  | 1-SMC-B-Testkarte-883110000129074 | Psychotherapeutische Praxis Norbert Graf AngermännTEST-ONLY | Angermänn   | Norbert                   |
      | /certs/valid/80276883110000129077-C_SMCB_HCI_AUT_E256.p12   | 1.2.276.0.76.4.50  | 1-SMC-B-Testkarte-883110000129077 | Praxis Rainer Graf d' AgóstinoTEST-ONLY                     | Agóstino    | Rainer                    |
      | /certs/valid/80276883110000129080-C_SMCB_AUT_R2048_X509.p12 | 1.2.276.0.76.4.51  | 2-SMC-B-Testkarte-883110000129080 | Zahnarztpraxis Dr. Hillbert TangerðalTEST-ONLY              | $NULL       | $NULL                     |
      | /certs/valid/80276883110000129083-C_HP_AUT_E256.p12         | 1.2.276.0.76.4.30  | 1-HBA-Testkarte-883110000129083   | $NULL                                                       | MaiÞer      | Roland                    |
      | /certs/valid/80276883110000129086-C_HP_AUT_R2048.p12        | 1.2.276.0.76.4.31  | 2-HBA-Testkarte-883110000129086   | $NULL                                                       | Szczyrbel   | Gustav Freiherr           |
      | /certs/valid/80276001011699802001-C_HP_AUT_E256.p12         | 1.2.276.0.76.4.233 | 9-1-AP-AaronAal01                 | $NULL                                                       | Aal         | Aaron                     |
      | /certs/valid/80276001011699802002-C_HP_AUT_R2048.p12        | 1.2.276.0.76.4.32  | 3-1-APO-BeaBiene02                | $NULL                                                       | Biene       | Bea                       |
      | /certs/valid/80276001011699802003-C_HP_AUT_E256.p12         | 1.2.276.0.76.4.46  | 4-1-PSY-DianaDorsch03             | $NULL                                                       | Dorsch      | Diana                     |
      | /certs/valid/80276001011699802004-C_HP_AUT_R2048.p12        | 1.2.276.0.76.4.235 | 9-1-HBM-EllaElster04              | $NULL                                                       | Elster      | Ella                      |


  @TCID:IDP_REF_TOK_003 @PRIO:1
    @Afo:A_21321 @Afo:A_20313
    @Approval @Ready
  Scenario Outline: GetTokenSigned - Gutfall - Validiere ID Token Claims
  ```
  Wir fordern einen Access Token an und überprüfen dass der ID Token korrekte Header und Body Claims enthält.

  -  Der at_hash Wert muss base64 URL encoded sein (enthält keine URL inkompatiblen Zeichen +/=)


    Given IDP I choose code verifier '${TESTENV.code_verifier01}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 98765 | code          |
    And IDP I sign the challenge with '<cert>'
    And IDP I request a code token with signed challenge successfully
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
            amr:              ["mfa","sc","pin"],
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
            nonce:            "98765",
            professionOID:    "1\\.2\\.276\\.0\\.76\\.4\\.(3\\d|4\\d|178|23[2-90]|240|241)",
            organizationName: "(.{1,64})",
            sub:              ".*",
            jti:              ".*"
          }
        """
    Examples: GetToken - Zertifikate zur Signatur der Challenge
      | cert                                                 |
      | /certs/valid/80276883110000018680-C_CH_AUT_E256.p12  |
      | /certs/valid/80276883110000018680-C_CH_AUT_R2048.p12 |

  @TCID:IDP_REF_TOK_004 @PRIO:1
  @Approval @Ready
  Scenario: GetTokenSigned - Subject Claim und IdNummer sind in beiden Tokens identisch
  ```
  Wir fordern einen Access Token an und überprüfen, dass der subject claim und die Id Nummer im ID Token und im
  Access Token ident sind.


    Given IDP I choose code verifier '${TESTENV.code_verifier01}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce  | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 887766 | code          |
    And IDP I sign the challenge with '/certs/valid/80276883110000129089-C_CH_AUT_E256.p12'
    And IDP I request a code token with signed challenge successfully
    And IDP I set the context with key REDIRECT_URI to '${TESTENV.redirect_uri}'
    And IDP I request an access token

    When IDP I extract the body claims from token ACCESS_TOKEN
    And IDP I store body claim 'sub' to variable 'access_token_sub'
    And IDP I store body claim 'idNummer' to variable 'access_token_idnummer'
    And IDP I extract the body claims from token ID_TOKEN
    Then IDP the body claim 'sub' should match '${VAR.access_token_sub}'
    And IDP the body claim 'idNummer' should match "${VAR.access_token_idnummer}"

  @TCID:IDP_REF_TOK_005 @PRIO:2
  @Approval @Ready
  Scenario: GetTokenSigned - Subject Claim ist bei unterschiedlichen Zertifikaten unterschiedlich
  ```
  Wir fordern einen Access Token an speichern den sub claim des Access Tokens und machen eine weitere Anfrage mit
  einem anderen Zertifikat.

  Der Subject Claim des Access Tokens der zweiten Anfrage darf nicht mit dem Subject Claim des ersten Tokens übereinstimmen.


    Given IDP I choose code verifier '${TESTENV.code_verifier01}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce  | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 887766 | code          |
    And IDP I sign the challenge with '/certs/valid/80276883110000129089-C_CH_AUT_E256.p12'
    And IDP I request a code token with signed challenge successfully
    And IDP I set the context with key REDIRECT_URI to '${TESTENV.redirect_uri}'
    And IDP I request an access token
    And IDP I extract the body claims from token ACCESS_TOKEN
    And IDP I store body claim 'sub' to variable 'access_token_sub'
    And IDP I choose code verifier '${TESTENV.code_verifier02}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce  | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge02} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 887766 | code          |

    When IDP I sign the challenge with '/certs/valid/egk-idp-idnumber-a-valid.p12'
    And IDP I request a code token with signed challenge successfully
    And IDP I set the context with key REDIRECT_URI to '${TESTENV.redirect_uri}'
    And IDP I request an access token
    And IDP I extract the body claims from token ACCESS_TOKEN
    Then IDP the body claim 'sub' should not match '${VAR.access_token_sub}'

  @TCID:IDP_REF_TOK_006 @PRIO:2
  @Approval @Ready
  Scenario: GetTokenSigned - Subject Claim ist bei unterschiedlichen Zertifikaten mit gleicher IDNummer identisch
  ```
  Wir fordern einen Access Token an speichern den sub claim des Access Tokens und machen eine weitere Anfrage mit
  einem Nachfolge Zertifikat mit identer IDNummer.

  Der Subject Claim des Access Tokens der zweiten Anfrage muss mit dem Subject Claim des ersten Tokens übereinstimmen.


    Given IDP I choose code verifier '${TESTENV.code_verifier01}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce  | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 887766 | code          |
    And IDP I sign the challenge with '/certs/valid/egk-idp-idnumber-a-valid.p12'
    And IDP I request a code token with signed challenge successfully
    And IDP I set the context with key REDIRECT_URI to '${TESTENV.redirect_uri}'
    And IDP I request an access token
    And IDP I extract the body claims from token ACCESS_TOKEN
    And IDP I store body claim 'sub' to variable 'access_token_sub'
    And IDP I choose code verifier '${TESTENV.code_verifier02}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce  | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge02} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 887766 | code          |

    When IDP I sign the challenge with '/certs/valid/egk-idp-idnumber-a-folgekarte-ecc.p12'
    And IDP I request a code token with signed challenge successfully
    And IDP I set the context with key REDIRECT_URI to '${TESTENV.redirect_uri}'
    And IDP I request an access token
    And IDP I extract the body claims from token ACCESS_TOKEN
    Then IDP the body claim 'sub' should match '${VAR.access_token_sub}'

  @TCID:IDP_REF_TOK_007 @PRIO:1
    @Afo:A_20327
    @Approval @Ready
    @Signature
  Scenario Outline: GetTokenSigned - Gutfall - Validiere Signatur Access Token
  ```
  Wir fordern einen Access Token an und überprüfen, dass der Access Token mit der puk_idp_sign signiert wurde.

    Given IDP I retrieve public keys from URIs
    And IDP I choose code verifier '${TESTENV.code_verifier01}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce  | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 888877 | code          |
    And IDP I sign the challenge with '<cert>'
    And IDP I request a code token with signed challenge successfully
    And IDP I set the context with key REDIRECT_URI to '${TESTENV.redirect_uri}'

    When IDP I request an access token
    Then IDP the context ACCESS_TOKEN must be signed with cert PUK_SIGN
    Examples: GetToken - Zertifikate zur Signatur der Challenge
      | cert                                                 |
      | /certs/valid/80276883110000018680-C_CH_AUT_E256.p12  |
      | /certs/valid/80276883110000018680-C_CH_AUT_R2048.p12 |

  @TCID:IDP_REF_TOK_008 @PRIO:1
    @Afo:A_20327
    @Approval @Ready
    @Signature
  Scenario Outline: GetTokenSigned - Gutfall - Validiere Signatur ID Token
  ```
  Wir fordern einen Access Token an und überprüfen, dass der ID Token mit der puk_idp_sign signiert wurde.

    Given IDP I retrieve public keys from URIs
    And IDP I choose code verifier '${TESTENV.code_verifier01}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce  | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 888877 | code          |
    And IDP I sign the challenge with '<cert>'
    And IDP I request a code token with signed challenge successfully
    And IDP I set the context with key REDIRECT_URI to '${TESTENV.redirect_uri}'

    When IDP I request an access token
    Then IDP the context ID_TOKEN must be signed with cert PUK_SIGN
    Examples: GetToken - Zertifikate zur Signatur der Challenge
      | cert                                                 |
      | /certs/valid/80276883110000018680-C_CH_AUT_E256.p12  |
      | /certs/valid/80276883110000018680-C_CH_AUT_R2048.p12 |


  @TCID:IDP_REF_TOK_009 @PRIO:2
  @Afo:A_20314 @Afo:A_20315
  @Approval @Ready @LongRunning
  @Timeout
  Scenario: GetTokenSigned - Veralteter Access Token code wird abgelehnt
  ```
  Wir fordern einen Token Code an, warten dann 1 Minute und prüfen, dass der Server eine Access Token Anfrage mit einer
  'invalid_grant' Fehlermeldung auf grund des abgelaufenen Token codes ablehnt.

    Given IDP I choose code verifier '${TESTENV.code_verifier01}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 98765 | code          |
    And IDP I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And IDP I request a code token with signed challenge successfully
    And IDP I set the context with key REDIRECT_URI to '${TESTENV.redirect_uri}'

    When IDP I wait PT65S
    And IDP I request an access token
    Then IDP the response is an 400 error with gematik code 3011 and error 'invalid_grant'

  @TCID:IDP_REF_TOK_010 @PRIO:2 @Negative
    @Approval @Ready
  Scenario Outline: GetTokenSigned - Null Parameter
  ```
  Wir fordern einen Access Token mit einer Anfrage an, in welcher je ein Parameter null gesetzt ist.

  Der Server muss diese Anfragen mit einer passenden Fehlermeldung ablehnen.

    Given IDP I choose code verifier '${TESTENV.code_verifier01}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce  | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 777766 | code          |
    And IDP I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And IDP I request a code token with signed challenge successfully
    And IDP I set the context with key REDIRECT_URI to '${TESTENV.redirect_uri}'
    When IDP I request an access token with
      | grant_type   | redirect_uri   | token_code_encrypted   | code_verifier   | client_id   |
      | <grant_type> | <redirect_uri> | <token_code_encrypted> | <code_verifier> | <client_id> |
    Then IDP the response is an 400 error with gematik code <err_id> and error '<err_code>'

    Examples: GetToken - Null Parameter Beispiele
      | err_id | err_code        | grant_type         | redirect_uri            | token_code_encrypted | code_verifier              | client_id            |
      | 3006   | invalid_request | $NULL              | ${TESTENV.redirect_uri} | $CONTEXT             | ${TESTENV.code_verifier01} | ${TESTENV.client_id} |
      | 1004   | invalid_request | authorization_code | $NULL                   | $CONTEXT             | ${TESTENV.code_verifier01} | ${TESTENV.client_id} |
      | 3005   | invalid_request | authorization_code | ${TESTENV.redirect_uri} | $NULL                | ${TESTENV.code_verifier01} | ${TESTENV.client_id} |
      | 3004   | invalid_request | authorization_code | ${TESTENV.redirect_uri} | $CONTEXT             | $NULL                      | ${TESTENV.client_id} |
      | 1002   | invalid_request | authorization_code | ${TESTENV.redirect_uri} | $CONTEXT             | ${TESTENV.code_verifier01} | $NULL                |

  @TCID:IDP_REF_TOK_011 @PRIO:2 @Negative
    @Approval @Ready
  Scenario Outline: GetTokenSigned - Fehlende Parameter
  ```
  Wir fordern einen Access Token mit einer Anfrage an, in welcher je ein Parameter fehlt.

  Der Server muss diese Anfragen mit einer passenden Fehlermeldung ablehnen.

    Given IDP I choose code verifier '${TESTENV.code_verifier01}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce  | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 776655 | code          |
    And IDP I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And IDP I request a code token with signed challenge successfully
    When IDP I request an access token with
      | grant_type   | redirect_uri   | token_code_encrypted   | code_verifier   | client_id   |
      | <grant_type> | <redirect_uri> | <token_code_encrypted> | <code_verifier> | <client_id> |
    Then IDP the response is an 400 error with gematik code <err_id> and error '<err_code>'

    Examples: GetToken - Fehlende Parameter Beispiele
      | err_id | err_code        | grant_type         | redirect_uri            | token_code_encrypted | code_verifier              | client_id            |
      | 3006   | invalid_request | $REMOVE            | ${TESTENV.redirect_uri} | $CONTEXT             | ${TESTENV.code_verifier01} | ${TESTENV.client_id} |
      | 1004   | invalid_request | authorization_code | $REMOVE                 | $CONTEXT             | ${TESTENV.code_verifier01} | ${TESTENV.client_id} |
      | 3005   | invalid_request | authorization_code | ${TESTENV.redirect_uri} | $REMOVE              | ${TESTENV.code_verifier01} | ${TESTENV.client_id} |
      | 3004   | invalid_request | authorization_code | ${TESTENV.redirect_uri} | $CONTEXT             | $REMOVE                    | ${TESTENV.client_id} |
      | 1002   | invalid_request | authorization_code | ${TESTENV.redirect_uri} | $CONTEXT             | ${TESTENV.code_verifier01} | $REMOVE              |

  #noinspection NonAsciiCharacters
  @TCID:IDP_REF_TOK_012 @PRIO:1 @Negative
    @Approval @Ready
  Scenario Outline: GetTokenSigned - Ungültige Parameter
  ```
  Wir fordern einen Access Token mit einer Anfrage an, in welcher ein Parameter ungültig ist.

  Der Server muss diese Anfragen mit einer passenden Fehlermeldung ablehnen.

    Given IDP I choose code verifier '${TESTENV.code_verifier01}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce  | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 776655 | code          |
    And IDP I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And IDP I request a code token with signed challenge successfully
    When IDP I request an access token with
      | grant_type   | redirect_uri   | token_code_encrypted   | code_verifier   | client_id   |
      | <grant_type> | <redirect_uri> | <token_code_encrypted> | <code_verifier> | <client_id> |
    Then IDP the response is an 400 error with gematik code <err_id> and error '<err_code>'

    Examples: GetToken - Ungültige Parameter Beispiele
      | err_id | err_code               | grant_type         | redirect_uri                   | token_code_encrypted                                                                                                                                      | code_verifier                                                                                                                  | client_id            |
      | 3014   | unsupported_grant_type | deepstate_grant    | ${TESTENV.redirect_uri}        | $CONTEXT                                                                                                                                                  | ${TESTENV.code_verifier01}                                                                                                     | ${TESTENV.client_id} |
      | 1020   | invalid_request        | authorization_code | http://www.somethingstore.com/ | $CONTEXT                                                                                                                                                  | ${TESTENV.code_verifier01}                                                                                                     | ${TESTENV.client_id} |
      | 3013   | invalid_grant          | authorization_code | ${TESTENV.redirect_uri}        | Ob Regen, Sturm oder Sonnenschein: Dankbare Ergebenheit ist kein Latein. Bleibe nicht länger abhängig vom Wetter, sondern schaue auf den einzigen Retter! | ${TESTENV.code_verifier01}                                                                                                     | ${TESTENV.client_id} |
      | 3016   | invalid_request        | authorization_code | ${TESTENV.redirect_uri}        | $CONTEXT                                                                                                                                                  | Was war das für ein Zaubertraum, der sich in meine Seele glückt? An Tannen gehn die Lichter an und immer weiter wird der Raum. | ${TESTENV.client_id} |
      | 3007   | invalid_client         | authorization_code | ${TESTENV.redirect_uri}        | $CONTEXT                                                                                                                                                  | ${TESTENV.code_verifier01}                                                                                                     | shadows              |

  @TCID:IDP_REF_TOK_013 @PRIO:2 @Negative
    @Approval @Ready
  Scenario Outline: GetTokenSigned - Access Token Ungültige User Consent Inhalte im Zertifikat
  ```
  Wir signieren eine Challenge mit einem Zertifikate, welches ungültige Einträge beim User Consent hat.
  Mit diesem fordern wir einen Access Token an.

  Der Access Token muss die ungültigen Inhalte (zu lange, falsche Format,...) korrekt enthalten.


    Given IDP I choose code verifier '${TESTENV.code_verifier01}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce  | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 887766 | code          |
    And IDP I sign the challenge with '<cert>'
    And IDP I request a code token with signed challenge
    Then IDP the response is an 400 error with gematik code 2020 and error "invalid_request"


    Examples: GetToken - Zertifikate und Claims
      | cert                                               |
      | /certs/invalid/egk-idp-famname-toolong-ecc.p12     |
      | /certs/invalid/egk-idp-firstname-toolong-ecc.p12   |
      | /certs/invalid/egk-idp-idnum-invalididnum2-ecc.p12 |
#      | /certs/invalid/egk-idp-profid-invoid1-ecc.p12      | # falsche rolle wird bei RISE nicht abgelehnt
#      | /certs/invalid/egk-idp-profid-invoid2-ecc.p12      | #
      | /certs/invalid/egk-idp-orgname-toolong-ecc.p12     |

  @TCID:IDP_REF_TOK_015 @PRIO:2 @Negative
    @Approval @Ready
  Scenario Outline: GetTokenSigned - Access Token User Consent Inhalte des Zertifikats sind null
  ```
  Wir signieren eine Challenge mit einem Zertifikate, welches ungültige Null Einträge beim User Consent hat.
  Mit diesem fordern wir einen Access Token an.

  Der Access Token darf die null Inhalte nicht enthalten.


    Given IDP I choose code verifier '${TESTENV.code_verifier01}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce  | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 887766 | code          |
    And IDP I sign the challenge with '<cert>'
    And IDP I request a code token with signed challenge
    Then IDP the response is an 400 error with gematik code 2020 and error 'invalid_request'

    Examples: GetToken - Zertifikate und Claims
      | cert                                          |
      | /certs/invalid/egk-idp-famname-null-ecc.p12   |
      | /certs/invalid/egk-idp-firstname-null-ecc.p12 |
#      | /certs/invalid/egk-idp-orgname-null-ecc.p12   |
      | /certs/invalid/egk-idp-profid-null-ecc.p12    |


  @TCID:IDP_REF_TOK_016 @PRIO:2 @Negative
    @Approval @Ready
  Scenario Outline: GetTokenSigned - ID Token User Consent Inhalte des Zertifikats sind null
  ```
  Wir signieren eine Challenge mit einem Zertifikate, welches ungültige Null Einträge beim User Consent hat.
  Mit diesem fordern wir einen Access Token an.

  Der ID Token darf die null Inhalte nicht enthalten.


    Given IDP I choose code verifier '${TESTENV.code_verifier01}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce  | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 887766 | code          |
    And IDP I sign the challenge with '<cert>'
    And IDP I request a code token with signed challenge
    Then IDP the response is an 400 error with gematik code 2020 and error 'invalid_request'

    Examples: GetToken - Zertifikate und Claims
      | cert                                          |
      | /certs/invalid/egk-idp-famname-null-ecc.p12   |
      | /certs/invalid/egk-idp-firstname-null-ecc.p12 |
#      | '/certs/invalid/egk-idp-orgname-null-ecc.p12'   |
      | /certs/invalid/egk-idp-profid-null-ecc.p12    |

