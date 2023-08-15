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
@SsoTokenFlow
Feature: Autorisiere Anwendung am IDP Server mittels SSO Token
  Frontends von TI Diensten müssen vom IDP Server über ein HTTP POST an den Authorization Endpoint ein Code Token abfragen können.

  Background: Initialisiere Testkontext durch Abfrage des Discovery Dokuments
    Given IDP I initialize scenario from discovery document endpoint
    And IDP I retrieve public keys from URIs

  @TCID:IDP_REF_AUTH_101 @PRIO:1
  @AFO-ID:A_20946-01 @AFO-ID:A_20950-01
  @Approval @Ready
  @TESTSTUFE:4
  Scenario: AuthorSSO - Gutfall - Validiere Antwortstruktur

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, signieren diesen und
  fordern einen TOKEN_CODE mit der signierten Challenge an.
  Dann löschen wir den Context mit Ausnahme des erhaltenen SSO Tokens und wiederholen die Schritte, nur fordern wir nun
  einen TOKEN_CODE mit dem SSO Token an.

  Die TOKEN_CODE Antwort muss den Code 302 die richtigen HTTP Header haben.
  - im Location header state, code aber
  - NICHT SSO Token als Query Parameter enthalten

    Given IDP I choose code verifier '${TESTENV.code_verifier02}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state        | nonce  | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge02} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx1 | 123456 | code          |
    And IDP I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And IDP I request a code token with signed challenge successfully
    And IDP I start new interaction keeping only
      | SSO_TOKEN_ENCRYPTED |
    And IDP I initialize scenario from discovery document endpoint
    And IDP I choose code verifier '${TESTENV.code_verifier01}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state        | nonce  | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx2 | 234567 | code          |

    When IDP I request a code token with sso token
    Then the response status is 302
    And IDP the response http headers match
        """
        Cache-Control=no-store
        Pragma=no-cache
        Content-Length=0
        Location=${TESTENV.redirect_uri_regex}[?|&]code=.*
        """
    And IDP I expect the Context with key SSO_TOKEN to match '$NULL'
    And IDP I expect the Context with key STATE to match 'xxxstatexxx2'

  @TCID:IDP_REF_AUTH_102 @PRIO:1
  @AFO-ID:A_20946-01 @AFO-ID:A_20950-01 @AFO-ID:A_20377
  @Approval @Ready @RefImplOnly
  @TESTSTUFE:4
  Scenario: AuthorSSO - Gutfall - Validiere Location Header und Code Token Claims

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, signieren diesen und
  fordern einen TOKEN_CODE mit der signierten Challenge an.
  Dann löschen wir den Context mit Ausnahme des erhaltenen SSO Tokens und wiederholen die Schritte nur fordern wir nun
  einen TOKEN_CODE mit dem SSO Token an.

  Die TOKEN_CODE Antwort muss im Location header state, code aber NICHT SSO Token als Query Parameter enthalten und
  die richtigen Claims im Token haben.


    Given IDP I choose code verifier '${TESTENV.code_verifier02}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state        | nonce  | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge02} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx1 | 123456 | code          |
    And IDP I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And IDP I request a code token with signed challenge successfully
    And IDP I start new interaction keeping only
      | SSO_TOKEN_ENCRYPTED |
    And IDP I initialize scenario from discovery document endpoint
    And IDP I choose code verifier '${TESTENV.code_verifier01}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state        | nonce  | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx2 | 234567 | code          |
    And IDP I request a code token with sso token successfully

    When IDP I extract the header claims from token TOKEN_CODE_ENCRYPTED
    Then IDP the header claims should match in any order
        """
          {
            alg: "dir",
            enc: "A256GCM",
            cty: "NJWT",
            exp: "[\\d]*",
            ____kid: ".*"
          }
        """

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
          { auth_time:             "${json-unit.ignore}",
            client_id:             "${TESTENV.client_id}",
            code_challenge:        "${TESTENV.code_challenge01}",
            code_challenge_method: "S256",
            exp:                   "[\\d]*",
            jti:                   "${json-unit.ignore}",
            iat:                   ".*",
            idNummer:              "[A-Z][\\d]{9,10}",
            iss:                   "${TESTENV.issuer}",
            family_name:           "(.{1,64})",
            given_name:            "(.{1,64})",
            nonce:                 "234567",
            organizationName:      "(.{1,64})",
            professionOID:         "1\\.2\\.276\\.0\\.76\\.4\\.(3\\d|4\\d|178|23[2-90]|240|241)",
            redirect_uri:          "${TESTENV.redirect_uri}",
            response_type:         "code",
            scope:                 "${TESTENV.scopes_basisflow_regex}",
            snc:                   ".*",
            state:                 "xxxstatexxx2",
            token_type:            "code"
          }
        """

  @TCID:IDP_REF_AUTH_103 @PRIO:1
  @AFO-ID:A_20319-01
  @Approval @Ready
  @Signature
  @RefImplOnly
  @TESTSTUFE:4
  Scenario: AuthorSSO - Validiere Signatur des Code Token

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, signieren diesen und
  fordern einen TOKEN_CODE mit der signierten Challenge an.
  Dann löschen wir den Context mit Ausnahme des erhaltenen SSO Tokens und wiederholen die Schritte nur fordern wir nun
  einen TOKEN_CODE mit dem SSO Token an.

  Der Code Token muss mit dem puk_idp_sig Zertifikat gültig signiert sein.


    Given IDP I choose code verifier '${TESTENV.code_verifier02}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state        | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge02} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx1 | 4444  | code          |
    And IDP I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And IDP I request a code token with signed challenge successfully
    And IDP I start new interaction keeping only
      | SSO_TOKEN_ENCRYPTED |
    And IDP I initialize scenario from discovery document endpoint
    And IDP I retrieve public keys from URIs
    And IDP I choose code verifier '${TESTENV.code_verifier01}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state        | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx2 | 3434  | code          |

    When IDP I request a code token with sso token successfully
    Then IDP the context TOKEN_CODE must be signed with cert PUK_SIGN


  @TCID:IDP_REF_AUTH_104 @PRIO:2
  @Approval @Ready
  @Timeout
  @LongRunning
  @TESTSTUFE:4
  Scenario: AuthorSSO - Veralteter Challenge Token wird abgelehnt

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, signieren diesen und
  fordern einen TOKEN_CODE mit der signierten Challenge an.
  Dann löschen wir den Context mit Ausnahme des erhaltenen SSO Tokens und wiederholen die Schritte, warten 3min
  und fordern dann erst einen TOKEN_CODE mit dem SSO Token an.

  Der Server muss diese Anfrage mit einem Timeout Fehler ablehnen.

    Given IDP I choose code verifier '${TESTENV.code_verifier02}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state        | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge02} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx1 | 4444  | code          |
    And IDP I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And IDP I request a code token with signed challenge successfully
    And IDP I start new interaction keeping only
      | SSO_TOKEN_ENCRYPTED |
    And IDP I initialize scenario from discovery document endpoint
    And IDP I retrieve public keys from URIs
    And IDP I choose code verifier '${TESTENV.code_verifier01}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state        | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx2 | 3434  | code          |

    When IDP I wait PT3M5S
    And IDP I request a code token with sso token
    Then IDP the response is an 400 error with gematik code 2032 and error 'invalid_request'

    # ------------------------------------------------------------------------------------------------------------------
    #
    # negative cases

  @TCID:IDP_REF_AUTH_105 @PRIO:2 @TESTFALL:Negativ
  @Approval @Ready
  @TESTSTUFE:4
  Scenario: AuthorSSO - Challenge Token fehlt beim SSO Token Aufruf

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, signieren diesen und
  fordern einen TOKEN_CODE mit der signierten Challenge an.
  Dann löschen wir den Context mit Ausnahme des erhaltenen SSO Tokens und wiederholen die Schritte nur fordern wir nun
  einen TOKEN_CODE mit dem SSO Token an, ohne den Challenge Token als Parameter mitzugeben.

  Der Server muss diese Anfrage mit HTTP Status 302 und einer Fehlermeldung im Location Header ablehnen.


    Given IDP I choose code verifier '${TESTENV.code_verifier02}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state        | nonce  | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge02} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx1 | 131313 | code          |
    And IDP I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And IDP I request a code token with signed challenge successfully
    And IDP I start new interaction keeping only
      | SSO_TOKEN_ENCRYPTED |
    And IDP I initialize scenario from discovery document endpoint
    And IDP I choose code verifier '${TESTENV.code_verifier01}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state        | nonce  | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx2 | 242424 | code          |

    When IDP I request a code token with sso token no challenge
    Then IDP the response is an 400 error with gematik code 2030 and error 'invalid_request'


  @AFO-ID:A_20948-01  @AFO-ID:A_20949 @TESTFALL:Negativ
  @TCID:IDP_REF_AUTH_106
  @PRIO:2
  @Approval @Ready
  @TESTSTUFE:4
  Scenario: AuthorSSO - Anfrage mit modifiziertem SSO Token

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, signieren diesen und
  fordern einen TOKEN_CODE mit der signierten Challenge an.
  Dann löschen wir den Context mit Ausnahme des erhaltenen SSO Tokens, modifizieren diesen und wiederholen die
  Schritte nur fordern wir nun einen TOKEN_CODE mit dem modifizierten SSO Token an.

  Die Server muss diese Anfrage mit HTTP Status 400 und einer Fehlermeldung ablehnen.

    Given IDP I choose code verifier '${TESTENV.code_verifier02}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state        | nonce  | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge02} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx1 | 123456 | code          |
    And IDP I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And IDP I request a code token with signed challenge successfully
    And IDP I start new interaction keeping only
      | SSO_TOKEN_ENCRYPTED |
    And IDP I flip bit -20 on context with key SSO_TOKEN_ENCRYPTED
    And IDP I initialize scenario from discovery document endpoint
    And IDP I choose code verifier '${TESTENV.code_verifier01}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state        | nonce  | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx2 | 234567 | code          |

    When IDP I request a code token with sso token
    Then IDP the response is an 400 error with gematik code 2040 and error 'access_denied'


  @TCID:IDP_REF_AUTH_107 @PRIO:2
  @OpenBug
  @issue:IDP-659
  @AFO-ID:A_20588-01
  @AFO-ID:A_20589
  @Approval @Ready
  @TESTSTUFE:4
  Scenario: Auth - Gesperrter User Agent

  ```
  Wir fordern einen Challenge Token mit einem gesperrten User Agent an.
  Als Antwort erwarten wir einen entsprechenden HTTP code, error id und error code

    Given IDP I choose code verifier 'zdrfcvz3iw47fgderuzbq834werb3q84wgrb3zercb8q3wbd834wefb348ch3rq9e8fd9sac'
        # REM code_challenge for given verifier can be obtained from https://tonyxu-io.github.io/pkce-generator/
    And IDP I set user agent to 'Bad-Actor-App/2.0'
    When IDP I request a challenge with
      | client_id            | scope                      | code_challenge                              | code_challenge_method | redirect_uri            | state       | nonce     | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 123456789 | code          |
    Then the response status is failed state
    And IDP the response is an 401 error with gematik code 1041 and error 'invalid_request'
    And IDP I set user agent to 'gematik.Testsuite/1.0/eRezeptApp'