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
@Authentication
Feature: Authentifiziere Anwendung am IDP Server

  Frontends von TI Diensten müssen vom IDP Server über ein **HTTP GET** an den Authorization Endpoint ein Code Challenge Token abfragen können.

  Background: Initialisiere Testkontext durch Abfrage des Discovery Dokuments
    Given IDP I initialize scenario from discovery document endpoint
    And IDP I retrieve public keys from URIs

  @TCID:IDP_REF_AUTH_001 @PRIO:1
  @Afo:A_20698  @Afo:A_20523
  @Approval @Ready
  Scenario: Auth - Gutfall - Validiere Antwortstruktur

  ```
  Wir wählen einen gültigen Code verifier und fordern einen Challenge Token an.

  Die HTTP Response muss:

  - den Code 200
  - die richtigen HTTP Header
  - das korrekte JSON im Body haben.


    Given IDP I choose code verifier 'zdrfcvz3iw47fgderuzbq834werb3q84wgrb3zercb8q3wbd834wefb348ch3rq9e8fd9sac'
        # REM code_challenge for given verifier can be obtained from https://tonyxu-io.github.io/pkce-generator/

    When IDP I request a challenge with
      | client_id            | scope                      | code_challenge                              | code_challenge_method | redirect_uri            | state       | nonce     | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 123456789 | code          |
    Then the response status is 200
    When IDP ich hole die öffentlichen Schlüssel von ihren URIs

    And IDP the response http headers match
        """
          Content-Type=application/json.*
        """
    And IDP the JSON response should match
  """
          {
            "challenge":     "ey[A-Za-z0-9\\-_\\.]*",
            "user_consent":  {
              "requested_scopes" : {
                "e-rezept" : ".*E-Rezept.*",
                "openid" : ".*ID\\-Token.*"
              },
              "requested_claims" : {
                "given_name" : ".*Vorname.*",
                "professionOID" : ".*Rolle.*",
                "organizationName" : ".*Organisationszugehörigkeit.*",
                "family_name" : ".*Nachname.*",
                "idNummer" : ".*Id.*Krankenversichertennummer.*Telematik\\-Id.*"
              }
            }
          }
        """

  @TCID:IDP_REF_AUTH_002 @PRIO:1
  @Afo:A_20376 @Afo:A_20521 @Afo:A_20377
  @Approval @Ready
  Scenario: Auth - Gutfall - Validiere Claims

  ```
  Wir wählen einen gültigen Code verifier und fordern einen Challenge Token an.

  Die HTTP Response muss die richtigen Claims im Token haben.

  - client_id, state müssen, code_challenge, nonce, redirect_uri müssen identisch sein



    Given IDP I choose code verifier 'zdrfcvz3iw47fgderuzbq834werb3q84wgrb3zercb8q3wbd834wefb348ch3rq9e8fd9sac'
        # REM code_challenge for given verifier can be obtained from https://tonyxu-io.github.io/pkce-generator/
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge                              | code_challenge_method | redirect_uri            | state       | nonce     | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 123456789 | code          |

    When IDP I extract the header claims from response field challenge
    Then IDP the header claims should match in any order
  """
          { alg: "BP256R1",
            typ: "JWT",
            kid: "${json-unit.ignore}"
          }
        """

    When IDP I extract the body claims from response field challenge
    Then IDP the body claims should match in any order
  """
          { client_id:             "${TESTENV.client_id}",
            code_challenge:        "P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk",
            code_challenge_method: "S256",
            exp:                   "[\\d]*",
            jti:                   "${json-unit.ignore}",
            iat:                   "[\\d]*",
            iss:                   "${TESTENV.issuer}",
            nonce:                 "123456789",
            redirect_uri:          "${TESTENV.redirect_uri}",
            response_type:         "code",
            snc:                   "${json-unit.ignore}",
            scope:                 "${TESTENV.scopes_basisflow_regex}",
            state:                 "xxxstatexxx",
            token_type:            "challenge"
          }
        """

  @TCID:IDP_REF_AUTH_003 @PRIO:2
  @Approval @Ready
  Scenario: Auth - Anfrage Parameter nonce optional

  ```
  Wir wählen einen gültigen Code verifier und fordern einen Challenge Token ohne nonce als Parameter an.

  Die HTTP Response darf in den claims keinen client nonce enthalten:


    Given IDP I choose code verifier 'zdrfcvz3iw47fgderuzbq834werb3q84wgrb3zercb8q3wbd834wefb348ch3rq9e8fd9sac'
        # REM code_challenge for given verifier can be obtained from https://tonyxu-io.github.io/pkce-generator/
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge                              | code_challenge_method | redirect_uri            | state       | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | code          |

    When IDP I extract the body claims from response field challenge
    # checking no nonce claim appears in response
    Then IDP the body claims should match in any order
  """
          { client_id:             "${TESTENV.client_id}",
            code_challenge:        "P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk",
            code_challenge_method: "S256",
            exp:                   "[\\d]*",
            jti:                   "${json-unit.ignore}",
            iat:                   "[\\d]*",
            iss:                   "${TESTENV.issuer}",
            redirect_uri:          "${TESTENV.redirect_uri}",
            response_type:         "code",
            scope:                 "${TESTENV.scopes_basisflow_regex}",
            snc:                   "${json-unit.ignore}",
            state:                 "xxxstatexxx",
            token_type:            "challenge"
          }
        """


  @TCID:IDP_REF_AUTH_004 @PRIO:1
  @Afo:A_20604
  @Approval @Ready @Signature
  Scenario: Auth - Validiere Signatur der Challenge

  ```
  Wir wählen einen gültigen Code verifier und fordern einen Challenge Token an.

  Die Challenge muss mit dem PUK_SIGN signiert sein.


    Given IDP I choose code verifier 'zdrfcvz3iw47fgderuzbq834werb3q84wgrb3zercb8q3wbd834wefb348ch3rq9e8fd9sac'
        # REM code_challenge for given verifier can be obtained from https://tonyxu-io.github.io/pkce-generator/
    When IDP I request a challenge with
      | client_id            | scope                      | code_challenge                              | code_challenge_method | redirect_uri            | state       | nonce     | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 123456789 | code          |
    Then IDP the context CHALLENGE must be signed with cert PUK_SIGN

  @TCID:IDP_REF_AUTH_005 @PRIO:2 @Negative
    @Afo:A_20698 @Afo:A_20440
    @Approval @Ready
  Scenario Outline: Auth - Fehlende Parameter

  ```
  Wir fordern einen Challenge Token mit einem ungültigen Request an,
  in welchem je ein verpflichtender Parameter fehlt.

  Als Antwort erwarten wir einen entsprechenden HTTP code, error id und error code


    When IDP I request a challenge with
      | client_id   | scope   | code_challenge   | code_challenge_method   | redirect_uri   | state   | nonce   | response_type   |
      | <client_id> | <scope> | <code_challenge> | <code_challenge_method> | <redirect_uri> | <state> | <nonce> | <response_type> |
    Then the response status is failed state
    And IDP the response is an <http_code> error with gematik code <err_id> and error '<err>'

    Examples: Auth - Fehlende Parameter Beispiele
      | http_code | err_id | err             | client_id            | scope                      | code_challenge                              | code_challenge_method | redirect_uri            | state       | nonce     | response_type |
      | 400       | 1002   | invalid_request | $REMOVE              | ${TESTENV.scope_basisflow} | P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 123456789 | code          |
      | 400       | 1004   | invalid_request | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk | S256                  | $REMOVE                 | xxxstatexxx | 123456789 | code          |
      | 302       | 1005   | invalid_request | ${TESTENV.client_id} | $REMOVE                    | P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 123456789 | code          |
      | 302       | 2009   | invalid_request | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | $REMOVE                                     | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 123456789 | code          |
      | 302       | 2008   | invalid_request | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk | $REMOVE               | ${TESTENV.redirect_uri} | xxxstatexxx | 123456789 | code          |
      | 302       | 2002   | invalid_request | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk | S256                  | ${TESTENV.redirect_uri} | $REMOVE     | 123456789 | code          |
      | 302       | 2004   | invalid_request | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 123456789 | $REMOVE       |
      # nonce is not mandatory so no example here

  @TCID:IDP_REF_AUTH_006 @PRIO:2 @Negative
    @Afo:A_20440
    @Approval @Ready
  Scenario Outline: Auth - Null Parameter

  ```
  Wir fordern einen Challenge Token mit einem ungültigen Request an,
  in welchem je ein verpflichtender Parameter null ist.

  Als Antwort erwarten wir einen entsprechenden HTTP code, error id und error code


    When IDP I request a challenge with
      | client_id   | scope   | code_challenge   | code_challenge_method   | redirect_uri   | state   | nonce   | response_type   |
      | <client_id> | <scope> | <code_challenge> | <code_challenge_method> | <redirect_uri> | <state> | <nonce> | <response_type> |
    Then the response status is failed state
    And IDP the response is an <return_code> error with gematik code <err_id> and error '<err>'

    Examples: Auth - Null Parameter Beispiele
      | return_code | err_id | err             | client_id            | scope                      | code_challenge                              | code_challenge_method | redirect_uri            | state       | nonce     | response_type |
      | 400         | 1002   | invalid_request | $NULL                | ${TESTENV.scope_basisflow} | P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 123456789 | code          |
      | 302         | 1005   | invalid_request | ${TESTENV.client_id} | $NULL                      | P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 123456789 | code          |
      | 302         | 2009   | invalid_request | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | $NULL                                       | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 123456789 | code          |
      | 302         | 2008   | invalid_request | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk | $NULL                 | ${TESTENV.redirect_uri} | xxxstatexxx | 123456789 | code          |
      | 400         | 1004   | invalid_request | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk | S256                  | $NULL                   | xxxstatexxx | 123456789 | code          |
      | 302         | 2002   | invalid_request | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk | S256                  | ${TESTENV.redirect_uri} | $NULL       | 123456789 | code          |
      | 302         | 2004   | invalid_request | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 123456789 | $NULL         |

  @TCID:IDP_REF_AUTH_007 @PRIO:1 @Negative
    @Afo:A_20440
    @Approval @Ready
  Scenario Outline: Auth - Ungültige Parameter

  ```
  Wir fordern einen Challenge Token mit einem ungültigen Request an,
  in welchem je ein verpflichtender Parameter einen ungültigen Wert hat.

  Als Antwort erwarten wir einen entsprechenden HTTP code, error id und error code

    When IDP I request a challenge with
      | client_id   | scope   | code_challenge   | code_challenge_method   | redirect_uri   | state   | nonce   | response_type   |
      | <client_id> | <scope> | <code_challenge> | <code_challenge_method> | <redirect_uri> | <state> | <nonce> | <response_type> |
    Then the response status is failed state
    And IDP the response is an <return_code> error with gematik code <err_id> and error '<err>'

    Examples: Auth - Ungültige Parameter Beispiele
      | return_code | err_id | err                       | client_id            | scope                      | code_challenge                                               | code_challenge_method | redirect_uri                     | state       | nonce | response_type |
            # REM invalid client_id
      | 400         | 2012   | invalid_request           | resistanceisfutile   | ${TESTENV.scope_basisflow} | P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk                  | S256                  | ${TESTENV.redirect_uri}          | xxxstatexxx | 12345 | code          |
            # REM invalid scope IDP-361
      | 302         | 1022   | invalid_scope             | ${TESTENV.client_id} | weareborg                  | ${TESTENV.code_challenge01}                                  | S256                  | ${TESTENV.redirect_uri}          | xxxstatexxx | 12345 | code          |
      | 302         | 1030   | invalid_scope             | ${TESTENV.client_id} | openid weareborg           | ${TESTENV.code_challenge01}                                  | S256                  | ${TESTENV.redirect_uri}          | xxxstatexxx | 12345 | code          |
            # opnenid or e-rezept only is not valid
      | 302         | 1022   | invalid_scope             | ${TESTENV.client_id} | openid                     | ${TESTENV.code_challenge01}                                  | S256                  | ${TESTENV.redirect_uri}          | xxxstatexxx | 12345 | code          |
      | 302         | 1022   | invalid_scope             | ${TESTENV.client_id} | e-rezept                   | P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk                  | S256                  | ${TESTENV.redirect_uri}          | xxxstatexxx | 12345 | code          |
            # REM invalid code_challenge: something definitely not being an S256 hash string (! und .)
      | 302         | 2010   | invalid_request           | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | Fest gemauert in der Erde! Steht die Form aus Lehm gebrannt. | S256                  | ${TESTENV.redirect_uri}          | xxxstatexxx | 12345 | code          |
            # REM unsupported code challenge method
      | 302         | 2008   | invalid_request           | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01}                                  | plain                 | ${TESTENV.redirect_uri}          | xxxstatexxx | 12345 | code          |
            # REM invalid code challenge method
      | 302         | 2008   | invalid_request           | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01}                                  | axanar                | ${TESTENV.redirect_uri}          | xxxstatexxx | 12345 | code          |
            # REM invalid redirect uri
      | 400         | 1020   | invalid_request           | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01}                                  | S256                  | http://www.drinkinggamezone.com/ | xxxstatexxx | 12345 | code          |
            # REM state could be any value
      | 302         | 2005   | unsupported_response_type | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01}                                  | S256                  | ${TESTENV.redirect_uri}          | xxxstatexxx | 12345 | invalid_type  |
            # REM nonce could be any value
