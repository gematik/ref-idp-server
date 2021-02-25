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
Feature: Authentifiziere Anwendung am IDP Server

  Frontends von TI Diensten müssen vom IDP Server über ein **HTTP GET** an den Authorization Endpoint ein Code Challenge Token abfragen können.

  Background: Initialisiere Testkontext durch Abfrage des Discovery Dokuments
    Given I initialize scenario from discovery document endpoint
    And I retrieve public keys from URIs

  @Afo:A_20601 @Afo:A_20740 @Afo:A_20698
  @Approval @Ready
  Scenario: Core Auth - Gutfall - Validiere Antwortstruktur

  ```
  Wir wählen einen gültigen Code verifier und fordern einen Challenge Token an.

  Die HTTP Response muss:

  - den Code 200
  - die richtigen HTTP Header
  - das korrekte JSON im Body haben.


    Given I choose code verifier 'zdrfcvz3iw47fgderuzbq834werb3q84wgrb3zercb8q3wbd834wefb348ch3rq9e8fd9sac'
        # REM code_challenge for given verifier can be obtained from https://tonyxu-io.github.io/pkce-generator/

    When I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce     | response_type |
      | eRezeptApp | e-rezept openid | P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 123456789 | code          |
    Then the response status is 200
    And the response http headers match
        """
          Content-Type=application/json.*
          Cache-Control=no-store
          Pragma=no-cache
        """
    And the JSON response should match
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

  @Afo:A_20601 @Afo:A_20740 @Afo:A_20376 @Afo:A_20521-01 @Afo:A_20377
  @Approval @Ready
  Scenario: Auth - Gutfall - Validiere Claims

  ```
  Wir wählen einen gültigen Code verifier und fordern einen Challenge Token an.

  Die HTTP Response muss die richtigen Claims im Token haben.


    Given I choose code verifier 'zdrfcvz3iw47fgderuzbq834werb3q84wgrb3zercb8q3wbd834wefb348ch3rq9e8fd9sac'
        # REM code_challenge for given verifier can be obtained from https://tonyxu-io.github.io/pkce-generator/
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce     | response_type |
      | eRezeptApp | e-rezept openid | P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 123456789 | code          |

    When I extract the header claims from response field challenge
    Then the header claims should match in any order
        """
          { alg: "BP256R1",
            exp: "[\\d]*",
            typ: "JWT",
            kid: "${json-unit.ignore}"
          }
        """
    When I extract the body claims from response field challenge
    Then the body claims should match in any order
        """
          { client_id:             "eRezeptApp",
            code_challenge:        "P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk",
            code_challenge_method: "S256",
            exp:                   "[\\d]*",
            jti:                   "${json-unit.ignore}",
            iat:                   "[\\d]*",
            iss:                   "https://idp.zentral.idp.splitdns.ti-dienste.de",
            nonce:                 "123456789",
            redirect_uri:          "http://redirect.gematik.de/erezept",
            response_type:         "code",
            snc:                   "${json-unit.ignore}",
            scope:                 "(e-rezept openid|openid e-rezept)",
            state:                 "xxxstatexxx",
            token_type:            "challenge"
          }
        """

  @Approval @Ready
  Scenario: Auth - Anfrage Parameter nonce optional

  ```
  Wir wählen einen gültigen Code verifier und fordern einen Challenge Token ohne nonce als Parameter an.

  Die HTTP Response darf in den claims keinen client nonce enthalten:


    Given I choose code verifier 'zdrfcvz3iw47fgderuzbq834werb3q84wgrb3zercb8q3wbd834wefb348ch3rq9e8fd9sac'
        # REM code_challenge for given verifier can be obtained from https://tonyxu-io.github.io/pkce-generator/
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | response_type |
      | eRezeptApp | e-rezept openid | P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | code          |

    When I extract the body claims from response field challenge
    Then the body claims should match in any order
        """
          { client_id:             "eRezeptApp",
            code_challenge:        "P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk",
            code_challenge_method: "S256",
            exp:                   "[\\d]*",
            jti:                   "${json-unit.ignore}",
            iat:                   "[\\d]*",
            iss:                   "https://idp.zentral.idp.splitdns.ti-dienste.de",
            redirect_uri:          "http://redirect.gematik.de/erezept",
            response_type:         "code",
            scope:                 "(e-rezept openid|openid e-rezept)",
            snc:                   "${json-unit.ignore}",
            state:                 "xxxstatexxx",
            token_type:            "challenge"
          }
        """

  @Afo:A_19908_01 @Afo:A_20604
  @Approval @Ready
  @Signature
  Scenario: Auth - Validiere Signatur der Challenge

  ```
  Wir wählen einen gültigen Code verifier und fordern einen Challenge Token an.

  Die Challenge muss mit dem PUK_SIGN signiert sein.


    Given I choose code verifier 'zdrfcvz3iw47fgderuzbq834werb3q84wgrb3zercb8q3wbd834wefb348ch3rq9e8fd9sac'
        # REM code_challenge for given verifier can be obtained from https://tonyxu-io.github.io/pkce-generator/
    When I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce     | response_type |
      | eRezeptApp | e-rezept openid | P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 123456789 | code          |
    Then the context CHALLENGE must be signed with cert PUK_SIGN


  @Afo:A_20740 @Afo:A_20601 @Afo:A_20698
    @Approval @Ready
  Scenario Outline: Auth - Fehlende Parameter

  ```
  Wir fordern einen Challenge Token mit einem ungültigen Request an,
  in welchem je ein verpflichtender Parameter fehlt.

    When I request a challenge with
      | client_id   | scope   | code_challenge   | code_challenge_method   | redirect_uri   | state   | nonce   | response_type   |
      | <client_id> | <scope> | <code_challenge> | <code_challenge_method> | <redirect_uri> | <state> | <nonce> | <response_type> |
    Then the response status is failed state
    And the JSON response should match
        """
          { detail_message: "Required .* parameter '.*' is not present",
            error_code:     "missing_parameters",
            error_uuid:     ".*",
            timestamp:      ".*"
          }
        """

    Examples: Auth - Fehlende Parameter Beispiele
      | client_id  | scope           | code_challenge                                                   | code_challenge_method | redirect_uri                       | state       | nonce     | response_type |
      | $REMOVE    | e-rezept openid | 932F3C1B56257CE8539AC269D7AAB42550DACF8818D075F0BDF1990562AAE3EF | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 123456789 | code          |
      | eRezeptApp | $REMOVE         | 932F3C1B56257CE8539AC269D7AAB42550DACF8818D075F0BDF1990562AAE3EF | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 123456789 | code          |
      | eRezeptApp | e-rezept openid | $REMOVE                                                          | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 123456789 | code          |
      | eRezeptApp | e-rezept openid | 932F3C1B56257CE8539AC269D7AAB42550DACF8818D075F0BDF1990562AAE3EF | $REMOVE               | http://redirect.gematik.de/erezept | xxxstatexxx | 123456789 | code          |
      | eRezeptApp | e-rezept openid | 932F3C1B56257CE8539AC269D7AAB42550DACF8818D075F0BDF1990562AAE3EF | S256                  | $REMOVE                            | xxxstatexxx | 123456789 | code          |
      | eRezeptApp | e-rezept openid | 932F3C1B56257CE8539AC269D7AAB42550DACF8818D075F0BDF1990562AAE3EF | S256                  | http://redirect.gematik.de/erezept | $REMOVE     | 123456789 | code          |
      | eRezeptApp | e-rezept openid | 932F3C1B56257CE8539AC269D7AAB42550DACF8818D075F0BDF1990562AAE3EF | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 123456789 | $REMOVE       |
      # nonce is not mandatory so no example here

  @Afo:A_20601 @Afo:A_20740
    @Approval @Ready
  Scenario Outline: Auth - Null Parameter

  ```
  Wir fordern einen Challenge Token mit einem ungültigen Request an,
  in welchem je ein verpflichtender Parameter null ist.


    When I request a challenge with
      | client_id   | scope   | code_challenge   | code_challenge_method   | redirect_uri   | state   | nonce   | response_type   |
      | <client_id> | <scope> | <code_challenge> | <code_challenge_method> | <redirect_uri> | <state> | <nonce> | <response_type> |
    Then the response status is failed state
    And the JSON response should match
        """
          { detail_message: "getAuthenticationChallenge.*invalid.*",
            error_code:     "invalid_request",
            error_uuid:     ".*",
            timestamp:      ".*"
          }
        """

    Examples: Auth - Null Parameter Beispiele
      | client_id  | scope           | code_challenge                                                   | code_challenge_method | redirect_uri                       | state       | nonce     | response_type |
      | $NULL      | e-rezept openid | 932F3C1B56257CE8539AC269D7AAB42550DACF8818D075F0BDF1990562AAE3EF | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 123456789 | code          |
      | eRezeptApp | $NULL           | 932F3C1B56257CE8539AC269D7AAB42550DACF8818D075F0BDF1990562AAE3EF | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 123456789 | code          |
      | eRezeptApp | e-rezept openid | $NULL                                                            | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 123456789 | code          |
      | eRezeptApp | e-rezept openid | 932F3C1B56257CE8539AC269D7AAB42550DACF8818D075F0BDF1990562AAE3EF | $NULL                 | http://redirect.gematik.de/erezept | xxxstatexxx | 123456789 | code          |
      | eRezeptApp | e-rezept openid | 932F3C1B56257CE8539AC269D7AAB42550DACF8818D075F0BDF1990562AAE3EF | S256                  | $NULL                              | xxxstatexxx | 123456789 | code          |
      | eRezeptApp | e-rezept openid | 932F3C1B56257CE8539AC269D7AAB42550DACF8818D075F0BDF1990562AAE3EF | S256                  | http://redirect.gematik.de/erezept | $NULL       | 123456789 | code          |
      | eRezeptApp | e-rezept openid | 932F3C1B56257CE8539AC269D7AAB42550DACF8818D075F0BDF1990562AAE3EF | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | $NULL     | code          |
      | eRezeptApp | e-rezept openid | 932F3C1B56257CE8539AC269D7AAB42550DACF8818D075F0BDF1990562AAE3EF | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 123456789 | $NULL         |

  @Afo:A_20601 @Afo:A_20440-01
    @Approval @Todo:ErrorMessage
  Scenario Outline: Auth - Ungültige Parameter

  ```
  Wir fordern einen Challenge Token mit einem ungültigen Request an,
  in welchem je ein verpflichtender Parameter einen ungültigen Wert hat.


    When I request a challenge with
      | client_id   | scope   | code_challenge   | code_challenge_method   | redirect_uri   | state   | nonce   | response_type   |
      | <client_id> | <scope> | <code_challenge> | <code_challenge_method> | <redirect_uri> | <state> | <nonce> | <response_type> |
    Then the response status is failed state
    And the JSON response should match
        """
          { detail_message: ".*",
            error_code:     "<error_code>",
            error_uuid:     ".*",
            timestamp:      ".*"
          }
        """

    Examples: Auth - Ungültige Parameter Beispiele
      | error_code            | client_id          | scope           | code_challenge                                                   | code_challenge_method | redirect_uri                       | state       | nonce | response_type |
            # REM invalid client_id
      | invalid_request       | resistanceisfutile | openid e-rezept | 932F3C1B56257CE8539AC269D7AAB42550DACF8818D075F0BDF1990562AAE3EF | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 12345 | code          |
            # REM invalid scope IDP-361
      | invalid_request       | eRezeptApp         | weareborg       | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg                      | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 12345 | code          |
            # opnenid or e-rezept only is not valid
      | invalid_request       | eRezeptApp         | openid          | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg                      | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 12345 | code          |
      | invalid_request       | eRezeptApp         | e-rezept        | 932F3C1B56257CE8539AC269D7AAB42550DACF8818D075F0BDF1990562AAE3EF | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 12345 | code          |
            # REM invalid code_challenge: something definitely not being an S256 hash string (! und .)
      | invalid_request       | eRezeptApp         | openid e-rezept | Fest gemauert in der Erde! Steht die Form aus Lehm gebrannt.     | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 12345 | code          |
            # REM unsupported code challenge method
      | internal_server_error | eRezeptApp         | openid e-rezept | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg                      | plain                 | http://redirect.gematik.de/erezept | xxxstatexxx | 12345 | code          |
            # REM invalid code challenge method
      | internal_server_error | eRezeptApp         | openid e-rezept | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg                      | axanar                | http://redirect.gematik.de/erezept | xxxstatexxx | 12345 | code          |
            # REM invalid redirect uri
      | redirect_uri_defunct  | eRezeptApp         | openid e-rezept | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg                      | S256                  | http://www.drinkinggamezone.com/   | xxxstatexxx | 12345 | code          |
            # REM state could be any value
      | invalid_request       | eRezeptApp         | openid e-rezept | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg                      | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 12345 | invalid_type  |
            # REM nonce could be any value

      # code challenge method plain and axanar:
#  {
#  "error_uuid": "2ea5c3e1-2bbf-45e6-8c96-61653e32038c",
#  "error_code": "internal_server_error",
#  "detail_message": "Failed to convert value of type 'java.lang.String' to required type 'de.gematik.idp.field.CodeChallengeMethod'; nested exception is org.springframework.core.convert.ConversionFailedException: Failed to convert from type [java.lang.String] to type [@org.springframework.web.bind.annotation.RequestParam @de.gematik.idp.server.validation.parameterConstraints.CheckCodeChallengeMethod @io.swagger.annotations.ApiParam de.gematik.idp.field.CodeChallengeMethod] for value 'plain'; nested exception is java.lang.IllegalArgumentException: No enum constant de.gematik.idp.field.CodeChallengeMethod.plain",
#  "timestamp": "2021-01-22T18:51:54.580485700+01:00[Europe\/Berlin]"
#  }


