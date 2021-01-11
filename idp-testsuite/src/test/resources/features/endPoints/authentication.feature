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

    @Afo:A_20601
    @Afo:A_20740
    @ReleaseV1
    Scenario: Auth - Gutfall

    ```
    Wir wählen einen gültigen Code verifier und fordern einen Challenge Token an.

    Die HTTP Response muss:

    - den Code 200
    - die richtigen HTTP Header
    - das korrekte JSON im Body und
    - die richtigen Claims im Token haben.


        Given I choose code verifier 'zdrfcvz3iw47fgderuzbq834werb3q84wgrb3zercb8q3wbd834wefb348ch3rq9e8fd9sac'
        # REM code_challenge for given verifier can be obtained from https://tonyxu-io.github.io/pkce-generator/
        When I request a challenge with
            | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       |
            | eRezeptApp | e-rezept openid | P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx |
        Then the response status is 200
        And the response http headers match
            """
            Content-Type=application/json
            Cache-Control=no-store
            Pragma=no-cache
            """
        And the JSON response should match
            """
            {
              "challenge": "ey[A-Za-z0-9\\\-_\\\.]*",
              "user_consent":  "${json-unit.ignore}"
            }
            """
            # TODO check JSON recursive for user consent

        When I extract the header claims from response field challenge
        Then the header claims should match in any order
            """
            {
                "snc": "${json-unit.ignore}",
                "typ": "JWT",
                "alg": "BP256R1",
                "exp": "[\\d]*",
                "jti": "${json-unit.ignore}"
            }
            """

        When I extract the body claims from response field challenge
        Then the body claims should match in any order
            """
            {
                "scope": "(e-rezept openid|openid e-rezept)",
                "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
                "response_type": "code",
                "code_challenge_method": "S256",
                "redirect_uri": "http://redirect.gematik.de/erezept",
                "state": "xxxstatexxx",
                "client_id": "eRezeptApp",
                "code_challenge": "P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk",
                "sub": "${json-unit.ignore}",
                "aud": "https://erp.zentral.erp.splitdns.ti-dienste.de",
                "nbf": "[\\d]*",
                "exp": "[\\d]*",
                "iat": "[\\d]*"
            }
            """

    @Afo:A_20601
        @Afo:A_20740
        @ReleaseV1
    Scenario Outline: Auth - Fehlende Parameter

    ```
    Wir fordern einen Challenge Token mit einem ungültigen Request an,
    in welchem je ein verpflichtender Parameter fehlt.

        When I request a challenge with
            | client_id   | scope   | code_challenge   | code_challenge_method   | redirect_uri   | state   |
            | <client_id> | <scope> | <code_challenge> | <code_challenge_method> | <redirect_uri> | <state> |
        Then the response status is failed state
        And the JSON response should match
        """
            {
                "error_code": "missing_parameters",
                "error_uuid": ".*",
                "timestamp": ".*",
                "detail_message": "Required .* parameter '.*' is not present"
            }
        """

        Examples: Auth - Fehlende Parameter Beispiele
            | client_id  | scope           | code_challenge                                                   | code_challenge_method | redirect_uri                       | state       |
            | $REMOVE    | e-rezept openid | 932F3C1B56257CE8539AC269D7AAB42550DACF8818D075F0BDF1990562AAE3EF | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx |
            | eRezeptApp | $REMOVE         | 932F3C1B56257CE8539AC269D7AAB42550DACF8818D075F0BDF1990562AAE3EF | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx |
            | eRezeptApp | e-rezept openid | $REMOVE                                                          | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx |
            | eRezeptApp | e-rezept openid | 932F3C1B56257CE8539AC269D7AAB42550DACF8818D075F0BDF1990562AAE3EF | $REMOVE               | http://redirect.gematik.de/erezept | xxxstatexxx |
            | eRezeptApp | e-rezept openid | 932F3C1B56257CE8539AC269D7AAB42550DACF8818D075F0BDF1990562AAE3EF | S256                  | $REMOVE                            | xxxstatexxx |
            | eRezeptApp | e-rezept openid | 932F3C1B56257CE8539AC269D7AAB42550DACF8818D075F0BDF1990562AAE3EF | S256                  | http://redirect.gematik.de/erezept | $REMOVE     |

    @Afo:A_20601
        @Afo:A_20740
        @ReleaseV1
    Scenario Outline: Auth - Null Parameter

    ```
    Wir fordern einen Challenge Token mit einem ungültigen Request an,
    in welchem je ein verpflichtender Parameter null ist.


        When I request a challenge with
            | client_id   | scope   | code_challenge   | code_challenge_method   | redirect_uri   | state   |
            | <client_id> | <scope> | <code_challenge> | <code_challenge_method> | <redirect_uri> | <state> |
        Then the response status is 400

        Examples: Auth - Null Parameter Beispiele
            | client_id  | scope           | code_challenge                                                   | code_challenge_method | redirect_uri                       | state       |
            | $NULL      | e-rezept openid | 932F3C1B56257CE8539AC269D7AAB42550DACF8818D075F0BDF1990562AAE3EF | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx |
            | eRezeptApp | $NULL           | 932F3C1B56257CE8539AC269D7AAB42550DACF8818D075F0BDF1990562AAE3EF | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx |
            | eRezeptApp | e-rezept openid | $NULL                                                            | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx |
            | eRezeptApp | e-rezept openid | 932F3C1B56257CE8539AC269D7AAB42550DACF8818D075F0BDF1990562AAE3EF | $NULL                 | http://redirect.gematik.de/erezept | xxxstatexxx |
            | eRezeptApp | e-rezept openid | 932F3C1B56257CE8539AC269D7AAB42550DACF8818D075F0BDF1990562AAE3EF | S256                  | $NULL                              | xxxstatexxx |
            | eRezeptApp | e-rezept openid | 932F3C1B56257CE8539AC269D7AAB42550DACF8818D075F0BDF1990562AAE3EF | S256                  | http://redirect.gematik.de/erezept | $NULL       |

    @Afo:A_20601
        @ReleaseV1
    Scenario Outline: Auth - Ungültige Parameter

    ```
    Wir fordern einen Challenge Token mit einem ungültigen Request an,
    in welchem je ein verpflichtender Parameter einen ungültigen Wert hat.


        When I request a challenge with
            | client_id   | scope   | code_challenge   | code_challenge_method   | redirect_uri   | state   |
            | <client_id> | <scope> | <code_challenge> | <code_challenge_method> | <redirect_uri> | <state> |
        Then the response status is failed state

        Examples: Auth - Ungültige Parameter Beispiele
            | client_id          | scope           | code_challenge                                                   | code_challenge_method | redirect_uri                       | state       |
            # REM invalid client_id
            | resistanceisfutile | openid e-rezept | 932F3C1B56257CE8539AC269D7AAB42550DACF8818D075F0BDF1990562AAE3EF | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx |
            # REM invalid scope IDP-361
            | eRezeptApp         | weareborg       | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg                      | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx |
            | eRezeptApp         | e-rezept        | 932F3C1B56257CE8539AC269D7AAB42550DACF8818D075F0BDF1990562AAE3EF | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx |
            # REM invalid code_challenge: something definitely not being an S256 hash string (! und .)
            | eRezeptApp         | openid e-rezept | Fest gemauert in der Erde! Steht die Form aus Lehm gebrannt.     | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx |
            # REM unsupported code challenge method
            | eRezeptApp         | openid e-rezept | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg                      | plain                 | http://redirect.gematik.de/erezept | xxxstatexxx |
            # REM invalid code challenge method
            | eRezeptApp         | openid e-rezept | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg                      | axanar                | http://redirect.gematik.de/erezept | xxxstatexxx |
            # REM invalid redirect uri
            | eRezeptApp         | openid e-rezept | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg                      | S256                  | http://www.drinkinggamezone.com/   | xxxstatexxx |
            # REM state could be any value
