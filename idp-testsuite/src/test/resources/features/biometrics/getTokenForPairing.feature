#
# Copyright (Date see Readme), gematik GmbH
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
# *******
#
# For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
#

@PRODUKT:IDP-D
@Biometrics
Feature: Fordere Access Token für Pairing an
  Frontends müssen mit einer eGK einen pairing Access/SSO/ID Token für den Zugriff auf die Pairing-Schnittstelle des IDP bekommen.

  Background: Initialisiere Testkontext durch Abfrage des Discovery Dokuments
    Given IDP I initialize scenario from discovery document endpoint
    And IDP I retrieve public keys from URIs

  @Approval
  @AFO-ID:A_20698
  @TCID:IDP_REF_BIOTOKEN_001 @PRIO:1
  @TESTSTUFE:4
  Scenario: Biometrie Auth - Gutfall - Fordere Challenge für Pairing an

  ```
  Wir wählen einen gültigen Code verifier und fordern einen Challenge Token an. Der Scope ist pairing für den Zugriff
  auf den Pairing Endpunkt

  Die HTTP Response muss:

  - den Code 200
  - die richtigen HTTP Header
  - das korrekte JSON im Body und
  - die richtigen Claims im Token haben.

    Given IDP I choose code verifier 'zdrfcvz3iw47fgderuzbq834werb3q84wgrb3zercb8q3wbd834wefb348ch3rq9e8fd9sac'
        # REM code_challenge for given verifier can be obtained from https://tonyxu-io.github.io/pkce-generator/
    When IDP I request a challenge with
      | client_id            | scope          | code_challenge                              | code_challenge_method | redirect_uri            | state       | nonce     | response_type |
      | ${TESTENV.client_id} | pairing openid | P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 123456789 | code          |
    Then the response status is 200
    And IDP the response http headers match
            """
            Content-Type=application/json.*
            Cache-Control=no-store
            Pragma=no-cache
            """
    And IDP the JSON response should match
            """
              { challenge: "ey[A-Za-z0-9\\-_\\.]*",
                user_consent:  {
                  requested_claims: {
                    idNummer: ".*Id.*Krankenversichertennummer.*Telematik\\-Id.*"
                  },
                  requested_scopes: {
                    pairing: "(.*biometrische.*Authentisierung.*)|(.*Pairing-Fachdienst.*)",
                    openid:  ".*ID\\-Token.*"
                  }
                }
              }
            """
    When IDP I extract the header claims from response field challenge
    Then IDP the header claims should match in any order
            """
              { typ: "JWT",
                alg: "BP256R1",
                kid: "${json-unit.ignore}"
              }
            """
    When IDP I extract the body claims from response field challenge
    Then IDP the body claims should match in any order
            """
              { scope:                 "pairing openid",
                iss:                   "${TESTENV.issuer}",
                response_type:         "code",
                code_challenge_method: "S256",
                redirect_uri:          "${TESTENV.redirect_uri}",
                state:                 "xxxstatexxx",
                client_id:             "${TESTENV.client_id}",
                code_challenge:        "P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk",
                exp:                   "[\\d]*",
                jti:                   "${json-unit.ignore}",
                iat:                   "[\\d]*",
                token_type:            "challenge",
                nonce:                 "123456789",
                snc:                   "${json-unit.ignore}"
              }
            """

  @AFO-ID:A_20699-03 @AFO-ID:A_20951-01
  @Approval
  @TCID:IDP_REF_BIOTOKEN_002 @PRIO:1
  @TESTSTUFE:4
  Scenario: Biometrie Author mit signierter Challenge - Gutfall - Validiere Antwortstruktur

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token für den Pairing Endpunkt an,
  signieren diesen und fordern einen TOKEN_CODE mit der signierten Challenge an.

  Die TOKEN_CODE Antwort muss den Code 302 und die richtigen HTTP Header haben.

    Given IDP I choose code verifier '${TESTENV.code_verifier01}'
    And IDP I request a challenge with
      | client_id            | scope          | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce | response_type |
      | ${TESTENV.client_id} | pairing openid | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 12345 | code          |
    And IDP I sign the challenge with '/certs/valid/80276883110000161754-C_CH_AUT_E256.p12'

    When IDP I request a code token with signed challenge
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

  @AFO-ID:A_20731 @AFO-ID:A_20464 @AFO-ID:A_20952 @AFO-ID:A_21410
  @Approval
  @TCID:IDP_REF_BIOTOKEN_003 @PRIO:1
  @TESTSTUFE:4
  Scenario: Biometrie GetToken mit signierter Challenge - Gutfall - Validiere Access Token Claims
    Given IDP I choose code verifier '${TESTENV.code_verifier01}'
    And IDP I request a challenge with
      | client_id            | scope          | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce  | response_type |
      | ${TESTENV.client_id} | pairing openid | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 887766 | code          |
    And IDP I sign the challenge with '/certs/valid/80276883110000161754-C_CH_AUT_E256.p12'
    And IDP I request a code token with signed challenge successfully
    And IDP I set the context with key REDIRECT_URI to '${TESTENV.redirect_uri}'
    And IDP I request an access token

    When IDP I extract the header claims from token ACCESS_TOKEN
    Then IDP the header claims should match in any order
        """
          { alg: "BP256R1",
            kid: ".*",
            typ: "at+JWT"
          }
        """
    When IDP I extract the body claims from token ACCESS_TOKEN
    Then IDP the body claims should match in any order
        """
          { acr:              "gematik-ehealth-loa-high",
            amr:              ["mfa", "sc", "pin"],
            aud:              "${TESTENV.aud.pairing}",
            auth_time:        "[\\d]*",
            azp:              "${TESTENV.client_id}",
            client_id:        "${TESTENV.client_id}",
            exp:              "[\\d]*",
            jti:              "${json-unit.ignore}",
            iat:              "[\\d]*",
            idNummer:         "X110675903",
            iss:              "${TESTENV.issuer}",
            scope:            "(openid pairing|pairing openid)",
            sub:              ".*"
          }
        """

  @AFO-ID:A_20699-03 @AFO-ID:A_20951-01
  @Approval
  @TCID:IDP_REF_BIOTOKEN_004 @PRIO:1
  @TESTSTUFE:4
  Scenario: Biometrie Author mit SSO Token - Gutfall - Validiere Antwortstruktur

  ```
  Wir fordern einen SSO Token für Pairing an, löschen alle anderen Kontextdaten.
  Dann wählen wir einen gültigen Code verifier, fordern einen Challenge Token für den Pairing Endpunkt an,
  signieren diesen und fordern einen TOKEN_CODE mit dem SSO Token an.

  Die TOKEN_CODE Antwort muss den Code 302 und die richtigen HTTP Header haben.

    Given IDP I choose code verifier '${TESTENV.code_verifier02}'
    And IDP I request a challenge with
      | client_id            | scope          | code_challenge              | code_challenge_method | redirect_uri            | state        | nonce  | response_type |
      | ${TESTENV.client_id} | pairing openid | ${TESTENV.code_challenge02} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx1 | 123456 | code          |
    And IDP I sign the challenge with '/certs/valid/80276883110000161754-C_CH_AUT_E256.p12'
    And IDP I request a code token with signed challenge successfully
    And IDP I start new interaction keeping only
      | SSO_TOKEN_ENCRYPTED |
    And IDP I initialize scenario from discovery document endpoint
    And IDP I retrieve public keys from URIs
    And IDP I choose code verifier '${TESTENV.code_verifier01}'
    And IDP I request a challenge with
      | client_id            | scope          | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce | response_type |
      | ${TESTENV.client_id} | pairing openid | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 12345 | code          |
    And IDP I sign the challenge with '/certs/valid/80276883110000161754-C_CH_AUT_E256.p12'

    When IDP I request a code token with sso token
    Then the response status is 302
    And IDP the response http headers match
        """
        Cache-Control=no-store
        Pragma=no-cache
        Content-Length=0
        Location=${TESTENV.redirect_uri_regex}[?|&]code=.*
        """
    And IDP I expect the Context with key STATE to match 'xxxstatexxx'
    And IDP I expect the Context with key SSO_TOKEN to match '$NULL'

  @AFO-ID:A_20731 @AFO-ID:A_20464 @AFO-ID:A_20952
  @Approval
  @TCID:IDP_REF_BIOTOKEN_005 @PRIO:1
  @TESTSTUFE:4
  Scenario: Biometrie GetToken mit SSO Token - Gutfall - Validiere Access Token Claims


    Given IDP I choose code verifier '${TESTENV.code_verifier02}'
    And IDP I request a challenge with
      | client_id            | scope          | code_challenge              | code_challenge_method | redirect_uri            | state        | nonce  | response_type |
      | ${TESTENV.client_id} | pairing openid | ${TESTENV.code_challenge02} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx1 | 123456 | code          |
    And IDP I sign the challenge with '/certs/valid/80276883110000161754-C_CH_AUT_E256.p12'
    And IDP I request a code token with signed challenge successfully
    And IDP I start new interaction keeping only
      | SSO_TOKEN_ENCRYPTED |
    And IDP I initialize scenario from discovery document endpoint
    And IDP I retrieve public keys from URIs
    And IDP I choose code verifier '${TESTENV.code_verifier01}'
    And IDP I request a challenge with
      | client_id            | scope          | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce  | response_type |
      | ${TESTENV.client_id} | pairing openid | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 887766 | code          |
    And IDP I sign the challenge with '/certs/valid/80276883110000161754-C_CH_AUT_E256.p12'
    And IDP I request a code token with sso token successfully
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
            kid: ".*",
            typ: "at+JWT"
          }
        """
    When IDP I extract the body claims from token ACCESS_TOKEN
    Then IDP the body claims should match in any order
        """
          { acr:              "gematik-ehealth-loa-high",
            amr:              ["mfa", "sc", "pin"],
            aud:              "${TESTENV.aud.pairing}",
            auth_time:        "[\\d]*",
            azp:              "${TESTENV.client_id}",
            client_id:        "${TESTENV.client_id}",
            exp:              "[\\d]*",
            jti:              "${json-unit.ignore}",
            iat:              "[\\d]*",
            idNummer:         "X110675903",
            iss:              "${TESTENV.issuer}",
            scope:            "(openid pairing|pairing openid)",
            sub:              ".*"
          }
        """


  @WIP
  Scenario: Biometrie Register - Zugriff mit ACCESS_TOKEN mit falschem amr
    #egk, signed_pairing_data etc passt alles. aber der client hat sich einen access token für den pairing endpoint mit seiner alternativen auth erstellen lassen
  # das thema wird in IDP-655 aufgenommen. falls es hier einen Testfall gibt, dann kommt der nach registration.feature
