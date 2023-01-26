#
# Copyright (c) 2023 gematik GmbH
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
@FastTrack
@ThirdPartyToken
@RefImplOnly
Feature: Beantrage Token mit dem Auth Code des sektoralen IDPs

  Die eRezept-App holt sich - nach einer Authentisierung beim sektoralen IDP - beim zentralen IDP einen ACCESS_TOKEN für den eRezept-Fachdienst.

  Background: Initialisiere Testkontext durch Abfrage des Discovery Dokuments
    Given IDP I initialize scenario from discovery document endpoint
    And IDP I retrieve public keys from URIs
    And IDP I initialize the sektoral idp endpoints


  @TCID:IDP_THIRD_PARTY_TOKEN_001 @PRIO:1
  @Approval @Ready
  Scenario: ThirdParty - Gutfall - Einreichen des authorization_codes beim Token endpoint, validiere Antwortstruktur

  ```
  Wir authentisieren uns unter Verwendung des sektoralen IDPs beim zentralen IDP (Nachricht 1-12) und reichen den Authorization Code beim Token Endpoint ein (Nachricht 13).
  Anschließen validieren wir die Antwortstruktur.

  Die HTTP Response (Nachricht 17) des zentralen IDP muss:

  - den Access Token
  - den ID Token
  - Ablaufzeitraum (expires, 300 Sekunden)
  - Token Typ Bearer

  enthalten.

    Given IDP I choose code verifier '${TESTENV.code_verifier01}'
    And IDP Frontend sends an authorization request to smartcard idp with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce     | response_type | kk_app_id  |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 123456789 | code          | kkAppId001 |
    And IDP Frontend sends an authorization request to fasttrack sektoral idp with
      | client_id           | scope               | code_challenge      | code_challenge_method | redirect_uri                     | state               | nonce               | response_type       |
      | $FILL_FROM_REDIRECT | $FILL_FROM_REDIRECT | $FILL_FROM_REDIRECT | $FILL_FROM_REDIRECT   | https://kk.dev.gematik.solutions | $FILL_FROM_REDIRECT | $FILL_FROM_REDIRECT | $FILL_FROM_REDIRECT |
    And IDP I request a code token with third party authorization code
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


  @TCID:IDP_THIRD_PARTY_TOKEN_002 @PRIO:1
  @Approval @Ready
  Scenario: ThirdParty - Gutfall - Einreichen des authorization_codes beim Token endpoint, ohne optinale nonce

  ```
  Wir authentisieren uns unter Verwendung des sektoralen IDPs beim zentralen IDP (Nachricht 1-12) und reichen den Authorization Code beim Token Endpoint ein (Nachricht 13).
  Im ersten Request (Nachricht 1) wird die optionale nonce nicht gesendet.

  Die HTTP Response (Nachricht 17) des zentralen IDP muss:

  - den Access Token
  - den ID Token
  - Ablaufzeitraum (expires, 300 Sekunden)
  - Token Typ Bearer

  enthalten.

    Given IDP I choose code verifier '${TESTENV.code_verifier01}'
    And IDP Frontend sends an authorization request to smartcard idp with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | response_type | kk_app_id  |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | code          | kkAppId001 |
    And IDP Frontend sends an authorization request to fasttrack sektoral idp with
      | client_id           | scope               | code_challenge      | code_challenge_method | redirect_uri                     | state               | nonce               | response_type       |
      | $FILL_FROM_REDIRECT | $FILL_FROM_REDIRECT | $FILL_FROM_REDIRECT | $FILL_FROM_REDIRECT   | https://kk.dev.gematik.solutions | $FILL_FROM_REDIRECT | $FILL_FROM_REDIRECT | $FILL_FROM_REDIRECT |
    And IDP I request a code token with third party authorization code
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


  @TCID:IDP_THIRD_PARTY_TOKEN_003 @PRIO:1
  @Approval @Ready
  Scenario: ThirdParty - Gutfall - Einreichen des ssotoken beim Token endpoint
  ```
  Wir fordern einen Access Token via SSO an und überprüfen dass die JSON Antwort folgende Felder enthält:

  - den Access Token
  - den ID Token
  - Ablaufzeitraum (expires, 300 Sekunden)
  - Token Typ Bearer

    Given IDP I choose code verifier '${TESTENV.code_verifier01}'
    And IDP Frontend sends an authorization request to smartcard idp with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce     | response_type | kk_app_id  |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 123456789 | code          | kkAppId001 |
    And IDP Frontend sends an authorization request to fasttrack sektoral idp with
      | client_id           | scope               | code_challenge      | code_challenge_method | redirect_uri                     | state               | nonce               | response_type       |
      | $FILL_FROM_REDIRECT | $FILL_FROM_REDIRECT | $FILL_FROM_REDIRECT | $FILL_FROM_REDIRECT   | https://kk.dev.gematik.solutions | $FILL_FROM_REDIRECT | $FILL_FROM_REDIRECT | $FILL_FROM_REDIRECT |
    And IDP I request a code token with third party authorization code
    And IDP I set the context with key REDIRECT_URI to '${TESTENV.redirect_uri}'
    When IDP I request an access token
    And IDP I start new interaction keeping only
      | SSO_TOKEN_ENCRYPTED |
    And IDP I initialize scenario from discovery document endpoint
    And IDP I retrieve public keys from URIs
    And IDP I choose code verifier '${TESTENV.code_verifier01}'
    And IDP I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state         | nonce  | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx2a | 997744 | code          |


    And IDP I request a code token with sso token successfully
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
