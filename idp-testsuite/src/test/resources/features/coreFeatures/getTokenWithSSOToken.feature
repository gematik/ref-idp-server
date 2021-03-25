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
@SsoTokenFlow
Feature: Fordere Access Token mittels SSO Token an
  Frontends von TI Diensten müssen vom IDP Server über ein HTTP POST an den Token Endpoint ein Access/SSO/ID Token abfragen können.

  Background: Initialisiere Testkontext durch Abfrage des Discovery Dokuments
    Given I initialize scenario from discovery document endpoint
    And I retrieve public keys from URIs

  @Afo:A_20950
    @Approval
  Scenario Outline: GetTokenSSO - Gutfall - Validiere Antwortstruktur
  ```
  Wir fordern einen Access Token via SSO an und überprüfen dass die JSON Antwort folgende Felder enthält:

  - den Access Token
  - den ID Token
  - Ablaufzeitraum (expires, 300 Sekunden)
  - Token Typ Bearer


    Given I choose code verifier '${TESTENV.code_verifier01}'
        # code_challenge for given verifier can be obtained from https://tonyxu-io.github.io/pkce-generator/
    And I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state         | nonce  | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx1a | 997755 | code          |
    And I sign the challenge with '<cert>'
    And I request a code token with signed challenge
    And I request an access token
    And I start new interaction keeping only
      | SSO_TOKEN           |
      | SSO_TOKEN_ENCRYPTED |
    And I initialize scenario from discovery document endpoint
    And I retrieve public keys from URIs
    And I choose code verifier '${TESTENV.code_verifier01}'
    And I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state         | nonce  | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx2a | 997744 | code          |
    And I request a code token with sso token
    And I set the context with key REDIRECT_URI to '${TESTENV.redirect_uri}'

    When I request an access token
    Then the response status is 200
    And the JSON response should match
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

  @Afo:A_20731 @Afo:A_20464 @Afo:A_20952 @Afo:A_20313
    @Approval
  Scenario Outline: GetTokenSSO - Gutfall - Validiere Access Token Claims
  ```
  Wir fordern einen Access Token via SSO an und überprüfen dass der Access Token korrekte Header und Body Claims enthält.

    Given I choose code verifier '${TESTENV.code_verifier01}'
        # code_challenge for given verifier can be obtained from https://tonyxu-io.github.io/pkce-generator/
    And I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state         | nonce  | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx1a | 997755 | code          |
    And I sign the challenge with '<cert>'
    And I request a code token with signed challenge
    And I request an access token
    And I start new interaction keeping only
      | SSO_TOKEN           |
      | SSO_TOKEN_ENCRYPTED |
    And I initialize scenario from discovery document endpoint
    And I retrieve public keys from URIs
    And I choose code verifier '${TESTENV.code_verifier01}'
    And I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state         | nonce  | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx2a | 997744 | code          |
    And I request a code token with sso token
    And I set the context with key REDIRECT_URI to '${TESTENV.redirect_uri}'
    And I request an access token

    When I extract the header claims from token ACCESS_TOKEN
    Then the header claims should match in any order
        """
          { alg: "BP256R1",
            kid: "${json-unit.ignore}",
            typ: "at+JWT"
          }
        """
    When I extract the body claims from token ACCESS_TOKEN
    Then the body claims should match in any order
        """
          { acr:              "gematik-ehealth-loa-high",
            amr:              ["mfa", "sc", "pin"],
            aud:              "https://erp.telematik.de/login",
            auth_time:        "[\\d]*",
            azp:              "${TESTENV.client_id}",
            client_id:        "${TESTENV.client_id}",
            exp:              "[\\d]*",
            jti:              "${json-unit.ignore}",
            family_name:      "(.{1,64})",
            given_name:       "(.{1,64})",
            iat:              "[\\d]*",
            idNummer:         "[A-Z][\\d]{9,10}",
            iss:              "${TESTENV.issuer}",
            organizationName: "(.{1,64})",
            professionOID:    "1\\.2\\.276\\.0\\.76\\.4\\.(3\\d|4\\d|178|23[2-90]|240|241)",
            scope:            "${TESTENV.scopes_basisflow_regex}",
            sub:              ".*"
          }
        """
    Examples: GetToken - Zertifikate zur Signatur der Challenge
      | cert                                                 |
      | /certs/valid/80276883110000018680-C_CH_AUT_E256.p12  |
      | /certs/valid/80276883110000018680-C_CH_AUT_R2048.p12 |

  @Afo:A_20313
    @Approval @Ready
  Scenario Outline: GetTokenSSO - Gutfall - Validiere ID Token Claims
  ```
  Wir fordern einen Access Token via SSO an und überprüfen dass der ID Token korrekte Header und Body Claims enthält.

    Given I choose code verifier '${TESTENV.code_verifier01}'
        # code_challenge for given verifier can be obtained from https://tonyxu-io.github.io/pkce-generator/
    And I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state         | nonce  | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx1a | 886655 | code          |
    And I sign the challenge with '<cert>'
    And I request a code token with signed challenge
    And I request an access token
    And I start new interaction keeping only
      | SSO_TOKEN           |
      | SSO_TOKEN_ENCRYPTED |
    And I initialize scenario from discovery document endpoint
    And I retrieve public keys from URIs
    And I choose code verifier '${TESTENV.code_verifier01}'
    And I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state         | nonce  | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx2a | 886644 | code          |
    And I request a code token with sso token
    And I set the context with key REDIRECT_URI to '${TESTENV.redirect_uri}'
    And I request an access token

    When I extract the header claims from token ID_TOKEN
    Then the header claims should match in any order
        """
          { alg: "BP256R1",
            kid: "${json-unit.ignore}",
            typ: "JWT"
          }
        """
    When I extract the body claims from token ID_TOKEN
    Then the body claims should match in any order
        """
          { acr:              "gematik-ehealth-loa-high",
            amr:              ["mfa", "sc", "pin"],
            at_hash:          ".*",
            aud:              "${TESTENV.client_id}",
            auth_time:        "[\\d]*",
            azp:              "${TESTENV.client_id}",
            exp:              "[\\d]*",
            family_name:      "(.{1,64})",
            given_name:       "(.{1,64})",
            iat:              "[\\d]*",
            idNummer:         "[A-Z][\\d]{9,10}",
            iss:              "${TESTENV.issuer}",
            nonce:            "886644",
            organizationName: "(.{1,64})",
            professionOID:    "1\\.2\\.276\\.0\\.76\\.4\\.(3\\d|4\\d|178|23[2-90]|240|241)",
            sub:              ".*",
            jti:              ".*"
          }
        """
    Examples: GetToken - Zertifikate zur Signatur der Challenge
      | cert                                                 |
      | /certs/valid/80276883110000018680-C_CH_AUT_E256.p12  |
      | /certs/valid/80276883110000018680-C_CH_AUT_R2048.p12 |

  @Afo:A_20327
    @Approval @Ready
    @Signature
  Scenario Outline: GetTokenSSO - Gutfall - Validiere Signatur Access Token
  ```
  Wir fordern einen Access Token via SSO an und überprüfen, dass der Access Token mit der puk_idp_sign signiert wurde.

    Given I choose code verifier '${TESTENV.code_verifier01}'
    And I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state         | nonce  | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx1a | 887722 | code          |
    And I sign the challenge with '<cert>'
    And I request a code token with signed challenge
    And I request an access token
    And I start new interaction keeping only
      | SSO_TOKEN           |
      | SSO_TOKEN_ENCRYPTED |
    And I initialize scenario from discovery document endpoint
    And I retrieve public keys from URIs
    And I choose code verifier '${TESTENV.code_verifier01}'
    And I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state         | nonce  | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx2a | 887711 | code          |
    And I request a code token with sso token
    And I set the context with key REDIRECT_URI to '${TESTENV.redirect_uri}'

    When I request an access token
    Then the context ACCESS_TOKEN must be signed with cert PUK_SIGN

    Examples: GetToken - Zertifikate zur Signatur der Challenge
      | cert                                                 |
      | /certs/valid/80276883110000018680-C_CH_AUT_E256.p12  |
      | /certs/valid/80276883110000018680-C_CH_AUT_R2048.p12 |

  @Afo:A_20327
    @Approval @Ready
    @Signature
  Scenario Outline: GetTokenSSO - Gutfall - Validiere Signatur ID Token
  ```
  Wir fordern einen Access Token via SSO an und überprüfen, dass der ID Token mit der puk_idp_sign signiert wurde.

    Given I choose code verifier '${TESTENV.code_verifier01}'
    And I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state         | nonce  | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx1a | 887722 | code          |
    And I sign the challenge with '<cert>'
    And I request a code token with signed challenge
    And I request an access token
    And I start new interaction keeping only
      | SSO_TOKEN           |
      | SSO_TOKEN_ENCRYPTED |
    And I initialize scenario from discovery document endpoint
    And I retrieve public keys from URIs
    And I choose code verifier '${TESTENV.code_verifier01}'
    And I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state         | nonce  | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx2a | 887711 | code          |
    And I request a code token with sso token
    And I set the context with key REDIRECT_URI to '${TESTENV.redirect_uri}'

    When I request an access token
    Then the context ID_TOKEN must be signed with cert PUK_SIGN

    Examples: GetToken - Zertifikate zur Signatur der Challenge
      | cert                                                 |
      | /certs/valid/80276883110000018680-C_CH_AUT_E256.p12  |
      | /certs/valid/80276883110000018680-C_CH_AUT_R2048.p12 |


  @Approval @Ready
  @Timeout
  Scenario: GetTokenSSO - Speichere SSO Token für manuelle Tests
  ```
  Wir fordern einen Access Token via SSO an und speichern den SSO Token im testartefacts Verzeichnis um
  für die nachfolgenden Testfälle aktuellere SSO Tokens nutzen zu können (bzw. wenn sich der Inhalt des
  SSO Tokens ändern sollte).


    Given I choose code verifier '${TESTENV.code_verifier01}'
    And I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state         | nonce  | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx1a | 887722 | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    When I request a code token with signed challenge
    Then I store SSO_TOKEN as text
    And I store SSO_TOKEN_ENCRYPTED as text


  # TODO RISE: da der SSO Token im Verzeichnis von der Referenzimplementierung stammt wird dieser Testfall fehlschlagen
  @Afo:A_20315 @Afo:A_20692
  @Approval
  @OpenBug
  @Timeout
  Scenario: GetTokenSSO - Veralteter SSO Token wird abgelehnt
  ```
  Wir laden einen veralteten SSO Token vom Dateisystem und überprüfen, dass der Server eine Anfrage für einen Access Token ablehnt.


    Given I choose code verifier '${TESTENV.code_verifier01}'
    And I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state         | nonce  | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx2a | 887711 | code          |

    When I load SSO_TOKEN from folder 'old_sso_token'
    And I load SSO_TOKEN_ENCRYPTED from folder 'old_sso_token'
    And I request a code token with sso token
    Then the response is an 400 error with gematik code 2040 and error 'access_denied'

  @Afo:A_20315 @Afo:A_20692
  @Approval
  @Manual
  Scenario: GetTokenSSO - Fast veralteter SSO Token wird akzeptiert
  ```
  Wir fragen einen SSO Token an, speichern diesen und testen, dass wir auch nach 11h59m mit diesem noch immer
  erfolgreich einen weiteren Access Token anfragen können.

