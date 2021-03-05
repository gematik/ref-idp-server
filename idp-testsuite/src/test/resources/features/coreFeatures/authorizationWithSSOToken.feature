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
Feature: Autorisiere Anwendung am IDP Server mittels SSO Token
  Frontends von TI Diensten müssen vom IDP Server über ein HTTP POST an den Authorization Endpoint ein Code Token abfragen können.

  Background: Initialisiere Testkontext durch Abfrage des Discovery Dokuments
    Given I initialize scenario from discovery document endpoint
    And I retrieve public keys from URIs

  @Afo:A_20946 @Afo:A_20950
  @Approval @Todo:ClarifyTokenCodeContentRelevant
  Scenario: Author mit SSO Token - Gutfall - Validiere Antwortstruktur

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, signieren diesen und
  fordern einen TOKEN_CODE mit der signierten Challenge an.
  Dann löschen wir den Context mit Ausnahme des erhaltenen SSO Tokens und wiederholen die Schritte nur fordern wir nun
  einen TOKEN_CODE mit dem SSO Token an.

  Die TOKEN_CODE Antwort muss den Code 302 die richtigen HTTP Header haben.
  - im Location header state, code aber NICHT SSO Token als Query Parameter enthalten
  - die richtigen Claims im Token haben.


    Given I choose code verifier 'sfnejkgsjknsfeknsknvgsrlgmreklgmnksrnvgjksnvgseklgvsrklmslrkbmsrklgnrvsgklsrgnksrf'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state        | nonce  | response_type |
      | eRezeptApp | e-rezept openid | ds7JaEfpdLidWekR52OhoVpjXHDlplLyV3GtUezxfY0 | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx1 | 123456 | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And I request a code token with signed challenge
    And the response status is 302
    And I start new interaction keeping only
      | SSO_TOKEN           |
      | SSO_TOKEN_ENCRYPTED |
    And I initialize scenario from discovery document endpoint
    And I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state        | nonce  | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx2 | 234567 | code          |

   # When I extract the header claims from token SSO_TOKEN_ENCRYPTED
   # Then the header claims should match in any order
   #     """
   #       {
   #         cty: "JWT",
   #         exp: "[\\d]*",
   #         enc: "A256GCM",
   #         alg: "dir"
   #       }
   #     """

    When I request a code token with sso token
    Then the response status is 302
    And the response http headers match
        """
        Cache-Control=no-store
        Pragma=no-cache
        Content-Length=0
        Location=http://redirect.gematik.de/erezept/token[?]code=.*
        """
    And I expect the Context with key SSO_TOKEN to match '$NULL'
    And I expect the Context with key STATE to match 'xxxstatexxx2'

  @Afo:A_20946 @Afo:A_20950 @Afo:A_20377
  @Approval @Todo:ClarifyTokenCodeContentRelevant
  Scenario: Author mit SSO Token - Gutfall - Validiere Location Header und Code Token Claims

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, signieren diesen und
  fordern einen TOKEN_CODE mit der signierten Challenge an.
  Dann löschen wir den Context mit Ausnahme des erhaltenen SSO Tokens und wiederholen die Schritte nur fordern wir nun
  einen TOKEN_CODE mit dem SSO Token an.

  Die TOKEN_CODE Antwort muss im Location header state, code aber NICHT SSO Token als Query Parameter enthalten und
  die richtigen Claims im Token haben.


    Given I choose code verifier 'sfnejkgsjknsfeknsknvgsrlgmreklgmnksrnvgjksnvgseklgvsrklmslrkbmsrklgnrvsgklsrgnksrf'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state        | nonce  | response_type |
      | eRezeptApp | e-rezept openid | ds7JaEfpdLidWekR52OhoVpjXHDlplLyV3GtUezxfY0 | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx1 | 123456 | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And I request a code token with signed challenge
    And the response status is 302
    And I start new interaction keeping only
      | SSO_TOKEN           |
      | SSO_TOKEN_ENCRYPTED |
    And I initialize scenario from discovery document endpoint
    And I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state        | nonce  | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx2 | 234567 | code          |
    And I request a code token with sso token

    When I extract the header claims from token TOKEN_CODE
    Then the header claims should match in any order
        """
          { alg: "BP256R1",
            exp: "[\\d]*",
            kid: "${json-unit.ignore}",
            typ: "JWT"
          }
        """
    When I extract the body claims from token TOKEN_CODE
    Then the body claims should match in any order
        """
          { auth_time:             "${json-unit.ignore}",
            client_id:             "eRezeptApp",
            code_challenge:        "Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg",
            code_challenge_method: "S256",
            exp:                   "[\\d]*",
            jti:                   "${json-unit.ignore}",
            idNummer:              "[A-Z][\\d]{9,10}",
            iss:                   "https://idp.zentral.idp.splitdns.ti-dienste.de",
            family_name:           "(.{1,64})",
            given_name:            "(.{1,64})",
            nonce:                 "234567",
            organizationName:      "(.{1,64})",
            professionOID:         "1\\.2\\.276\\.0\\.76\\.4\\.(3\\d|4\\d|178|23[2-90]|240|241)",
            redirect_uri:          "http://redirect.gematik.de/erezept",
            response_type:         "code",
            scope:                 "(e-rezept openid|openid e-rezept)",
            snc:                   ".*",
            state:                 "xxxstatexxx2",
            token_type:            "code"
          }
        """
    # TODO Inhalt ist laut Spec nicht vorgegeben, daher evt. nur für Referenzimplementierung relevant


  @Afo:A_20624 @Afo:A_20319
  @Approval @Ready
  @Signature
  Scenario: Author mit SSO Token - Validiere Signatur des Code Token

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, signieren diesen und
  fordern einen TOKEN_CODE mit der signierten Challenge an.
  Dann löschen wir den Context mit Ausnahme des erhaltenen SSO Tokens und wiederholen die Schritte nur fordern wir nun
  einen TOKEN_CODE mit dem SSO Token an.

  Der Code Token muss mit dem Auth Zertifikat gültig signiert sein.


    Given I choose code verifier 'sfnejkgsjknsfeknsknvgsrlgmreklgmnksrnvgjksnvgseklgvsrklmslrkbmsrklgnrvsgklsrgnksrf'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state        | nonce | response_type |
      | eRezeptApp | e-rezept openid | ds7JaEfpdLidWekR52OhoVpjXHDlplLyV3GtUezxfY0 | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx1 | 4444  | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And I request a code token with signed challenge
    And the response status is 302
    And I start new interaction keeping only
      | SSO_TOKEN           |
      | SSO_TOKEN_ENCRYPTED |
    And I initialize scenario from discovery document endpoint
    And I retrieve public keys from URIs
    And I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state        | nonce | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx2 | 3434  | code          |

    When I request a code token with sso token
    Then the context TOKEN_CODE must be signed with cert PUK_SIGN


  @Approval @Ready
  @Timeout
  @LongRunning
  Scenario: Author mit SSO Token - Veralteter Challenge Token wird abgelehnt

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, signieren diesen und
  fordern einen TOKEN_CODE mit der signierten Challenge an.
  Dann löschen wir den Context mit Ausnahme des erhaltenen SSO Tokens und wiederholen die Schritte, warten 3min
  und fordern dann erst einen TOKEN_CODE mit dem SSO Token an.

  Der Server muss diese Anfrage mit einem Timeout Fehler ablehnen.

    Given I choose code verifier 'sfnejkgsjknsfeknsknvgsrlgmreklgmnksrnvgjksnvgseklgvsrklmslrkbmsrklgnrvsgklsrgnksrf'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state        | nonce | response_type |
      | eRezeptApp | e-rezept openid | ds7JaEfpdLidWekR52OhoVpjXHDlplLyV3GtUezxfY0 | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx1 | 4444  | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And I request a code token with signed challenge
    And the response status is 302
    And I start new interaction keeping only
      | SSO_TOKEN           |
      | SSO_TOKEN_ENCRYPTED |
    And I initialize scenario from discovery document endpoint
    And I retrieve public keys from URIs
    And I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state        | nonce | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx2 | 3434  | code          |

    When I wait PT3M5S
    And I request a code token with sso token
    Then the response is an 302 error with gematik code 2040 and error 'access_denied'

    # ------------------------------------------------------------------------------------------------------------------
    #
    # negative cases

  @Approval @Ready
  Scenario: Author mit SSO Token - Challenge Token fehlt beim SSO Token Aufruf

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, signieren diesen und
  fordern einen TOKEN_CODE mit der signierten Challenge an.
  Dann löschen wir den Context mit Ausnahme des erhaltenen SSO Tokens und wiederholen die Schritte nur fordern wir nun
  einen TOKEN_CODE mit dem SSO Token an, ohne den Challenge Token als Parameter mitzugeben.

  Der Server muss diese Anfrage mit HTTP Status 302 und einer Fehlermeldung im Location Header ablehnen.


    Given I choose code verifier 'sfnejkgsjknsfeknsknvgsrlgmreklgmnksrnvgjksnvgseklgvsrklmslrkbmsrklgnrvsgklsrgnksrf'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state        | nonce  | response_type |
      | eRezeptApp | e-rezept openid | ds7JaEfpdLidWekR52OhoVpjXHDlplLyV3GtUezxfY0 | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx1 | 131313 | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And I request a code token with signed challenge
    And the response status is 302
    And I start new interaction keeping only
      | SSO_TOKEN           |
      | SSO_TOKEN_ENCRYPTED |
    And I initialize scenario from discovery document endpoint
    And I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state        | nonce  | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx2 | 242424 | code          |

    When I request a code token with sso token no challenge
    Then the response is an 302 error with gematik code 2030 and error 'invalid_request'


  @Afo:A_20948
  @WiP
  Scenario: Author mit SSO Token - Anfrage mit modifiziertem SSO Token

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, signieren diesen und
  fordern einen TOKEN_CODE mit der signierten Challenge an.
  Dann löschen wir den Context mit Ausnahme des erhaltenen SSO Tokens, modifizieren diesen und wiederholen die
  Schritte nur fordern wir nun einen TOKEN_CODE mit dem modifizierten SSO Token an.

  Die Server muss diese Anfrage mit HTTP Status 302 und einer Fehlermeldung im Location Header ablehnen.


    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 9999  | code          |
        # TODO first perform with signed challenge then modify sso token then retry with modified sso token
        # TODO how to modify the sso token to ensure that the idp checks the signature correctly

    When I request a code token with sso token
    Then the response is an 302 error with gematik code 9999 and error 'TODO'
