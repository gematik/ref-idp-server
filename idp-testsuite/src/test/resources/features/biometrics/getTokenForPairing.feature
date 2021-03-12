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
@biometrics
Feature: Fordere Access Token für Pairing an
  Frontends müssen mit einer eGK einen pairing Access/SSO/ID Token für den Zugriff auf die Pairing-Schnittstelle des IDP bekommen.

  Background: Initialisiere Testkontext durch Abfrage des Discovery Dokuments
    Given I initialize scenario from discovery document endpoint
    And I retrieve public keys from URIs

  @Approval
  Scenario: Biometrie Auth - Gutfall - Fordere Challenge für Pairing an

  ```
  Wir wählen einen gültigen Code verifier und fordern einen Challenge Token an. Der Scope ist pairing für den Zugriff
  auf den Pairing Endpunkt

  Die HTTP Response muss:

  - den Code 200
  - die richtigen HTTP Header
  - das korrekte JSON im Body und
  - die richtigen Claims im Token haben.

    Given I choose code verifier 'zdrfcvz3iw47fgderuzbq834werb3q84wgrb3zercb8q3wbd834wefb348ch3rq9e8fd9sac'
        # REM code_challenge for given verifier can be obtained from https://tonyxu-io.github.io/pkce-generator/
    When I request a challenge with
      | client_id  | scope          | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce     | response_type |
      | eRezeptApp | pairing openid | P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 123456789 | code          |
    Then the response status is 200
    And the response http headers match
            """
            Content-Type=application/json.*
            Cache-Control=no-store
            Pragma=no-cache
            """
    And the JSON response should match
            """
              { challenge: "ey[A-Za-z0-9\\-_\\.]*",
                user_consent:  {
                  requested_claims: {
                    idNummer: ".*Id.*Krankenversichertennummer.*Telematik\\-Id.*"
                  },
                  requested_scopes: {
                    pairing: ".*biometrische.*Authentisierung.*",
                    openid:  ".*ID\\-Token.*"
                  }
                }
              }
            """
    When I extract the header claims from response field challenge
    Then the header claims should match in any order
            """
              { typ: "JWT",
                alg: "BP256R1",
                exp: "[\\d]*",
                kid: "${json-unit.ignore}"
              }
            """
    When I extract the body claims from response field challenge
    Then the body claims should match in any order
            """
              { scope:                 "pairing openid",
                iss:                   "https:\\/\\/idp.*\\.zentral\\.idp\\.splitdns\\.ti\\-dienste\\.de",
                response_type:         "code",
                code_challenge_method: "S256",
                redirect_uri:          "http://redirect.gematik.de/erezept",
                state:                 "xxxstatexxx",
                client_id:             "eRezeptApp",
                code_challenge:        "P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk",
                exp:                   "[\\d]*",
                jti:                   "${json-unit.ignore}",
                iat:                   "[\\d]*",
                token_type:            "challenge",
                nonce:                 "123456789",
                snc:                   "${json-unit.ignore}"
              }
            """

  @Afo:A_20699 @Afo:A_20951 @Afo:A_20460 @Afo:A_20699
  @Todo:CheckAfos
  @Approval
  Scenario: Biometrie Author mit signierter Challenge - Gutfall - Validiere Antwortstruktur

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token für den Pairing Endpunkt an,
  signieren diesen und fordern einen TOKEN_CODE mit der signierten Challenge an.

  Die TOKEN_CODE Antwort muss den Code 302 und die richtigen HTTP Header haben.

    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope          | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce | response_type |
      | eRezeptApp | pairing openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 12345 | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'

    When I request a code token with signed challenge
    Then the response status is 302
    And the response http headers match
        """
        Cache-Control=no-store
        Pragma=no-cache
        Content-Length=0

        Location=http://redirect.gematik.de/erezept/token[?]code=.*
        """
    And I expect the Context with key STATE to match 'xxxstatexxx'
    And I expect the Context with key SSO_TOKEN to match '.*'

  @Afo:A_20731 @Afo:A_20310 @Afo:A_20464 @Afo:A_20952
  @Todo:CheckAfosReferences
  @Todo:CompareSubjectInfosInAccessTokenAndInCert
  @Todo:audFestlegen
  @Approval
    # TODO: wollen wir noch den Wert der auth_time gegen den Zeitpunkt der Authentifizierung pruefen
  Scenario: Biometrie GetToken mit signierter Challenge - Gutfall - Validiere Access Token Claims
    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope          | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce  | response_type |
      | eRezeptApp | pairing openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 887766 | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And I request a code token with signed challenge
    And I set the context with key REDIRECT_URI to 'http://redirect.gematik.de/erezept'
    And I request an access token

    When I extract the header claims from token ACCESS_TOKEN
    Then the header claims should match in any order
        """
          { alg: "BP256R1",
            kid: ".*",
            typ: "at+JWT"
          }
        """
    When I extract the body claims from token ACCESS_TOKEN
    Then the body claims should match in any order
        """
          { acr:              "gematik-ehealth-loa-high",
            amr:              '["mfa", "sc", "pin"]',
            aud:              "https://.*",
            auth_time:        "[\\d]*",
            azp:              "eRezeptApp",
            client_id:        "eRezeptApp",
            exp:              "[\\d]*",
            jti:              "${json-unit.ignore}",
            iat:              "[\\d]*",
            idNummer:         "[A-Z][\\d]{9,10}",
            professionOID:    ".*",
            organizationName: ".*",
            given_name:       ".*",
            family_name:      ".*",
            iss:              "http.*",
            scope:            "(openid pairing|pairing openid)",
            sub:              ".*"
          }
        """

  @Afo:A_20699 @Afo:A_20951 @Afo:A_20460 @Afo:A_20699
  @Todo:CheckAfos
  @Approval
  Scenario: Biometrie Author mit SSO Token - Gutfall - Validiere Antwortstruktur

  ```
  Wir fordern einen SSO Token für Pairing an, löschen alle anderen Kontextdaten.
  Dann wählen wir einen gültigen Code verifier, fordern einen Challenge Token für den Pairing Endpunkt an,
  signieren diesen und fordern einen TOKEN_CODE mit dem SSO Token an.

  Die TOKEN_CODE Antwort muss den Code 302 und die richtigen HTTP Header haben.

    Given I choose code verifier 'sfnejkgsjknsfeknsknvgsrlgmreklgmnksrnvgjksnvgseklgvsrklmslrkbmsrklgnrvsgklsrgnksrf'
    And I request a challenge with
      | client_id  | scope          | code_challenge                              | code_challenge_method | redirect_uri                       | state        | nonce  | response_type |
      | eRezeptApp | pairing openid | ds7JaEfpdLidWekR52OhoVpjXHDlplLyV3GtUezxfY0 | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx1 | 123456 | code          |
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
      | client_id  | scope          | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce | response_type |
      | eRezeptApp | pairing openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 12345 | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'

    When I request a code token with sso token
    Then the response status is 302
    And the response http headers match
        """
        Cache-Control=no-store
        Pragma=no-cache
        Content-Length=0
        Location=http://redirect.gematik.de/erezept/token[?]code=.*
        """
    And I expect the Context with key STATE to match 'xxxstatexxx'
    And I expect the Context with key SSO_TOKEN to match '$NULL'

  @Afo:A_20731 @Afo:A_20310 @Afo:A_20464 @Afo:A_20952
  @Todo:CheckAfosReferences
  @Todo:CompareSubjectInfosInAccessTokenAndInCert
  @Todo:audFestlegen
  @Approval
    # TODO: wollen wir noch den Wert der auth_time gegen den Zeitpunkt der Authentifizierung pruefen
  Scenario: Biometrie GetToken mit SSO Token - Gutfall - Validiere Access Token Claims


    Given I choose code verifier 'sfnejkgsjknsfeknsknvgsrlgmreklgmnksrnvgjksnvgseklgvsrklmslrkbmsrklgnrvsgklsrgnksrf'
    And I request a challenge with
      | client_id  | scope          | code_challenge                              | code_challenge_method | redirect_uri                       | state        | nonce  | response_type |
      | eRezeptApp | pairing openid | ds7JaEfpdLidWekR52OhoVpjXHDlplLyV3GtUezxfY0 | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx1 | 123456 | code          |
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
      | client_id  | scope          | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce  | response_type |
      | eRezeptApp | pairing openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 887766 | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And I request a code token with sso token
    And I set the context with key REDIRECT_URI to 'http://redirect.gematik.de/erezept'
    And I request an access token

    When I extract the header claims from token ACCESS_TOKEN
    Then the header claims should match in any order
        """
          { alg: "BP256R1",
            kid: ".*",
            typ: "at+JWT"
          }
        """
    When I extract the body claims from token ACCESS_TOKEN
    Then the body claims should match in any order
        """
          { acr:              "gematik-ehealth-loa-high",
            amr:              '["mfa", "sc", "pin"]',
            aud:              "https://.*",
            auth_time:        "[\\d]*",
            azp:              "eRezeptApp",
            client_id:        "eRezeptApp",
            exp:              "[\\d]*",
            jti:              "${json-unit.ignore}",
            iat:              "[\\d]*",
            idNummer:         "[A-Z][\\d]{9,10}",
            professionOID:    ".*",
            organizationName: ".*",
            given_name:       ".*",
            family_name:      ".*",
            iss:              "http.*",
            scope:            "(openid pairing|pairing openid)",
            sub:              ".*"
          }
        """

  Scenario: Biometrie Auth - Null/Remove/Ungültige Werte?
  ```
  Analog zu den Auth tests im Basic flow muss der Server diese Anfragen für den scope pairing mit einer Fehlermeldung ablehnen.


    #egk, signed_pairing_data etc passt alles. aber der client hat sich einen access token für den pairing endpoint mit seiner alternativen auth erstellen lassen
    #todo: klaeren, ob das schon beim ausstellen des access token abgelehnt werden muss oder erst an dieser stelle? -> vermutlich schon beim token endpunkt
  Scenario: Biometrie Register - Zugriff mit ACCESS_TOKEN mit falschem amr


      # TODO Zert ohne idnummer sollte schon beim access_token abgelehnt werden
