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
Feature: Registrierung für Alternative Authentisierung am IDP Server

  Frontends müssen mit einer eGK einen Access Token für den Zugriff auf die Pairing-Schnittstelle des IDP bekommen.
  Frontends müssen mit einer eGK und einem Access Token Geräte registrieren .
  Frontends müssen mit eGK und vielleicht auch mit alternativer Authentisierung (zu klären) Geräte deregistrieren können.

  Background: Initialisiere Testkontext durch Abfrage des Discovery Dokuments
    Given I initialize scenario from discovery document endpoint
    And I retrieve public keys from URIs

  @Approval
  Scenario: Biometrie Register - GetToken mit signierter Challenge - Gutfall

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
            Content-Type=application/json
            Cache-Control=no-store
            Pragma=no-cache
            """
    And the JSON response should match
            """
              { challenge: "ey[A-Za-z0-9\\\-_\\\.]*",
                user_consent:  [
                  "given_name",
                  "family_name",
                  "organizationName",
                  "professionOID",
                  "idNummer"
                ]
              }
            """

    When I extract the header claims from response field challenge
    Then the header claims should match in any order
            """
              { typ: "JWT",
                alg: "BP256R1",
                exp: "[\\d]*"
              }
            """

    When I extract the body claims from response field challenge
    Then the body claims should match in any order
            """
              { scope:                 "pairing openid",
                iss:                   "https://idp.zentral.idp.splitdns.ti-dienste.de",
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
  Scenario: Biometrie Register - GetToken mit signierter Challenge - Gutfall - Validiere Antwortstruktur

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, signieren diesen und
  fordern einen TOKEN_CODE mit der signierten Challenge an.

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
        Location=http.*code=.*
        """
    And I expect the Context with key STATE to match 'xxxstatexxx'
    And I expect the Context with key SSO_TOKEN to match '.*'

  @Afo:A_20731 @Afo:A_20310 @Afo:A_20464 @Afo:A_20952
  @Todo:CheckAfosReferences
  @Todo:CompareSubjectInfosInAccessTokenAndInCert
  @Todo:audFestlegen
  @Approval
    # TODO: wollen wir noch den Wert der auth_time gegen den Zeitpunkt der Authentifizierung pruefen
  Scenario: Biometrie Register - GetToken mit signierter Challenge - Gutfall - Validiere Access Token Claims
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
            exp: "[\\d]*",
            kid: ".*",
            typ: "at+JWT"
          }
        """

    When I extract the body claims from token ACCESS_TOKEN
    Then the body claims should match in any order
        """
          { acr:              "eidas-loa-high",
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

  @Approval
  @Todo:InhalteDerPairingDataBefüllen
  Scenario: Biometrie Register - Gutfall
    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope          | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce  | response_type |
      | eRezeptApp | pairing openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 887766 | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And I request a code token with signed challenge
    And I set the context with key REDIRECT_URI to 'http://redirect.gematik.de/erezept'
    And I request an access token
    When I create a device information token with
      | device_name | device_manufacturer | device_product | device_model | device_os | device_version |
      | eRezeptApp  | Fair Phone          | FairPhone 3    | F3           | Android   | 1.0.2 f        |
    And I create pairing data with
      | key_data                                           | key_identifier | signature_algorithm_identifier | device_product | cert_id       | issuer  | not_after | public_key                                          |
      | /keys/valid/80276883110000018680-C_CH_AUT_E256.p12 | thisismykey    | ES256                          | FairPhone 3    | grgdgfdgfdhfd | Android | 1.0.2 f   | /certs/valid/80276883110000018680-C_CH_AUT_E256.p12 |
    And I sign pairing data with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    When I register the device with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    Then the response status is 200

