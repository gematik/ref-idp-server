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
@Ss0TokenFlow
Feature: Fordere Access Token mittels SSO Token an
  Frontends von TI Diensten müssen vom IDP Server über ein HTTP POST an den Token Endpoint ein Access/SSO/ID Token abfragen können.

  Background: Initialisiere Testkontext durch Abfrage des Discovery Dokuments
    Given I initialize scenario from discovery document endpoint
    And I retrieve public keys from URIs

  @Afo:A_20950-01
  @Approval @Todo:AccessTokenContent
  Scenario: GetToken mit SSO Token - Gutfall - Check Access Token - Validiere Antwortstruktur
    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
        # code_challenge for given verifier can be obtained from https://tonyxu-io.github.io/pkce-generator/
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state         | nonce  | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx1a | 997755 | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And I request a code token with signed challenge
    And I request an access token
    And I start new interaction keeping only
      | SSO_TOKEN           |
      | SSO_TOKEN_ENCRYPTED |
    And I initialize scenario from discovery document endpoint
    And I retrieve public keys from URIs
    And I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state         | nonce  | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx2a | 997744 | code          |
    And I request a code token with sso token
    And I set the context with key REDIRECT_URI to 'http://redirect.gematik.de/erezept'

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

  @Afo:A_20731 @Afo:A_20310 @Afo:A_20464 @Afo:A_20952
  @Approval @Todo:AccessTokenContent
  @Todo:CompareSubjectInfosInAccessTokenAndInCert
  # TODO: wollen wir noch den Wert der auth_time gegen den Zeitpunkt der Authentifizierung pruefen
  Scenario: GetToken mit SSO Token - Gutfall - Check Access Token - Validiere Access Token Claims
    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
        # code_challenge for given verifier can be obtained from https://tonyxu-io.github.io/pkce-generator/
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state         | nonce  | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx1a | 997755 | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And I request a code token with signed challenge
    And I request an access token
    And I start new interaction keeping only
      | SSO_TOKEN           |
      | SSO_TOKEN_ENCRYPTED |
    And I initialize scenario from discovery document endpoint
    And I retrieve public keys from URIs
    And I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state         | nonce  | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx2a | 997744 | code          |
    And I request a code token with sso token
    And I set the context with key REDIRECT_URI to 'http://redirect.gematik.de/erezept'
    And I request an access token

    When I extract the header claims from token ACCESS_TOKEN
    Then the header claims should match in any order
        """
          { alg: "BP256R1",
            exp: "[\\d]*",
            kid: "${json-unit.ignore}",
            typ: "at+JWT"
          }
        """
    When I extract the body claims from token ACCESS_TOKEN
    Then the body claims should match in any order
        """
          { acr:              "gematik-ehealth-loa-high",
            amr:              "[\"mfa\", \"sc\", \"pin\"]",
            aud:              "https://erp.telematik.de/login",
            auth_time:        "[\\d]*",
            azp:              "eRezeptApp",
            client_id:        "eRezeptApp",
            exp:              "[\\d]*",
            jti:              "${json-unit.ignore}",
            family_name:      "(.{1,64})",
            given_name:       "(.{1,64})",
            iat:              "[\\d]*",
            idNummer:         "[A-Z][\\d]{9,10}",
            iss:              "http.*",
            organizationName: "(.{1,64})",
            professionOID:    "1\\.2\\.276\\.0\\.76\\.4\\.(3\\d|4\\d|178|23[2-90]|240|241)",
            scope:            "(openid e-rezept|e-rezept openid)",
            sub:              ".*"
          }
        """

  @Approval @Ready
  Scenario: GetToken mit SSO Token - Gutfall - Check ID Token - Validiere Antwortstruktur
    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
        # code_challenge for given verifier can be obtained from https://tonyxu-io.github.io/pkce-generator/
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state         | nonce  | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx1a | 886655 | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And I request a code token with signed challenge
    And I request an access token
    And I start new interaction keeping only
      | SSO_TOKEN           |
      | SSO_TOKEN_ENCRYPTED |
    And I initialize scenario from discovery document endpoint
    And I retrieve public keys from URIs
    And I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state         | nonce  | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx2a | 886644 | code          |
    And I request a code token with sso token
    And I set the context with key REDIRECT_URI to 'http://redirect.gematik.de/erezept'

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

  @Approval @Ready
  Scenario: GetToken mit SSO Token - Gutfall - Check ID Token - Validiere ID Token Claims
    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
        # code_challenge for given verifier can be obtained from https://tonyxu-io.github.io/pkce-generator/
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state         | nonce  | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx1a | 886655 | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And I request a code token with signed challenge
    And I request an access token
    And I start new interaction keeping only
      | SSO_TOKEN           |
      | SSO_TOKEN_ENCRYPTED |
    And I initialize scenario from discovery document endpoint
    And I retrieve public keys from URIs
    And I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state         | nonce  | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx2a | 886644 | code          |
    And I request a code token with sso token
    And I set the context with key REDIRECT_URI to 'http://redirect.gematik.de/erezept'
    And I request an access token

    When I extract the header claims from token ID_TOKEN
    Then the header claims should match in any order
        """
          { alg: "BP256R1",
            exp: "[\\d]*",
            kid: "${json-unit.ignore}",
            typ: "JWT"
          }
        """
    When I extract the body claims from token ID_TOKEN
    Then the body claims should match in any order
        """
          { acr:              "gematik-ehealth-loa-high",
            amr:              '["mfa", "sc", "pin"]',
            at_hash:          ".*",
            aud:              "eRezeptApp",
            auth_time:        "[\\d]*",
            azp:              "eRezeptApp",
            exp:              "[\\d]*",
            family_name:      "(.{1,64})",
            given_name:       "(.{1,64})",
            iat:              "[\\d]*",
            idNummer:         "[A-Z][\\d]{9,10}",
            iss:              "http.*",
            nonce:            "886644",
            organizationName: "(.{1,64})",
            professionOID:    "1\\.2\\.276\\.0\\.76\\.4\\.(3\\d|4\\d|178|23[2-90]|240|241)",
            sub:              ".*",
            jti:              ".*"
          }
        """

  @Afo:A_20625 @Afo:A_20327
  @Approval @Ready
  @Signature
  Scenario: GetToken mit SSO Token - Validiere Signatur ID Token
    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state         | nonce  | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx1a | 887722 | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And I request a code token with signed challenge
    And I request an access token
    And I start new interaction keeping only
      | SSO_TOKEN           |
      | SSO_TOKEN_ENCRYPTED |
    And I initialize scenario from discovery document endpoint
    And I retrieve public keys from URIs
    And I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state         | nonce  | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx2a | 887711 | code          |
    And I request a code token with sso token
    And I set the context with key REDIRECT_URI to 'http://redirect.gematik.de/erezept'

    When I request an access token
    Then the context ID_TOKEN must be signed with cert PUK_SIGN


  @Approval @Ready
  @Timeout
  Scenario: GetToken mit SSO Token - Speichere SSO Token für manuelle Tests
    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state         | nonce  | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx1a | 887722 | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    When I request a code token with signed challenge
    Then I store SSO_TOKEN as text
    And I store SSO_TOKEN_ENCRYPTED as text

  @Afo:A_20315-01
  @Approval @Todo:NotCheckingSsoTokenExactly12H
  @Timeout
  Scenario: GetToken mit SSO Token - Veralteter SSO Token wird abgelehnt

    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state         | nonce  | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx2a | 887711 | code          |

    When I load SSO_TOKEN from folder 'old_sso_token'
    And I load SSO_TOKEN_ENCRYPTED from folder 'old_sso_token'
    And I request a code token with sso token
    Then the response is an 302 error with code "invalid_request" and message matching 'SsoToken%20expired'

  # TODO we have no scenario where we check that an SSO Token is valid after 11h59m

  # TODO card specific cases (if user consent claims should be validated)
