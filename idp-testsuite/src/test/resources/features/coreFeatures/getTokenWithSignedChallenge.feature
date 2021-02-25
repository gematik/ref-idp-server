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
@SignedChallengeFlow
Feature: Fordere Access Token mit einer signierten Challenge an
  Frontends von TI Diensten müssen vom IDP Server über ein HTTP POST an den Token Endpoint ein Access/SSO/ID Token abfragen können.

  Background: Initialisiere Testkontext durch Abfrage des Discovery Dokuments
    Given I initialize scenario from discovery document endpoint
    And I retrieve public keys from URIs

  @Afo:A_20463 @Afo:A_20321-01
  @Approval @Ready
  Scenario: GetToken Signierte Challenge - Gutfall - Check Access Token - Validiere Antwortstruktur
    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce  | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 887766 | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And I request a code token with signed challenge
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

  @Afo:A_20731 @Afo:A_20310 @Afo:A_20464 @Afo:A_20952 @Afo:21320 @Afo:A_21321
  @Approval @Todo:AccessTokenContent
  @Todo:CompareSubjectInfosInAccessTokenAndInCert
    # TODO: wollen wir noch den Wert der auth_time gegen den Zeitpunkt der Authentifizierung pruefen
  Scenario: GetToken Signierte Challenge - Gutfall - Check Access Token - Validiere Access Token Claims
    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce  | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 887766 | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And I request a code token with signed challenge
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
            amr:              '["mfa", "sc", "pin"]',
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
        # TODO abklären mit RISE: jti ist immer im header

        # TODO organizationName bei HBA nicht gesetzt
        # TODO bei SMC-B sind names optional, wie gehen wir damit um?
        # TODO Zu klären: wo prüfen wir die gültigkeit der professionOID am server? oder akzeptieren wir was in der Karte steht?
        # 1\\.2\\.276\\.0\\.76\\.4\\.(3\\d|4\\d|178|23[2-0]|240|241)

        # TODO acr separator format either ":" or "-" ?

  @Approval @Ready
  @Todo:WeAlreadyHaveTheseChecksInAnotherTestcase @Todo:Duplicate
  Scenario: GetToken Signierte Challenge - Gutfall - Check ID Token - Validiere Antwortstruktur
    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 98765 | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And I request a code token with signed challenge
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

  @Afo:A_21321
  @Approval @Ready
  Scenario: GetToken Signierte Challenge - Gutfall - Check ID Token - Validiere ID Token Claims
    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 98765 | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And I request a code token with signed challenge
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
            nonce:            "98765",
            professionOID:    "1\\.2\\.276\\.0\\.76\\.4\\.(3\\d|4\\d|178|23[2-90]|240|241)",
            organizationName: "(.{1,64})",
            sub:              ".*",
            jti:              ".*"
          }
        """

  @Approval @Todo:AccessTokenContent
  Scenario: GetToken Signierte Challenge - Subject Claim ist abhängig von idNummer
    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce  | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 887766 | code          |
    And I sign the challenge with '/certs/valid/80276883110000129089-C_CH_AUT_E256.p12'
    And I request a code token with signed challenge
    And I set the context with key REDIRECT_URI to 'http://redirect.gematik.de/erezept'
    And I request an access token

    When I extract the body claims from token ACCESS_TOKEN
    Then the body claim 'sub' should match '.*'
    And the body claim 'idNummer' should match "[A-Z][\d]{9,10}"
    When I extract the body claims from token ID_TOKEN
    Then the body claim 'sub' should match '.*'
    And the body claim 'idNummer' should match "[A-Z][\d]{9,10}"

    # TODO write method to save a specific claim and compare it with another (positive and negative)
    # TODO rewrite test case to run two times and verify that sub values do mismatch

  @Approval @Todo:AccessTokenContent
  Scenario: GetToken Signierte Challenge - Subject Claim wird auch für nicht durch Versicherte signierte Challenges erstellt
    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce  | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 887766 | code          |
    And I sign the challenge with '/certs/valid/80276883110000129083-C_HP_AUT_E256.p12'
    And I request a code token with signed challenge
    And I set the context with key REDIRECT_URI to 'http://redirect.gematik.de/erezept'
    And I request an access token

    When I extract the body claims from token ACCESS_TOKEN
    Then the body claim 'sub' should match '.*'
    And the body claim 'idNummer' should match "[\d]\-.*"
    When I extract the body claims from token ID_TOKEN
    Then the body claim 'sub' should match '.*'
    And the body claim 'idNummer' should match "[\d]\-.*"

  @Afo:A_20327-02
  @Approval @Ready
  @Signature
  Scenario: GetToken Signierte Challenge - Validiere Signatur Access Token
    Given I retrieve public keys from URIs
    And I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce  | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 888877 | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And I request a code token with signed challenge
    And I set the context with key REDIRECT_URI to 'http://redirect.gematik.de/erezept'

    When I request an access token
    Then the context ACCESS_TOKEN must be signed with cert PUK_SIGN

  @Afo:A_20625 @Afo:A_20327-02
  @Approval @Ready
  @Signature
  Scenario: GetToken Signierte Challenge - Validiere Signatur ID Token
    Given I retrieve public keys from URIs
    And I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce  | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 888877 | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And I request a code token with signed challenge
    And I set the context with key REDIRECT_URI to 'http://redirect.gematik.de/erezept'

    When I request an access token
    Then the context ID_TOKEN must be signed with cert PUK_SIGN

    # TODO card specific cases (if user consent claims should be validated)


  @Afo:A_20314 @Afo:A_20315-01
  @Approval @Todo
  @Timeout
  Scenario: GetToken Signierte Challenge - Veralteter Token code wird abgelehnt
    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 98765 | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And I request a code token with signed challenge
    And I set the context with key REDIRECT_URI to 'http://redirect.gematik.de/erezept'

    When I wait PT65S
    And I request an access token
    Then the response status is 400
    And the JSON response should match
        """
          { error_code: "invalid_request",
            error_uuid: ".*",
            timestamp: ".*",
            detail_message: "The given JWT has expired and is no longer valid (exp is in the past)"
          }
        """


  @Approval @Todo:ErrorMessages
  Scenario Outline: GetToken Signierte Challenge - Null Parameter
    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce  | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 777766 | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And I request a code token with signed challenge
    And I set the context with key REDIRECT_URI to 'http://redirect.gematik.de/erezept'
    When I request an access token with
      | grant_type   | redirect_uri   | code   | code_verifier   | client_id   |
      | <grant_type> | <redirect_uri> | <code> | <code_verifier> | <client_id> |
    Then the response status is 400
    And the JSON response should match
        """
          { error_code: "invalid_request",
            error_uuid: ".*",
            timestamp: ".*",
            detail_message: ".*"
          }
        """
    # TODO check error detail message

    Examples: GetToken - Null Parameter Beispiele
      | grant_type         | redirect_uri                       | code                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | code_verifier                                                                      | client_id |
      | $NULL              | http://redirect.gematik.de/erezept | eyJhbGciOiJCUDI1NlIxIn0.eyJzdWIiOiJzdWJqZWN0Iiwib3JnYW5pemF0aW9uTmFtZSI6ImdlbWF0aWsgR21iSCBOT1QtVkFMSUQiLCJwcm9mZXNzaW9uT0lEIjoiMS4yLjI3Ni4wLjc2LjQuNDkiLCJpZE51bW1lciI6IlgxMTA0MTE2NzUiLCJpc3MiOiJzZW5kZXIiLCJyZXNwb25zZV90eXBlIjoiY29kZSIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJnaXZlbl9uYW1lIjoiRGFyaXVzIE1pY2hhZWwgQnJpYW4gVWJibyIsImNsaWVudF9pZCI6Im9pZGNfY2xpZW50IiwiYWNyIjoiZWlkYXMtbG9hLWhpZ2giLCJhdWQiOiJlcnAuemVudHJhbC5lcnAudGktZGllbnN0ZS5kZSIsInNjb3BlIjoib3BlbmlkIGUtcmV6ZXB0IiwiYXV0aF90aW1lIjoxNjA3MzQ5MjExLCJyZWRpcmVjdF91cmkiOiJodHRwOmxvY2FsaG9zdDo4MDgwIiwic3RhdGUiOiJ4eHhzdGF0ZXh4eCIsImV4cCI6MTYwNzM1MjgxMSwiZmFtaWx5X25hbWUiOiJCw7ZkZWZlbGQiLCJjb2RlX2NoYWxsZW5nZSI6IkNhM1ZlOGpTc0JRT0JGVnFRdkxzMUUtZEdWMUJYZzJGVHZyZC1UZzE5VmcifQ.RsR3JFqMCFV9I7m8l5SlyTMNGOCF8GeInDEtj9zvBDRCIjjPSYjjHlwiCxYsimYhrcFzr77bpXUjd1BbprzI_Q | drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj | erezept   |
      | authorization_code | $NULL                              | eyJhbGciOiJCUDI1NlIxIn0.eyJzdWIiOiJzdWJqZWN0Iiwib3JnYW5pemF0aW9uTmFtZSI6ImdlbWF0aWsgR21iSCBOT1QtVkFMSUQiLCJwcm9mZXNzaW9uT0lEIjoiMS4yLjI3Ni4wLjc2LjQuNDkiLCJpZE51bW1lciI6IlgxMTA0MTE2NzUiLCJpc3MiOiJzZW5kZXIiLCJyZXNwb25zZV90eXBlIjoiY29kZSIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJnaXZlbl9uYW1lIjoiRGFyaXVzIE1pY2hhZWwgQnJpYW4gVWJibyIsImNsaWVudF9pZCI6Im9pZGNfY2xpZW50IiwiYWNyIjoiZWlkYXMtbG9hLWhpZ2giLCJhdWQiOiJlcnAuemVudHJhbC5lcnAudGktZGllbnN0ZS5kZSIsInNjb3BlIjoib3BlbmlkIGUtcmV6ZXB0IiwiYXV0aF90aW1lIjoxNjA3MzQ5MjExLCJyZWRpcmVjdF91cmkiOiJodHRwOmxvY2FsaG9zdDo4MDgwIiwic3RhdGUiOiJ4eHhzdGF0ZXh4eCIsImV4cCI6MTYwNzM1MjgxMSwiZmFtaWx5X25hbWUiOiJCw7ZkZWZlbGQiLCJjb2RlX2NoYWxsZW5nZSI6IkNhM1ZlOGpTc0JRT0JGVnFRdkxzMUUtZEdWMUJYZzJGVHZyZC1UZzE5VmcifQ.RsR3JFqMCFV9I7m8l5SlyTMNGOCF8GeInDEtj9zvBDRCIjjPSYjjHlwiCxYsimYhrcFzr77bpXUjd1BbprzI_Q | drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj | erezept   |
      | authorization_code | http://redirect.gematik.de/erezept | $NULL                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj | erezept   |
      | authorization_code | http://redirect.gematik.de/erezept | eyJhbGciOiJCUDI1NlIxIn0.eyJzdWIiOiJzdWJqZWN0Iiwib3JnYW5pemF0aW9uTmFtZSI6ImdlbWF0aWsgR21iSCBOT1QtVkFMSUQiLCJwcm9mZXNzaW9uT0lEIjoiMS4yLjI3Ni4wLjc2LjQuNDkiLCJpZE51bW1lciI6IlgxMTA0MTE2NzUiLCJpc3MiOiJzZW5kZXIiLCJyZXNwb25zZV90eXBlIjoiY29kZSIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJnaXZlbl9uYW1lIjoiRGFyaXVzIE1pY2hhZWwgQnJpYW4gVWJibyIsImNsaWVudF9pZCI6Im9pZGNfY2xpZW50IiwiYWNyIjoiZWlkYXMtbG9hLWhpZ2giLCJhdWQiOiJlcnAuemVudHJhbC5lcnAudGktZGllbnN0ZS5kZSIsInNjb3BlIjoib3BlbmlkIGUtcmV6ZXB0IiwiYXV0aF90aW1lIjoxNjA3MzQ5MjExLCJyZWRpcmVjdF91cmkiOiJodHRwOmxvY2FsaG9zdDo4MDgwIiwic3RhdGUiOiJ4eHhzdGF0ZXh4eCIsImV4cCI6MTYwNzM1MjgxMSwiZmFtaWx5X25hbWUiOiJCw7ZkZWZlbGQiLCJjb2RlX2NoYWxsZW5nZSI6IkNhM1ZlOGpTc0JRT0JGVnFRdkxzMUUtZEdWMUJYZzJGVHZyZC1UZzE5VmcifQ.RsR3JFqMCFV9I7m8l5SlyTMNGOCF8GeInDEtj9zvBDRCIjjPSYjjHlwiCxYsimYhrcFzr77bpXUjd1BbprzI_Q | $NULL                                                                              | erezept   |
      | authorization_code | http://redirect.gematik.de/erezept | eyJhbGciOiJCUDI1NlIxIn0.eyJzdWIiOiJzdWJqZWN0Iiwib3JnYW5pemF0aW9uTmFtZSI6ImdlbWF0aWsgR21iSCBOT1QtVkFMSUQiLCJwcm9mZXNzaW9uT0lEIjoiMS4yLjI3Ni4wLjc2LjQuNDkiLCJpZE51bW1lciI6IlgxMTA0MTE2NzUiLCJpc3MiOiJzZW5kZXIiLCJyZXNwb25zZV90eXBlIjoiY29kZSIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJnaXZlbl9uYW1lIjoiRGFyaXVzIE1pY2hhZWwgQnJpYW4gVWJibyIsImNsaWVudF9pZCI6Im9pZGNfY2xpZW50IiwiYWNyIjoiZWlkYXMtbG9hLWhpZ2giLCJhdWQiOiJlcnAuemVudHJhbC5lcnAudGktZGllbnN0ZS5kZSIsInNjb3BlIjoib3BlbmlkIGUtcmV6ZXB0IiwiYXV0aF90aW1lIjoxNjA3MzQ5MjExLCJyZWRpcmVjdF91cmkiOiJodHRwOmxvY2FsaG9zdDo4MDgwIiwic3RhdGUiOiJ4eHhzdGF0ZXh4eCIsImV4cCI6MTYwNzM1MjgxMSwiZmFtaWx5X25hbWUiOiJCw7ZkZWZlbGQiLCJjb2RlX2NoYWxsZW5nZSI6IkNhM1ZlOGpTc0JRT0JGVnFRdkxzMUUtZEdWMUJYZzJGVHZyZC1UZzE5VmcifQ.RsR3JFqMCFV9I7m8l5SlyTMNGOCF8GeInDEtj9zvBDRCIjjPSYjjHlwiCxYsimYhrcFzr77bpXUjd1BbprzI_Q | drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj | $NULL     |

  @Approval @Todo:ErrorMessages
  Scenario Outline: GetToken Signierte Challenge - Fehlende Parameter
    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce  | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 776655 | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And I request a code token with signed challenge
    When I request an access token with
      | grant_type   | redirect_uri   | code   | code_verifier   | client_id   |
      | <grant_type> | <redirect_uri> | <code> | <code_verifier> | <client_id> |
    Then the response status is 400
    And the JSON response should match
        """
          { error_code: "<error_code>",
            error_uuid: ".*",
            timestamp: ".*",
            detail_message: ".*"
          }
        """
    # TODO check error detail message


    Examples: GetToken - Fehlende Parameter Beispiele
      | error_code         | grant_type         | redirect_uri                       | code                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | code_verifier                                                                      | client_id |
      | missing_parameters | $REMOVE            | http://redirect.gematik.de/erezept | eyJhbGciOiJCUDI1NlIxIn0.eyJzdWIiOiJzdWJqZWN0Iiwib3JnYW5pemF0aW9uTmFtZSI6ImdlbWF0aWsgR21iSCBOT1QtVkFMSUQiLCJwcm9mZXNzaW9uT0lEIjoiMS4yLjI3Ni4wLjc2LjQuNDkiLCJpZE51bW1lciI6IlgxMTA0MTE2NzUiLCJpc3MiOiJzZW5kZXIiLCJyZXNwb25zZV90eXBlIjoiY29kZSIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJnaXZlbl9uYW1lIjoiRGFyaXVzIE1pY2hhZWwgQnJpYW4gVWJibyIsImNsaWVudF9pZCI6Im9pZGNfY2xpZW50IiwiYWNyIjoiZWlkYXMtbG9hLWhpZ2giLCJhdWQiOiJlcnAuemVudHJhbC5lcnAudGktZGllbnN0ZS5kZSIsInNjb3BlIjoib3BlbmlkIGUtcmV6ZXB0IiwiYXV0aF90aW1lIjoxNjA3MzQ5MjExLCJyZWRpcmVjdF91cmkiOiJodHRwOmxvY2FsaG9zdDo4MDgwIiwic3RhdGUiOiJ4eHhzdGF0ZXh4eCIsImV4cCI6MTYwNzM1MjgxMSwiZmFtaWx5X25hbWUiOiJCw7ZkZWZlbGQiLCJjb2RlX2NoYWxsZW5nZSI6IkNhM1ZlOGpTc0JRT0JGVnFRdkxzMUUtZEdWMUJYZzJGVHZyZC1UZzE5VmcifQ.RsR3JFqMCFV9I7m8l5SlyTMNGOCF8GeInDEtj9zvBDRCIjjPSYjjHlwiCxYsimYhrcFzr77bpXUjd1BbprzI_Q | drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj | erezept   |
      | missing_parameters | authorization_code | $REMOVE                            | eyJhbGciOiJCUDI1NlIxIn0.eyJzdWIiOiJzdWJqZWN0Iiwib3JnYW5pemF0aW9uTmFtZSI6ImdlbWF0aWsgR21iSCBOT1QtVkFMSUQiLCJwcm9mZXNzaW9uT0lEIjoiMS4yLjI3Ni4wLjc2LjQuNDkiLCJpZE51bW1lciI6IlgxMTA0MTE2NzUiLCJpc3MiOiJzZW5kZXIiLCJyZXNwb25zZV90eXBlIjoiY29kZSIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJnaXZlbl9uYW1lIjoiRGFyaXVzIE1pY2hhZWwgQnJpYW4gVWJibyIsImNsaWVudF9pZCI6Im9pZGNfY2xpZW50IiwiYWNyIjoiZWlkYXMtbG9hLWhpZ2giLCJhdWQiOiJlcnAuemVudHJhbC5lcnAudGktZGllbnN0ZS5kZSIsInNjb3BlIjoib3BlbmlkIGUtcmV6ZXB0IiwiYXV0aF90aW1lIjoxNjA3MzQ5MjExLCJyZWRpcmVjdF91cmkiOiJodHRwOmxvY2FsaG9zdDo4MDgwIiwic3RhdGUiOiJ4eHhzdGF0ZXh4eCIsImV4cCI6MTYwNzM1MjgxMSwiZmFtaWx5X25hbWUiOiJCw7ZkZWZlbGQiLCJjb2RlX2NoYWxsZW5nZSI6IkNhM1ZlOGpTc0JRT0JGVnFRdkxzMUUtZEdWMUJYZzJGVHZyZC1UZzE5VmcifQ.RsR3JFqMCFV9I7m8l5SlyTMNGOCF8GeInDEtj9zvBDRCIjjPSYjjHlwiCxYsimYhrcFzr77bpXUjd1BbprzI_Q | drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj | erezept   |
      | missing_parameters | authorization_code | http://redirect.gematik.de/erezept | $REMOVE                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj | erezept   |
      | invalid_request    | authorization_code | http://redirect.gematik.de/erezept | eyJhbGciOiJCUDI1NlIxIn0.eyJzdWIiOiJzdWJqZWN0Iiwib3JnYW5pemF0aW9uTmFtZSI6ImdlbWF0aWsgR21iSCBOT1QtVkFMSUQiLCJwcm9mZXNzaW9uT0lEIjoiMS4yLjI3Ni4wLjc2LjQuNDkiLCJpZE51bW1lciI6IlgxMTA0MTE2NzUiLCJpc3MiOiJzZW5kZXIiLCJyZXNwb25zZV90eXBlIjoiY29kZSIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJnaXZlbl9uYW1lIjoiRGFyaXVzIE1pY2hhZWwgQnJpYW4gVWJibyIsImNsaWVudF9pZCI6Im9pZGNfY2xpZW50IiwiYWNyIjoiZWlkYXMtbG9hLWhpZ2giLCJhdWQiOiJlcnAuemVudHJhbC5lcnAudGktZGllbnN0ZS5kZSIsInNjb3BlIjoib3BlbmlkIGUtcmV6ZXB0IiwiYXV0aF90aW1lIjoxNjA3MzQ5MjExLCJyZWRpcmVjdF91cmkiOiJodHRwOmxvY2FsaG9zdDo4MDgwIiwic3RhdGUiOiJ4eHhzdGF0ZXh4eCIsImV4cCI6MTYwNzM1MjgxMSwiZmFtaWx5X25hbWUiOiJCw7ZkZWZlbGQiLCJjb2RlX2NoYWxsZW5nZSI6IkNhM1ZlOGpTc0JRT0JGVnFRdkxzMUUtZEdWMUJYZzJGVHZyZC1UZzE5VmcifQ.RsR3JFqMCFV9I7m8l5SlyTMNGOCF8GeInDEtj9zvBDRCIjjPSYjjHlwiCxYsimYhrcFzr77bpXUjd1BbprzI_Q | $REMOVE                                                                            | erezept   |
      | missing_parameters | authorization_code | http://redirect.gematik.de/erezept | eyJhbGciOiJCUDI1NlIxIn0.eyJzdWIiOiJzdWJqZWN0Iiwib3JnYW5pemF0aW9uTmFtZSI6ImdlbWF0aWsgR21iSCBOT1QtVkFMSUQiLCJwcm9mZXNzaW9uT0lEIjoiMS4yLjI3Ni4wLjc2LjQuNDkiLCJpZE51bW1lciI6IlgxMTA0MTE2NzUiLCJpc3MiOiJzZW5kZXIiLCJyZXNwb25zZV90eXBlIjoiY29kZSIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJnaXZlbl9uYW1lIjoiRGFyaXVzIE1pY2hhZWwgQnJpYW4gVWJibyIsImNsaWVudF9pZCI6Im9pZGNfY2xpZW50IiwiYWNyIjoiZWlkYXMtbG9hLWhpZ2giLCJhdWQiOiJlcnAuemVudHJhbC5lcnAudGktZGllbnN0ZS5kZSIsInNjb3BlIjoib3BlbmlkIGUtcmV6ZXB0IiwiYXV0aF90aW1lIjoxNjA3MzQ5MjExLCJyZWRpcmVjdF91cmkiOiJodHRwOmxvY2FsaG9zdDo4MDgwIiwic3RhdGUiOiJ4eHhzdGF0ZXh4eCIsImV4cCI6MTYwNzM1MjgxMSwiZmFtaWx5X25hbWUiOiJCw7ZkZWZlbGQiLCJjb2RlX2NoYWxsZW5nZSI6IkNhM1ZlOGpTc0JRT0JGVnFRdkxzMUUtZEdWMUJYZzJGVHZyZC1UZzE5VmcifQ.RsR3JFqMCFV9I7m8l5SlyTMNGOCF8GeInDEtj9zvBDRCIjjPSYjjHlwiCxYsimYhrcFzr77bpXUjd1BbprzI_Q | drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj | $REMOVE   |
