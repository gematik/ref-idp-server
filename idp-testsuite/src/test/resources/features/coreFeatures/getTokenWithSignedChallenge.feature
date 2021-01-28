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

  @Approval @Ready
  Scenario: GetToken Signierte Challenge - Gutfall - Check Access Token - Validiere Antwortstruktur
    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce  | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 887766 | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And I request a code token with SIGNED_CHALLENGE
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

  @Approval @Todo:AccessTokenContent
  Scenario: GetToken Signierte Challenge - Gutfall - Check Access Token - Validiere Access Token Claims
    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce  | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 887766 | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And I request a code token with SIGNED_CHALLENGE
    And I set the context with key REDIRECT_URI to 'http://redirect.gematik.de/erezept'

    When I request an access token
    And I extract the header claims from token ACCESS_TOKEN
    Then the header claims should match in any order
        """
          { alg: "BP256R1",
            exp: "[\\d]*",
            jti: "${json-unit.ignore}",
            typ: "at+JWT"
          }
        """
    When I extract the body claims from token ACCESS_TOKEN
    Then the body claims should match in any order
        """
          { acr:              "eidas-loa-high",
            amr:              '["mfa", "sc", "pin"]',
            aud:              "https://erp.zentral.erp.splitdns.ti-dienste.de",
            auth_time:        "[\\d]*",
            azp:              "eRezeptApp",
            client_id:        "eRezeptApp",
            exp:              "[\\d]*",
            family_name:      "(.{1,64})",
            given_name:       "(.{1,64})",
            iat:              "[\\d]*",
            idNummer:         "[A-Z][\\d]{9,10}",
            iss:              "http.*",
            organizationName: "(.{1,64})",
            professionOID:    "1\\.2\\.276\\.0\\.76\\.4\\.(3\\d|4\\d|178|23[2-90]|240|241)",
            scope:            "(openid e-rezept|e-rezept openid)",
            sub:              "subject"
          }
        """
        # TODO abklären mit RISE: jti ist immer im header

        # TODO when eGK verwendet wird, darf keine professionOID claim vorhanden sein
        # TODO organizationName bei HBA nicht gesetzt
        # TODO bei SMC-B sind names optional, wie gehen wir damit um?
        # TODO Zu klären: wo prüfen wir die gültigkeit der professionOID am server? oder akzeptieren wir was in der Karte steht?
        # 1\\.2\\.276\\.0\\.76\\.4\\.(3\\d|4\\d|178|23[2-0]|240|241)

        # TODO acr separator format either ":" or "-" ?

  @Approval @Ready
  Scenario: GetToken Signierte Challenge - Gutfall - Check ID Token - Validiere Antwortstruktur
    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 98765 | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And I request a code token with SIGNED_CHALLENGE
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
  Scenario: GetToken Signierte Challenge - Gutfall - Check ID Token - Validiere ID Token Claims
    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 98765 | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And I request a code token with SIGNED_CHALLENGE
    And I set the context with key REDIRECT_URI to 'http://redirect.gematik.de/erezept'

    When I request an access token
    And I extract the header claims from response field id_token
    Then the header claims should match in any order
        """
          { alg: "BP256R1",
            exp: "[\\d]*",
            typ: "JWT"
          }
        """
    When I extract the body claims from response field id_token
    Then the body claims should match in any order
        """
          { acr:              "eidas-loa-high",
            amr:              '["mfa", "sc", "pin"]',
            at_hash:          ".*",
            aud:              "https://erp.zentral.erp.splitdns.ti-dienste.de",
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
            sub:              "eRezeptApp"
          }
        """

  @Afo:A_20625 @Afo:A_20327
  @Approval @Ready
  @Signature
  Scenario: GetToken Signierte Challenge - Validiere Signatur ID Token
    Given I retrieve public keys from URIs
    And I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce  | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 888877 | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And I request a code token with SIGNED_CHALLENGE
    And I set the context with key REDIRECT_URI to 'http://redirect.gematik.de/erezept'

    When I request an access token
    Then the context ID_TOKEN must be signed with cert PUK_TOKEN

    # TODO card specific cases (if user consent claims should be validated)

  @Approval @Todo:ErrorMessages
  Scenario Outline: GetToken Signierte Challenge - Null Parameter
    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce  | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 777766 | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And I request a code token with SIGNED_CHALLENGE
    And I set the context with key REDIRECT_URI to 'http://redirect.gematik.de/erezept'
    When I request an access token with
      | grant_type   | redirect_uri   | code   | code_verifier   | client_id   |
      | <grant_type> | <redirect_uri> | <code> | <code_verifier> | <client_id> |
    Then the response status is 400
    # TODO check error message in response

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
    And I request a code token with SIGNED_CHALLENGE
    When I request an access token with
      | grant_type   | redirect_uri   | code   | code_verifier   | client_id   |
      | <grant_type> | <redirect_uri> | <code> | <code_verifier> | <client_id> |
    Then the response status is 400
    # TODO check error message in response


    Examples: GetToken - Fehlende Parameter Beispiele
      | grant_type         | redirect_uri                       | code                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | code_verifier                                                                      | client_id |
      | $REMOVE            | http://redirect.gematik.de/erezept | eyJhbGciOiJCUDI1NlIxIn0.eyJzdWIiOiJzdWJqZWN0Iiwib3JnYW5pemF0aW9uTmFtZSI6ImdlbWF0aWsgR21iSCBOT1QtVkFMSUQiLCJwcm9mZXNzaW9uT0lEIjoiMS4yLjI3Ni4wLjc2LjQuNDkiLCJpZE51bW1lciI6IlgxMTA0MTE2NzUiLCJpc3MiOiJzZW5kZXIiLCJyZXNwb25zZV90eXBlIjoiY29kZSIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJnaXZlbl9uYW1lIjoiRGFyaXVzIE1pY2hhZWwgQnJpYW4gVWJibyIsImNsaWVudF9pZCI6Im9pZGNfY2xpZW50IiwiYWNyIjoiZWlkYXMtbG9hLWhpZ2giLCJhdWQiOiJlcnAuemVudHJhbC5lcnAudGktZGllbnN0ZS5kZSIsInNjb3BlIjoib3BlbmlkIGUtcmV6ZXB0IiwiYXV0aF90aW1lIjoxNjA3MzQ5MjExLCJyZWRpcmVjdF91cmkiOiJodHRwOmxvY2FsaG9zdDo4MDgwIiwic3RhdGUiOiJ4eHhzdGF0ZXh4eCIsImV4cCI6MTYwNzM1MjgxMSwiZmFtaWx5X25hbWUiOiJCw7ZkZWZlbGQiLCJjb2RlX2NoYWxsZW5nZSI6IkNhM1ZlOGpTc0JRT0JGVnFRdkxzMUUtZEdWMUJYZzJGVHZyZC1UZzE5VmcifQ.RsR3JFqMCFV9I7m8l5SlyTMNGOCF8GeInDEtj9zvBDRCIjjPSYjjHlwiCxYsimYhrcFzr77bpXUjd1BbprzI_Q | drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj | erezept   |
      | authorization_code | $REMOVE                            | eyJhbGciOiJCUDI1NlIxIn0.eyJzdWIiOiJzdWJqZWN0Iiwib3JnYW5pemF0aW9uTmFtZSI6ImdlbWF0aWsgR21iSCBOT1QtVkFMSUQiLCJwcm9mZXNzaW9uT0lEIjoiMS4yLjI3Ni4wLjc2LjQuNDkiLCJpZE51bW1lciI6IlgxMTA0MTE2NzUiLCJpc3MiOiJzZW5kZXIiLCJyZXNwb25zZV90eXBlIjoiY29kZSIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJnaXZlbl9uYW1lIjoiRGFyaXVzIE1pY2hhZWwgQnJpYW4gVWJibyIsImNsaWVudF9pZCI6Im9pZGNfY2xpZW50IiwiYWNyIjoiZWlkYXMtbG9hLWhpZ2giLCJhdWQiOiJlcnAuemVudHJhbC5lcnAudGktZGllbnN0ZS5kZSIsInNjb3BlIjoib3BlbmlkIGUtcmV6ZXB0IiwiYXV0aF90aW1lIjoxNjA3MzQ5MjExLCJyZWRpcmVjdF91cmkiOiJodHRwOmxvY2FsaG9zdDo4MDgwIiwic3RhdGUiOiJ4eHhzdGF0ZXh4eCIsImV4cCI6MTYwNzM1MjgxMSwiZmFtaWx5X25hbWUiOiJCw7ZkZWZlbGQiLCJjb2RlX2NoYWxsZW5nZSI6IkNhM1ZlOGpTc0JRT0JGVnFRdkxzMUUtZEdWMUJYZzJGVHZyZC1UZzE5VmcifQ.RsR3JFqMCFV9I7m8l5SlyTMNGOCF8GeInDEtj9zvBDRCIjjPSYjjHlwiCxYsimYhrcFzr77bpXUjd1BbprzI_Q | drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj | erezept   |
      | authorization_code | http://redirect.gematik.de/erezept | $REMOVE                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj | erezept   |
      | authorization_code | http://redirect.gematik.de/erezept | eyJhbGciOiJCUDI1NlIxIn0.eyJzdWIiOiJzdWJqZWN0Iiwib3JnYW5pemF0aW9uTmFtZSI6ImdlbWF0aWsgR21iSCBOT1QtVkFMSUQiLCJwcm9mZXNzaW9uT0lEIjoiMS4yLjI3Ni4wLjc2LjQuNDkiLCJpZE51bW1lciI6IlgxMTA0MTE2NzUiLCJpc3MiOiJzZW5kZXIiLCJyZXNwb25zZV90eXBlIjoiY29kZSIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJnaXZlbl9uYW1lIjoiRGFyaXVzIE1pY2hhZWwgQnJpYW4gVWJibyIsImNsaWVudF9pZCI6Im9pZGNfY2xpZW50IiwiYWNyIjoiZWlkYXMtbG9hLWhpZ2giLCJhdWQiOiJlcnAuemVudHJhbC5lcnAudGktZGllbnN0ZS5kZSIsInNjb3BlIjoib3BlbmlkIGUtcmV6ZXB0IiwiYXV0aF90aW1lIjoxNjA3MzQ5MjExLCJyZWRpcmVjdF91cmkiOiJodHRwOmxvY2FsaG9zdDo4MDgwIiwic3RhdGUiOiJ4eHhzdGF0ZXh4eCIsImV4cCI6MTYwNzM1MjgxMSwiZmFtaWx5X25hbWUiOiJCw7ZkZWZlbGQiLCJjb2RlX2NoYWxsZW5nZSI6IkNhM1ZlOGpTc0JRT0JGVnFRdkxzMUUtZEdWMUJYZzJGVHZyZC1UZzE5VmcifQ.RsR3JFqMCFV9I7m8l5SlyTMNGOCF8GeInDEtj9zvBDRCIjjPSYjjHlwiCxYsimYhrcFzr77bpXUjd1BbprzI_Q | $REMOVE                                                                            | erezept   |
      | authorization_code | http://redirect.gematik.de/erezept | eyJhbGciOiJCUDI1NlIxIn0.eyJzdWIiOiJzdWJqZWN0Iiwib3JnYW5pemF0aW9uTmFtZSI6ImdlbWF0aWsgR21iSCBOT1QtVkFMSUQiLCJwcm9mZXNzaW9uT0lEIjoiMS4yLjI3Ni4wLjc2LjQuNDkiLCJpZE51bW1lciI6IlgxMTA0MTE2NzUiLCJpc3MiOiJzZW5kZXIiLCJyZXNwb25zZV90eXBlIjoiY29kZSIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJnaXZlbl9uYW1lIjoiRGFyaXVzIE1pY2hhZWwgQnJpYW4gVWJibyIsImNsaWVudF9pZCI6Im9pZGNfY2xpZW50IiwiYWNyIjoiZWlkYXMtbG9hLWhpZ2giLCJhdWQiOiJlcnAuemVudHJhbC5lcnAudGktZGllbnN0ZS5kZSIsInNjb3BlIjoib3BlbmlkIGUtcmV6ZXB0IiwiYXV0aF90aW1lIjoxNjA3MzQ5MjExLCJyZWRpcmVjdF91cmkiOiJodHRwOmxvY2FsaG9zdDo4MDgwIiwic3RhdGUiOiJ4eHhzdGF0ZXh4eCIsImV4cCI6MTYwNzM1MjgxMSwiZmFtaWx5X25hbWUiOiJCw7ZkZWZlbGQiLCJjb2RlX2NoYWxsZW5nZSI6IkNhM1ZlOGpTc0JRT0JGVnFRdkxzMUUtZEdWMUJYZzJGVHZyZC1UZzE5VmcifQ.RsR3JFqMCFV9I7m8l5SlyTMNGOCF8GeInDEtj9zvBDRCIjjPSYjjHlwiCxYsimYhrcFzr77bpXUjd1BbprzI_Q | drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj | $REMOVE   |
