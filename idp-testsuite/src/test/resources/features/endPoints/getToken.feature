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
Feature: Fordere Access Token an
    Frontends von TI Diensten müssen vom IDP Server über ein HTTP POST an den Token Endpoint ein Access/SSO/ID Token abfragen können.

    Background: Initialisiere Testkontext durch Abfrage des Discovery Dokuments
        Given I initialize scenario from discovery document endpoint

    @Ready
    Scenario: GetToken - Gutfall ohne SSO Token
        Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
        And I request a challenge with
            | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       |
            | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx |
        And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
        And I request a code token with SIGNED_CHALLENGE
        And I set the context with key REDIRECT_URI to 'http://redirect.gematik.de/erezept'
        When I request an access token
        Then the response status is 200
        And the JSON response should match
        """
          {
              "expires_in": 300,
              "token_type": "Bearer",
              "id_token": "ey.*",
              "access_token": "ey.*",
              "sso_token": null
           }
        """
        # TODO remove sso_token from JSON response

        When I extract the header claims from response field access_token
        Then the header claims should match in any order
        """
            {
                "alg": "BP256R1",
                "jti": "${json-unit.ignore}",
                "typ":"at+JWT",
                "exp": "[\\d]*"
            }
        """

        When I extract the body claims from response field access_token
        Then the body claims should match in any order
        """
            {
                "iss": "http.*",
                "iat": "[\\d]*",
                "exp": "[\\d]*",
                "nbf": "[\\d]*",
                "professionOID": "1\\.2\\.276\\.0\\.76\\.4\\.(3\\d|4\\d|178|23[2-90]|240|241)",
                "given_name": "(.{1,64})",
                "family_name": "(.{1,64})",
                "organizationName": "(.{1,64})",
                "idNummer": "[A-Z][\\d]{9,10}",
                "acr": "eidas-loa-high",
                "code_challenge_method": "S256",
                "client_id": "eRezeptApp",
                "scope": "(openid e-rezept|e-rezept openid)",
                "auth_time": "[\\d]*",
                "redirect_uri": "http://redirect.gematik.de/erezept",
                "code_challenge": ".*",
                "sub": "subject",
                "response_type": "code",
                "aud": "https://erp.zentral.erp.splitdns.ti-dienste.de",
                "state": "xxxstatexxx"
            }
        """
        # TODO state ist nicht in den body claims des Access Tokens!
        # TODO when eGK verwendet wird, darf keine professionOID claim vorhanden sein
        # TODO organizationName bei HBA nicht gesetzt
        # TODO bei SMC-B sind names optional, wie gehen wir damit um?
        # TODO Zu klären: wo prüfen wir die gültigkeit der professionOID am server? oder akzeptieren wir was in der Karte steht?
        # 1\\.2\\.276\\.0\\.76\\.4\\.(3\\d|4\\d|178|23[2-0]|240|241)

        # TODO acr separator format either ":" or "-" ?

        When I extract the header claims from response field id_token
        Then the header claims should match in any order
        """
            {
                "alg": "BP256R1",
                "typ": "JWT",
                "exp": "[\\d]*"
            }
        """

        When I extract the body claims from response field id_token
        Then the body claims should match in any order
        """
            {
                "iss": "http.*",
                "sub": "eRezeptApp",
                "iat": "[\\d]*",
                "exp": "[\\d]*",
                "nbf": "[\\d]*",
                "professionOID": "1\\.2\\.276\\.0\\.76\\.4\\.(3\\d|4\\d|178|23[2-90]|240|241)",
                "given_name": "(.{1,64})",
                "family_name": "(.{1,64})",
                "organizationName": "(.{1,64})",
                "idNummer": "[A-Z][\\d]{9,10}",
                "aud": "https://erp.zentral.erp.splitdns.ti-dienste.de"
            }
        """

    @Ready
    Scenario: GetToken - Gutfall mit SSO Token
        Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
        # code_challenge for given verifier can be obtained from https://tonyxu-io.github.io/pkce-generator/
        And I request a challenge with
            | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state         |
            | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx1a |
        And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
        And I request a code token with SIGNED_CHALLENGE
        And I request an access token
        And I start new interaction keeping only SSO_TOKEN
        And I initialize scenario from discovery document endpoint
        And I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
        And I request a challenge with
            | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state         |
            | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx2a |
        And I request a code token with SSO_TOKEN
        And I set the context with key REDIRECT_URI to 'http://redirect.gematik.de/erezept'
        When I request an access token
        Then the response status is 200
        And the JSON response should match
        """
          {
              "expires_in": 300,
              "token_type": "Bearer",
              "id_token": "ey.*",
              "access_token": "ey.*",
              "sso_token": null
           }
        """

        When I extract the header claims from response field access_token
        Then the header claims should match in any order
        """
            {
                "alg": "BP256R1",
                "jti": "${json-unit.ignore}",
                "typ": "at+JWT",
                "exp": "[\\d]*"
            }
        """
        #  TODO   "cty": "NJWT",

        When I extract the body claims from response field access_token
        Then the body claims should match in any order
        """
            {
                "iss": "http.*",
                "iat": "[\\d]*",
                "exp": "[\\d]*",
                "nbf": "[\\d]*",
                "professionOID": "1\\.2\\.276\\.0\\.76\\.4\\.(3\\d|4\\d|178|23[2-90]|240|241)",
                "given_name": "(.{1,64})",
                "family_name": "(.{1,64})",
                "organizationName": "(.{1,64})",
                "idNummer": "[A-Z][\\d]{9,10}",
                "acr": "eidas-loa-high",
                "code_challenge_method": "S256",
                "client_id": "eRezeptApp",
                "scope": "(openid e-rezept|e-rezept openid)",
                "auth_time": "[\\d]*",
                "redirect_uri": "http://redirect.gematik.de/erezept",
                "code_challenge": ".*",
                "sub": "subject",
                "response_type": "code",
                "aud": "https://erp.zentral.erp.splitdns.ti-dienste.de",
                "state": "xxxstatexxx2a"
            }
        """

        When I extract the header claims from response field id_token
        Then the header claims should match in any order
        """
            {
                "alg": "BP256R1",
                "typ": "JWT",
                "exp": "[\\d]*"
            }
        """

        When I extract the body claims from response field id_token
        Then the body claims should match in any order
        """
            {
                "iss": "http.*",
                "sub": "eRezeptApp",
                "iat": "[\\d]*",
                "exp": "[\\d]*",
                "nbf": "[\\d]*",
                "professionOID": "1\\.2\\.276\\.0\\.76\\.4\\.(3\\d|4\\d|178|23[2-90]|240|241)",
                "given_name": "(.{1,64})",
                "family_name": "(.{1,64})",
                "organizationName": "(.{1,64})",
                "idNummer": "[A-Z][\\d]{9,10}",
                "aud": "https://erp.zentral.erp.splitdns.ti-dienste.de"
            }
        """

    # TODO negative cases
    # TODO card specific cases

    @Ready
    Scenario Outline: GetToken - Null Parameter
        Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
        And I request a challenge with
            | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       |
            | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx |
        And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
        And I request a code token with SIGNED_CHALLENGE
        And I set the context with key REDIRECT_URI to 'http://redirect.gematik.de/erezept'
        When I request an access token with
            | grant_type   | redirect_uri   | code   | code_verifier   | client_id   |
            | <grant_type> | <redirect_uri> | <code> | <code_verifier> | <client_id> |
        Then the response status is 400
        Examples: GetToken - Null Parameter Beispiele
            | grant_type         | redirect_uri                       | code                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | code_verifier                                                                      | client_id |
            | $NULL              | http://redirect.gematik.de/erezept | eyJhbGciOiJCUDI1NlIxIn0.eyJzdWIiOiJzdWJqZWN0Iiwib3JnYW5pemF0aW9uTmFtZSI6ImdlbWF0aWsgR21iSCBOT1QtVkFMSUQiLCJwcm9mZXNzaW9uT0lEIjoiMS4yLjI3Ni4wLjc2LjQuNDkiLCJpZE51bW1lciI6IlgxMTA0MTE2NzUiLCJpc3MiOiJzZW5kZXIiLCJyZXNwb25zZV90eXBlIjoiY29kZSIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJnaXZlbl9uYW1lIjoiRGFyaXVzIE1pY2hhZWwgQnJpYW4gVWJibyIsImNsaWVudF9pZCI6Im9pZGNfY2xpZW50IiwiYWNyIjoiZWlkYXMtbG9hLWhpZ2giLCJhdWQiOiJlcnAuemVudHJhbC5lcnAudGktZGllbnN0ZS5kZSIsInNjb3BlIjoib3BlbmlkIGUtcmV6ZXB0IiwiYXV0aF90aW1lIjoxNjA3MzQ5MjExLCJyZWRpcmVjdF91cmkiOiJodHRwOmxvY2FsaG9zdDo4MDgwIiwic3RhdGUiOiJ4eHhzdGF0ZXh4eCIsImV4cCI6MTYwNzM1MjgxMSwiZmFtaWx5X25hbWUiOiJCw7ZkZWZlbGQiLCJjb2RlX2NoYWxsZW5nZSI6IkNhM1ZlOGpTc0JRT0JGVnFRdkxzMUUtZEdWMUJYZzJGVHZyZC1UZzE5VmcifQ.RsR3JFqMCFV9I7m8l5SlyTMNGOCF8GeInDEtj9zvBDRCIjjPSYjjHlwiCxYsimYhrcFzr77bpXUjd1BbprzI_Q | drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj | erezept   |
            | authorization_code | $NULL                              | eyJhbGciOiJCUDI1NlIxIn0.eyJzdWIiOiJzdWJqZWN0Iiwib3JnYW5pemF0aW9uTmFtZSI6ImdlbWF0aWsgR21iSCBOT1QtVkFMSUQiLCJwcm9mZXNzaW9uT0lEIjoiMS4yLjI3Ni4wLjc2LjQuNDkiLCJpZE51bW1lciI6IlgxMTA0MTE2NzUiLCJpc3MiOiJzZW5kZXIiLCJyZXNwb25zZV90eXBlIjoiY29kZSIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJnaXZlbl9uYW1lIjoiRGFyaXVzIE1pY2hhZWwgQnJpYW4gVWJibyIsImNsaWVudF9pZCI6Im9pZGNfY2xpZW50IiwiYWNyIjoiZWlkYXMtbG9hLWhpZ2giLCJhdWQiOiJlcnAuemVudHJhbC5lcnAudGktZGllbnN0ZS5kZSIsInNjb3BlIjoib3BlbmlkIGUtcmV6ZXB0IiwiYXV0aF90aW1lIjoxNjA3MzQ5MjExLCJyZWRpcmVjdF91cmkiOiJodHRwOmxvY2FsaG9zdDo4MDgwIiwic3RhdGUiOiJ4eHhzdGF0ZXh4eCIsImV4cCI6MTYwNzM1MjgxMSwiZmFtaWx5X25hbWUiOiJCw7ZkZWZlbGQiLCJjb2RlX2NoYWxsZW5nZSI6IkNhM1ZlOGpTc0JRT0JGVnFRdkxzMUUtZEdWMUJYZzJGVHZyZC1UZzE5VmcifQ.RsR3JFqMCFV9I7m8l5SlyTMNGOCF8GeInDEtj9zvBDRCIjjPSYjjHlwiCxYsimYhrcFzr77bpXUjd1BbprzI_Q | drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj | erezept   |
            | authorization_code | http://redirect.gematik.de/erezept | $NULL                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj | erezept   |
            | authorization_code | http://redirect.gematik.de/erezept | eyJhbGciOiJCUDI1NlIxIn0.eyJzdWIiOiJzdWJqZWN0Iiwib3JnYW5pemF0aW9uTmFtZSI6ImdlbWF0aWsgR21iSCBOT1QtVkFMSUQiLCJwcm9mZXNzaW9uT0lEIjoiMS4yLjI3Ni4wLjc2LjQuNDkiLCJpZE51bW1lciI6IlgxMTA0MTE2NzUiLCJpc3MiOiJzZW5kZXIiLCJyZXNwb25zZV90eXBlIjoiY29kZSIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJnaXZlbl9uYW1lIjoiRGFyaXVzIE1pY2hhZWwgQnJpYW4gVWJibyIsImNsaWVudF9pZCI6Im9pZGNfY2xpZW50IiwiYWNyIjoiZWlkYXMtbG9hLWhpZ2giLCJhdWQiOiJlcnAuemVudHJhbC5lcnAudGktZGllbnN0ZS5kZSIsInNjb3BlIjoib3BlbmlkIGUtcmV6ZXB0IiwiYXV0aF90aW1lIjoxNjA3MzQ5MjExLCJyZWRpcmVjdF91cmkiOiJodHRwOmxvY2FsaG9zdDo4MDgwIiwic3RhdGUiOiJ4eHhzdGF0ZXh4eCIsImV4cCI6MTYwNzM1MjgxMSwiZmFtaWx5X25hbWUiOiJCw7ZkZWZlbGQiLCJjb2RlX2NoYWxsZW5nZSI6IkNhM1ZlOGpTc0JRT0JGVnFRdkxzMUUtZEdWMUJYZzJGVHZyZC1UZzE5VmcifQ.RsR3JFqMCFV9I7m8l5SlyTMNGOCF8GeInDEtj9zvBDRCIjjPSYjjHlwiCxYsimYhrcFzr77bpXUjd1BbprzI_Q | $NULL                                                                              | erezept   |
            | authorization_code | http://redirect.gematik.de/erezept | eyJhbGciOiJCUDI1NlIxIn0.eyJzdWIiOiJzdWJqZWN0Iiwib3JnYW5pemF0aW9uTmFtZSI6ImdlbWF0aWsgR21iSCBOT1QtVkFMSUQiLCJwcm9mZXNzaW9uT0lEIjoiMS4yLjI3Ni4wLjc2LjQuNDkiLCJpZE51bW1lciI6IlgxMTA0MTE2NzUiLCJpc3MiOiJzZW5kZXIiLCJyZXNwb25zZV90eXBlIjoiY29kZSIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJnaXZlbl9uYW1lIjoiRGFyaXVzIE1pY2hhZWwgQnJpYW4gVWJibyIsImNsaWVudF9pZCI6Im9pZGNfY2xpZW50IiwiYWNyIjoiZWlkYXMtbG9hLWhpZ2giLCJhdWQiOiJlcnAuemVudHJhbC5lcnAudGktZGllbnN0ZS5kZSIsInNjb3BlIjoib3BlbmlkIGUtcmV6ZXB0IiwiYXV0aF90aW1lIjoxNjA3MzQ5MjExLCJyZWRpcmVjdF91cmkiOiJodHRwOmxvY2FsaG9zdDo4MDgwIiwic3RhdGUiOiJ4eHhzdGF0ZXh4eCIsImV4cCI6MTYwNzM1MjgxMSwiZmFtaWx5X25hbWUiOiJCw7ZkZWZlbGQiLCJjb2RlX2NoYWxsZW5nZSI6IkNhM1ZlOGpTc0JRT0JGVnFRdkxzMUUtZEdWMUJYZzJGVHZyZC1UZzE5VmcifQ.RsR3JFqMCFV9I7m8l5SlyTMNGOCF8GeInDEtj9zvBDRCIjjPSYjjHlwiCxYsimYhrcFzr77bpXUjd1BbprzI_Q | drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj | $NULL     |

    @Ready
    Scenario Outline: GetToken - Fehlende Parameter
        Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
        And I request a challenge with
            | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       |
            | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx |
        And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
        And I request a code token with SIGNED_CHALLENGE
        When I request an access token with
            | grant_type   | redirect_uri   | code   | code_verifier   | client_id   |
            | <grant_type> | <redirect_uri> | <code> | <code_verifier> | <client_id> |
        Then the response status is 400

        Examples: GetToken - Fehlende Parameter Beispiele
            | grant_type         | redirect_uri                       | code                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | code_verifier                                                                      | client_id |
            | $REMOVE            | http://redirect.gematik.de/erezept | eyJhbGciOiJCUDI1NlIxIn0.eyJzdWIiOiJzdWJqZWN0Iiwib3JnYW5pemF0aW9uTmFtZSI6ImdlbWF0aWsgR21iSCBOT1QtVkFMSUQiLCJwcm9mZXNzaW9uT0lEIjoiMS4yLjI3Ni4wLjc2LjQuNDkiLCJpZE51bW1lciI6IlgxMTA0MTE2NzUiLCJpc3MiOiJzZW5kZXIiLCJyZXNwb25zZV90eXBlIjoiY29kZSIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJnaXZlbl9uYW1lIjoiRGFyaXVzIE1pY2hhZWwgQnJpYW4gVWJibyIsImNsaWVudF9pZCI6Im9pZGNfY2xpZW50IiwiYWNyIjoiZWlkYXMtbG9hLWhpZ2giLCJhdWQiOiJlcnAuemVudHJhbC5lcnAudGktZGllbnN0ZS5kZSIsInNjb3BlIjoib3BlbmlkIGUtcmV6ZXB0IiwiYXV0aF90aW1lIjoxNjA3MzQ5MjExLCJyZWRpcmVjdF91cmkiOiJodHRwOmxvY2FsaG9zdDo4MDgwIiwic3RhdGUiOiJ4eHhzdGF0ZXh4eCIsImV4cCI6MTYwNzM1MjgxMSwiZmFtaWx5X25hbWUiOiJCw7ZkZWZlbGQiLCJjb2RlX2NoYWxsZW5nZSI6IkNhM1ZlOGpTc0JRT0JGVnFRdkxzMUUtZEdWMUJYZzJGVHZyZC1UZzE5VmcifQ.RsR3JFqMCFV9I7m8l5SlyTMNGOCF8GeInDEtj9zvBDRCIjjPSYjjHlwiCxYsimYhrcFzr77bpXUjd1BbprzI_Q | drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj | erezept   |
            | authorization_code | $REMOVE                            | eyJhbGciOiJCUDI1NlIxIn0.eyJzdWIiOiJzdWJqZWN0Iiwib3JnYW5pemF0aW9uTmFtZSI6ImdlbWF0aWsgR21iSCBOT1QtVkFMSUQiLCJwcm9mZXNzaW9uT0lEIjoiMS4yLjI3Ni4wLjc2LjQuNDkiLCJpZE51bW1lciI6IlgxMTA0MTE2NzUiLCJpc3MiOiJzZW5kZXIiLCJyZXNwb25zZV90eXBlIjoiY29kZSIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJnaXZlbl9uYW1lIjoiRGFyaXVzIE1pY2hhZWwgQnJpYW4gVWJibyIsImNsaWVudF9pZCI6Im9pZGNfY2xpZW50IiwiYWNyIjoiZWlkYXMtbG9hLWhpZ2giLCJhdWQiOiJlcnAuemVudHJhbC5lcnAudGktZGllbnN0ZS5kZSIsInNjb3BlIjoib3BlbmlkIGUtcmV6ZXB0IiwiYXV0aF90aW1lIjoxNjA3MzQ5MjExLCJyZWRpcmVjdF91cmkiOiJodHRwOmxvY2FsaG9zdDo4MDgwIiwic3RhdGUiOiJ4eHhzdGF0ZXh4eCIsImV4cCI6MTYwNzM1MjgxMSwiZmFtaWx5X25hbWUiOiJCw7ZkZWZlbGQiLCJjb2RlX2NoYWxsZW5nZSI6IkNhM1ZlOGpTc0JRT0JGVnFRdkxzMUUtZEdWMUJYZzJGVHZyZC1UZzE5VmcifQ.RsR3JFqMCFV9I7m8l5SlyTMNGOCF8GeInDEtj9zvBDRCIjjPSYjjHlwiCxYsimYhrcFzr77bpXUjd1BbprzI_Q | drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj | erezept   |
            | authorization_code | http://redirect.gematik.de/erezept | $REMOVE                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj | erezept   |
            | authorization_code | http://redirect.gematik.de/erezept | eyJhbGciOiJCUDI1NlIxIn0.eyJzdWIiOiJzdWJqZWN0Iiwib3JnYW5pemF0aW9uTmFtZSI6ImdlbWF0aWsgR21iSCBOT1QtVkFMSUQiLCJwcm9mZXNzaW9uT0lEIjoiMS4yLjI3Ni4wLjc2LjQuNDkiLCJpZE51bW1lciI6IlgxMTA0MTE2NzUiLCJpc3MiOiJzZW5kZXIiLCJyZXNwb25zZV90eXBlIjoiY29kZSIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJnaXZlbl9uYW1lIjoiRGFyaXVzIE1pY2hhZWwgQnJpYW4gVWJibyIsImNsaWVudF9pZCI6Im9pZGNfY2xpZW50IiwiYWNyIjoiZWlkYXMtbG9hLWhpZ2giLCJhdWQiOiJlcnAuemVudHJhbC5lcnAudGktZGllbnN0ZS5kZSIsInNjb3BlIjoib3BlbmlkIGUtcmV6ZXB0IiwiYXV0aF90aW1lIjoxNjA3MzQ5MjExLCJyZWRpcmVjdF91cmkiOiJodHRwOmxvY2FsaG9zdDo4MDgwIiwic3RhdGUiOiJ4eHhzdGF0ZXh4eCIsImV4cCI6MTYwNzM1MjgxMSwiZmFtaWx5X25hbWUiOiJCw7ZkZWZlbGQiLCJjb2RlX2NoYWxsZW5nZSI6IkNhM1ZlOGpTc0JRT0JGVnFRdkxzMUUtZEdWMUJYZzJGVHZyZC1UZzE5VmcifQ.RsR3JFqMCFV9I7m8l5SlyTMNGOCF8GeInDEtj9zvBDRCIjjPSYjjHlwiCxYsimYhrcFzr77bpXUjd1BbprzI_Q | $REMOVE                                                                            | erezept   |
            | authorization_code | http://redirect.gematik.de/erezept | eyJhbGciOiJCUDI1NlIxIn0.eyJzdWIiOiJzdWJqZWN0Iiwib3JnYW5pemF0aW9uTmFtZSI6ImdlbWF0aWsgR21iSCBOT1QtVkFMSUQiLCJwcm9mZXNzaW9uT0lEIjoiMS4yLjI3Ni4wLjc2LjQuNDkiLCJpZE51bW1lciI6IlgxMTA0MTE2NzUiLCJpc3MiOiJzZW5kZXIiLCJyZXNwb25zZV90eXBlIjoiY29kZSIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJnaXZlbl9uYW1lIjoiRGFyaXVzIE1pY2hhZWwgQnJpYW4gVWJibyIsImNsaWVudF9pZCI6Im9pZGNfY2xpZW50IiwiYWNyIjoiZWlkYXMtbG9hLWhpZ2giLCJhdWQiOiJlcnAuemVudHJhbC5lcnAudGktZGllbnN0ZS5kZSIsInNjb3BlIjoib3BlbmlkIGUtcmV6ZXB0IiwiYXV0aF90aW1lIjoxNjA3MzQ5MjExLCJyZWRpcmVjdF91cmkiOiJodHRwOmxvY2FsaG9zdDo4MDgwIiwic3RhdGUiOiJ4eHhzdGF0ZXh4eCIsImV4cCI6MTYwNzM1MjgxMSwiZmFtaWx5X25hbWUiOiJCw7ZkZWZlbGQiLCJjb2RlX2NoYWxsZW5nZSI6IkNhM1ZlOGpTc0JRT0JGVnFRdkxzMUUtZEdWMUJYZzJGVHZyZC1UZzE5VmcifQ.RsR3JFqMCFV9I7m8l5SlyTMNGOCF8GeInDEtj9zvBDRCIjjPSYjjHlwiCxYsimYhrcFzr77bpXUjd1BbprzI_Q | drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj | $REMOVE   |

    @Ready
    Scenario: GetToken - Scope openid ohne SSO Token
        Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
        And I request a challenge with
            | client_id  | scope  | code_challenge                              | code_challenge_method | redirect_uri                       | state       |
            | eRezeptApp | openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx |
        And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
        And I request a code token with SIGNED_CHALLENGE
        And I set the context with key REDIRECT_URI to 'http://redirect.gematik.de/erezept'
        When I request an access token
        Then the response status is 200
        And the JSON response should match
        """
            {
                "expires_in": 300,
                "token_type": "Bearer",
                "id_token": "ey.*",
                "access_token": null,
                "sso_token": null
            }
        """
