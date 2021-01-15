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
Feature: Autorisiere Anwendung am IDP Server
    Frontends von TI Diensten müssen vom IDP Server über ein HTTP POST an den Authorization Endpoint ein Code Token abfragen können.

    Background: Initialisiere Testkontext durch Abfrage des Discovery Dokuments
        Given I initialize scenario from discovery document endpoint


    @ReleaseV1
    # TODO add NONCE to request
    Scenario: Author - Validiere signierte Challenge

    ```
    Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an und signieren diesen.
    Die signierte Challenge muss:

    - die richtigen Claims im Token haben

        Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
        And I request a challenge with
            | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       |
            | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx |
        When I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
        And I extract the header claims from token SIGNED_CHALLENGE
        Then the header claims should match in any order
            """
            {
                "alg": "BP256R1",
                "typ": "JWT",
                "cty": "NJWT",
                "x5c": "${json-unit.ignore}"
            }
            """
            # TODO RISE alg ist mit PS256 im LG003
        When I extract the body claims from token SIGNED_CHALLENGE
        Then the body claims should match in any order
            """
            {
                "njwt": "${json-unit.ignore}"
            }
            """

    @Afo:A_20699
    @Afo:A_20951
    @Afo:A_20460
    @ReleaseV1
    # TODO add NONCE to request
    Scenario: Author - Gutfall ohne SSO Token

    ```
    Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, signieren diesen und
    fordern einen TOKEN_CODE mit der signierten Challenge an.

    Die TOKEN_CODE Antwort muss

    - den Code 302
    - die richtigen HTTP Header
    - im Location header state, code und SSO Token als Query Parameter enthalten
    - die richtigen Claims im Token haben.


        Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
        And I request a challenge with
            | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       |
            | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx |
        And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'

        When I request a code token with SIGNED_CHALLENGE
        Then the response status is 302
        And the response http headers match
            """
            Cache-Control=no-store
            Pragma=no-cache
            Content-Length=0
            Location=http.*code=.*
            """
        When I extract the header claims from token TOKEN_CODE
        Then the header claims should match in any order
            """
            {
                "alg": "BP256R1",
                "typ": "JWT",
                "cty": "NJWT",
                "jti": "${json-unit.ignore}",
                "exp": "[\\d]*"
            }
            """
            # TODO remove "cty": "NJWT",

        When I extract the body claims from token TOKEN_CODE
        Then the body claims should match in any order
            """
            {
                "scope": "(e-rezept openid|openid e-rezept)",
                "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
                "response_type": "code",
                "code_challenge_method": "S256",
                "redirect_uri": "http://redirect.gematik.de/erezept",
                "state": "xxxstatexxx",
                "client_id": "eRezeptApp",
                "code_challenge": "Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg",
                "sub": "${json-unit.ignore}",
                "aud": "https://erp.zentral.erp.splitdns.ti-dienste.de",
                "nbf": "[\\d]*",
                "exp": "[\\d]*",
                "iat": "[\\d]*",
                "professionOID": "1\\.2\\.276\\.0\\.76\\.4\\.(3\\d|4\\d|178|23[2-90]|240|241)",
                "given_name": "(.{1,64})",
                "family_name": "(.{1,64})",
                "organizationName": "(.{1,64})",
                "idNummer": "[A-Z][\\d]{9,10}",
                "acr": "${json-unit.ignore}",
                "auth_time": "${json-unit.ignore}"
            }
            """
        # TODO Inhalt ist laut Spec nicht vorgegeben, daher evt. nur für Referenzimplementierung relevant
        # TODO RISE antwortet zusätzlich mit snc, client_id, nonce, token_type, dafür fehlt acr, sub, aud

        And I expect the Context with key STATE to match 'xxxstatexxx'
        And I expect the Context with key SSO_TOKEN to match '.*'

    @Afo:A_20946
    @Afo:A_20950
    @ReleaseV1
    Scenario: Author - Gutfall mit SSO Token

    ```
    Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, signieren diesen und
    fordern einen TOKEN_CODE mit der signierten Challenge an.
    Dann löschen wir den Context mit Ausnahme des erhaltenen SSO Tokens und wiederholen die Schritte nur fordern wir nun
    einen TOKEN_CODE mit dem SSO Token an.

    Die TOKEN_CODE Antwort muss

    - den Code 302
    - die richtigen HTTP Header
    - im Location header state, code aber NICHT SSO Token als Query Parameter enthalten
    - die richtigen Claims im Token haben.


        Given I choose code verifier 'sfnejkgsjknsfeknsknvgsrlgmreklgmnksrnvgjksnvgseklgvsrklmslrkbmsrklgnrvsgklsrgnksrf'
        And I request a challenge with
            | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state        |
            | eRezeptApp | e-rezept openid | ds7JaEfpdLidWekR52OhoVpjXHDlplLyV3GtUezxfY0 | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx1 |
        And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
        And I request a code token with SIGNED_CHALLENGE
        And the response status is 302
        And I start new interaction keeping only SSO_TOKEN
        And I initialize scenario from discovery document endpoint
        And I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
        And I request a challenge with
            | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state        |
            | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx2 |
        When I request a code token with SSO_TOKEN
        # TODO RISE zu klären: Request Parameter ist wohl unsigned_challenge statt challenge_token
        Then the response status is 302
        And the response http headers match
            """
            Cache-Control=no-store
            Pragma=no-cache
            Content-Length=0
            Location=http.*code=.*
            """
        When I extract the header claims from token TOKEN_CODE
        Then the header claims should match in any order
            """
            {
                "alg": "BP256R1",
                "typ": "JWT",
                "jti": "${json-unit.ignore}",
                "exp": "[\\d]*"
            }
            """

        When I extract the body claims from token TOKEN_CODE
        Then the body claims should match in any order
            """
            {
                "scope": "(e-rezept openid|openid e-rezept)",
                "code_challenge_method": "S256",
                "redirect_uri": "http://redirect.gematik.de/erezept",
                "client_id": "eRezeptApp",
                "code_challenge": "Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg",
                "exp": "[\\d]*",
                "response_type": "code",
                "state": "xxxstatexxx2",
                "sub": "${json-unit.ignore}",
                "professionOID": "1\\.2\\.276\\.0\\.76\\.4\\.(3\\d|4\\d|178|23[2-90]|240|241)",
                "given_name": "(.{1,64})",
                "family_name": "(.{1,64})",
                "organizationName": "(.{1,64})",
                "idNummer": "[A-Z][\\d]{9,10}",
                "acr": "${json-unit.ignore}",
                "auth_time": "${json-unit.ignore}"
            }
            """

        And I expect the Context with key SSO_TOKEN to match '$NULL'
        And I expect the Context with key STATE to match 'xxxstatexxx2'


    @Afo:A_20624
    @Afo:A_20319
    @Signature
    Scenario: Author - Validiere Signatur des Code Token mit signierter Challenge

    ```
    Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, signieren diesen und
    fordern einen TOKEN_CODE mit der signierten Challenge an.

    Der Code Token muss mit dem Auth Zertifikat gültig signiert sein.

        Given I retrieve public keys from URIs
        And I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
        And I request a challenge with
            | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       |
            | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx |
        And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
        When I request a code token with SIGNED_CHALLENGE
        Then the context TOKEN_CODE must be signed with cert PUK_AUTH


    @Afo:A_20624
    @Afo:A_20319
    @Signature
    Scenario: Author - Validiere Signatur des Code Token mit SSO Token

    ```
    Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, signieren diesen und
    fordern einen TOKEN_CODE mit der signierten Challenge an.
    Dann löschen wir den Context mit Ausnahme des erhaltenen SSO Tokens und wiederholen die Schritte nur fordern wir nun
    einen TOKEN_CODE mit dem SSO Token an.

    Der Code Token muss mit dem Auth Zertifikat gültig signiert sein.


        Given I choose code verifier 'sfnejkgsjknsfeknsknvgsrlgmreklgmnksrnvgjksnvgseklgvsrklmslrkbmsrklgnrvsgklsrgnksrf'
        And I request a challenge with
            | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state        |
            | eRezeptApp | e-rezept openid | ds7JaEfpdLidWekR52OhoVpjXHDlplLyV3GtUezxfY0 | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx1 |
        And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
        And I request a code token with SIGNED_CHALLENGE
        And the response status is 302
        And I start new interaction keeping only SSO_TOKEN
        And I initialize scenario from discovery document endpoint
        And I retrieve public keys from URIs
        And I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
        And I request a challenge with
            | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state        |
            | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx2 |
        When I request a code token with SSO_TOKEN
        Then the context TOKEN_CODE must be signed with cert PUK_AUTH

    # ------------------------------------------------------------------------------------------------------------------
    #
    # negative cases

    @Ready
    Scenario: Author - Aufruf ohne Parameter

    ```
    Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an und
    fordern dann einen TOKEN_CODE an, ohne einen Parameter (SSO Token oder signierte Challenge) mitzugeben.

    Der Server muss diese Anfrage mit HTTP Status 400 ablehnen.


        Given I choose code verifier 'sfnejkgsjknsfeknsknvgsrlgmreklgmnksrnvgjksnvgseklgvsrklmslrkbmsrklgnrvsgklsrgnksrf'
        And I request a challenge with
            | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state        |
            | eRezeptApp | e-rezept openid | ds7JaEfpdLidWekR52OhoVpjXHDlplLyV3GtUezxfY0 | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx1 |
        When I request a code token with NO_PARAMS
        Then  the response status is 400
        # TODO AuthError über 302 retournieren - https://openid.net/specs/openid-connect-core-1_0.html#AuthError

    @Ready
    Scenario: Author - Challenge Token fehlt beim SSO Token Aufruf

    ```
    Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, signieren diesen und
    fordern einen TOKEN_CODE mit der signierten Challenge an.
    Dann löschen wir den Context mit Ausnahme des erhaltenen SSO Tokens und wiederholen die Schritte nur fordern wir nun
    einen TOKEN_CODE mit dem SSO Token an, ohne den Challenge Token als Parameter mitzugeben.

    Der Server muss diese Anfrage mit HTTP Status 400 ablehnen.


        Given I choose code verifier 'sfnejkgsjknsfeknsknvgsrlgmreklgmnksrnvgjksnvgseklgvsrklmslrkbmsrklgnrvsgklsrgnksrf'
        And I request a challenge with
            | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state        |
            | eRezeptApp | e-rezept openid | ds7JaEfpdLidWekR52OhoVpjXHDlplLyV3GtUezxfY0 | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx1 |
        And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
        And I request a code token with SIGNED_CHALLENGE
        And the response status is 302
        And I start new interaction keeping only SSO_TOKEN
        And I initialize scenario from discovery document endpoint
        And I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
        And I request a challenge with
            | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state        |
            | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx2 |
        When I request a code token with SSO_TOKEN_NO_CHALLENGE
        Then the response status is 400
        # TODO AuthError über 302 retournieren - https://openid.net/specs/openid-connect-core-1_0.html#AuthError


    @Ready
    @OpenBug
    @issue:IDP-368
    Scenario: Author - Schlechtfall Challenge mit abgelaufenem Zertifikat signiert

    ```
    Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, signieren diesen
    mit einem ABGELAUFENEN Zertifikat und fordern einen TOKEN_CODE mit der signierten Challenge an.

    Der Server muss diese Anfrage mit HTTP Status 400 ablehnen.


        Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
        And I request a challenge with
            | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       |
            | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx |
        When I sign the challenge with '/certs/invalid/smcb-idp-expired.p12'
        And I request a code token with SIGNED_CHALLENGE
        Then the response status is 400
        # TODO AuthError über 302 retournieren - https://openid.net/specs/openid-connect-core-1_0.html#AuthError

    @Afo:A_20951
    @Afo:A_20318
    @Ready
    @OpenBug
    @issue:IDP-368
    Scenario: Author - Schlechtfall Challenge mit gesperrtem Zertifikat signiert

    ```
    Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, signieren diesen
    mit einem GESPERRTEN Zertifikat und fordern einen TOKEN_CODE mit der signierten Challenge an.

    Der Server muss diese Anfrage mit HTTP Status 400 ablehnen.


        Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
        And I request a challenge with
            | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       |
            | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx |
        When I sign the challenge with '/certs/invalid/smcb-idp-revoked.p12'
        And I request a code token with SIGNED_CHALLENGE
        Then the response status is 400
        # TODO AuthError über 302 retournieren - https://openid.net/specs/openid-connect-core-1_0.html#AuthError

    @Ready
    @OpenBug
    @issue:IDP-368
    Scenario: Author - Schlechtfall Challenge mit selbst signiertem Zertifikat signiert

    ```
    Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, signieren diesen
    mit einem SELBST SIGNIERTEN Zertifikat und fordern einen TOKEN_CODE mit der signierten Challenge an.

    Der Server muss diese Anfrage mit HTTP Status 400 ablehnen.


        Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
        And I request a challenge with
            | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       |
            | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx |
        When I sign the challenge with '/certs/invalid/smcb-idp-selfsigned.p12'
        And I request a code token with SIGNED_CHALLENGE
        Then the response status is 400
        # TODO AuthError über 302 retournieren - https://openid.net/specs/openid-connect-core-1_0.html#AuthError

    @Afo:A_20951
    @Afo:A_20460
    @Ready
    Scenario: Author - Schlechtfall Fehlerhafte Signatur der SIGNED_CHALLENGE (Keine Signatur)

    ```
    Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, ändern den Inhalt zu einem Text der
    definitiv nicht signiert ist und fordern einen TOKEN_CODE mit dieser Challenge an.

    Der Server muss diese Anfrage mit HTTP Status 400 ablehnen.


        Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
        And I request a challenge with
            | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       |
            | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx |
        When I set the context with key SIGNED_CHALLENGE to 'invalid signed challenge for sure'
        And I request a code token with SIGNED_CHALLENGE
        Then the response status is 400
        # TODO AuthError über 302 retournieren - https://openid.net/specs/openid-connect-core-1_0.html#AuthError

    @Ready
    Scenario: Author - Schlechtfall Falscher Inhalt in der signierten Challenge

    ```
    Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, modifizieren den Inhalt, der definitiv falsch ist.
    Signieren diesen und fordern einen TOKEN_CODE mit der signierten falschen Challenge an.

    Der Server muss diese Anfrage mit HTTP Status 400 ablehnen.


        Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
        And I request a challenge with
            | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       |
            | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx |
        When I set the context with key CHALLENGE to 'malicious content test'
        And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
        And I request a code token with SIGNED_CHALLENGE
        Then the response status is 400
        # TODO AuthError über 302 retournieren - https://openid.net/specs/openid-connect-core-1_0.html#AuthError

    @Afo:A_20951
    @Afo:A_20460
    @Ready
    Scenario: Author - Schlechtfall Invalide Signatur

    ```
    Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, signieren diesen und
    flippen im signierten Challenge ein signifikantes bit.
    Dann fordern wir einen TOKEN_CODE mit der signierten falschen Challenge an.

    Der Server muss diese Anfrage mit HTTP Status 400 ablehnen.


        Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
        And I request a challenge with
            | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       |
            | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx |
        When I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
        #flipping bits seems to be tricky. due to bits as bytes and bytes as base64 the last couple of bits may or may not have influence on the signature
        And I flip bit -20 on context with key SIGNED_CHALLENGE
        And I request a code token with SIGNED_CHALLENGE
        Then the response status is 400
        # TODO AuthError über 302 retournieren - https://openid.net/specs/openid-connect-core-1_0.html#AuthError

    @Afo:A_20948
    @WiP
    Scenario: Author - Schlechtfall Anfrage mit modifiziertem SSO Token

    ```
    Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, signieren diesen und
    fordern einen TOKEN_CODE mit der signierten Challenge an.
    Dann löschen wir den Context mit Ausnahme des erhaltenen SSO Tokens, modifizieren diesen und wiederholen die
    Schritte nur fordern wir nun einen TOKEN_CODE mit dem modifizierten SSO Token an.

    Die Server muss diese Anfrage mit HTTP Status 400 ablehnen.


        Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
        And I request a challenge with
            | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       |
            | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx |
        # TODO first perform with signed challenge then modify sso token then retry with modified sso token
        # TODO how to modify the sso token to ensure that the idp checks the signature correctly
        When I request a code token with SSO_TOKEN
        Then the response status is 302
        # TODO AuthError über 302 retournieren - https://openid.net/specs/openid-connect-core-1_0.html#AuthError
        # TODO validate response
