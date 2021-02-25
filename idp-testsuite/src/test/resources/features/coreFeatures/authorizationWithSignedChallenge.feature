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
Feature: Autorisiere Anwendung am IDP Server mit signierter Challenge
  Frontends von TI Diensten müssen vom IDP Server über ein HTTP POST an den Authorization Endpoint ein Code Token abfragen können.

  Background: Initialisiere Testkontext durch Abfrage des Discovery Dokuments
    Given I initialize scenario from discovery document endpoint
    And I retrieve public keys from URIs


  @Approval @Ready
  Scenario: Author - Validiere signierte Challenge BP256R1

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an und signieren diesen.
  Die signierte Challenge muss:

  - die richtigen Claims im Token haben

    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 1234  | code          |

    When I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And I extract the header claims from token SIGNED_CHALLENGE
    Then the header claims should match in any order
        """
          { alg: "BP256R1",
            cty: "NJWT",
            typ: "JWT",
            x5c: "${json-unit.ignore}"
          }
        """
    When I extract the body claims from token SIGNED_CHALLENGE
    Then the body claims should match in any order
        """
          {
            njwt: "${json-unit.ignore}"
          }
        """

  @WiP
  @Approval @Todo:ImplementRSASigning
  Scenario: Author - Validiere signierte Challenge PS256

    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 1234  | code          |
    #When I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    #And I extract the header claims from token SIGNED_CHALLENGE
    #Then the header claims should match in any order
  #"""
  #          {
  #              "alg": "BP256R1",
  #              "typ": "JWT",
  #              "cty": "NJWT",
  #              "x5c": "${json-unit.ignore}"
  #          }
  #          """
    #When I extract the body claims from token SIGNED_CHALLENGE
    #Then the body claims should match in any order
  #"""
  #          {
  #              "njwt": "${json-unit.ignore}"
  #          }
  #          """

  @Afo:A_20699-1 @Afo:A_20951-1 @Afo:A_20460
  @Approval @Todo:ClarifyTokenCodeContentRelevant
  Scenario: Author mit signierter Challenge - Gutfall - Validiere Antwortstruktur

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, signieren diesen und
  fordern einen TOKEN_CODE mit der signierten Challenge an.

  Die TOKEN_CODE Antwort muss den Code 302 und die richtigen HTTP Header haben.


    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 12345 | code          |
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

  @WiP
  @ToDo:ServerConfiguration
  Scenario: Author mit signierter Challenge für Client ohne SSL Token - Gutfall - Validiere Antwortstruktur

  ```
  Wir wählen einen gültigen Code verifier für einen registrierten Client der kein SSL Token zurückbekommen darf.
  Wir fordern einen Challenge Token an, signieren diesen und fordern einen TOKEN_CODE mit der signierten Challenge an.

  Die TOKEN_CODE Antwort muss den Code 302, die richtigen HTTP Header und keinen SSO Token haben.


    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id     | scope           | code_challenge                              | code_challenge_method | redirect_uri                      | state       | nonce | response_type |
      | gematikTestPs | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://test-ps.gematik.de/erezept | xxxstatexxx | 12345 | code          |
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
    And I expect the Context with key SSO_TOKEN to match '$NULL'

  @Afo:A_20699-1 @Afo:A_20951-1 @Afo:A_20460 @Afo:A_20731 @Afo:A_20310 @Afo:A_20377 @Afo:A_20697 @Afo:A_21317
  @Approval @Todo:ClarifyTokenCodeContentRelevant @Todo:CompareSubjectInfosInTokenAndInCert
  Scenario: Author mit signierter Challenge - Gutfall - Validiere Location Header und Code Token Claims

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, signieren diesen und
  fordern einen TOKEN_CODE mit der signierten Challenge an.

  Die TOKEN_CODE Antwort muss im Location header state, code und SSO Token als Query Parameter enthalten und
  die richtigen Claims im Token haben.


    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 12345 | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And I request a code token with signed challenge

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
        {
            auth_time:             "${json-unit.ignore}",
            client_id:             "eRezeptApp",
            code_challenge:        "Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg",
            code_challenge_method: "S256",
            exp:                   "[\\d]*",
            jti:                   "${json-unit.ignore}",
            family_name:           "(.{1,64})",
            given_name:            "(.{1,64})",
            iat:                   "[\\d]*",
            idNummer:              "[A-Z][\\d]{9,10}",
            iss:                   "https://idp.zentral.idp.splitdns.ti-dienste.de",
            nbf:                   "[\\d]*",
            nonce:                 "12345",
            organizationName:      "(.{1,64})",
            professionOID:         "1\\.2\\.276\\.0\\.76\\.4\\.(3\\d|4\\d|178|23[2-90]|240|241)",
            redirect_uri:          "http://redirect.gematik.de/erezept",
            response_type:         "code",
            scope:                 "(e-rezept openid|openid e-rezept)",
            snc:                   ".*",
            state:                 "xxxstatexxx",
            token_type:            "code"
        }
        """
        # TODO Inhalt ist laut Spec nicht vorgegeben, daher evt. nur für Referenzimplementierung relevant


  @Afo:A_20624 @Afo:A_20319
  @Approval @Ready
  @Signature
  Scenario: Author mit signierter Challenge - Validiere Signatur des Code Token

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, signieren diesen und
  fordern einen TOKEN_CODE mit der signierten Challenge an.

  Der Code Token muss mit dem Auth Zertifikat gültig signiert sein.

    Given I retrieve public keys from URIs
    And I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 3333  | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'

    When I request a code token with signed challenge
    Then the context TOKEN_CODE must be signed with cert PUK_SIGN

  @Afo:A_20695
  @Approval @Ready
  @Signature
  Scenario: Author mit signierter Challenge - Validiere Signatur des SSO Token

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, signieren diesen und
  fordern einen TOKEN_CODE und einen SSO_TOKEN mit der signierten Challenge an.

  Der SSO Token muss mit dem Auth Zertifikat gültig signiert sein.

    Given I retrieve public keys from URIs
    And I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 3333  | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'

    When I request a code token with signed challenge
    Then the context SSO_TOKEN must be signed with cert PUK_SIGN

  @Afo:A_20314
  @Approval @Ready
  @Timeout
  @LongRunning
  Scenario: Author mit signierter Challenge - Veralteter Challenge Token wird abgelehnt

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, signieren diesen, warten 3 Minuten und
  fordern dann einen TOKEN_CODE mit der signierten Challenge an.

  Der Server muss diese Anfrage mit einem Timeout Fehler ablehnen.

    Given I retrieve public keys from URIs
    And I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 3333  | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'

    When I wait PT3M5S
    And I request a code token with signed challenge
    Then the response is an 302 error with code 'invalid_request' and message matching 'The%20given%20JWT%20has%20expired%20and%20is%20no%20longer%20valid%20%28exp%20is%20in%20the%20past%29'



    # ------------------------------------------------------------------------------------------------------------------
    #
    # negative cases

  @Approval @Ready
  Scenario: Author mit signierter Challenge - Aufruf ohne Parameter

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an und
  fordern dann einen TOKEN_CODE an, ohne einen Parameter (SSO Token oder signierte Challenge) mitzugeben.

  Der Server muss diese Anfrage mit HTTP Status 302 und einer Fehlermeldung im Location Header ablehnen.


    Given I choose code verifier 'sfnejkgsjknsfeknsknvgsrlgmreklgmnksrnvgjksnvgseklgvsrklmslrkbmsrklgnrvsgklsrgnksrf'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state        | nonce | response_type |
      | eRezeptApp | e-rezept openid | ds7JaEfpdLidWekR52OhoVpjXHDlplLyV3GtUezxfY0 | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx1 | 1212  | code          |

    When I request a code token with no params
    Then the response is an 302 error with code 'invalid_request' and message matching 'validateChallengeAndGetTokenCode.signedChallenge%3A%20must%20not%20be%20null'


  @Afo:A_20951-1
  @Approval @Todo:ErrorMessages
  Scenario: Author mit signierter Challenge - Challenge mit abgelaufenem Zertifikat signiert

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, signieren diesen
  mit einem ABGELAUFENEN Zertifikat und fordern einen TOKEN_CODE mit der signierten Challenge an.

  Der Server muss diese Anfrage mit HTTP Status 302 und einer Fehlermeldung im Location Header ablehnen.


    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 3344  | code          |

    When I sign the challenge with '/certs/invalid/smcb-idp-expired.p12'
    And I request a code token with signed challenge
    Then the response is an 302 error with code 'invalid_request' and message matching 'Error%20while%20verifying%20client%20certificate'

  @Afo:A_20951-1 @Afo:A_20318 @Afo:A_20465
  @OpenBug @TODO:OCSPChecks
  @Approval
  Scenario: Author mit signierter Challenge - Challenge mit gesperrtem Zertifikat signiert

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, signieren diesen
  mit einem GESPERRTEN Zertifikat und fordern einen TOKEN_CODE mit der signierten Challenge an.

  Der Server muss diese Anfrage mit HTTP Status 302 und einer Fehlermeldung im Location Header ablehnen.


    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 0101  | code          |

    When I sign the challenge with '/certs/invalid/smcb-idp-revoked.p12'
    And I request a code token with signed challenge
    Then the response is an 302 error with code 'invalid_request' and message matching 'TODO'

  @Afo:A_20951-1
  @Approval
  Scenario: Author mit signierter Challenge - Challenge mit selbst signiertem Zertifikat signiert

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, signieren diesen
  mit einem SELBST SIGNIERTEN Zertifikat und fordern einen TOKEN_CODE mit der signierten Challenge an.

  Der Server muss diese Anfrage mit HTTP Status 302 und einer Fehlermeldung im Location Header ablehnen.


    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 0011  | code          |

    When I sign the challenge with '/certs/invalid/smcb-idp-selfsigned.p12'
    And I request a code token with signed challenge
    Then the response is an 302 error with code 'invalid_request' and message matching 'Error%20while%20verifying%20client%20certificate'

  @Afo:A_20951-1 @Afo:A_20460
  @Approval @Ready
  Scenario: Author mit signierter Challenge - Fehlerhafte Signatur der SIGNED_CHALLENGE (Keine Signatur)

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, ändern den Inhalt zu einem Text der
  definitiv nicht signiert ist und fordern einen TOKEN_CODE mit dieser Challenge an.

  Der Server muss diese Anfrage mit HTTP Status 302 und einer Fehlermeldung im Location Header ablehnen.


    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce  | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 110011 | code          |

    When I set the context with key SIGNED_CHALLENGE to 'invalid signed challenge for sure'
    And I request a code token with signed challenge
    Then the response is an 302 error with code 'invalid_request' and message matching '.*Error%20during%20JOSE-operations.*'

  @Approval @Ready
  Scenario: Author mit signierter Challenge - Falscher Inhalt in der signierten Challenge

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, modifizieren den Inhalt, der definitiv falsch ist.
  Signieren diesen und fordern einen TOKEN_CODE mit der signierten falschen Challenge an.

  Der Server muss diese Anfrage mit HTTP Status 302 und einer Fehlermeldung im Location Header ablehnen.


    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce  | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 220022 | code          |

    When I set the context with key CHALLENGE to 'malicious content test'
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And I request a code token with signed challenge
    Then the response is an 302 error with code 'invalid_request' and message matching '.*Error%20during%20JOSE-operations.*'

  @Afo:A_20951-1 @Afo:A_20460
  @Approval @Ready
  Scenario: Author mit signierter Challenge - Invalide Signatur

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, signieren diesen und
  flippen im signierten Challenge ein signifikantes bit.
  Dann fordern wir einen TOKEN_CODE mit der signierten falschen Challenge an.

  Der Server muss diese Anfrage mit HTTP Status 302 und einer Fehlermeldung im Location Header ablehnen.


    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 3322  | code          |

    When I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    #flipping bits seems to be tricky. due to bits as bytes and bytes as base64 the last couple of bits may or may not have influence on the signature
    And I flip bit -20 on context with key SIGNED_CHALLENGE
    And I request a code token with signed challenge
    Then the response is an 302 error with code 'invalid_request' and message matching 'Error%20during%20JOSE-operations'
