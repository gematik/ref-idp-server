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
  Scenario: AuthorChallenge - Validiere signierte Challenge mit BP256R1

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an und signieren diesen mit einem EC Zertifikat.
  Die signierte Challenge muss:

  - die richtigen Claims im Token haben

    Given I choose code verifier '${TESTENV.code_verifier01}'
    And I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 1234  | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'

    When I extract the header claims from token SIGNED_CHALLENGE
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
  Scenario: AuthorChallenge - Validiere signierte Challenge mit PS256
  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an und signieren diesen mit einem RSA Zertifikat.
  Die signierte Challenge muss:

  - die richtigen Claims im Token haben

  @Afo:A_20699 @Afo:A_20951 @Afo:A_20693
  @Approval @Ready
  Scenario: AuthorChallenge - Gutfall - Validiere Antwortstruktur

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, signieren diesen und
  fordern einen TOKEN_CODE mit der signierten Challenge an.

  Die TOKEN_CODE Antwort muss den Code 302 und die richtigen HTTP Header haben.


    Given I choose code verifier '${TESTENV.code_verifier01}'
    And I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | state123456 | 12345 | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'

    When I request a code token with signed challenge
    Then the response status is 302
    And the response http headers match
        """
        Content-Length=0
        Location=${TESTENV.redirect_uri_regex}[?|&]code=.*
        """
    And I expect the Context with key STATE to match 'state123456'
    And I expect the Context with key SSO_TOKEN to match '.*'

  @Afo:A_21472
  @Approval @Ready
  Scenario: AuthorChallenge - Gutfall - Primärsysteme Client ohne SSO Token

  ```
  Wir wählen einen gültigen Code verifier für einen registrierten Client der kein SSO Token zurückbekommen darf.
  Wir fordern einen Challenge Token an, signieren diesen und fordern einen TOKEN_CODE mit der signierten Challenge an.

  Die TOKEN_CODE Antwort muss den Code 302, die richtigen HTTP Header aber keinen SSO Token enthalten.


    Given I choose code verifier '${TESTENV.code_verifier01}'
    And I request a challenge with
      | client_id     | scope                      | code_challenge              | code_challenge_method | redirect_uri                      | state       | nonce | response_type |
      | gematikTestPs | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | http://test-ps.gematik.de/erezept | xxxstatexxx | 12345 | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'

    When I request a code token with signed challenge
    Then the response status is 302
    And the response http headers match
        """
        Content-Length=0
        Location=http://test-ps.gematik.de/erezept[?|&]code=.*
        """
    And I expect the Context with key STATE to match 'xxxstatexxx'
    And I expect the Context with key SSO_TOKEN to match '$NULL'

  @Afo:A_20699 @Afo:A_20951 @Afo:A_20731 @Afo:A_20377 @Afo:A_20697 @Afo:A_21317
  @Approval @Ready
  Scenario: AuthorChallenge - Gutfall - Validiere Location Header und Code Token Claims

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, signieren diesen und
  fordern einen TOKEN_CODE mit der signierten Challenge an.

  Die TOKEN_CODE Antwort muss im Location header state, code und SSO Token als Query Parameter enthalten und
  die richtigen Claims im Token haben.


    Given I choose code verifier '${TESTENV.code_verifier01}'
    And I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state      | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | state23456 | 12345 | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And I request a code token with signed challenge

    When I extract the header claims from token TOKEN_CODE
    Then the header claims should match in any order
        """
          { alg: "BP256R1",
            kid: "${json-unit.ignore}",
            typ: "JWT"
          }
        """

    When I extract the body claims from token TOKEN_CODE
    Then the body claims should match in any order
        """
        {
            auth_time:             "${json-unit.ignore}",
            client_id:             "${TESTENV.client_id}",
            code_challenge:        "${TESTENV.code_challenge01}",
            code_challenge_method: "S256",
            exp:                   "[\\d]*",
            jti:                   "${json-unit.ignore}",
            family_name:           "(.{1,64})",
            given_name:            "(.{1,64})",
            iat:                   "[\\d]*",
            idNummer:              "[A-Z][\\d]{9,10}",
            iss:                   "${TESTENV.issuer}",
            nonce:                 "12345",
            organizationName:      "(.{1,64})",
            professionOID:         "1\\.2\\.276\\.0\\.76\\.4\\.(3\\d|4\\d|178|23[2-90]|240|241)",
            redirect_uri:          "${TESTENV.redirect_uri}",
            response_type:         "code",
            scope:                 "${TESTENV.scopes_basisflow_regex}",
            snc:                   ".*",
            state:                 "state23456",
            token_type:            "code"
        }
        """

  @Afo:A_20319
  @Approval @Ready
  @Signature
  Scenario: AuthorChallenge - Validiere Signatur des Code Token

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, signieren diesen und
  fordern einen TOKEN_CODE mit der signierten Challenge an.

  Der Code Token muss mit dem puk_idp_sign Zertifikat gültig signiert sein und korrekte header Claims haben.

    Given I retrieve public keys from URIs
    And I choose code verifier '${TESTENV.code_verifier01}'
    And I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 3333  | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'

    When I request a code token with signed challenge
    Then the context TOKEN_CODE must be signed with cert PUK_SIGN

    When I extract the header claims from token TOKEN_CODE
    Then the header claims should match in any order
        """
          {
            alg: "BP256R1",
            typ: "JWT",
            kid: "puk_idp_sig"
          }
        """

  @Afo:A_20695
  @Approval @Ready
  @Signature
  Scenario: AuthorChallenge - Validiere Signatur des SSO Token

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, signieren diesen und
  fordern einen TOKEN_CODE und einen SSO_TOKEN mit der signierten Challenge an.

  Der SSO Token muss mit dem puk_idp_sign Zertifikat gültig signiert sein.

    Given I retrieve public keys from URIs
    And I choose code verifier '${TESTENV.code_verifier01}'
    And I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 3333  | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'

    When I request a code token with signed challenge
    Then the context SSO_TOKEN must be signed with cert PUK_SIGN

  @Afo:A_20314
  @Approval @Ready
  @Timeout
  @LongRunning
  Scenario: AuthorChallenge - Veralteter Challenge Token wird abgelehnt

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, signieren diesen, warten 3 Minuten und
  fordern dann einen TOKEN_CODE mit der signierten Challenge an.

  Der Server muss diese Anfrage mit einem Timeout Fehler ablehnen.

    Given I retrieve public keys from URIs
    And I choose code verifier '${TESTENV.code_verifier01}'
    And I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 3333  | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'

    When I wait PT3M5S
    And I request a code token with signed challenge
    Then the response is an 302 error with gematik code 2032 and error 'invalid_request'


  # ------------------------------------------------------------------------------------------------------------------
  #
  # negative cases

  @Approval @Ready
  Scenario: AuthorChallenge - Aufruf ohne Parameter

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an und
  fordern dann einen TOKEN_CODE an, ohne einen Parameter (SSO Token oder signierte Challenge) mitzugeben.

  Der Server muss diese Anfrage mit HTTP Status 302 und einer Fehlermeldung im Location Header ablehnen.


    Given I choose code verifier '${TESTENV.code_verifier02}'
    And I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state        | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge02} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx1 | 1212  | code          |

    When I request a code token with no params
    Then the response is an 400 error with gematik code 2030 and error 'invalid_request'


  @Afo:A_20951
  @Approval @Ready
  Scenario: AuthorChallenge - Challenge mit abgelaufenem Zertifikat signiert

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, signieren diesen
  mit einem ABGELAUFENEN Zertifikat und fordern einen TOKEN_CODE mit der signierten Challenge an.

  Der Server muss diese Anfrage mit HTTP Status 302 und einer Fehlermeldung im Location Header ablehnen.


    Given I choose code verifier '${TESTENV.code_verifier01}'
    And I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 3344  | code          |

    When I sign the challenge with '/certs/invalid/smcb-idp-expired.p12'
    And I request a code token with signed challenge
    Then the response is an 400 error with gematik code 2020 and error 'invalid_request'

  @Afo:A_20951 @Afo:A_20318 @Afo:A_20465
  @OutOfScope:KeyChecksOCSP
  @manual
  @Approval @Ready
  Scenario: AuthorChallenge - Challenge mit gesperrtem Zertifikat signiert
  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, signieren diesen
  mit einem GESPERRTEN Zertifikat und fordern einen TOKEN_CODE mit der signierten Challenge an.

  Der Server muss diese Anfrage mit HTTP Status 302 und einer Fehlermeldung im Location Header ablehnen.

  # Given I choose code verifier '${TESTENV.code_verifier01}'
  # And I request a challenge with
  #  | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce | response_type |
  #  | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 0101  | code          |

  # When I sign the challenge with '/certs/invalid/smcb-idp-revoked.p12'
  # And I request a code token with signed challenge
  # Then the response is an 302 error with gematik code 2020 and error 'invalid_request'


  @Afo:A_20951
  @Approval @Ready
  Scenario: AuthorChallenge - Challenge mit selbst signiertem Zertifikat signiert

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, signieren diesen
  mit einem SELBST SIGNIERTEN Zertifikat und fordern einen TOKEN_CODE mit der signierten Challenge an.

  Der Server muss diese Anfrage mit HTTP Status 302 und einer Fehlermeldung im Location Header ablehnen.


    Given I choose code verifier '${TESTENV.code_verifier01}'
    And I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 0011  | code          |

    When I sign the challenge with '/certs/invalid/smcb-idp-selfsigned.p12'
    And I request a code token with signed challenge
    Then the response is an 400 error with gematik code 2020 and error 'invalid_request'

  @Afo:A_20951
  @Approval @Ready
  Scenario: AuthorChallenge - Fehlerhafte Signatur der SIGNED_CHALLENGE (Keine Signatur)

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, ändern den Inhalt zu einem Text der
  definitiv nicht signiert ist und fordern einen TOKEN_CODE mit dieser Challenge an.

  Der Server muss diese Anfrage mit HTTP Status 302 und einer Fehlermeldung im Location Header ablehnen.


    Given I choose code verifier '${TESTENV.code_verifier01}'
    And I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce  | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 110011 | code          |

    When I set the context with key SIGNED_CHALLENGE to 'invalid signed challenge for sure'
    And I request a code token with signed challenge
    Then the response is an 400 error with gematik code 2031 and error 'invalid_request'

  @Approval @Ready
  Scenario: AuthorChallenge - Falscher Inhalt in der signierten Challenge

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, modifizieren den Inhalt, der definitiv falsch ist.
  Signieren diesen und fordern einen TOKEN_CODE mit der signierten falschen Challenge an.

  Der Server muss diese Anfrage mit HTTP Status 302 und einer Fehlermeldung im Location Header ablehnen.


    Given I choose code verifier '${TESTENV.code_verifier01}'
    And I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce  | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 220022 | code          |

    When I set the context with key CHALLENGE to 'malicious content test'
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And I request a code token with signed challenge
    Then the response is an 400 error with gematik code 2031 and error 'invalid_request'

  @Afo:A_20951
  @Approval @Ready
  Scenario: AuthorChallenge - Invalide Signatur

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, signieren diesen und
  flippen im signierten Challenge ein signifikantes bit.
  Dann fordern wir einen TOKEN_CODE mit der signierten falschen Challenge an.

  Der Server muss diese Anfrage mit HTTP Status 302 und einer Fehlermeldung im Location Header ablehnen.


    Given I choose code verifier '${TESTENV.code_verifier01}'
    And I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 3322  | code          |

    When I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    #flipping bits seems to be tricky. due to bits as bytes and bytes as base64 the last couple of bits may or may not have influence on the signature
    And I flip bit -20 on context with key SIGNED_CHALLENGE
    And I request a code token with signed challenge
    Then the response is an 400 error with gematik code 2013 and error 'invalid_request'

  @Approval @Ready
  Scenario: AuthorChallenge - Forder Code über Signed Challenge Endpunkt mit SSO Token Parameter an

  ```
  Wir fordern einen SSO token an, und schicken diesen dann an den signed challenge Endpunkt.

  Der Server muss diese Anfrage mit HTTP Status 302 und einer Fehlermeldung im Location Header ablehnen.

    Given I choose code verifier '${TESTENV.code_verifier01}'
        # code_challenge for given verifier can be obtained from https://tonyxu-io.github.io/pkce-generator/
    And I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state         | nonce  | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx1a | 997755 | code          |
    And I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
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
    And I request a code token with signed challenge with sso token
    Then the response is an 400 error with gematik code 2030 and error 'invalid_request'


  @Approval @Ready
    @Todo:IDP-553 @Todo:IDP-500
  Scenario Outline: AuthorChallenge - IDNummer invalid oder null

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an und signieren diesen mit einem Zertifikat
  welches eine ungültige IDNummer enthält.
  Dann fordern wir einen TOKEN_CODE mit der signierten Challenge an.

  Der Server muss diese Anfrage mit HTTP Status 302 und einer Fehlermeldung im Location Header ablehnen.

    Given I choose code verifier '${TESTENV.code_verifier01}'
    And I request a challenge with
      | client_id            | scope                      | code_challenge              | code_challenge_method | redirect_uri            | state       | nonce  | response_type |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | ${TESTENV.code_challenge01} | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 887766 | code          |

    When I sign the challenge with <cert>
    And I request a code token with signed challenge
    Then the response is an 400 error with gematik code -1 and error 'invalid_request'

    Examples: Author - Zertifikate
      | cert                                                |
      | '/certs/invalid/egk-idp-idnum-invalididnum-ecc.p12' |
      | '/certs/invalid/egk-idp-idnum-null-ecc.p12'         |
