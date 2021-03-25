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
@DiscoveryDocument
Feature: Fordere Discovery Dokument an
  Frontends von TI Diensten müssen vom IDP Server über ein HTTP GET an den Discovery Endpoint ein Discovery Dokument
  abfragen können. Welches alle notwendigen Informationen enthält um die IDP Server Endpunkte bedienen zu können.

  @Afo:A_20457  @Afo:A_20688
  @Approval @Ready
  Scenario: Disc - Dokument muss verfügbar sein

  ```
  Wir fordern das Discovery Dokument an.

  Die Antwort des Servers muss:

  - den HTTP Status 200 und
  - den Content Typ application/json haben (optional gefolgt von einem charset)


    When I request the discovery document
    Then the response status is 200
    And the response content type matches 'application/json.*'

  @Afo:A_20591
  @Approval @Ready
  Scenario: Disc - Dokument muss signiert sein

  ```
  Wir fordern das Discovery Dokument an.

  Die Antwort des Servers muss mit dem richtigen Zertifikat signiert sein


    Given I initialize scenario from discovery document endpoint
    And I retrieve public keys from URIs

    When I request the discovery document
    Then the response must be signed with cert PUK_DISC

  @Afo:A_20591
  @Approval @Ready
  Scenario: Disc - Dokument header claims sind korrekt

  ```
  Wir fordern das Discovery Dokument an.

  Die Antwort des Servers muss:

  - die korrekten Header Claims gesetzt haben


    Given I request the discovery document

    When I extract the header claims
    Then the header claims should match in any order
        """
        {
          alg: "BP256R1",
          kid: "${json-unit.ignore}",
          x5c: "${json-unit.ignore}"
        }
        """

  @Afo:A_20698 @Afo:A_20591 @Afo:A_20439 @Afo:A_20458
  @Approval @Ready
  Scenario: Disc - Dokument body claims sind korrekt

  ```
  Wir fordern das Discovery Dokument an.

  Die Antwort des Servers muss:

  - die korrekten Body Claims gesetzt haben
  - der Claim code_challenge_methods_supported ist optional


    Given I request the discovery document

    When I extract the body claims
    Then the body claims should match in any order
        """
          { acr_values_supported:                   '["gematik-ehealth-loa-high"]',
            authorization_endpoint:                 "http.*",
            auth_pair_endpoint:                     "http.*",
            sso_endpoint:                           "http.*",
            uri_pair:                               "http.*",
            exp:                                    "[\\d]*",
            grant_types_supported:                  '["authorization_code"]',
            iat:                                    "[\\d]*",
            id_token_signing_alg_values_supported:  '["BP256R1"]',
            issuer:                                 "${TESTENV.issuer}",
            jwks_uri:                               "http.*",
            uri_puk_idp_sig:                        ".*",
            uri_puk_idp_enc:                        ".*",
            uri_disc:                               ".*",
            response_modes_supported:               '["query"]',
            response_types_supported:               '["code"]',
            scopes_supported:                       '["openid","e-rezept"]',
            subject_types_supported:                '["pairwise"]',
            token_endpoint:                         "http.*",
            token_endpoint_auth_methods_supported:  '["none"]',
            ____code_challenge_methods_supported:   '["S256"]'
          }
        """

  @Afo:A_20698
  @Approval @Ready
  Scenario: Disc - Zeitliche Body Claims sind korrekt

  ```
  Wir fordern das Discovery Dokument an.

  Die Antwort des Servers muss gültige zeitliche Claim Attribute für iat und exp haben.


    Given I request the discovery document

    When I extract the body claims
    # iat must be within 24h and before now
    Then the body claim 'iat' contains a date not before P-1DT-1S
    And the body claim 'iat' contains a date not after PT1S
    # exp must be after now but within 24h
    And the body claim 'exp' contains a date not before PT1S
    And the body claim 'exp' contains a date not after P1DT1S

  @Afo:A_20691
  @manual
  @Approval @Ready @Timeout
  Scenario: Disc - Prüfe Zeitliche Gültigkeit ist maximal 24h
  ```
  Ich wiederhole stündlich das Szenario 'Disc - Discovery Dokument - Zeitliche Body Claims sind korrekt'

  Result: Keiner der Testdurchläufe darf fehlschlagen
  ```


  @Afo:A_20687 @Afo:A_20439
  @Approval @Ready
  Scenario: Disc - Die URLs im Dokument sind erreichbar

  ```
  Wir fordern das Discovery Dokument an und überprüfen die URIs in den Claims

  - issuer
  - authorization_endpoint
  - token_endpoint
  - auth_pair_endpoint
  - uri_pair

  Die Antwort des Servers auf Anfragen auf diese URIs muss erfolgreich sein im Sinne der Erreichbarkeit,
  kann aber einen Fehler (4XX) retournieren.


    Given I request the discovery document

    When I extract the body claims
    Then URI in claim "uri_disc" exists with method GET and status 200
    And URI in claim "uri_disc" exists with method POST and status 405
    And URI in claim "authorization_endpoint" exists with method GET and status 400
    And URI in claim "authorization_endpoint" exists with method POST and status 400
    And URI in claim "sso_endpoint" exists with method GET and status 405
    And URI in claim "sso_endpoint" exists with method POST and status 400
    And URI in claim "token_endpoint" exists with method GET and status 405
    And URI in claim "token_endpoint" exists with method POST and status 400
    And URI in claim "auth_pair_endpoint" exists with method GET and status 405
    And URI in claim "auth_pair_endpoint" exists with method POST and status 400
    And URI in claim "uri_pair" exists with method GET and status 403
    And URI in claim "uri_pair" exists with method POST and status 403
    # content type not supported

  @Afo:A_20732 @Afo:A_20591
  @Approval @Ready @OutOfScope:KeyChecksOCSP
  Scenario: Disc - Die idpSig URI ist erreichbar und enthält ein public X509 Zertifikat

  ```
  Wir fordern das Discovery Dokument an und überprüfen die Inhalte der URI für uri_puk_idp_sign

  Die Antwort des Servers auf Anfragen auf diese URIs muss ein valides ECC BP256 Zertifikat liefern.

    Given I request the discovery document
    And I extract the body claims

    When I request the uri from claim "uri_puk_idp_sig" with method GET and status 200
    Then the JSON response should match
        """
          { crv: "BP-256",
            kid: "puk_idp_sig",
            use: "sig",
            kty: "EC",
            x:   "${json-unit.ignore}",
            x5c: "${json-unit.ignore}",
            y:   "${json-unit.ignore}"
          }
        """
    And the JSON response should be a valid certificate
    # The correct usage is then checked in the workflow scenarios

  @Afo:A_20732
  @Approval @Ready @OutOfScope:KeyChecksOCSP
  Scenario: Disc - Die idpEnc URI ist erreichbar und enthält einen public X509 Schlüssel

  ```
  Wir fordern das Discovery Dokument an und überprüfen die Inhalte der URI für uri_puk_idp_enc

  Die Antwort des Servers auf Anfragen auf diese URIs muss einen validen ECC BP256 Schlüssel liefern.

    Given I request the discovery document
    And I extract the body claims

    When I request the uri from claim "uri_puk_idp_enc" with method GET and status 200
    Then the JSON response should match
        """
          { crv: "BP-256",
            kid: "puk_idp_enc",
            use: "enc",
            kty: "EC",
            x:   "${json-unit.ignore}",
            y:   "${json-unit.ignore}"
          }
        """
    And the JSON response should be a valid public key
    # The correct usage is then checked in the workflow scenarios

  @Approval @Ready @OutOfScope:KeyChecksOCSP
  Scenario Outline: Disc - Check JWKS URI

  ```
  Wir fordern das Discovery Dokument an und überprüfen die Inhalte der URI aus den jwks_uri Claim
  Die Antwort des Servers auf die Anfrage auf diese URIs muss einen validen ECC BP256 Schlüsselset liefern.


    Given I request the discovery document
    And I extract the body claims

    When I request the uri from claim "<claim>" with method GET and status 200
    Then the JSON response should match
        """
          {
            keys: [
              {
                kid:  "puk_idp_enc",
                use:  "enc",
                kty:  "EC",
                crv:  "BP-256",
                x:    ".*",
                y:    ".*"
              },
              {
                x5c:  "${json-unit.ignore}",
                kid:  "puk_idp_sig",
                use:  "sig",
                kty:  "EC",
                crv:  "BP-256",
                x:    ".*",
                y:    ".*"
              }
            ]
          }
        """

    And the JSON array 'keys' of response should contain valid certificates for 'idpSig'
    # The correct usage is then checked in the workflow scenarios

    Examples:
      | claim    |
      | jwks_uri |
