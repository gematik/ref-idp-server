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


# TODO RISE alle Szenarien mit @StufeX Annotationen versehen

@testsuite

Feature: Fordere Discovery Dokument an
    Frontends von TI Diensten müssen vom IDP Server über ein HTTP GET an den Discovery Endpoint ein Discovery Dokument
    abfragen können. Welches alle notwendigen Informationen enthält um die IDP Server Endpunkte bedienen zu können.

    @Afo:A_20668
    @Afo:A_19874
    @ReleaseV1
    Scenario: Disc - Discovery Dokument muss verfügbar sein

    ```
    Wir fordern das Discovery Dokument an.

    Die Antwort des Servers muss:

    - den HTTP Status 200 und
    - den Content Typ application/json haben und


        When I request the discovery document
        Then the response status is 200
        And the response content type is 'application/json'

    @Afo:A_20614
    @Afo:A_20623
    @Afo:A_20591
    @Signature
    Scenario: Disc - Discovery Dokument muss signiert sein

    ```
    Wir fordern das Discovery Dokument an.

    Die Antwort des Servers muss mit dem richtigen Zertifikat signiert sein


        Given I initialize scenario from discovery document endpoint
        And I retrieve public keys from URIs
        When I request the discovery document
        Then the response must be signed with cert PUK_DISC

    @Afo:A_20458
    @ReleaseV1
    Scenario: Disc - Discovery Dokument header claims sind korrekt

    ```
    Wir fordern das Discovery Dokument an.

    Die Antwort des Servers muss:

    - die korrekten Header Claims gesetzt haben


        Given I request the discovery document
        When I extract the header claims
        Then the header claims should match in any order
        """
        {
          alg: "BP256R1"
        }
        """
        # IDP-181: kein x5c im header
        # TODO IDP-134 IntJira fordert die Wiedereinführung des x5c header

    @Afo:A_20297_01
    @Afo:A_20505_01
    @Afo:A_20506_01
    @Afo:A_20698
    @ReleaseV1
    Scenario: Disc - Discovery Dokument body claims sind korrekt

    ```
    Wir fordern das Discovery Dokument an.

    Die Antwort des Servers muss:

    - die korrekten Body Claims gesetzt haben


        Given I request the discovery document
        When I extract the body claims
        Then the body claims should match in any order
        """
        {
          issuer: "http.*",
          authorization_endpoint: "http.*",
          token_endpoint: "http.*",
          jwks_uri : "(http|file).*",
          subject_types_supported : "[\"pairwise\"]",
          id_token_signing_alg_values_supported : "[\"BP256R1\"]",
          response_types_supported : "[\"code\"]",
          scopes_supported : "[\"openid\",\"e-rezept\"]",
          response_modes_supported : "[\"query\"]",
          grant_types_supported : "[\"authorization_code\"]",
          acr_values_supported : "[\"urn:eidas:loa:high\"]",
          token_endpoint_auth_methods_supported : "[\"none\"]",
          puk_uri_auth: ".*",
          puk_uri_token: ".*",
          puk_uri_disc: ".*",
          nbf: "[\\d]*",
          exp: "[\\d]*",
          iat: "[\\d]*"
        }
        """
        # TODO RISE for now puk uris can be anything as we use file paths in the work around here
        # TODO RISE puk uri tokens UPPERCASE, puk uri disc fehlt, puk uri auth fehlt, dafür claims_supported

        # iat must be within 24h and before now
        And the body claim 'iat' contains a date NOT_BEFORE P-1DT-1S
        And the body claim 'iat' contains a date NOT_AFTER PT1S
        # nbf must be in past and within 24h
        And the body claim 'nbf' contains a date NOT_BEFORE P-1DT-1S
        And the body claim 'nbf' contains a date NOT_AFTER PT1S
        # exp must be after now but within 24h
        And the body claim 'exp' contains a date NOT_BEFORE PT1S
        And the body claim 'exp' contains a date NOT_AFTER P1DT1S

    @Afo:A_20687
    @ReleaseV1
    Scenario: Disc - Die URLs im Discovery Dokument sind erreichbar

    ```
    Wir fordern das Discovery Dokument an und überprüfen die URIs in den Claims

    - issuer
    - authorization_endpoint
    - token_endpoint

    Die Antwort des Servers auf Anfragen auf diese URIs muss erfolgen, kann aber einen Fehler (4XX) retournieren.


        Given I request the discovery document
        When I extract the body claims
        Then URI in claim "issuer" exists with method GET and status 404
        And URI in claim "issuer" exists with method POST and status 404
        And URI in claim "authorization_endpoint" exists with method GET and status 400
        And URI in claim "authorization_endpoint" exists with method POST and status 400
        And URI in claim "token_endpoint" exists with method GET and status 405
        And URI in claim "token_endpoint" exists with method POST and status 400

    @ReleaseV1
        @OpenBug # currently not working if we use file based key material
    Scenario Outline: Disc - Die Schlüssel URIs sind erreichbar und enthalten public X509 Schlüssel

    ```
    Wir fordern das Discovery Dokument an und überprüfen die Inhalte der URIs aus den PUK Claims

    - puk_uri_auth
    - puk_uri_token
    - puk_uri_disc

    Die Antwort des Servers auf Anfragen auf diese URIs muss einen validen ECC BP256 Schlüssel liefern.

        Given I request the discovery document
        And I extract the body claims
        When I request the uri from claim "<claim>" with method GET and status 200
        Then the JSON response should match
        """
        { "x5c": "${json-unit.ignore}",
          "kid": "${json-unit.ignore}",
          "kty": "EC",
          "crv": "BP-256",
          "x": "${json-unit.ignore}",
          "y": "${json-unit.ignore}"
        }
        """
        # TODO implement checks that these are all valid keys
        # The correct usage is then checked in the workflow scenarios

        Examples: Die claims welche Schlüssel URIs enthalten
            | claim         |
            | puk_uri_auth  |
            | puk_uri_token |
            | puk_uri_disc  |

    Scenario Outline: Check JWKS URI

    ```
    Wir fordern das Discovery Dokument an und überprüfen die Inhalte der URI aus den jwks_uri Claim
    Die Antwort des Servers auf die Anfrage auf diese URIs muss einen validen ECC BP256 Schlüsselset liefern.


        Given I request the discovery document
        And I extract the body claims
        When I request the uri from claim "<claim>" with method GET and status 200
        Then the JSON response should match
        """
        { "keys": "${json-unit.ignore}" }
        """

        And JSON response has node 'keys[0]'
        # TODO implement checks that these are all valid keys
        # The correct usage is then checked in the workflow scenarios

        Examples:
            | claim    |
            | jwks_uri |
