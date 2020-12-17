@testsuite
Feature: Discovery document
    Client applications of TI services need to be able to request all necessary information about keys and endpoints
    amongst others from the IDP server via the discovery document end point via GET method.

    @Afo:A_20668
    @Afo:A_19874
    Scenario: Check discovery document is signed
        Given I request the discovery document successfully
        Then the response content type is 'application/json'
        And the response must be signed with cert '/authenticatorModule_idpServer.p12'
        # TODO we need the specific keys for each endpoint

    @Afo:A_20458
    @Afo:IDP-181
    Scenario: Check discovery document headers are structured as specified
        Given I request the discovery document successfully
        When I extract the header claims
        Then the header claims should match in any order
        """
        {
          alg: "BP256R1",
          x5c: "${json-unit.ignore}"
        }
        """
        # TODO check x5c is a valid key

    @Afo:A_20297_01
    @Afo:A_20505_01
    @Afo:A_20506_01
    @Afo:A_20698
    Scenario: Check discovery document body is structured as specified
        Given I request the discovery document successfully
        When I extract the body claims
        Then the body claims should match in any order
        """
        {
          issuer: "${json-unit.ignore}",
          authorization_endpoint: "${json-unit.ignore}",
          token_endpoint: "${json-unit.ignore}",
          jwks_uri : "${json-unit.ignore}",
          subject_types_supported : "[\"pairwise\"]",
          id_token_signing_alg_values_supported : "[\"BP256R1\"]",
          response_types_supported : "[\"code\"]",
          scopes_supported : "[\"openid\",\"e-rezept\"]",
          response_modes_supported : "[\"query\"]",
          grant_types_supported : "[\"authorization_code\"]",
          acr_values_supported : "[\"urn:eidas:loa:high\"]",
          token_endpoint_auth_methods_supported : "[\"none\"]",
          puk_uri_auth: "${json-unit.ignore}",
          puk_uri_token: "${json-unit.ignore}",
          puk_uri_disc: "${json-unit.ignore}",
          nbf: "${json-unit.ignore}",
          exp: "${json-unit.ignore}",
          iat: "${json-unit.ignore}"
        }
        """
# TODO clarify where nbf, exp and iat are defined in spec and add possible values to list

    @Afo:A_20687
    Scenario: Check discovery document contains valid URIs
        Given I request the discovery document successfully
        When I extract the body claims
        Then URI in claim "issuer" exists with method GET and status 404
        And URI in claim "issuer" exists with method POST and status 404
        And URI in claim "authorization_endpoint" exists with method GET and status 400
        And URI in claim "authorization_endpoint" exists with method POST and status 400
        And URI in claim "token_endpoint" exists with method GET and status 405
        And URI in claim "token_endpoint" exists with method POST and status 400

    Scenario Outline: Check Key URIs
        Given I request the discovery document successfully
        When I extract the body claims
        And I request the uri from claim "<claim>" with method GET and status 200
        Then the JSON response should match
        """
        { keys: "${json-unit.ignore}" }
        """
        And JSON response has node 'keys[0]'
        # TODO Then it must be a valid public X509 key

        Examples:
            | claim         |
            | puk_uri_auth  |
            | puk_uri_token |
            | puk_uri_disc  |
            | jwks_uri      |