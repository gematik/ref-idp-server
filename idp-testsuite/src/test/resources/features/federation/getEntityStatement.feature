#
# Copyright (c) 2023 gematik GmbH
# 
# Licensed under the Apache License, Version 2.0 (the License);
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#



@Federation
@EntityStatement
@RefImplOnly
Feature: EntityStatements abrufen

  Background: Initialisiere Testkontext der Föderation
    Given IDP I initialize the federation endpoints

  @Product:Fachdienst
  @TCID:FACHDIENST_ENTITY_STATEMENT_001 @PRIO:1
  @Approval
  Scenario: FD EntityStatement - Gutfall - Validiere Response

  ```
  Wir rufen das EntityStatement beim Fachdienst ab

  Die HTTP Response muss:

  - den Code 200
  - einen JWS enthalten

    Given TGR clear recorded messages
    When IDP I fetch fachdienst EntityStatement
    And TGR find request to path "/.well-known/openid-federation"
    Then the response status is 200
    And IDP the response content type matches 'application/entity-statement+jwt;charset=UTF-8'

  @Product:Fachdienst
  @TCID:FACHDIENST_ENTITY_STATEMENT_002 @PRIO:1
  @Approval
  Scenario: FD EntityStatement - Gutfall - Validiere Header Claims

  ```
  Wir rufen das EntityStatement beim Fachdienst ab

  Der JWE im Body muss bestimmte Header Claims enthalten

    When IDP I fetch fachdienst EntityStatement
    And TGR find request to path "/.well-known/openid-federation"
    Then TGR current response at "$.body.header" matches as JSON:
        """
{
  alg: "ES256",
  typ: "entity-statement+jwt",
  kid: "puk_fachdienst_sig"
}
        """

  @Product:Fachdienst
  @TCID:FACHDIENST_ENTITY_STATEMENT_003 @PRIO:1
  @Approval
  Scenario: FD EntityStatement - Gutfall - Validiere Body Claims

  ```
  Wir rufen das EntityStatement beim Fachdienst ab

  Die HTTP Response muss:

  - den Code 200
  - einen JWS enthalten

    Given TGR clear recorded messages
    When IDP I fetch fachdienst EntityStatement
    And TGR find request to path "/.well-known/openid-federation"
    Then TGR current response at "$.body.body" matches as JSON:
        """
{
  iss: 'http.*',
  sub: 'http.*',
  iat: "${json-unit.ignore}",
  exp: "${json-unit.ignore}",
  jwks: {
    keys: [
      {
        use: "sig",
        kid: "puk_fachdienst_sig",
        kty: "EC",
        crv: "P-256",
        x: "${json-unit.ignore}",
        y: "${json-unit.ignore}"
      }
    ]
  },
  authority_hints: "${json-unit.ignore}",
  metadata: {
    openid_relying_party: {
      signed_jwks_uri: 'http.*/jws.json',
      organization_name: "Fachdienst007 des FedIdp POCs",
      client_name: "Fachdienst007",
      logo_uri: 'http.*',
      redirect_uris: ["https://Fachdienst007.de/client","https://redirect.testsuite.gsi"],
      response_types: ["code"],
      client_registration_types: ["automatic"],
      grant_types: ["authorization_code"],
      require_pushed_authorization_requests: true,
      token_endpoint_auth_method: "private_key_jwt",
      default_acr_values: "gematik-ehealth-loa-high",
      id_token_signed_response_alg: "ES256",
      id_token_encrypted_response_alg: "ECDH-ES",
      id_token_encrypted_response_enc: "A256GCM",
      scope: "urn:telematik:display_name urn:telematik:versicherter openid"
    },
    federation_entity: {
      name: "Fachdienst007",
      contacts: "Support@Fachdienst007.de",
      homepage_uri: "https://Fachdienst007.de"
    }
  }
}
        """


  @Product:FedMaster
  @TCID:FEDMASTER_ENTITY_STATEMENT_001 @PRIO:1
  @Approval
  Scenario: Fedmaster EntityStatement - Gutfall - Validiere Response

  ```
  Wir rufen das EntityStatement beim Fedmaster ab

  Die HTTP Response muss:

  - den Code 200
  - einen JWS enthalten

    Given TGR clear recorded messages
    When IDP I fetch fedmaster EntityStatement
    And TGR find request to path "/.well-known/openid-federation"
    Then the response status is 200
    And IDP the response content type matches 'application/entity-statement+jwt;charset=UTF-8'


  @Product:FedMaster
  @TCID:FEDMASTER_ENTITY_STATEMENT_002 @PRIO:1
  @Approval
  Scenario: Fedmaster EntityStatement - Gutfall - Validiere Header Claims

  ```
  Wir rufen das EntityStatement beim Fedmaster ab

  Der JWE im Body muss bestimmte Header Claims enthalten

    Given TGR clear recorded messages
    When IDP I fetch fedmaster EntityStatement
    And TGR find request to path "/.well-known/openid-federation"
    Then TGR current response at "$.body.header" matches as JSON:
        """
{
  alg: "ES256",
  typ: "entity-statement+jwt",
  kid: "puk_fed_sig"
}
        """

  @Product:FedMaster
  @TCID:FEDMASTER_ENTITY_STATEMENT_003 @PRIO:1
  @Approval
  Scenario: Fedmaster EntityStatement - Gutfall - Validiere Body Claims

  ```
  Wir rufen das EntityStatement beim Fedmaster ab

  Die HTTP Response muss:

  - den Code 200
  - einen JWS enthalten

    Given TGR clear recorded messages
    When IDP I fetch fedmaster EntityStatement
    And TGR find request to path "/.well-known/openid-federation"
    Then TGR current response at "$.body.body" matches as JSON:
        """
{
  iss: 'http.*',
  sub: 'http.*',
  iat: "${json-unit.ignore}",
  exp: "${json-unit.ignore}",
  jwks: {
    keys: [
      {
        use: "sig",
        kid: "puk_fed_sig",
        kty: "EC",
        crv: "P-256",
        x: "${json-unit.ignore}",
        y: "${json-unit.ignore}"
      }
    ]
  },
  metadata: {
    federation_entity: {
      federation_fetch_endpoint: 'http.*/federation_fetch_endpoint',
      federation_list_endpoint: 'http.*/federation_list',
      idp_list_endpoint: 'http.*/.well-known/idp_list'
    }
  }
}
        """


  @Product:FedIdp
  @TCID:FEDIDP_ENTITY_STATEMENT_001 @PRIO:1
  @Approval
  Scenario: Sektoraler IDP EntityStatement - Gutfall - Validiere Response

  ```
  Wir rufen das EntityStatement beim Fachdienst ab

  Die HTTP Response muss:

  - den Code 200
  - einen JWS enthalten

    Given TGR clear recorded messages
    When IDP I fetch fed sektoral idp EntityStatement
    And TGR find request to path "/.well-known/openid-federation"
    Then the response status is 200
    And IDP the response content type matches 'application/entity-statement+jwt;charset=UTF-8'


  @Product:FedIdp
  @TCID:FEDIDP_ENTITY_STATEMENT_002 @PRIO:1
  @Approval
  Scenario: Sektoraler IDP EntityStatement - Gutfall - Validiere Header Claims

  ```
  Wir rufen das EntityStatement beim Fachdienst ab

  Der JWE im Body muss bestimmte Header Claims enthalten

    Given TGR clear recorded messages
    When IDP I fetch fed sektoral idp EntityStatement
    And TGR find request to path "/.well-known/openid-federation"
    Then TGR current response at "$.body.header" matches as JSON:
        """
{
  alg: "ES256",
  typ: "entity-statement+jwt",
  kid: "puk_fed_idp_sig"
}
        """

  @Product:FedIdp
  @TCID:FEDIDP_ENTITY_STATEMENT_003 @PRIO:1
  @Approval
  Scenario: Sektoraler IDP EntityStatement - Gutfall - Validiere Body Claims

  ```
  Wir rufen das EntityStatement beim Fachdienst ab

  Die HTTP Response muss:

  - den Code 200
  - einen JWS enthalten

    Given TGR clear recorded messages
    When IDP I fetch fed sektoral idp EntityStatement
    And TGR find request to path "/.well-known/openid-federation"
    Then TGR current response at "$.body.body" matches as JSON:
        """
{
  iss: 'http.*',
  sub: 'http.*',
  iat: "${json-unit.ignore}",
  exp: "${json-unit.ignore}",
  jwks: {
    keys: [
      {
        use: "sig",
        kid: "puk_fed_idp_sig",
        kty: "EC",
        crv: "P-256",
        x: "${json-unit.ignore}",
        y: "${json-unit.ignore}"
      }
    ]
  },
  authority_hints: ["todo Bezeichnung des Federation Master"],
  metadata: {
    openid_provider: {
      issuer: 'http.*',
      signed_jwks_uri: 'http.*/jws.json',
      organization_name: "Föderierter IDP des POC",
      logo_uri: 'http.*',
      authorization_endpoint: 'http.*/auth',
      token_endpoint: 'http.*/token',
      pushed_authorization_request_endpoint: 'http.*/PAR_Auth',
      client_registration_types_supported: ["automatic"],
      subject_types_supported: ["pairwise"],
      response_types_supported: ["code"],
      scopes_supported: ["urn:telematik:given_name","urn:telematik:geburtsdatum","urn:telematik:alter","urn:telematik:display_name","urn:telematik:geschlecht","urn:telematik:email","urn:telematik:versicherter"],
      response_modes_supported: ["query"],
      grant_types_supported: ["authorization_code"],
      require_pushed_authorization_requests: true,
      token_endpoint_auth_methods_supported: ["self_signed_tls_client_auth"],
      request_authentication_methods_supported: {
        ar: ["none"],
        par: ["self_signed_tls_client_auth"]
      },
      id_token_signing_alg_values_supported: ["ES256"],
      id_token_encryption_alg_values_supported: ["ECDH-ES"],
      id_token_encryption_enc_values_supported: ["A256GCM"],
      user_type_supported: ["IP"]
    },
    federation_entity: {
      name: "idp4711",
      contacts: "support@idp4711.de",
      homepage_uri: "https://idp4711.de"
    }
  }
}
        """
