#
# Copyright (Date see Readme), gematik GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# *******
#
# For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
#

@erpEntityStatement
@SektAuth
@PRODUKT:IDP-D
Feature: eRezept Entity Statement Endpoint

  Tests des Entity Statements des eRezept Authservers

  Background:
    Given IDP I initialize scenario from discovery document endpoint
    And TGR find first request to path "/.well-known/openid-configuration"
    And TGR set local variable "issuer" to "!{rbel:currentResponseAsString('$.body.body.issuer')}"
    When TGR sende eine leere GET Anfrage an "${issuer}/.well-known/openid-federation"

  @TCID:IDP_ERP_ENTITY_STATEMENT_001
  @Approval
  Scenario: eRP EntityStatement - Gutfall - Validiere Response

  ```
  Wir rufen das Entity Statement des eRezept Authservers ab
  Die HTTP Response muss:
  - den Code 200
  - einen JWS enthalten

    When TGR find first request to path "/.well-known/openid-federation"
    Then TGR current response with attribute "$.responseCode" matches "200"
    And TGR current response with attribute "$.header.Content-Type" matches "application/entity-statement\+jwt.*"


  @TCID:IDP_ERP_ENTITY_STATEMENT_002
  @Approval
  Scenario: eRP EntityStatement - Gutfall - Validiere Response Header Claims

  ```
  Wir rufen das Entity Statement des eRezept Authservers ab

  Der Response Body muss ein JWS mit den folgenden Header Claims sein:


    When TGR find first request to path "/.well-known/openid-federation"
    Then TGR current response at "$.body.header" matches as JSON:
            """
          {
          alg:        'ES256',
          kid:        '.*',
          typ:        'entity-statement+jwt'
          }
        """


  @TCID:IDP_ERP_ENTITY_STATEMENT_003
  @Approval
  Scenario: eRP EntityStatement - Gutfall - Validiere Response Body Claims

  ```
  Wir rufen das Entity Statement des eRezept Authservers ab

  Der Response Body muss ein JWS mit den folgenden Body Claims sein:

    When TGR find first request to path "/.well-known/openid-federation"
    Then TGR current response at "$.body.body" matches as JSON:
            """
          {
            iss:                           'http.*',
            sub:                           'http.*',
            iat:                           "${json-unit.ignore}",
            exp:                           "${json-unit.ignore}",
            jwks:                          "${json-unit.ignore}",
            authority_hints:               "${json-unit.ignore}",
            metadata:                      "${json-unit.ignore}",
          }
        """
    And TGR current response with attribute "$.body.body.authority_hints.0" matches ".*.federationmaster.de"


  @TCID:IDP_ERP_ENTITY_STATEMENT_004
  @Approval
  Scenario: eRP EntityStatement - Gutfall - Validiere Metadata Body Claim

  ```
  Wir rufen das Entity Statement des eRezept Authservers ab

  Der Response Body muss ein JWS sein. Dieser muss einen korrekt aufgebauten Body Claim metadata enthalten

    When TGR find first request to path "/.well-known/openid-federation"
    Then TGR current response at "$.body.body.metadata" matches as JSON:
    """
          {
            openid_relying_party:                      "${json-unit.ignore}",
            federation_entity:                         "${json-unit.ignore}"
          }
    """


  @TCID:IDP_ERP_ENTITY_STATEMENT_005
  @Approval
  Scenario: eRP EntityStatement - Gutfall - Validiere openid_relying_party Claim

  ```
  Wir rufen das Entity Statement des eRezept Authservers ab

  Der Response Body muss ein JWS sein. Dieser muss im Claim metadata, einen korrekt aufgebauten Body Claim openid_relying_party enthalten

    When TGR find first request to path "/.well-known/openid-federation"
    Then TGR current response at "$.body.body.metadata.openid_relying_party" matches as JSON:
    """
          {
            ____jwks:                                     "${json-unit.ignore}",
            ____signed_jwks_uri:                          'http.*',
            organization_name:                            '.*',
            client_name:                                  'E-Rezept Fachdienst',
            redirect_uris:                                "${json-unit.ignore}",
            response_types:                               ["code"],
            client_registration_types:                    ["automatic"],
            grant_types:                                  ["authorization_code"],
            require_pushed_authorization_requests:        true,
            token_endpoint_auth_method:                   "self_signed_tls_client_auth",
            default_acr_values:                           "${json-unit.ignore}",
            id_token_signed_response_alg:                 "ES256",
            id_token_encrypted_response_alg:              "ECDH-ES",
            id_token_encrypted_response_enc:              "A256GCM",
            scope:                                        '.*',
            ti_features_supported:                        "${json-unit.ignore}"
          }
    """
    And TGR current response at "$.body.body.metadata.openid_relying_party.ti_features_supported" matches as JSON:
    """
          {
            id_token_version_supported:      ["1.0.0", "2.0.0"]
          }
    """


  @TCID:IDP_ERP_ENTITY_STATEMENT_006
  @Approval
  Scenario: eRP EntityStatement - Gutfall - Validiere federation_entity Claim

  ```
  Wir rufen das Entity Statement des eRezept Authservers ab

  Der Response Body muss ein JWS sein. Dieser muss im Claim metadata, einen korrekt aufgebauten Body Claim federation_entity enthalten

    When TGR find first request to path "/.well-known/openid-federation"
    Then TGR current response at "$.body.body.metadata.federation_entity" matches as JSON:
    """
          {
            organization_name:    'RISE GmbH',
            ____contacts:         "${json-unit.ignore}",
            ____homepage_uri:     'http.*'
          }
    """

  @TCID:IDP_ERP_ENTITY_STATEMENT_008
  @Approval
  Scenario: eRP EntityStatement - Gutfall - Validiere JWKS in Body Claims

  ```
  Wir rufen das Entity Statement des eRezept Authservers ab

  Der Response Body muss ein JWS mit einem JWKS Claim sein.
  Das JWKS muss mindestens einen strukturell korrekten JWK mit use = sig und x5c-Element enthalten.

    When TGR find first request to path "/.well-known/openid-federation"
    And TGR set local variable "entityStatementSigKeyKid" to "!{rbel:currentResponseAsString('$.body.header.kid')}"
    Then TGR current response at "$.body.body.jwks.keys.[?(@.kid.content =='${entityStatementSigKeyKid}')]" matches as JSON:
        """
          {
            use:                           'sig',
            kid:                           '.*',
            kty:                           'EC',
            crv:                           'P-256',
            x:                             "${json-unit.ignore}",
            y:                             "${json-unit.ignore}",
            alg:                           "ES256"
          }
        """


  @TCID:IDP_ERP_ENTITY_STATEMENT_009
  @Approval
  Scenario: eRP EntityStatement - Gutfall - Validiere Signatur

  ```
  Wir rufen das Entity Statement des eRezept Authservers ab

  Die Signatur muss valide sein:

    When TGR find first request to path "/.well-known/openid-federation"
    And TGR current response with attribute "$.body.signature.isValid" matches "true"


  @TCID:IDP_ERP_ENTITY_STATEMENT_010
  @Approval
  Scenario: eRP EntityStatement - Gutfall - Validiere Scope Claim

  ```
  Wir rufen das Entity Statement des eRezept Authservers ab
  Der Scope muss mindestens die Claims openid und urn:telematik:versicherter (für das Schreiben in der ePA) enthalten


    When TGR find first request to path "/.well-known/openid-federation"
    And TGR current response with attribute "$.body.body.metadata.openid_relying_party.scope" matches "openid urn:telematik:display_name urn:telematik:versicherter"


  @TCID:IDP_ERP_ENTITY_STATEMENT_011
  @Approval
  Scenario: eRP EntityStatement - Gutfall - Validiere Enc Key
  ```
  Wir rufen das Entity Statement des eRezept Authservers ab

  Das Entity Statement muss einen JWKS und dieser muss einen ENC-Key enthalten:


    When TGR find first request to path "/.well-known/openid-federation"
    Then TGR current response at "$.body.body.metadata.openid_relying_party.jwks.keys.[?(@.use.content == 'enc')]" matches as JSON:
      """
        {
          use:                           'enc',
          kid:                           '.*',
          kty:                           'EC',
          crv:                           'P-256',
          x:                             "${json-unit.ignore}",
          y:                             "${json-unit.ignore}",
          alg:                           ".*"
        }
      """


  @TCID:IDP_ERP_ENTITY_STATEMENT_012
  @Approval
  Scenario: eRP EntityStatement - Gutfall - Validiere TLS Key
  ```
  Wir rufen das Entity Statement des eRezept Authservers ab

  Das Entity Statement muss einen JWKS und dieser muss einen Sig-Key mit x5c-Element enthalten:

    When TGR find first request to path "/.well-known/openid-federation"
    Then TGR current response at "$.body.body.metadata.openid_relying_party.jwks.keys.[?((@.use.content == 'sig') && ( @.x5c.0.content =~ '.*'))]" matches as JSON:
      """
        {
          use:                           'sig',
          kid:                           '.*',
          kty:                           'EC',
          crv:                           'P-256',
          x:                             "${json-unit.ignore}",
          y:                             "${json-unit.ignore}",
          alg:                           "ES256",
          x5c:                           "${json-unit.ignore}"
        }
      """