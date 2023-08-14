#
# Copyright 2023 gematik GmbH
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


Feature: Authentisierung mit sektoralem IDP

  Die eRezept-App stößt eine Authentisierung über die IDP Föderation an

  Background: Initialisiere Testkontext durch Abfrage des Discovery Dokuments
    Given IDP I initialize scenario from discovery document endpoint
    And TGR find request to path "/.well-known/openid-configuration"
    And TGR set local variable "fedAuthEndpoint" to "!{rbel:currentResponseAsString('$.body.body.federation_authorization_endpoint')}"
    And TGR set local variable "tokenEndpoint" to "!{rbel:currentResponseAsString('$.body.body.token_endpoint')}"


  @TCID:FED_IDP_AUTH_001
  @Approval
  Scenario: Fed Auth Endpoint - Der federation_authorization_endpoint ist erreichbar

  ```
  Wir fordern das Discovery Dokument an und überprüfen den fed_auth_endpoint
  Ein korrekte Request an den fed_auth_endpoint muss mit einem Redirect und einer request_uri beantwortet werden

    Given TGR clear recorded messages
    When TGR sende eine GET Anfrage an "${fedAuthEndpoint}" mit folgenden Daten:
      | client_id  | state       | redirect_uri                        | code_challenge                              | code_challenge_method | response_type | nonce | scope           | idp_iss                           |
      | eRezeptApp | xxxstatexxx | https://redirect.gematik.de/erezept | ds7JaEfpdLidWekR52OhoVpjXHDlplLyV3GtUezxfY0 | S256                  | code          | 1234  | openid e-rezept | https://gsi.dev.gematik.solutions |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "302"
    And TGR current response with attribute "$.header.Location.request_uri.value" matches "urn.*"


  @TCID:FED_IDP_AUTH_002
  @Approval
  Scenario: Fed Auth Endpoint - Authentication Request an den GSI

  ```
  Wir fordern vom fed_auth_endpoint eine request_uri an. Mit dieser gehen wir zum GSI
  Der Authentication Request an den GSI muss mit einem auth_code per redirect beantwortet werden

    Given TGR clear recorded messages
    And TGR sende eine GET Anfrage an "${fedAuthEndpoint}" mit folgenden Daten:
      | client_id  | state       | redirect_uri                        | code_challenge                              | code_challenge_method | response_type | nonce | scope           | idp_iss                           |
      | eRezeptApp | xxxstatexxx | https://redirect.gematik.de/erezept | ds7JaEfpdLidWekR52OhoVpjXHDlplLyV3GtUezxfY0 | S256                  | code          | 1234  | openid e-rezept | https://gsi.dev.gematik.solutions |
    And TGR find request to path ".*"
    And TGR set local variable "requestUri" to "!{rbel:currentResponseAsString('$.header.Location.request_uri.value')}"
    And TGR set local variable "gsiAuthEndpoint" to "!{rbel:currentResponseAsString('$.header.Location.basicPath')}"
    And TGR clear recorded messages
    When TGR sende eine GET Anfrage an "${gsiAuthEndpoint}" mit folgenden Daten:
      | request_uri   | user_id  |
      | ${requestUri} | 12345678 |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "302"
    And TGR current response with attribute "$.header.Location.code.value" matches ".*"


  @TCID:FED_IDP_AUTH_003
  @Approval
  Scenario: Fed Auth Endpoint - Auth Code des GSI beim eRezept Auth Server einreichen

  ```
  Wir fordern vom fed_auth_endpoint eine request_uri an. Mit dieser gehen wir zum GSI
  Der Authentication Request an den GSI wird mit einem auth_code beantwortet
  Diesen senden wir an den Auth Server des eRezepts
  Die Antwort muss einen auth_code des eRezept Authservers enthalten

    Given TGR clear recorded messages
    And TGR sende eine GET Anfrage an "${fedAuthEndpoint}" mit folgenden Daten:
      | client_id  | state       | redirect_uri                        | code_challenge                              | code_challenge_method | response_type | nonce | scope           | idp_iss                           |
      | eRezeptApp | xxxstatexxx | https://redirect.gematik.de/erezept | ds7JaEfpdLidWekR52OhoVpjXHDlplLyV3GtUezxfY0 | S256                  | code          | 1234  | openid e-rezept | https://gsi.dev.gematik.solutions |
    And TGR find request to path ".*"
    And TGR set local variable "requestUri" to "!{rbel:currentResponseAsString('$.header.Location.request_uri.value')}"
    And TGR set local variable "gsiAuthEndpoint" to "!{rbel:currentResponseAsString('$.header.Location.basicPath')}"
    And TGR clear recorded messages
    And TGR sende eine GET Anfrage an "${gsiAuthEndpoint}" mit folgenden Daten:
      | request_uri   | user_id  |
      | ${requestUri} | 12345678 |
    And TGR find request to path ".*"
    And TGR set local variable "gsiAuthCode" to "!{rbel:currentResponseAsString('$.header.Location.code.value')}"
    And TGR set local variable "fachdienstState" to "!{rbel:currentResponseAsString('$.header.Location.state.value')}"
    And TGR clear recorded messages
    When TGR sende eine POST Anfrage an "${fedAuthEndpoint}" mit folgenden Daten:
      | code           | state              |
      | ${gsiAuthCode} | ${fachdienstState} |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "302"
    And TGR current response with attribute "$.header.Location.code.value" matches ".*"
    And TGR current response with attribute "$.header.Location.basicPath" matches "https://redirect.gematik.de/erezept"


  @TCID:FED_IDP_AUTH_004
  @Approval
  Scenario: Fed Auth Endpoint - Auth Code des eRezept Authservers beim Token Endpoint einreichen

  ```
  Wir fordern vom fed_auth_endpoint eine request_uri an. Mit dieser gehen wir zum GSI
  Der Authentication Request an den GSI wird mit einem auth_code beantwortet.
  Diesen senden wir an den Auth Server des eRezepts
  Die Antwort muss einen auth_code des eRezept Authservers enthalten
  Diesen senden wir an den Token Endpoint des zentralen IDPs

    Given TGR clear recorded messages
    And TGR sende eine GET Anfrage an "${fedAuthEndpoint}" mit folgenden Daten:
      | client_id  | state       | redirect_uri                        | code_challenge                              | code_challenge_method | response_type | nonce | scope           | idp_iss                           |
      | eRezeptApp | xxxstatexxx | https://redirect.gematik.de/erezept | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | code          | 1234  | openid e-rezept | https://gsi.dev.gematik.solutions |
    And TGR find request to path ".*"
    And TGR set local variable "requestUri" to "!{rbel:currentResponseAsString('$.header.Location.request_uri.value')}"
    And TGR set local variable "gsiAuthEndpoint" to "!{rbel:currentResponseAsString('$.header.Location.basicPath')}"
    And TGR clear recorded messages
    And TGR sende eine GET Anfrage an "${gsiAuthEndpoint}" mit folgenden Daten:
      | request_uri   | user_id  |
      | ${requestUri} | 12345678 |
    And TGR find request to path ".*"
    And TGR set local variable "gsiAuthCode" to "!{rbel:currentResponseAsString('$.header.Location.code.value')}"
    And TGR set local variable "fachdienstState" to "!{rbel:currentResponseAsString('$.header.Location.state.value')}"
    And TGR clear recorded messages
    And TGR sende eine POST Anfrage an "${fedAuthEndpoint}" mit folgenden Daten:
      | code           | state              |
      | ${gsiAuthCode} | ${fachdienstState} |
    And TGR find request to path ".*"
    And TGR set local variable "fachdienstCode" to "!{rbel:currentResponseAsString('$.header.Location.code.value')}"
    And TGR clear recorded messages
    When TGR sende eine POST Anfrage an "${tokenEndpoint}" mit folgenden Daten:
      | code              | key_verifier       | grant_type         | redirect_uri                        | client_id  |
      | ${fachdienstCode} | ${fed.keyVerifier} | authorization_code | https://redirect.gematik.de/erezept | eRezeptApp |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "200"
    Then TGR current response at "$.body" matches as JSON:
            """
          {
            expires_in:                         300,
            token_type:                         'Bearer',
            id_token:                           '.*',
            access_token:                       '.*'
          }
        """


  @TCID:FED_IDP_AUTH_005
    @Approval
    @OpenBug
    @GRAS-22
  Scenario Outline: Fed Auth Endpoint - Fehlerhafte Parameter bei GET an Federation Auth Endpoint

  ```
  Wir senden einen GET-Request mit fehlerhaft befüllten Parametern an den Fed Auht Endpoint. Der Request muss abgelehnt werden.

    Given TGR clear recorded messages
    When TGR sende eine GET Anfrage an "${fedAuthEndpoint}" mit folgenden Daten:
      | client_id  | state       | redirect_uri  | code_challenge                              | code_challenge_method | response_type  | nonce | scope   | idp_iss  |
      | <clientId> | xxxstatexxx | <redirectUri> | ds7JaEfpdLidWekR52OhoVpjXHDlplLyV3GtUezxfY0 | S256                  | <responseType> | 1234  | <scope> | <idpIss> |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "<errorCode>"

    Examples:
      | clientId      | redirectUri                         | responseType | scope           | idpIss                                | errorCode |
      | invalidClient | https://redirect.gematik.de/erezept | code         | openid e-rezept | https://gsi.dev.gematik.solutions     | 400       |
      | eRezeptApp    | http://redirect.gematik.de/erezept  | code         | openid e-rezept | https://gsi.dev.gematik.solutions     | 400       |
      | eRezeptApp    | https://redirect.gematik.de/erezept | token        | openid e-rezept | https://gsi.dev.gematik.solutions     | 400       |
      | eRezeptApp    | https://redirect.gematik.de/erezept | code         | openid fhir-vzd | https://gsi.dev.gematik.solutions     | 400       |
      | eRezeptApp    | https://redirect.gematik.de/erezept | code         | openid e-rezept | https://idpfadi.dev.gematik.solutions | 400       |


  @TCID:FED_IDP_AUTH_006
    @Approval
    @OpenBug
    @GRAS-22
  Scenario Outline: Fed Auth Endpoint - Fehlerhafte Parameter bei POST an Federation Auth Endpoint

  ```
  Wir fordern vom fed_auth_endpoint eine request_uri an. Mit dieser gehen wir zum GSI
  Der Authentication Request an den GSI wird mit einem auth_code beantwortet
  Wir senden einen POST an den fed auth endpoint mit fehlerhaften Parametern. Dieser muss mit einer Fehlermeldung beantwortet werden.

    Given TGR clear recorded messages
    And TGR sende eine GET Anfrage an "${fedAuthEndpoint}" mit folgenden Daten:
      | client_id  | state       | redirect_uri                        | code_challenge                              | code_challenge_method | response_type | nonce | scope           | idp_iss                           |
      | eRezeptApp | xxxstatexxx | https://redirect.gematik.de/erezept | ds7JaEfpdLidWekR52OhoVpjXHDlplLyV3GtUezxfY0 | S256                  | code          | 1234  | openid e-rezept | https://gsi.dev.gematik.solutions |
    And TGR find request to path ".*"
    And TGR set local variable "requestUri" to "!{rbel:currentResponseAsString('$.header.Location.request_uri.value')}"
    And TGR set local variable "gsiAuthEndpoint" to "!{rbel:currentResponseAsString('$.header.Location.basicPath')}"
    And TGR clear recorded messages
    And TGR sende eine GET Anfrage an "${gsiAuthEndpoint}" mit folgenden Daten:
      | request_uri   | user_id  |
      | ${requestUri} | 12345678 |
    And TGR find request to path ".*"
    And TGR set local variable "gsiAuthCode" to "!{rbel:currentResponseAsString('$.header.Location.code.value')}"
    And TGR set local variable "fachdienstState" to "!{rbel:currentResponseAsString('$.header.Location.state.value')}"
    And TGR clear recorded messages
    When TGR sende eine POST Anfrage an "${fedAuthEndpoint}" mit folgenden Daten:
      | code   | state   |
      | <code> | <state> |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "<errorCode>"

    Examples:
      | code           | state              | errorCode |
      | invalidcode    | ${fachdienstState} | 400       |
      | ${gsiAuthCode} | xxxstatexxx        | 400       |