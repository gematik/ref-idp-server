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

@Product:IDP-D
@FastTrack
@ThirdPartyAuth
@RefImplOnly
Feature: Authentifiziere User am Third Party Endpoint

  Die eRezept-App stößt eine Authentisierung durch einen Aufruf des Third Party Endpoints an

  Background: Initialisiere Testkontext durch Abfrage des Discovery Dokuments
    Given IDP I initialize scenario from discovery document endpoint
    And IDP I retrieve public keys from URIs
    And IDP I initialize the sektoral idp endpoints

  @TCID:IDP_THIRD_PARTY_AUTH_001 @PRIO:1
  @Approval @Ready
  Scenario: ThirdParty - Gutfall -Auth-Request an zentralen IDP, validiere Antwortstruktur

  ```
  Wir senden einen gültigen Authorization Request (Nachricht 1) an den Third Party Authorization Endpunkt. Als Antwort erwartend wir einen
  Redirect, der zur Kassen-App weitergeleitet wird (Nachricht 2 und 3).

  Die HTTP Response muss:

  - den Code 302
  - einen korrekten Location-Header

  enthalten.

    Given IDP Frontend sends an authorization request to smartcard idp with
      | client_id            | scope                      | code_challenge                              | code_challenge_method | redirect_uri            | state       | nonce     | response_type | kk_app_id  |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 123456789 | code          | kkAppId001 |
    Then the response status is 302
    And IDP the response http headers match
        """
        Content-Length=0
        Location=https://kk.dev.gematik.solutions.*[?|&]code_challenge=.*
        """

    #TODO: check more params?

    And IDP the response URI exists with param 'client_id' and value 'smartcardIdp'
    And IDP the response URI exists with param 'scope' and value 'erp_sek_auth%2Bopenid'
    And IDP the response URI exists with param 'redirect_uri' and value 'http%3A%2F%2Fredirect.gematik.de%2Ferezept'

  @TCID:IDP_THIRD_PARTY_AUTH_002 @PRIO:1
  @Approval @Ready
  Scenario: ThirdParty - Gutfall - Weiterleitung des Auth-Reqs des zentralen IDPs, validiere Antwortstruktur

  ```
  Wir senden einen gültigen Authorization Request an den Third Party Authorization Endpunkt (Nachricht 1). Den Redirect der Antwort (Nachricht 3) senden
  wir weiter zum sektoralen IDP (Nachricht 4) und validieren die Antwort (Nachricht 7).

  Die HTTP Response des sektoralen IDP muss:

  - den Code 302
  - einen korrekten Location-Header mit Authorization Code und state

  enthalten.

    Given IDP Frontend sends an authorization request to smartcard idp with
      | client_id            | scope                      | code_challenge                              | code_challenge_method | redirect_uri            | state       | nonce     | response_type | kk_app_id  |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 123456789 | code          | kkAppId001 |
    Then the response status is 302
    And IDP Frontend sends an authorization request to fasttrack sektoral idp with
      | client_id           | scope               | code_challenge      | code_challenge_method | redirect_uri                     | state               | nonce               | response_type       |
      | $FILL_FROM_REDIRECT | $FILL_FROM_REDIRECT | $FILL_FROM_REDIRECT | $FILL_FROM_REDIRECT   | https://kk.dev.gematik.solutions | $FILL_FROM_REDIRECT | $FILL_FROM_REDIRECT | $FILL_FROM_REDIRECT |
    Then the response status is 302
    And IDP the response http headers match
        """
        Content-Length=0
        Location=https://kk.dev.gematik.solutions[?|&]code=.*[?|&]state=.*
        """


  @TCID:IDP_THIRD_PARTY_AUTH_003 @PRIO:1
  @Approval @Ready
  Scenario: ThirdParty - Gutfall - Einreichen den third_party_authorization_code, validiere Antwortstruktur

  ```
  Wir reichen den Authorization Code des sektoralen IDPs beim third_party_endpoint des zentralen IDPs ein (Nachricht 9).

  Die HTTP Response des zentralen IDP (Nachricht 12) muss:

  - den Code 302
  - einen korrekten Location-Header mit Authorization Code und state

  enthalten.

    Given IDP Frontend sends an authorization request to smartcard idp with
      | client_id            | scope                      | code_challenge                              | code_challenge_method | redirect_uri            | state       | nonce     | response_type | kk_app_id  |
      | ${TESTENV.client_id} | ${TESTENV.scope_basisflow} | P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | 123456789 | code          | kkAppId001 |
    Then the response status is 302
    And IDP Frontend sends an authorization request to fasttrack sektoral idp with
      | client_id           | scope               | code_challenge      | code_challenge_method | redirect_uri                     | state               | nonce               | response_type       |
      | $FILL_FROM_REDIRECT | $FILL_FROM_REDIRECT | $FILL_FROM_REDIRECT | $FILL_FROM_REDIRECT   | https://kk.dev.gematik.solutions | $FILL_FROM_REDIRECT | $FILL_FROM_REDIRECT | $FILL_FROM_REDIRECT |
    Then the response status is 302
    And IDP I request a code token with third party authorization code
    Then the response status is 302
    And IDP the response http headers match
        """
        Content-Length=0
        Location=${TESTENV.redirect_uri_regex}[?|&]code=.*[?|&]ssotoken=.*
        """
    And IDP the response URI exists with param 'state' and value 'xxxstatexxx'


  @TCID:IDP_THIRD_PARTY_AUTH_004 @PRIO:1
  @Approval @Ready
  Scenario: ThirdParty - Die kk_app_list_uri ist erreichbar

  ```
  Wir fordern das Discovery Dokument an und überprüfen die URI der kk_app_list_uri

    Given IDP I request the discovery document

    When IDP I extract the body claims
    Then IDP URI in claim "kk_app_list_uri" exists with method GET and status 200
    When IDP I extract the body claims
    Then IDP the body claims should match in any order
        """
        {
          "kk_app_list":[{"kk_app_id":"kkAppId001","kk_app_name":"Gematik KK"},{"kk_app_id":"kkAppId002","kk_app_name":"Andere KK"}]
        }
        """
