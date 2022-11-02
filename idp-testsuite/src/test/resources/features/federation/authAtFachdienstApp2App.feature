#
# Copyright (c) 2022 gematik GmbH
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


@Product:Fachdienst
@Federation
@Fachdienst
@RefImplOnly
@App2App
Feature: Authentisierung am Fachdienst

  Background: Initialisiere Testkontext der Föderation
    Given IDP I initialize the federation endpoints
    Given IDP I fetch the Fachdienst's IDP List


  @TCID:FACHDIENST_AUTH_001 @PRIO:1
  @Approval
  Scenario: App2App FD IDP Auth - Gutfall - Authentisierung am Auth-Endpunkt des FD

  ```
  Wir senden einen gültigen Authorization Request (Nachricht 1 im App2App-Flow) an den Fachdienst

  Die HTTP Response (Nachricht 4 im App2App-Flow) muss:

  - den HTTP Status Code 302
  - die Parameter client_id und request_uri enthalten

    Given IDP Frontend sends an authorization request to fachdienst with
      | client_id            | scope    | code_challenge                              | code_challenge_method | redirect_uri            | state       | response_type |
      | ${TESTENV.client_id} | e-rezept | P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | code          |
    Then the response status is 302
    And IDP the response http headers match
        """
        Content-Length=0
        Location=http.*
        """
    And IDP the response URI exists with param 'client_id' and value '.*'
    And IDP the response URI exists with param 'request_uri' and value 'urn%3A.*%3A.*'


  @TCID:FACHDIENST_AUTH_002 @PRIO:1
  @Approval
  Scenario: App2App FD IDP Auth - Gutfall - Authentisierung am Auth-Endpunkt des FD und am IDP

  ```
  Wir senden einen gültigen Authorization Request (Nachricht 1 im App2App-Flow) an den Fachdienst

  Die HTTP Response (Nachricht 4 im App2App-Flow) muss:

  - den HTTP Status Code 302
  - mit Parameter request_uri weitergeleitet werden (als Nachricht 6 im App2App-Flow)

  Die darauf folgende HTTP Response (Nachricht 7 im App2App-Flow) muss:

  - den HTTP Status Code 302

    Given IDP Frontend sends an authorization request to fachdienst with
      | client_id            | scope    | code_challenge                              | code_challenge_method | redirect_uri            | state       | response_type |
      | ${TESTENV.client_id} | e-rezept | P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | code          |
    Then the response status is 302

    When IDP Authenticator Module sends an authorization request to Fed_Sektoral_IDP_APP with
      | request_uri         |
      | $FILL_FROM_REDIRECT |

    Then the response status is 302

    And IDP the response http headers match
        """
        Content-Length=0
        Location=http.*
        """
    And IDP the response URI exists with param 'code' and value '.*'
    And IDP the response URI exists with param 'state' and value '.*'

  @TCID:FACHDIENST_AUTH_003 @PRIO:1
  @Approval
  Scenario: App2App FD IDP Auth - Gutfall - Authentisierung am Auth-Endpunkt des FD und am IDP, Authorisierung beim Fachdienst

  ```
  Wir senden einen gültigen Authorization Request (Nachricht 1 im App2App-Flow) an den Fachdienst

  Die HTTP Response (Nachricht 4 im App2App-Flow) muss:

  - den HTTP Status Code 302
  - mit Parameter request_uri weitergeleitet werden (als Nachricht 6 im App2App-Flow)

  Die darauf folgende HTTP Response (Nachricht 7 im App2App-Flow) muss:

  - den HTTP Status Code 302

    Given IDP Frontend sends an authorization request to fachdienst with
      | client_id            | scope    | code_challenge                              | code_challenge_method | redirect_uri            | state       | response_type |
      | ${TESTENV.client_id} | e-rezept | P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk | S256                  | ${TESTENV.redirect_uri} | xxxstatexxx | code          |
    Then the response status is 302

    When IDP Authenticator Module sends an authorization request to Fed_Sektoral_IDP_APP with
      | request_uri         |
      | $FILL_FROM_REDIRECT |

    Then the response status is 302

    When IDP I send an authorization code to fachdienst with
      | code                | state               |
      | $FILL_FROM_REDIRECT | $FILL_FROM_REDIRECT |

  # TODO: Unterscheidung zwischen app2app und web2app muss im flow eingebaut werden
    Then the response status is 200

#    Then the response status is 302
#
#    And IDP the response URI exists with param 'code' and value '.*'
#    And IDP the response URI exists with param 'state' and value '.*'
