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
@biometrics
Feature: Deregistrierung für Alternative Authentisierung am IDP Server

  Frontends müssen mit eGK und auch mit alternativer Authentisierung Geräte deregistrieren können.

  Background: Initialisiere Testkontext durch Abfrage des Discovery Dokuments
    Given I initialize scenario from discovery document endpoint
    And I retrieve public keys from URIs

  @Todo:InhalteDerPairingDataBefüllen
  Scenario: Biometrie Deregister - Gutfall - Erzeuge Pairing und lösche dieses wieder
    Given I request an pairing access token with eGK cert '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And I create a device information token with
      | device_name | device_manufacturer | device_product | device_model | device_os | device_version |
      | eRezeptApp  | Fair Phone          | FairPhone 3    | F3           | Android   | 1.0.2 f        |
    And I create pairing data with
      | key_data                                           | key_identifier | signature_algorithm_identifier | device_product | cert_id       | issuer  | not_after | public_key                                          |
      | /keys/valid/80276883110000018680-C_CH_AUT_E256.p12 | thisismykey2   | ES256                          | FairPhone 3    | grgdgfdgfdhfd | Android | 1.0.2 f   | /certs/valid/80276883110000018680-C_CH_AUT_E256.p12 |
    And I sign pairing data with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    And I register the device with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'

    When I deregister the device with 'thisismykey2'
    Then the response status is 200

  Scenario: Biometrie Deregister - Gutfall - Erzeuge mehrere Pairings und lösche nur eines

  Scenario: Biometrie Deregister - Lösche Pairing für nicht existenten key identifier

  Scenario: Biometrie Deregister - Lösche Pairing für key identifier einer anderen IDNummer

    # mir ist hier noch nicht klar, wann genau das zerifikat keine IDNumber hat
  Scenario: Biometrie Deregister - Lösche Pairing mit Zertifikate ohne IDNummer

  Scenario: Biometrie Deregister - Lösche Pairing mit e-Rezept Access Token

  Scenario: Biometrie Deregister - Lösche Pairing mit e-Rezept SSO Token

  Scenario: Biometrie Deregister - Lösche Pairing fehlender key identifier in der Anfrage

  Scenario: Biometrie Deregister - Lösche Pairing Null key identifier in der Anfrage

    # alles passt, aber der client hat sich einen access token mit scope eRezept und nicht pairing ausstellen lassen -> ablehnen
  Scenario: Biometrie Registrierung - Zugriff mit ACCESS_TOKEN mit falschem Scope
