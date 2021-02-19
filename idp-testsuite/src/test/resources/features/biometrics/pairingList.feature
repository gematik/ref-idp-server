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
Feature: Fordere Pairingliste für Alternative Authentisierung am IDP Server an

  Frontends müssen mit einer eGK und einem Pairing Access oder SSO Token ihre Pairings einsehen können.
  # TODO nutze für die Scenarios in diesem feature eigenes ZERT mit eigener IDNummer um concurrency issues mit den paralellen tests zu verunmöglichen

  Background: Initialisiere Testkontext durch Abfrage des Discovery Dokuments
    Given I initialize scenario from discovery document endpoint
    And I retrieve public keys from URIs

  @Todo:InhalteDerPairingDataBefüllen
  Scenario: Biometrie Pairingliste - Gutfall - Erzeuge einen Pairingeintrag für IDNummer und fordere Pairingliste an
    # TODO erzeuge pairing eintrag
    Given I request an pairing access token with eGK cert '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
    When I request all pairings
    # TODO check correct response data

  Scenario: Biometrie Pairingliste - Gutfall - Erzeuge mehrere Pairingeinträge für IDNummer und fordere Pairingliste an

  Scenario: Biometrie Pairingliste - Fordere Pairingliste an für nicht existente IdNummer

  Scenario: Biometrie Pairingliste - Fordere Pairingliste an mit eRezept Access Token

  Scenario: Biometrie Pairingliste - Fordere Pairingliste an mit eRezept SSO Token

  # obsolet da wir keinen access token kriegen
  # Scenario: Biometrie Pairingliste - Fordere Pairingliste an mit Zertifikat ohne IDNummer

