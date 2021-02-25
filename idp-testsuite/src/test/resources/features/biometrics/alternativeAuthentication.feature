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
Feature: Alternative Authentisierung, Anwendung am IDP Server

  Frontends von TI Diensten müssen sich mit ihrem zuvor registrierten Pairingdaten beim IDP authentisieren können

  Background: Initialisiere Testkontext durch Abfrage des Discovery Dokuments und registriere Gerät
    Given I initialize scenario from discovery document endpoint
    And I retrieve public keys from URIs


  @todo:pairingdatenHinterlegen

  @Afo:A_20699-1 @Afo:A_20951-1 @Afo:A_20460
  @Todo:CheckAfos
  @Todo:NichtDeviceInformationTokenErzeugenWennNichtNotwendig
  @Approval
  @AlternatveAuth
  Scenario: Author mit alternativer Authentisierung (signed authentication data) - Gutfall - Validiere Antwortstruktur

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, bauen die signed authentication data passend zu dem im Background registrierten Pairing, signieren diese mit dem PrK_SE_Aut und
  fordern einen AUTHORIZATION_CODE mit den signed authentication data an.

  Die Antwort muss den Code 302 und die richtigen HTTP Header haben.

    Given I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I create a device information token with
      | device_name | device_manufacturer | device_product | device_model | device_os | device_version |
      | eRezeptApp  | Fair Phone          | FairPhone 3    | F3           | Android   | 1.0.2 f        |
    And I create pairing data with
      | key_data                     | key_identifier | signature_algorithm_identifier | device_product | serialnumber    | issuer  | not_after | public_key                                    |
      | /keys/valid/Pub_Se_Aut-1.pem | keyidauth002   | ES256                          | FairPhone 3    | 419094927676993 | Android | 1.0.2 f   | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'

    And I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 12345 | code          |
    And I create a device information token with
      | device_name | device_manufacturer | device_product | device_model | device_os | device_version |
      | eRezeptApp  | Fair Phone          | FairPhone 3    | F3           | Android   | 1.0.2 f        |
#      | device_information_data_version | name       | device_type_data_version | manufacturer | product     | model | os      | os_version |
#      | 0.1.0                           | eRezeptApp | 0.1.0                    | Fair Phone   | FairPhone 3 | F3    | Android | 8.0.0      |
    And I create authentication data with
      | authentication_data_version | authentication_cert                           | key_identifier | amr            |
      | 0.1.0                       | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyidauth002   | [mfa hwk face] |
    And I sign authentication data with '/keys/valid/Priv_Se_Aut-1-pkcs8.der'
    When I request a code token with alternative authentication
    Then the response status is 302
    And the response http headers match
        """
        Cache-Control=no-store
        Pragma=no-cache
        Content-Length=0
        Location=http.*code=.*
        """
    And I expect the Context with key STATE to match 'xxxstatexxx'
    And I expect the Context with key SSO_TOKEN to match '.*'


  @Afo:A_20699-1 @Afo:A_20951-1 @Afo:A_20460 @Afo:A_20731 @Afo:A_20310 @Afo:A_20377 @Afo:A_20697 @Afo:A_21317
  @Todo:ClarifyTokenCodeContentRelevant @Todo:CompareSubjectInfosInTokenAndInAuthenticationData @Todo:CheckAfos
  @Todo:CheckAmr
  @Approval
  @AlternatveAuth
  Scenario: Author mit alternativer Authentisierung (signed authentication data) - Gutfall - Validiere Location Header und Code Token Claims

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, bauen die signed authentication data passend zu dem im Background registrierten Pairing, signieren diese mit dem PrK_SE_Aut und
  fordern einen AUTHORIZATION_CODE mit den signed authentication data an.

  Die AUTHORIZATION_CODE Antwort muss im Location header state, code und SSO Token als Query Parameter enthalten und
  die richtigen Claims im Token haben.

    Given I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I create a device information token with
      | device_name | device_manufacturer | device_product | device_model | device_os | device_version |
      | eRezeptApp  | Fair Phone          | FairPhone 3    | F3           | Android   | 1.0.2 f        |
    And I create pairing data with
      | key_data                     | key_identifier | signature_algorithm_identifier | device_product | serialnumber    | issuer  | not_after | public_key                                    |
      | /keys/valid/Pub_Se_Aut-1.pem | keyidauth002   | ES256                          | FairPhone 3    | 419094927676993 | Android | 1.0.2 f   | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'

    And I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 12345 | code          |
    And I create a device information token with
      | device_name | device_manufacturer | device_product | device_model | device_os | device_version |
      | eRezeptApp  | Fair Phone          | FairPhone 3    | F3           | Android   | 1.0.2 f        |
#      | device_information_data_version | name       | device_type_data_version | manufacturer | product     | model | os      | os_version |
#      | 0.1.0                           | eRezeptApp | 0.1.0                    | Fair Phone   | FairPhone 3 | F3    | Android | 8.0.0      |
    And I create authentication data with
      | authentication_data_version | authentication_cert                           | key_identifier | amr            |
      | 0.1.0                       | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyidauth002   | [mfa hwk face] |
    And I sign authentication data with '/keys/valid/Priv_Se_Aut-1-pkcs8.der'
    When I request a code token with alternative authentication

    When I extract the header claims from token TOKEN_CODE
    Then the header claims should match in any order
        """
          { alg: "BP256R1",
            exp: "[\\d]*",
            kid: "${json-unit.ignore}",
            typ: "JWT"
          }
        """
    When I extract the body claims from token TOKEN_CODE
    Then the body claims should match in any order
        """
        {
            auth_time:             "${json-unit.ignore}",
            client_id:             "eRezeptApp",
            code_challenge:        "Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg",
            code_challenge_method: "S256",
            exp:                   "[\\d]*",
            jti:                   "${json-unit.ignore}",
            family_name:           "(.{1,64})",
            given_name:            "(.{1,64})",
            iat:                   "[\\d]*",
            idNummer:              "[A-Z][\\d]{9,10}",
            iss:                   "https://idp.zentral.idp.splitdns.ti-dienste.de",
            nbf:                   "[\\d]*",
            nonce:                 "12345",
            organizationName:      "(.{1,64})",
            professionOID:         "1\\.2\\.276\\.0\\.76\\.4\\.(3\\d|4\\d|178|23[2-90]|240|241)",
            redirect_uri:          "http://redirect.gematik.de/erezept",
            response_type:         "code",
            scope:                 "(e-rezept openid|openid e-rezept)",
            snc:                   ".*",
            state:                 "xxxstatexxx",
            token_type:            "code"
        }
        """

  @Afo:A_20624 @Afo:A_20319
  @Todo:checkAfos
  @Signature
  @Approval
  @AlternatveAuth
  Scenario: Author mit alternativer Authentisierung (signed authentication data) - Validiere Signatur des Code Token

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, bauen die signed authentication data passend zu dem im Background registrierten Pairing, signieren diese mit dem PrK_SE_Aut und
  fordern einen AUTHORIZATION_CODE mit den signed authentication data an.

  Der AUTHORIZATION_CODE muss mit dem passenden FD.Sig Zertifikat des IDPs gültig signiert sein.

    Given I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I create a device information token with
      | device_name | device_manufacturer | device_product | device_model | device_os | device_version |
      | eRezeptApp  | Fair Phone          | FairPhone 3    | F3           | Android   | 1.0.2 f        |
    And I create pairing data with
      | key_data                     | key_identifier | signature_algorithm_identifier | device_product | serialnumber    | issuer  | not_after | public_key                                    |
      | /keys/valid/Pub_Se_Aut-1.pem | keyidauth002   | ES256                          | FairPhone 3    | 419094927676993 | Android | 1.0.2 f   | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'

    And I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 12345 | code          |
    And I create a device information token with
      | device_name | device_manufacturer | device_product | device_model | device_os | device_version |
      | eRezeptApp  | Fair Phone          | FairPhone 3    | F3           | Android   | 1.0.2 f        |
#      | device_information_data_version | name       | device_type_data_version | manufacturer | product     | model | os      | os_version |
#      | 0.1.0                           | eRezeptApp | 0.1.0                    | Fair Phone   | FairPhone 3 | F3    | Android | 8.0.0      |
    And I create authentication data with
      | authentication_data_version | authentication_cert                           | key_identifier | amr            |
      | 0.1.0                       | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyidauth002   | [mfa hwk face] |
    And I sign authentication data with '/keys/valid/Priv_Se_Aut-1-pkcs8.der'
    When I request a code token with alternative authentication

    Then the context TOKEN_CODE must be signed with cert PUK_SIGN

  @Afo:A_20695
  @Todo:checkAfos
  @Signature
  @Approval
  @AlternatveAuth
  Scenario: Author mit alternativer Authentisierung (signed authentication data) - Validiere Signatur des SSO Token

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, bauen die signed authentication data passend zu dem im Background registrierten Pairing, signieren diese mit dem PrK_SE_Aut und
  fordern einen AUTHORIZATION_CODE und einen SSO_TOKEN mit den signed authentication data an.

  Der SSO_TOKEN muss mit dem Auth Zertifikat gültig signiert sein.

    Given I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I create a device information token with
      | device_name | device_manufacturer | device_product | device_model | device_os | device_version |
      | eRezeptApp  | Fair Phone          | FairPhone 3    | F3           | Android   | 1.0.2 f        |
    And I create pairing data with
      | key_data                     | key_identifier | signature_algorithm_identifier | device_product | serialnumber    | issuer  | not_after | public_key                                    |
      | /keys/valid/Pub_Se_Aut-1.pem | keyidauth002   | ES256                          | FairPhone 3    | 419094927676993 | Android | 1.0.2 f   | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'

    And I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 12345 | code          |
    And I create a device information token with
      | device_name | device_manufacturer | device_product | device_model | device_os | device_version |
      | eRezeptApp  | Fair Phone          | FairPhone 3    | F3           | Android   | 1.0.2 f        |
#      | device_information_data_version | name       | device_type_data_version | manufacturer | product     | model | os      | os_version |
#      | 0.1.0                           | eRezeptApp | 0.1.0                    | Fair Phone   | FairPhone 3 | F3    | Android | 8.0.0      |
    And I create authentication data with
      | authentication_data_version | authentication_cert                           | key_identifier | amr            |
      | 0.1.0                       | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyidauth002   | [mfa hwk face] |
    And I sign authentication data with '/keys/valid/Priv_Se_Aut-1-pkcs8.der'
    When I request a code token with alternative authentication

    Then the context SSO_TOKEN must be signed with cert PUK_SIGN


  @Afo:A_20731 @Afo:A_20310 @Afo:A_20464 @Afo:A_20952 @Afo:21320 @Afo:A_21321
  @Todo:checkAfos
  @Todo:amrAnpassen
  @Todo:CompareSubjectInfosInAccessTokenAndInCert
  @Approval
  @AlternatveAuth
  @OpenBug
    # TODO: wollen wir noch den Wert der auth_time gegen den Zeitpunkt der Authentifizierung pruefen
  Scenario: GetToken signed pairing data - Gutfall - Check Access Token - Validiere Access Token Claims

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, bauen die signed authentication data passend zu dem im Background registrierten Pairing, signieren diese mit dem PrK_SE_Aut.
  fordern einen AUTHORIZATION_CODE und damit dann einen ACCESS_TOKEN.

  Der ACCESS_TOKEN muss die richtigen Claims mit den richtigen Inhalten haben.

    Given I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I create a device information token with
      | device_name | device_manufacturer | device_product | device_model | device_os | device_version |
      | eRezeptApp  | Fair Phone          | FairPhone 3    | F3           | Android   | 1.0.2 f        |
    And I create pairing data with
      | key_data                     | key_identifier | signature_algorithm_identifier | device_product | serialnumber    | issuer  | not_after | public_key                                    |
      | /keys/valid/Pub_Se_Aut-1.pem | keyidauth002   | ES256                          | FairPhone 3    | 419094927676993 | Android | 1.0.2 f   | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'

    And I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 12345 | code          |
    And I create a device information token with
      | device_name | device_manufacturer | device_product | device_model | device_os | device_version |
      | eRezeptApp  | Fair Phone          | FairPhone 3    | F3           | Android   | 1.0.2 f        |
#      | device_information_data_version | name       | device_type_data_version | manufacturer | product     | model | os      | os_version |
#      | 0.1.0                           | eRezeptApp | 0.1.0                    | Fair Phone   | FairPhone 3 | F3    | Android | 8.0.0      |
    And I create authentication data with
      | authentication_data_version | authentication_cert                           | key_identifier | amr            |
      | 0.1.0                       | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyidauth002   | [mfa hwk face] |
    And I sign authentication data with '/keys/valid/Priv_Se_Aut-1-pkcs8.der'
    When I request a code token with alternative authentication
    And I set the context with key REDIRECT_URI to 'http://redirect.gematik.de/erezept'
    And I request an access token

    When I extract the header claims from token ACCESS_TOKEN
    Then the header claims should match in any order
        """
          { alg: "BP256R1",
            exp: "[\\d]*",
            kid: "${json-unit.ignore}",
            typ: "at+JWT"
          }
        """
    When I extract the body claims from token ACCESS_TOKEN
    Then the body claims should match in any order
        """
          { acr:              "gematik-ehealth-loa-high",
            aud:              "https://erp.telematik.de/login",
            amr:              "[mfa hwk face]",
            auth_time:        "[\\d]*",
            azp:              "eRezeptApp",
            client_id:        "eRezeptApp",
            exp:              "[\\d]*",
            jti:              "${json-unit.ignore}",
            family_name:      "(.{1,64})",
            given_name:       "(.{1,64})",
            iat:              "[\\d]*",
            idNummer:         "[A-Z][\\d]{9,10}",
            iss:              "http.*",
            organizationName: "(.{1,64})",
            professionOID:    "1\\.2\\.276\\.0\\.76\\.4\\.(3\\d|4\\d|178|23[2-90]|240|241)",
            scope:            "(openid e-rezept|e-rezept openid)",
            sub:              ".*"
          }
        """

  @Afo:A_21321
  @Todo:checkAfos
  @Todo:amrAnpassen
  @Approval
  @AlternatveAuth
  @OpenBug
  Scenario: GetToken signed pairing data - Gutfall - Check ID Token - Validiere ID Token Claims
    Given I request an pairing access token with eGK cert '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I create a device information token with
      | device_name | device_manufacturer | device_product | device_model | device_os | device_version |
      | eRezeptApp  | Fair Phone          | FairPhone 3    | F3           | Android   | 1.0.2 f        |
    And I create pairing data with
      | key_data                     | key_identifier | signature_algorithm_identifier | device_product | serialnumber    | issuer  | not_after | public_key                                    |
      | /keys/valid/Pub_Se_Aut-1.pem | keyidauth002   | ES256                          | FairPhone 3    | 419094927676993 | Android | 1.0.2 f   | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 |
    And I sign pairing data with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'
    And I register the device with '/certs/valid/egk-idp-idnumber-a-valid-ecc.p12'

    And I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 12345 | code          |
    And I create a device information token with
      | device_name | device_manufacturer | device_product | device_model | device_os | device_version |
      | eRezeptApp  | Fair Phone          | FairPhone 3    | F3           | Android   | 1.0.2 f        |
#      | device_information_data_version | name       | device_type_data_version | manufacturer | product     | model | os      | os_version |
#      | 0.1.0                           | eRezeptApp | 0.1.0                    | Fair Phone   | FairPhone 3 | F3    | Android | 8.0.0      |
    And I create authentication data with
      | authentication_data_version | authentication_cert                           | key_identifier | amr            |
      | 0.1.0                       | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyidauth002   | [mfa hwk face] |
    And I sign authentication data with '/keys/valid/Priv_Se_Aut-1-pkcs8.der'
    When I request a code token with alternative authentication
    And I set the context with key REDIRECT_URI to 'http://redirect.gematik.de/erezept'
    And I request an access token

    When I extract the header claims from token ID_TOKEN
    Then the header claims should match in any order
        """
          { alg: "BP256R1",
            exp: "[\\d]*",
            kid: "${json-unit.ignore}",
            typ: "JWT"
          }
        """
    When I extract the body claims from token ID_TOKEN
    Then the body claims should match in any order
        """
          { acr:              "eidas-loa-high",
            amr:              '["mfa", "hwk", "face"]',
            at_hash:          ".*",
            aud:              "eRezeptApp",
            auth_time:        "[\\d]*",
            azp:              "eRezeptApp",
            exp:              "[\\d]*",
            family_name:      "(.{1,64})",
            given_name:       "(.{1,64})",
            iat:              "[\\d]*",
            idNummer:         "[A-Z][\\d]{9,10}",
            iss:              "http.*",
            nonce:            "98765",
            professionOID:    "1\\.2\\.276\\.0\\.76\\.4\\.(3\\d|4\\d|178|23[2-90]|240|241)",
            organizationName: "(.{1,64})",
            sub:              ".*"
          }
        """

# ------------------------------------------------------------------------------------------------------------------
    #
    # negative cases

  @WIP
  Scenario: Author mit alternativer Authentisierung (signed authentication data) - Aufruf ohne Parameter

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, bauen die signed authentication data passend zu dem im Background registrierten Pairing, signieren diese mit dem PrK_SE_Aut und
  fordern einen TOKEN_CODE, ohne den Parameter "signed_authentication_data" mitzugeben.

  Der Server muss diese Anfrage mit HTTP Status 302 und einer Fehlermeldung im Location Header ablehnen.

    Given I choose code verifier 'sfnejkgsjknsfeknsknvgsrlgmreklgmnksrnvgjksnvgseklgvsrklmslrkbmsrklgnrvsgklsrgnksrf'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state        | nonce | response_type |
      | eRezeptApp | e-rezept openid | ds7JaEfpdLidWekR52OhoVpjXHDlplLyV3GtUezxfY0 | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx1 | 1212  | code          |

    When I request a code token with no params
    Then the response is an 302 error with code 'invalid_request' and message matching 'validateChallengeAndGetTokenCode.signedChallenge%3A%20must%20not%20be%20null'

  @WIP
  @Todo:testfallAnpassenDerServerHatNichtSoVieleDatenInDatenbankHierWirdGegenBlockAllowListGeprueft
  Scenario: Author mit alternativer Authentisierung (signed authentication data) - Gutfall - fehlende Parameter in device_information

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, bauen die signed authentication data passend zu dem im Background registrierten Pairing, signieren diese mit dem PrK_SE_Aut und
  fordern einen AUTHORIZATION_CODE mit den signed authentication data an. In den device_information fehlt ein Parameter, daher kann das Gerät nicht mehr auf der Allow-List gefunden werden

  Der Server muss diese Anfrage mit HTTP Status 302 und einer Fehlermeldung im Location Header ablehnen.

    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 12345 | code          |
    And I create a device information token with
      | device_information_data_version | name       | device_type_data_version | manufacturer | product     | model | os      | os_version |
      | 0.1.0                           | eRezeptApp | 0.1.0                    | $NULL        | FairPhone 3 | F3    | Android | 8.0.0      |
    And I create authentication data with
      | authentication_data_version | auth_certificate                              | key_identifier | amr                    |
      | 0.1.0                       | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyident002    | ["mfa","hwk", "face" ] |
    And I sign authentication data with '/keys/valid/Priv_Se_Aut-1-pkcs8.der'
    When I request a code token with alternative authentication
    Then the response is an 302 error with code 'invalid_request' and message matching 'validateChallengeAndGetTokenCode.signedChallenge%3A%20must%20not%20be%20null'

  @Todo:RueckspracheMitHannesOhneAmrAblehnen
  @WIP
  Scenario: Author mit alternativer Authentisierung (signed authentication data) - Gutfall - fehlende AMR in authentication_data

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, bauen die signed authentication data passend zu dem im Background registrierten Pairing, signieren diese mit dem PrK_SE_Aut und
  fordern einen AUTHORIZATION_CODE mit den signed authentication data an. In den authentication_data fehlt die AMR.

  Der Server muss diese Anfrage mit HTTP Status 302 und einer Fehlermeldung im Location Header ablehnen.

    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 12345 | code          |
    And I create a device information token with
      | device_information_data_version | name       | device_type_data_version | manufacturer | product     | model | os      | os_version |
      | 0.1.0                           | eRezeptApp | 0.1.0                    | Fair Phone   | FairPhone 3 | F3    | Android | 8.0.0      |
    And I create authentication data with
      | authentication_data_version | auth_certificate                              | key_identifier | amr   |
      | 0.1.0                       | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyident002    | $NULL |
    And I sign authentication data with '/keys/valid/Priv_Se_Aut-1-pkcs8.der'
    When I request a code token with alternative authentication
    Then the response is an 302 error with code 'invalid_request' and message matching 'validateChallengeAndGetTokenCode.signedChallenge%3A%20must%20not%20be%20null'


  @Afo:A_20951-1
  @Todo:checkAfos
  @Todo:ErrorMessages
  @Todo:HierMitZuvorRegistrietenDatenArbeitenDamitManNichtEtwasUngueltigesRegistrierenMussUndDaranScheitert
  @WIP
  Scenario: Author mit alternativer Authentisierung (signed authentication data) - im signed authenication data ist ein abgelaufenes zertifikat hinterlegt

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, bauen die signed authentication data passend zu dem im Background registrierten Pairing, signieren diese mit dem PrK_SE_Aut und
  fordern einen TOKEN_CODE mit den signed authentication data an. In den signed authentication data ist ein abgelaufenes zertifikat hinterlegt

  Der Server muss diese Anfrage mit HTTP Status 302 und einer Fehlermeldung im Location Header ablehnen.


    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 3344  | code          |
    And I create a device information token with
      | device_information_data_version | name       | device_type_data_version | manufacturer | product     | model | os      | os_version |
      | 0.1.0                           | eRezeptApp | 0.1.0                    | Fair Phone   | FairPhone 3 | F3    | Android | 8.0.0      |
    And I create authentication data with
      | authentication_data_version | auth_certificate                              | key_identifier | amr                    |
      | 0.1.0                       | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyident002    | ["mfa","hwk", "face" ] |
    And I sign authentication data with '/keys/valid/Priv_Se_Aut-1-pkcs8.der'
    When I request a code token with alternative authentication
    Then the response is an 302 error with code 'invalid_request' and message matching 'TODO'

  @WIP
  @Afo:A_20951-1
  @Todo:checkAfos
  @Todo:ErrorMessages
  @Todo:HierMitZuvorRegistrietenDatenArbeitenDamitManNichtEtwasUngueltigesRegistrierenMussUndDaranScheitert
  Scenario: Author mit alternativer Authentisierung (signed authentication data) - im signed authenication data ist ein gesperrtes zertifikat hinterlegt

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, bauen die signed authentication data passend zu dem im Background registrierten Pairing, signieren diese mit dem PrK_SE_Aut und
  fordern einen TOKEN_CODE mit den signed authentication data an. In den signed authentication data ist ein gesperrtes zertifikat hinterlegt

  Der Server muss diese Anfrage mit HTTP Status 302 und einer Fehlermeldung im Location Header ablehnen.


    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 3344  | code          |
    And I create a device information token with
      | device_information_data_version | name       | device_type_data_version | manufacturer | product     | model | os      | os_version |
      | 0.1.0                           | eRezeptApp | 0.1.0                    | Fair Phone   | FairPhone 3 | F3    | Android | 8.0.0      |
    And I create authentication data with
      | authentication_data_version | auth_certificate                              | key_identifier | amr                    |
      | 0.1.0                       | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyident002    | ["mfa","hwk", "face" ] |
    And I sign authentication data with '/keys/valid/Priv_Se_Aut-1-pkcs8.der'
    When I request a code token with alternative authentication
    Then the response is an 302 error with code 'invalid_request' and message matching 'TODO'

  @Afo:A_20951-1
  @Todo:checkAfos
  @Todo:ErrorMessages
  @Todo:HierMitZuvorRegistrietenDatenArbeitenDamitManNichtEtwasUngueltigesRegistrierenMussUndDaranScheitert
  @WIP
  Scenario: Author mit alternativer Authentisierung (signed authentication data) - im signed authenication data ist ein falsches zertifikat (andere idNumber) hinterlegt

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, bauen die signed authentication data passend zu dem im Background registrierten Pairing, signieren diese mit dem PrK_SE_Aut und
  fordern einen TOKEN_CODE mit den signed authentication data an. In den signed authentication data ist ein zertifikat mit einer anderen idNumber hinterlegt

  Der Server muss diese Anfrage mit HTTP Status 302 und einer Fehlermeldung im Location Header ablehnen.


    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 3344  | code          |
    And I create a device information token with
      | device_information_data_version | name       | device_type_data_version | manufacturer | product     | model | os      | os_version |
      | 0.1.0                           | eRezeptApp | 0.1.0                    | Fair Phone   | FairPhone 3 | F3    | Android | 8.0.0      |
    And I create authentication data with
      | authentication_data_version | auth_certificate                              | key_identifier | amr                    |
      | 0.1.0                       | /certs/valid/egk-idp-idnumber-b-valid-ecc.p12 | keyident002    | ["mfa","hwk", "face" ] |
    And I sign authentication data with '/keys/valid/Priv_Se_Aut-1-pkcs8.der'
    When I request a code token with alternative authentication
    Then the response is an 302 error with code 'invalid_request' and message matching 'TODO'

  @Afo:A_20951-1
  @Todo:checkAfos
  @Todo:ErrorMessages
  @Todo:HierMitZuvorRegistrietenDatenArbeitenDamitManNichtEtwasUngueltigesRegistrierenMussUndDaranScheitert
  @WIP
  Scenario: Author mit alternativer Authentisierung (signed authentication data) - im signed authenication data ist ein falsches zertifikat (gleiche idNumber) hinterlegt

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, bauen die signed authentication data passend zu dem im Background registrierten Pairing, signieren diese mit dem PrK_SE_Aut und
  fordern einen TOKEN_CODE mit den signed authentication data an. In den signed authentication data ist ein anderes Zertifikat als bei der registrierung, aber mit derselben idNumber hinterlegt

  Der Server muss diese Anfrage mit HTTP Status 302 und einer Fehlermeldung im Location Header ablehnen (weil er die signatur der signed_pairing_data nicht validieren kann).


    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 3344  | code          |
    And I create a device information token with
      | device_information_data_version | name       | device_type_data_version | manufacturer | product     | model | os      | os_version |
      | 0.1.0                           | eRezeptApp | 0.1.0                    | Fair Phone   | FairPhone 3 | F3    | Android | 8.0.0      |
    And I create authentication data with
      | authentication_data_version | auth_certificate                              | key_identifier | amr                    |
      | 0.1.0                       | /certs/valid/egk-idp-idnumber-b-valid-ecc.p12 | keyident002    | ["mfa","hwk", "face" ] |
    And I sign authentication data with '/keys/valid/Priv_Se_Aut-1-pkcs8.der'
    When I request a code token with alternative authentication
    Then the response is an 302 error with code 'invalid_request' and message matching 'TODO'


  @Afo:A_20951-1
  @Todo:checkAfos
  @Todo:ErrorMessages
  @WIP
  Scenario: Author mit alternativer Authentisierung (signed authentication data) - key_identifier passt nicht zum vorhandenen pairing

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, bauen die signed authentication data passend zu dem im Background registrierten Pairing, signieren diese mit dem PrK_SE_Aut und
  fordern einen TOKEN_CODE mit den signed authentication data an. In den signed authentication data ist ein zertifikat mit einer anderen idNumber hinterlegt

  Der Server muss diese Anfrage mit HTTP Status 302 und einer Fehlermeldung im Location Header ablehnen.


    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 3344  | code          |
    And I create a device information token with
      | device_information_data_version | name       | device_type_data_version | manufacturer | product     | model | os      | os_version |
      | 0.1.0                           | eRezeptApp | 0.1.0                    | Fair Phone   | FairPhone 3 | F3    | Android | 8.0.0      |
    And I create authentication data with
      | authentication_data_version | auth_certificate                              | key_identifier     | amr                    |
      | 0.1.0                       | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | invalidkeyident003 | ["mfa","hwk", "face" ] |
    And I sign authentication data with '/keys/valid/Priv_Se_Aut-1-pkcs8.der'
    When I request a code token with alternative authentication
    Then the response is an 302 error with code 'invalid_request' and message matching 'TODO'


  @Todo:checkAfos
  @Todo:ErrorMessages
  @WIP
  Scenario: Author mit alternativer Authentisierung (signed authentication data) - im signed authenication data fehlen device informationen

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, bauen die signed authentication data aber ohne device_information, signieren diese mit dem PrK_SE_Aut und
  fordern einen TOKEN_CODE mit den signed authentication data an.

  Der Server muss diese Anfrage mit HTTP Status 302 und einer Fehlermeldung im Location Header ablehnen.


    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 3344  | code          |
    And I create authentication data with
      | authentication_data_version | auth_certificate                              | key_identifier | amr                    |
      | 0.1.0                       | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | keyident002    | ["mfa","hwk", "face" ] |
    And I sign authentication data with '/keys/valid/Priv_Se_Aut-1-pkcs8.der'
    When I request a code token with alternative authentication
    Then the response is an 302 error with code 'invalid_request' and message matching 'TODO'


  @Afo:A_20951-1
  @Todo:checkAfos
  @Todo:ErrorMessages
  @Todo:HierMitZuvorRegistrietenDatenArbeitenDamitManNichtEtwasUngueltigesRegistrierenMussUndDaranScheitert
  @WIP
  Scenario: Author mit alternativer Authentisierung (signed authentication data) - Signatur der signed authenication data ist mit falschem Schlüssel erstellt

  ```
  Wir wählen einen gültigen Code verifier, fordern einen Challenge Token an, bauen die signed authentication data passend zu dem im Background registrierten Pairing, signieren diese mit einem anderen PrK_SE_Aut als dem zuvor registrierten und
  fordern einen TOKEN_CODE mit den signed authentication data an.

  Der Server muss diese Anfrage mit HTTP Status 302 und einer Fehlermeldung im Location Header ablehnen.


    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 3344  | code          |
    And I create a device information token with
      | device_information_data_version | name       | device_type_data_version | manufacturer | product     | model | os      | os_version |
      | 0.1.0                           | eRezeptApp | 0.1.0                    | Fair Phone   | FairPhone 3 | F3    | Android | 8.0.0      |
    And I create authentication data with
      | authentication_data_version | auth_certificate                              | key_identifier     | amr                    |
      | 0.1.0                       | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | invalidkeyident003 | ["mfa","hwk", "face" ] |
    And I sign authentication data with '/keys/valid/Priv_Se_Aut-2-pkcs8.der'
    When I request a code token with alternative authentication
    Then the response is an 302 error with code 'invalid_request' and message matching 'TODO'


  @WIP
  Scenario: Author mit alternativer Authentisierung (signed authentication data) - pairing daten wurden vorher gelöscht

  ```
  Wir löschen einen bestimmten Pairing Entry. Dann wählen wir einen gültigen Code verifier, fordern einen Challenge Token an, bauen die signed authentication data passend zu dem zuvor gelöschten Pairing, signieren diese mit dem PrK_SE_Aut und
  fordern einen TOKEN_CODE mit den signed authentication data an.

  Der Server muss diese Anfrage mit HTTP Status 302 und einer Fehlermeldung im Location Header ablehnen.


    Given I choose code verifier 'drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj'
    And I request a challenge with
      | client_id  | scope           | code_challenge                              | code_challenge_method | redirect_uri                       | state       | nonce | response_type |
      | eRezeptApp | e-rezept openid | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | http://redirect.gematik.de/erezept | xxxstatexxx | 3344  | code          |
    And I create a device information token with
      | device_information_data_version | name       | device_type_data_version | manufacturer | product     | model | os      | os_version |
      | 0.1.0                           | eRezeptApp | 0.1.0                    | Fair Phone   | FairPhone 3 | F3    | Android | 8.0.0      |
    And I create authentication data with
      | authentication_data_version | auth_certificate                              | key_identifier     | amr                    |
      | 0.1.0                       | /certs/valid/egk-idp-idnumber-a-valid-ecc.p12 | invalidkeyident003 | ["mfa","hwk", "face" ] |
    And I sign authentication data with '/keys/valid/Priv_Se_Aut-1-pkcs8.der'
    When I request a code token with alternative authentication
    Then the response is an 302 error with code 'invalid_request' and message matching 'TODO'
