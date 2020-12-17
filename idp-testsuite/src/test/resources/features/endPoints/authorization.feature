@testsuite
Feature: Authorize app at IDP
    Client applications of TI services need to be able to request a token code
    from the authorization end point via POST method.

    Background: Initialize from discovery document
        Given I initialize scenario from discovery document endpoint

    @OpenBug
    Scenario: Gutfall ohne SSO Token
        Given I choose code verifier '123123123'
        Given I request a challenge with status successfully with
            | client_id | scope           | code_challenge                                                   | code_challenge_method | redirect_uri        | state       |
            | erezept   | e-rezept openid | 932F3C1B56257CE8539AC269D7AAB42550DACF8818D075F0BDF1990562AAE3EF | S256                  | http:localhost:8080 | xxxstatexxx |
        When I sign the challenge with '/certs/valid/80276883110000018680-C_CH_AUT_E256.p12'
        And I request a code token with SIGNED_CHALLENGE with status successfully
        Then the response status is 302
        # TODO swagger docu says 200 as successful status! FIX SWAGGER DOCU
        # TODO validate response

    @OpenBug
    Scenario: Gutfall mit SSO Token
        Given I choose code verifier '123123123'
        And I request a challenge with status successfully with
            | client_id | scope           | code_challenge                                                   | code_challenge_method | redirect_uri        | state       |
            | erezept   | e-rezept openid | 932F3C1B56257CE8539AC269D7AAB42550DACF8818D075F0BDF1990562AAE3EF | S256                  | http:localhost:8080 | xxxstatexxx |
        When I request a code token with SSO_TOKEN with status successfully
        Then the response status is 302
        # TODO validate response


    # TODO negative cases


