@testsuite
Feature: Authenticate app at IDP
    Client applications of TI services need to be able to request a code challenge token
    from the authorization end point via GET method.

    Background: Initialize from discovery document
        Given I initialize scenario from discovery document endpoint

    @Afo:A_20601
    @Afo:A_20740
    @OpenBug
    Scenario: Gutfall
        Given I choose code verifier '123123123'
        When I request a challenge with status successfully with
            | client_id | scope           | code_challenge                                                   | code_challenge_method | redirect_uri          | state       |
            | erezept   | e-rezept openid | 932F3C1B56257CE8539AC269D7AAB42550DACF8818D075F0BDF1990562AAE3EF | S256                  | http://localhost:8080 | xxxstatexxx |
        Then the response status is 200
        # TODO validate response

    @Afo:A_20601
        @Afo:A_20740
        @OpenBug
        @issue:IDP-331
    Scenario Outline: Missing parameters
        When I request a challenge with status unsuccessfully with
            | client_id   | scope   | code_challenge   | code_challenge_method   | redirect_uri   | state   |
            | <client_id> | <scope> | <code_challenge> | <code_challenge_method> | <redirect_uri> | <state> |
        Then the response status is 400

        Examples: Param lists for authorization endpoint with one param missing
            | client_id | scope           | code_challenge                                                   | code_challenge_method | redirect_uri          | state       |
            | $REMOVE   | e-rezept openid | 932F3C1B56257CE8539AC269D7AAB42550DACF8818D075F0BDF1990562AAE3EF | S256                  | http://localhost:8080 | xxxstatexxx |
            | erezept   | $REMOVE         | $REMOVE                                                          | S256                  | http://localhost:8080 | xxxstatexxx |
            | erezept   | e-rezept openid | $REMOVE                                                          | S256                  | http://localhost:8080 | xxxstatexxx |
            | erezept   | e-rezept openid | 932F3C1B56257CE8539AC269D7AAB42550DACF8818D075F0BDF1990562AAE3EF | $REMOVE               | http://localhost:8080 | xxxstatexxx |
            | erezept   | e-rezept openid | 932F3C1B56257CE8539AC269D7AAB42550DACF8818D075F0BDF1990562AAE3EF | S256                  | $REMOVE               | xxxstatexxx |
            | erezept   | e-rezept openid | 932F3C1B56257CE8539AC269D7AAB42550DACF8818D075F0BDF1990562AAE3EF | S256                  | http://localhost:8080 | $REMOVE     |

    @Afo:A_20601
        @Afo:A_20740
        @OpenBug
        @issue:IDP-331
    Scenario Outline: Null parameters
        When I request a challenge with status unsuccessfully with
            | client_id   | scope   | code_challenge   | code_challenge_method   | redirect_uri   | state   |
            | <client_id> | <scope> | <code_challenge> | <code_challenge_method> | <redirect_uri> | <state> |
        Then the response status is 400

        Examples:
            | client_id | scope           | code_challenge                                                   | code_challenge_method | redirect_uri          | state       |
            | $NULL     | e-rezept openid | 932F3C1B56257CE8539AC269D7AAB42550DACF8818D075F0BDF1990562AAE3EF | S256                  | http://localhost:8080 | xxxstatexxx |
            | erezept   | $NULL           | 932F3C1B56257CE8539AC269D7AAB42550DACF8818D075F0BDF1990562AAE3EF | S256                  | http://localhost:8080 | xxxstatexxx |
            | erezept   | e-rezept openid | $NULL                                                            | S256                  | http://localhost:8080 | xxxstatexxx |
            | erezept   | e-rezept openid | 932F3C1B56257CE8539AC269D7AAB42550DACF8818D075F0BDF1990562AAE3EF | $NULL                 | http://localhost:8080 | xxxstatexxx |
            | erezept   | e-rezept openid | 932F3C1B56257CE8539AC269D7AAB42550DACF8818D075F0BDF1990562AAE3EF | S256                  | $NULL                 | xxxstatexxx |
            | erezept   | e-rezept openid | 932F3C1B56257CE8539AC269D7AAB42550DACF8818D075F0BDF1990562AAE3EF | S256                  | http://localhost:8080 | $NULL       |

    @Afo:A_20601
        @OpenBug
    Scenario Outline: Invalid parameters
        When I request a challenge with status unsuccessfully with
            | client_id   | scope   | code_challenge   | code_challenge_method   | redirect_uri   | state   |
            | <client_id> | <scope> | <code_challenge> | <code_challenge_method> | <redirect_uri> | <state> |
        Then the response status is 400

        Examples: Invalid parameters
            | client_id          | scope           | code_challenge                                                   | code_challenge_method | redirect_uri          | state       |
            # invalid client_id
            | resistanceisfutile | openid e-rezept | 932F3C1B56257CE8539AC269D7AAB42550DACF8818D075F0BDF1990562AAE3EF | S256                  | http://localhost:8080 | xxxstatexxx |
            # invalid scope values
            | erezept            | e-rezept        | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg                      | S256                  | http://localhost:8080 | xxxstatexxx |

