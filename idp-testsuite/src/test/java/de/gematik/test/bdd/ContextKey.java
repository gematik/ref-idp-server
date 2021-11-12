/*
 * Copyright (c) 2021 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.test.bdd;

public interface ContextKey {

    String RESPONSE = "RESPONSE";
    String CLAIMS = "CLAIMS";
    String HEADER_CLAIMS = "HEADER_CLAIMS";
    String DISC_DOC = "DISC_DOC";
    String CHALLENGE = "CHALLENGE";
    String USER_CONSENT = "USER_CONSENT";
    String SIGNED_CHALLENGE = "SIGNED_CHALLENGE";
    String SSO_TOKEN = "SSO_TOKEN";
    String SSO_TOKEN_ENCRYPTED = "SSO_TOKEN_ENCRYPTED";
    String TOKEN_REDIRECT_URL = "TOKEN_REDIRECT_URL";
    String CODE_VERIFIER = "CODE_VERIFIER";
    String CLIENT_ID = "CLIENT_ID";
    String STATE = "STATE";
    String TOKEN_CODE = "TOKEN_CODE";
    String TOKEN_CODE_ENCRYPTED = "TOKEN_CODE_ENCRYPTED";
    String REDIRECT_URI = "REDIRECT_URI";
    String PUK_DISC = "PUK_DISC";
    String PUK_SIGN = "PUK_SIGN";
    String PUK_ENC = "PUK_ENC";
    String ACCESS_TOKEN_ENCRYPTED = "ACCESS_TOKEN_ENCRYPTED";
    String ACCESS_TOKEN = "ACCESS_TOKEN";
    String ID_TOKEN_ENCRYPTED = "ID_TOKEN_ENCRYPTED";
    String ID_TOKEN = "ID_TOKEN";
    String DEVICE_INFO = "DEVICE_INFO";
    String PAIRING_DATA = "PAIRING_DATA";
    String SIGNED_PAIRING_DATA = "SIGNED_PAIRING_DATA";
    String AUTHENTICATION_DATA = "AUTHENTICATION_DATA";
    String SIGEND_AUTHENTICATION_DATA = "SIGEND_AUTHENTICATION_DATA";
    String USER_AGENT = "USER_AGENT";
    String AUTH_URL_SEKTORAL_IDP = "AUTH_URL_SEKTORAL_IDP";

    String CUCUMBER_REGEX = "(RESPONSE|CLAIMS|HEADER_CLAIMS"
        + "|DISC_DOC"
        + "|CHALLENGE|USER_CONSENT"
        + "|SIGNED_CHALLENGE|SSO_TOKEN|SSO_TOKEN_ENCRYPTED"
        + "|TOKEN_REDIRECT_URL|CODE_VERIFIER|CLIENT_ID|STATE|TOKEN_CODE|TOKEN_CODE_ENCRYPTED"
        + "|REDIRECT_URI"
        + "|PUK_DISC|PUK_SIGN|PUK_ENC"
        + "|ACCESS_TOKEN|ACCESS_TOKEN_ENCRYPTED|ID_TOKEN_ENCRYPTED|ID_TOKEN"
        + "|DEVICE_INFO|PAIRING_DATA|SIGNED_PAIRING_DATA|AUTHENTICATION_DATA|SIGEND_AUTHENTICATION_DATA"
        + "|USER_AGENT)";

    String[] ENCRYPTED_KEYS = new String[]{
        SSO_TOKEN_ENCRYPTED, TOKEN_CODE_ENCRYPTED
    };
}
