/*
 * Copyright (c) 2021 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.idp.test.steps.model;

public enum ContextKey {
    RESPONSE, CLAIMS, HEADER_CLAIMS,
    DISC_DOC,
    CHALLENGE, USER_CONSENT,
    SIGNED_CHALLENGE, SSO_TOKEN, SSO_TOKEN_ENCRYPTED,
    TOKEN_REDIRECT_URL, CODE_VERIFIER, CLIENT_ID, STATE, TOKEN_CODE, TOKEN_CODE_ENCRYPTED,
    REDIRECT_URI,
    PUK_DISC, PUK_AUTH, PUK_TOKEN,
    ACCESS_TOKEN, ID_TOKEN,
    DEVICE_INFO, PAIRING_DATA, SIGNED_PAIRING_DATA;

    public final static String CUCUMBER_REGEX = "(RESPONSE|CLAIMS|HEADER_CLAIMS"
        + "|DISC_DOC"
        + "|CHALLENGE|USER_CONSENT"
        + "|SIGNED_CHALLENGE|SSO_TOKEN|SSO_TOKEN_ENCRYPTED"
        + "|TOKEN_REDIRECT_URL|CODE_VERIFIER|CLIENT_ID|STATE|TOKEN_CODE|TOKEN_CODE_ENCRYPTED"
        + "|REDIRECT_URI"
        + "|PUK_DISC|PUK_AUTH|PUK_TOKEN"
        + "|ACCESS_TOKEN|ID_TOKEN"
        + "|DEVICE_INFO|PAIRING_DATA|SIGNED_PAIRING_DATA)";
}
