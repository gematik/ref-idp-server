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

package de.gematik.idp;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class IdpConstants {

    public static final String DISCOVERY_DOCUMENT_ENDPOINT = "/discoveryDocument";
    public static final String AUTHORIZATION_ENDPOINT = "/authorization";
    public static final String TOKEN_ENDPOINT = "/token";
    public static final String PAIRING_ENDPOINT = "/pairing";
    public static final String PUK_URI_AUTH = "/authKey/jwks.json";
    public static final String PUK_URI_TOKEN = "/tokenKey/jwks.json";
    public static final String PUK_URI_DISC = "/discKey/jwks.json";
    public static final String CLIENT_ID = "eRezeptApp";
    public static final String AUDIENCE = "https://erp.zentral.erp.splitdns.ti-dienste.de";
    public static final int JTI_LENGTH = 16;
}
