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

package de.gematik.idp.field;

import com.fasterxml.jackson.annotation.JsonValue;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public enum ClaimName {
    GIVEN_NAME("given_name"),
    FAMILY_NAME("family_name"),
    ORGANIZATION_NAME("organizationName"),
    PROFESSION_OID("professionOID"),
    ID_NUMBER("idNummer"),
    ISSUED_AT("iat"),
    AUTH_TIME("auth_time"),
    ISSUER("iss"),
    EXPIRES_AT("exp"),
    ALGORITHM("alg"),
    RESPONSE_TYPE("response_type"),
    SCOPE("scope"),
    CLIENT_ID("client_id"),
    STATE("state"),
    REDIRECT_URI("redirect_uri"),
    TYPE("typ"),
    CONTENT_TYPE("cty"),
    JWT_ID("jti"),
    NOT_BEFORE("nbf"),
    CLIENT_SIGNATURE("csig"),
    NESTED_JWT("njwt"),
    CODE_CHALLENGE("code_challenge"), // (Hashwert des "code_verifier") [RFC7636 # section-4.2]
    CODE_CHALLENGE_METHOD("code_challenge_method"), // HASH-Algorithmus (S256) [RFC7636 # section-4.3]
    CONFIRMATION("cnf"), // gemSpec_IDP_Dienst
    CLAIMS("claims"), // gemSpec_IDP_Dienst
    AUTHENTICATION_CONTEXT_CLASS("acr"), // https://openid.net/specs/openid-connect-core-1_0.html#IDToken
    SUBJECT("sub"),
    X509_Certificate_Chain("x5c"),
    NONCE("snc"),
    AUDIENCE("aud"),
    JWKS_URI("jwks_uri"),
    ACR_VALUES_SUPPORTED("acr_values_supported");

    @JsonValue
    private final String joseName;
}
