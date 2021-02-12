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

package de.gematik.idp.error;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public enum IdpErrorType {

    INVALID_REQUEST("The request is malformed."),
    INVALID_CLIENT("Client authentication failed"),
    INVALID_CLIENT_CERTIFICATE("Client certificate validation failed"),
    INVALID_GRANT("The provided authorization grant or refresh token is invalid, expired, revoked, "
        + "does not match the redirection URI used in the authorization request, or was issued to another client."),
    UNAUTHORIZED_CLIENT("The authenticated client is not authorized to use this authorization grant type."),
    URI_BUILDER_ERROR("The authenticated client is not authorized to use this authorization grant type."),
    UNSUPPORTED_GRANT_TYPE("The authorization grant type is not supported by the authorization server."),
    INVALID_SCOPE("The requested scope is invalid, unknown, malformed, or exceeds the scope granted by the "
        + "resource owner."),
    ACCESS_DENIED("The resource owner or authorization server denied the request."),
    UNSUPPORTED_RESPONSE_TYPE("The authorization server does not support obtaining an authorization code "
        + "using this method."),
    SERVER_ERROR("The authorization server encountered an unexpected condition that prevented it from "
        + "fulfilling the request. "),
    TEMPORARILY_UNAVAILABLE("The authorization server is currently unable to handle the request due to a "
        + "temporary overloading or maintenance of the server."),
    UNSUPPORTED_TRANSFORM_ALGORITHM("The given PKCE transform algorithm is not supported"),
    MISSING_PARAMETERS("Parameters are missing"),
    INVALID_PARAMETER_VALUE("Parameter value is invalid"),
    PKCE_VERIFICATION_FAILURE("PKCE verification failed"),
    INTERNAL_SERVER_ERROR("Unexpected internal server-error occured"),
    REDIRECT_URI_DEFUNCT("Redirect-URI is invalid or missing"),
    RESOURCE_NOT_FOUND("The requested resource was not found."),
    STATE_MISSING_IN_NESTED_CHALLENGE("Parameter 'state' missing in Nested Challenge"),
    DEVICE_VALIDATION_NOT_ALLOWED("The device information given matched with not allowed configuration."),
    DEVICE_VALIDATION_PAIRING_EXPIRED("The pairing data has expired.");

    private final String description;
}
