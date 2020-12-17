/*
 * Copyright (c) 2020 gematik GmbH
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

    INVALID_REQUEST("The request is missing a required parameter, includes an" +
        "unsupported parameter value (other than grant type)," +
        "repeats a parameter, includes multiple credentials," +
        "utilizes more than one mechanism for authenticating the" +
        "client, or is otherwise malformed."),
    INVALID_CLIENT("Client authentication failed (e.g., unknown client, no" +
        "client authentication included, or unsupported" +
        "authentication method).  The authorization server MAY" +
        "return an HTTP 401 (Unauthorized) status code to indicate" +
        "which HTTP authentication schemes are supported.  If the" +
        "client attempted to authenticate via the \"Authorization\"" +
        "request header field, the authorization server MUST" +
        "respond with an HTTP 401 (Unauthorized) status code and" +
        "include the \"WWW-Authenticate\" response header field" +
        "matching the authentication scheme used by the client."),
    INVALID_GRANT("The provided authorization grant (e.g., authorization" +
        "code, resource owner credentials) or refresh token is" +
        "invalid, expired, revoked, does not match the redirection" +
        "URI used in the authorization request, or was issued to" +
        "another client."),
    UNAUTHORIZED_CLIENT("The authenticated client is not authorized to use this" +
        "authorization grant type."),
    UNSUPPORTED_GRANT_TYPE("The authorization grant type is not supported by the" +
        "authorization server."),
    INVALID_SCOPE("The requested scope is invalid, unknown, malformed, or" +
        "exceeds the scope granted by the resource owner."),
    ACCESS_DENIED("The resource owner or authorization server denied the" +
        "request."),
    UNSUPPORTED_RESPONSE_TYPE("The authorization server does not support obtaining an" +
        "authorization code using this method."),
    SERVER_ERROR("The authorization server encountered an unexpected" +
        "condition that prevented it from fulfilling the request." +
        "(This error code is needed because a 500 Internal Server" +
        "Error HTTP status code cannot be returned to the client" +
        "via an HTTP redirect.)"),
    TEMPORARILY_UNAVAILABLE("The authorization server is currently unable to handle" +
        "the request due to a temporary overloading or maintenance" +
        "of the server.  (This error code is needed because a 503" +
        "Service Unavailable HTTP status code cannot be returned" +
        "to the client via an HTTP redirect.)"),
    UNSUPPORTED_TRANSFORM_ALGORITHM("The given PKCE transform algorithm is not supported"),
    MISSING_PARAMETERS("Parameters are missing"),
    PKCE_VERIFICATION_FAILURE("PKCE verification failed"),
    INTERNAL_SERVER_ERROR("Unexpected internal server-error occured");

    private final String description;
}
