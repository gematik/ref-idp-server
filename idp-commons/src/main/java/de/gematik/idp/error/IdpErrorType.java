/*
 *  Copyright 2023 gematik GmbH
 *  
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *  
 *     http://www.apache.org/licenses/LICENSE-2.0
 *  
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.idp.error;

import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import java.util.Optional;
import java.util.stream.Stream;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public enum IdpErrorType {
  INTERACTION_REQUIRED("interaction_required"),
  LOGIN_REQUIRED("login_required"),
  ACCOUNT_SELECTION_REQUIRED("account_selection_required"),
  CONSENT_REQUIRED("consent_required"),
  INVALID_REQUEST_URI("invalid_request_uri"),
  INVALID_REQUEST_OBJECT("invalid_request_object"),
  REQUEST_NOT_SUPPORTED("request_not_supported"),
  REQUEST_URI_NOT_SUPPORTED("request_uri_not_supported"),
  REGISTRATION_NOT_SUPPORTED("registration_not_supported"),
  INVALID_REQUEST("invalid_request"),
  UNAUTHORIZED_CLIENT("unauthorized_client"),
  ACCESS_DENIED("access_denied"),
  UNSUPPORTED_RESPONSE_TYPE("unsupported_response_type"),
  INVALID_SCOPE("invalid_scope"),
  SERVER_ERROR("server_error"),
  TEMPORARILY_UNAVAILABLE("temporarily_unavailable"),
  INVALID_CLIENT("invalid_client"),
  INVALID_GRANT("invalid_grant"),
  UNSUPPORTED_GRANT_TYPE("unsupported_grant_type");

  private final String serializationValue;

  public static Optional<IdpErrorType> fromSerializationValue(final String serializationValue) {
    return Stream.of(IdpErrorType.values())
        .filter(candidate -> candidate.getSerializationValue().equals(serializationValue))
        .findAny();
  }

  @JsonValue
  public String getSerializationValue() {
    return serializationValue;
  }
}
