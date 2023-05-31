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

package de.gematik.idp.data;

import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.RequiredArgsConstructor;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
@RequiredArgsConstructor
public enum Oauth2ErrorCode {
  INVALID_REQUEST("invalid_request"),
  INVALID_CLIENT("invalid_client"),
  INVALID_GRANT("invalid_grant"),
  UNAUTHORIZED_CLIENT("unauthorized_client"),
  INVALID_SCOPE("invalid_scope"),
  UNSUPPORTED_GRANT_TYPE("unsupported_grant_type");

  private final String serializationValue;

  @JsonValue
  public String getSerializationValue() {
    return serializationValue;
  }
}
