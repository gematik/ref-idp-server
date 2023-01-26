/*
 * Copyright (c) 2023 gematik GmbH
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

package de.gematik.idp.server.exceptions;

import de.gematik.idp.data.IdpErrorResponse;
import de.gematik.idp.error.IdpErrorType;
import lombok.Getter;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

@Getter
public class IdpServerException extends ResponseStatusException {

  public static final int ERROR_ID_ACCESS_DENIED = 4001;
  public static final int ERROR_ID_BLOCKLIST = 4002;
  private static final long serialVersionUID = -6555732805035877954L;

  private final IdpErrorType errorType;
  private String errorCode = "-1";

  public IdpServerException(final IdpErrorResponse errorResponse, final Exception e) {
    super(mapToStatus(errorResponse), errorResponse.getDetailMessage(), e);
    errorType = errorResponse.getError();
    errorCode = errorResponse.getCode();
  }

  public IdpServerException(
      final String message,
      final Exception e,
      final IdpErrorType errorType,
      final HttpStatus responseCode) {
    super(responseCode, message, e);
    this.errorType = errorType;
  }

  public IdpServerException(final IdpErrorType errorType, final HttpStatus responseCode) {
    super(responseCode, errorType.getSerializationValue());
    this.errorType = errorType;
  }

  public IdpServerException(
      final String s, final IdpErrorType errorType, final HttpStatus responseCode) {
    super(responseCode, s);
    this.errorType = errorType;
  }

  public IdpServerException(
      final int errorCode, final IdpErrorType errorType, final String message) {
    super(HttpStatus.BAD_REQUEST, message);
    this.errorType = errorType;
    this.errorCode = String.valueOf(errorCode);
  }

  public IdpServerException(
      final int errorCode,
      final IdpErrorType errorType,
      final String message,
      final HttpStatus returnStatus) {
    super(returnStatus, message);
    this.errorType = errorType;
    this.errorCode = String.valueOf(errorCode);
  }

  public IdpServerException(
      final int errorCode, final IdpErrorType errorType, final String message, final Exception e) {
    super(HttpStatus.BAD_REQUEST, message, e);
    this.errorType = errorType;
    this.errorCode = String.valueOf(errorCode);
  }

  public IdpServerException(
      final int errorCode,
      final IdpErrorType errorType,
      final String message,
      final HttpStatus returnStatus,
      final Exception e) {
    super(returnStatus, message, e);
    this.errorType = errorType;
    this.errorCode = String.valueOf(errorCode);
  }

  private static HttpStatus mapToStatus(final IdpErrorResponse errorResponse) {
    if (errorResponse.getHttpStatusCode() > 100 && errorResponse.getHttpStatusCode() < 600) {
      return HttpStatus.valueOf(errorResponse.getHttpStatusCode());
    } else {
      return HttpStatus.BAD_REQUEST;
    }
  }

  @Override
  public String getMessage() {
    return getReason();
  }
}
