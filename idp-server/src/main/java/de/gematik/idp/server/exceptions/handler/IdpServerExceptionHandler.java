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

package de.gematik.idp.server.exceptions.handler;

import de.gematik.idp.error.IdpErrorType;
import de.gematik.idp.exceptions.IdpJoseException;
import de.gematik.idp.server.exceptions.IdpServerException;
import de.gematik.idp.server.exceptions.data.IdpErrorTypeResponse;
import java.time.ZonedDateTime;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class IdpServerExceptionHandler {

    private static final Logger LOG = LoggerFactory.getLogger(IdpServerExceptionHandler.class);

    @ExceptionHandler(IdpServerException.class)
    public ResponseEntity<IdpErrorTypeResponse> handleIdpServerException(final IdpServerException exc) {
        final IdpErrorTypeResponse body = getBody(exc.getErrorType());
        if (!StringUtils.isEmpty(exc.getMessage())) {
            body.setDetailMessage(exc.getMessage());
        }
        logEntry(body, exc);
        return new ResponseEntity<>(body, getHeader(), exc.getResponseCode());
    }

    @ExceptionHandler(IdpJoseException.class)
    public ResponseEntity<IdpErrorTypeResponse> handleIdpJoseException(final IdpJoseException exc) {
        return handleIdpServerException(
                new IdpServerException(exc.getMessage(), exc, IdpErrorType.INVALID_REQUEST, HttpStatus.BAD_REQUEST));
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<IdpErrorTypeResponse> handleMissingServletRequestParameter(
            final MissingServletRequestParameterException ex) {
        final IdpErrorTypeResponse body = getBody(IdpErrorType.MISSING_PARAMETERS);
        body.setDetailMessage(ex.getMessage());
        logEntry(body, ex);
        return new ResponseEntity<>(body, getHeader(), HttpStatus.BAD_REQUEST);
    }

    private void logEntry(final IdpErrorTypeResponse body, final Exception exc) {
        LOG.info("Returning error to client: {}, error_id: {}", exc.getMessage(), body.getErrorUuid());
        LOG.debug(body.toString(), exc);
    }

    private HttpHeaders getHeader() {
        final HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.add(HttpHeaders.CONTENT_TYPE, "application/json");
        responseHeaders.add(HttpHeaders.CACHE_CONTROL, "no-store");
        responseHeaders.add(HttpHeaders.PRAGMA, "no-cache");
        return responseHeaders;
    }

    private IdpErrorTypeResponse getBody(final IdpErrorType error) {
        return IdpErrorTypeResponse.builder()
                .errorCode(error.name().toLowerCase())
                .errorUuid(UUID.randomUUID().toString())
                .timestamp(ZonedDateTime.now().toString())
                .detailMessage(error.getDescription())
                .build();
    }
}
