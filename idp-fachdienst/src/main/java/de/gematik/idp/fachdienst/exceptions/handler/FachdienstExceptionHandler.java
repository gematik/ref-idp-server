/*
 * Copyright (c) 2022 gematik GmbH
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

package de.gematik.idp.fachdienst.exceptions.handler;

import de.gematik.idp.data.fachdienst.FachdienstErrorResponse;
import de.gematik.idp.fachdienst.exceptions.FachdienstException;
import java.time.ZonedDateTime;
import javax.validation.ConstraintViolationException;
import javax.validation.ValidationException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
@RequiredArgsConstructor
@Slf4j
public class FachdienstExceptionHandler {

    @ExceptionHandler(FachdienstException.class)
    public ResponseEntity<FachdienstErrorResponse> handleFachdienstException(final FachdienstException exc) {
        final FachdienstErrorResponse body = getBody(exc);
        return new ResponseEntity<>(body, getHeader(), exc.getStatus());
    }

    @ExceptionHandler({ConstraintViolationException.class, ValidationException.class,
        MethodArgumentNotValidException.class})
    public ResponseEntity<FachdienstErrorResponse> handleValidationException(final Exception exc) {
        return handleFachdienstException(
            (FachdienstException) ExceptionUtils.getThrowableList(exc)
                .stream()
                .filter(FachdienstException.class::isInstance)
                .findAny()
                .orElseGet(() -> new FachdienstException(exc.getMessage(), exc, HttpStatus.BAD_REQUEST)));
    }

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<FachdienstErrorResponse> handleRuntimeException(final Exception exc) {
        return handleFachdienstException(
            new FachdienstException("Invalid Request", exc, HttpStatus.INTERNAL_SERVER_ERROR));
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<FachdienstErrorResponse> handleMissingServletRequestParameter(
        final MissingServletRequestParameterException ex) {
        return handleFachdienstException(
            new FachdienstException(ex.getMessage(), ex, HttpStatus.BAD_REQUEST));
    }

    private HttpHeaders getHeader() {
        final HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.add(HttpHeaders.CONTENT_TYPE, "application/json; charset=utf-8");
        responseHeaders.remove(HttpHeaders.CACHE_CONTROL);
        responseHeaders.remove(HttpHeaders.PRAGMA);
        return responseHeaders;
    }

    private FachdienstErrorResponse getBody(final FachdienstException exception) {
        return FachdienstErrorResponse.builder()
            .timestamp(ZonedDateTime.now().toEpochSecond())
            .errorMessage(exception.getReason())
            .build();
    }
}
