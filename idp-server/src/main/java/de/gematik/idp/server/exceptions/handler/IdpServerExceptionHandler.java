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

package de.gematik.idp.server.exceptions.handler;

import de.gematik.idp.data.IdpErrorResponse;
import de.gematik.idp.error.IdpErrorType;
import de.gematik.idp.exceptions.IdpJoseException;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.server.ServerUrlService;
import de.gematik.idp.server.configuration.IdpConfiguration;
import de.gematik.idp.server.controllers.IdpKey;
import de.gematik.idp.server.exceptions.IdpServerException;
import de.gematik.idp.token.IdpJwe;
import de.gematik.idp.token.JsonWebToken;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import jakarta.validation.ValidationException;
import jakarta.ws.rs.core.UriBuilder;
import java.net.URI;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.time.ZonedDateTime;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.commons.lang3.math.NumberUtils;
import org.springframework.dao.NonTransientDataAccessException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.HttpMediaTypeNotAcceptableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingPathVariableException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.util.UriUtils;

@ControllerAdvice
@RequiredArgsConstructor
@Slf4j
public class IdpServerExceptionHandler {

  private static final int MAX_HEADER_SIZE = 200;
  private final ServerUrlService serverUrlService;
  private final IdpKey idpEnc;
  private final IdpConfiguration idpConfiguration;

  @ExceptionHandler(IdpServerException.class)
  public ResponseEntity<IdpErrorResponse> handleIdpServerException(
      final IdpServerException exc, final WebRequest request, final HttpServletResponse response) {
    final IdpErrorResponse body = getBody(exc);
    if (!StringUtils.isEmpty(exc.getMessage())) {
      body.setDetailMessage(exc.getMessage());
    }
    logEntry(body, exc);

    if (exc.getStatusCode().is3xxRedirection()) {
      return buildForwardingError(body, request, response, exc);
    }
    return new ResponseEntity<>(body, getHeader(), exc.getStatusCode());
  }

  private ResponseEntity<IdpErrorResponse> buildForwardingError(
      final IdpErrorResponse errorResponse,
      final WebRequest request,
      final HttpServletResponse response,
      final IdpServerException exc) {
    response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
    response.setHeader(HttpHeaders.PRAGMA, "no-cache");
    final String redirectUri = request.getParameter("redirect_uri");
    if (redirectUri == null) {
      final IdpErrorResponse body = getBody(exc);
      if (!StringUtils.isEmpty(exc.getMessage())) {
        body.setDetailMessage(exc.getMessage());
      }
      return new ResponseEntity<>(body, getHeader(), HttpStatus.BAD_REQUEST);
    } else {
      final UriBuilder uriBuilder =
          UriBuilder.fromPath(redirectUri)
              .queryParam(
                  "error",
                  UriUtils.encodeQueryParam(
                      errorResponse.getError().getSerializationValue(), Charset.defaultCharset()))
              .queryParam(
                  "gematik_code",
                  UriUtils.encodeQueryParam(errorResponse.getCode(), Charset.defaultCharset()))
              .queryParam("gematik_timestamp", errorResponse.getTimestamp())
              .queryParam(
                  "gematik_uuid",
                  UriUtils.encodeQueryParam(errorResponse.getErrorUuid(), Charset.defaultCharset()))
              .queryParam(
                  "gematik_error_text",
                  UriUtils.encodeQueryParam(
                      errorResponse.getDetailMessage(), Charset.defaultCharset()));
      addStateIfAvailable(uriBuilder, request);
      addDescriptionIfAvailable(uriBuilder, exc);
      final URI location = uriBuilder.build();
      response.setHeader(HttpHeaders.LOCATION, location.toString());

      return new ResponseEntity<>(HttpStatus.FOUND);
    }
  }

  private void addDescriptionIfAvailable(
      final UriBuilder uriBuilder, final IdpServerException exc) {
    try {
      Optional.ofNullable(exc)
          .filter(Objects::nonNull)
          .map(IdpServerException::getMessage)
          .filter(org.apache.commons.lang3.StringUtils::isNotEmpty)
          .map(str -> str.substring(0, Math.min(str.length(), MAX_HEADER_SIZE)))
          .map(value -> UriUtils.encodeQueryParam(value, StandardCharsets.UTF_8))
          .ifPresent(descr -> uriBuilder.queryParam("error_description", descr));
    } catch (final RuntimeException e) {
      // swallow
    }
  }

  private void addStateIfAvailable(final UriBuilder uriBuilder, final WebRequest request) {
    try {
      Optional.ofNullable(request.getParameter("signed_challenge"))
          .filter(Objects::nonNull)
          .map(IdpJwe::new)
          .map(jwe -> jwe.decryptNestedJwt(idpEnc.getIdentity().getPrivateKey()))
          .flatMap(jwt -> jwt.getStringBodyClaim(ClaimName.NESTED_JWT))
          .map(JsonWebToken::new)
          .flatMap(jwt -> jwt.getStringBodyClaim(ClaimName.STATE))
          .map(str -> str.substring(0, Math.min(str.length(), MAX_HEADER_SIZE)))
          .map(value -> UriUtils.encodeQueryParam(value, StandardCharsets.UTF_8))
          .ifPresent(state -> uriBuilder.queryParam("state", state));
    } catch (final RuntimeException e) {
      // swallow
    }
  }

  @ExceptionHandler({
    ConstraintViolationException.class,
    ValidationException.class,
    MethodArgumentNotValidException.class,
    IdpJoseException.class
  })
  public ResponseEntity<IdpErrorResponse> handleValidationException(
      final Exception exc, final WebRequest request, final HttpServletResponse response) {
    return handleIdpServerException(
        (IdpServerException)
            ExceptionUtils.getThrowableList(exc).stream()
                .filter(IdpServerException.class::isInstance)
                .findAny()
                .or(() -> tryToExtractErrorCodeFromConstraintViolationAndConvertToIdpException(exc))
                .or(() -> tryToExtractErrorCodeFromExceptionMessageAndConvertToIdpException(exc))
                .or(() -> tryToMapJoseExceptionToIdpException(exc))
                .orElseGet(
                    () ->
                        new IdpServerException(
                            "Ein Fehler ist aufgetreten",
                            exc,
                            IdpErrorType.SERVER_ERROR,
                            HttpStatus.BAD_REQUEST)),
        request,
        response);
  }

  private Optional<IdpServerException>
      tryToExtractErrorCodeFromConstraintViolationAndConvertToIdpException(final Exception exc) {
    return Optional.of(exc)
        .filter(ConstraintViolationException.class::isInstance)
        .map(ConstraintViolationException.class::cast)
        .map(ConstraintViolationException::getConstraintViolations)
        .stream()
        .flatMap(Set::stream)
        .map(ConstraintViolation::getMessage)
        .filter(NumberUtils::isParsable)
        .map(Integer::parseInt)
        .sorted()
        .filter(idpConfiguration.getErrors().getErrorCodeMap()::containsKey)
        .map(idpConfiguration.getErrors().getErrorCodeMap()::get)
        .map(errorCode -> new IdpServerException(errorCode, exc))
        .findFirst();
  }

  private Optional<IdpServerException>
      tryToExtractErrorCodeFromExceptionMessageAndConvertToIdpException(final Exception exc) {
    return Optional.of(exc)
        .map(Exception::getMessage)
        .filter(NumberUtils::isParsable)
        .map(Integer::parseInt)
        .filter(idpConfiguration.getErrors().getErrorCodeMap()::containsKey)
        .map(idpConfiguration.getErrors().getErrorCodeMap()::get)
        .map(errorCode -> new IdpServerException(errorCode, exc));
  }

  private Optional<IdpServerException> tryToMapJoseExceptionToIdpException(final Exception exc) {
    return Optional.of(exc)
        .map(Exception::getClass)
        .map(Class::getSimpleName)
        .filter(idpConfiguration.getErrors().getJoseExceptionMap()::containsKey)
        .map(idpConfiguration.getErrors().getJoseExceptionMap()::get)
        .map(errorCode -> new IdpServerException(errorCode, exc));
  }

  @ExceptionHandler(Exception.class)
  public ResponseEntity<IdpErrorResponse> handleRuntimeException(
      final Exception exc, final WebRequest request, final HttpServletResponse response) {
    return handleIdpServerException(
        new IdpServerException(
            "Invalid Request", exc, IdpErrorType.SERVER_ERROR, HttpStatus.INTERNAL_SERVER_ERROR),
        request,
        response);
  }

  @ExceptionHandler({
    HttpMediaTypeNotAcceptableException.class,
    HttpMediaTypeNotSupportedException.class
  })
  public ResponseEntity<IdpErrorResponse> handleHttpMediaTypeNotAcceptableException(
      final Exception exc) {
    log.debug("", exc);
    return new ResponseEntity<>(HttpStatus.NOT_ACCEPTABLE);
  }

  @ExceptionHandler(NonTransientDataAccessException.class)
  public ResponseEntity<IdpErrorResponse> handleDbIntegrityError(
      final NonTransientDataAccessException exc,
      final WebRequest request,
      final HttpServletResponse response) {
    return handleIdpServerException(
        new IdpServerException(
            "Invalid Request", exc, IdpErrorType.INVALID_REQUEST, HttpStatus.CONFLICT),
        request,
        response);
  }

  @ExceptionHandler(MissingServletRequestParameterException.class)
  public ResponseEntity<IdpErrorResponse> handleMissingServletRequestParameter(
      final MissingServletRequestParameterException ex,
      final WebRequest request,
      final HttpServletResponse response) {
    return handleIdpServerException(
        Optional.ofNullable(
                idpConfiguration.getErrors().getGenericErrorMap().get(ex.getParameterName()))
            .map(resp -> new IdpServerException(resp, ex))
            .orElseGet(
                () ->
                    new IdpServerException(
                        ex.getMessage(), ex, IdpErrorType.INVALID_REQUEST, HttpStatus.BAD_REQUEST)),
        request,
        response);
  }

  @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
  public ResponseEntity<IdpErrorResponse> handleMethodNotSupported(
      final HttpRequestMethodNotSupportedException ex) {
    log.info("Returning error to client: {}", ex.getMessage());
    return new ResponseEntity<>(getHeader(), HttpStatus.METHOD_NOT_ALLOWED);
  }

  @ExceptionHandler(MissingPathVariableException.class)
  public ResponseEntity<IdpErrorResponse> handleMissingPathVariableException(
      final MissingPathVariableException ex,
      final WebRequest request,
      final HttpServletResponse response) {
    return handleIdpServerException(
        Optional.ofNullable(idpConfiguration.getErrors().getErrorCodeMap().get(1500))
            .map(resp -> new IdpServerException(resp, ex))
            .orElseGet(
                () ->
                    new IdpServerException(
                        ex.getMessage(), ex, IdpErrorType.INVALID_REQUEST, HttpStatus.BAD_REQUEST)),
        request,
        response);
  }

  private void logEntry(final IdpErrorResponse body, final Exception exc) {
    log.info("Returning error to client: {}, error_id: {}", exc.getMessage(), body.getErrorUuid());
    log.debug(body.toString(), exc);
  }

  private HttpHeaders getHeader() {
    final HttpHeaders responseHeaders = new HttpHeaders();
    responseHeaders.add(HttpHeaders.CONTENT_TYPE, "application/json; charset=utf-8");
    responseHeaders.remove(HttpHeaders.CACHE_CONTROL);
    responseHeaders.remove(HttpHeaders.PRAGMA);
    return responseHeaders;
  }

  private IdpErrorResponse getBody(final IdpServerException exception) {
    return IdpErrorResponse.builder()
        .code(exception.getErrorCode())
        .error(exception.getErrorType())
        .errorUuid(UUID.randomUUID().toString())
        .timestamp(ZonedDateTime.now().toEpochSecond())
        .detailMessage(exception.getMessage())
        .build();
  }
}
