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

package de.gematik.idp.server.exceptions.handler;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.error.IdpErrorType;
import de.gematik.idp.exceptions.IdpJoseException;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.server.ServerUrlService;
import de.gematik.idp.server.controllers.IdpKey;
import de.gematik.idp.server.exceptions.IdpServerException;
import de.gematik.idp.server.exceptions.data.IdpErrorTypeResponse;
import de.gematik.idp.token.IdpJwe;
import de.gematik.idp.token.JsonWebToken;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.ZonedDateTime;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import javax.servlet.http.HttpServletResponse;
import javax.validation.ConstraintViolationException;
import javax.validation.ValidationException;
import javax.ws.rs.core.UriBuilder;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.util.UriUtils;

@ControllerAdvice
@RequiredArgsConstructor
public class IdpServerExceptionHandler {

    private static final Logger LOG = LoggerFactory.getLogger(IdpServerExceptionHandler.class);
    private final ServerUrlService serverUrlService;
    private final IdpKey authKey;

    @ExceptionHandler(IdpServerException.class)
    public ResponseEntity<IdpErrorTypeResponse> handleIdpServerException(final IdpServerException exc,
        final WebRequest request, final HttpServletResponse response) {
        if (isAuthorizationRequest(request)) {
            return buildForwardingError(exc, request, response);
        }

        final IdpErrorTypeResponse body = getBody(exc.getErrorType());
        if (!StringUtils.isEmpty(exc.getMessage())) {
            body.setDetailMessage(exc.getMessage());
        }
        logEntry(body, exc);
        return new ResponseEntity<>(body, getHeader(), exc.getStatus());
    }

    private ResponseEntity<IdpErrorTypeResponse> buildForwardingError(final IdpServerException exc,
        final WebRequest request, final HttpServletResponse response) {
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        response.setHeader(HttpHeaders.PRAGMA, "no-cache");
        final UriBuilder uriBuilder = UriBuilder.fromPath(serverUrlService.determineServerUrl())
            .queryParam("error", "invalid_request");
        addStateIfAvailable(uriBuilder, request);
        addDescriptionIfAvailable(uriBuilder, exc);
        final URI location = uriBuilder.build();
        response.setHeader(HttpHeaders.LOCATION, location.toString());

        return new ResponseEntity<>(HttpStatus.FOUND);
    }

    private void addDescriptionIfAvailable(final UriBuilder uriBuilder, final IdpServerException exc) {
        try {
            Optional.ofNullable(exc)
                .filter(Objects::nonNull)
                .map(IdpServerException::getMessage)
                .filter(org.apache.commons.lang3.StringUtils::isNotEmpty)
                .map(value -> UriUtils.encodeQueryParam(value, StandardCharsets.UTF_8))
                .ifPresent(descr -> uriBuilder.queryParam("error_description", descr));
        } catch (final RuntimeException e) {
            //swallow
        }
    }

    private void addStateIfAvailable(final UriBuilder uriBuilder, final WebRequest request) {
        try {
            Optional.ofNullable(request.getParameter("signed_challenge"))
                .filter(Objects::nonNull)
                .map(IdpJwe::new)
                .map(jwe -> jwe.decryptNestedJwt(authKey.getIdentity().getPrivateKey()))
                .flatMap(jwt -> jwt.getStringBodyClaim(ClaimName.NESTED_JWT))
                .map(JsonWebToken::new)
                .flatMap(jwt -> jwt.getStringBodyClaim(ClaimName.STATE))
                .map(value -> UriUtils.encodeQueryParam(value, StandardCharsets.UTF_8))
                .ifPresent(state -> uriBuilder.queryParam("state", state));
        } catch (final RuntimeException e) {
            //swallow
        }
    }

    private boolean isAuthorizationRequest(final WebRequest webRequest) {
        if (!(webRequest instanceof ServletWebRequest)) {
            return false;
        }
        final ServletWebRequest servletWebRequest = (ServletWebRequest) webRequest;
        final Path normalizedRequestPath = Path.of(servletWebRequest.getRequest().getRequestURI()).normalize();
        final boolean isForwardingEnpointUrl =
            normalizedRequestPath.equals(Path.of(IdpConstants.BASIC_AUTHORIZATION_ENDPOINT)) ||
                normalizedRequestPath.equals(Path.of(IdpConstants.SSO_ENDPOINT));
        return isForwardingEnpointUrl && servletWebRequest.getHttpMethod() == HttpMethod.POST;
    }

    @ExceptionHandler(IdpJoseException.class)
    public ResponseEntity<IdpErrorTypeResponse> handleIdpJoseException(final IdpJoseException exc,
        final WebRequest request, final HttpServletResponse response) {
        return handleIdpServerException(
            new IdpServerException(exc.getMessageForUntrustedClients(), exc, IdpErrorType.INVALID_REQUEST,
                HttpStatus.BAD_REQUEST),
            request, response);
    }

    @ExceptionHandler({ConstraintViolationException.class, ValidationException.class})
    public ResponseEntity<IdpErrorTypeResponse> handleValidationException(final ValidationException exc,
        final WebRequest request, final HttpServletResponse response) {
        return handleIdpServerException(
            new IdpServerException(exc.getMessage(), exc, IdpErrorType.INVALID_REQUEST,
                HttpStatus.BAD_REQUEST), request, response);
    }

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<IdpErrorTypeResponse> handleRuntimeException(final RuntimeException exc,
        final WebRequest request, final HttpServletResponse response) {
        return handleIdpServerException(
            new IdpServerException("Invalid Request", exc, IdpErrorType.INTERNAL_SERVER_ERROR,
                HttpStatus.INTERNAL_SERVER_ERROR), request, response);
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<IdpErrorTypeResponse> handleMissingServletRequestParameter(
        final MissingServletRequestParameterException ex, final WebRequest request,
        final HttpServletResponse response) {
        return handleIdpServerException(
            new IdpServerException(ex.getMessage(), ex, IdpErrorType.MISSING_PARAMETERS,
                HttpStatus.BAD_REQUEST), request, response);
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
