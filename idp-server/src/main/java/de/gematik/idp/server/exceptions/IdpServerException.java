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

package de.gematik.idp.server.exceptions;

import de.gematik.idp.error.IdpErrorType;
import lombok.Getter;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

@Getter
public class IdpServerException extends ResponseStatusException {

    private static final long serialVersionUID = -6338520681700326027L;

    private final IdpErrorType errorType;

    public IdpServerException(final String message, final Exception e) {
        super(HttpStatus.INTERNAL_SERVER_ERROR, message, e);
        errorType = IdpErrorType.SERVER_ERROR;
    }

    public IdpServerException(final String s) {
        super(HttpStatus.INTERNAL_SERVER_ERROR, s);
        errorType = IdpErrorType.SERVER_ERROR;
    }

    public IdpServerException(final String message, final Exception e, final IdpErrorType errorType,
        final HttpStatus responseCode) {
        super(responseCode, message, e);
        this.errorType = errorType;
    }

    public IdpServerException(final IdpErrorType errorType, final HttpStatus responseCode) {
        super(responseCode, errorType.getDescription());
        this.errorType = errorType;
    }

    public IdpServerException(final String s, final IdpErrorType errorType, final HttpStatus responseCode) {
        super(responseCode, s);
        this.errorType = errorType;
    }

    @Override
    public String getMessage() {
        return getReason();
    }
}
