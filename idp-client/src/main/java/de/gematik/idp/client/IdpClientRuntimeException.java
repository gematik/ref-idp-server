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

package de.gematik.idp.client;

import de.gematik.idp.error.IdpErrorType;
import java.util.Optional;
import lombok.EqualsAndHashCode;
import lombok.Getter;

@Getter
@EqualsAndHashCode
public class IdpClientRuntimeException extends RuntimeException {

    private static final long serialVersionUID = -3280232274428362763L;
    private final Optional<String> gematikErrorCode;
    private final Optional<IdpErrorType> idpErrorType;

    public IdpClientRuntimeException(final Exception e) {
        super(e);
        gematikErrorCode = Optional.empty();
        idpErrorType = Optional.empty();
    }

    public IdpClientRuntimeException(final String s) {
        super(s);
        gematikErrorCode = Optional.empty();
        idpErrorType = Optional.empty();
    }

    public IdpClientRuntimeException(final String message, final Exception e) {
        super(message, e);
        gematikErrorCode = Optional.empty();
        idpErrorType = Optional.empty();
    }

    public IdpClientRuntimeException(final String s, final Optional<String> gematikCode, final Optional<IdpErrorType> errorDescription) {
        super(s);
        gematikErrorCode = gematikCode;
        idpErrorType = errorDescription;
    }
}
