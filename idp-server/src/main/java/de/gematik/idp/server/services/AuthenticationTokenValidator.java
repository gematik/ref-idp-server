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

package de.gematik.idp.server.services;

import static de.gematik.idp.field.ClaimName.EXPIRES_AT;

import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.server.controllers.IdpKey;
import de.gematik.idp.server.exceptions.IdpServerException;
import de.gematik.idp.server.exceptions.oauth2spec.IdpServerInvalidRequestException;
import de.gematik.idp.token.JsonWebToken;
import java.time.ZonedDateTime;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationTokenValidator {

    public static final Logger LOGGER = LoggerFactory.getLogger(AuthenticationTokenValidator.class);
    private final IdpKey authKey;

    public void validateAuthenticationToken(final JsonWebToken authenticationToken) {
        validateExpiration(authenticationToken.getDateTimeClaim(EXPIRES_AT, () -> authenticationToken.getHeaderClaims())
            .orElseThrow(() -> new IdpServerInvalidRequestException("Invalid Authentication-Token given")));
        final IdpJwtProcessor idpJwtProcessor = new IdpJwtProcessor(authKey.getIdentity());
        idpJwtProcessor.verifyAndThrowExceptionIfFail(authenticationToken);
        LOGGER.debug("AuthenticationToken validation successful");
    }

    private void validateExpiration(final ZonedDateTime exp) {
        if (exp.isBefore(ZonedDateTime.now())) {
            throw new IdpServerException("AuthenticationToken expired");
        }
    }
}
