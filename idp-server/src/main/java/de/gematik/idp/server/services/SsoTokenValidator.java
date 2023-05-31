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

package de.gematik.idp.server.services;

import static de.gematik.idp.field.ClaimName.EXPIRES_AT;

import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.error.IdpErrorType;
import de.gematik.idp.server.controllers.IdpKey;
import de.gematik.idp.server.exceptions.IdpServerException;
import de.gematik.idp.server.exceptions.oauth2spec.IdpServerInvalidRequestException;
import de.gematik.idp.token.IdpJwe;
import de.gematik.idp.token.JsonWebToken;
import java.security.Key;
import java.time.ZonedDateTime;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class SsoTokenValidator {

  public static final Logger LOGGER = LoggerFactory.getLogger(SsoTokenValidator.class);
  private final IdpKey idpSig;
  private final Key tokenEncryptionKey;

  public JsonWebToken decryptAndValidateSsoToken(final IdpJwe encryptedSsoToken) {
    final JsonWebToken ssoToken = decryptSsoToken(encryptedSsoToken);
    validateExpiration(
        encryptedSsoToken
            .getHeaderDateTimeClaim(EXPIRES_AT)
            .orElseThrow(() -> new IdpServerInvalidRequestException("Invalid SSO-Token given")));
    final IdpJwtProcessor idpJwtProcessor = new IdpJwtProcessor(idpSig.getIdentity());
    idpJwtProcessor.verifyAndThrowExceptionIfFail(ssoToken);
    LOGGER.debug("SsoToken validation successful");
    return ssoToken;
  }

  private JsonWebToken decryptSsoToken(final IdpJwe ssoToken) {
    try {
      return ssoToken.decryptNestedJwt(tokenEncryptionKey);
    } catch (final RuntimeException e) {
      throw new IdpServerException(
          2040, IdpErrorType.ACCESS_DENIED, "Error during SSO-Token decryption");
    }
  }

  private void validateExpiration(final ZonedDateTime exp) {
    if (exp.isBefore(ZonedDateTime.now())) {
      throw new IdpServerException(
          2040,
          IdpErrorType.ACCESS_DENIED,
          "SSO_TOKEN nicht valide, bitte um neuerliche Authentisierung");
    }
  }
}
