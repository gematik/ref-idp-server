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

package de.gematik.idp.server.validation.parameterConstraints;

import de.gematik.idp.error.IdpErrorType;
import de.gematik.idp.server.exceptions.IdpServerException;
import de.gematik.idp.server.services.ScopeService;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import java.util.stream.Stream;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpStatus;

@RequiredArgsConstructor
public class ScopeValidator implements ConstraintValidator<CheckScope, String> {

  final ScopeService scopeService;

  @Override
  public boolean isValid(final String rawScopes, final ConstraintValidatorContext context) {
    if (StringUtils.isEmpty(rawScopes)) {
      throw new IdpServerException(
          1005, IdpErrorType.INVALID_REQUEST, "scope wurde nicht übermittelt", HttpStatus.FOUND);
    }

    final String[] scopes = rawScopes.split(" ");
    final long numberOfValidScopes =
        Stream.of(scopes).filter(scope -> scopeService.getScopes().contains(scope)).count();

    if (!rawScopes.contains("openid") || (scopes.length < 2)) {
      throw new IdpServerException(
          1022, IdpErrorType.INVALID_SCOPE, "scope ist ungültig", HttpStatus.FOUND);
    }

    if (numberOfValidScopes != scopes.length) {
      throw new IdpServerException(
          1030, IdpErrorType.INVALID_SCOPE, "Fachdienst ist unbekannt", HttpStatus.FOUND);
    }

    return true;
  }
}
