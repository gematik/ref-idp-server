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

import de.gematik.idp.server.services.ClientRegistrationService;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class ClientIdValidator implements ConstraintValidator<CheckClientId, String> {

  final ClientRegistrationService clientRegistrationService;

  @Override
  public boolean isValid(
      final String clientId, final ConstraintValidatorContext constraintValidatorContext) {
    return clientRegistrationService.getClientConfiguration(clientId).isPresent();
  }
}
