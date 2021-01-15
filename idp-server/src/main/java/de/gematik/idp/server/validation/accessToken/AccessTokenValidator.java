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

package de.gematik.idp.server.validation.accessToken;

import de.gematik.idp.field.ClaimName;
import de.gematik.idp.server.RequestAccessToken;
import java.util.Optional;
import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class AccessTokenValidator implements ConstraintValidator<ValidateKvnrWithAccessToken, String> {

    private ClaimName targetClaim;
    private final RequestAccessToken requestAccessToken;

    @Override
    public void initialize(final ValidateKvnrWithAccessToken constraintAnnotation) {
        targetClaim = constraintAnnotation.shouldMatch();
    }

    @Override
    public boolean isValid(final String value, final ConstraintValidatorContext context) {
        return Optional.ofNullable(requestAccessToken.getAccessToken())
            .map(accessToken -> accessToken.getBodyClaim(targetClaim))
            .filter(Optional::isPresent)
            .map(Optional::get)
            .filter(String.class::isInstance)
            .map(String.class::cast)
            .map(claimValue -> claimValue.equals(value))
            .orElse(false);
    }
}
