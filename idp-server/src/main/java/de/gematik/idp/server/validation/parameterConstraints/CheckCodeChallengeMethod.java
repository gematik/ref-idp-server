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

package de.gematik.idp.server.validation.parameterConstraints;

import static java.lang.annotation.ElementType.PARAMETER;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import de.gematik.idp.field.CodeChallengeMethod;
import de.gematik.idp.server.validation.parameterConstraints.CheckCodeChallengeMethod.CodeChallengeMethodVerifier;
import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;
import javax.validation.Constraint;
import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import javax.validation.Payload;

@Documented
@Constraint(validatedBy = CodeChallengeMethodVerifier.class)
@Target({PARAMETER})
@Retention(RUNTIME)
public @interface CheckCodeChallengeMethod {

    String message() default "";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    class CodeChallengeMethodVerifier implements ConstraintValidator<CheckCodeChallengeMethod, CodeChallengeMethod> {

        @Override
        public boolean isValid(final CodeChallengeMethod codeChallengeMethod,
            final ConstraintValidatorContext context) {
            return codeChallengeMethod == CodeChallengeMethod.S256;
        }
    }
}
