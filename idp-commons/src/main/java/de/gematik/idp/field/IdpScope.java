/*
 * Copyright (c) 2021 gematik GmbH
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

package de.gematik.idp.field;

import java.util.Optional;
import java.util.stream.Stream;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public enum IdpScope {
    OPENID("openid"), EREZEPT("e-rezept"), PAIRING("pairing");

    private final String jwtValue;

    public static Optional<IdpScope> fromJwtValue(final String jwtValue) {
        return Stream.of(IdpScope.values())
            .filter(candidate -> candidate.getJwtValue().equals(jwtValue))
            .findAny();
    }
}
