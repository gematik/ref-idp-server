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

package de.gematik.idp.test.steps.model;

import java.util.Arrays;

public enum IdpEndpointType {
    Sektoral_IDP, Smartcard_IDP;

    public final static String CUCUMBER_REGEX = "(sektoral idp|smartcard idp)";

    private final String value;

    public static IdpEndpointType fromString(final String value) {
        return Arrays.stream(IdpEndpointType.values())
            .filter(e -> e.value.equals(value))
            .findFirst()
            .orElseThrow(() -> new AssertionError("Invalid IDP Endpoint Type '" + value + "'"));

    }

    IdpEndpointType() {
        value = name().toLowerCase().replace("_", " ");
    }

    @Override
    public String toString() {
        return value;
    }
}
