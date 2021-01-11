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

package de.gematik.idp.test.steps.model;

public enum DateCompareMode {
    BEFORE("before"), AFTER("after"), NOT_BEFORE(
        "not before"), NOT_AFTER("not after");

    private final String value;
    private final String compareMathSign;

    DateCompareMode(final String value) {
        this.value = value.toUpperCase().replace(" ", "_");
        switch (value) {
            case "not before":
                compareMathSign = ">=";
                break;
            case "after":
                compareMathSign = ">";
                break;
            case "before":
                compareMathSign = "<";
                break;
            case "not after":
                compareMathSign = "<=";
                break;
            default:
                compareMathSign = "??";
        }

    }

    @Override
    public String toString() {
        return value;
    }

    public String mathSign() {
        return compareMathSign;
    }
}
