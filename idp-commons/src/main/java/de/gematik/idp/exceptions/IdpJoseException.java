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

package de.gematik.idp.exceptions;

public class IdpJoseException extends RuntimeException {

    private static final long serialVersionUID = -838371828368858466L;
    private final boolean containsSensitiveInformation;

    public IdpJoseException(final Exception e) {
        super(e);
        containsSensitiveInformation = true;
    }

    public IdpJoseException(final String message, final Exception e) {
        super(message, e);
        containsSensitiveInformation = true;
    }

    public IdpJoseException(final String s) {
        super(s);
        containsSensitiveInformation = true;
    }

    public IdpJoseException(final String message, final boolean containsSensitiveInformation, final Exception e) {
        super(message, e);
        this.containsSensitiveInformation = containsSensitiveInformation;
    }

    public String getMessageForUntrustedClients() {
        if (containsSensitiveInformation) {
            return "Error during JOSE-operations";
        } else {
            return getMessage();
        }
    }
}
