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

package de.gematik.idp.fedmaster.services;

import static de.gematik.idp.EnvHelper.getSystemProperty;
import de.gematik.idp.data.FederationPubKey;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class FedRegistration {

    private static boolean registered = false;

    public static void registerOnce(final List<FederationPubKey> otherKeyList) {
        if (!registered) {
            for (final FederationPubKey fedPupKey : otherKeyList) {
                final Optional<String> fdUrl = getOtherServerUrl(fedPupKey.getIssuer());
                if (fdUrl.isPresent()) {
                    fedPupKey.setUrl(fdUrl.get());
                    log.info("Registered other: " + fdUrl);
                }
            }
            registered = true;
        }
    }

    private static Optional<String> getOtherServerUrl(final String serverEnvName) {
        try {
            final StringBuilder str = new StringBuilder();
            str.append(getSystemProperty(serverEnvName).orElse("http://127.0.0.1"));
            str.append(":");
            str.append(getSystemProperty(serverEnvName + "_PORT").orElseThrow());
            return Optional.of(str.toString());
        } catch (final NoSuchElementException e) {
            return Optional.empty();
        }
    }

}
