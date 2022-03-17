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

package de.gematik.idp.fachdienst.services;

import de.gematik.idp.crypto.Nonce;
import de.gematik.idp.data.FederationPrivKey;
import de.gematik.idp.data.fachdienst.ClientAssertion;
import java.time.ZonedDateTime;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;

@RequiredArgsConstructor
public class ClientAssertionBuilder {

    private static final int JTI_MAX_LENGTH = 32;
    final int JWT_TTL_SECS = 90;

    @Autowired
    FederationPrivKey entityStatementSigKey;

    public ClientAssertion buildClientAssertion(final String serverUrl, final String sekIdpAuthEndpoint) {
        final ZonedDateTime currentTime = ZonedDateTime.now();
        return ClientAssertion.builder()
            .iss(serverUrl)
            .sub(serverUrl)
            .aud(sekIdpAuthEndpoint)
            .jti(new Nonce().getNonceAsHex(JTI_MAX_LENGTH))
            .exp(currentTime.plusSeconds(JWT_TTL_SECS).toEpochSecond())
            .iat(currentTime.toEpochSecond())
            .build();
    }

}
