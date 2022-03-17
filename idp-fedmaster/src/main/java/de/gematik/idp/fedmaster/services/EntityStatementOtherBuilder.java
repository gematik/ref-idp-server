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

import de.gematik.idp.data.FederationPrivKey;
import de.gematik.idp.data.FederationPubKey;
import de.gematik.idp.data.JwtHelper;
import de.gematik.idp.data.fedmaster.EntityStatementOther;
import java.time.ZonedDateTime;
import java.util.List;
import javax.annotation.Resource;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;

@RequiredArgsConstructor
public class EntityStatementOtherBuilder {

    @Autowired
    FederationPrivKey entityStatementSigKey;
    @Resource
    List<FederationPubKey> otherKeyList;

    private static final int ENTITY_STATEMENT_FD_TTL_DAYS = 7;

    public EntityStatementOther buildEntityStatementOther(final String serverUrl, final String sub) {
        final ZonedDateTime currentTime = ZonedDateTime.now();
        return EntityStatementOther.builder()
            .exp(currentTime.plusDays(ENTITY_STATEMENT_FD_TTL_DAYS).toEpochSecond())
            .iat(currentTime.toEpochSecond())
            .iss(serverUrl)
            .sub(sub)
            .jwks(JwtHelper.getJwks(getKey(sub)))
            .build();
    }

    private FederationPubKey getKey(final String sub) {
        for (final FederationPubKey fedPupKey : otherKeyList) {
            if (fedPupKey.getUrl().equals(sub)) {
                return fedPupKey;
            }
        }

        return null;

    }

}
