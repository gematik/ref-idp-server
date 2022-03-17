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

import static de.gematik.idp.IdpConstants.FEDMASTER_FEDERATION_API_ENDPOINT;
import de.gematik.idp.data.FederationPrivKey;
import de.gematik.idp.data.JwtHelper;
import de.gematik.idp.data.fedmaster.EntityStatement;
import de.gematik.idp.data.fedmaster.FederationEntity;
import de.gematik.idp.data.fedmaster.Metadata;
import java.time.ZonedDateTime;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;

@RequiredArgsConstructor
public class EntityStatementBuilder {

    @Autowired
    FederationPrivKey entityStatementSigKey;
    private static final int ENTITY_STATEMENT_TTL_DAYS = 7;

    public EntityStatement buildEntityStatement(final String serverUrl) {
        final ZonedDateTime currentTime = ZonedDateTime.now();
        return EntityStatement.builder()
            .exp(currentTime.plusDays(ENTITY_STATEMENT_TTL_DAYS).toEpochSecond())
            .iat(currentTime.toEpochSecond())
            .iss(serverUrl)
            .sub(serverUrl)
            .jwks(JwtHelper.getJwks(entityStatementSigKey))
            .metadata(getMetadata(serverUrl))
            .build();
    }

    private Metadata getMetadata(final String serverUrl) {
        final String apiEndpoint = serverUrl + FEDMASTER_FEDERATION_API_ENDPOINT;
        final FederationEntity federationEntity = FederationEntity.builder()
            .federationApiEndpoint(apiEndpoint)
            .build();
        return Metadata.builder()
            .federationEntity(federationEntity)
            .build();
    }

}
