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

import de.gematik.idp.data.FederationPubKey;
import de.gematik.idp.data.fedmaster.EntityListEntry;
import de.gematik.idp.data.fedmaster.EntityListing;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Resource;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class EntityListingBuilder {

    @Resource
    List<FederationPubKey> otherKeyList;

    private static final int ENTITY_STATEMENT_TTL_DAYS = 1;

    public EntityListing buildEntityListing(final String serverUrl) {
        final ZonedDateTime currentTime = ZonedDateTime.now();
        return EntityListing.builder()
            .exp(currentTime.plusDays(ENTITY_STATEMENT_TTL_DAYS).toEpochSecond())
            .iat(currentTime.toEpochSecond())
            .iss(serverUrl)
            .idpEntityList(createIdpEntityList())
            .build();
    }

    private List<EntityListEntry> createIdpEntityList() {
        final List<EntityListEntry> entityList = new ArrayList<>();

        for (final FederationPubKey fedPupKey : otherKeyList) {
            if (fedPupKey.getType().equals("idp")) {
                entityList.add(EntityListEntry.builder()
                    .iss(fedPupKey.getUrl())
                    .name(fedPupKey.getIssuer())
                    .logoUri("todo-logo")
                    .userTypeSupported("todo-utsupp")
                    .build()
                );
            }
        }

        return entityList;
    }

}
