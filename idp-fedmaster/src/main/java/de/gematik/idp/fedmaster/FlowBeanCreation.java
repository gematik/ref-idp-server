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

package de.gematik.idp.fedmaster;

import de.gematik.idp.data.FederationPubKey;
import de.gematik.idp.fedmaster.services.EntityListingBuilder;
import de.gematik.idp.fedmaster.services.EntityStatementBuilder;
import de.gematik.idp.fedmaster.services.EntityStatementOtherBuilder;
import java.util.ArrayList;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class FlowBeanCreation {

    private final FederationPubKey fachdienstSigKey;
    private final FederationPubKey idpSigKey;

    @Bean
    public EntityStatementBuilder entityStatementBuilder() {
        return new EntityStatementBuilder();
    }

    @Bean
    public EntityStatementOtherBuilder entityStatementOtherBuilder() {
        return new EntityStatementOtherBuilder();
    }

    @Bean
    public EntityListingBuilder entityListBuilder() {
        return new EntityListingBuilder();
    }

    @Bean
    public List<FederationPubKey> otherKeyList() {
        final List<FederationPubKey> theList = new ArrayList<>();
        theList.add(fachdienstSigKey);
        theList.add(idpSigKey);
        return theList;
    }

}
