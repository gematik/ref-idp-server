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

package de.gematik.idp.fedmaster.controller;

import static de.gematik.idp.IdpConstants.ENTITY_LISTING_ENDPOINT;
import static de.gematik.idp.IdpConstants.ENTITY_STATEMENT_ENDPOINT;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.data.FederationPubKey;
import de.gematik.idp.data.JwtHelper;
import de.gematik.idp.fedmaster.ServerUrlService;
import de.gematik.idp.fedmaster.services.EntityListingBuilder;
import de.gematik.idp.fedmaster.services.EntityStatementBuilder;
import de.gematik.idp.fedmaster.services.FedRegistration;
import java.util.List;
import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@Slf4j
public class FedmasterController {

    private final EntityStatementBuilder entityStatementBuilder;
    private final EntityListingBuilder entityListingBuilder;
    private final ServerUrlService serverUrlService;
    private final IdpJwtProcessor jwtProcessor;
    private final ObjectMapper objectMapper;

    @Resource
    List<FederationPubKey> otherKeyList;


    @GetMapping(value = ENTITY_STATEMENT_ENDPOINT, produces = "application/jose;charset=UTF-8")
    public String getEntityStatement(final HttpServletRequest request) {
        FedRegistration.registerOnce(otherKeyList);
        return JwtHelper.signJson(jwtProcessor, objectMapper, entityStatementBuilder
            .buildEntityStatement(serverUrlService.determineServerUrl(request)));
    }

    @GetMapping(value = ENTITY_LISTING_ENDPOINT, produces = "application/jwt;charset=UTF-8")
    public String getEntityListing(final HttpServletRequest request) {
        FedRegistration.registerOnce(otherKeyList);
        return JwtHelper.signJson(jwtProcessor, objectMapper,
            entityListingBuilder.buildEntityListing(serverUrlService.determineServerUrl(request)));
    }

}
