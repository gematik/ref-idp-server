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

import static de.gematik.idp.IdpConstants.FEDMASTER_FEDERATION_API_ENDPOINT;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.data.FederationPubKey;
import de.gematik.idp.data.JwtHelper;
import de.gematik.idp.fedmaster.ServerUrlService;
import de.gematik.idp.fedmaster.services.EntityStatementOtherBuilder;
import de.gematik.idp.fedmaster.services.FedRegistration;
import java.util.List;
import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.NotEmpty;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@Slf4j
public class FederationApiController {

    private final EntityStatementOtherBuilder entityStatementOtherBuilder;
    private final ServerUrlService serverUrlService;
    private final IdpJwtProcessor jwtProcessor;
    private final ObjectMapper objectMapper;

    @Resource
    List<FederationPubKey> otherKeyList;


    @GetMapping(value = FEDMASTER_FEDERATION_API_ENDPOINT, produces = "application/jose;charset=UTF-8")
    public String getEntityStatementOther(
        // iss is mandatory parameter, but ignored in this scenario
        @RequestParam(name = "iss") @NotEmpty final String iss,
        @RequestParam(name = "sub") @NotEmpty final String sub,
        final HttpServletRequest request) {
        FedRegistration.registerOnce(otherKeyList);
        return JwtHelper.signJson(jwtProcessor, objectMapper, entityStatementOtherBuilder
            .buildEntityStatementOther(serverUrlService.determineServerUrl(request), sub));
    }

}
