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

package de.gematik.idp.server.controllers;

import static de.gematik.idp.IdpConstants.DISCOVERY_DOCUMENT_ENDPOINT;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.data.IdpDiscoveryDocument;
import de.gematik.idp.data.IdpJwksDocument;
import de.gematik.idp.server.ServerUrlService;
import de.gematik.idp.server.exceptions.IdpServerException;
import de.gematik.idp.server.services.DiscoveryDocumentBuilder;
import de.gematik.idp.server.validation.clientSystem.ValidateClientSystem;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import java.util.Collections;
import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import net.dracoblue.spring.web.mvc.method.annotation.HttpResponseHeader;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Api(tags = {
    "DiscoveryDocument-Dienst"}, description = "REST Endpunkte für das Abfragen der öffentlichen Informationen des IDP Rest Services")
@RequiredArgsConstructor
public class DiscoveryDocumentController {

    private final IdpKey idpSig;
    private final IdpKey discSig;
    private final ObjectMapper objectMapper;
    private final ServerUrlService serverUrlService;
    private final DiscoveryDocumentBuilder discoveryDocumentBuilder;
    private IdpJwtProcessor jwtProcessor;

    @PostConstruct
    public void setUp() {
        jwtProcessor = new IdpJwtProcessor(discSig.getIdentity());
    }

    @GetMapping("/jwks")
    @ApiOperation(value = "Endpunkt für Schlüsselinformationen für die Tokenabfrage", notes = "Verbaut Schlüsselinformationen in ein JWK und liefert dieses zurück.")
    public IdpJwksDocument getJwks() {
        return idpSig.buildJwks();
    }

    @GetMapping(value = {DISCOVERY_DOCUMENT_ENDPOINT,
        "/auth/realms/idp/.well-known/openid-configuration"}, produces = MediaType.APPLICATION_JSON_VALUE)
    @ApiOperation(value = "Endpunkt für Abfrage aller öffentlich verfügbaren Informationen zum IDP Server", notes = "Diese Daten sind mit dem privaten Schlüssel des IDP Servers verschlüsselt.")
    @ValidateClientSystem
    @HttpResponseHeader(name = "Cache-Control", value = "#{environment.getProperty('caching.discoveryDocument.cacheControl')}", valueExpression = true)
    public String getDiscoveryDocument(final HttpServletRequest request) {
        return signDiscoveryDocument(discoveryDocumentBuilder
            .buildDiscoveryDocument(serverUrlService.determineServerUrl(request),
                serverUrlService.getIssuerUrl()));
    }

    private String signDiscoveryDocument(final IdpDiscoveryDocument discoveryDocument) {
        try {
            return jwtProcessor
                .buildJws(objectMapper.writeValueAsString(discoveryDocument), Collections.emptyMap(), true)
                .getRawString();
        } catch (final JsonProcessingException e) {
            throw new IdpServerException("Error during discovery-document serialization", e);
        }
    }
}
