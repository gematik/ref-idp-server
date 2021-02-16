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

import de.gematik.idp.server.configuration.IdpConfiguration;
import de.gematik.idp.server.exceptions.IdpServerStartupException;
import io.swagger.annotations.Api;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import javax.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import net.dracoblue.spring.web.mvc.method.annotation.HttpResponseHeader;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.MediaType;
import org.springframework.util.StreamUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.tautua.markdownpapers.Markdown;
import org.tautua.markdownpapers.parser.ParseException;

@RestController
@Api(tags = {
    "DiscoveryDocument-Dienst"}, description = "REST Endpunkte für das Abfragen der öffentlichen Informationen des IDP Rest Services")
@RequiredArgsConstructor
public class TokenFlowController {

    private final ResourceLoader resourceLoader;
    private final IdpConfiguration idpConfiguration;
    private String tokenFlowHtml;

    @PostConstruct
    public void renderTokenFlowHtml() {
        final String tokenFlowMarkdown = readMarkdown();

        final Markdown md = new Markdown();
        final StringWriter out = new StringWriter();
        try {
            md.transform(new StringReader(tokenFlowMarkdown), out);
        } catch (final ParseException e) {
            throw new IdpServerStartupException("Error during Markdown conversion", e);
        }
        tokenFlowHtml = out.toString();
    }

    private String readMarkdown() {
        final Resource resource = resourceLoader.getResource(idpConfiguration.getTokenFlowMdResource());
        try (final InputStream inputStream = resource.getInputStream()) {
            return StreamUtils.copyToString(inputStream, StandardCharsets.UTF_8);
        } catch (final IOException e) {
            throw new IdpServerStartupException(
                "Error while loading TokenFlow from resources '" + idpConfiguration.getTokenFlowMdResource() + "'", e);
        }
    }

    @GetMapping(value = "/tokenFlow.html", produces = MediaType.TEXT_HTML_VALUE)
    @HttpResponseHeader(name = "Cache-Control", value = "max-age=300")
    public String getDiscoveryDocument() {
        return tokenFlowHtml;
    }
}
