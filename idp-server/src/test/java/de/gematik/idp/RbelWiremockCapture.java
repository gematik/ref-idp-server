/*
 * Copyright (c) 2021 gematik GmbH
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

package de.gematik.idp;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.common.ProxySettings;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.http.HttpHeader;
import com.github.tomakehurst.wiremock.http.Request;
import com.github.tomakehurst.wiremock.http.Response;
import de.gematik.rbellogger.captures.RbelCapturer;
import de.gematik.rbellogger.converter.RbelConverter;
import de.gematik.rbellogger.data.RbelHostname;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.Arrays;

import java.util.stream.Collectors;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;

@Slf4j
public class RbelWiremockCapture extends RbelCapturer {

    private final String proxyFor;
    private final ProxySettings proxySettings;
    private final WireMockConfiguration wireMockConfiguration;
    private WireMockServer wireMockServer;
    private boolean isInitialized;

    @Builder
    public RbelWiremockCapture(final RbelConverter rbelConverter,
                               final String proxyFor, final ProxySettings proxySettings, final WireMockConfiguration wireMockConfiguration) {
        super(rbelConverter);
        this.proxyFor = proxyFor;
        this.proxySettings = proxySettings;
        this.wireMockConfiguration = wireMockConfiguration;
    }

    public RbelWiremockCapture initialize() {
        if (isInitialized) {
            return this;
        }

        log.info("Starting Wiremock-Capture. This will boot a proxy-server for the target url '{}'", proxyFor);
        final WireMockConfiguration wireMockConfiguration = getWireMockConfiguration();
        wireMockServer = new WireMockServer(wireMockConfiguration);
        wireMockServer.start();

        wireMockServer.stubFor(WireMock.any(WireMock.anyUrl())
            .willReturn(aResponse().proxiedFrom(proxyFor)));

        wireMockServer.addMockServiceRequestListener((request, response) -> {
            getRbelConverter().parseMessage(requestToRbelMessage(request),
                new RbelHostname(request.getClientIp(), -1),
                new RbelHostname(request.getHost(), request.getPort()));
            getRbelConverter().parseMessage(responseToRbelMessage(response),
                new RbelHostname(request.getClientIp(), -1),
                new RbelHostname(request.getHost(), request.getPort()));
        });

        log.info("Started Wiremock-Server at '{}'.", wireMockServer.baseUrl());

        isInitialized = true;

        return this;
    }

    private WireMockConfiguration getWireMockConfiguration() {
        if (this.wireMockConfiguration != null) {
            return this.wireMockConfiguration;
        }
        final WireMockConfiguration wireMockConfiguration = WireMockConfiguration.options()
            .dynamicPort()
            .trustAllProxyTargets(true)
            .enableBrowserProxying(false);
        if (proxySettings != null) {
            wireMockConfiguration.proxyVia(proxySettings);
        }
        return wireMockConfiguration;
    }

    private byte[] requestToRbelMessage(final Request request) {
        byte[] httpRequestHeader = (request.getMethod().toString() + " " + getRequestUrl(request) + " HTTP/1.1\r\n"
            + request.getHeaders().all().stream().map(HttpHeader::toString)
            .collect(Collectors.joining("\r\n")) + "\r\n\r\n").getBytes();

        return Arrays.concatenate(httpRequestHeader, request.getBody());
    }

    private byte[] responseToRbelMessage(final Response response) {
        byte[] httpResponseHeader = ("HTTP/1.1 " + response.getStatus() + " "
            + (response.getStatusMessage() != null ? response.getStatusMessage() : "") + "\r\n"
            + response.getHeaders().all().stream().map(HttpHeader::toString)
            .map(str -> str.replace("\n", "\r\n"))
            .collect(Collectors.joining("\r\n"))
            + "\r\n\r\n").getBytes();

        return Arrays.concatenate(httpResponseHeader, response.getBody());
    }

    private String getRequestUrl(Request request) {
        return (proxyFor == null ? "" : proxyFor) + request.getUrl();
    }

    public String getProxyAdress() {
        return "http://localhost:" + wireMockServer.port();
    }

    @Override
    public void close() {
        if (wireMockServer.isRunning()) {
            wireMockServer.stop();
        }
    }
}
