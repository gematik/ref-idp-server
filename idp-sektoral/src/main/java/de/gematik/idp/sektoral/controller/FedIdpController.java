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

package de.gematik.idp.sektoral.controller;

import static de.gematik.idp.IdpConstants.ENTITY_STATEMENT_ENDPOINT;
import static de.gematik.idp.IdpConstants.FEDIDP_AUTH_ENDPOINT;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.crypto.Nonce;
import de.gematik.idp.data.JwtHelper;
import de.gematik.idp.data.fedidp.ParResponse;
import de.gematik.idp.sektoral.ServerUrlService;
import de.gematik.idp.sektoral.data.FedIdpAuthSession;
import de.gematik.idp.sektoral.services.EntityStatementBuilder;
import java.time.ZonedDateTime;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.Pattern;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@Slf4j
public class FedIdpController {

    private static final int MAX_AUTH_SESSION_AMOUNT = 10000;
    private static final int URI_NONCE_LENGTH = 16;
    private final EntityStatementBuilder entityStatementBuilder;
    private final ServerUrlService serverUrlService;
    private final IdpJwtProcessor jwtProcessor;
    private final ObjectMapper objectMapper;

    private final Map<String, FedIdpAuthSession> fedIdpAuthSessions = new LinkedHashMap<>() {

        @Override
        protected boolean removeEldestEntry(final Entry<String, FedIdpAuthSession> eldest) {
            return size() > MAX_AUTH_SESSION_AMOUNT;
        }
    };

    @GetMapping(value = ENTITY_STATEMENT_ENDPOINT, produces = "application/jose;charset=UTF-8")
    public String getEntityStatement(final HttpServletRequest request) {
        return JwtHelper.signJson(jwtProcessor, objectMapper, entityStatementBuilder
            .buildEntityStatement(serverUrlService.determineServerUrl(request)));
    }

    /* Federation App2App flow
     * Request(in)  == message nr.2 PushedAuthRequest(PAR)
     *                 messages nr.2c ... nr.2d
     * Response(out)== message nr.3
     */
    @GetMapping(value = FEDIDP_AUTH_ENDPOINT, produces = "application/json;charset=UTF-8")
    public ParResponse getRequestUri(
        @RequestParam(name = "client_id") @NotEmpty final String fachdienstClientId,
        @RequestParam(name = "state") @NotEmpty final String fachdienstState,
        @RequestParam(name = "redirect_uri") @NotEmpty final String fachdienstRedirectUri,
        @RequestParam(name = "code_challenge") @NotEmpty final String fachdienstCodeChallenge,
        @RequestParam(name = "code_challenge_method") @NotEmpty @Pattern(regexp = "S256") final String fachdienstCodeChallengeMethod,
        @RequestParam(name = "response_type") @NotEmpty @Pattern(regexp = "code") final String responseType,
        @RequestParam(name = "nonce") @NotEmpty final String fachdienstNonce,
        @RequestParam(name = "scope") @NotEmpty @Pattern(regexp = "erp_sek_auth+openid") final String scope,
        @RequestParam(name = "acr_values") @NotEmpty final String acrValues,
        @RequestParam(name = "client_assertion_type") @NotEmpty final String clientAssertionType,
        @RequestParam(name = "client_assertion") @NotEmpty final String clientAssertion,
        @RequestParam(name = "claims") @NotEmpty final String claims,
        final HttpServletRequest reqMsgNr2,
        final HttpServletResponse respMsgNr3) {

        final int REQUEST_URI_TTL_SECS = 90;
        log.info("Amount of stored fedIdpAuthSessions: {}", fedIdpAuthSessions.size());
        log.info("clientAssertion: {}", clientAssertion);

        // URI zur späteren Identifikation des Requestes: https://tools.ietf.org/id/draft-ietf-oauth-par-04.html#section-2.2
        final String requestUri = "urn:" + fachdienstClientId + ":" + new Nonce().getNonceAsHex(URI_NONCE_LENGTH);

        fedIdpAuthSessions.put(fachdienstState, FedIdpAuthSession.builder()
            .fachdienstCodeChallenge(fachdienstCodeChallenge)
            .fachdienstNonce(fachdienstNonce)
            .fachdienstRedirektUri(fachdienstRedirectUri)
            .requestUri(requestUri)
            .expiresAt(ZonedDateTime.now().plusSeconds(REQUEST_URI_TTL_SECS).toString())
            .build()
        );

        setNoCacheHeader(respMsgNr3);
        respMsgNr3.setStatus(HttpStatus.CREATED.value());

        return ParResponse.builder()
            .requestUri(requestUri)
            .expiresIn(REQUEST_URI_TTL_SECS)
            .build();
    }

    private static void setNoCacheHeader(final HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Pragma", "no-cache");
    }
}
